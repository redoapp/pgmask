//! Trace an output column back to the base columns it derives from.
//!
//! Output classification refuses any field the `RowDescription` gives no
//! provenance for — every expression, aggregate, set operation and CTE
//! reference. That is safe and it refuses about half of real analytical SQL.
//!
//! Lineage relaxes it on one condition: if every base column an output field
//! derives from is explicitly released by the operator's catalog, the field
//! cannot carry a masked value and can be served.
//!
//! # This inverts the safety property, so read the guards
//!
//! Everywhere else in pgmask, missing something costs utility. The allowlist in
//! `analysis` is sound by construction: a shape we fail to recognise is a
//! shape we refuse.
//!
//! Here it is the other way round. A source column we fail to notice is a
//! column we do not check against the catalog, and "no masked sources found"
//! becomes "release it". **Under-reporting is a disclosure.** Every rule below
//! exists to make silence impossible to mistake for safety.
//!
//! # Why a library, and what it does not tell you
//!
//! `sqllineage` does the name resolution — scopes, aliases, CTEs, subqueries —
//! which is the expensive half and is a whole Postgres analyzer to rewrite. On
//! the TPC-DS corpus it resolved 27 of the 42 queries pgmask refuses.
//!
//! But its `ColumnOrigin::Concrete` does **not** mean resolved. When it cannot
//! work out which CTE a name came from it returns `Concrete` with the table
//! named `?cte?`; there is a second placeholder, `?unknown?`. A caller that
//! trusts the enum variant reads a sentinel as a base column. Hence
//! [`Verdict`] and the guards in [`resolve`]:
//!
//! 1. A source table that does not exist in the live schema is unresolved.
//!    Checked by existence, not by matching `?cte?` — a placeholder added in a
//!    later release then fails closed instead of passing silently.
//! 2. An empty source list is unresolved. Empty means either "genuinely none"
//!    or "did not look inside", and the type cannot distinguish them: `count(*)`
//!    and a string literal sit in the same bucket as a `CASE` over scalar
//!    subqueries whose sources were missed. Costs nothing to refuse, because
//!    `analysis` already releases `count(*)` and literals by shape.
//! 3. A mapping count that does not match the field count is unresolved. We
//!    address fields by position, and a mismatch means the positions are not
//!    ours to claim.
//! 4. A parse failure is unresolved. `sqlparser-rs` is not the Postgres grammar
//!    and does not have to be — anything it cannot read, we refuse.
//! 5. A source that is a column of a view whose definition contains a set
//!    operation is unresolved. Such a column is several columns, so a rule
//!    releasing it releases all of them.
//! 6. **The backstop.** If a masked column's *name* appears anywhere in the
//!    statement, nothing is released — whatever the resolver reported.
//!    Names come from the token stream (including decoded `u&"…"` idents)
//!    union the parse tree (which already expands those escapes on
//!    `ColumnRef`). Either source alone has a blind spot the other covers.
//! 7. **A `Release` is an allowlist of shapes.** A non-empty source list is
//!    not a complete source list. `sqllineage` does not descend into a
//!    `SubLink`, so `city || (SELECT email FROM …)` reports only `city`.
//!    Guards 1–5 named the last construct that leaked; 7 inverts the
//!    question the way [`crate::analysis`] does: the output expression must
//!    be built only from node types that cannot hide a nested query. A
//!    `SubLink`, a window, or a node kind we have not listed stays
//!    unresolved — even when every *reported* source is released.
//!
//! # Why 6 and 7 both exist
//!
//! Guards 1-5 are each shaped like the bug that produced them. Three of this
//! project's five disclosures were the same mistake in different clothes:
//!
//! - a set operation, where one field draws from two columns
//! - a view whose definition contains one, invisible in the statement
//! - a scalar subquery, which `sqllineage` does not descend into
//!
//! Each was closed by asking "did the resolver under-report *this* construct".
//! That approach can only ever cover constructs someone has thought of, and the
//! third arrived after the first two were fixed.
//!
//! Guard 7 stops treating "we found some sources and they are released" as
//! "we found every source". It does not try to teach the resolver about
//! `SubLink`; it refuses to `Release` an expression the resolver is not
//! trusted to have finished. A `ColumnRef` that is the output of a
//! FROM-clause subquery or CTE is that inner expression: following the
//! alias is how `SELECT x FROM (SELECT city || (SELECT …) AS x)` stays a
//! `SubLink` instead of looking like a stored column. A subquery in WHERE
//! is still a predicate, not a source of the field.
//!
//! Guard 6 does not ask about constructs. It asks whether a masked column is
//! named in the statement at all — including in WHERE, which 7 does not
//! inspect, because a predicate is not a source of the projected value.
//! The **lexer** supplies every identifier spelling in the text
//! (unicode-escaped idents decoded to their catalog names); the **parse
//! tree** supplies names the token stream does not spell as words.
//!
//! A disclosure now needs the resolver to under-report, the shape to look
//! closed after following FROM/CTE aliases, *and* the backstop to miss the
//! name. The unicode-escaped concat that leaked under the GUI catalog
//! failed 6 and would now fail 7 even if the subquery had named only
//! released columns. Wrapping that concat as `SELECT x FROM (… AS x)`
//! used to make the described field a `ColumnRef`; 7 follows the alias.
//! A FROM colnames list on a `RangeVar` is a different hole with no
//! SubLink: `SELECT upper(city) FROM customers AS t(id, city, …)` binds
//! the released name to email. sqllineage and a closed ColumnRef both
//! treat it as `customers.city`. That list is incomplete, the same
//! inversion as `RangeFunction` / join-with-colnames.
//!
//! The premise — that the backstop sees everything the resolver can name — is
//! asserted in `tests/lineage_superset.rs` rather than assumed. That test has
//! already caught one violation: the backstop's first implementation walked the
//! parse tree and missed `id` in `sum(n) OVER (ORDER BY id …)`, because
//! `pg_query`'s walker does not enter a `WindowDef`.
//!
//! **This is a mitigation, not a proof.** Lineage inverts the safety property
//! and no amount of guarding changes that; it stays opt-in and off by default.

use std::collections::HashSet;
use std::sync::Arc;

use sqllineage::types::{AnalyzeOptions, CatalogProvider, ColumnOrigin, Dialect, TableRef};

use crate::analysis::{output_lineage_is_closed, StatementInspection};
use crate::catalog::Snapshot;

/// What lineage can say about one output field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Every base column it derives from is explicitly released. Safe to serve.
    Release,
    /// It derives from a column the catalog masks. Refused, but we can say
    /// which column, which is the difference between a ticket and a rewrite.
    Blocked(String),
    /// Not resolved. Refused, and deliberately indistinguishable from a
    /// refusal for any other reason.
    Unresolved,
}

/// The operator's schema, in the shape the analyser wants.
///
/// Holds an `Arc` rather than a borrow because `CatalogProvider` has to be
/// boxed as `'static`. The snapshot is already refcounted and swapped whole on
/// refresh, so this is a pointer bump and the view stays consistent for the
/// duration of the analysis.
struct SnapshotCatalog(Arc<Snapshot>);

impl CatalogProvider for SnapshotCatalog {
    /// Required by the trait, and — measured — consulted by nothing.
    ///
    /// The campaign reports all four value-replacing mutants here as surviving,
    /// and they are equivalent rather than untested. Replacing this with `None`,
    /// an empty list or `["xyzzy"]` changes the verdict of **no** shape:
    ///
    /// ```text
    ///   SELECT upper(ship_city) FROM demo.orders                     Release
    ///   SELECT upper(c.city) FROM …customers c JOIN …orders o ON …   Release
    ///   SELECT upper(city) FROM …customers JOIN …orders USING (id)   Release
    ///   SELECT * FROM demo.orders                                    Unresolved
    ///   SELECT upper(x.ship_city) FROM (SELECT * FROM …orders) x     Unresolved
    ///   WITH q AS (SELECT * FROM …orders) SELECT upper(ship_city)    Unresolved
    /// ```
    ///
    /// Identical with the real columns and with each mutant. The reason is that
    /// a column list is wanted for star expansion, and every star shape is
    /// already `Unresolved` — guard 2 refuses an empty source list — before the
    /// answer could matter. Named columns resolve without it.
    ///
    /// Kept correct rather than stubbed: this is a `sqllineage` implementation
    /// detail, not a contract, and a version bump could start consulting it.
    /// The six shapes above are what was measured, not a proof over all SQL.
    fn list_columns(&self, table: &TableRef) -> Option<Vec<String>> {
        self.0
            .relation_columns(&qualify(table))
            .map(<[String]>::to_vec)
    }

    fn resolve_column(&self, column: &str, candidates: &[TableRef]) -> Option<TableRef> {
        let wanted = column.to_ascii_lowercase();
        let mut owners = candidates.iter().filter(|t| {
            self.0
                .relation_columns(&qualify(t))
                .is_some_and(|cs| cs.contains(&wanted))
        });
        let first = owners.next()?;
        // Two candidates owning the same column name is genuinely ambiguous.
        // Guessing here would pick a mask at random.
        if owners.next().is_some() {
            return None;
        }
        Some(first.clone())
    }
}

/// `schema.table`, defaulting the schema the way an unqualified name resolves
/// in practice. A wrong guess here cannot cause a release: the name either
/// matches a real relation or the existence guard rejects it.
fn qualify(table: &TableRef) -> String {
    match &table.schema {
        Some(schema) => format!("{}.{}", schema, table.table),
        None => format!("public.{}", table.table),
    }
}

/// Resolve every output field of `sql` against the catalog.
///
/// Returns one verdict per field, in field order. Any doubt anywhere collapses
/// that field — and in the cases below, the whole statement — to
/// [`Verdict::Unresolved`].
///
/// Takes the principal's roles because releasability is per-principal: a column
/// support may read in the clear is still masked for everyone else, and a
/// verdict computed for the wrong principal would release it to them.
pub fn resolve(
    sql: &str,
    field_count: usize,
    snapshot: &Arc<Snapshot>,
    roles: &HashSet<String>,
) -> Vec<Verdict> {
    let inspection = StatementInspection::new(sql);
    resolve_inspected(&inspection, field_count, snapshot, roles)
}

pub(crate) fn resolve_inspected(
    inspection: &StatementInspection<'_>,
    field_count: usize,
    snapshot: &Arc<Snapshot>,
    roles: &HashSet<String>,
) -> Vec<Verdict> {
    let sql = inspection.sql();
    let unresolved = vec![Verdict::Unresolved; field_count];

    let opts = AnalyzeOptions {
        dialect: Dialect::PostgreSql,
        catalog: Some(Box::new(SnapshotCatalog(Arc::clone(snapshot)))),
        normalize_case: true,
    };
    // Guard 4: anything the parser cannot read.
    let Ok(results) = sqllineage::analyze(sql, opts) else {
        return unresolved;
    };
    // More than one statement means several result sets, and we would have to
    // know which one this `RowDescription` belongs to.
    // A slice pattern rather than a count check plus an index: the same
    // "exactly one statement" rule, enforced by the compiler.
    let [result] = results.as_slice() else {
        return unresolved;
    };
    let mappings = &result.columns.mappings;
    // Guard 3: positional correspondence, or nothing.
    if mappings.len() != field_count {
        return unresolved;
    }

    // Guard 6: a masked column mentioned anywhere in the statement.
    //
    // **This is the backstop, and it is the reason to stop adding guards shaped
    // like the last bug.** Guards 1-5 each answer "did `sqllineage`
    // under-report *this* construct" — a set operation, a view, a scalar
    // subquery — and each was written after a disclosure of exactly that shape.
    // A guard per construct only ever covers constructs someone thought of, and
    // three of the five disclosures in this repo were this same mistake.
    //
    // This asks a question `sqllineage` is not involved in: does the statement
    // mention a masked column at all? If it does not, no output field can carry
    // a masked value however the expressions nest and whatever the resolver
    // saw. It is computed from the token stream (unicode-escaped identifiers
    // decoded) union the parse tree (`ColumnRef` names already expanded),
    // independently of the resolver, so the resolver *and* every name source
    // have to miss the same column for a release to be wrong. The token
    // stream alone missed `u&"email"`; the tree alone once missed `id` in a
    // `WindowDef`.
    //
    // Applied as a *downgrade of `Release`* rather than an early return, so a
    // field `sqllineage` correctly identified as `Blocked` still names the
    // column it derives from. That message is the difference between a ticket
    // and a rewrite, and an early return threw it away.
    //
    // Guard 7 is the other downgrade of `Release`: even when no masked name
    // appears, a `SubLink` in the output is incomplete sources, and "we
    // found `city`" is not "we found every source".
    //
    // The cost is utility, not safety: `SELECT upper(city) FROM people WHERE
    // email = 'x'` no longer releases, because `email` is mentioned. That
    // statement is a predicate oracle anyway.
    let masked_column_in_statement =
        snapshot.inspection_references_masked_column(inspection, roles);
    let shape_closed = output_lineage_is_closed(inspection, field_count);

    mappings
        .iter()
        .enumerate()
        .map(|(index, mapping)| {
            // Guard 2: silence is not safety.
            if mapping.sources.is_empty() {
                return Verdict::Unresolved;
            }
            let mut blocked: Option<String> = None;
            for source in &mapping.sources {
                let ColumnOrigin::Concrete { table, column } = source else {
                    // Ambiguous, Wildcard and Recursive all mean "a catalog
                    // would be needed" or "partial". We have already supplied a
                    // catalog, so anything still unresolved stays unresolved.
                    return Verdict::Unresolved;
                };
                let relation = qualify(table);
                // Guard 1: the table has to be real. `?cte?` and `?unknown?`
                // arrive here looking exactly like base columns.
                let Some(columns) = snapshot.relation_columns(&relation) else {
                    return Verdict::Unresolved;
                };
                let wanted = column.to_ascii_lowercase();
                if !columns.contains(&wanted) {
                    return Verdict::Unresolved;
                }
                // Guard 5: the source must not be a column of a view whose
                // definition contains a set operation.
                //
                // Such a column is itself several columns. `v_mixed.v` is a
                // city on one branch and an address on the other, so a rule
                // releasing it releases both — and lineage resolving an
                // expression down to `v_mixed.v` and finding it released is
                // exactly how a masked address reached a client after the
                // provenance-level check for this was already in place.
                //
                // The generated-shape campaign found it in its first run, via
                //   SELECT c0, row_number() OVER (…) FROM (… FROM fz.v_mixed …)
                // where distrusting the provenance sent the field to lineage,
                // and lineage released what provenance had just refused to.
                if snapshot.relation_is_opaque_view(&relation) {
                    return Verdict::Unresolved;
                }
                let released = snapshot
                    .lookup_by_name(&relation, &wanted)
                    // Unclassified is masked under default-deny. Treating "not
                    // in the catalog" as "fine" is the whole failure mode this
                    // module exists to avoid, so `None` is never released.
                    .is_some_and(|c| c.for_roles(roles).is_passthrough());
                if !released {
                    // Keep going: report the first masked source, but a later
                    // one being unresolvable still has to win.
                    blocked.get_or_insert(format!("{relation}.{wanted}"));
                }
            }
            match blocked {
                Some(column) => Verdict::Blocked(column),
                None if masked_column_in_statement => Verdict::Unresolved,
                // Guard 7: reported sources are not complete sources.
                None if !shape_closed.get(index).is_some_and(|closed| *closed) => {
                    Verdict::Unresolved
                }
                None => Verdict::Release,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )]
    use super::*;
    use crate::mask::Mask;

    /// `orders` is entirely released; `customers.email` is masked and
    /// `customers.city` is not.
    fn snapshot() -> Arc<Snapshot> {
        let mut s = Snapshot::default();
        s.insert_relation_for_test(
            "demo.orders",
            &[
                ("id", Mask::None),
                ("status", Mask::None),
                ("ship_city", Mask::None),
                ("order_total", Mask::None),
            ],
        );
        s.insert_relation_for_test(
            "demo.customers",
            &[
                ("id", Mask::None),
                ("city", Mask::None),
                ("email", Mask::Redact),
            ],
        );
        Arc::new(s)
    }

    fn verdicts(sql: &str, fields: usize) -> Vec<Verdict> {
        resolve(sql, fields, &snapshot(), &HashSet::new())
    }
    fn one(sql: &str) -> Verdict {
        verdicts(sql, 1).into_iter().next().expect("one field")
    }

    #[test]
    fn an_expression_over_released_columns_is_released() {
        assert_eq!(
            one("SELECT upper(ship_city) FROM demo.orders"),
            Verdict::Release
        );
        assert_eq!(
            one("SELECT ship_city || '/' || status FROM demo.orders"),
            Verdict::Release
        );
        // Set operations were the top refusal cause on TPC-DS.
        assert_eq!(
            one("SELECT ship_city FROM demo.orders UNION SELECT ship_city FROM demo.orders"),
            Verdict::Release
        );
    }

    #[test]
    fn a_masked_source_blocks_and_names_itself() {
        assert_eq!(
            one("SELECT lower(email) FROM demo.customers"),
            Verdict::Blocked("demo.customers.email".into())
        );
        // One masked source anywhere is enough, however much released data
        // surrounds it.
        assert_eq!(
            one("SELECT city || email FROM demo.customers"),
            Verdict::Blocked("demo.customers.email".into())
        );
    }

    #[test]
    fn a_column_absent_from_the_catalog_is_never_released() {
        // Unclassified means masked under default-deny. Reading "not in the
        // catalog" as "nothing to worry about" is the failure this module is
        // built to avoid.
        let mut s = Snapshot::default();
        s.relation_columns_for_test("demo.t", &["a", "b"]);
        let v = resolve(
            "SELECT upper(a) FROM demo.t",
            1,
            &Arc::new(s),
            &HashSet::new(),
        );
        assert_ne!(v[0], Verdict::Release);
    }

    #[test]
    fn the_lexical_backstop_includes_unclassified_default_denied_columns() {
        let mut snapshot = Snapshot::default();
        snapshot.insert_relation_for_test("demo.orders", &[("id", Mask::None)]);
        snapshot.relation_columns_for_test("demo.hidden", &["secret"]);
        let verdict = resolve(
            "SELECT min((SELECT secret FROM demo.hidden LIMIT 1)) \
             OVER (PARTITION BY q.id) FROM (SELECT id FROM demo.orders) q",
            1,
            &Arc::new(snapshot),
            &HashSet::new(),
        );
        assert_ne!(
            verdict[0],
            Verdict::Release,
            "unclassified is masked, so silence from the resolver cannot release it"
        );
    }

    #[test]
    fn an_unclassified_name_on_an_unrelated_relation_does_not_block_release() {
        let mut snapshot = Snapshot::default();
        snapshot.insert_relation_for_test("demo.people", &[("city", Mask::None)]);
        snapshot.relation_columns_for_test("demo.unrelated", &["city"]);
        let verdict = resolve(
            "SELECT upper(city) FROM demo.people",
            1,
            &Arc::new(snapshot),
            &HashSet::new(),
        );
        assert_eq!(verdict[0], Verdict::Release);
    }

    // --- the guards ------------------------------------------------------

    #[test]
    fn a_placeholder_table_is_not_a_resolution() {
        // sqllineage returns `?cte?` as ColumnOrigin::Concrete when it cannot
        // work out which CTE a name came from. Believing the variant is exactly
        // how a masked column gets released. TPC-DS query_33 is this shape.
        let sql = "WITH a AS (SELECT ship_city AS c FROM demo.orders), \
                        b AS (SELECT ship_city AS c FROM demo.orders) \
                   SELECT c FROM (SELECT c FROM a UNION ALL SELECT c FROM b) u";
        // Whatever it resolves to, it must never be Blocked-with-a-fake-table
        // or Released on the strength of one.
        for v in verdicts(sql, 1) {
            if let Verdict::Blocked(source) = &v {
                assert!(
                    !source.contains('?'),
                    "a sentinel reached the message: {source}"
                );
            }
        }
    }

    #[test]
    fn an_empty_source_list_is_unresolved_not_safe() {
        // `count(*)` genuinely has no sources; a CASE over scalar subqueries
        // whose sources were missed looks identical. analysis releases the
        // first by shape, so refusing both here costs nothing.
        assert_eq!(one("SELECT count(*) FROM demo.orders"), Verdict::Unresolved);
        assert_eq!(one("SELECT 'literal'"), Verdict::Unresolved);
    }

    #[test]
    fn a_field_count_mismatch_collapses_everything() {
        // Fields are addressed by position. If the counts disagree, the
        // positions are not ours to claim.
        let v = verdicts("SELECT ship_city, status FROM demo.orders", 3);
        assert!(v.iter().all(|x| *x == Verdict::Unresolved));
        assert_eq!(v.len(), 3);
    }

    #[test]
    fn unparseable_and_multi_statement_sql_is_unresolved() {
        assert_eq!(one("this is not sql"), Verdict::Unresolved);
        for v in verdicts("SELECT ship_city FROM demo.orders; SELECT 1", 1) {
            assert_eq!(v, Verdict::Unresolved);
        }
    }

    // --- unqualified names, where the catalog does the disambiguating -----
    //
    // Coverage found `resolve_column` had never executed: sqlsmith qualifies
    // everything, so the fuzz campaign never reached it. It is the function
    // that decides which table an unqualified column belongs to, and picking
    // the wrong one attributes a masked column to a released table.

    fn two_tables() -> Arc<Snapshot> {
        let mut s = Snapshot::default();
        // `shared` exists in both; `only_pub` and `secret` in one each.
        s.insert_relation_for_test(
            "demo.pub_t",
            &[("shared", Mask::None), ("only_pub", Mask::None)],
        );
        s.insert_relation_for_test(
            "demo.sec_t",
            &[("shared", Mask::Redact), ("secret", Mask::Redact)],
        );
        Arc::new(s)
    }

    /// A released column of a set-operation view must not be released by
    /// lineage, however explicitly the catalog releases it.
    ///
    /// This is the third disclosure in this area and the first that lineage
    /// caused on its own: distrusting the engine's provenance sends the field
    /// down the opaque path, and lineage then resolved it to `v_mixed.v`, found
    /// a `mask = "none"` rule, and released what provenance had just refused
    /// to. The generated-shape campaign hit it in its first run.
    ///
    /// Removing the `relation_is_opaque_view` guard in `resolve` makes this
    /// test fail, which is the only reason to trust that it is doing anything.
    #[test]
    fn a_column_of_a_set_operation_view_is_never_released_by_lineage() {
        let mut s = Snapshot::default();
        // Released as far as the catalog is concerned — the rule an operator
        // writes because `v` looks like a city column.
        s.insert_relation_for_test("fz.v_mixed", &[("v", Mask::None)]);
        s.insert_opaque_view_for_test("fz.v_mixed");
        let snapshot = Arc::new(s);

        for sql in [
            "SELECT upper(v) FROM fz.v_mixed",
            "SELECT c0 FROM (SELECT v AS c0 FROM fz.v_mixed) q",
            "WITH w AS (SELECT v FROM fz.v_mixed) SELECT lower(v) FROM w",
        ] {
            assert_ne!(
                resolve(sql, 1, &snapshot, &HashSet::new())[0],
                Verdict::Release,
                "must not release through a set-operation view: {sql}"
            );
        }
    }

    /// The same shape over an ordinary view still resolves, so the guard is
    /// specific rather than a blanket refusal of views.
    #[test]
    fn an_ordinary_view_still_resolves_through_lineage() {
        let mut s = Snapshot::default();
        s.insert_relation_for_test("fz.v_plain", &[("city", Mask::None)]);
        let snapshot = Arc::new(s);
        assert_eq!(
            resolve(
                "SELECT upper(city) FROM fz.v_plain",
                1,
                &snapshot,
                &HashSet::new()
            )[0],
            Verdict::Release
        );
    }

    /// The backstop: a masked column mentioned anywhere blocks release.
    ///
    /// Three disclosures came from `sqllineage` under-reporting which base
    /// columns feed a field — a set operation, a view column, and a scalar
    /// subquery. Each was closed by a guard aimed at that construct, which only
    /// ever covers constructs someone thought of. This rule does not care about
    /// the construct: if a masked column is named in the statement at all,
    /// nothing is released.
    ///
    /// The scalar-subquery case is the one that leaked. `d` is masked and lives
    /// two levels down inside a `SubLink`, where the resolver does not look —
    /// but `pg_query` sees it, and that is enough.
    #[test]
    fn a_masked_column_anywhere_blocks_release() {
        let mut s = Snapshot::default();
        s.insert_relation_for_test(
            "demo.t",
            &[("shared", Mask::None), ("secret", Mask::Redact)],
        );
        let snapshot = Arc::new(s);
        for sql in [
            "SELECT min((SELECT secret FROM demo.t LIMIT 1)) OVER (PARTITION BY shared) FROM demo.t",
            "SELECT upper(shared) FROM demo.t WHERE secret = 'x'",
            "SELECT shared FROM demo.t ORDER BY secret",
            // Closed output, unicode-escaped name in a predicate: Guard 7
            // does not look at WHERE, so only the backstop naming `secret`
            // can refuse. The concat cases below are also SubLinks and would
            // stay refused even if decode stopped working.
            r#"SELECT upper(shared) FROM demo.t WHERE u&"secret" = 'x'"#,
            r#"SELECT upper(shared) FROM demo.t WHERE u&"s\0065cret" = 'x'"#,
            r#"SELECT shared || (SELECT u&"secret" FROM demo.t WHERE shared = demo.t.shared LIMIT 1) FROM demo.t"#,
            r#"SELECT shared || (SELECT u&"s\0065cret" FROM demo.t LIMIT 1) FROM demo.t"#,
            r#"SELECT CONCAT(shared, (SELECT u&"secret" FROM demo.t LIMIT 1)) FROM demo.t"#,
            r#"SELECT ARRAY[shared, (SELECT u&"secret" FROM demo.t LIMIT 1)] FROM demo.t"#,
        ] {
            assert_ne!(
                resolve(sql, 1, &snapshot, &HashSet::new())[0],
                Verdict::Release,
                "a masked column is named here, so nothing may be released: {sql}"
            );
        }
    }

    /// A scalar subquery in the *output* is not a complete source list.
    ///
    /// `sqllineage` does not descend into a `SubLink`. Concatenating a released
    /// column with one looks fully resolved (`shared` only) and used to
    /// `Release` — which is a disclosure as soon as the subquery reads a
    /// masked column the backstop fails to name. The closed-shape guard
    /// refuses on the construct, independently of which names appear.
    ///
    /// A subquery in WHERE is a predicate, not a source of the field, and
    /// still resolves below.
    #[test]
    fn a_subquery_in_the_output_is_never_released_on_reported_sources() {
        let mut s = Snapshot::default();
        s.insert_relation_for_test(
            "demo.t",
            &[("shared", Mask::None), ("secret", Mask::Redact)],
        );
        let snapshot = Arc::new(s);
        for sql in [
            "SELECT shared || (SELECT shared FROM demo.t LIMIT 1) FROM demo.t",
            "SELECT CONCAT(shared, (SELECT shared FROM demo.t LIMIT 1)) FROM demo.t",
            "SELECT ARRAY[shared, (SELECT shared FROM demo.t LIMIT 1)] FROM demo.t",
            "SELECT (SELECT shared FROM demo.t LIMIT 1) FROM demo.t",
            // One closed branch does not make the other complete.
            "SELECT shared FROM demo.t UNION SELECT (SELECT shared FROM demo.t LIMIT 1)",
            // Wrapping the SubLink so the described field is a ColumnRef.
            // Guard 7 used to stop at the outer `x` and Release; the
            // FROM-alias list hides `secret` from Guard 6.
            "SELECT x FROM (SELECT shared || (SELECT shared FROM demo.t LIMIT 1) AS x FROM demo.t) q",
            "SELECT q.x FROM (SELECT shared || (SELECT shared FROM demo.t LIMIT 1) AS x FROM demo.t) q",
            "WITH q AS (SELECT shared || (SELECT shared FROM demo.t LIMIT 1) AS x FROM demo.t) SELECT x FROM q",
            "SELECT y FROM (SELECT x AS y FROM (SELECT shared || (SELECT shared FROM demo.t LIMIT 1) AS x FROM demo.t) q) r",
            "SELECT x FROM (SELECT CONCAT(shared, (SELECT shared FROM demo.t LIMIT 1)) AS x FROM demo.t) q",
            "SELECT x FROM (SELECT shared || (SELECT a FROM demo.t AS t(s, a) LIMIT 1) AS x FROM demo.t) q",
        ] {
            assert_ne!(
                resolve(sql, 1, &snapshot, &HashSet::new())[0],
                Verdict::Release,
                "a SubLink feeds this field and sqllineage does not look inside: {sql}"
            );
        }
    }

    /// ...and a statement naming only released columns still resolves, so the
    /// backstop is a masked-column check rather than a retreat from lineage.
    ///
    /// The subquery here reads a relation the catalog has never heard of, which
    /// is deliberate: the field's value comes from `shared` alone, and the
    /// `IN` is a predicate oracle of the kind already accepted everywhere else.
    #[test]
    fn released_columns_still_resolve_even_beside_a_subquery() {
        let mut s = Snapshot::default();
        s.insert_relation_for_test(
            "demo.t",
            &[("shared", Mask::None), ("secret", Mask::Redact)],
        );
        let snapshot = Arc::new(s);
        for sql in [
            "SELECT upper(shared) FROM demo.t",
            "SELECT upper(shared) FROM demo.t WHERE shared IN (SELECT x FROM elsewhere)",
            // Following a FROM alias of a stored column is still closed.
            "SELECT upper(x) FROM (SELECT shared AS x FROM demo.t) q",
            "SELECT x FROM (SELECT shared AS x FROM demo.t) q",
        ] {
            assert_eq!(
                resolve(sql, 1, &snapshot, &HashSet::new())[0],
                Verdict::Release,
                "only released columns are named here: {sql}"
            );
        }
    }

    /// A FROM colnames list remaps attnums by position.
    ///
    /// `AS t(id, city, …)` binds the released name `city` to `email`.
    /// Guard 6 never sees the word `email`; sqllineage reports
    /// `demo.t.city`. Guard 7 treats the list as incomplete, the same
    /// inversion as `RangeFunction` / join-with-colnames. A SELECT-list
    /// `AS` is not that list and still releases (the 0.1.96 pin).
    #[test]
    fn a_from_colnames_list_that_hides_a_masked_column_is_not_released() {
        let mut s = Snapshot::default();
        s.insert_relation_for_test(
            "demo.t",
            &[
                ("id", Mask::None),
                ("email", Mask::Redact),
                ("name", Mask::Redact),
                ("note", Mask::Redact),
                ("city", Mask::None),
            ],
        );
        s.insert_relation_for_test(
            "demo.v",
            &[
                ("id", Mask::None),
                ("email", Mask::Redact),
                ("name", Mask::Redact),
                ("city", Mask::None),
            ],
        );
        let snapshot = Arc::new(s);
        for sql in [
            "SELECT upper(city) FROM demo.t AS t(id, city, n, note, c)",
            "SELECT city || 'x' FROM demo.t AS t(id, city, n, note, c)",
            "SELECT city::text FROM demo.t AS t(id, city, n, note, c)",
            "SELECT city FROM demo.t AS t(id, city, n, note, c) \
             UNION ALL SELECT city FROM demo.t AS t(id, city, n, note, c)",
            "SELECT city FROM demo.t AS t(id, city, n, note, c) \
             EXCEPT SELECT city FROM demo.t",
            "SELECT upper(city) FROM demo.v AS v(id, city, n, c)",
        ] {
            assert_ne!(
                resolve(sql, 1, &snapshot, &HashSet::new())[0],
                Verdict::Release,
                "FROM colnames remapped a masked attnum onto a released name: {sql}"
            );
        }
        for sql in [
            "SELECT upper(city) FROM demo.t",
            "SELECT upper(x) FROM (SELECT city AS x FROM demo.t) q",
        ] {
            assert_eq!(
                resolve(sql, 1, &snapshot, &HashSet::new())[0],
                Verdict::Release,
                "a real city column, or a SELECT-list alias of one, still releases: {sql}"
            );
        }
    }

    #[test]
    fn an_unqualified_name_owned_by_one_table_resolves_to_it() {
        let s = two_tables();
        let sql = "SELECT upper(only_pub) FROM demo.pub_t JOIN demo.sec_t ON true";
        assert_eq!(resolve(sql, 1, &s, &HashSet::new())[0], Verdict::Release);
    }

    #[test]
    fn an_unqualified_name_reaching_a_masked_column_is_not_released() {
        let s = two_tables();
        let sql = "SELECT upper(secret) FROM demo.pub_t JOIN demo.sec_t ON true";
        assert_ne!(resolve(sql, 1, &s, &HashSet::new())[0], Verdict::Release);
    }

    #[test]
    fn an_ambiguous_unqualified_name_is_never_released() {
        // `shared` is released in one table and masked in the other. Guessing
        // picks a mask at random, and half those guesses are a disclosure.
        let s = two_tables();
        let sql = "SELECT upper(shared) FROM demo.pub_t JOIN demo.sec_t ON true";
        assert_ne!(
            resolve(sql, 1, &s, &HashSet::new())[0],
            Verdict::Release,
            "an ambiguous column must not be released on a guess"
        );
    }

    #[test]
    fn a_star_expansion_cannot_release_a_masked_column() {
        // `SELECT *` needs the catalog to expand. If expansion misses a column,
        // the mask that column carries is missed with it.
        let s = two_tables();
        for sql in [
            "SELECT * FROM (SELECT * FROM demo.sec_t) q",
            "SELECT upper(x) FROM (SELECT * FROM demo.sec_t) q(x, y)",
        ] {
            for v in resolve(sql, 2, &s, &HashSet::new()) {
                assert_ne!(v, Verdict::Release, "{sql}");
            }
        }
    }

    #[test]
    fn releasability_is_per_principal() {
        let mut s = Snapshot::default();
        s.insert_relation_for_test("demo.t", &[("secret", Mask::Redact)]);
        s.set_role_mask_for_test("demo.t", "secret", "support", Mask::None);
        let s = Arc::new(s);

        let nobody = HashSet::new();
        let support: HashSet<String> = ["support".to_string()].into_iter().collect();
        assert!(matches!(
            resolve("SELECT upper(secret) FROM demo.t", 1, &s, &nobody)[0],
            Verdict::Blocked(_)
        ));
        assert_eq!(
            resolve("SELECT upper(secret) FROM demo.t", 1, &s, &support)[0],
            Verdict::Release
        );
    }
}

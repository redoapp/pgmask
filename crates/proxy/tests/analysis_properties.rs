//! Properties of the release rules, rather than examples of them.
//!
//! Every disclosure this project has found in the analysis layer was the same
//! query in a spelling nobody had written down:
//!
//! ```text
//!   0.1.16   SELECT id, sum(salary) FROM t GROUP BY id
//!   0.1.18   ... GROUP BY <an alias of id>
//!   0.1.18   ... GROUP BY ROLLUP(<an alias of id>)
//!   0.1.31   SELECT * FROM ( ... GROUP BY id )
//! ```
//!
//! Each was fixed by adding the spelling to a list of literal strings, which
//! only ever protects against the spellings someone already thought of. Four
//! rounds of that is enough evidence that the list is the wrong shape.
//!
//! The property underneath them is simple and does not need the list: **a
//! transformation that does not change what a query returns must not make the
//! analysis more permissive.** Wrapping a statement in `SELECT * FROM (…)`
//! returns the same rows. Naming a target and grouping by that name groups by
//! the same column. If the plain form is refused and a rewritten form is
//! released, that difference is a disclosure whatever the rewrite was.
//!
//! `proptest` is already a dependency here — used for the `RowDescription`
//! parser and the masks — and this is the module it had not been pointed at.
//! No new crate: the repository hand-rolled its own RNG in `shapegen` rather
//! than take `rand`, and that posture is worth keeping.

use pgmask::analysis::{analyze, Relaxations, Safety, StatementInspection};
use proptest::prelude::*;

/// Everything a session can open. Testing with relaxations *on* is the strict
/// choice: it is the configuration in which a rule can release, so it is the
/// one in which a rule can be wrong.
const OPEN: Relaxations = Relaxations {
    summaries: true,
    fine_date_trunc: true,
};

/// Is `a` strictly more permissive than `b` for any field?
///
/// `Releasable` is the permissive verdict; anything else withholds. A rewrite
/// may refuse *more* than the original — over-refusal is a utility cost, not a
/// disclosure — so only the other direction fails.
fn more_permissive(a: &[Safety], b: &[Safety]) -> bool {
    a.iter()
        .zip(b.iter())
        .any(|(x, y)| *x == Safety::Releasable && *y != Safety::Releasable)
}

/// Column names that exist in the fixtures these rules are written against.
fn column() -> impl Strategy<Value = &'static str> {
    prop_oneof![
        Just("id"),
        Just("city"),
        Just("email"),
        Just("annual_salary"),
        Just("birth_date"),
    ]
}

/// A reducing aggregate: the family that is released as a summary, and
/// therefore the family where releasing wrongly discloses a value.
fn aggregate() -> impl Strategy<Value = &'static str> {
    prop_oneof![
        Just("sum"),
        Just("avg"),
        Just("min"),
        Just("max"),
        Just("count")
    ]
}

/// The grouping the guard will read, or `None` when it cannot be read.
///
/// This — not `analyze` — is where the spelling bugs lived, and pointing the
/// first version of these properties at `analyze` made all of them vacuous.
/// The singleton-group decision is not taken in `analyze` at all: `session`
/// combines this reader with the catalog's unique keys and passes the verdict
/// *down* as a `Relaxations` flag. So both spellings came back `Releasable`,
/// the comparison found no difference, and reverting three real disclosures
/// failed to trip a single property.
fn grouping(sql: &str) -> Option<Vec<String>> {
    StatementInspection::new(sql).group_by_columns()
}

/// Does the rewrite read a grouping that still covers everything the plain form
/// grouped by?
///
/// `None` means unbounded, which refuses, so it is always acceptable. Reading
/// *extra* names is acceptable too — over-refusal is a utility cost. Losing a
/// name is the disclosure: the guard then cannot see the key it was grouped by.
fn covers(rewritten: &Option<Vec<String>>, plain: &Option<Vec<String>>) -> bool {
    match (rewritten, plain) {
        (None, _) => true,
        (Some(_), None) => true,
        (Some(r), Some(p)) => p.iter().all(|name| r.contains(name)),
    }
}

proptest! {
    /// A meaning-preserving rewrite must not lose a grouped column.
    ///
    /// All four spelling disclosures are this one property. Each rewrite groups
    /// by the same column as the plain form, so a reader that returns fewer
    /// names for the rewrite is a guard that cannot see the key:
    ///
    ///   plain    GROUP BY id            -> ["id"]
    ///   wrapped  SELECT * FROM (…)      -> []      before 0.1.31
    ///   aliased  GROUP BY <alias of id> -> ["c"]   before 0.1.18
    #[test]
    fn no_rewrite_loses_a_grouped_column(
        agg in aggregate(),
        value in column(),
        grouped in column(),
        alias in "[a-z]{2,6}",
        wrapper in prop_oneof![Just("ROLLUP"), Just("CUBE")],
    ) {
        prop_assume!(alias != grouped && alias != value);
        let plain = format!(
            "SELECT {grouped}, {agg}({value}) FROM demo.customers GROUP BY {grouped}"
        );
        let base = grouping(&plain);

        let rewrites = [
            ("star wrapper", format!("SELECT * FROM ({plain}) q")),
            ("nested wrappers", format!("SELECT * FROM (SELECT * FROM ({plain}) a) b")),
            ("output alias", format!(
                "SELECT {grouped} AS {alias}, {agg}({value}) FROM demo.customers GROUP BY {alias}")),
            ("ordinal", format!(
                "SELECT {grouped}, {agg}({value}) FROM demo.customers GROUP BY 1")),
            ("grouping set", format!(
                "SELECT {grouped}, {agg}({value}) FROM demo.customers GROUP BY {wrapper}({grouped})")),
            ("alias in a grouping set", format!(
                "SELECT {grouped} AS {alias}, {agg}({value}) FROM demo.customers \
                 GROUP BY {wrapper}({alias})")),
        ];

        for (what, sql) in &rewrites {
            let rewritten = grouping(sql);
            prop_assert!(
                covers(&rewritten, &base),
                "{what} lost a grouped column\n  plain     {plain}\n    {base:?}\n  rewritten {sql}\n    {rewritten:?}",
            );
        }
    }

    /// Wrapping a statement in `SELECT * FROM (…)` returns the same rows, so it
    /// must not release more.
    ///
    /// This is 0.1.31 as a property. The analysis unwraps that shape and judges
    /// the subquery's targets, while the grouping was read from the outer
    /// clause — empty for a wrapper — so the guard and the classifier were
    /// looking at different statements and every salary came back.
    #[test]
    fn wrapping_in_a_star_subquery_never_releases_more(
        agg in aggregate(),
        value in column(),
        grouped in column(),
    ) {
        let plain = format!("SELECT {grouped}, {agg}({value}) FROM demo.customers GROUP BY {grouped}");
        let wrapped = format!("SELECT * FROM ({plain}) q");

        let a = analyze(&plain, 2, OPEN);
        let b = analyze(&wrapped, 2, OPEN);
        prop_assert!(
            !more_permissive(&b, &a),
            "wrapping released more than the plain form\n  plain:   {plain}\n    {a:?}\n  wrapped: {wrapped}\n    {b:?}",
        );
    }

    /// Grouping by a target's alias groups by that target, so it must not
    /// release more than grouping by the column directly.
    ///
    /// This is 0.1.18. The reader saw the literal alias, found it in no unique
    /// key, and released the aggregate.
    #[test]
    fn grouping_by_an_alias_never_releases_more(
        agg in aggregate(),
        value in column(),
        grouped in column(),
        alias in "[a-z]{1,6}",
    ) {
        prop_assume!(alias != grouped && alias != value);
        let plain = format!("SELECT {grouped}, {agg}({value}) FROM demo.customers GROUP BY {grouped}");
        let aliased = format!(
            "SELECT {grouped} AS {alias}, {agg}({value}) FROM demo.customers GROUP BY {alias}"
        );

        let a = analyze(&plain, 2, OPEN);
        let b = analyze(&aliased, 2, OPEN);
        prop_assert!(
            !more_permissive(&b, &a),
            "the alias spelling released more\n  plain:   {plain}\n    {a:?}\n  aliased: {aliased}\n    {b:?}",
        );
    }

    /// An ordinal names the same target the column reference does.
    #[test]
    fn grouping_by_an_ordinal_never_releases_more(
        agg in aggregate(),
        value in column(),
        grouped in column(),
    ) {
        let plain = format!("SELECT {grouped}, {agg}({value}) FROM demo.customers GROUP BY {grouped}");
        let ordinal = format!("SELECT {grouped}, {agg}({value}) FROM demo.customers GROUP BY 1");

        let a = analyze(&plain, 2, OPEN);
        let b = analyze(&ordinal, 2, OPEN);
        prop_assert!(
            !more_permissive(&b, &a),
            "the ordinal spelling released more\n  plain:   {plain}\n    {a:?}\n  ordinal: {ordinal}\n    {b:?}",
        );
    }

    /// `ROLLUP(x)` groups by `x` among other things, so it cannot release more
    /// than grouping by `x` does. This is the spelling that was found only by
    /// testing the fix for the previous one.
    #[test]
    fn a_grouping_set_never_releases_more(
        agg in aggregate(),
        value in column(),
        grouped in column(),
        wrapper in prop_oneof![Just("ROLLUP"), Just("CUBE")],
    ) {
        let plain = format!("SELECT {grouped}, {agg}({value}) FROM demo.customers GROUP BY {grouped}");
        let set = format!(
            "SELECT {grouped}, {agg}({value}) FROM demo.customers GROUP BY {wrapper}({grouped})"
        );

        let a = analyze(&plain, 2, OPEN);
        let b = analyze(&set, 2, OPEN);
        prop_assert!(
            !more_permissive(&b, &a),
            "the grouping-set spelling released more\n  plain: {plain}\n    {a:?}\n  set:   {set}\n    {b:?}",
        );
    }

    /// Withholding a relaxation can only ever refuse more.
    ///
    /// The session decides `summaries` and `fine_date_trunc` from policy and
    /// catalog. If turning one *off* ever released a field that leaving it on
    /// refused, the flags would not be doing what their name says, and a
    /// stricter configuration would be the less safe one.
    #[test]
    fn closing_a_relaxation_never_releases_more(
        agg in aggregate(),
        value in column(),
        grouped in column(),
        unit in prop_oneof![Just("year"), Just("month"), Just("day")],
    ) {
        for sql in [
            format!("SELECT {grouped}, {agg}({value}) FROM demo.customers GROUP BY {grouped}"),
            format!("SELECT date_trunc('{unit}', birth_date), {agg}({value}) FROM demo.customers GROUP BY 1"),
        ] {
            let open = analyze(&sql, 2, OPEN);
            for closed in [
                Relaxations { summaries: false, fine_date_trunc: true },
                Relaxations { summaries: true, fine_date_trunc: false },
                Relaxations { summaries: false, fine_date_trunc: false },
            ] {
                let shut = analyze(&sql, 2, closed);
                prop_assert!(
                    !more_permissive(&shut, &open),
                    "a closed relaxation released more than an open one\n  {sql}\n  open {open:?}\n  shut {shut:?} with {closed:?}",
                );
            }
        }
    }

    /// The analysis must not panic, whatever it is handed.
    ///
    /// `analyze` runs on client-supplied text before anything has validated it.
    /// A panic here takes the connection down.
    #[test]
    fn analysis_never_panics(sql in ".{0,200}", fields in 0usize..8) {
        let _ = analyze(&sql, fields, OPEN);
    }
}

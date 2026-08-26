//! Deciding whether an output field could be used to *read* a classified value.
//!
//! Fields with no provenance are refused. Measured against TPC-DS that refused
//! 90% of the queries — decision-support SQL is aggregate-shaped almost
//! everywhere, and an aggregate over a column has no provenance. This module
//! recovers the ones that cannot be used to read a value.
//!
//! # The threat model this encodes
//!
//! The bar is **"a masked value does not appear in a projection"**. It is not
//! "you cannot read an anonymised value", which is what this comment used to
//! say and what the README implied — and against an adversarial client that
//! claim is simply false. `scripts/test-inference.sh` measures it:
//!
//!   - `SELECT sum(salary) FROM t GROUP BY id` returned every salary exactly,
//!     in one query, when `id` is unique and released. The "group of one" trade
//!     was written down as an incidental edge case; grouping by a key made it
//!     the bulk interface. **Refused since v0.1.16** — see below.
//!   - the filter side is ungoverned, so `WHERE email LIKE 'a%'` with `count(*)`
//!     recovers a full address in **313 queries**, measured, through the proxy.
//!   - an error is a one-bit channel that needs no aggregate: `1/(CASE WHEN …
//!     THEN 0 ELSE 1 END)`.
//!
//! None of that is a defect in the rules below; every one follows from masking
//! the *projection* and leaving the predicate alone. It is recorded here
//! because the distinction decides who the tool is for: it reduces incidental
//! exposure for an analyst who is not attacking you, and it does not contain
//! one who is. Governing the filter side is the only sound answer and it is a
//! different product — it would refuse `WHERE email = …` outright.
//!
//! The one route that stays closed is the one that is decidable from the
//! statement and the catalog alone: [`StatementInspection::group_by_columns`]
//! reads the grouping, and if it covers a declared unique key — or cannot be
//! read at all — the session withholds the aggregate relaxation, so a reducing
//! aggregate is refused rather than released. That leaves real aggregation
//! untouched, which is the point of doing it this way rather than by disabling
//! summaries — and why the reader resolves ordinals and grouping sets instead
//! of refusing them, since `GROUP BY 1` and `ROLLUP(city)` are the honest form
//! of the same syntax. A grouping it still cannot read falls back to the
//! lexical backstop in the session rather than to a refusal, because refusing
//! outright took time-bucketed aggregation with it: `date_trunc` over a coarse
//! literal unit is released on purpose, so `SELECT date_trunc('month', ts),
//! sum(amount) … GROUP BY 1` worked before the guard and not after.
//!
//! Reducing aggregates *not* ruled out by that key test are released from the
//! syntactic layer into [`Safety::Summary`], and the session resolves the
//! source through one syntax-and-catalog path: a sum over an explicitly
//! qualified unmasked column is served exactly, and a sum over a masked column
//! is masked with that column's own mask. That is
//! what closes the `WHERE id = 1` form of the attack, which cannot be decided
//! from the statement and the catalog — whether a predicate matches one row is
//! a property of the data — by giving up the *precision* rather than the
//! summary: `sum(annual_salary)` collapses to the bucket floor, never the
//! exact salary, whatever the predicate.
//!
//! That relaxation is what makes this tractable without a lineage engine. If the
//! outermost node of a target expression is a reducing aggregate, it cannot
//! return a stored value *whatever is inside it* once the *output* is masked,
//! so the source only has to be named, never reconstructed.
//!
//! # Why an allowlist of shapes, and not "does it reference a column?"
//!
//! The obvious rule is "walk the expression; if it contains no `ColumnRef` it
//! cannot leak a column". That requires an *exhaustive* traversal, and
//! `pg_query`'s own walker documents that it "doesn't iterate over every
//! possible node type". Proving absence across an incomplete traversal is
//! unsound, and this rule converts refusals into acceptances — so unsound means
//! a leak, not a false pass.
//!
//! So the burden is inverted. Rather than prove no column is referenced, we
//! match a short list of expression shapes that are *positively known* to carry
//! no column data. Anything not on the list stays refused. Adding a shape is a
//! deliberate, reviewable act; forgetting one costs utility, never safety.
//!
//! # How this module uses pg_query
//!
//! Parse and scan come from the library (`pg_query::parse`, `pg_query::scan`,
//! protobuf `Node` types). `pg_query`'s `nodes()` iterator is **not** used to
//! prove absence: upstream documents that it "doesn't iterate over every
//! possible node type", and a skipped node is an allow. Hostile / read-only /
//! write gates share one local descent (`walk_tree`) over those protobuf
//! fields. [`StatementInspection`] caches the parse so the session does not
//! re-parse the same SQL for each gate.

use std::collections::HashSet;
use std::sync::OnceLock;

use pg_query::protobuf::node::Node as NodeEnum;
use pg_query::protobuf::{SelectStmt, Token};

mod catalog_surface;
mod catalogs;
mod frontend;
mod hostile;
mod json_extract;
mod lineage_shape;
mod names;
mod safety;
mod walk;

use walk::walk_parsed;

pub use catalog_surface::{VANILLA_INFORMATION_SCHEMA, VANILLA_PG_CATALOG};
pub use catalogs::{
    every_relation_is_qualified, provenance_is_trustworthy, reads_only_server_metadata,
    touches_leaky_system_catalog,
};
pub use frontend::{
    calls_untrusted_function, is_procedural_statement, is_sql_prepare_or_cursor, is_write_statement,
};
pub use hostile::{
    hostile_join_or_rename_masked, hostile_uses_whole_row, masked_exceeds_outer_projection,
};
pub use json_extract::{
    JsonExtract, JsonExtractArgument, JsonExtractColumn, JsonExtractPathSegment,
    JsonExtractResolution, QualifiedFrom,
};
pub use safety::{analyze, Relaxations, Safety};

pub(crate) use lineage_shape::output_lineage_is_closed;

use catalogs::{
    every_relation_is_qualified_inspected, provenance_is_trustworthy_inspected,
    reads_only_server_metadata_inspected, touches_leaky_system_catalog_inspected,
};
use frontend::{
    calls_untrusted_function_inspected, is_sql_prepare_or_cursor_inspected,
    is_write_statement_inspected,
};
use hostile::{
    hostile_join_or_rename_masked_inspected, hostile_uses_whole_row_inspected,
    masked_exceeds_outer_projection_inspected,
};
use safety::{
    analyze_inspected, group_item_columns, positions_are_trustworthy, summary_argument_name,
    unwrap_star_over_subquery,
};

/// One parsed and lazily scanned view of a statement for a release decision.
///
/// A `RowDescription` asks several independent safety questions. Keeping their
/// conservative rules separate is useful; reparsing the same SQL for each one
/// is not. This module gives those checks one deep interface while preserving
/// their independent implementations.
pub struct StatementInspection<'sql> {
    sql: &'sql str,
    parsed: OnceLock<Option<pg_query::ParseResult>>,
    identifiers: OnceLock<Option<Vec<String>>>,
}

impl<'sql> StatementInspection<'sql> {
    /// The columns a top-level `GROUP BY` groups on.
    ///
    /// `Some([])` means there is no grouping. `None` means there is one but it
    /// cannot be reduced to plain column names, and the caller must treat that
    /// as possibly-singleton, because a grouping it cannot read is a grouping
    /// it cannot clear.
    ///
    /// Read off the top-level `SelectStmt`'s `group_clause` rather than walked.
    /// That matters: the walker has documented gaps, and a missed `GROUP BY`
    /// here would look like "no grouping" and release exactly the aggregate
    /// this exists to catch. A direct field read has nothing to miss.
    ///
    /// Read from the statement `analyze_inspected` actually judges: it unwraps
    /// `SELECT * FROM (subselect)` before classifying, so the grouping has to be
    /// taken from the same place or the two halves of the guard disagree. This
    /// used to say that an aggregate inside a subquery "is not the released
    /// field", which the unwrapping in this module had already falsified.
    ///
    /// Three shapes are readable, because refusing them costs real queries:
    /// a column reference, an ordinal into the target list (`GROUP BY 1` is
    /// idiomatic), and `ROLLUP`/`CUBE`/`GROUPING SETS` over either. For a
    /// grouping set the names are unioned across every set, which is the safe
    /// direction: each set is a subset of the union, so a key contained in any
    /// one of them is contained in the union.
    ///
    /// An arbitrary expression stays unreadable. Collecting the columns beneath
    /// it needs a complete traversal, and this file exists because proving
    /// absence across `pg_query`'s incomplete walker is how three disclosures
    /// got in. The cost is small in practice: a query grouping by an expression
    /// almost always selects it too, and an expression target has no provenance,
    /// so it was already refused a step earlier for its own reasons.
    pub fn group_by_columns(&self) -> Option<Vec<String>> {
        let parsed = self.parsed()?;
        let [statement] = parsed.protobuf.stmts.as_slice() else {
            return Some(Vec::new());
        };
        let Some(NodeEnum::SelectStmt(select)) =
            statement.stmt.as_ref().and_then(|s| s.node.as_ref())
        else {
            return Some(Vec::new());
        };

        // The same statement `analyze_inspected` judges, not the one the client
        // wrote. It unwraps `SELECT * FROM (subselect)` and classifies the
        // *subquery's* target list, so the released aggregate can live inside
        // the subquery — while this used to read the outer `group_clause`,
        // which is empty for the wrapper, and report "no grouping".
        //
        // That put the two halves of the guard on different statements and
        // restored the 0.1.16 disclosure verbatim:
        //
        //   SELECT id, sum(annual_salary) FROM demo.customers GROUP BY id
        //     -> refused
        //   SELECT * FROM (SELECT id, sum(annual_salary) FROM demo.customers
        //                  GROUP BY id) q
        //     -> served, every salary exactly
        //
        // The comment above this function used to argue the case could not
        // arise — "an aggregate inside a subquery is not the released field" —
        // and the unwrapping in the same module had already made that false.
        let mut select: &SelectStmt = select;
        while let Some(inner) = unwrap_star_over_subquery(select) {
            select = inner;
        }

        if select.group_clause.is_empty() {
            return Some(Vec::new());
        }
        let mut columns = Vec::with_capacity(select.group_clause.len());
        for item in &select.group_clause {
            group_item_columns(item, &select.target_list, &mut columns)?;
        }
        Some(columns)
    }

    pub fn new(sql: &'sql str) -> Self {
        Self {
            sql,
            parsed: OnceLock::new(),
            identifiers: OnceLock::new(),
        }
    }

    pub fn sql(&self) -> &'sql str {
        self.sql
    }

    pub fn is_parseable(&self) -> bool {
        self.parsed().is_some()
    }

    pub fn identifiers(&self) -> Option<&[String]> {
        self.identifiers
            .get_or_init(|| scan_identifiers(self.sql))
            .as_deref()
    }

    /// Names the lineage backstop may treat as column or relation mentions.
    ///
    /// The token stream is the complete source of *spellings in the text*, and
    /// the parse tree is the complete source of *decoded* names (`u&"email"`
    /// is `email` on a `ColumnRef`). Either source alone has a blind spot the
    /// other covers; a name either of them reports is a name the statement
    /// mentioned. `None` when even the scanner cannot read the text.
    pub fn backstop_identifiers(&self) -> Option<Vec<String>> {
        let mut names = self.identifiers()?.to_vec();
        if let Some(parsed) = self.parsed() {
            names.extend(tree_identifier_names(parsed));
        }
        Some(names)
    }

    pub fn output_safety(&self, field_count: usize, allow: Relaxations) -> Vec<Safety> {
        analyze_inspected(self, field_count, allow)
    }

    /// Resolution material for a reducing aggregate over a single bare column.
    ///
    /// [`Safety::Summary`] is reached without the catalog, because analysis does
    /// not resolve names. Mask selection deliberately does not come from a
    /// blocked lineage verdict: that verdict can describe several inputs or a
    /// transformed input, and one source's mask is not a policy for the result.
    ///
    /// The resolver below needs no `sqllineage`: an aggregate over one bare
    /// column is attributable from the statement and the catalog alone. It
    /// returns, for the one trusted select, the explicitly schema-qualified
    /// FROM relations `(schema, relname)` and, aligned to `field_count`, the bare
    /// column each field reduces when the field is exactly such an aggregate
    /// (`cast(sum(x) AS bigint)` is; an expression or multi-argument aggregate
    /// keeps the opaque posture).
    ///
    /// Any parse doubt — a set operation, a star, an unqualified relation (which
    /// needs the session's `search_path`), or a FROM entry that is not a plain
    /// named range — collapses the whole thing to `None`, and the caller keeps
    /// its normal opaque posture.
    pub fn summary_resolution(&self, field_count: usize) -> Option<SummaryResolution> {
        let parsed = self.parsed()?;
        if parsed.protobuf.stmts.len() != 1 {
            return None;
        }
        let NodeEnum::SelectStmt(select) = parsed
            .protobuf
            .stmts
            .first()
            .and_then(|s| s.stmt.as_ref())
            .and_then(|s| s.node.as_ref())?
        else {
            return None;
        };
        // Same unwrap as `analyze_inspected`: `SELECT * FROM (subquery)`.
        let mut select: &SelectStmt = select;
        while let Some(inner) = unwrap_star_over_subquery(select) {
            select = inner;
        }
        if !positions_are_trustworthy(select, field_count) {
            return None;
        }
        let mut relations = Vec::with_capacity(select.from_clause.len());
        for entry in &select.from_clause {
            let NodeEnum::RangeVar(range) = entry.node.as_ref()? else {
                // A subquery, join, function or lateral in FROM is lineage's
                // territory; this backstop only handles plain named ranges.
                return None;
            };
            // The proxy does not track `search_path`. Treating an unqualified
            // `payroll` as `public.payroll` can apply that relation's weaker
            // mask to a value actually read from `private.payroll`.
            if range.schemaname.is_empty() {
                return None;
            }
            relations.push((range.schemaname.clone(), range.relname.clone()));
        }
        let fields = select
            .target_list
            .iter()
            .map(|entry| match entry.node.as_ref() {
                Some(NodeEnum::ResTarget(target)) => target
                    .val
                    .as_ref()
                    .and_then(|v| v.node.as_ref())
                    .and_then(|expr| summary_argument_name(expr, 0))
                    .map_or(SummaryArgument::Unattributable, SummaryArgument::BareColumn),
                _ => SummaryArgument::Unattributable,
            })
            .collect();
        Some(SummaryResolution { relations, fields })
    }

    pub fn reads_only_server_metadata(&self) -> bool {
        reads_only_server_metadata_inspected(self)
    }

    pub fn provenance_is_trustworthy(&self) -> bool {
        provenance_is_trustworthy_inspected(self)
    }

    pub fn every_relation_is_qualified(&self) -> bool {
        every_relation_is_qualified_inspected(self)
    }

    pub fn is_write_statement(&self) -> bool {
        is_write_statement_inspected(self)
    }

    pub fn is_sql_prepare_or_cursor(&self) -> bool {
        is_sql_prepare_or_cursor_inspected(self)
    }

    pub fn calls_untrusted_function(&self) -> bool {
        calls_untrusted_function_inspected(self)
    }

    pub fn touches_leaky_system_catalog(&self) -> bool {
        touches_leaky_system_catalog_inspected(self)
    }

    pub fn masked_exceeds_outer_projection(&self, masked: &HashSet<String>) -> bool {
        masked_exceeds_outer_projection_inspected(self, masked)
    }

    pub fn hostile_uses_whole_row(
        &self,
        relation_columns: &std::collections::HashMap<String, Vec<String>>,
    ) -> bool {
        hostile_uses_whole_row_inspected(self, relation_columns)
    }

    pub fn hostile_join_or_rename_masked(
        &self,
        relation_columns: &std::collections::HashMap<String, Vec<String>>,
        masked: &HashSet<String>,
    ) -> bool {
        hostile_join_or_rename_masked_inspected(self, relation_columns, masked)
    }

    pub(crate) fn parsed(&self) -> Option<&pg_query::ParseResult> {
        self.parsed
            .get_or_init(|| pg_query::parse(self.sql).ok())
            .as_ref()
    }
}

/// Syntax-level attribution for reducing aggregates in one result set.
///
/// This is deliberately not an anonymous pair of parallel vectors: callers
/// must name whether they are asking about FROM relations or result fields,
/// and each field says explicitly whether its argument can be attributed.
pub struct SummaryResolution {
    relations: Vec<(String, String)>,
    fields: Vec<SummaryArgument>,
}

impl SummaryResolution {
    pub fn relations(&self) -> &[(String, String)] {
        &self.relations
    }

    pub fn fields(&self) -> &[SummaryArgument] {
        &self.fields
    }
}

/// The only aggregate argument shape whose catalog policy can safely govern a
/// reducing result. Everything else retains the opaque posture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SummaryArgument {
    BareColumn(String),
    Unattributable,
}

/// Whether `pg_query` can parse the statement at all.
///
/// The lexer scans nonsense happily, so a caller that needs "we could not read
/// this, so it could reference anything" has to ask the parser separately.
pub fn is_parseable(sql: &str) -> bool {
    StatementInspection::new(sql).is_parseable()
}

/// Every identifier the statement mentions, from the **lexer**.
///
/// Table names, aliases, function names and column names, undifferentiated.
/// That is deliberate: this is a backstop, and over-naming costs a refusal
/// while under-naming costs a disclosure.
///
/// **Why the lexer and not the parse tree alone.** The first version of this
/// walked `pg_query`'s node tree for `ColumnRef`s, and the containment test in
/// `tests/lineage_superset.rs` immediately caught it missing `id` in
///
/// ```sql
/// SELECT sum(n) OVER (ORDER BY id ROWS BETWEEN CURRENT ROW AND CURRENT ROW) FROM t
/// ```
///
/// — the walker does not descend into a `WindowDef`. That is the traversal gap
/// this module's header warns about, and a backstop with a blind spot is not a
/// backstop. The token stream has no such gap: every identifier in the text is
/// a token, whatever the grammar does with it afterwards.
///
/// The token stream still has to *name* what it sees. Unicode-escaped
/// identifiers (`u&"email"`, `u&"e\006dail"`) are one token whose source
/// spelling is not the catalog name; leaving them unnamed let
/// `lineage = "allow"` release `city || (SELECT u&"email" …)` because
/// `sqllineage` does not look inside the subquery and the backstop never
/// saw `email`. They are decoded here. An encoding we cannot decode — a
/// malformed `u&"…"` or a `UESCAPE` clause that redefines the escape
/// character — fails the whole scan, which callers treat as "could mention
/// anything".
///
/// The lineage backstop unions this set with decoded parse-tree names
/// ([`StatementInspection::backstop_identifiers`]) so a name either source
/// reports is a name the statement mentioned. Hostile counting stays on
/// this function so a unicode ident is still one mention, not two.
///
/// `None` when the text cannot even be scanned, which the caller must treat as
/// "could mention anything".
pub fn referenced_identifiers(sql: &str) -> Option<Vec<String>> {
    scan_identifiers(sql)
}

fn scan_identifiers(sql: &str) -> Option<Vec<String>> {
    let scanned = pg_query::scan(sql).ok()?;
    let mut names = Vec::new();
    for token in &scanned.tokens {
        if token.token == Token::Uescape as i32 {
            // `U&"d!0061t" UESCAPE '!'` is `dat`. We do not apply a caller-chosen
            // escape; naming the wrong identifier would be a release.
            return None;
        }
        let start = usize::try_from(token.start).ok()?;
        let end = usize::try_from(token.end).ok()?;
        let text = sql.get(start..end)?;
        // `UIDENT`, or any token whose source is spelled as one: an encoding
        // we do not recognise is a name we cannot clear.
        if token.token == Token::Uident as i32 || is_unicode_ident_spelling(text) {
            names.push(decode_unicode_ident(text)?);
            continue;
        }
        // Not `token() == Ident`. Two whole classes of name are not
        // `Ident`, and an audit found both:
        //
        //   * a *quoted* name's span includes its quotes, so `"email"`
        //     never matched the catalog's `email`
        //   * pg_query lexes unreserved keywords as their own token
        //     types, so a column called `value`, `source`, `name`,
        //     `comment`, `owner` or `year` produced no token at all
        //
        // Either one silently reopened the hole this function exists to
        // close, and neither is exotic — every ORM quotes identifiers,
        // and `comment` and `source` are ordinary column names.
        //
        // So the rule is textual rather than grammatical: anything
        // shaped like a name counts, keyword or not. Over-naming costs
        // a refusal; under-naming is a disclosure.
        if let Some(inner) = text.strip_prefix('"').and_then(|t| t.strip_suffix('"')) {
            // `""` is an escaped quote inside a quoted identifier.
            names.push(inner.replace("\"\"", "\"").to_ascii_lowercase());
            continue;
        }
        let word = !text.is_empty()
            && text.starts_with(|c: char| c.is_alphabetic() || c == '_')
            && text
                .chars()
                .all(|c| c.is_alphanumeric() || c == '_' || c == '$');
        if word {
            names.push(text.to_ascii_lowercase());
        }
    }
    Some(names)
}

fn is_unicode_ident_spelling(text: &str) -> bool {
    text.starts_with("u&") || text.starts_with("U&")
}

/// Decode `u&"email"` / `U&"e\006dail"` to the catalog name `email`.
///
/// `\XXXX` is four hex digits, `\+XXXXXX` is six. `""` is a literal quote.
/// A doubled escape is a literal escape. Anything else fails closed.
fn decode_unicode_ident(text: &str) -> Option<String> {
    let body = text
        .strip_prefix("u&")
        .or_else(|| text.strip_prefix("U&"))?;
    let inner = body.strip_prefix('"')?.strip_suffix('"')?;
    decode_unicode_ident_body(inner, '\\').map(|name| name.to_ascii_lowercase())
}

fn decode_unicode_ident_body(inner: &str, escape: char) -> Option<String> {
    let mut out = String::new();
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        if c == '"' {
            if chars.next() == Some('"') {
                out.push('"');
                continue;
            }
            return None;
        }
        if c != escape {
            out.push(c);
            continue;
        }
        match chars.next()? {
            '+' => out.push(hex_codepoint(&mut chars, 6)?),
            c if c == escape => out.push(escape),
            c => {
                // The consumed char is the first of four hex digits.
                let mut value = c.to_digit(16)?;
                for _ in 0..3 {
                    value = value
                        .saturating_mul(16)
                        .saturating_add(chars.next()?.to_digit(16)?);
                }
                out.push(char::from_u32(value)?);
            }
        }
    }
    Some(out)
}

fn hex_codepoint(chars: &mut std::str::Chars<'_>, width: usize) -> Option<char> {
    let mut value = 0u32;
    for _ in 0..width {
        value = value
            .saturating_mul(16)
            .saturating_add(chars.next()?.to_digit(16)?);
    }
    char::from_u32(value)
}

/// Decoded names the parse tree reports: `ColumnRef` fields (unicode escapes
/// already expanded), alias / `USING` `String` nodes, `ColumnDef` names, and
/// `RangeVar` relation names.
///
/// Complements [`scan_identifiers`]. The tree names what the token stream
/// spelled as `u&"email"`; the token stream names `id` inside a `WindowDef`
/// the walker historically skipped. Union is the backstop; either source
/// alone is how this leaked.
fn tree_identifier_names(parsed: &pg_query::ParseResult) -> Vec<String> {
    let mut names = Vec::new();
    walk_parsed(parsed, &mut |node| match node.node.as_ref() {
        Some(NodeEnum::ColumnRef(column)) => {
            for field in &column.fields {
                if let Some(NodeEnum::String(s)) = field.node.as_ref() {
                    names.push(s.sval.to_ascii_lowercase());
                }
            }
        }
        Some(NodeEnum::String(s)) => names.push(s.sval.to_ascii_lowercase()),
        Some(NodeEnum::ColumnDef(def)) => names.push(def.colname.to_ascii_lowercase()),
        Some(NodeEnum::RangeVar(range)) => {
            if !range.relname.is_empty() {
                names.push(range.relname.to_ascii_lowercase());
            }
            if !range.schemaname.is_empty() {
                names.push(range.schemaname.to_ascii_lowercase());
            }
        }
        _ => {}
    });
    names
}

#[cfg(test)]
mod provenance_trust_tests;
#[cfg(test)]
mod referenced_identifier_probe;
#[cfg(test)]
mod tests;

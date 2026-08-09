//! The Phase 0 query-shape matrix.
//!
//! Each shape asks one question: when Postgres describes this result set, does
//! it still tell us which stored column each output field came from?
//!
//! `expect` is our prior, not an assertion — the point of the spike is to find
//! where the prior is wrong, so the runner flags disagreements.

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Expect {
    /// table_oid/attnum populated: we can classify and mask this.
    Provenance,
    /// 0/0 — a computed expression. Masking must refuse.
    Opaque,
    /// Genuinely don't know. This is why the spike exists.
    Unknown,
}

pub struct Shape {
    pub id: &'static str,
    pub group: &'static str,
    pub sql: &'static str,
    /// Statements run before `sql` on the same session (transactions, temp DDL).
    pub setup: &'static [&'static str],
    /// Best-effort cleanup after `sql`.
    pub teardown: &'static [&'static str],
    pub expect: Expect,
}

const NONE: &[&str] = &[];

macro_rules! shape {
    ($id:expr, $group:expr, $expect:expr, $sql:expr) => {
        Shape {
            id: $id,
            group: $group,
            sql: $sql,
            setup: NONE,
            teardown: NONE,
            expect: $expect,
        }
    };
    ($id:expr, $group:expr, $expect:expr, $sql:expr, setup = $setup:expr, teardown = $teardown:expr) => {
        Shape {
            id: $id,
            group: $group,
            sql: $sql,
            setup: $setup,
            teardown: $teardown,
            expect: $expect,
        }
    };
}

use Expect::*;

pub const SHAPES: &[Shape] = &[
    // --- Baselines ---------------------------------------------------------
    shape!("baseline", "baseline", Provenance, "SELECT email FROM t"),
    // If * works, it is free for us — and costs a parser-based design real effort.
    shape!("star", "baseline", Provenance, "SELECT * FROM t"),
    // Confirms the catalog must key on (oid, attnum), never on output name.
    shape!(
        "aliased",
        "baseline",
        Provenance,
        "SELECT email AS contact_email FROM t"
    ),
    shape!(
        "qualified",
        "baseline",
        Provenance,
        "SELECT a.email FROM t a"
    ),
    shape!(
        "join",
        "baseline",
        Provenance,
        "SELECT t.email, u.note FROM t JOIN u ON u.t_id = t.id"
    ),
    shape!(
        "distinct",
        "baseline",
        Unknown,
        "SELECT DISTINCT email FROM t"
    ),
    // RowDescription must arrive even with no DataRows.
    shape!(
        "empty_result",
        "baseline",
        Provenance,
        "SELECT email FROM t WHERE false"
    ),
    // --- Subqueries and CTEs -----------------------------------------------
    shape!(
        "subquery_flat",
        "subquery",
        Unknown,
        "SELECT email FROM (SELECT email FROM t) q"
    ),
    // The important one: if flattening is what preserves provenance, this breaks.
    shape!(
        "subquery_nonflat",
        "subquery",
        Unknown,
        "SELECT email FROM (SELECT email FROM t OFFSET 0) q"
    ),
    shape!(
        "cte",
        "subquery",
        Unknown,
        "WITH c AS (SELECT email FROM t) SELECT email FROM c"
    ),
    shape!(
        "cte_materialized",
        "subquery",
        Unknown,
        "WITH c AS MATERIALIZED (SELECT email FROM t) SELECT email FROM c"
    ),
    shape!(
        "cte_recursive",
        "subquery",
        Unknown,
        "WITH RECURSIVE c(id, email) AS (
           SELECT id, email FROM t WHERE id = 1
           UNION ALL
           SELECT t.id, t.email FROM t JOIN c ON t.id = c.id + 1
         )
         SELECT id, email FROM c"
    ),
    // --- Set operations ----------------------------------------------------
    shape!(
        "union_all",
        "setop",
        Unknown,
        "SELECT email FROM t UNION ALL SELECT email FROM t"
    ),
    shape!(
        "union",
        "setop",
        Unknown,
        "SELECT email FROM t UNION SELECT email FROM t"
    ),
    shape!(
        "intersect",
        "setop",
        Unknown,
        "SELECT email FROM t INTERSECT SELECT email FROM t"
    ),
    shape!(
        "except",
        "setop",
        Unknown,
        "SELECT email FROM t EXCEPT SELECT email FROM t WHERE id > 2"
    ),
    // --- Views -------------------------------------------------------------
    // CRITICAL: view OID or base table OID? Decides whether the catalog needs
    // view entries.
    shape!("view", "view", Unknown, "SELECT email FROM v_t"),
    shape!("view_star", "view", Unknown, "SELECT * FROM v_t"),
    shape!("view_nested", "view", Unknown, "SELECT email FROM v_nested"),
    shape!("matview", "view", Unknown, "SELECT email FROM mv_t"),
    // A set operation hidden in a view. If this reports provenance, then the
    // reported column is one of two sources for the field, and any rule on it
    // releases both — which is a leak on any engine, not just CockroachDB.
    shape!("view_union", "view", Unknown, "SELECT v FROM v_union"),
    shape!(
        "view_over_union",
        "view",
        Unknown,
        "SELECT v FROM v_over_union"
    ),
    // --- Partitioning ------------------------------------------------------
    // Parent OID or child OID? If child, catalog resolution walks the hierarchy.
    shape!(
        "partition_parent",
        "partition",
        Unknown,
        "SELECT email FROM p"
    ),
    shape!(
        "partition_child",
        "partition",
        Provenance,
        "SELECT email FROM p_west"
    ),
    // --- Expressions -------------------------------------------------------
    // A no-op cast may or may not survive as a bare Var.
    shape!("cast", "expression", Unknown, "SELECT email::text FROM t"),
    shape!("lower", "expression", Opaque, "SELECT lower(email) FROM t"),
    shape!("concat", "expression", Opaque, "SELECT email || '' FROM t"),
    shape!(
        "coalesce",
        "expression",
        Opaque,
        "SELECT COALESCE(email, '') FROM t"
    ),
    // Semantically leaks email but is opaque to provenance — the fail-closed case.
    shape!(
        "case",
        "expression",
        Opaque,
        "SELECT CASE WHEN id > 1 THEN email ELSE NULL END FROM t"
    ),
    shape!(
        "window",
        "expression",
        Unknown,
        "SELECT email, row_number() OVER (ORDER BY id) FROM t"
    ),
    shape!(
        "group_by",
        "expression",
        Unknown,
        "SELECT city, count(*) FROM t GROUP BY city"
    ),
    // string_agg leaks every value, count does not. Provenance cannot tell them
    // apart — policy must.
    shape!(
        "aggregates",
        "expression",
        Opaque,
        "SELECT count(*), count(email), string_agg(email, ',') FROM t"
    ),
    // --- Functions ---------------------------------------------------------
    shape!(
        "fn_setof_table",
        "function",
        Unknown,
        "SELECT * FROM f_setof_t()"
    ),
    shape!(
        "fn_table_out",
        "function",
        Opaque,
        "SELECT * FROM f_table_out()"
    ),
    shape!(
        "fn_srf_target",
        "function",
        Unknown,
        "SELECT email, f_srf() FROM t"
    ),
    // --- Lateral -----------------------------------------------------------
    shape!(
        "lateral",
        "lateral",
        Unknown,
        "SELECT t.email, x.note
         FROM t, LATERAL (SELECT note FROM u WHERE u.t_id = t.id LIMIT 1) x"
    ),
    // --- Session-scoped relations ------------------------------------------
    // Temp OIDs are per-session — the catalog can never contain them. This is a
    // fail-closed target, not a masking target.
    shape!(
        "temp_table",
        "session",
        Provenance,
        "SELECT email FROM tmp_t",
        setup = &[
            "CREATE TEMP TABLE IF NOT EXISTS tmp_t (id int, email text)",
            "INSERT INTO tmp_t VALUES (1, 'temp@example.com')",
        ],
        teardown = NONE
    ),
    // Rows arrive detached from the originating statement. Does FETCH describe them?
    shape!(
        "cursor",
        "session",
        Unknown,
        "FETCH ALL FROM spike_cur",
        setup = &["BEGIN", "DECLARE spike_cur CURSOR FOR SELECT email FROM t"],
        teardown = &["CLOSE spike_cur", "COMMIT"]
    ),
    // --- Extended protocol -------------------------------------------------
    // Every shape above already goes through Parse/Describe; this one carries a
    // bound parameter so Bind/Execute is exercised too.
    shape!(
        "extended_param",
        "protocol",
        Provenance,
        "SELECT email FROM t WHERE id = 1"
    ),
];

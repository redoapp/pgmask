#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

#[test]
fn inspection_parse_and_scan_failures_make_every_fact_conservative() {
    let inspection = StatementInspection::new("SELECT \0");
    assert!(!inspection.is_parseable());
    assert!(inspection.identifiers().is_none());
    assert!(!inspection.reads_only_server_metadata());
    assert!(!inspection.provenance_is_trustworthy());
    assert!(!inspection.every_relation_is_qualified());
    assert_eq!(
        inspection.output_safety(2, ALLOW_ALL),
        vec![Safety::Unknown; 2]
    );
}

// --- system catalogs ---------------------------------------------------

#[test]
fn metadata_only_catalog_queries_are_released() {
    // The shapes psql actually sends. Each is full of expressions that
    // output classification cannot judge.
    for sql in [
        "SELECT n.nspname, c.relname, pg_catalog.pg_get_userbyid(c.relowner) \
         FROM pg_catalog.pg_class c \
         JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace",
        "SELECT a.attname, pg_catalog.format_type(a.atttypid, a.atttypmod) \
         FROM pg_catalog.pg_attribute a WHERE a.attrelid = 1",
        "SELECT pg_catalog.pg_get_viewdef(c.oid) FROM pg_catalog.pg_class c",
        "SELECT pg_catalog.pg_get_indexdef(i.indexrelid) FROM pg_catalog.pg_index i",
        "SELECT * FROM generate_series(1, 3) g, pg_catalog.pg_class c",
        "SELECT table_name FROM information_schema.tables",
        "SELECT rolname FROM pg_roles",
        "SELECT * FROM information_schema.user_mappings",
        "SELECT * FROM information_schema.foreign_servers",
        "SELECT * FROM information_schema.foreign_tables",
        "SELECT * FROM information_schema.foreign_data_wrappers",
        "SELECT column_name FROM information_schema.columns",
        "SELECT c.oid FROM pg_catalog.pg_class c JOIN pg_catalog.pg_statistic_ext e \
         ON e.stxrelid = c.oid",
    ] {
        assert!(reads_only_server_metadata(sql), "should be released: {sql}");
    }
}

#[test]
fn catalogs_that_carry_user_data_are_not_released() {
    // pg_stats returns most_common_vals and histogram_bounds — literal
    // values sampled out of the user's tables, including the ones the proxy
    // pseudonymises. Measured on the demo database, not assumed.
    for sql in [
        "SELECT most_common_vals FROM pg_catalog.pg_stats",
        "SELECT stavalues1 FROM pg_catalog.pg_statistic",
        "SELECT stxdmcv FROM pg_catalog.pg_statistic_ext_data",
        "SELECT rolpassword FROM pg_catalog.pg_authid",
        "SELECT query FROM pg_catalog.pg_stat_activity",
        "SELECT data FROM pg_catalog.pg_largeobject",
        "SELECT umoptions FROM pg_catalog.pg_user_mappings",
        "SELECT subconninfo FROM pg_catalog.pg_subscription",
        "SELECT statement FROM pg_catalog.pg_cursors",
        "SELECT statement FROM pg_cursors",
        r#"SELECT statement FROM u&"pg_cursors""#,
        "SELECT conninfo FROM pg_catalog.pg_stat_wal_receiver",
        "SELECT passwd FROM pg_user",
        "SELECT * FROM pg_catalog.pg_user",
        "EXPLAIN SELECT most_common_vals FROM pg_catalog.pg_stats",
        "SELECT chunk_data FROM pg_toast.pg_toast_12345",
        "SELECT count(*) FROM pg_toast.pg_toast_12345 WHERE chunk_data LIKE '%@%'",
        "SELECT * FROM pg_toast_12345",
        r#"SELECT * FROM u&"pg_toast".u&"pg_toast_12345""#,
        "SELECT srvoptions FROM pg_catalog.pg_foreign_server",
        "SELECT fdwoptions FROM pg_foreign_data_wrapper",
        r#"SELECT srvoptions FROM u&"pg_foreign_server""#,
        "EXPLAIN SELECT chunk_data FROM pg_toast.pg_toast_12345",
        "SELECT option_value FROM information_schema.user_mapping_options",
        "SELECT * FROM information_schema.foreign_server_options",
        "SELECT * FROM information_schema.foreign_data_wrapper_options",
        r#"SELECT * FROM information_schema.u&"user_mapping_options""#,
        "SELECT option_value FROM user_mapping_options",
        "SELECT option_value FROM information_schema.column_options",
        "SELECT * FROM information_schema.foreign_table_options",
        r#"SELECT * FROM information_schema.u&"column_options""#,
        "SELECT option_value FROM column_options",
        "SELECT umoptions FROM information_schema._pg_user_mappings",
        "SELECT srvoptions FROM information_schema._pg_foreign_servers",
        "SELECT fdwoptions FROM information_schema._pg_foreign_data_wrappers",
        "SELECT ftoptions FROM information_schema._pg_foreign_tables",
        "SELECT attfdwoptions FROM information_schema._pg_foreign_table_columns",
        "SELECT umoptions FROM _pg_user_mappings",
        r#"SELECT * FROM information_schema.u&"_pg_user_mappings""#,
        "EXPLAIN SELECT * FROM information_schema.column_options",
        // Prefix, not the name list: a future `_pg_foreign_*` wrapper.
        "SELECT * FROM information_schema._pg_foreign_future",
        "SELECT * FROM _pg_foreign_future",
    ] {
        assert!(
            !reads_only_server_metadata(sql),
            "must not be released: {sql}"
        );
        assert!(
            touches_leaky_system_catalog(sql),
            "must be frontend-refused: {sql}"
        );
    }
}

#[test]
fn a_user_table_anywhere_disqualifies_the_whole_statement() {
    for sql in [
        "SELECT c.email FROM demo.customers c JOIN pg_catalog.pg_class k ON true",
        "SELECT relname FROM pg_catalog.pg_class WHERE relname IN (SELECT email FROM demo.customers)",
        "SELECT (SELECT email FROM demo.customers LIMIT 1) FROM pg_catalog.pg_class",
        // `pg_query::nodes()` does not enter LIMIT / window frames.
        "SELECT relname FROM pg_catalog.pg_class LIMIT (SELECT email FROM demo.customers)",
        "SELECT relname, count(*) OVER (PARTITION BY (SELECT email FROM demo.customers LIMIT 1)) FROM pg_catalog.pg_class",
    ] {
        assert!(!reads_only_server_metadata(sql), "must not be released: {sql}");
    }
}

#[test]
fn an_unqualified_catalog_name_passes_here_and_is_settled_by_oids() {
    // Harlequin writes `from pg_database`. Refusing it outright locked out a
    // real client; accepting it on the name alone would be exploitable via
    // `SET search_path TO public, pg_catalog` against a user-owned
    // `public.pg_database`. So this layer lets the name through and
    // session.rs confirms the RowDescription OID really is a system relation.
    assert!(reads_only_server_metadata(
        "SELECT datname FROM pg_database"
    ));
    assert!(reads_only_server_metadata(
        "SELECT relname FROM pg_catalog.pg_class"
    ));
    // A bare name that is not even catalog-shaped is still refused here.
    assert!(!reads_only_server_metadata("SELECT email FROM customers"));
}

#[test]
fn qualification_is_reported_for_the_all_expressions_case() {
    assert!(every_relation_is_qualified(
        "SELECT pg_catalog.pg_get_userbyid(c.relowner) FROM pg_catalog.pg_class c"
    ));
    assert!(!every_relation_is_qualified(
        "SELECT upper(datname) FROM pg_database"
    ));
    assert!(every_relation_is_qualified(
        "WITH k AS (SELECT oid FROM pg_catalog.pg_class) SELECT count(*) FROM k"
    ));
    assert!(!every_relation_is_qualified(
        "SELECT 1 FROM pg_catalog.pg_class LIMIT (SELECT 1 FROM t)"
    ));
}

#[test]
fn functions_that_take_sql_as_a_string_are_refused() {
    // The parse tree has no RangeVar for `demo.customers` here, so without
    // the escape list the entire rule is bypassable in one call.
    for sql in [
        "SELECT pg_catalog.query_to_xml('SELECT email FROM demo.customers', false, true, '') \
         FROM pg_catalog.pg_class",
        "SELECT table_to_xml('demo.customers'::regclass, false, true, '') \
         FROM pg_catalog.pg_class",
        "SELECT schema_to_xml('demo', false, true, '') FROM pg_catalog.pg_class",
        "SELECT database_to_xml(false, true, '') FROM pg_catalog.pg_class",
        "SELECT pg_read_file('/etc/passwd') FROM pg_catalog.pg_class",
        "SELECT dblink('', 'SELECT email FROM demo.customers') FROM pg_catalog.pg_class",
        "SELECT pg_stat_get_activity(NULL) FROM pg_catalog.pg_class",
        "SELECT pg_ls_logdir() FROM pg_catalog.pg_class",
        "SELECT pg_logical_slot_get_changes('s', NULL, NULL) FROM pg_catalog.pg_class",
        "SELECT pg_stat_get_wal_receiver() FROM pg_catalog.pg_class",
        "SELECT crosstab('SELECT email FROM demo.customers') FROM pg_catalog.pg_class",
        "SELECT dblink_exec('dbname=x', 'SELECT 1') FROM pg_catalog.pg_class",
        "SELECT pg_file_read('postgresql.conf', 0, 100) FROM pg_catalog.pg_class",
        "SELECT loread(1, 100) FROM pg_catalog.pg_class",
        "SELECT pg_get_wal_records_info('0/0', '0/0') FROM pg_catalog.pg_class",
    ] {
        assert!(
            !reads_only_server_metadata(sql),
            "must not be released: {sql}"
        );
    }
}

#[test]
fn unnamed_target_list_functions_are_not_metadata_only() {
    // Denylist polarity: `SELECT f() FROM pg_class` skipped untrusted for
    // every f not on CATALOG_ESCAPE_FUNCTIONS. pageinspect, sleep, GUC
    // writes, and any future dump were the unnamed remainder.
    for sql in [
        "SELECT get_raw_page('demo.customers'::regclass, 0) FROM pg_catalog.pg_class",
        "SELECT pg_catalog.get_raw_page('demo.customers'::regclass, 0) FROM pg_catalog.pg_class",
        r#"SELECT u&"get_raw_page"('demo.customers'::regclass, 0) FROM pg_catalog.pg_class"#,
        "SELECT heap_page_items(get_raw_page('demo.customers'::regclass, 0)) FROM pg_catalog.pg_class",
        "SELECT pg_sleep(0) FROM pg_catalog.pg_class",
        "SELECT set_config('application_name', 'x', false) FROM pg_catalog.pg_class",
        "SELECT pg_file_write('x', 'y', false) FROM pg_catalog.pg_class",
        "SELECT pg_terminate_backend(pg_backend_pid()) FROM pg_catalog.pg_class",
        "SELECT not_a_catalog_fn() FROM pg_catalog.pg_class",
        "SELECT demo.sleep_if(true) FROM pg_catalog.pg_class",
    ] {
        assert!(
            !reads_only_server_metadata(sql),
            "must not be released: {sql}"
        );
        assert!(
            calls_untrusted_function(sql),
            "must hit untrusted after losing the fast path: {sql}"
        );
    }
    // Catalog-browser helpers and trusted names keep the fast path.
    for sql in [
        "SELECT pg_catalog.format_type(a.atttypid, a.atttypmod) \
         FROM pg_catalog.pg_attribute a",
        "SELECT pg_get_userbyid(c.relowner) FROM pg_catalog.pg_class c",
        "SELECT pg_get_viewdef(c.oid) FROM pg_catalog.pg_class c",
        "SELECT count(*) FROM pg_catalog.pg_class",
        "SELECT pg_relation_size(c.oid) FROM pg_catalog.pg_class c",
    ] {
        assert!(reads_only_server_metadata(sql), "should be released: {sql}");
        assert!(
            !calls_untrusted_function(sql),
            "metadata-only skips untrusted: {sql}"
        );
    }
}

#[test]
fn data_bearing_set_returning_functions_do_not_get_the_metadata_fast_path() {
    // Range functions can expose the same data as denied catalog views,
    // while a joined pg_catalog relation supplies the otherwise-required
    // relation marker. Refuse data-bearing SRFs rather than maintaining a
    // second, inevitably incomplete denylist.
    for sql in [
        "SELECT a.query FROM pg_stat_get_activity(NULL) a, pg_catalog.pg_class c",
        "SELECT * FROM pg_ls_waldir(), pg_catalog.pg_class",
    ] {
        assert!(!reads_only_server_metadata(sql), "must be refused: {sql}");
    }
    assert!(reads_only_server_metadata(
        "SELECT n.nspname, c.relname FROM pg_catalog.pg_class c \
         JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace"
    ));
}

#[test]
fn a_cte_may_go_unqualified_but_only_if_it_is_declared_here() {
    assert!(reads_only_server_metadata(
        "WITH cls AS (SELECT oid, relname FROM pg_catalog.pg_class) \
         SELECT relname FROM cls"
    ));
    // A CTE named after a catalog must not launder a user table.
    assert!(!reads_only_server_metadata(
        "WITH pg_class AS (SELECT email FROM demo.customers) SELECT email FROM pg_class"
    ));
}

#[test]
fn size_functions_are_released_but_value_returning_ones_are_not() {
    // Every GUI client shows table sizes. A byte count cannot carry a row.
    for sql in [
        "SELECT pg_total_relation_size('demo.customers')",
        "SELECT pg_relation_size(c.oid) FROM pg_catalog.pg_class c",
    ] {
        assert_eq!(
            analyze(sql, 1, ALLOW_NONE),
            vec![Safety::Releasable],
            "{sql}"
        );
    }
    // A formatted size is still released under the default posture. It is
    // a pure scalar now rather than a size function, so it sits behind the
    // summaries gate and the strict posture refuses it — which is what the
    // strict posture is for.
    assert_eq!(
        analyze(
            "SELECT pg_size_pretty(pg_table_size('demo.customers'))",
            1,
            ALLOW_ALL
        ),
        vec![Safety::Releasable]
    );
    // But the formatters take a *value*, and `pg_size_pretty` renders
    // anything under 10240 as "%lld bytes" — so a modulo and a divide
    // reconstruct any bigint exactly. They are released only over a
    // releasable argument, which is what the GUI case actually is.
    for sql in [
        "SELECT pg_size_pretty(salary) FROM t",
        "SELECT pg_size_pretty((salary % 10000)::bigint) FROM t",
        "SELECT pg_column_size(email) FROM t",
        "SELECT pg_size_bytes(note) FROM t",
    ] {
        assert_eq!(analyze(sql, 1, ALLOW_ALL), vec![Safety::Unknown], "{sql}");
    }
    // The neighbouring trap stays shut: these return an actual member.
    for sql in [
        "SELECT max(email) FROM demo.customers",
        "SELECT pg_read_file('/etc/passwd')",
    ] {
        assert_eq!(analyze(sql, 1, ALLOW_ALL), vec![Safety::Unknown], "{sql}");
    }
}

#[test]
fn show_is_released_because_a_guc_is_not_table_data() {
    for sql in ["SHOW search_path", "SHOW ALL", "SHOW transaction_isolation"] {
        assert!(reads_only_server_metadata(sql), "{sql}");
    }
}

#[test]
fn absence_of_evidence_is_not_release() {
    // pg_query has a known bug where a self-referencing CTE yields an empty
    // table list. Releasing on an empty set would turn that into a leak.
    for sql in [
        "SELECT 1",
        "SELECT now()",
        "WITH f AS (SELECT * FROM f LIMIT 1) SELECT * FROM f",
        "not valid sql at all",
        "SELECT 1; SELECT 2",
    ] {
        assert!(
            !reads_only_server_metadata(sql),
            "must not be released: {sql}"
        );
    }
}

use super::*;

/// Default posture: summaries released.
/// Everything the session can open, for tests about the shape rules.
const ALLOW_ALL: Relaxations = Relaxations {
    summaries: true,
    fine_date_trunc: true,
};
/// Nothing opened: what a masked column in the statement produces.
const ALLOW_NONE: Relaxations = Relaxations {
    summaries: false,
    fine_date_trunc: false,
};

fn safety(sql: &str, fields: usize) -> Vec<Safety> {
    analyze(sql, fields, ALLOW_ALL)
}

/// The stricter posture, for the cases that must hold either way.
fn strict(sql: &str, fields: usize) -> Vec<Safety> {
    analyze(sql, fields, ALLOW_NONE)
}

fn is_safe(sql: &str) -> bool {
    safety(sql, 1) == vec![Safety::Releasable]
}

/// A reducing aggregate used as a *window* function reduces nothing.
///
/// The frame belongs to the caller, and `ROWS BETWEEN CURRENT ROW AND
/// CURRENT ROW` makes `sum` the identity function. Before this was fixed,
///
///   SELECT sum(annual_salary)
///            OVER (ORDER BY id ROWS BETWEEN CURRENT ROW AND CURRENT ROW)
///     FROM fz.people
///
/// returned exact salaries through a bucketed column under the *strictest*
/// configuration, because `Releasable` short-circuits `lineage` and
/// `opaque` alike. Found by the generated campaign, not by review.
#[test]
fn a_reducing_aggregate_over_a_window_is_not_releasable() {
    for sql in [
        "SELECT sum(salary) OVER (ORDER BY id ROWS BETWEEN CURRENT ROW AND CURRENT ROW) FROM t",
        "SELECT sum(salary) OVER () FROM t",
        "SELECT avg(salary) OVER (PARTITION BY dept) FROM t",
        "SELECT count(salary) OVER (ORDER BY id) FROM t",
        "SELECT bool_or(flag) OVER (ORDER BY id) FROM t",
    ] {
        assert!(
            !is_safe(sql),
            "a windowed aggregate must not be released: {sql}"
        );
    }
}

/// The same names without `OVER` are still summaries — resolved to a mask
/// when their source is masked, passed through when it is released. So
/// `sum`/`avg` stop at `Safety::Summary` and the counts stay `Releasable`.
#[test]
fn plain_reducing_aggregates_are_still_summaries() {
    for sql in ["SELECT sum(salary) FROM t", "SELECT avg(salary) FROM t"] {
        assert_eq!(
            safety(sql, 1),
            vec![Safety::Summary],
            "{sql} is a reducing aggregate and must be masked when its source is masked"
        );
    }
    // A count is a tally, never a value from a row, so it is released.
    for sql in ["SELECT count(*) FROM t", "SELECT count(salary) FROM t"] {
        assert_eq!(
            safety(sql, 1),
            vec![Safety::Releasable],
            "{sql} is a row count and stays released"
        );
    }
}

/// Ranking windows keep working: they emit a position, whatever the frame.
#[test]
fn ranking_windows_are_still_releasable() {
    assert!(is_safe("SELECT row_number() OVER (ORDER BY salary) FROM t"));
    assert!(is_safe(
        "SELECT rank() OVER (PARTITION BY dept ORDER BY salary) FROM t"
    ));
}

// --- What the rule exists to rescue -------------------------------------

#[test]
fn literals_are_provably_column_free() {
    assert!(is_safe("SELECT 1"));
    assert!(is_safe("SELECT 'hello'"));
    assert!(is_safe("SELECT NULL"));
    assert!(is_safe("SELECT 1::text"));
}

#[test]
fn context_functions_are_provably_column_free() {
    assert!(is_safe("SELECT now()"));
    assert!(is_safe("SELECT current_database()"));
    assert!(is_safe("SELECT version()"));
    assert!(is_safe("SELECT CURRENT_TIMESTAMP"));
    assert!(is_safe("SELECT CURRENT_USER"));
}

#[test]
fn count_star_is_provably_column_free() {
    assert!(is_safe("SELECT count(*) FROM t"));
}

/// The most common analytical shape there is, and the reason this rule pays
/// for itself: the group key keeps its normal masking, the count is rescued.
#[test]
fn group_by_with_a_count_rescues_only_the_count() {
    assert_eq!(
        safety("SELECT city, count(*) FROM t GROUP BY city", 2),
        vec![Safety::Unknown, Safety::Releasable]
    );
}

// --- What must never be rescued -----------------------------------------

#[test]
fn anything_touching_a_column_stays_unknown() {
    for sql in [
        "SELECT email FROM t",
        "SELECT lower(email) FROM t",
        "SELECT email || '' FROM t",
        "SELECT coalesce(email, '') FROM t",
        "SELECT CASE WHEN id > 0 THEN email END FROM t",
        "SELECT email::text FROM t",
        "SELECT substr(email, 1, 5) FROM t",
        "SELECT to_json(t) FROM t",
    ] {
        assert_eq!(
            safety(sql, 1),
            vec![Safety::Unknown],
            "{sql} must not be rescued"
        );
    }
}

#[test]
fn a_subquery_returning_a_column_stays_unknown() {
    assert_eq!(
        safety("SELECT (SELECT email FROM t LIMIT 1)", 1),
        vec![Safety::Unknown]
    );
}

/// Superseded by `ranking_windows_are_releasable_but_only_as_windows` and
/// `aggregates_that_return_a_stored_value_stay_unknown`. What survives here
/// is the distinction that matters: a window that ranks is fine, a window
/// that reaches into a row is not.
#[test]
fn windows_are_split_by_whether_they_return_a_value() {
    assert_eq!(
        safety("SELECT count(*) OVER () FROM t", 1),
        vec![Safety::Releasable]
    );
    assert_eq!(
        safety("SELECT nth_value(email, 2) OVER (ORDER BY id) FROM t", 1),
        vec![Safety::Unknown]
    );
}

/// FILTER is now allowed on a summarising aggregate. It creates a counting
/// oracle, but the identical oracle already exists via a plain WHERE clause,
/// which is an accepted limitation — refusing FILTER alone bought nothing.
#[test]
fn a_filtered_summary_is_releasable_but_a_filtered_selector_is_not() {
    assert_eq!(
        safety("SELECT count(*) FILTER (WHERE email = 'x') FROM t", 1),
        vec![Safety::Releasable]
    );
    assert_eq!(
        safety("SELECT max(email) FILTER (WHERE id > 0) FROM t", 1),
        vec![Safety::Unknown]
    );
}

#[test]
fn a_shadowed_function_name_stays_unknown() {
    // Someone could define evil.now() returning a column value.
    assert_eq!(safety("SELECT evil.now() FROM t", 1), vec![Safety::Unknown]);
}

// --- Position correspondence --------------------------------------------

#[test]
fn set_operations_collapse_the_whole_analysis() {
    assert_eq!(
        safety("SELECT 1 UNION ALL SELECT 1", 1),
        vec![Safety::Unknown]
    );
}

#[test]
fn a_star_shifts_positions_so_nothing_is_claimed() {
    // `SELECT *, 1 FROM t` has 2 target entries but N fields. If the counts
    // disagree we must not map position 1 to the literal.
    assert_eq!(
        safety("SELECT *, 1 FROM t", 5),
        vec![Safety::Unknown; 5],
        "a star expansion must not let a literal claim the wrong position"
    );
    // Counts can accidentally match again when one star expands to zero
    // fields and a later star expands to several. Position still is not
    // trustworthy.
    let sql = "SELECT e.*, 1, upper(p.email), q.* \
               FROM e, fz.people p, (SELECT id, salary FROM fz.people) q";
    assert_eq!(safety(sql, 4), vec![Safety::Unknown; 4]);
}

#[test]
fn multi_statement_input_collapses_the_analysis() {
    assert_eq!(safety("SELECT 1; SELECT 2", 1), vec![Safety::Unknown]);
}

#[test]
fn unparseable_sql_collapses_the_analysis() {
    assert_eq!(safety("this is not sql", 1), vec![Safety::Unknown]);
    assert_eq!(safety("", 1), vec![Safety::Unknown]);
}

#[test]
fn a_field_count_mismatch_collapses_the_analysis() {
    assert_eq!(safety("SELECT 1, 2", 3), vec![Safety::Unknown; 3]);
}

#[test]
fn non_select_statements_are_not_analysed() {
    assert_eq!(
        safety("INSERT INTO t (a) VALUES (1) RETURNING a", 1),
        vec![Safety::Unknown]
    );
}

/// The relaxation itself, after the WHERE-singleton closure: a reducing
/// aggregate stops at `Safety::Summary` so the session can mask its output
/// with the source column's mask — a sum over a bucketed column returns a
/// bucket, never the exact value, whatever the predicate. Counts stay
/// `Releasable` because a tally never degrades into its input.
#[test]
fn summarising_aggregates_split_by_whether_they_can_be_masked() {
    for sql in [
        "SELECT sum(salary) FROM t",
        "SELECT avg(salary) FROM t",
        "SELECT stddev(salary) FROM t",
        "SELECT sum(CASE WHEN email = 'x' THEN 1 ELSE 0 END) FROM t",
    ] {
        assert_eq!(
            safety(sql, 1),
            vec![Safety::Summary],
            "{sql} should be a resolvable summary"
        );
    }
    // A count is a tally, never a member of the set it consumes.
    for sql in [
        "SELECT count(email) FROM t",
        "SELECT count(DISTINCT email) FROM t",
    ] {
        assert_eq!(
            safety(sql, 1),
            vec![Safety::Releasable],
            "{sql} should be a released count"
        );
    }
    // Arithmetic over a summary is no longer itself releasable: it stops
    // at `Unknown` and the session refuses or masks it through the opaque
    // posture. That is the safe direction — `sum(a)/sum(b)` is one row
    // from being a ratio of exact values.
    for sql in [
        // `sum(salary) OVER (PARTITION BY dept)` was here, asserting the
        // behaviour that turned out to be a disclosure: as a window
        // function the caller picks the frame, and a frame of one row makes
        // `sum` the identity. See
        // `a_reducing_aggregate_over_a_window_is_not_releasable`.
        "SELECT sum(a) / sum(b) FROM t",
        "SELECT sum(salary) + 1 FROM t",
    ] {
        assert_eq!(
            safety(sql, 1),
            vec![Safety::Unknown],
            "{sql} wraps a summary and must not be released blind"
        );
    }
}

/// **The trap this whole module exists to avoid.** Every one of these is an
/// aggregate or window function that hands back a value it consumed.
/// `max(email)` is an email address.
#[test]
fn functions_that_return_a_stored_value_are_never_released() {
    for sql in [
        "SELECT max(email) FROM t",
        "SELECT min(email) FROM t",
        "SELECT mode() WITHIN GROUP (ORDER BY email) FROM t",
        "SELECT percentile_disc(0.5) WITHIN GROUP (ORDER BY salary) FROM t",
        "SELECT percentile_cont(0.5) WITHIN GROUP (ORDER BY salary) FROM t",
        "SELECT string_agg(email, ',') FROM t",
        "SELECT array_agg(email) FROM t",
        "SELECT json_agg(email) FROM t",
        "SELECT jsonb_agg(email) FROM t",
        "SELECT xmlagg(email) FROM t",
        "SELECT first_value(email) OVER (ORDER BY id) FROM t",
        "SELECT last_value(email) OVER (ORDER BY id) FROM t",
        "SELECT nth_value(email, 2) OVER (ORDER BY id) FROM t",
        "SELECT lag(email) OVER (ORDER BY id) FROM t",
        "SELECT lead(email) OVER (ORDER BY id) FROM t",
    ] {
        assert_eq!(
            safety(sql, 1),
            vec![Safety::Unknown],
            "{sql} returns a stored value and must never be released"
        );
    }
}

/// Arithmetic is releasable only when every operand is. A summary divided by
/// a summary is no longer released — it stops at `Unknown` so the opaque
/// posture refuses or masks it; a column times two is still that column.
#[test]
fn arithmetic_is_releasable_only_through_releasable_operands() {
    assert_eq!(safety("SELECT salary * 2 FROM t", 1), vec![Safety::Unknown]);
    assert_eq!(safety("SELECT salary + 0 FROM t", 1), vec![Safety::Unknown]);
    assert_eq!(
        safety("SELECT email || '' FROM t", 1),
        vec![Safety::Unknown]
    );
    assert_eq!(
        safety("SELECT sum(a) - sum(b) FROM t", 1),
        vec![Safety::Unknown]
    );
}

/// Only CASE *results* can carry a value out. A condition over a classified
/// column is a predicate, which is the already-accepted oracle.
#[test]
fn case_is_judged_on_its_result_branches() {
    assert_eq!(
        safety("SELECT CASE WHEN id > 0 THEN email ELSE NULL END FROM t", 1),
        vec![Safety::Unknown]
    );
    assert_eq!(
        safety("SELECT CASE WHEN email = 'x' THEN 1 ELSE 0 END FROM t", 1),
        vec![Safety::Releasable]
    );
    // A releasable branch and a leaking branch is not releasable.
    assert_eq!(
        safety("SELECT CASE WHEN id > 0 THEN 1 ELSE email END FROM t", 1),
        vec![Safety::Unknown]
    );
}

#[test]
fn ranking_windows_are_releasable_but_only_as_windows() {
    assert_eq!(
        safety("SELECT row_number() OVER (ORDER BY salary) FROM t", 1),
        vec![Safety::Releasable]
    );
    assert_eq!(
        safety("SELECT rank() OVER (ORDER BY salary) FROM t", 1),
        vec![Safety::Releasable]
    );
    assert_eq!(
        safety("SELECT row_number() FROM t", 1),
        vec![Safety::Unknown]
    );
}

#[test]
fn coarsening_is_releasable_but_never_as_a_window() {
    assert_eq!(
        safety("SELECT date_trunc('month', birth_date) FROM t", 1),
        vec![Safety::Releasable]
    );
    // A window frame can narrow to a single row, so the argument does not
    // hold there.
    assert_eq!(
        safety("SELECT date_trunc('month', birth_date) OVER () FROM t", 1),
        vec![Safety::Unknown]
    );
}

#[test]
fn the_strict_setting_refuses_summaries_but_keeps_count_star() {
    assert_eq!(
        strict("SELECT sum(salary) FROM t", 1),
        vec![Safety::Unknown]
    );
    assert_eq!(
        strict("SELECT avg(salary) FROM t", 1),
        vec![Safety::Unknown]
    );
    // count(*) consumes no column at all, so it survives either way.
    assert_eq!(
        strict("SELECT count(*) FROM t", 1),
        vec![Safety::Releasable]
    );
    assert_eq!(strict("SELECT 1", 1), vec![Safety::Releasable]);
}

#[test]
fn unknown_and_qualified_function_names_are_not_trusted() {
    assert_eq!(
        safety("SELECT my_agg(email) FROM t", 1),
        vec![Safety::Unknown]
    );
    assert_eq!(
        safety("SELECT evil.sum(email) FROM t", 1),
        vec![Safety::Unknown]
    );
}

/// `SELECT * FROM (subquery)` wraps most TPC-DS queries; the fields are the
/// subquery's target list, positionally.
#[test]
fn a_star_over_a_subquery_is_unwrapped() {
    assert_eq!(
        safety(
            "SELECT * FROM (SELECT city, sum(salary) FROM t GROUP BY city) q",
            2
        ),
        vec![Safety::Unknown, Safety::Summary]
    );
    // But not when the correspondence is not ours to claim.
    assert_eq!(
        safety("SELECT * FROM (SELECT 1) a, (SELECT 2) b", 2),
        vec![Safety::Unknown; 2]
    );
    assert_eq!(
        safety(
            "SELECT * FROM (SELECT email FROM t UNION SELECT email FROM t) q",
            1
        ),
        vec![Safety::Unknown]
    );
}

#[test]
fn pure_scalars_do_not_cover_a_summary() {
    // These wrap a reducing aggregate, which now stops at `Safety::Summary`,
    // so the wrapper stops at `Unknown` and the opaque posture refuses or
    // masks it — `round(sum(a)/sum(b), 1)` is itself one row away from a
    // ratio of exact values.
    assert_eq!(
        safety("SELECT round(sum(a) / sum(b), 1) FROM t", 1),
        vec![Safety::Unknown]
    );
    assert_eq!(
        safety("SELECT abs(sum(salary)) FROM t", 1),
        vec![Safety::Unknown]
    );
    // ...and never over a column.
    assert_eq!(
        safety("SELECT round(salary) FROM t", 1),
        vec![Safety::Unknown]
    );
    assert_eq!(
        safety("SELECT abs(salary) FROM t", 1),
        vec![Safety::Unknown]
    );
}

// --- summary resolution backstop -------------------------------------

/// The `lineage = "refuse"` backstop hands back the FROM relations and each
/// field's bare aggregate argument, so the session can attribute the column
/// to the catalog and mask it. Only the simplest shape resolves: an
/// aggregate over one unadorned column. Anything else is `None`, kept below
/// the bar that lets the caller release.
#[test]
fn summary_resolution_names_the_aggregate_argument() {
    let inspection = StatementInspection::new(
        "SELECT bucketname, sum(salary) FROM canary.no_unique GROUP BY bucketname",
    );
    let (relations, columns) = inspection.summary_resolution(2).expect("trusted select");
    assert_eq!(
        relations,
        vec![("canary".to_string(), "no_unique".to_string())]
    );
    // `bucketname` is a plain column, not an aggregate; `sum(salary)` is.
    assert_eq!(columns, vec![None, Some("salary".to_string())]);
}

#[test]
fn summary_resolution_peels_a_cast_off_the_aggregate() {
    let inspection = StatementInspection::new("SELECT cast(sum(salary) AS bigint) FROM demo.t");
    let (_relations, columns) = inspection.summary_resolution(1).expect("trusted select");
    assert_eq!(columns, vec![Some("salary".to_string())]);
}

#[test]
fn summary_resolution_refuses_shapes_lineage_owns() {
    // JOINs, stars, multiple statements and non-selects collapse the whole
    // resolution to `None`, and the session keeps its opaque posture.
    let collapsing: &[(&str, usize)] = &[
        ("SELECT sum(salary) FROM demo.t JOIN demo.u ON true", 1),
        ("SELECT * FROM demo.t", 1),
        ("SELECT sum(salary) FROM demo.t; SELECT 1", 1),
    ];
    for (sql, n) in collapsing {
        assert!(
            StatementInspection::new(sql)
                .summary_resolution(*n)
                .is_none(),
            "must collapse: {sql}"
        );
    }
    // An aggregate argument analysis cannot attribute — an expression or a
    // qualified name — stays per-field `None`, which the session resolves
    // to the opaque posture rather than a guess.
    let unattributable: &[&str] = &[
        "SELECT sum(salary + 1) FROM demo.t",
        "SELECT sum(t.salary) FROM demo.t",
    ];
    for sql in unattributable {
        let (relations, columns) = StatementInspection::new(sql).summary_resolution(1).unwrap();
        assert!(!relations.is_empty(), "the FROM is still readable: {sql}");
        assert_eq!(columns, vec![None], "no attribution: {sql}");
    }
}

/// The reason PURE_SCALARS is an allowlist. A user-defined function taking a
/// harmless argument can return anything at all, so "all arguments are
/// releasable" says nothing about an arbitrary callee.
#[test]
fn an_unknown_function_over_releasable_arguments_is_not_released() {
    assert_eq!(
        safety("SELECT leak_email(1) FROM t", 1),
        vec![Safety::Unknown]
    );
    assert_eq!(
        safety("SELECT leak_email() FROM t", 1),
        vec![Safety::Unknown]
    );
    assert_eq!(
        safety("SELECT leak_email(count(*)) FROM t", 1),
        vec![Safety::Unknown]
    );
}

/// Regression for a hole found by adversarial review rather than by a test.
///
/// `date_part`/`extract` do not coarsen, they extract a component, and the
/// component is an argument. Through a `date-year` masked column,
/// `date_part('epoch', birth_date)` returned the exact date and
/// `date_part('day', …)` returned precisely what the mask hides.
#[test]
fn component_extraction_is_never_released() {
    for sql in [
        "SELECT date_part('epoch', birth_date) FROM t",
        "SELECT date_part('day', birth_date) FROM t",
        "SELECT extract(epoch from birth_date) FROM t",
        "SELECT extract(day from birth_date) FROM t",
        "SELECT width_bucket(salary, 0, 1000000, 1000000) FROM t",
    ] {
        assert_eq!(
            safety(sql, 1),
            vec![Safety::Unknown],
            "{sql} recovers detail the mask removed"
        );
    }
}

/// `date_trunc` is released only to a coarse *literal* precision. The unit is
/// an argument, so a fine one coarsens nothing.
#[test]
fn date_trunc_is_released_only_at_coarse_literal_precision() {
    for unit in ["day", "month", "quarter", "year"] {
        assert_eq!(
            safety(
                &format!("SELECT date_trunc('{unit}', birth_date) FROM t"),
                1
            ),
            vec![Safety::Releasable],
            "{unit} should be coarse enough"
        );
    }
    for unit in ["microseconds", "milliseconds", "second", "minute", "hour"] {
        assert_eq!(
            safety(
                &format!("SELECT date_trunc('{unit}', birth_date) FROM t"),
                1
            ),
            vec![Safety::Unknown],
            "{unit} coarsens too little"
        );
    }
    // A computed precision cannot be checked, so it fails closed.
    assert_eq!(
        safety("SELECT date_trunc(some_unit, birth_date) FROM t", 1),
        vec![Safety::Unknown]
    );
}

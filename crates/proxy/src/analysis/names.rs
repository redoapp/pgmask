//! Function and catalog name lists the rest of analysis consults.
//!
//! Allowlists, not denylists: a name we fail to recognise is refused, never
//! released. Adding a name is a deliberate, reviewable act.

use pg_query::protobuf::node::Node as NodeEnum;

/// Functions reporting how much storage an object occupies.
///
/// Every GUI client shows table sizes; Beekeeper's stack and Harlequin both
/// call these. They take a relation and return a byte count, so unlike
/// `min(email)` there is no argument that could come back out — the return type
/// is a number, whatever is inside. They do leak approximate row counts, which
/// is the same order of disclosure as `count(*)`, already accepted.
///
/// `pg_read_file` and friends are emphatically not here; those are on
/// `CATALOG_ESCAPE_FUNCTIONS`.
pub(crate) const SIZE_FUNCTIONS: &[&str] = &[
    "pg_relation_size",
    "pg_table_size",
    "pg_indexes_size",
    "pg_total_relation_size",
    "pg_database_size",
    "pg_tablespace_size",
];

// Size-*formatting* functions. Released only when their argument is.
//
// These were on the list above, justified by the same sentence — "they take a
// relation and return a byte count, so there is no argument that could come
// back out". That is true of the six that remain and false of these three,
// which take a **value**:
//
// ```sql
// SELECT pg_size_pretty(salary) FROM t;                       -- "4321 bytes"
// SELECT pg_size_pretty((salary % 10000)::bigint),
//        pg_size_pretty((salary / 10000)::bigint) FROM t;      -- exact, any bigint
// SELECT pg_column_size(email) FROM t;                         -- exact byte length
// ```
//
// `pg_size_pretty` renders `|v| < 10240` as `"%lld bytes"`, so a modulo and a
// divide reconstruct any value exactly. Same shape as the `sum(...) OVER`
// disclosure: a caller-supplied argument turns an allowlisted "cannot return
// an input" function into the identity. Found by an audit, confirmed against
// a live server.
//
// They live in [`PURE_SCALARS`] instead, which releases a call only when every
// argument is releasable. That keeps the case GUI clients actually need —
// `pg_size_pretty(pg_table_size('t'))`, a formatted *relation* size — and
// refuses the value ones, without a special case for either.

/// Zero-argument functions returning session or clock context, never table data.
///
/// Deliberately short. `random()` and `gen_random_uuid()` would also qualify but
/// are omitted because nothing needs them and every entry is attack surface.
pub(crate) const CONTEXT_FUNCTIONS: &[&str] = &[
    "now",
    "current_database",
    "current_catalog",
    "current_schema",
    "current_user",
    "session_user",
    "user",
    "version",
    "clock_timestamp",
    "statement_timestamp",
    "transaction_timestamp",
    "pg_backend_pid",
];

/// Aggregates that collapse many rows into a summary and structurally cannot
/// return one of the values they consumed.
///
/// Everything here answers "how many / how much / how spread out", never "which
/// one". Whatever the argument expression is, the result is not a member of the
/// input set.
pub(crate) const REDUCING_AGGREGATES: &[&str] = &[
    "count",
    "sum",
    "avg",
    "stddev",
    "stddev_pop",
    "stddev_samp",
    "variance",
    "var_pop",
    "var_samp",
    "corr",
    "covar_pop",
    "covar_samp",
    "regr_avgx",
    "regr_avgy",
    "regr_count",
    "regr_intercept",
    "regr_r2",
    "regr_slope",
    "regr_sxx",
    "regr_sxy",
    "regr_syy",
    "bool_and",
    "bool_or",
    "every",
];

// Deliberately absent from REDUCING_AGGREGATES, having been in it:
//
//   bit_and / bit_or / bit_xor — technically reductions, but far leakier per
//   group than the numeric summaries. `bit_or` over a handful of integers
//   reveals every bit set in any member. They are vanishingly rare over
//   classified columns, so the utility given up is nil.

/// Aggregates and window functions that **return one of the input values**, and
/// are therefore exactly what this module must keep refusing.
///
/// Not used in code — the allowlists above are what gate behaviour — but written
/// down because the temptation to add "aggregates are safe" as a category is
/// what would break this. `max(email)` is an email address.
const _RETURNS_A_STORED_VALUE: &[&str] = &[
    "min",
    "max",
    "mode",
    "percentile_disc",
    "percentile_cont",
    "first_value",
    "last_value",
    "nth_value",
    "lag",
    "lead",
    "string_agg",
    "array_agg",
    "json_agg",
    "jsonb_agg",
    "json_object_agg",
    "jsonb_object_agg",
    "xmlagg",
];

/// Window functions that emit a position or rank, never a value from the row.
///
/// Only released when actually used as a window function; the names are not
/// reserved and a plain call of the same name is not this.
pub(crate) const RANKING_WINDOWS: &[&str] = &[
    "row_number",
    "rank",
    "dense_rank",
    "percent_rank",
    "cume_dist",
    "ntile",
];

/// Set-returning functions allowed in a `FROM` clause of a metadata query.
///
/// An allowlist rather than a denylist, because the denylist here is on
/// *relations*: `LEAKY_SYSTEM_CATALOGS` denies the `pg_stat_activity` and
/// `pg_stat_statements` views, and the SRFs behind them —
/// `pg_stat_get_activity()`, `pg_stat_statements()` — return identical rows
/// while appearing as a `RangeFunction` that no relation rule matches. Naming
/// those two would leave every other data-bearing SRF, `pg_ls_waldir()`
/// included.
///
/// Everything here computes from its arguments and reads no table. The list is
/// short on purpose and exists because psql's `\d` genuinely needs
/// `generate_series` in `FROM`; without it, describing a table stops working
/// on four of five Postgres versions, which is the whole reason
/// `system_catalogs = "allow"` exists. `pg_options_to_table` / `aclexplode`
/// are the same `\d` shape for reloptions and ACLs. Do not put catalog-browser
/// helpers here — a helper as a FROM SRF is a different shape than `\d`.
pub(crate) const GENERATORS_IN_FROM: &[&str] = &[
    "generate_series",
    "generate_subscripts",
    "unnest",
    "pg_options_to_table",
    "aclexplode",
];

/// Pure scalar functions that compute from their arguments and nothing else.
///
/// Releasable *only when every argument is*, which is what makes them safe:
/// `round(sum(a) / sum(b), 1)` is arithmetic over summaries, `round(salary)` is
/// still a salary.
///
/// This has to be an allowlist rather than "any function with releasable
/// arguments". A user-defined `leak_email(1)` takes a constant and returns a
/// column value, so argument safety says nothing about an arbitrary function.
pub(crate) const PURE_SCALARS: &[&str] = &[
    "abs",
    "round",
    "ceil",
    "ceiling",
    "floor",
    "trunc",
    "sign",
    "mod",
    "div",
    "power",
    "sqrt",
    "cbrt",
    "exp",
    "ln",
    "log",
    "greatest",
    "least",
    "nullif",
    "to_char",
    "to_number",
    // Size formatters: safe over a size, an identity over a value. See the
    // note above `SIZE_FUNCTIONS`.
    "pg_size_pretty",
    "pg_size_bytes",
    "pg_column_size",
    "numeric",
    "int4",
    "int8",
    "float8",
];

/// The bare function name, rejecting anything schema-qualified.
///
/// `pg_catalog.now()` is the same function, but `myschema.now()` is not, and
/// telling them apart means resolving search_path. Refusing qualified names
/// costs a little utility and removes the question.
pub(crate) fn function_name(parts: &[pg_query::protobuf::Node]) -> Option<String> {
    let [only] = parts else {
        return None;
    };
    match only.node.as_ref()? {
        NodeEnum::String(s) => Some(s.sval.to_ascii_lowercase()),
        _ => None,
    }
}

/// Catalogs that hold user data, not metadata about it.
///
/// Measured, not assumed. On the demo database `pg_stats` returns
/// `most_common_vals = {shared@example.com}` for a pseudonymised column, and
/// exact `histogram_bounds` for a date masked to its year and an IP masked to
/// its /24. Releasing `pg_catalog` wholesale would hand back the values the
/// proxy exists to hide.
///
/// `pg_statistic_ext` is deliberately absent: it records *which* extended
/// statistics objects exist. The values live in `pg_statistic_ext_data`, and
/// `\d` reads the former.
///
/// TOAST heaps are not on this name list: they are `pg_toast.pg_toast_<oid>`
/// and the oid is not known statically. [`range_var_is_leaky_catalog`] matches
/// the schema / `pg_toast_` prefix instead.
const LEAKY_SYSTEM_CATALOGS: &[&str] = &[
    // Sampled values from user tables.
    "pg_statistic",
    "pg_statistic_ext_data",
    "pg_stats",
    "pg_stats_ext",
    "pg_stats_ext_exprs",
    // Other sessions' SQL text, literals included. Session-local
    // `pg_cursors.statement` / `pg_prepared_statements` carry the same
    // class of text (DECLARE / PREPARE bodies with literals).
    "pg_stat_activity",
    "pg_stat_statements",
    "pg_prepared_statements",
    "pg_cursors",
    // Replication conninfo can embed passwords.
    "pg_stat_wal_receiver",
    // Large object contents.
    "pg_largeobject",
    // Password hashes and connection strings.
    "pg_authid",
    "pg_shadow",
    "pg_user",
    "pg_user_mapping",
    "pg_user_mappings",
    "pg_subscription",
    // FDW server / wrapper options: the same class as user mappings
    // (passwords, endpoints). `pg_foreign_table` stays off the list so `\d`
    // of a foreign table still works; heap `\d` never reads these two.
    "pg_foreign_server",
    "pg_foreign_data_wrapper",
    // SQL-standard wrappers of the same option catalogs. `FROM
    // information_schema.user_mapping_options` is metadata-only (schema
    // allowlist) and never names `pg_user_mapping`, so the pg_ catalog
    // denylist does not see it. The previous pass caught three of the
    // five PUBLIC option views; `column_options` / `foreign_table_options`
    // (attfdwoptions / ftoptions) are the same class. Internal
    // `_pg_*` base views carry the raw option arrays those wrappers
    // explode — GRANT is not PUBLIC, but a superuser (or
    // `SET search_path TO information_schema`) still reads them.
    "user_mapping_options",
    "foreign_server_options",
    "foreign_data_wrapper_options",
    "column_options",
    "foreign_table_options",
    "_pg_user_mappings",
    "_pg_foreign_servers",
    "_pg_foreign_data_wrappers",
    "_pg_foreign_tables",
    "_pg_foreign_table_columns",
    // Host configuration and file contents.
    "pg_file_settings",
    "pg_hba_file_rules",
    "pg_ident_file_mappings",
    "pg_backend_memory_contexts",
];

/// Catalogs whose rows are user data, session SQL, passwords, or toasted
/// cell bytes. Refused at the frontend on every posture.
pub(crate) fn range_var_is_leaky_catalog(v: &pg_query::protobuf::RangeVar) -> bool {
    let schema = v.schemaname.to_ascii_lowercase();
    let relation = v.relname.to_ascii_lowercase();
    // TOAST heaps are the toasted bytes of user columns, masked ones
    // included. `reltoastrelid` from `pg_class` plus `SET search_path TO
    // pg_toast` makes `SELECT count(*) FROM pg_toast_NNNN WHERE chunk_data
    // LIKE '%x%'` a membership oracle. `chunk_data` is not in the snapshot
    // (the loader skips `pg_toast`), so the hostile name set never sees it.
    // Unqualified `pg_toast_*` is catalog-shaped (`pg_` prefix) and would
    // otherwise look metadata-only.
    if schema == "pg_toast" || relation.starts_with("pg_toast_") {
        return true;
    }
    // information_schema implements SQL/MED option views on `_pg_*`
    // base views. New ones keep that prefix; a name list alone misses
    // the next wrapper. Unqualified `_pg_*` is the same views after
    // `SET search_path TO information_schema` (RangeVar.schemaname is
    // empty). A CTE named `_pg_foo` would also match — fail closed.
    // `_pg_*` *functions* (`_pg_truetypid`) are FuncCalls, not
    // RangeVars, and stay catalog-safe helpers.
    if relation.starts_with("_pg_") && (schema.is_empty() || schema == "information_schema") {
        return true;
    }
    LEAKY_SYSTEM_CATALOGS.contains(&relation.as_str())
}

/// Functions that reach data the parse tree never names.
///
/// `query_to_xml('SELECT * FROM demo.customers', …)` takes its query as a
/// *string*, so no `RangeVar` for `customers` exists to check. Without this
/// list the whole rule is bypassable in one call.
pub(crate) const CATALOG_ESCAPE_FUNCTIONS: &[&str] = &[
    "query_to_xml",
    "query_to_xmlschema",
    "query_to_xml_and_xmlschema",
    "table_to_xml",
    "table_to_xmlschema",
    "table_to_xml_and_xmlschema",
    "cursor_to_xml",
    "cursor_to_xmlschema",
    "schema_to_xml",
    "schema_to_xmlschema",
    "schema_to_xml_and_xmlschema",
    "database_to_xml",
    "database_to_xmlschema",
    "database_to_xml_and_xmlschema",
    "dblink",
    "dblink_send_query",
    "dblink_get_result",
    "dblink_exec",
    "dblink_connect",
    "dblink_connect_u",
    "dblink_disconnect",
    "dblink_open",
    "dblink_fetch",
    "dblink_close",
    "dblink_get_connections",
    "dblink_get_pkey",
    "dblink_build_sql_insert",
    "dblink_build_sql_update",
    "dblink_build_sql_delete",
    // tablefunc: query-as-string / named-table walk, same class as query_to_xml.
    "crosstab",
    "crosstab2",
    "crosstab3",
    "crosstab4",
    "connectby",
    "pg_read_file",
    "pg_read_binary_file",
    "pg_file_read",
    "pg_logdir_ls",
    "pg_ls_dir",
    "pg_ls_logdir",
    "pg_ls_waldir",
    "pg_ls_archive_statusdir",
    "pg_ls_tmpdir",
    "pg_ls_logicalmapdir",
    "pg_ls_logicalsnapdir",
    "pg_ls_summariesdir",
    "pg_stat_file",
    "lo_get",
    "lo_import",
    "lo_export",
    "lo_open",
    "loread",
    // Defense in depth: target-list `FuncCall` is an allowlist now, but a
    // helper that is later added by mistake must still not dump these.
    "pg_stat_get_activity",
    "pg_stat_get_backend_activity",
    "pg_stat_get_wal_receiver",
    "pg_stat_statements",
    "pg_logical_slot_get_changes",
    "pg_logical_slot_peek_changes",
    "pg_logical_slot_get_binary_changes",
    "pg_logical_slot_peek_binary_changes",
    "pg_get_wal_record_info",
    "pg_get_wal_records_info",
    "pg_get_wal_records_info_till_end_of_wal",
    "pg_get_wal_block_info",
    "pg_get_wal_funames",
];

/// Catalog-browser helpers allowed on the metadata-only fast path.
///
/// Target-list `SELECT f() FROM pg_class` used to be metadata-only unless `f`
/// was on [`CATALOG_ESCAPE_FUNCTIONS`]. That is denylist polarity: every
/// unnamed dump (`get_raw_page`, `crosstab`, `pg_sleep`, `set_config`, …)
/// skipped the untrusted-function gate. Same class as RangeFunction, inverted
/// the same way — only trusted names, FROM-generators, and this introspection
/// list keep the fast path. The escape list still wins if a name is on both.
pub(crate) const CATALOG_HELPER_FUNCTIONS: &[&str] = &[
    // psql `\d` / GUI browsers.
    "format_type",
    "pg_get_userbyid",
    "pg_get_indexdef",
    "pg_get_constraintdef",
    "pg_get_expr",
    "pg_get_viewdef",
    "pg_get_functiondef",
    "pg_get_function_arguments",
    "pg_get_function_result",
    "pg_get_function_identity_arguments",
    "pg_get_function_arg_default",
    "pg_get_ruledef",
    "pg_get_triggerdef",
    "pg_get_serial_sequence",
    "pg_get_partkeydef",
    "pg_get_partition_constraintdef",
    "pg_get_replica_identity_index",
    "pg_get_statisticsobjdef",
    "pg_get_statisticsobjdef_columns",
    "pg_get_statisticsobjdef_expressions",
    "pg_get_keywords",
    "pg_get_catalog_foreign_keys",
    "pg_get_multixact_members",
    "pg_get_object_address",
    "pg_identify_object",
    "pg_identify_object_as_address",
    "pg_describe_object",
    "pg_index_column_has_property",
    "pg_index_has_property",
    "pg_indexam_has_property",
    "obj_description",
    "shobj_description",
    "col_description",
    "pg_options_to_table",
    "aclexplode",
    "array_to_string",
    "array_length",
    "cardinality",
    "array_upper",
    "array_lower",
    "array_ndims",
    "array_dims",
    "array_append",
    "array_prepend",
    "array_cat",
    "array_remove",
    "array_replace",
    "array_position",
    "array_positions",
    "string_to_array",
    "pg_typeof",
    "pg_collation_for",
    "pg_collation_actual_version",
    "pg_encoding_to_char",
    "pg_char_to_encoding",
    "current_setting",
    "current_schemas",
    "to_regclass",
    "to_regtype",
    "to_regnamespace",
    "to_regrole",
    "to_regproc",
    "to_regprocedure",
    "to_regoper",
    "to_regoperator",
    "to_regcollation",
    "pg_table_is_visible",
    "pg_type_is_visible",
    "pg_function_is_visible",
    "pg_operator_is_visible",
    "pg_opclass_is_visible",
    "pg_opfamily_is_visible",
    "pg_collation_is_visible",
    "pg_conversion_is_visible",
    "pg_ts_config_is_visible",
    "pg_ts_dict_is_visible",
    "pg_ts_parser_is_visible",
    "pg_ts_template_is_visible",
    "has_table_privilege",
    "has_schema_privilege",
    "has_column_privilege",
    "has_database_privilege",
    "has_sequence_privilege",
    "has_function_privilege",
    "has_language_privilege",
    "has_tablespace_privilege",
    "has_foreign_data_wrapper_privilege",
    "has_server_privilege",
    "has_type_privilege",
    "has_parameter_privilege",
    "pg_has_role",
    "row_to_json",
    "to_json",
    "to_jsonb",
    "json_build_object",
    "json_build_array",
    "jsonb_build_object",
    "jsonb_build_array",
    "json_agg",
    "jsonb_agg",
    "json_object_agg",
    "jsonb_object_agg",
    "array_agg",
    "string_agg",
    "xmlagg",
    "min",
    "max",
    "quote_ident",
    "quote_literal",
    "quote_nullable",
    "starts_with",
    "pg_postmaster_start_time",
    "pg_conf_load_time",
    "pg_is_in_recovery",
    "pg_is_wal_replay_paused",
    "pg_last_wal_receive_lsn",
    "pg_last_wal_replay_lsn",
    "pg_last_xact_replay_timestamp",
    "pg_current_wal_lsn",
    "pg_current_wal_insert_lsn",
    "pg_current_wal_flush_lsn",
    "pg_walfile_name",
    "pg_walfile_name_offset",
    "pg_wal_lsn_diff",
    "pg_relation_filepath",
    "pg_relation_filenode",
    "pg_filenode_relation",
    "pg_tablespace_location",
    "pg_tablespace_databases",
    "pg_current_logfile",
    "pg_read_all_settings",
    "pg_my_temp_schema",
    "pg_is_other_temp_schema",
    "pg_jit_available",
    "pg_listening_channels",
    "pg_notification_queue_usage",
    "pg_control_system",
    "pg_control_checkpoint",
    "pg_control_recovery",
    "pg_control_init",
    "pg_get_wal_resource_managers",
    "age",
    "txid_current",
    "txid_current_if_assigned",
    "txid_current_snapshot",
    "txid_snapshot_xmin",
    "txid_snapshot_xmax",
    "txid_snapshot_xip",
    "txid_visible_in_snapshot",
    "txid_status",
    "pg_current_xact_id",
    "pg_current_xact_id_if_assigned",
    "pg_current_snapshot",
    "pg_snapshot_xmin",
    "pg_snapshot_xmax",
    "pg_snapshot_xip",
    "pg_visible_in_snapshot",
    "pg_xact_status",
    "pg_sequence_parameters",
    "pg_sequence_last_value",
    "pg_get_function_sqlbody",
    "pg_relation_is_updatable",
    "pg_column_is_updatable",
];

pub(crate) fn func_call_name_parts(call: &pg_query::protobuf::FuncCall) -> Option<Vec<String>> {
    let mut parts = Vec::with_capacity(call.funcname.len());
    for node in &call.funcname {
        let NodeEnum::String(s) = node.node.as_ref()? else {
            return None;
        };
        parts.push(s.sval.to_ascii_lowercase());
    }
    Some(parts)
}

pub(crate) fn is_trusted_function_name(name: &str) -> bool {
    CONTEXT_FUNCTIONS.contains(&name)
        || SIZE_FUNCTIONS.contains(&name)
        || REDUCING_AGGREGATES.contains(&name)
        || RANKING_WINDOWS.contains(&name)
        || PURE_SCALARS.contains(&name)
        || TEXT_FUNCTIONS.contains(&name)
        || name == "date_trunc"
}

/// Unqualified text helpers that analysis already treats as ordinary expressions
/// (usually opaque). Listed so a `lower(city)` under default posture is not
/// mistaken for a user-defined function; they never get a free pass past the
/// projection / opaque gates.
const TEXT_FUNCTIONS: &[&str] = &[
    "length",
    "char_length",
    "character_length",
    "octet_length",
    "lower",
    "upper",
    "initcap",
    "substr",
    "substring",
    "left",
    "right",
    "trim",
    "btrim",
    "ltrim",
    "rtrim",
    "replace",
    "translate",
    "overlay",
    "concat",
    "concat_ws",
    "format",
    "repeat",
    "reverse",
    "ascii",
    "chr",
    "md5",
    "convert",
    "convert_from",
    "convert_to",
    "encode",
    "decode",
];

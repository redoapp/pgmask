//! Vanilla PostgreSQL 18 catalog surface, classified once.
//!
//! Every official heap ([catalogs-overview][1]), system view
//! ([views-overview][2]), monitoring-stats view ([monitoring-stats][3]), and
//! `information_schema` relation (`information_schema.sql`) is either
//! metadata-safe or leaky. There is no third bucket. Unknown catalog-shaped
//! names stay leaky via the invert in [`range_var_is_leaky_catalog`].
//!
//! Contrib exceptions (`pg_buffercache`, `pg_stat_statements_info`,
//! `pg_wait_sampling_{profile,history,current}`) are named separately.
//! A new Postgres major is a table diff: progress and `pg_statio_*` views
//! already listed stay allowed; an unseen name in those families is leaky.
//!
//! Classified-leaky names are leaky in **any** schema, so
//! `SET search_path` / `public.pg_stats` cannot wrap them. Unknown
//! catalog-shaped names stay leaky via invert. The only rules outside the
//! table are TOAST oids, future `information_schema._pg_*` wrappers, and
//! unqualified fork dumps that are not catalog-shaped (`citus_lock_waits`).
//!
//! Tests fail if a name is duplicated, unsorted, or if
//! `SELECT * FROM pg_catalog.{name}` disagrees with the classification.
//!
//! [1]: https://www.postgresql.org/docs/18/catalogs-overview.html
//! [2]: https://www.postgresql.org/docs/18/views-overview.html
//! [3]: https://www.postgresql.org/docs/18/monitoring-stats.html

/// `(relation, metadata_safe)`. Sorted by name; lookup is binary search.
///
/// `true` is schema / counter / connection *metadata* (`\d`, `pg_roles`,
/// table-size dashboards). `false` is sampled cell values, other sessions'
/// SQL, passwords, toasted bytes, or host file contents.
pub const VANILLA_PG_CATALOG: &[(&str, bool)] = &[
    ("pg_aggregate", true),
    ("pg_aios", true),
    ("pg_am", true),
    ("pg_amop", true),
    ("pg_amproc", true),
    ("pg_attrdef", true),
    ("pg_attribute", true),
    ("pg_auth_members", true),
    ("pg_authid", false),
    ("pg_available_extension_versions", true),
    ("pg_available_extensions", true),
    ("pg_backend_memory_contexts", false),
    ("pg_cast", true),
    ("pg_class", true),
    ("pg_collation", true),
    ("pg_config", true),
    ("pg_constraint", true),
    ("pg_conversion", true),
    ("pg_cursors", false),
    ("pg_database", true),
    ("pg_db_role_setting", true),
    ("pg_default_acl", true),
    ("pg_depend", true),
    ("pg_description", true),
    ("pg_enum", true),
    ("pg_event_trigger", true),
    ("pg_extension", true),
    ("pg_file_settings", false),
    ("pg_foreign_data_wrapper", false),
    ("pg_foreign_server", false),
    ("pg_foreign_table", true),
    ("pg_group", true),
    ("pg_hba_file_rules", false),
    ("pg_ident_file_mappings", false),
    ("pg_index", true),
    ("pg_indexes", true),
    ("pg_inherits", true),
    ("pg_init_privs", true),
    ("pg_language", true),
    ("pg_largeobject", false),
    ("pg_largeobject_metadata", true),
    ("pg_locks", true),
    ("pg_matviews", true),
    ("pg_namespace", true),
    ("pg_opclass", true),
    ("pg_operator", true),
    ("pg_opfamily", true),
    ("pg_parameter_acl", true),
    ("pg_partitioned_table", true),
    ("pg_policies", true),
    ("pg_policy", true),
    ("pg_prepared_statements", false),
    ("pg_prepared_xacts", true),
    ("pg_proc", true),
    ("pg_publication", true),
    ("pg_publication_namespace", true),
    ("pg_publication_rel", true),
    ("pg_publication_tables", true),
    ("pg_range", true),
    ("pg_replication_origin", true),
    ("pg_replication_origin_status", true),
    ("pg_replication_slots", true),
    ("pg_rewrite", true),
    ("pg_roles", true),
    ("pg_rules", true),
    ("pg_seclabel", true),
    ("pg_seclabels", true),
    ("pg_sequence", true),
    ("pg_sequences", true),
    ("pg_settings", true),
    ("pg_shadow", false),
    ("pg_shdepend", true),
    ("pg_shdescription", true),
    ("pg_shmem_allocations", true),
    ("pg_shmem_allocations_numa", true),
    ("pg_shseclabel", true),
    ("pg_stat_activity", false),
    ("pg_stat_all_indexes", true),
    ("pg_stat_all_tables", true),
    ("pg_stat_archiver", true),
    ("pg_stat_bgwriter", true),
    ("pg_stat_checkpointer", true),
    ("pg_stat_database", true),
    ("pg_stat_database_conflicts", true),
    ("pg_stat_gssapi", true),
    ("pg_stat_io", true),
    ("pg_stat_progress_analyze", true),
    ("pg_stat_progress_basebackup", true),
    ("pg_stat_progress_cluster", true),
    ("pg_stat_progress_copy", true),
    ("pg_stat_progress_create_index", true),
    ("pg_stat_progress_vacuum", true),
    ("pg_stat_recovery_prefetch", true),
    ("pg_stat_replication", true),
    ("pg_stat_replication_slots", true),
    ("pg_stat_slru", true),
    ("pg_stat_ssl", true),
    ("pg_stat_subscription", true),
    ("pg_stat_subscription_stats", true),
    ("pg_stat_sys_indexes", true),
    ("pg_stat_sys_tables", true),
    ("pg_stat_user_functions", true),
    ("pg_stat_user_indexes", true),
    ("pg_stat_user_tables", true),
    ("pg_stat_wal", true),
    ("pg_stat_wal_receiver", false),
    ("pg_stat_xact_all_tables", true),
    ("pg_stat_xact_sys_tables", true),
    ("pg_stat_xact_user_functions", true),
    ("pg_stat_xact_user_tables", true),
    ("pg_statio_all_indexes", true),
    ("pg_statio_all_sequences", true),
    ("pg_statio_all_tables", true),
    ("pg_statio_sys_indexes", true),
    ("pg_statio_sys_sequences", true),
    ("pg_statio_sys_tables", true),
    ("pg_statio_user_indexes", true),
    ("pg_statio_user_sequences", true),
    ("pg_statio_user_tables", true),
    // Sampled cell values. Measured on the demo database: `pg_stats`
    // returns `most_common_vals = {shared@example.com}` for a
    // pseudonymised column, and exact `histogram_bounds` for a date
    // masked to its year. `pg_statistic_ext` is definition-only (`\d`);
    // the values live in `pg_statistic_ext_data`.
    ("pg_statistic", false),
    ("pg_statistic_ext", true),
    ("pg_statistic_ext_data", false),
    ("pg_stats", false),
    ("pg_stats_ext", false),
    ("pg_stats_ext_exprs", false),
    ("pg_subscription", false),
    ("pg_subscription_rel", true),
    ("pg_tables", true),
    ("pg_tablespace", true),
    ("pg_timezone_abbrevs", true),
    ("pg_timezone_names", true),
    ("pg_transform", true),
    ("pg_trigger", true),
    ("pg_ts_config", true),
    ("pg_ts_config_map", true),
    ("pg_ts_dict", true),
    ("pg_ts_parser", true),
    ("pg_ts_template", true),
    ("pg_type", true),
    ("pg_user", false),
    ("pg_user_mapping", false),
    ("pg_user_mappings", false),
    ("pg_views", true),
    ("pg_wait_events", true),
];

/// `(relation, metadata_safe)`. Sorted by name.
///
/// Option views and `_pg_*` internals are leaky (FDW / user-mapping secrets).
/// Name / grant / type views are metadata-safe so GUI browsers keep working.
pub const VANILLA_INFORMATION_SCHEMA: &[(&str, bool)] = &[
    ("_pg_foreign_data_wrappers", false),
    ("_pg_foreign_servers", false),
    ("_pg_foreign_table_columns", false),
    ("_pg_foreign_tables", false),
    ("_pg_user_mappings", false),
    ("administrable_role_authorizations", true),
    ("applicable_roles", true),
    ("attributes", true),
    ("character_sets", true),
    ("check_constraint_routine_usage", true),
    ("check_constraints", true),
    ("collation_character_set_applicability", true),
    ("collations", true),
    ("column_column_usage", true),
    ("column_domain_usage", true),
    ("column_options", false),
    ("column_privileges", true),
    ("column_udt_usage", true),
    ("columns", true),
    ("constraint_column_usage", true),
    ("constraint_table_usage", true),
    ("data_type_privileges", true),
    ("domain_constraints", true),
    ("domain_udt_usage", true),
    ("domains", true),
    ("element_types", true),
    ("enabled_roles", true),
    ("foreign_data_wrapper_options", false),
    ("foreign_data_wrappers", true),
    ("foreign_server_options", false),
    ("foreign_servers", true),
    ("foreign_table_options", false),
    ("foreign_tables", true),
    ("information_schema_catalog_name", true),
    ("key_column_usage", true),
    ("parameters", true),
    ("referential_constraints", true),
    ("role_column_grants", true),
    ("role_routine_grants", true),
    ("role_table_grants", true),
    ("role_udt_grants", true),
    ("role_usage_grants", true),
    ("routine_column_usage", true),
    ("routine_privileges", true),
    ("routine_routine_usage", true),
    ("routine_sequence_usage", true),
    ("routine_table_usage", true),
    ("routines", true),
    ("schemata", true),
    ("sequences", true),
    ("sql_features", true),
    ("sql_implementation_info", true),
    ("sql_parts", true),
    ("sql_sizing", true),
    ("table_constraints", true),
    ("table_privileges", true),
    ("tables", true),
    ("transforms", true),
    ("triggered_update_columns", true),
    ("triggers", true),
    ("udt_privileges", true),
    ("usage_privileges", true),
    ("user_defined_types", true),
    ("user_mapping_options", false),
    ("user_mappings", true),
    ("view_column_usage", true),
    ("view_routine_usage", true),
    ("view_table_usage", true),
    ("views", true),
];

/// Contrib relations that are metadata-safe by name, not vanilla Postgres.
///
/// `pg_stat_statements` itself (query text) is *not* here; invert refuses it.
/// `pg_stat_statements_info` is dealloc counters. `pg_wait_sampling_*` is
/// queryid + wait counts, not query text — named, not a prefix, so an unseen
/// sibling is leaky.
const CONTRIB_METADATA_SAFE_PG: &[&str] = &[
    "pg_buffercache",
    "pg_stat_statements_info",
    "pg_wait_sampling_current",
    "pg_wait_sampling_history",
    "pg_wait_sampling_profile",
];

fn lookup(table: &[(&str, bool)], name: &str) -> Option<bool> {
    table
        .binary_search_by_key(&name, |(n, _)| *n)
        .ok()
        .and_then(|i| table.get(i).map(|(_, safe)| *safe))
}

pub(crate) fn vanilla_pg_classification(relation: &str) -> Option<bool> {
    lookup(VANILLA_PG_CATALOG, relation)
}

pub(crate) fn vanilla_information_schema_classification(relation: &str) -> Option<bool> {
    lookup(VANILLA_INFORMATION_SCHEMA, relation)
}

/// Whether a `pg_catalog` / unqualified `pg_*` relation is metadata-safe.
///
/// Vanilla names use the table. Unknown names are leaky unless they are a
/// named contrib exception.
pub(crate) fn relation_is_metadata_safe_pg(relation: &str) -> bool {
    if let Some(safe) = vanilla_pg_classification(relation) {
        return safe;
    }
    CONTRIB_METADATA_SAFE_PG.contains(&relation)
}

/// True when the vanilla tables classify this relation leaky.
///
/// Applied in any schema: `public.pg_stats` and unqualified
/// `user_mapping_options` (after `SET search_path`) wrap the same secrets.
fn relation_is_classified_leaky(relation: &str) -> bool {
    matches!(vanilla_pg_classification(relation), Some(false))
        || matches!(
            vanilla_information_schema_classification(relation),
            Some(false)
        )
}

/// Whether an `information_schema` relation is metadata-safe.
///
/// Unknown views are leaky. `_pg_*` internals are classified leaky in the
/// table; the prefix rule in [`range_var_is_leaky_catalog`] still catches a
/// future wrapper the table has not named.
pub(crate) fn relation_is_metadata_safe_information_schema(relation: &str) -> bool {
    vanilla_information_schema_classification(relation).unwrap_or(false)
}

/// Catalogs whose rows are user data, session SQL, passwords, or toasted
/// cell bytes. Refused at the frontend on every posture.
///
/// A classified-leaky name is leaky in any schema. Catalog-shaped unknown
/// names are leaky. Named contrib exceptions stay allowed. The rules
/// outside the tables are TOAST oids, future `_pg_*` wrappers, and
/// unqualified fork dumps that are not catalog-shaped.
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
    // Fork dumps whose *unqualified* names are not catalog-shaped
    // (`citus_lock_waits` has no `pg_` prefix). Invert never sees them.
    // Catalog-shaped names (`pg_stat_activity`, `pg_stat_statements_info`)
    // go through classification / invert instead of these substrings.
    if is_non_catalog_shaped_fork_dump(&relation) {
        return true;
    }
    // Classified leaky in any schema: `public.pg_stats` and unqualified
    // `user_mapping_options` wrap the same secrets the table already named.
    if relation_is_classified_leaky(&relation) {
        return true;
    }
    // Invert: a catalog-shaped name not classified metadata-safe is leaky.
    // `pg_catalog.hypopg_list_indexes`, `pg_dist_authinfo`,
    // `information_schema.not_yet_invented_options`, and the next
    // extension were metadata-only because the schema matched.
    if schema == "information_schema" {
        return !relation_is_metadata_safe_information_schema(&relation);
    }
    if schema == "pg_catalog" || (schema.is_empty() && relation.starts_with("pg_")) {
        return !relation_is_metadata_safe_pg(&relation);
    }
    false
}

/// Unqualified fork dumps invert cannot see (`citus_lock_waits` has no `pg_`
/// prefix). Substring, not a name list: the next `edb_stat_activity` must
/// fail closed. `pg_*` names are skipped so `pg_stat_statements_info` is
/// not a special case on the `stat_statements` substring.
fn is_non_catalog_shaped_fork_dump(relation: &str) -> bool {
    if relation.starts_with("pg_") {
        return false;
    }
    relation.starts_with("citus_stat_")
        || relation.contains("stat_activity")
        || relation.contains("lock_waits")
        || relation.contains("stat_statements")
}

#[cfg(test)]
mod tests {
    use super::super::{reads_only_server_metadata, touches_leaky_system_catalog};
    use super::*;

    fn assert_sorted_unique_partition(entries: &[(&str, bool)], kind: &str) {
        let mut prev: Option<&str> = None;
        for (name, _) in entries {
            assert!(!name.is_empty(), "{kind} contains an empty relation name");
            if let Some(p) = prev {
                assert!(
                    p < *name,
                    "{kind} is not sorted unique: {p:?} then {name:?}"
                );
            }
            prev = Some(name);
        }
    }

    #[test]
    fn vanilla_surfaces_are_sorted_unique_partitions() {
        assert_sorted_unique_partition(VANILLA_PG_CATALOG, "VANILLA_PG_CATALOG");
        assert_sorted_unique_partition(VANILLA_INFORMATION_SCHEMA, "VANILLA_INFORMATION_SCHEMA");
        for (name, _) in VANILLA_PG_CATALOG {
            assert!(
                name.starts_with("pg_"),
                "vanilla pg catalog {name} is not catalog-shaped"
            );
        }
        let pg_leaky = VANILLA_PG_CATALOG.iter().filter(|(_, s)| !*s).count();
        let is_leaky = VANILLA_INFORMATION_SCHEMA
            .iter()
            .filter(|(_, s)| !*s)
            .count();
        // Snapshot of the leaky half so a reclassification is a deliberate diff.
        assert_eq!(pg_leaky, 22, "vanilla pg leaky count");
        assert_eq!(is_leaky, 10, "vanilla information_schema leaky count");
        assert_eq!(VANILLA_PG_CATALOG.len(), 144, "vanilla pg surface size");
        assert_eq!(
            VANILLA_INFORMATION_SCHEMA.len(),
            69,
            "vanilla information_schema surface size"
        );
    }

    #[test]
    fn lookup_agrees_with_linear_scan() {
        for (name, safe) in VANILLA_PG_CATALOG {
            assert_eq!(vanilla_pg_classification(name), Some(*safe));
        }
        for (name, safe) in VANILLA_INFORMATION_SCHEMA {
            assert_eq!(vanilla_information_schema_classification(name), Some(*safe));
        }
        assert_eq!(vanilla_pg_classification("hypopg_list_indexes"), None);
        assert_eq!(
            vanilla_information_schema_classification("not_a_real_view"),
            None
        );
    }

    #[test]
    fn every_classified_pg_relation_matches_the_frontend_gate() {
        for (name, safe) in VANILLA_PG_CATALOG {
            let qualified = format!("SELECT * FROM pg_catalog.{name}");
            let unqualified = format!("SELECT * FROM {name}");
            assert_eq!(
                touches_leaky_system_catalog(&qualified),
                !*safe,
                "{qualified}"
            );
            assert_eq!(
                touches_leaky_system_catalog(&unqualified),
                !*safe,
                "{unqualified}"
            );
            if *safe {
                assert!(
                    reads_only_server_metadata(&qualified),
                    "safe pg relation lost the metadata fast path: {qualified}"
                );
            } else {
                assert!(
                    !reads_only_server_metadata(&qualified),
                    "leaky pg relation kept the metadata fast path: {qualified}"
                );
            }
        }
    }

    #[test]
    fn every_classified_information_schema_relation_matches_the_frontend_gate() {
        for (name, safe) in VANILLA_INFORMATION_SCHEMA {
            let sql = format!("SELECT * FROM information_schema.{name}");
            assert_eq!(touches_leaky_system_catalog(&sql), !*safe, "{sql}");
            if *safe {
                assert!(
                    reads_only_server_metadata(&sql),
                    "safe IS relation lost the metadata fast path: {sql}"
                );
            } else {
                assert!(
                    !reads_only_server_metadata(&sql),
                    "leaky IS relation kept the metadata fast path: {sql}"
                );
            }
        }
    }

    #[test]
    fn unknown_catalog_shaped_names_are_leaky() {
        for sql in [
            "SELECT * FROM pg_catalog.hypopg_list_indexes",
            "SELECT * FROM pg_catalog.unknown_extension_dump",
            "SELECT * FROM pg_stat_statements",
            "SELECT * FROM pg_stat_monitor",
            "SELECT * FROM information_schema.not_a_real_view",
            "SELECT * FROM information_schema._pg_foreign_future",
        ] {
            assert!(
                touches_leaky_system_catalog(sql),
                "unclassified catalog-shaped name must be leaky: {sql}"
            );
        }
    }

    #[test]
    fn classified_leaky_is_leaky_in_any_schema() {
        for sql in [
            "SELECT * FROM public.pg_stats",
            "SELECT * FROM public.pg_stat_activity",
            "SELECT * FROM public.user_mapping_options",
            "SELECT * FROM user_mapping_options",
            "SELECT * FROM column_options",
        ] {
            assert!(
                touches_leaky_system_catalog(sql),
                "classified-leaky must not depend on schema: {sql}"
            );
        }
        // A user table that happens to share a *safe* catalog name is not
        // this gate's problem; OIDs settle it.
        assert!(!touches_leaky_system_catalog(
            "SELECT * FROM public.pg_class"
        ));
        assert!(!touches_leaky_system_catalog(
            "SELECT * FROM information_schema.tables"
        ));
        // Unqualified name/grant views are not leaky: they might be user tables.
        assert!(!touches_leaky_system_catalog("SELECT * FROM tables"));
    }

    #[test]
    fn fork_substrings_skip_catalog_shaped_names() {
        assert!(!is_non_catalog_shaped_fork_dump("pg_stat_statements_info"));
        assert!(!is_non_catalog_shaped_fork_dump("pg_stat_activity"));
        assert!(is_non_catalog_shaped_fork_dump("citus_stat_activity"));
        assert!(is_non_catalog_shaped_fork_dump("edb_stat_activity"));
        assert!(is_non_catalog_shaped_fork_dump("citus_lock_waits"));
        assert!(is_non_catalog_shaped_fork_dump("citus_stat_statements"));
        assert!(is_non_catalog_shaped_fork_dump("citus_stat_tenants"));
        assert!(!touches_leaky_system_catalog(
            "SELECT * FROM pg_catalog.pg_stat_statements_info"
        ));
        assert!(touches_leaky_system_catalog(
            "SELECT * FROM pg_catalog.pg_stat_activity"
        ));
        assert!(touches_leaky_system_catalog(
            "SELECT * FROM citus_stat_statements"
        ));
    }

    #[test]
    fn unseen_progress_statio_and_wait_sampling_names_are_leaky() {
        for name in [
            "pg_stat_progress_future",
            "pg_statio_future",
            "pg_wait_sampling_dump",
        ] {
            assert!(
                !relation_is_metadata_safe_pg(name),
                "prefix-allow was an allow for an unseen name: {name}"
            );
            assert!(
                touches_leaky_system_catalog(&format!("SELECT * FROM pg_catalog.{name}")),
                "{name}"
            );
        }
        for name in [
            "pg_wait_sampling_profile",
            "pg_wait_sampling_history",
            "pg_wait_sampling_current",
        ] {
            assert!(relation_is_metadata_safe_pg(name), "{name}");
            assert!(!touches_leaky_system_catalog(&format!(
                "SELECT * FROM pg_catalog.{name}"
            )));
        }
    }

    #[test]
    fn contrib_exceptions_are_not_in_the_vanilla_table() {
        for name in CONTRIB_METADATA_SAFE_PG {
            assert!(
                vanilla_pg_classification(name).is_none(),
                "{name} is contrib; keep it off VANILLA_PG_CATALOG"
            );
            assert!(
                relation_is_metadata_safe_pg(name),
                "{name} must stay metadata-safe as a named contrib exception"
            );
        }
        assert!(!relation_is_metadata_safe_pg("pg_stat_statements"));
        assert!(!relation_is_metadata_safe_pg("pg_stat_progress_future"));
        assert!(!relation_is_metadata_safe_pg("pg_statio_future"));
        assert!(!relation_is_metadata_safe_pg("pg_wait_sampling_dump"));
    }

    #[test]
    fn gui_residuals_stay_metadata_safe() {
        for name in [
            "pg_roles",
            "pg_foreign_table",
            "pg_settings",
            "pg_class",
            "pg_attribute",
            "pg_statistic_ext",
            "pg_attrdef",
            "pg_rewrite",
            "pg_proc",
            "pg_policy",
        ] {
            assert_eq!(
                vanilla_pg_classification(name),
                Some(true),
                "{name} must stay classified metadata-safe"
            );
        }
    }
}

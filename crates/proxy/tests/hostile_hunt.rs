//! One-shot hunt: SQL shapes not yet in the campaign. Fail if any oracle is open.
//!
//! Analyst residual (must stay allowed): bare `SELECT` of a masked column,
//! simple `ORDER BY` of one, `SELECT … FETCH FIRST`, and `SELECT *` / `TABLE`.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::collections::{HashMap, HashSet};

use pgmask::analysis::{
    calls_untrusted_function, hostile_join_or_rename_masked, hostile_uses_whole_row,
    is_sql_prepare_or_cursor, is_write_statement, masked_exceeds_outer_projection,
    touches_leaky_system_catalog,
};

fn masked() -> HashSet<String> {
    ["email", "name", "phone", "annual_salary", "internal_note"]
        .into_iter()
        .map(str::to_string)
        .collect()
}

fn relations() -> HashMap<String, Vec<String>> {
    let mut m = HashMap::new();
    m.insert(
        "demo.customers".into(),
        vec![
            "id".into(),
            "email".into(),
            "name".into(),
            "phone".into(),
            "city".into(),
            "birth_date".into(),
            "annual_salary".into(),
            "last_ip".into(),
            "account_uuid".into(),
            "internal_note".into(),
            "lookup_key".into(),
        ],
    );
    m.insert(
        "customers".into(),
        vec![
            "id".into(),
            "email".into(),
            "name".into(),
            "phone".into(),
            "city".into(),
        ],
    );
    m
}

fn hostile_refused(sql: &str) -> bool {
    masked_exceeds_outer_projection(sql, &masked())
        || hostile_uses_whole_row(sql, &relations())
        || hostile_join_or_rename_masked(sql, &relations(), &masked())
}

fn any_frontend_refuse(sql: &str) -> bool {
    is_write_statement(sql)
        || is_sql_prepare_or_cursor(sql)
        || calls_untrusted_function(sql)
        || touches_leaky_system_catalog(sql)
        || hostile_refused(sql)
}

#[test]
fn hunt_finds_no_new_oracles() {
    let must_allow = [
        "SELECT email FROM demo.customers",
        "SELECT email, id FROM demo.customers WHERE id = 1",
        "SELECT id FROM demo.customers ORDER BY email",
        "SELECT * FROM demo.customers",
        "TABLE demo.customers",
        "SELECT email FROM demo.customers FETCH FIRST 10 ROWS ONLY",
        "SELECT city FROM demo.customers WHERE city = 'Denver'",
        "SELECT count(*) FROM demo.customers WHERE city = 'Denver'",
        "SELECT email FROM demo.customers WHERE id IN (1, 2)",
        "BEGIN",
        "EXPLAIN SELECT email FROM demo.customers",
        "EXPLAIN SELECT id FROM demo.customers ORDER BY email",
        "SHOW search_path",
        "SELECT DISTINCT email FROM demo.customers",
        "SELECT id FROM demo.customers ORDER BY email NULLS FIRST",
        "SELECT id FROM demo.customers ORDER BY email DESC",
        "TABLE ONLY demo.customers",
        "SELECT t.email FROM demo.customers t",
        r#"SELECT id, count(*) OVER w FROM demo.customers WINDOW w AS (ORDER BY email)"#,
        r#"SELECT id FROM demo.customers ORDER BY email COLLATE "C""#,
        r#"SELECT id FROM demo.customers ORDER BY email USING >"#,
        r#"SELECT id FROM demo.customers ORDER BY email USING OPERATOR(pg_catalog.<)"#,
    ];
    let mut bad = Vec::new();
    for sql in must_allow {
        if hostile_refused(sql) {
            bad.push(format!("OVER-REFUSED analyst SELECT:\n  {sql}"));
        }
    }

    let oracles: &[&str] = &[
        // JSON unique-keys / scalar / value predicates
        r#"SELECT count(*) FROM demo.customers WHERE u&"email" IS JSON WITH UNIQUE KEYS"#,
        r#"SELECT count(*) FROM demo.customers WHERE u&"email" IS JSON WITHOUT UNIQUE KEYS"#,
        r#"SELECT count(*) FROM demo.customers WHERE u&"email" IS JSON SCALAR"#,
        r#"SELECT count(*) FROM demo.customers WHERE u&"email" IS JSON VALUE"#,
        r#"SELECT count(*) FROM demo.customers WHERE u&"email" IS JSON SCALAR WITH UNIQUE KEYS"#,
        r#"SELECT count(*) FROM demo.customers WHERE u&"email" IS NOT JSON WITH UNIQUE KEYS"#,
        r#"SELECT JSON_OBJECT('e': u&"email" WITH UNIQUE KEYS) FROM demo.customers"#,
        r#"SELECT JSON_OBJECT('e': u&"email" ABSENT ON NULL) FROM demo.customers"#,
        r#"SELECT JSON_ARRAY(u&"email" RETURNING jsonb) FROM demo.customers"#,
        r#"SELECT JSON_ARRAY(u&"email" NULL ON NULL) FROM demo.customers"#,
        r#"SELECT json_arrayagg(u&"email" RETURNING jsonb) FROM demo.customers"#,
        r#"SELECT json_objectagg(u&"email": city WITH UNIQUE KEYS) FROM demo.customers"#,
        // substring SIMILAR / overlay / translate family
        r#"SELECT count(*) FROM demo.customers WHERE substring(u&"email" similar '%#"x#"%' escape '#') = 'x'"#,
        r#"SELECT count(*) FROM demo.customers WHERE overlay(u&"email" placing 'x' from 1 for 1) = 'x'"#,
        r#"SELECT count(*) FROM demo.customers WHERE translate(u&"email", 'a', 'b') = 'x'"#,
        r#"SELECT count(*) FROM demo.customers WHERE replace(u&"email", 'a', 'b') = 'x'"#,
        r#"SELECT count(*) FROM demo.customers WHERE reverse(u&"email") = 'x'"#,
        r#"SELECT count(*) FROM demo.customers WHERE repeat(u&"email", 1) = 'x'"#,
        r#"SELECT count(*) FROM demo.customers WHERE ascii(u&"email") = 117"#,
        r#"SELECT count(*) FROM demo.customers WHERE chr(ascii(u&"email")) = 'u'"#,
        r#"SELECT count(*) FROM demo.customers WHERE quote_literal(u&"email") LIKE '%x%'"#,
        r#"SELECT count(*) FROM demo.customers WHERE quote_nullable(u&"email") LIKE '%x%'"#,
        r#"SELECT count(*) FROM demo.customers WHERE quote_ident(u&"email") = 'x'"#,
        r#"SELECT count(*) FROM demo.customers WHERE strpos(u&"email", '@') = 1"#,
        r#"SELECT count(*) FROM demo.customers WHERE substr(u&"email", 1, 1) = 'u'"#,
        r#"SELECT count(*) FROM demo.customers WHERE lpad(u&"email", 10) = 'x'"#,
        r#"SELECT count(*) FROM demo.customers WHERE rpad(u&"email", 10) = 'x'"#,
        r#"SELECT count(*) FROM demo.customers WHERE ltrim(u&"email", 'u') = 'x'"#,
        r#"SELECT count(*) FROM demo.customers WHERE rtrim(u&"email") = 'x'"#,
        r#"SELECT count(*) FROM demo.customers WHERE btrim(u&"email") = 'x'"#,
        r#"SELECT count(*) FROM demo.customers WHERE initcap(u&"email") = 'x'"#,
        r#"SELECT count(*) FROM demo.customers WHERE to_hex(length(u&"email")) = 'c'"#,
        r#"SELECT count(*) FROM demo.customers WHERE octet_length(u&"email") = 5"#,
        r#"SELECT count(*) FROM demo.customers WHERE bit_length(u&"email") = 40"#,
        r#"SELECT count(*) FROM demo.customers WHERE character_length(u&"email") = 5"#,
        r#"SELECT count(*) FROM demo.customers WHERE char_length(u&"email") = 5"#,
        r#"SELECT count(*) FROM demo.customers WHERE get_byte(u&"email"::bytea, 0) = 117"#,
        r#"SELECT count(*) FROM demo.customers WHERE get_bit(u&"email"::bytea, 0) = 1"#,
        r#"SELECT count(*) FROM demo.customers WHERE encode(u&"email"::bytea, 'base64') LIKE '%x%'"#,
        r#"SELECT count(*) FROM demo.customers WHERE convert(u&"email"::bytea, 'UTF8', 'LATIN1') IS NOT NULL"#,
        r#"SELECT count(*) FROM demo.customers WHERE sha256(u&"email"::bytea) IS NOT NULL"#,
        r#"SELECT count(*) FROM demo.customers WHERE to_tsvector('simple', u&"email") @@ 'x'"#,
        r#"SELECT count(*) FROM demo.customers WHERE u&"email" % 'x'"#,
        r#"SELECT count(*) FROM demo.customers WHERE similarity(u&"email", 'x') > 0.5"#,
        r#"SELECT count(*) FROM demo.customers WHERE levenshtein(u&"email", 'x') < 3"#,
        r#"SELECT count(*) FROM demo.customers WHERE regexp_like(u&"email", 'x')"#,
        r#"SELECT count(*) FROM demo.customers WHERE regexp_count(u&"email", 'x') > 0"#,
        r#"SELECT count(*) FROM demo.customers WHERE regexp_substr(u&"email", 'x') = 'x'"#,
        r#"SELECT count(*) FROM demo.customers WHERE regexp_instr(u&"email", 'x') = 1"#,
        r#"SELECT count(*) FROM demo.customers WHERE regexp_replace(u&"email", 'x', 'y') = 'y'"#,
        r#"SELECT count(*) FROM demo.customers WHERE u&"email" ~~* 'x%'"#,
        r#"SELECT count(*) FROM demo.customers WHERE u&"email" !~~ 'x%'"#,
        r#"SELECT count(*) FROM demo.customers WHERE u&"email" !~ 'x'"#,
        r#"SELECT count(*) FROM demo.customers WHERE u&"email" !~* 'x'"#,
        r#"SELECT count(*) FROM demo.customers WHERE u&"email" OPERATOR(pg_catalog.~~*) 'x%'"#,
        r#"SELECT count(*) FROM demo.customers WHERE u&"email" IS NOT DISTINCT FROM 'x'"#,
        r#"SELECT count(*) FROM demo.customers WHERE u&"annual_salary" > 100000"#,
        r#"SELECT count(*) FROM demo.customers WHERE u&"annual_salary" BETWEEN 1 AND 2"#,
        r#"SELECT count(*) FROM demo.customers WHERE u&"phone" LIKE '5%'"#,
        r#"SELECT count(*) FROM demo.customers WHERE u&"name" ILIKE 'a%'"#,
        r#"SELECT count(*) FROM demo.customers WHERE u&"internal_note" IS NULL"#,
        // LATERAL / SRF / VALUES of a masked column
        r#"SELECT count(*) FROM demo.customers, LATERAL (VALUES (u&"email")) v(e) WHERE e = 'x'"#,
        r#"SELECT count(*) FROM demo.customers, LATERAL string_to_table(u&"email", '@') s"#,
        r#"SELECT count(*) FROM demo.customers, LATERAL regexp_split_to_table(u&"email", '@') s"#,
        r#"SELECT * FROM string_to_table((SELECT u&"email" FROM demo.customers LIMIT 1), '@')"#,
        r#"SELECT count(*) FROM demo.customers, unnest(string_to_array(u&"email", '@')) s"#,
        r#"SELECT count(*) FROM demo.customers WHERE string_to_array(u&"email", '@') && ARRAY['x']"#,
        r#"SELECT count(*) FROM demo.customers WHERE u&"email" = ANY(string_to_array('x,y', ','))"#,
        // Window GROUPS / EXCLUDE / FILTER already partly covered
        r#"SELECT id, count(*) OVER (ORDER BY id GROUPS BETWEEN (SELECT count(*) FROM demo.customers t2 WHERE t2.u&"email" = 'x') PRECEDING AND CURRENT ROW) FROM demo.customers"#,
        r#"SELECT id, count(*) OVER (ORDER BY u&"email" GROUPS BETWEEN 1 PRECEDING AND 1 FOLLOWING EXCLUDE CURRENT ROW) FROM demo.customers"#,
        r#"SELECT id, count(*) OVER (ORDER BY id RANGE BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW EXCLUDE TIES) FROM demo.customers WHERE u&"email" = 'x'"#,
        // JOIN USING mixed, NATURAL variants
        r#"SELECT count(*) FROM demo.customers a JOIN demo.customers b USING (id, u&"email")"#,
        r#"SELECT count(*) FROM demo.customers a NATURAL LEFT JOIN demo.customers b"#,
        r#"SELECT count(*) FROM demo.customers a NATURAL RIGHT JOIN demo.customers b"#,
        r#"SELECT count(*) FROM demo.customers a NATURAL FULL JOIN demo.customers b"#,
        r#"SELECT count(*) FROM demo.customers a INNER JOIN demo.customers b ON a.id = b.id AND a.u&"email" = b.u&"email""#,
        r#"SELECT count(*) FROM demo.customers a CROSS JOIN demo.customers b WHERE a.u&"email" = b.u&"email""#,
        // TABLESAMPLE / ONLY / inheritance
        r#"SELECT count(*) FROM demo.customers TABLESAMPLE SYSTEM (50) REPEATABLE (length(u&"email"))"#,
        r#"SELECT count(*) FROM demo.customers TABLESAMPLE BERNOULLI ((SELECT count(*) FROM demo.customers WHERE u&"email" = 'x'))"#,
        // UNIQUE / MATCH / OVERLAPS (some may fail to parse → fail closed)
        r#"SELECT count(*) FROM demo.customers WHERE UNIQUE (SELECT u&"email" FROM demo.customers)"#,
        r#"SELECT count(*) FROM demo.customers WHERE u&"email" MATCH (SELECT u&"email" FROM demo.customers)"#,
        r#"SELECT count(*) FROM demo.customers WHERE (birth_date, birth_date) OVERLAPS (birth_date, u&"email"::date)"#,
        // XML extras
        r#"SELECT count(*) FROM demo.customers WHERE xmlcomment(u&"email") IS NOT NULL"#,
        r#"SELECT count(*) FROM demo.customers WHERE xmlpi(name p, u&"email") IS NOT NULL"#,
        r#"SELECT count(*) FROM demo.customers WHERE xmlroot(xmlelement(name e, u&"email"), version '1.0') IS NOT NULL"#,
        r#"SELECT count(*) FROM demo.customers WHERE xmlconcat(xmlelement(name e, u&"email")) IS NOT NULL"#,
        r#"SELECT count(*) FROM demo.customers WHERE xpath('//e', xmlelement(name e, u&"email")) IS NOT NULL"#,
        r#"SELECT count(*) FROM demo.customers WHERE xml_is_well_formed(u&"email")"#,
        r#"SELECT count(*) FROM XMLTABLE(XMLNAMESPACES(u&"email" AS n), '/n:e' PASSING '<e/>' COLUMNS x text PATH '.')"#,
        // Whole-row extras
        r#"SELECT hstore(t.*) FROM demo.customers t"#,
        r#"SELECT jsonb_pretty(to_jsonb(t)) FROM demo.customers t"#,
        r#"SELECT jsonb_each(to_jsonb(t)) FROM demo.customers t"#,
        r#"SELECT * FROM demo.customers t, jsonb_each(to_jsonb(t))"#,
        r#"SELECT (jsonb_each(to_jsonb(t))).* FROM demo.customers t"#,
        r#"SELECT json_each_text(row_to_json(t)) FROM demo.customers t"#,
        r#"SELECT jsonb_object_keys(to_jsonb(t)) FROM demo.customers t"#,
        r#"SELECT t::json FROM demo.customers t"#,
        r#"SELECT t::jsonb FROM demo.customers t"#,
        r#"SELECT CAST(t AS jsonb) FROM demo.customers t"#,
        r#"SELECT ROW(t.*)::text FROM demo.customers t"#,
        r#"SELECT (t).*::text FROM demo.customers t"#,
        r#"SELECT demo.customers FROM demo.customers"#,
        r#"SELECT customers FROM demo.customers"#,
        r#"SELECT count(*) FROM demo.customers t WHERE (t).* IS NOT NULL"#,
        r#"SELECT * FROM json_populate_record(null::demo.customers, to_json(t)) FROM demo.customers t"#,
        r#"SELECT * FROM json_to_record(to_json(t)) AS x(id int, email text) FROM demo.customers t"#,
        r#"SELECT count(*) FROM demo.customers t WHERE t::demo.customers IS NOT NULL"#,
        r#"SELECT count(*) FROM demo.customers t WHERE row_to_json(t)->>'email' = 'x'"#,
        r#"SELECT count(*) FROM demo.customers t WHERE to_jsonb(t) @> '{"email":"x"}'"#,
        r#"SELECT count(*) FROM demo.customers t WHERE jsonb_path_query_first(to_jsonb(t), '$.email') #>> '{}' = 'x'"#,
        // EXPLAIN wrappers around unicode predicates
        r#"EXPLAIN (ANALYZE false, COSTS false) SELECT count(*) FROM demo.customers WHERE u&"email" = 'x'"#,
        r#"EXPLAIN (VERBOSE true) SELECT count(*) FROM demo.customers WHERE u&"email" = 'x'"#,
        r#"EXPLAIN (FORMAT JSON) SELECT count(*) FROM demo.customers WHERE u&"email" = 'x'"#,
        r#"EXPLAIN (GENERIC_PLAN) SELECT count(*) FROM demo.customers WHERE u&"email" = 'x'"#,
        // Collation / domain / cstring
        r#"SELECT count(*) FROM demo.customers WHERE u&"email" COLLATE "und-x-icu" = 'x'"#,
        r#"SELECT count(*) FROM demo.customers WHERE u&"email"::cstring = 'x'"#,
        r#"SELECT count(*) FROM demo.customers WHERE u&"email"::name = 'x'"#,
        r#"SELECT count(*) FROM demo.customers WHERE u&"email"::varchar(32) = 'x'"#,
        r#"SELECT count(*) FROM demo.customers WHERE CAST(u&"email" AS character varying) = 'x'"#,
        // GROUPING / FILTER / WITHIN GROUP extras
        r#"SELECT percentile_cont(0.5) WITHIN GROUP (ORDER BY u&"annual_salary") FROM demo.customers"#,
        r#"SELECT count(*) FILTER (WHERE u&"annual_salary" > 1) FROM demo.customers"#,
        r#"SELECT bool_or(u&"email" = 'x') FROM demo.customers"#,
        r#"SELECT bool_and(u&"email" <> 'x') FROM demo.customers"#,
        r#"SELECT every(u&"email" <> 'x') FROM demo.customers"#,
        // JSON_TABLE plan / passing
        r#"SELECT * FROM demo.customers, JSON_TABLE(u&"email", '$' COLUMNS (x text PATH '$')) jt"#,
        r#"SELECT * FROM JSON_TABLE((SELECT u&"email" FROM demo.customers LIMIT 1), '$' COLUMNS (x text PATH '$')) jt"#,
        // set-op with unicode on one side only
        r#"SELECT u&"email" FROM demo.customers INTERSECT SELECT 'x'"#,
        r#"SELECT u&"email" FROM demo.customers EXCEPT SELECT 'x'"#,
        r#"SELECT 'x' INTERSECT SELECT u&"email" FROM demo.customers"#,
        r#"SELECT u&"email" FROM demo.customers UNION ALL SELECT u&"name" FROM demo.customers"#,
        // CTE SEARCH / CYCLE extras
        r#"WITH RECURSIVE r AS (SELECT id, u&"email" FROM demo.customers UNION ALL SELECT id, email FROM r WHERE false)
           SEARCH DEPTH FIRST BY u&"email" SET ord CYCLE u&"email" SET is_cycle USING path SELECT count(*) FROM r"#,
        // Prefix mixed
        r#"SELECT count(*) FROM demo.customers WHERE U&"\0065mail" = 'x'"#,
        r#"SELECT count(*) FROM demo.customers WHERE u&"\0065mail" LIKE 'x%'"#,
        // Alias hiding via output name then filter (inner still names email)
        r#"SELECT count(*) FROM (SELECT u&"email" AS c2 FROM demo.customers) s WHERE c2 = 'x'"#,
        r#"SELECT count(*) FROM (SELECT u&"email" FROM demo.customers) s(c2) WHERE c2 = 'x'"#,
        // Whole-row in ARRAY constructor already; VARIADIC
        r#"SELECT format('%s', VARIADIC ARRAY[t::text]) FROM demo.customers t"#,
        // current of — needs cursor, still a ColumnRef?
        r#"SELECT count(*) FROM demo.customers WHERE CURRENT OF c"#,
        // Leaky catalogs (frontend, every posture)
        r#"SELECT most_common_vals FROM pg_stats"#,
        r#"SELECT most_common_vals FROM pg_catalog.pg_stats"#,
        r#"SELECT * FROM u&"pg_stats""#,
        r#"SELECT * FROM pg_catalog.u&"pg_stats""#,
        r#"SELECT query FROM pg_stat_activity"#,
        r#"SELECT * FROM u&"pg_stat_activity""#,
        r#"SELECT rolpassword FROM u&"pg_authid""#,
        r#"EXPLAIN SELECT most_common_vals FROM pg_stats"#,
        r#"EXPLAIN (ANALYZE true) SELECT query FROM pg_stat_activity"#,
        r#"EXPLAIN SELECT * FROM pg_catalog.pg_stats"#,
        r#"SELECT query FROM pg_stat_get_activity(NULL)"#,
        r#"SELECT * FROM pg_stat_get_activity(NULL) a"#,
        r#"SELECT * FROM pg_stat_statements()"#,
        r#"SELECT statement FROM pg_cursors"#,
        r#"SELECT * FROM pg_prepared_statements"#,
        r#"SELECT passwd FROM pg_user"#,
        r#"SELECT * FROM pg_user"#,
        r#"SELECT data FROM pg_largeobject"#,
        r#"SELECT stavalues1 FROM pg_statistic"#,
        r#"WITH s AS (SELECT * FROM pg_stats) SELECT * FROM s"#,
        r#"SELECT * FROM (SELECT * FROM pg_stats) s"#,
        r#"SELECT pg_read_file('/etc/passwd')"#,
        r#"SELECT query_to_xml('SELECT email FROM demo.customers', false, true, '')"#,
        // Writes still refuse
        r#"ANALYZE demo.customers"#,
        r#"VACUUM demo.customers"#,
        r#"REFRESH MATERIALIZED VIEW demo.v"#,
        r#"SELECT email INTO x FROM demo.customers"#,
        r#"SELECT email FROM demo.customers FOR UPDATE"#,
        r#"MERGE INTO demo.customers t USING demo.customers s ON t.id = s.id WHEN MATCHED THEN UPDATE SET city = s.city"#,
        r#"COPY demo.customers TO STDOUT"#,
        r#"LISTEN x"#,
        r#"LOAD 'auto_explain'"#,
        r#"SELECT CAST(1 AS numeric((SELECT count(*) FROM demo.customers WHERE u&"email" = 'x'), 0))"#,
        r#"SELECT count(*) FROM demo.customers WHERE CAST(1 AS numeric((SELECT count(*) FROM demo.customers t2 WHERE t2.u&"email" = 'x'), 0)) IS NOT NULL"#,
        r#"SELECT JSON_VALUE('1', '$' RETURNING numeric((SELECT count(*) FROM demo.customers WHERE u&"email" = 'x'), 0))"#,
        r#"SELECT JSON_QUERY('1', '$' RETURNING numeric((SELECT count(*) FROM demo.customers WHERE u&"email" = 'x'), 0))"#,
        r#"SELECT count(*) FROM demo.customers WHERE JSON_VALUE('1', '$' RETURNING numeric((SELECT count(*) FROM demo.customers t2 WHERE t2.u&"email" = 'x'), 0)) IS NOT NULL"#,
        r#"EXPLAIN SELECT JSON_VALUE('1', '$' RETURNING numeric((SELECT count(*) FROM demo.customers WHERE u&"email" = 'x'), 0))"#,
        r#"SELECT database_to_xml(true, true, '') FROM pg_catalog.pg_class"#,
        r#"SELECT schema_to_xml('demo', true, true, '') FROM pg_catalog.pg_class"#,
        r#"SELECT pg_stat_get_activity(NULL) FROM pg_catalog.pg_class"#,
        r#"SELECT pg_ls_logdir() FROM pg_catalog.pg_class"#,
        r#"SELECT pg_logical_slot_get_changes('s', NULL, NULL) FROM pg_catalog.pg_class"#,
        r#"SELECT pg_stat_get_wal_receiver() FROM pg_catalog.pg_class"#,
        r#"SELECT pg_stat_get_wal_receiver() FROM pg_catalog.pg_database"#,
        r#"SELECT crosstab('SELECT email FROM demo.customers') FROM pg_catalog.pg_class"#,
        r#"SELECT connectby('demo.customers','id','id','id','1',0) FROM pg_catalog.pg_class"#,
        r#"SELECT dblink_exec('dbname=x', 'SELECT 1') FROM pg_catalog.pg_class"#,
        r#"SELECT dblink_connect('dbname=x') FROM pg_catalog.pg_class"#,
        r#"SELECT pg_file_read('postgresql.conf', 0, 100) FROM pg_catalog.pg_class"#,
        r#"SELECT pg_logdir_ls() FROM pg_catalog.pg_class"#,
        r#"SELECT loread(1, 100) FROM pg_catalog.pg_class"#,
        r#"SELECT lo_open(1, 262144) FROM pg_catalog.pg_class"#,
        r#"SELECT pg_get_wal_records_info('0/0', '0/0') FROM pg_catalog.pg_class"#,
        r#"SELECT pg_get_wal_block_info('0/0', '0/0') FROM pg_catalog.pg_class"#,
        // Target-list FuncCall is an allowlist: unnamed dumps joined to
        // pg_class used to skip the untrusted-function gate.
        r#"SELECT get_raw_page('demo.customers'::regclass, 0) FROM pg_catalog.pg_class"#,
        r#"SELECT pg_catalog.get_raw_page('demo.customers'::regclass, 0) FROM pg_catalog.pg_class"#,
        r#"SELECT u&"get_raw_page"('demo.customers'::regclass, 0) FROM pg_catalog.pg_class"#,
        r#"SELECT heap_page_items(get_raw_page('demo.customers'::regclass, 0)) FROM pg_catalog.pg_class"#,
        r#"SELECT pg_sleep(0) FROM pg_catalog.pg_class"#,
        r#"SELECT set_config('application_name', 'x', false) FROM pg_catalog.pg_class"#,
        r#"SELECT pg_file_write('x', 'y', false) FROM pg_catalog.pg_class"#,
        r#"SELECT pg_terminate_backend(pg_backend_pid()) FROM pg_catalog.pg_class"#,
        r#"SELECT not_a_catalog_fn() FROM pg_catalog.pg_class"#,
    ];

    for sql in oracles {
        if !any_frontend_refuse(sql) {
            let parse_ok = pg_query::parse(sql).is_ok();
            bad.push(format!("OPEN (parse_ok={parse_ok}):\n  {sql}"));
        }
    }

    if !bad.is_empty() {
        panic!("{} finding(s):\n{}", bad.len(), bad.join("\n"));
    }
}

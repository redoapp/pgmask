//! Adversarial campaign against the hostile read-only gate.
//!
//! Unicode-escaped identifiers (`u&"email"`) never appear as the bare word
//! `email` in the token stream. Every shape here is a membership / value
//! oracle if the parse-tree tally misses the decoded name. Whole-row casts
//! never name a masked column at all.
//!
//! Allowed residual under hostile: bare projection of a masked column, and
//! simple `ORDER BY` of one (cells stay masked). Everything else must refuse.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::collections::{HashMap, HashSet};

use pgmask::analysis::{
    hostile_join_or_rename_masked, hostile_uses_whole_row, masked_exceeds_outer_projection,
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

fn must_refuse_projection(sql: &str) -> Option<&'static str> {
    if masked_exceeds_outer_projection(sql, &masked()) {
        None
    } else {
        Some("projection-gate allowed a masked-column oracle")
    }
}

fn must_refuse_whole_row(sql: &str) -> Option<&'static str> {
    if hostile_uses_whole_row(sql, &relations()) {
        None
    } else {
        Some("whole-row gate allowed a cleartext row oracle")
    }
}

fn must_refuse_join_rename(sql: &str) -> Option<&'static str> {
    if hostile_join_or_rename_masked(sql, &relations(), &masked()) {
        None
    } else {
        Some("join/rename gate allowed a hidden-name oracle")
    }
}

fn must_allow_projection(sql: &str) -> Option<&'static str> {
    if masked_exceeds_outer_projection(sql, &masked()) {
        Some("projection-gate over-refused a bare projection / simple ORDER BY")
    } else {
        None
    }
}

/// One campaign pass. Returns every shape that is still open (or over-refused).
fn run_pass() -> Vec<(String, &'static str)> {
    let mut open = Vec::new();
    let mut check = |sql: &str, fail: Option<&'static str>| {
        if let Some(why) = fail {
            open.push((sql.to_string(), why));
        }
    };

    // --- Residual that must stay allowed -----------------------------------
    for sql in [
        "SELECT email FROM demo.customers",
        "SELECT email, id FROM demo.customers WHERE id = 1",
        "SELECT id FROM demo.customers ORDER BY email",
        "SELECT email FROM demo.customers ORDER BY email",
        "SELECT email FROM demo.customers ORDER BY 1",
        "SELECT email AS e FROM demo.customers ORDER BY e",
        "SELECT id FROM demo.customers ORDER BY email COLLATE \"C\"",
        "SELECT id FROM demo.customers ORDER BY email::text",
        r#"SELECT id FROM demo.customers ORDER BY u&"email" COLLATE "C""#,
        r#"SELECT id FROM demo.customers ORDER BY u&"email" USING <"#,
        "SELECT email FROM demo.customers WHERE id IN (1, 2)",
        "SELECT city FROM demo.customers WHERE city = 'Denver'",
        "SELECT count(*) FROM demo.customers WHERE city = 'Denver'",
    ] {
        check(sql, must_allow_projection(sql));
    }

    // --- Unicode membership oracles ----------------------------------------
    let unicode: &[&str] = &[
        r#"SELECT count(*) FROM demo.customers WHERE u&"email" = 'x'"#,
        r#"SELECT count(*) FROM demo.customers WHERE u&"email" LIKE 'x%'"#,
        r#"SELECT count(*) FROM demo.customers WHERE u&"email" ILIKE 'x%'"#,
        r#"SELECT count(*) FROM demo.customers WHERE u&"email" SIMILAR TO 'x%'"#,
        r#"SELECT count(*) FROM demo.customers WHERE u&"email" ~ 'x'"#,
        r#"SELECT count(*) FROM demo.customers WHERE u&"email" ~* 'x'"#,
        r#"SELECT count(*) FROM demo.customers WHERE u&"email" IN ('x')"#,
        r#"SELECT count(*) FROM demo.customers WHERE u&"email" NOT IN ('x')"#,
        r#"SELECT count(*) FROM demo.customers WHERE u&"email" BETWEEN 'a' AND 'z'"#,
        r#"SELECT count(*) FROM demo.customers WHERE u&"email" BETWEEN SYMMETRIC 'a' AND 'z'"#,
        r#"SELECT count(*) FROM demo.customers WHERE u&"email" IS DISTINCT FROM 'x'"#,
        r#"SELECT count(*) FROM demo.customers WHERE u&"email" IS NOT DISTINCT FROM 'x'"#,
        r#"SELECT count(*) FROM demo.customers WHERE u&"email" IS NULL"#,
        r#"SELECT count(*) FROM demo.customers WHERE u&"email" IS NOT NULL"#,
        r#"SELECT count(*) FROM demo.customers WHERE (u&"email" = 'x') IS TRUE"#,
        r#"SELECT count(*) FROM demo.customers WHERE (u&"email" = 'x') IS NOT FALSE"#,
        r#"SELECT count(*) FROM demo.customers WHERE (u&"email" = 'x') IS UNKNOWN"#,
        r#"SELECT count(*) FROM demo.customers WHERE NOT (u&"email" = 'x')"#,
        r#"SELECT count(*) FROM demo.customers WHERE (u&"email" = 'x') AND true"#,
        r#"SELECT count(*) FROM demo.customers WHERE (u&"email" = 'x') OR false"#,
        r#"SELECT count(*) FROM demo.customers WHERE u&"email" LIKE 'x%' ESCAPE '\'"#,
        r#"SELECT count(*) FROM demo.customers WHERE u&"email" COLLATE "C" = 'x'"#,
        r#"SELECT count(*) FROM demo.customers WHERE CAST(u&"email" AS text) = 'x'"#,
        r#"SELECT count(*) FROM demo.customers WHERE u&"email"::text = 'x'"#,
        r#"SELECT count(*) FROM demo.customers WHERE 'x' = ANY(ARRAY[u&"email"])"#,
        r#"SELECT count(*) FROM demo.customers WHERE u&"email" = ANY(ARRAY['x'])"#,
        r#"SELECT count(*) FROM demo.customers WHERE u&"email" = ALL(ARRAY['x'])"#,
        r#"SELECT count(*) FROM demo.customers WHERE u&"email" LIKE ANY(ARRAY['x%'])"#,
        r#"SELECT count(*) FROM demo.customers WHERE COALESCE(u&"email", 'x') = 'x'"#,
        r#"SELECT count(*) FROM demo.customers WHERE NULLIF(u&"email", 'x') IS NULL"#,
        r#"SELECT count(*) FROM demo.customers WHERE GREATEST(u&"email", 'a') = 'x'"#,
        r#"SELECT count(*) FROM demo.customers WHERE LEAST(u&"email", 'z') = 'x'"#,
        r#"SELECT count(*) FROM demo.customers WHERE CASE u&"email" WHEN 'x' THEN true ELSE false END"#,
        r#"SELECT count(*) FROM demo.customers WHERE CASE WHEN u&"email" = 'x' THEN true ELSE false END"#,
        r#"SELECT count(*) FROM demo.customers WHERE (ARRAY[u&"email"])[1] = 'x'"#,
        r#"SELECT count(*) FROM demo.customers WHERE ROW(u&"email") = ROW('x')"#,
        r#"SELECT count(*) FROM demo.customers WHERE (u&"email", id) = ('x', 1)"#,
        r#"SELECT count(*) FROM demo.customers WHERE (u&"email", id) > ('a', 0)"#,
        r#"SELECT count(*) FROM demo.customers t WHERE (t).u&"email" = 'x'"#,
        r#"SELECT count(*) FROM demo.customers t WHERE t.u&"email" = 'x'"#,
        r#"SELECT count(*) FROM demo.customers WHERE overlay(u&"email" placing 'x' from 1) = 'x'"#,
        r#"SELECT count(*) FROM demo.customers WHERE substring(u&"email" from 1 for 5) = 'x'"#,
        r#"SELECT count(*) FROM demo.customers WHERE trim(u&"email") = 'x'"#,
        r#"SELECT count(*) FROM demo.customers WHERE position('x' in u&"email") = 1"#,
        r#"SELECT count(*) FROM demo.customers WHERE format('%s', u&"email") = 'x'"#,
        r#"SELECT count(*) FROM demo.customers WHERE concat(u&"email") = 'x'"#,
        r#"SELECT count(*) FROM demo.customers WHERE md5(u&"email") = md5('x')"#,
        r#"SELECT count(*) FROM demo.customers WHERE lower(u&"email") = 'x'"#,
        r#"SELECT count(*) FROM demo.customers WHERE starts_with(u&"email", 'x')"#,
        r#"SELECT count(*) FROM demo.customers WHERE split_part(u&"email", '@', 1) = 'x'"#,
        r#"SELECT count(*) FROM demo.customers WHERE length(u&"email") = 5"#,
        r#"SELECT count(*) FROM demo.customers WHERE pg_column_size(u&"email") = 20"#,
        // JOIN … ON
        r#"SELECT count(*) FROM demo.customers a JOIN demo.customers b ON a.u&"email" = b.u&"email""#,
        r#"SELECT count(*) FROM demo.customers a JOIN (VALUES (1)) v(x) ON a.u&"email" = 'x'"#,
        r#"SELECT count(*) FROM demo.customers a LEFT JOIN (VALUES (1)) v(x) ON a.u&"email" = 'x'"#,
        r#"SELECT count(*) FROM demo.customers a RIGHT JOIN (VALUES (1)) v(x) ON a.u&"email" = 'x'"#,
        r#"SELECT count(*) FROM demo.customers a FULL JOIN (VALUES (1)) v(x) ON a.u&"email" = 'x'"#,
        r#"SELECT count(*) FROM demo.customers a JOIN demo.customers b USING (u&"email")"#,
        r#"SELECT count(*) FROM demo.customers a INNER JOIN LATERAL (SELECT 1 WHERE a.u&"email" = 'x') s ON true"#,
        // FROM / SRF
        r#"SELECT count(*) FROM demo.customers, unnest(ARRAY[u&"email"])"#,
        r#"SELECT count(*) FROM demo.customers, generate_series(1, CASE WHEN u&"email" = 'x' THEN 1 ELSE 0 END)"#,
        r#"SELECT * FROM unnest((SELECT array_agg(u&"email") FROM demo.customers))"#,
        r#"SELECT * FROM ROWS FROM (unnest(ARRAY(SELECT u&"email" FROM demo.customers)))"#,
        r#"SELECT * FROM unnest(ARRAY(SELECT u&"email" FROM demo.customers)) WITH ORDINALITY"#,
        // Aggregates / FILTER / ORDER BY inside agg
        r#"SELECT count(*) FILTER (WHERE u&"email" = 'x') FROM demo.customers"#,
        r#"SELECT string_agg(city, ',') FILTER (WHERE u&"email" = 'x') FROM demo.customers"#,
        r#"SELECT string_agg(city, ',' ORDER BY u&"email") FROM demo.customers"#,
        r#"SELECT string_agg(city, ',' ORDER BY u&"email" = 'x') FROM demo.customers"#,
        r#"SELECT array_agg(city ORDER BY u&"email" = 'x') FROM demo.customers"#,
        r#"SELECT json_agg(city ORDER BY u&"email" = 'x') FROM demo.customers"#,
        r#"SELECT json_object_agg(city, id ORDER BY u&"email" = 'x') FROM demo.customers"#,
        r#"SELECT mode() WITHIN GROUP (ORDER BY u&"email") FROM demo.customers"#,
        r#"SELECT percentile_disc(0.5) WITHIN GROUP (ORDER BY u&"email" = 'x') FROM demo.customers"#,
        r#"SELECT json_agg(city) FILTER (WHERE u&"email" = 'x') FROM demo.customers"#,
        r#"SELECT json_object_agg(city, u&"email") FROM demo.customers"#,
        r#"SELECT json_arrayagg(u&"email") FROM demo.customers"#,
        r#"SELECT json_objectagg(city: u&"email") FROM demo.customers"#,
        r#"SELECT xmlagg(xmlelement(name e, u&"email")) FROM demo.customers"#,
        r#"SELECT GROUPING(u&"email"), count(*) FROM demo.customers GROUP BY GROUPING SETS ((u&"email"), ())"#,
        // Window / frame offsets
        r#"SELECT id, count(*) OVER (PARTITION BY u&"email") FROM demo.customers"#,
        r#"SELECT id, count(*) OVER (ORDER BY u&"email" = 'x') FROM demo.customers"#,
        r#"SELECT id, count(*) OVER (PARTITION BY id ORDER BY id ROWS BETWEEN (SELECT count(*) FROM demo.customers t2 WHERE t2.u&"email" = 'x') PRECEDING AND CURRENT ROW) FROM demo.customers"#,
        r#"SELECT id, count(*) OVER w FROM demo.customers WINDOW w AS (PARTITION BY u&"email" = 'x')"#,
        r#"SELECT id, sum(id) OVER (ORDER BY id RANGE BETWEEN (SELECT count(*)::int FROM demo.customers t2 WHERE t2.u&"email" = 'x') PRECEDING AND CURRENT ROW) FROM demo.customers"#,
        r#"SELECT ntile(2) OVER (ORDER BY u&"email") FROM demo.customers"#,
        r#"SELECT first_value(city) OVER (ORDER BY u&"email") FROM demo.customers"#,
        r#"SELECT count(*) FILTER (WHERE u&"email" = 'x') OVER () FROM demo.customers"#,
        // GROUP BY / HAVING / DISTINCT
        r#"SELECT count(*) FROM demo.customers GROUP BY u&"email""#,
        r#"SELECT count(*) FROM demo.customers GROUP BY CUBE(u&"email")"#,
        r#"SELECT count(*) FROM demo.customers GROUP BY ROLLUP(u&"email")"#,
        r#"SELECT count(*) FROM demo.customers GROUP BY GROUPING SETS ((u&"email"))"#,
        r#"SELECT count(*) FROM demo.customers GROUP BY u&"email" COLLATE "C""#,
        r#"SELECT count(*) FROM demo.customers HAVING bool_or(u&"email" = 'x')"#,
        r#"SELECT DISTINCT ON (u&"email") id FROM demo.customers"#,
        r#"SELECT DISTINCT ON (u&"email" = 'x') id FROM demo.customers"#,
        // ORDER BY oracles (not simple sort)
        r#"SELECT id FROM demo.customers ORDER BY u&"email" = 'x'"#,
        r#"SELECT id FROM demo.customers ORDER BY lower(u&"email")"#,
        r#"SELECT id FROM demo.customers ORDER BY CASE WHEN u&"email" = 'x' THEN 0 ELSE 1 END"#,
        // LIMIT / OFFSET / FETCH
        r#"SELECT id FROM demo.customers LIMIT (SELECT count(*) FROM demo.customers WHERE u&"email" = 'x')"#,
        r#"SELECT id FROM demo.customers OFFSET (SELECT count(*) FROM demo.customers WHERE u&"email" = 'x')"#,
        r#"SELECT id FROM demo.customers FETCH FIRST (SELECT count(*) FROM demo.customers WHERE u&"email" = 'x') ROWS ONLY"#,
        // Subqueries / CTEs / set ops
        r#"SELECT count(*) FROM demo.customers WHERE EXISTS (SELECT 1 FROM demo.customers t2 WHERE t2.u&"email" = 'x')"#,
        r#"SELECT count(*) FROM demo.customers WHERE id IN (SELECT id FROM demo.customers WHERE u&"email" = 'x')"#,
        r#"SELECT count(*) FROM demo.customers WHERE 'x' IN (SELECT u&"email" FROM demo.customers)"#,
        r#"SELECT count(*) FROM demo.customers WHERE 'x' = ANY (SELECT u&"email" FROM demo.customers)"#,
        r#"SELECT count(*) FROM demo.customers WHERE 'x' = ALL (SELECT u&"email" FROM demo.customers)"#,
        r#"SELECT count(*) FROM demo.customers WHERE 'x' = SOME (SELECT u&"email" FROM demo.customers)"#,
        r#"WITH q AS (SELECT * FROM demo.customers WHERE u&"email" = 'x') SELECT count(*) FROM q"#,
        r#"WITH q AS MATERIALIZED (SELECT * FROM demo.customers WHERE u&"email" = 'x') SELECT count(*) FROM q"#,
        r#"SELECT count(*) FROM (SELECT * FROM demo.customers WHERE u&"email" = 'x') s"#,
        r#"SELECT (SELECT count(*) FROM demo.customers WHERE u&"email" = 'x')"#,
        r#"SELECT EXISTS (SELECT 1 FROM demo.customers WHERE u&"email" = 'x')"#,
        r#"VALUES ((SELECT u&"email" FROM demo.customers LIMIT 1))"#,
        r#"SELECT u&"email" FROM demo.customers UNION SELECT 'x'"#,
        r#"SELECT id FROM demo.customers WHERE u&"email" = 'x' UNION SELECT 1"#,
        r#"WITH RECURSIVE x(n, u&"email") AS (SELECT 1, email FROM demo.customers) SELECT count(*) FROM x"#,
        r#"SELECT * FROM (VALUES ('x')) v(u&"email")"#,
        // JSON / XML constructors
        r#"SELECT count(*) FROM demo.customers WHERE JSON_OBJECT('e': u&"email")->>'e' = 'x'"#,
        r#"SELECT count(*) FROM demo.customers WHERE JSON_ARRAY(u&"email")->>0 = 'x'"#,
        r#"SELECT count(*) FROM demo.customers WHERE json_build_object('e', u&"email")->>'e' = 'x'"#,
        r#"SELECT count(*) FROM demo.customers WHERE jsonb_build_array(u&"email")->>0 = 'x'"#,
        r#"SELECT count(*) FROM demo.customers WHERE to_json(u&"email")::text LIKE '%x%'"#,
        r#"SELECT count(*) FROM demo.customers WHERE JSON_VALUE(JSON_OBJECT('e': u&"email"), '$.e') = 'x'"#,
        r#"SELECT count(*) FROM demo.customers WHERE JSON_QUERY(JSON_OBJECT('e': u&"email"), '$.e') IS NOT NULL"#,
        r#"SELECT count(*) FROM demo.customers WHERE JSON_EXISTS(JSON_OBJECT('e': u&"email"), '$.e')"#,
        r#"SELECT count(*) FROM demo.customers WHERE JSON_SERIALIZE(JSON_OBJECT('e': u&"email")) LIKE '%x%'"#,
        r#"SELECT count(*) FROM demo.customers WHERE xmlforest(u&"email") IS NOT NULL"#,
        r#"SELECT count(*) FROM demo.customers WHERE xmlelement(name e, u&"email") IS NOT NULL"#,
        r#"SELECT count(*) FROM demo.customers WHERE xmlserialize(CONTENT xmlforest(u&"email" AS e) AS text) LIKE '%x%'"#,
        r#"SELECT * FROM XMLTABLE('/row' PASSING xmlelement(name row, xmlforest(u&"email")) COLUMNS e text PATH 'email')"#,
        r#"SELECT jt.* FROM demo.customers, JSON_TABLE(json_build_object('e', u&"email"), '$' COLUMNS (e text PATH '$.e')) jt"#,
        // EXPLAIN / PREPARE / DECLARE (read-only wrappers)
        r#"EXPLAIN SELECT count(*) FROM demo.customers WHERE u&"email" = 'x'"#,
        r#"EXPLAIN (ANALYZE false) SELECT count(*) FROM demo.customers WHERE u&"email" = 'x'"#,
        r#"PREPARE q AS SELECT count(*) FROM demo.customers WHERE u&"email" = 'x'"#,
        r#"DECLARE c CURSOR FOR SELECT count(*) FROM demo.customers WHERE u&"email" = 'x'"#,
        // Hex / mixed unicode
        r#"SELECT count(*) FROM demo.customers WHERE u&"e\006dail" = 'x'"#,
        r#"SELECT count(*) FROM demo.customers WHERE u&"e\006dail" LIKE 'x%'"#,
        // Projection of an expression (not bare)
        r#"SELECT lower(u&"email") FROM demo.customers"#,
        r#"SELECT u&"email" || '' FROM demo.customers"#,
        r#"SELECT pg_column_size(u&"email") FROM demo.customers"#,
        r#"SELECT count(*) FROM demo.customers TABLESAMPLE SYSTEM ((SELECT count(*) FROM demo.customers WHERE u&"email" = 'x'))"#,
        r#"SELECT count(*) FROM ONLY demo.customers WHERE u&"email" = 'x'"#,
        r#"SELECT count(*) FROM demo.customers WHERE u&"email" OPERATOR(pg_catalog.=) 'x'"#,
        r#"SELECT count(*) FROM demo.customers WHERE U&"!0065mail" UESCAPE '!' = 'x'"#,
        r#"SELECT count(*) FROM demo.customers WHERE u&"email" IS JSON"#,
        r#"SELECT count(*) FROM demo.customers WHERE CAST(u&"email" AS varchar) = 'x'"#,
        r#"SELECT id FROM demo.customers FETCH FIRST (SELECT count(*) FROM demo.customers WHERE u&"email" = 'x') ROWS WITH TIES"#,
        r#"SELECT count(*) FROM demo.customers WHERE u&"email" SIMILAR TO 'x%' ESCAPE '#'"#,
        r#"SELECT json_object_agg(city, id ORDER BY u&"email") FROM demo.customers"#,
        r#"SELECT percentile_cont(0.5) WITHIN GROUP (ORDER BY length(u&"email")) FROM demo.customers"#,
    ];
    for sql in unicode {
        check(sql, must_refuse_projection(sql));
    }

    // --- Whole-row cleartext oracles ---------------------------------------
    let whole_row: &[&str] = &[
        "SELECT count(*) FROM demo.customers t WHERE t::text LIKE '%x%'",
        "SELECT count(*) FROM demo.customers t WHERE format('%s', t) LIKE '%x%'",
        "SELECT count(*) FROM demo.customers WHERE customers::text LIKE '%x%'",
        "SELECT count(*) FROM demo.customers t WHERE CAST(t AS text) LIKE '%x%'",
        "SELECT count(*) FROM demo.customers t WHERE t::text COLLATE \"C\" LIKE '%x%'",
        "SELECT count(*) FROM demo.customers t WHERE t::text LIKE '%x%' COLLATE \"C\"",
        "SELECT count(*) FILTER (WHERE t::text LIKE '%x%') FROM demo.customers t",
        "SELECT count(*) FROM demo.customers t WHERE (t::text LIKE '%x%') IS TRUE",
        "SELECT count(*) FROM demo.customers t WHERE (t::text LIKE '%x%') IS NOT FALSE",
        "SELECT count(*) FROM demo.customers t JOIN (VALUES (1)) v(x) ON t::text LIKE '%x%'",
        "SELECT count(*) FROM demo.customers t LEFT JOIN (VALUES (1)) v(x) ON t::text LIKE '%@%'",
        "SELECT count(*) FROM demo.customers t WHERE COALESCE(t::text, '') LIKE '%x%'",
        "SELECT count(*) FROM demo.customers t WHERE NULLIF(t::text, '') LIKE '%x%'",
        "SELECT count(*) FROM demo.customers t WHERE (ARRAY[t::text])[1] LIKE '%x%'",
        "SELECT count(*) FROM demo.customers t WHERE ROW(t)::text LIKE '%x%'",
        "SELECT count(*) FROM demo.customers t WHERE CASE WHEN t::text LIKE '%x%' THEN true ELSE false END",
        "SELECT count(*) FROM demo.customers t WHERE XMLSERIALIZE(CONTENT xmlelement(name r, t) AS text) LIKE '%x%'",
        "SELECT count(*) FROM demo.customers t WHERE JSON_OBJECT('r': t)::text LIKE '%x%'",
        "SELECT count(*) FROM demo.customers t WHERE JSON_ARRAY(t)::text LIKE '%x%'",
        "SELECT json_agg(t) FROM demo.customers t",
        "SELECT to_json(t) FROM demo.customers t",
        "SELECT row_to_json(t) FROM demo.customers t",
        "SELECT t FROM demo.customers t",
        "SELECT t::text FROM demo.customers t",
        "SELECT * FROM demo.customers t ORDER BY t::text",
        "SELECT count(*) FROM (SELECT * FROM demo.customers) t WHERE t::text LIKE '%x%'",
        "SELECT id FROM demo.customers t ORDER BY t::text",
        r#"SELECT count(*) FROM demo.customers t WHERE t::text LIKE '%' || u&"email" || '%'"#,
        "SELECT count(*) FROM demo.customers t WHERE overlay(t::text placing 'x' from 1) LIKE '%x%'",
        "SELECT count(*) FROM demo.customers t WHERE substring(t::text from 1 for 20) LIKE '%@%'",
        "SELECT count(*) FROM demo.customers t HAVING bool_or(t::text LIKE '%x%')",
        "SELECT count(*) FROM demo.customers t WHERE EXISTS (SELECT 1 FROM demo.customers t2 WHERE t2::text LIKE '%x%')",
        "SELECT id FROM demo.customers t LIMIT (SELECT count(*) FROM demo.customers t2 WHERE t2::text LIKE '%@%')",
        "SELECT count(*) FROM demo.customers t WHERE t IS NOT DISTINCT FROM t",
        "SELECT string_agg(city, ',' ORDER BY t::text) FROM demo.customers t",
        "SELECT id, count(*) OVER (ORDER BY t::text) FROM demo.customers t",
        "SELECT id, count(*) OVER (PARTITION BY t::text) FROM demo.customers t",
        "SELECT count(*) FROM demo.customers t WHERE t::jsonb IS NOT NULL",
        "SELECT count(*) FROM demo.customers a JOIN demo.customers b ON a::text = b::text",
    ];
    for sql in whole_row {
        check(sql, must_refuse_whole_row(sql));
    }

    // --- NATURAL JOIN / column-alias rename --------------------------------
    let join_rename: &[&str] = &[
        "SELECT count(*) FROM demo.customers AS t(c1,c2,c3,c4,c5,c6,c7,c8,c9,c10,c11) WHERE c2 = 'x'",
        "SELECT count(*) FROM demo.customers a NATURAL JOIN demo.customers b",
        r#"SELECT count(*) FROM demo.customers NATURAL JOIN (VALUES ('x')) v(u&"email")"#,
        "SELECT count(*) FROM customers AS t(c1,c2,c3,c4,c5) WHERE c2 = 'x'",
    ];
    for sql in join_rename {
        check(sql, must_refuse_join_rename(sql));
    }

    open
}

#[test]
fn hostile_campaign_finds_no_open_oracles() {
    let open = run_pass();
    if !open.is_empty() {
        let mut msg = format!("{} open oracle(s):\n", open.len());
        for (sql, why) in &open {
            msg.push_str(&format!("  OPEN [{why}]\n    {sql}\n"));
        }
        panic!("{msg}");
    }
}

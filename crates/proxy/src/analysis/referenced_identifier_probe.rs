#![allow(clippy::unwrap_used, clippy::panic)]
use super::*;

/// The statement that leaked. `d` must be in the set even though it only
/// appears inside a scalar subquery two levels down.
#[test]
fn columns_inside_scalar_subqueries_are_seen() {
    let sql = "SELECT min((SELECT d FROM fz.t8 LIMIT 1 OFFSET 3)) OVER (PARTITION BY subq.c0) \
               FROM (SELECT id AS c0 FROM fz.v_join) subq";
    let cols = referenced_identifiers(sql).expect("scans");
    assert!(cols.contains(&"d".to_string()), "got {cols:?}");
    assert!(cols.contains(&"id".to_string()), "got {cols:?}");
}

/// A summary over a singleton group is the value it summarised, so the
/// grouping has to be read — or admitted to be unreadable.
#[test]
fn group_by_columns_reads_the_clause_or_admits_it_cannot() {
    let cols = |sql: &str| StatementInspection::new(sql).group_by_columns();
    assert_eq!(cols("SELECT sum(x) FROM t"), Some(vec![]));
    assert_eq!(
        cols("SELECT id, sum(x) FROM t GROUP BY id"),
        Some(vec!["id".to_string()])
    );
    assert_eq!(
        cols("SELECT sum(x) FROM t GROUP BY t.id, city"),
        Some(vec!["id".to_string(), "city".to_string()])
    );
    // The wrapper the analysis unwraps. `analyze_inspected` classifies the
    // *subquery's* targets for `SELECT * FROM (…)`, so the grouping has to
    // come from there too. Reading the outer clause reported "no grouping"
    // and served every salary in the table:
    //
    //   SELECT * FROM (SELECT id, sum(annual_salary) FROM demo.customers
    //                  GROUP BY id) q
    //
    // Confirmed against a live server before the fix and after it.
    assert_eq!(
        cols("SELECT * FROM (SELECT id, sum(x) FROM t GROUP BY id) q"),
        Some(vec!["id".to_string()])
    );
    assert_eq!(
        cols("SELECT * FROM (SELECT * FROM (SELECT id, sum(x) FROM t GROUP BY id) a) b"),
        Some(vec!["id".to_string()])
    );
    // A wrapper over an ungrouped aggregate is still ungrouped.
    assert_eq!(
        cols("SELECT * FROM (SELECT sum(x) FROM t) q"),
        Some(Vec::new())
    );

    // A grouping that cannot be reduced to names must read as unknown, so
    // the caller refuses rather than assuming it is not a singleton.
    // An ordinal names a target-list entry, and `GROUP BY 1` is idiomatic
    // enough that refusing it costs real queries. Reading it also keeps the
    // guard honest: it is the same attack written differently.
    assert_eq!(
        cols("SELECT id, sum(x) FROM t GROUP BY 1"),
        Some(vec!["id".to_string()])
    );
    assert_eq!(
        cols("SELECT city, id, sum(x) FROM t GROUP BY 2, 1"),
        Some(vec!["id".to_string(), "city".to_string()])
    );

    // Grouping sets union their names, because each set is a subset of the
    // union — a key inside any one of them is inside the union.
    assert_eq!(
        cols("SELECT sum(x) FROM t GROUP BY GROUPING SETS ((a),(b))"),
        Some(vec!["a".to_string(), "b".to_string()])
    );
    assert_eq!(
        cols("SELECT city, sum(x) FROM t GROUP BY ROLLUP(city)"),
        Some(vec!["city".to_string()])
    );
    assert_eq!(
        cols("SELECT sum(x) FROM t GROUP BY CUBE(b, c)"),
        Some(vec!["b".to_string(), "c".to_string()])
    );
    assert_eq!(
        cols("SELECT sum(x) FROM t GROUP BY GROUPING SETS ((a, b), (c))"),
        Some(vec!["a".to_string(), "b".to_string(), "c".to_string()])
    );
    // A grouping construct nested in another is *not* readable: the raw
    // parse tree renders the inner `CUBE` as an ordinary `FuncCall`, and
    // only the outermost construct becomes a `GroupingSet`.
    assert_eq!(
        cols("SELECT sum(x) FROM t GROUP BY ROLLUP(a, CUBE(b, c))"),
        None
    );
    // `GROUP BY ()` collapses the relation to one row and distinguishes by
    // nothing, so it contributes no names.
    assert_eq!(
        cols("SELECT sum(x) FROM t GROUP BY GROUPING SETS ((a),())"),
        Some(vec!["a".to_string()])
    );

    // Still unreadable, and still refused by the caller: an expression, and
    // an ordinal pointing at one.
    assert_eq!(cols("SELECT sum(x) FROM t GROUP BY lower(a)"), None);
    assert_eq!(cols("SELECT lower(a), sum(x) FROM t GROUP BY 1"), None);
    assert_eq!(
        cols("SELECT id, sum(x) FROM t GROUP BY ROLLUP(lower(a))"),
        None
    );
    // An ordinal off the end of the target list is not a name either.
    assert_eq!(cols("SELECT id, sum(x) FROM t GROUP BY 9"), None);

    // A star shifts every position after it by an amount not visible in the
    // target list, so an ordinal stops naming the entry it indexes. Here
    // `GROUP BY 2` is `id` if `z` expands to nothing, while `target_list[1]`
    // is `city` — reading it would report a non-key for a grouping that is
    // one. Refused instead, and independently of the star check in
    // `positions_are_trustworthy` that happens to refuse the whole
    // statement first.
    assert_eq!(
        cols("SELECT z.*, city, id, sum(x) FROM z, t GROUP BY 2"),
        None
    );
    assert_eq!(cols("SELECT *, sum(x) FROM t GROUP BY 1"), None);
    // An output alias denotes whatever its target computes, so both names
    // are collected. Reading only the alias released every salary through
    // `SELECT id AS c, sum(salary) … GROUP BY c`.
    assert_eq!(
        cols("SELECT id AS c, sum(x) FROM t GROUP BY c"),
        Some(vec!["c".to_string(), "id".to_string()])
    );
    // An alias onto an expression is as unreadable as the expression, and
    // falls to the caller's lexical backstop rather than to a name.
    assert_eq!(
        cols("SELECT date_trunc('month', ts) AS m, sum(x) FROM t GROUP BY m"),
        None
    );
    // A qualified name is never an output alias, so no lookup happens.
    assert_eq!(
        cols("SELECT id AS c, sum(x) FROM t GROUP BY t.c"),
        Some(vec!["c".to_string()])
    );
    // Self-referential alias: bounded because the lookup only runs at the
    // top of an item.
    assert_eq!(
        cols("SELECT c AS c, sum(x) FROM t GROUP BY c"),
        Some(vec!["c".to_string(), "c".to_string()])
    );
    // A grouping set nests grouping elements, and Postgres resolves an
    // output alias in each of them — verified against a live server, which
    // served `GROUP BY ROLLUP(c)` as a grouping by `id`. Reading only `c`
    // here was a second copy of the same disclosure.
    assert_eq!(
        cols("SELECT id AS c, sum(x) FROM t GROUP BY ROLLUP(c)"),
        Some(vec!["c".to_string(), "id".to_string()])
    );
    assert_eq!(
        cols("SELECT id AS c, sum(x) FROM t GROUP BY GROUPING SETS ((c))"),
        Some(vec!["c".to_string(), "id".to_string()])
    );
    // An ordinal lands in an expression, where Postgres does *not* resolve
    // an alias, so the target is read for what it computes and no lookup
    // runs. `GROUP BY 1` here is `id` either way.
    assert_eq!(
        cols("SELECT id AS c, sum(x) FROM t GROUP BY 1"),
        Some(vec!["id".to_string()])
    );

    // A star does not make a *named* grouping unreadable — only an ordinal
    // depends on the positions.
    assert_eq!(
        cols("SELECT z.*, sum(x) FROM z, t GROUP BY id"),
        Some(vec!["id".to_string()])
    );
}

/// Coarsening below the mask is not coarsening.
///
/// `date_trunc` was released for any unit "at or above a day", and the
/// fixture's `birth_date` is masked to its year. Measured through the
/// proxy: `date_trunc('day', birth_date)` returned `1975-02-14`, the whole
/// value, and `'week'` returned a seven-day window — both from a column
/// whose plain projection is `1975-01-01`.
///
/// Year and coarser are safe against any date column, because year is the
/// coarsest date mask on offer. Finer units are safe only when the caller
/// says the statement names nothing masked.
#[test]
fn date_trunc_below_the_mask_is_not_a_summary() {
    // `summaries` stays on in both: the summaries gate sits above the
    // `date_trunc` arm and would short-circuit the whole thing, which would
    // make this test pass for the wrong reason.
    const COARSE_ONLY: Relaxations = Relaxations {
        summaries: true,
        fine_date_trunc: false,
    };
    const FINE: Relaxations = Relaxations {
        summaries: true,
        fine_date_trunc: true,
    };
    let unconditional = |sql: &str| analyze(sql, 1, COARSE_ONLY);
    let permitted = |sql: &str| analyze(sql, 1, FINE);

    for unit in ["year", "decade", "century", "millennium"] {
        let sql = format!("SELECT date_trunc('{unit}', birth_date) FROM t");
        assert_eq!(unconditional(&sql), vec![Safety::Releasable], "{sql}");
    }
    for unit in ["day", "week", "month", "quarter"] {
        let sql = format!("SELECT date_trunc('{unit}', birth_date) FROM t");
        assert_eq!(unconditional(&sql), vec![Safety::Unknown], "{sql}");
        assert_eq!(permitted(&sql), vec![Safety::Releasable], "{sql}");
    }
    // Finer than a day was already refused and stays refused either way.
    for unit in ["microseconds", "second", "hour"] {
        let sql = format!("SELECT date_trunc('{unit}', birth_date) FROM t");
        assert_eq!(permitted(&sql), vec![Safety::Unknown], "{sql}");
    }
    // A computed precision is not a literal and cannot be checked.
    assert_eq!(
        permitted("SELECT date_trunc(u, birth_date) FROM t"),
        vec![Safety::Unknown]
    );
}

/// The functions a whole rule rests on, asserted directly.
///
/// `cargo mutants` can replace a function body with a constant and see
/// whether anything notices. These survived that, which means the
/// rules built on them were pinned only end-to-end — by
/// `scripts/test-fuzz.sh`, which `cargo test` does not run. A `cargo test`
/// that passes while a guard always returns the wrong constant is a suite
/// that would not notice a disclosure coming back.
#[test]
fn the_predicates_whole_rules_rest_on() {
    // `is_parseable` is how a caller distinguishes "this says nothing" from
    // "this is nonsense we cannot read". Constant in either direction is
    // wrong: `true` trusts gibberish, `false` refuses everything.
    assert!(is_parseable("SELECT 1"));
    assert!(!is_parseable("SELEKT ¯\\_(ツ)_/¯ FROM"));

    // The lexer is the backstop under lineage, the catalog fast path and
    // the singleton-group guard. Its word test survived three mutations, so
    // pin the edges it actually has to get right.
    let ids = |sql: &str| referenced_identifiers(sql).expect("scans");
    // A quoted name keeps its spelling, minus the quotes, and an escaped
    // quote inside one survives.
    assert!(ids(r#"SELECT "Odd Name" FROM t"#).contains(&"odd name".to_string()));
    assert!(ids(r#"SELECT "a""b" FROM t"#).contains(&"a\"b".to_string()));
    // A leading digit is not a name; a leading underscore is.
    let numeric = ids("SELECT 1234 FROM t");
    assert!(!numeric.contains(&"1234".to_string()));
    assert!(ids("SELECT _x FROM t").contains(&"_x".to_string()));
    // `$` is legal inside a name but not at its start.
    assert!(ids("SELECT a$b FROM t").contains(&"a$b".to_string()));
    // And an operator is not a name, or every statement would name one.
    assert!(!ids("SELECT a + b FROM t").contains(&"+".to_string()));
}

/// Found by `cargo mutants`, not by review: two guards no test detected
/// being broken. The code was right; nothing said so.
///
/// Mechanical mutation is worth more than the hand-picked table in
/// `scripts/test-mutations.py` here, because the table only contains guards
/// someone already thought to protect — the same blind spot as an inference
/// suite that only knows the spellings it was given.
#[test]
fn guards_that_no_test_was_watching() {
    const FINE: Relaxations = Relaxations {
        summaries: true,
        fine_date_trunc: true,
    };
    let safety = |sql: &str, n: usize| analyze(sql, n, FINE);

    // `bare` is `args.is_empty() && agg_filter.is_none() && over.is_none()`,
    // and flipping either `&&` to `||` survived. It matters: a context
    // function is released *because* it takes nothing, and `CREATE
    // FUNCTION` is available to ordinary users, so `public.now(text)`
    // returning its argument is a real shape. With the guard broken,
    // `now(email)` releases the email.
    assert_eq!(safety("SELECT now(email) FROM t", 1), vec![Safety::Unknown]);
    assert_eq!(
        safety("SELECT current_user(email) FROM t", 1),
        vec![Safety::Unknown]
    );
    assert_eq!(
        safety("SELECT version(email) FROM t", 1),
        vec![Safety::Unknown]
    );
    // The releasable form still is.
    assert_eq!(safety("SELECT now()", 1), vec![Safety::Releasable]);
    assert_eq!(safety("SELECT version()", 1), vec![Safety::Releasable]);

    // `COALESCE` releases only when *every* argument does. Flipping the
    // `==` to `!=` survived, and it inverts the rule: two unreadable
    // arguments would have been released together.
    assert_eq!(
        safety("SELECT COALESCE(email, phone) FROM t", 1),
        vec![Safety::Unknown]
    );
    assert_eq!(
        safety("SELECT COALESCE(email, '') FROM t", 1),
        vec![Safety::Unknown]
    );
    assert_eq!(safety("SELECT COALESCE(1, 2)", 1), vec![Safety::Releasable]);

    // `unwrap_star_over_subquery`'s early return was the third survivor and
    // is *not* pinned here, because it turned out to be an equivalent
    // mutant: the two conditions it checks are re-enforced by slice
    // patterns further down the same function, so flipping it changes
    // nothing observable. Asserting a shape that happens to be refused
    // anyway would have looked like coverage and provided none — see the
    // note on the function itself.
    //
    // The shape it exists for still unwraps, which is worth holding.
    assert_eq!(
        safety("SELECT * FROM (SELECT 1 AS a) q", 1),
        vec![Safety::Releasable]
    );
}

/// The case that made this lexical: the tree walk does not enter a
/// `WindowDef`, so `id` was invisible to it.
#[test]
fn columns_in_a_window_clause_are_seen() {
    let sql = "SELECT sum(n) OVER (ORDER BY id ROWS BETWEEN CURRENT ROW AND CURRENT ROW) FROM t";
    let cols = referenced_identifiers(sql).expect("scans");
    assert!(cols.contains(&"id".to_string()), "got {cols:?}");
    assert!(cols.contains(&"n".to_string()), "got {cols:?}");
}

#[test]
fn columns_in_case_arms_casts_and_where_are_seen() {
    let sql = "SELECT CASE WHEN n > 0 THEN cast(email AS text) ELSE note END \
               FROM t WHERE last_ip IS NOT NULL ORDER BY birth_date";
    let cols = referenced_identifiers(sql).expect("scans");
    for want in ["n", "email", "note", "last_ip", "birth_date"] {
        assert!(cols.contains(&want.to_string()), "missing {want}: {cols:?}");
    }
}

#[test]
fn hostile_projection_gate_closes_the_inference_routes() {
    let masked: HashSet<String> = ["email", "annual_salary"]
        .into_iter()
        .map(str::to_string)
        .collect();
    // Allowed: bare projection, filter on a released key.
    assert!(!masked_exceeds_outer_projection(
        "SELECT email, id FROM demo.customers WHERE id = 1",
        &masked
    ));
    // Predicate oracle.
    assert!(masked_exceeds_outer_projection(
        "SELECT id FROM demo.customers WHERE email LIKE 'u%'",
        &masked
    ));
    // ORDER BY ranking.
    assert!(!masked_exceeds_outer_projection(
        "SELECT id FROM demo.customers ORDER BY email",
        &masked
    ));
    // Single-row aggregate.
    assert!(masked_exceeds_outer_projection(
        "SELECT sum(annual_salary) FROM demo.customers WHERE id = 1",
        &masked
    ));
    // Error-channel CASE over a subquery that projects email.
    assert!(masked_exceeds_outer_projection(
        "SELECT 1/(CASE WHEN (SELECT email FROM demo.customers WHERE id=1) LIKE 'u%' \
         THEN 0 ELSE 1 END)",
        &masked
    ));
    // TypeName.typmods: CAST numeric(p,s) hid a subquery membership oracle.
    assert!(masked_exceeds_outer_projection(
        r#"SELECT CAST(1 AS numeric((SELECT count(*) FROM demo.customers WHERE u&"email" = 'x'), 0))"#,
        &masked
    ));
    // JSON RETURNING uses JsonOutput.type_name, not TypeCast.
    assert!(masked_exceeds_outer_projection(
        r#"SELECT JSON_VALUE('1', '$' RETURNING numeric((SELECT count(*) FROM demo.customers WHERE u&"email" = 'x'), 0))"#,
        &masked
    ));
    assert!(masked_exceeds_outer_projection(
        r#"SELECT JSON_QUERY('1', '$' RETURNING numeric((SELECT count(*) FROM demo.customers WHERE u&"email" = 'x'), 0))"#,
        &masked
    ));
    // Cleartext ORDER BY is accepted — values stay masked on the wire.
    assert!(!masked_exceeds_outer_projection(
        "SELECT email FROM demo.customers ORDER BY 1",
        &masked
    ));
    assert!(!masked_exceeds_outer_projection(
        "SELECT email AS e FROM demo.customers ORDER BY e",
        &masked
    ));
    // EXPLAIN of an allowed SELECT is the same residual (analyst debugging).
    assert!(!masked_exceeds_outer_projection(
        "EXPLAIN SELECT email, id FROM demo.customers WHERE id = 1",
        &masked
    ));
    assert!(!masked_exceeds_outer_projection(
        "EXPLAIN SELECT id FROM demo.customers ORDER BY email",
        &masked
    ));
    assert!(masked_exceeds_outer_projection(
        "EXPLAIN SELECT count(*) FROM demo.customers WHERE email = 'x'",
        &masked
    ));
    // ORDER BY with a predicate is a membership oracle — not credited.
    assert!(masked_exceeds_outer_projection(
        "SELECT id FROM demo.customers ORDER BY email = 'user1@example.com' DESC",
        &masked
    ));
    // Unicode-escaped identifiers decode on ColumnRef; lexical scan misses them.
    assert!(masked_exceeds_outer_projection(
        r#"SELECT id FROM demo.customers WHERE u&"email" = 'user1@example.com'"#,
        &masked
    ));
    assert!(masked_exceeds_outer_projection(
        r#"SELECT count(*) FROM demo.customers WHERE u&"e\006dail" LIKE 'u%'"#,
        &masked
    ));
    // Equality on the masked column itself.
    assert!(masked_exceeds_outer_projection(
        "SELECT email FROM demo.customers WHERE email = 'user1@example.com'",
        &masked
    ));
}

#[test]
fn hostile_closes_whole_row_cleartext_oracles() {
    use std::collections::HashMap;
    let mut relations = HashMap::new();
    relations.insert(
        "demo.customers".into(),
        vec!["id".into(), "email".into(), "name".into(), "city".into()],
    );
    assert!(hostile_uses_whole_row(
        "SELECT count(*) FROM demo.customers t WHERE t::text LIKE '%u%'",
        &relations
    ));
    assert!(hostile_uses_whole_row(
        "SELECT count(*) FROM demo.customers t WHERE format('%s', t) LIKE '%u%'",
        &relations
    ));
    assert!(hostile_uses_whole_row(
        "SELECT count(*) FROM demo.customers WHERE customers::text LIKE '%u%'",
        &relations
    ));
    assert!(hostile_uses_whole_row(
        "SELECT id FROM demo.customers t ORDER BY t::text",
        &relations
    ));
    assert!(hostile_uses_whole_row(
        "SELECT count(*) FROM demo.customers a JOIN demo.customers b ON a::text = b::text",
        &relations
    ));
    assert!(hostile_uses_whole_row(
        "SELECT count(*) FILTER (WHERE t::text LIKE '%u%') FROM demo.customers t",
        &relations
    ));
    assert!(hostile_uses_whole_row(
        "SELECT count(*) FROM demo.customers t WHERE t::text COLLATE \"C\" LIKE '%u%'",
        &relations
    ));
    assert!(hostile_uses_whole_row(
        "SELECT count(*) FROM (SELECT * FROM demo.customers) t WHERE t::text LIKE '%u%'",
        &relations
    ));
    assert!(!hostile_uses_whole_row(
        "SELECT email, id FROM demo.customers WHERE id = 1",
        &relations
    ));
    assert!(!hostile_uses_whole_row(
        "SELECT id FROM demo.customers t WHERE t.id = 1",
        &relations
    ));
    assert!(!hostile_uses_whole_row(
        "SELECT email FROM demo.customers email WHERE id = 1",
        &relations
    ));
}

#[test]
fn hostile_closes_join_rename_and_window_oracles() {
    use std::collections::HashMap;
    let masked: HashSet<String> = ["email", "name"].into_iter().map(str::to_string).collect();
    let mut relations = HashMap::new();
    relations.insert(
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
    assert!(hostile_join_or_rename_masked(
        "SELECT count(*) FROM demo.customers AS t(c1,c2,c3,c4,c5,c6,c7,c8,c9,c10,c11) \
         WHERE c2 = 'user1@example.com'",
        &relations,
        &masked
    ));
    assert!(hostile_join_or_rename_masked(
        "SELECT count(*) FROM demo.customers a NATURAL JOIN demo.customers b",
        &relations,
        &masked
    ));
    assert!(hostile_join_or_rename_masked(
        r#"SELECT count(*) FROM demo.customers NATURAL JOIN (VALUES ('x')) v(u&"email")"#,
        &relations,
        &masked
    ));
    assert!(masked_exceeds_outer_projection(
        r#"SELECT count(*) FROM demo.customers a
           JOIN (VALUES ('x')) v(u&"email") USING (u&"email")"#,
        &masked
    ));
    assert!(masked_exceeds_outer_projection(
        r#"SELECT id, count(*) OVER (PARTITION BY u&"email" = 'x')
           FROM demo.customers"#,
        &masked
    ));
    assert!(masked_exceeds_outer_projection(
        r#"WITH q(u&"email") AS (SELECT 'x')
           SELECT count(*) FROM demo.customers NATURAL JOIN q"#,
        &masked
    ));
    assert!(masked_exceeds_outer_projection(
        r#"SELECT count(*) FROM demo.customers
           GROUP BY GROUPING SETS ((u&"email"))"#,
        &masked
    ));
    assert!(masked_exceeds_outer_projection(
        r#"SELECT count(*) FROM demo.customers GROUP BY ROLLUP (u&"email")"#,
        &masked
    ));
    assert!(masked_exceeds_outer_projection(
        r#"SELECT count(*) FROM demo.customers
           WHERE 'x' = ANY(ARRAY[u&"email"])"#,
        &masked
    ));
    assert!(masked_exceeds_outer_projection(
        r#"SELECT count(*) FROM demo.customers
           WHERE CASE u&"email" WHEN 'x' THEN true ELSE false END"#,
        &masked
    ));
    assert!(masked_exceeds_outer_projection(
        r#"SELECT id FROM demo.customers
           LIMIT (SELECT count(*) FROM demo.customers WHERE u&"email" = 'x')"#,
        &masked
    ));
    assert!(masked_exceeds_outer_projection(
        r#"SELECT count(*) FROM demo.customers t WHERE (t).u&"email" = 'x'"#,
        &masked
    ));
    assert!(masked_exceeds_outer_projection(
        r#"SELECT count(*) FROM demo.customers WHERE (ARRAY[u&"email"])[1] = 'x'"#,
        &masked
    ));
    assert!(masked_exceeds_outer_projection(
        r#"SELECT count(*) FROM demo.customers WHERE xmlforest(u&"email") IS NOT NULL"#,
        &masked
    ));
    // JOIN … ON, BooleanTest, JSON constructors, xmlserialize — previously live OPEN.
    assert!(masked_exceeds_outer_projection(
        r#"SELECT count(*) FROM demo.customers a
           JOIN (VALUES (1)) v(x) ON a.u&"email" = 'user1@example.com'"#,
        &masked
    ));
    assert!(masked_exceeds_outer_projection(
        r#"SELECT count(*) FROM demo.customers
           WHERE (u&"email" = 'user1@example.com') IS TRUE"#,
        &masked
    ));
    assert!(masked_exceeds_outer_projection(
        r#"SELECT count(*) FROM demo.customers
           WHERE JSON_OBJECT('e': u&"email")->>'e' = 'user1@example.com'"#,
        &masked
    ));
    assert!(masked_exceeds_outer_projection(
        r#"SELECT count(*) FROM demo.customers
           WHERE JSON_ARRAY(u&"email")->>0 = 'user1@example.com'"#,
        &masked
    ));
    assert!(masked_exceeds_outer_projection(
        r#"SELECT count(*) FROM demo.customers
           WHERE xmlserialize(CONTENT xmlforest(u&"email" AS e) AS text)
                 LIKE '%user1@example.com%'"#,
        &masked
    ));
    // Aggregate ORDER BY / WITHIN GROUP, window frame offsets, JSON_VALUE,
    // JSON_TABLE, PREPARE/DECLARE — previously live OPEN.
    assert!(masked_exceeds_outer_projection(
        r#"SELECT string_agg(city, ',' ORDER BY u&"email" = 'x') FROM demo.customers"#,
        &masked
    ));
    assert!(masked_exceeds_outer_projection(
        r#"SELECT mode() WITHIN GROUP (ORDER BY u&"email") FROM demo.customers"#,
        &masked
    ));
    assert!(masked_exceeds_outer_projection(
        r#"SELECT id, count(*) OVER (PARTITION BY id ORDER BY id ROWS BETWEEN
           (SELECT count(*) FROM demo.customers t2 WHERE t2.u&"email" = 'x')
           PRECEDING AND CURRENT ROW) FROM demo.customers"#,
        &masked
    ));
    assert!(masked_exceeds_outer_projection(
        r#"SELECT count(*) FROM demo.customers
           WHERE JSON_VALUE(JSON_OBJECT('e': u&"email"), '$.e') = 'x'"#,
        &masked
    ));
    assert!(masked_exceeds_outer_projection(
        r#"SELECT jt.* FROM demo.customers,
           JSON_TABLE(json_build_object('e', u&"email"), '$'
             COLUMNS (e text PATH '$.e')) jt"#,
        &masked
    ));
    assert!(masked_exceeds_outer_projection(
        r#"PREPARE q AS SELECT count(*) FROM demo.customers WHERE u&"email" = 'x'"#,
        &masked
    ));
    assert!(masked_exceeds_outer_projection(
        r#"DECLARE c CURSOR FOR SELECT count(*) FROM demo.customers WHERE u&"email" = 'x'"#,
        &masked
    ));
    assert!(masked_exceeds_outer_projection(
        r#"WITH RECURSIVE r AS (SELECT * FROM demo.customers)
           SEARCH DEPTH FIRST BY u&"email" SET ord SELECT count(*) FROM r"#,
        &masked
    ));
    assert!(masked_exceeds_outer_projection(
        r#"WITH RECURSIVE r AS (SELECT * FROM demo.customers)
           CYCLE u&"email" SET is_cycle USING path SELECT count(*) FROM r"#,
        &masked
    ));
    assert!(hostile_uses_whole_row(
        "SELECT json_arrayagg(t) FROM demo.customers t",
        &relations
    ));
    assert!(hostile_uses_whole_row(
        "SELECT json_objectagg('k': t) FROM demo.customers t",
        &relations
    ));
    assert!(hostile_uses_whole_row(
        "SELECT count(*) FROM demo.customers t WHERE JSON_SERIALIZE(t) LIKE '%x%'",
        &relations
    ));
    assert!(hostile_uses_whole_row(
        "SELECT count(*) FROM demo.customers t WHERE t IS JSON",
        &relations
    ));
    assert!(masked_exceeds_outer_projection(
        r#"SELECT count(*) FROM demo.customers,
           XMLTABLE('/e' PASSING '<e>x</e>'
             COLUMNS x text PATH '.' DEFAULT u&"email")"#,
        &masked
    ));
    assert!(masked_exceeds_outer_projection(
        r#"SELECT json_arrayagg(city) OVER (PARTITION BY u&"email") FROM demo.customers"#,
        &masked
    ));
    assert!(hostile_join_or_rename_masked(
        "SELECT count(*) FROM (SELECT * FROM demo.customers) AS t(c1,c2,c3,c4,c5,c6,c7,c8,c9,c10,c11) WHERE c2 = 'x'",
        &relations,
        &masked
    ));
    assert!(hostile_join_or_rename_masked(
        "WITH q(c1,c2,c3,c4,c5,c6,c7,c8,c9,c10,c11) AS (SELECT * FROM demo.customers) \
         SELECT count(*) FROM q WHERE c2 = 'x'",
        &relations,
        &masked
    ));
    assert!(hostile_join_or_rename_masked(
        r#"PREPARE q AS SELECT count(*) FROM demo.customers a NATURAL JOIN demo.customers b"#,
        &relations,
        &masked
    ));
    assert!(hostile_join_or_rename_masked(
        r#"PREPARE q AS SELECT count(*) FROM demo.customers AS t(c1,c2,c3,c4,c5,c6,c7,c8,c9,c10,c11) WHERE c2 = 'x'"#,
        &relations,
        &masked
    ));
    assert!(hostile_uses_whole_row(
        "SELECT count(*) FROM demo.customers t WHERE (ARRAY[t::text])[1] LIKE '%x%'",
        &relations
    ));
    assert!(hostile_uses_whole_row(
        "SELECT count(*) FROM demo.customers t WHERE JSON_OBJECT('r': t)::text LIKE '%x%'",
        &relations
    ));
    assert!(hostile_uses_whole_row(
        "SELECT id FROM demo.customers t LIMIT (SELECT count(*) FROM demo.customers t2 WHERE t2::text LIKE '%@%')",
        &relations
    ));
    assert!(hostile_uses_whole_row(
        "SELECT string_agg(city, ',' ORDER BY t::text) FROM demo.customers t",
        &relations
    ));
    assert!(!masked_exceeds_outer_projection(
        r#"SELECT id FROM demo.customers ORDER BY u&"email" USING <"#,
        &masked
    ));
    assert!(!hostile_join_or_rename_masked(
        "SELECT email, id FROM demo.customers WHERE id = 1",
        &relations,
        &masked
    ));
}

#[test]
fn procedural_statements_are_recognised() {
    assert!(is_procedural_statement(
        "DO $$ BEGIN RAISE NOTICE 'x'; END $$"
    ));
    assert!(is_procedural_statement("CALL demo.do_thing()"));
    assert!(is_procedural_statement(
        "CREATE FUNCTION f() RETURNS void AS $$ BEGIN END $$ LANGUAGE plpgsql"
    ));
    assert!(is_procedural_statement(
        "CREATE PROCEDURE p() LANGUAGE plpgsql AS $$ BEGIN END $$"
    ));
    assert!(is_procedural_statement(
        "SELECT 1; DO $$ BEGIN NULL; END $$"
    ));
    assert!(!is_procedural_statement(
        "SELECT email, id FROM demo.customers WHERE id = 1"
    ));
    assert!(!is_procedural_statement("SELECT now()"));
}

#[test]
fn write_statements_are_recognised() {
    for sql in [
        "INSERT INTO t VALUES (1)",
        "UPDATE t SET x = 1",
        "DELETE FROM t WHERE id = 1",
        "MERGE INTO t USING s ON t.id = s.id WHEN MATCHED THEN DELETE",
        "TRUNCATE t",
        "CREATE TABLE t (id int)",
        "DROP TABLE t",
        "ALTER TABLE t ADD COLUMN x int",
        "CREATE INDEX ON t (id)",
        "GRANT SELECT ON t TO u",
        "SELECT * INTO t FROM s",
        "CREATE TABLE t AS SELECT 1",
        "WITH d AS (DELETE FROM t RETURNING *) SELECT * FROM d",
        "COPY t FROM STDIN",
        "COPY t TO STDOUT",
        "DO $$ BEGIN NULL; END $$",
        "CALL foo()",
        "NOTIFY x",
        "VACUUM t",
        "SELECT email FROM t FOR UPDATE",
        "SELECT email FROM t FOR SHARE",
        "CREATE VIEW v AS SELECT email FROM t",
        "CREATE OR REPLACE VIEW v AS SELECT 1",
        "LOAD 'auto_explain'",
        "CHECKPOINT",
        "LOCK TABLE t",
        "COMMENT ON TABLE t IS 'x'",
        "CREATE STATISTICS s ON a FROM t",
        "IMPORT FOREIGN SCHEMA s FROM SERVER x INTO public",
        "EXPLAIN INSERT INTO t VALUES (1)",
        "EXPLAIN (ANALYZE true) INSERT INTO t VALUES (1)",
    ] {
        assert!(is_write_statement(sql), "expected write: {sql}");
    }
    for sql in [
        "SELECT email, id FROM demo.customers WHERE id = 1",
        "SELECT 1",
        "BEGIN",
        "COMMIT",
        "ROLLBACK",
        "EXPLAIN SELECT 1",
        "SHOW search_path",
        "SET search_path TO public",
        "PREPARE q AS SELECT 1",
        "EXECUTE q",
        "DEALLOCATE q",
        "DECLARE c CURSOR FOR SELECT 1",
        "FETCH ALL FROM c",
        "MOVE FORWARD 1 FROM c",
        "CLOSE c",
        "SELECT 1 FETCH FIRST 1 ROW ONLY",
        "DISCARD ALL",
        "RESET ALL",
    ] {
        assert!(!is_write_statement(sql), "expected read: {sql}");
    }
}

#[test]
fn sql_prepare_and_cursor_statements_are_recognised() {
    for sql in [
        "PREPARE q AS SELECT 1",
        "PREPARE q AS SELECT count(*) FROM demo.customers WHERE email = 'x'",
        "EXECUTE q",
        "EXECUTE q(1)",
        "DEALLOCATE q",
        "DEALLOCATE ALL",
        "DECLARE c CURSOR FOR SELECT 1",
        "DECLARE c CURSOR WITH HOLD FOR SELECT email FROM demo.customers",
        "FETCH ALL FROM c",
        "FETCH FORWARD 10 FROM c",
        "MOVE FORWARD 1 FROM c",
        "CLOSE c",
        "CLOSE ALL",
    ] {
        assert!(
            is_sql_prepare_or_cursor(sql),
            "expected SQL PREPARE/cursor: {sql}"
        );
    }
    for sql in [
        "SELECT 1",
        "SELECT email, id FROM demo.customers WHERE id = 1",
        "SELECT * FROM demo.customers FETCH FIRST 10 ROWS ONLY",
        "SELECT * FROM demo.customers FETCH FIRST 10 ROWS WITH TIES",
        "SELECT 1 FETCH FIRST 1 ROW ONLY",
        "BEGIN",
        "EXPLAIN SELECT 1",
        "SHOW search_path",
        "DISCARD ALL",
        "not valid sql at all",
    ] {
        assert!(
            !is_sql_prepare_or_cursor(sql),
            "must not refuse ordinary SELECT/session SQL: {sql}"
        );
    }
}

#[test]
fn untrusted_functions_are_caught_before_execution() {
    assert!(calls_untrusted_function("SELECT demo.sleep_if(1, 'u')"));
    assert!(calls_untrusted_function(
        "SELECT * FROM demo.sleep_if(1, 'u') AS t"
    ));
    assert!(calls_untrusted_function(
        "SELECT id FROM t WHERE demo.email_ok(id, 'u')"
    ));
    assert!(calls_untrusted_function("SELECT pg_sleep(0.1)"));
    assert!(calls_untrusted_function(
        "PREPARE q AS SELECT pg_sleep(0.1)"
    ));
    assert!(calls_untrusted_function(
        "DECLARE c CURSOR FOR SELECT pg_sleep(0.1)"
    ));
    assert!(calls_untrusted_function("SELECT evil.sum(1)"));
    // Trusted builtins / pg_catalog.
    assert!(!calls_untrusted_function("SELECT now()"));
    assert!(!calls_untrusted_function("SELECT pg_catalog.now()"));
    assert!(!calls_untrusted_function(
        "SELECT count(*) FROM demo.customers"
    ));
    assert!(!calls_untrusted_function(
        "SELECT lower(city) FROM demo.customers"
    ));
    assert!(!calls_untrusted_function(
        "SELECT email, id FROM demo.customers WHERE id = 1"
    ));
}

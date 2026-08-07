/**
 * The Phase 0 query-shape matrix.
 *
 * Each shape asks one question: when Postgres describes this result set, does
 * it still tell us which stored column each output field came from?
 *
 * `expect` is our prior, not an assertion — the point of the spike is to find
 * out where the prior is wrong. Recorded so the results table shows surprises
 * rather than just data.
 *
 *   'provenance' — we expect table_oid/attnum populated for the marked fields
 *   'opaque'     — we expect 0/0 (a computed expression; masking must refuse)
 *   'unknown'    — genuinely don't know, this is why the spike exists
 */

export const shapes = [
  // --- Baselines ----------------------------------------------------------
  {
    id: 'baseline',
    group: 'baseline',
    label: 'Plain column reference',
    sql: 'SELECT email FROM t',
    expect: 'provenance',
  },
  {
    id: 'star',
    group: 'baseline',
    label: 'SELECT *',
    sql: 'SELECT * FROM t',
    expect: 'provenance',
    note: 'If this works, * is free for us and costs a parser-based design real effort.',
  },
  {
    id: 'aliased',
    group: 'baseline',
    label: 'Column aliased to a different output name',
    sql: 'SELECT email AS contact_email FROM t',
    expect: 'provenance',
    note: 'Confirms we must key the catalog on (oid, attnum), never on output name.',
  },
  {
    id: 'qualified',
    group: 'baseline',
    label: 'Table alias',
    sql: 'SELECT a.email FROM t a',
    expect: 'provenance',
  },
  {
    id: 'join',
    group: 'baseline',
    label: 'Join, columns from both sides',
    sql: 'SELECT t.email, u.note FROM t JOIN u ON u.t_id = t.id',
    expect: 'provenance',
  },
  {
    id: 'distinct',
    group: 'baseline',
    label: 'SELECT DISTINCT',
    sql: 'SELECT DISTINCT email FROM t',
    expect: 'unknown',
  },
  {
    id: 'empty_result',
    group: 'baseline',
    label: 'Zero rows returned',
    sql: 'SELECT email FROM t WHERE false',
    expect: 'provenance',
    note: 'RowDescription must arrive even with no DataRows.',
  },

  // --- Subqueries and CTEs -------------------------------------------------
  {
    id: 'subquery_flat',
    group: 'subquery',
    label: 'Flattenable subquery',
    sql: 'SELECT email FROM (SELECT email FROM t) q',
    expect: 'unknown',
  },
  {
    id: 'subquery_nonflat',
    group: 'subquery',
    label: 'Non-flattenable subquery (OFFSET 0 defeats pullup)',
    sql: 'SELECT email FROM (SELECT email FROM t OFFSET 0) q',
    expect: 'unknown',
    note: 'The important one. If flattening is what preserves provenance, this breaks.',
  },
  {
    id: 'cte',
    group: 'subquery',
    label: 'CTE',
    sql: 'WITH c AS (SELECT email FROM t) SELECT email FROM c',
    expect: 'unknown',
  },
  {
    id: 'cte_materialized',
    group: 'subquery',
    label: 'CTE, forced MATERIALIZED',
    sql: 'WITH c AS MATERIALIZED (SELECT email FROM t) SELECT email FROM c',
    expect: 'unknown',
  },
  {
    id: 'cte_recursive',
    group: 'subquery',
    label: 'Recursive CTE',
    sql: `WITH RECURSIVE c(id, email) AS (
            SELECT id, email FROM t WHERE id = 1
            UNION ALL
            SELECT t.id, t.email FROM t JOIN c ON t.id = c.id + 1
          )
          SELECT id, email FROM c`,
    expect: 'unknown',
  },

  // --- Set operations ------------------------------------------------------
  {
    id: 'union_all',
    group: 'setop',
    label: 'UNION ALL',
    sql: 'SELECT email FROM t UNION ALL SELECT email FROM t',
    expect: 'unknown',
  },
  {
    id: 'union',
    group: 'setop',
    label: 'UNION (dedup)',
    sql: 'SELECT email FROM t UNION SELECT email FROM t',
    expect: 'unknown',
  },
  {
    id: 'intersect',
    group: 'setop',
    label: 'INTERSECT',
    sql: 'SELECT email FROM t INTERSECT SELECT email FROM t',
    expect: 'unknown',
  },
  {
    id: 'except',
    group: 'setop',
    label: 'EXCEPT',
    sql: 'SELECT email FROM t EXCEPT SELECT email FROM t WHERE id > 2',
    expect: 'unknown',
  },

  // --- Views ---------------------------------------------------------------
  {
    id: 'view',
    group: 'view',
    label: 'Simple view',
    sql: 'SELECT email FROM v_t',
    expect: 'unknown',
    note: 'CRITICAL: view OID or base table OID? Determines whether the catalog needs view entries.',
  },
  {
    id: 'view_star',
    group: 'view',
    label: 'SELECT * from a view',
    sql: 'SELECT * FROM v_t',
    expect: 'unknown',
  },
  {
    id: 'view_nested',
    group: 'view',
    label: 'View over a view',
    sql: 'SELECT email FROM v_nested',
    expect: 'unknown',
  },
  {
    id: 'matview',
    group: 'view',
    label: 'Materialized view',
    sql: 'SELECT email FROM mv_t',
    expect: 'unknown',
  },

  // --- Partitioning --------------------------------------------------------
  {
    id: 'partition_parent',
    group: 'partition',
    label: 'Query the partitioned parent',
    sql: 'SELECT email FROM p',
    expect: 'unknown',
    note: 'Parent OID or child OID? If child, catalog resolution must walk the hierarchy.',
  },
  {
    id: 'partition_child',
    group: 'partition',
    label: 'Query a partition directly',
    sql: 'SELECT email FROM p_west',
    expect: 'provenance',
  },

  // --- Expressions (expected opaque) --------------------------------------
  {
    id: 'cast',
    group: 'expression',
    label: 'Cast: email::text',
    sql: 'SELECT email::text FROM t',
    expect: 'unknown',
    note: 'A no-op cast may or may not survive as a bare Var.',
  },
  {
    id: 'lower',
    group: 'expression',
    label: 'Function call: lower(email)',
    sql: 'SELECT lower(email) FROM t',
    expect: 'opaque',
  },
  {
    id: 'concat',
    group: 'expression',
    label: "Concatenation: email || ''",
    sql: "SELECT email || '' FROM t",
    expect: 'opaque',
  },
  {
    id: 'coalesce',
    group: 'expression',
    label: "COALESCE(email, '')",
    sql: "SELECT COALESCE(email, '') FROM t",
    expect: 'opaque',
  },
  {
    id: 'case',
    group: 'expression',
    label: 'CASE returning the column unchanged',
    sql: 'SELECT CASE WHEN id > 1 THEN email ELSE NULL END FROM t',
    expect: 'opaque',
    note: 'Semantically leaks email but is opaque to provenance — the fail-closed case.',
  },
  {
    id: 'window',
    group: 'expression',
    label: 'Column alongside a window function',
    sql: 'SELECT email, row_number() OVER (ORDER BY id) FROM t',
    expect: 'unknown',
  },
  {
    id: 'group_by',
    group: 'expression',
    label: 'GROUP BY returning the grouped column',
    sql: 'SELECT city, count(*) FROM t GROUP BY city',
    expect: 'unknown',
  },
  {
    id: 'aggregates',
    group: 'expression',
    label: 'count(*), count(col), string_agg(col)',
    sql: "SELECT count(*), count(email), string_agg(email, ',') FROM t",
    expect: 'opaque',
    note: 'string_agg leaks every value; count does not. Provenance cannot tell them apart — policy must.',
  },

  // --- Functions -----------------------------------------------------------
  {
    id: 'fn_setof_table',
    group: 'function',
    label: 'Function RETURNS SETOF <table>',
    sql: 'SELECT * FROM f_setof_t()',
    expect: 'unknown',
  },
  {
    id: 'fn_table_out',
    group: 'function',
    label: 'Function RETURNS TABLE(...)',
    sql: 'SELECT * FROM f_table_out()',
    expect: 'opaque',
  },
  {
    id: 'fn_srf_target',
    group: 'function',
    label: 'Set-returning function in the target list',
    sql: 'SELECT email, f_srf() FROM t',
    expect: 'unknown',
  },

  // --- Lateral -------------------------------------------------------------
  {
    id: 'lateral',
    group: 'lateral',
    label: 'LATERAL subquery',
    sql: `SELECT t.email, x.note
          FROM t, LATERAL (SELECT note FROM u WHERE u.t_id = t.id LIMIT 1) x`,
    expect: 'unknown',
  },

  // --- Session-scoped relations -------------------------------------------
  {
    id: 'temp_table',
    group: 'session',
    label: 'Temp table',
    setup: [
      'CREATE TEMP TABLE tmp_t (id int, email text)',
      "INSERT INTO tmp_t VALUES (1, 'temp@example.com')",
    ],
    sql: 'SELECT email FROM tmp_t',
    expect: 'provenance',
    note: 'Temp OIDs are per-session — the catalog can never contain them. Fail-closed target.',
  },
  {
    id: 'cursor',
    group: 'session',
    label: 'DECLARE CURSOR + FETCH',
    setup: ['BEGIN', 'DECLARE spike_cur CURSOR FOR SELECT email FROM t'],
    sql: 'FETCH ALL FROM spike_cur',
    teardown: ['CLOSE spike_cur', 'COMMIT'],
    expect: 'unknown',
    note: 'Rows arrive detached from the originating statement. Does FETCH still describe them?',
  },

  // --- Extended protocol ---------------------------------------------------
  {
    id: 'extended_param',
    group: 'protocol',
    label: 'Extended protocol (bound parameter)',
    sql: 'SELECT email FROM t WHERE id = $1',
    values: [1],
    expect: 'provenance',
    note: 'node-postgres uses Parse/Bind/Execute when values are present.',
  },
];

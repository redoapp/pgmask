# Phase 6: lineage — what it would buy, and who should compute it

pgmask refuses a result set when a field has no provenance and no allowlisted
shape explains it. Lineage is the idea of tracing such a field back to the base
columns it derives from, then deciding from those: if none of them is masked,
release it.

Two questions had to be answered before building anything. **How much does it
buy?** and **who computes it?** Both were measured rather than estimated,
because the guesses were wrong in both cases.

## What it buys: about a third

Measured against the 42 TPC-DS queries pgmask actually refuses (the refusal list
comes from `crates/corpus`, not from re-deriving the rules), with a catalog
where the 58 sensitive columns are masked and the other 371 reviewed and
released:

| outcome | count | |
|---|---|---|
| lineage releases it | **14** | 33% — real answers |
| touches a masked column | 9 | 21% — correctly still refused |
| unresolvable | 19 | 45% — still refused, fail closed |

Rejection rate on TPC-DS: **52% → 35%**.

The prior guess was "potentially most of the remaining 42". That was wrong by a
factor of three.

The 9 that still get refused are worth more than the number suggests. Today they
produce `output column has no column provenance`. With lineage they can say
*"derives from `customer.c_first_name`, which is masked"* — the difference
between a support ticket and a rewritten query.

### A note on measuring this

This number was computed three times before it was trusted. The first pass said
16 resolvable, the second said 32; the first was too strict about bare
identifiers, the second silently ignored qualifiers it did not recognise. The
14/9/19 split comes from a pass that treats **any** unrecognised qualifier as
unresolvable, which is the direction that has to be wrong-but-safe.

## Who computes it: Postgres

`EXPLAIN (VERBOSE, COSTS OFF, FORMAT JSON)` already contains the answer. Scan
nodes give `alias -> schema.relation`; the top node's `Output` gives resolved,
qualified column references. It does not execute the query.

```sql
WITH t AS (SELECT email AS e FROM demo.customers) SELECT upper(e) FROM t
--  Output=['upper(customers.email)']
```

Through an alias, through a CTE, back to the base column, with no resolver
written. That is the whole argument: the hard part of lineage is name
resolution, and Postgres has already done it.

### Where it fails, and how it fails

All three are detectable, and all three must fail closed:

| shape | what EXPLAIN gives | rule |
|---|---|---|
| `WITH … AS MATERIALIZED` | `upper(t.e)` — a CTE, not a scan | qualifier matches no scan alias → refuse |
| `WHERE false` | `Result Output=['email']`, **no scan nodes at all** | nothing to resolve → refuse |
| scalar subquery | `Output=['(InitPlan 1).col1']` | lineage lives in a sibling node → refuse |

The middle one is the trap. The planner proved the query returns nothing and
dropped the relation, leaving a bare `email` with nothing behind it. Treating
"no lineage found" as "safe" is the same absence-of-evidence bug that
`reads_only_server_metadata` had to be written around.

The 45% unresolvable is dominated by the first row: TPC-DS is written in a
heavily CTE-based style, and a CTE referenced more than once is materialized, so
the plan shows a `CTE Scan`. That is recoverable in principle — the CTE's own
subplan is in the tree — but **EXPLAIN does not name a CTE's output columns**,
only their expressions. Recovering `wswscs.sun_sales` means combining the plan
with the parse tree to get the CTE's column list and order. That is the
difference between a one-week version and a three-week one.

### Cost

Planning, not execution. Measured on TPC-DS with realistic cardinalities (faked
`reltuples`/`relpages`, which came out *faster* than the empty-table case, so
that caveat was not hiding anything):

```
81 queries:  min 0.24 ms   median 0.48 ms   p95 1.39 ms   max 12.62 ms
```

Against a 50k-row demo database, EXPLAIN is a near-constant **0.16–0.24 ms** —
7% of a 10k-row scan, 4% of a join with a `GROUP BY`, and ~100% of a point
lookup only because the lookup itself is 0.19 ms.

Three things make that a non-issue in practice:

1. **It only runs where we currently refuse.** Everything that passes output
   classification today never touches it and pays nothing.
2. **It can be pipelined.** We already parse the SQL before `Describe`, so we
   know whether lineage will be needed and can send the EXPLAIN in the same
   flush. One round trip, not two — and the round trip, not the planner, is the
   real cost against a remote database.
3. **It caches** on statement text + `search_path` + user + catalog generation.

Watch the tail: `query_64` took 12.6 ms. This wants a statement timeout with
fail-closed on expiry, and the cache hit rate wants instrumenting from day one,
because planning burns CPU on the database you are protecting.

## Why not a lineage library

`sqllineage` v0.2 is a Rust crate that does exactly this, statically, with no
database. It looked excellent:

- **Parsed all 42 TPC-DS queries.** Zero failures. The dialect worry — that
  `sqlparser-rs` would choke where the real Postgres grammar does not — was
  simply wrong.
- **Models unresolved states properly.** `Concrete` / `Ambiguous` / `Wildcard` /
  `Recursive`, so a fail-closed consumer can refuse anything not `Concrete`.
- **Takes a `CatalogProvider`**, and we have a catalog. Wiring our column lists
  in took 30 lines and moved it from 7 fully-resolved queries to **32 of 42** —
  better than EXPLAIN's 23, with no round trip and no CTE materialization
  problem.

Then the test that mattered. Comparing its source columns against the base
columns Postgres's own planner projects, on queries where both resolved:

| | |
|---|---|
| sets agree, or sqllineage saw more | 14 |
| **sqllineage missed columns EXPLAIN found** | **3** |
| not comparable | 15 |

**Three of seventeen — an 18% under-report rate on answers it reported as fully
resolved.** `query_33`, `query_56` and `query_60` each missed
`store_sales.ss_ext_sales_price`: `UNION ALL` across three sales channels, where
it resolved some branches and not others.

Under-reporting is the leak direction. Over-reporting costs a query; missing a
source column means saying "nothing sensitive here" about something sensitive.

There is a second, quieter problem. An empty `sources` list means either
"genuinely none" or "I did not look inside", and the type cannot distinguish
them. Of the ten such cases, `count(*)` and `'DIAMOND' || ',' || 'AIRBORNE'` are
genuinely source-free, while `query_9`'s `bucket1` is a `CASE` over scalar
subqueries whose sources were simply not found. A consumer must fail closed on
empty sources — which costs nothing here, since our existing allowlist already
releases `count(*)` and literals.

**None of this is a criticism of the library.** It is built for data-catalog
lineage, where a missed edge is a cosmetic gap in a graph. We would be using it
as a security control, where a missed edge is a disclosure. It is three weeks
old at v0.2.0 and worth re-testing later.

## The recommendation

**EXPLAIN is the authority.** Postgres resolved the names; it cannot disagree
with itself. The only thing that can be wrong is our extraction from the plan,
which is our code and can be made conservative.

**`sqllineage` is the oracle**, as a dev-dependency, the same role `pgwire`
plays for the wire protocol in `tests/differential.rs`. It needs no database, so
it runs in CI on the corpus; where it reports a source column our extraction
missed, that is a bug in our extraction and the build should say so. Its own
under-reporting does not matter in that direction — we only act on it finding
*more* than we did.

Neither replaces the other, and using the library as the authority would have
shipped a leak on one query in six.

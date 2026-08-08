# Phase 6: lineage — what it bought, and who computes it

> **Shipped.** `lineage = "allow"`, off by default. Measured end to end on
> TPC-DS with a complete catalog (58 masked of 429): **refusals 55% → 26%**,
> which beat the estimate below of ~35%. The estimate was computed against what
> EXPLAIN could resolve; the implementation uses `sqllineage`, which resolves
> more and handles CTEs natively.

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

## Which engine: sqllineage, with two guards

`sqllineage` v0.2 is a Rust crate that computes this statically, with no
database. It was nearly rejected on a measurement error, so both the finding and
the correction are recorded here.

- **Parsed all 42 TPC-DS queries.** Zero failures. The dialect worry — that
  `sqlparser-rs` would choke where the real Postgres grammar does not — was
  simply wrong.
- **Takes a `CatalogProvider`**, and we have a catalog. Wiring our column lists
  in took 30 lines and moved it from 7 fully-resolved queries to 32 of 42.

### The measurement error, because it is the lesson

Comparing its source columns against what Postgres's planner projects, three
queries appeared to *miss* columns — `query_33`, `query_56`, `query_60` each
seemed to drop `store_sales.ss_ext_sales_price` from a `UNION ALL`. That is the
leak direction, and it nearly disqualified the crate.

It was not a miss. Dumping the actual mapping for `query_33`:

```
i_manufact_id  <- [?cte?.i_manufact_id]  (Direct)
total_sales    <- [?cte?.total_sales]    (Aggregation)
```

`?cte?` is the library's placeholder for a CTE it could not resolve — and it is
returned as `ColumnOrigin::Concrete`, so code that trusts the enum variant reads
it as a resolved base column. The classifier doing the comparison believed the
variant. **The type says resolved and it is not.**

There is a second sentinel, `?unknown?`, produced the same way.

### The guards

Both sentinels, and any future one, are caught by not trusting names:

1. **A `Concrete` source whose table is not in the operator's schema is
   unresolved.** Checking existence rather than matching `?cte?` by name means a
   sentinel added in a later version fails closed instead of silently passing.
2. **A mapping with an empty `sources` list is unresolved.** Empty means either
   "genuinely none" or "did not look inside", and the type cannot tell you
   which: `count(*)` and `'DIAMOND' || ',' || 'AIRBORNE'` sit in the same bucket
   as `query_9`'s `bucket1`, a `CASE` over scalar subqueries whose sources were
   missed. Failing closed here costs nothing, because the existing allowlist
   already releases `count(*)` and literals.

With both guards applied:

| | |
|---|---|
| genuinely resolved | **27** of 42 |
| `Concrete` but a placeholder table | 5 → refuse |
| target with no sources | 10 → refuse |
| **under-reports vs Postgres, on the 14 comparable queries** | **0** |

27 beats EXPLAIN's 23, with no round trip, no planning load on the database
being protected, and none of the CTE-materialization problem — a CTE is just a
scope to a static analyser.

### What is still not proven

Zero misses in 14 comparable queries is encouraging, not proof. And the `?cte?`
episode is the standing warning: a type that says `Concrete` was not. The
residual risk that no corpus can measure is a *misparse* — `sqlparser-rs`
accepting a query and reading it differently from Postgres. A parse failure is
safe (refuse); a silent misreading is not.

So EXPLAIN does not go away, it changes role.

## The recommendation

**`sqllineage` is the engine**, behind the two guards above.

**EXPLAIN is the oracle.** `crates/corpus` already submits SQL to a real
Postgres; adding a differential — where Postgres's own plan names a source
column sqllineage did not, fail the build — turns the authority into a test
rather than a runtime dependency. Same role `pgwire` plays for the wire protocol
in `tests/differential.rs`: not the implementation, the second opinion.

That ordering was reversed in the first draft of this document, on the strength
of a comparison that was measuring its own bug.

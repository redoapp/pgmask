# Experiment: pgmask against TPC-DS

The hand-written corpus in [`../neon/`](../neon/) was 31 queries we wrote
ourselves, which is a poor way to estimate how a fail-closed proxy behaves on
real analytical SQL. TPC-DS is the industry-standard decision-support benchmark:
99 queries over a 25-table retail schema, deliberately heavy on aggregates,
window functions, `INTERSECT`/`EXCEPT`, `ROLLUP` and `GROUPING SETS`.

**First run: 90% of it was refused.** That was not a rounding error on the 32%
we measured against our own corpus — it was a different conclusion, and it drove
the change described at the bottom. It now sits at **55%**.

## Running it

```bash
./examples/tpcds/fetch.sh                    # schema + 99 queries (TPC-licensed, not vendored)
psql "$DSN" -f examples/tpcds/corpus/tpcds.sql
cargo run -p pgmask --release -- <rendered catalog>
DSN=postgres://…:6451/tpcds cargo run -p corpus --release -- examples/tpcds/corpus/queries
```

**No data is needed.** `crates/corpus` submits each query with `Parse` +
`Describe` and never executes it. Postgres describes the result set from the
schema alone, which is exactly what pgmask classifies against — so the whole
measurement runs on an empty database with only the DDL loaded. No `dsdgen`, no
load, and nothing is scanned or returned. Phase 0's finding that every shape is
describable without execution is what makes this possible.

The TPC-DS reference DDL loads into Postgres 17 unmodified: 25 tables, no errors.

## Results

| | direct | through pgmask |
|---|---|---|
| described (would be served) | 77 | **8** |
| refused by pgmask | 0 | **69** |
| did not parse — Postgres dialect | 22 | 22 |

**90% of the 77 queries pgmask actually judged were refused.**

The 22 excluded queries fail against Postgres regardless of pgmask — mostly the
TPC-DS `days` interval keyword, plus one multi-statement file. That is a
well-known TPC-DS/Postgres incompatibility, and they are kept out of the
denominator rather than counted as our failures.

## Why it is so much worse than our own corpus

Decision-support SQL is aggregate-shaped almost everywhere. Nearly every TPC-DS
query's target list is `sum(...)`, `avg(...)`, `count(col)` over a column, and an
aggregate over a column has no provenance. Our 31 hand-written queries had a
long tail of plain column reads; TPC-DS has almost none.

The honest reading: **for row-level lookup workloads pgmask is usable today, and
for analytical workloads it is not.** Which of those you have decides whether
Phase 6 is optional.

## The cause bucketing is unreliable on real SQL

pgmask's own counters reported:

```
rejections=69  opaque_function=61  opaque_aggregate=7  opaque_anonymous=1
fields_rescued=14  set_op_like_share=0%
```

That breakdown is **wrong**, and the experiment is what exposed it. The buckets
are inferred from the output column *name* — the heuristic documented in
`metrics.rs` — and real SQL aliases its aggregates:

```sql
sum(ss_ext_sales_price) as revenue
```

The field arrives named `revenue`, not `sum`, so it lands in `opaque_function`.
In truth essentially all 69 refusals are aggregates over columns.

Our own corpus did not expose this because we wrote it without aliases, which is
not how anyone writes SQL. Two consequences:

1. The "expressions 47% / aggregates 33%" split from the Neon run is skewed the
   same way and should be treated as indicative, not measured.
2. The fix is available and cheap: bucket causes with `analysis.rs`, which reads
   the expression shape from the parse tree and does not care what the field was
   aliased to. The heuristic was the right call when there was no parser; there
   is one now.

## What this settles about Phase 6

The aggregate rule is not a nice-to-have. On the standard analytical benchmark
it is the difference between 90% refused and something usable, and it dwarfs
every other rule we considered — set operations scored **0%** here.

The trap remains unchanged: `count`/`sum`/`avg` emit no stored value, while
`min`/`max` return a real one and `string_agg`/`array_agg` return all of them.
The parse tree separates them by function name, but that allowlist has to be
right, because every entry converts refusals into acceptances.


## Follow-up: releasing summaries

The 90% forced the threat model to be stated explicitly rather than assumed. The
bar is **"you cannot read an anonymised value"**, not "no information flows". On
that bar `sum(salary)` is fine — it is a summary, not a salary. A group of one
row makes it that person's salary, and that is accepted, exactly as the
predicate oracles in handoff §11 already are.

That relaxation needs no lineage engine. If the outermost node of a target
expression is a **reducing** aggregate, it cannot return a value it consumed
whatever is inside it — a purely syntactic check on the parse tree.

| | refused | rate |
|---|---|---|
| output-classification only | 69 | 90% |
| + reducing aggregates, ranking windows, coarsening | 46 | 60% |
| + arithmetic/CASE through releasable operands, `SELECT *` unwrapping | **42** | **55%** |

Controlled by `summaries = "allow" \| "refuse"`; `refuse` restores the 90%.

### What is still refused, and why it is the right list

The list of functions that must **never** be released is the load-bearing part,
and it is not "aggregates are safe":

- `min`, `max`, `mode`, `percentile_disc/cont` — return an actual member
- `string_agg`, `array_agg`, `json_agg`, `xmlagg` — return all of them
- `first_value`, `last_value`, `nth_value`, `lag`, `lead` — reach into a row

`max(email)` is an email address. Nine unit tests exist purely to keep that list
honest.

### The next blocker moved

With aggregates handled, the remaining 42 are dominated by **set operations** —
TPC-DS's characteristic `SELECT * FROM (channel_a UNION ALL channel_b)` — plus
scalar subqueries in target lists and multi-`FROM` star queries.

Set operations scored 7% on our hand-written corpus and 0% on the first TPC-DS
run, because everything died on aggregates before reaching them. They are now
the main cost. Fixing the top cause reveals the next one, and a measured
priority is only ever valid for the current top.

## Follow-up: what the hand-written catalog had missed

The catalog used above was written by hand and covered **12** columns. Running
`crates/classify` over the same 429-column schema proposed **58** — and the
delta was not padding. It found four `*_street/city/county/state/zip` blocks
beyond `customer_address`, every `*_manager` employee name, both income-band
columns, and all four `customer_demographics` special-category columns
(`cd_gender`, `cd_marital_status`, `cd_education_status`, `cd_credit_rating`),
none of which the hand-written catalog had.

Reviewing 429 columns by hand is the kind of task that gets done once, badly,
and never revisited. The same run also broke four of the classifier's own rules
— including an unanchored `ip_addr` pattern that matched `cs_sh|ip_addr|_sk` and
proposed an IP mask for an integer surrogate key. All four are pinned by tests
now. Details in [`docs/classification.md`](../../docs/classification.md).

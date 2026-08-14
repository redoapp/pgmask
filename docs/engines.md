# Engines: Postgres and CockroachDB

pgmask is tested against Postgres 13–17 and CockroachDB v25.4. Both speak the
pgwire protocol, and the proxy makes no attempt to detect which one it is
talking to. That is a deliberate choice, and this document is about why it is
safe to make and what it cost to get there.

## The rule the whole design rests on

Postgres's `RowDescription` reports, per output field, the table OID and column
attnum the value came from, and zero for both when the field is computed. The
proxy binds its masking plan to that, never to the statement text: every
row-producing path emits a `RowDescription` first, so cursors, `FETCH`,
multi-statement queries and re-executed prepared statements are all covered
without any special handling.

CockroachDB implements the same field. It is not, however, the same promise.

## What CockroachDB does differently

For a set operation:

```sql
SELECT city FROM customers UNION ALL SELECT email FROM customers
```

there is one output field drawing values from two source columns. Postgres
reports zero provenance — it declines to name a single origin for a field that
has several. CockroachDB reports **the first branch's** table OID and attnum on
the simple-query path, and zero for the same statement on the extended
protocol's `Describe`. The two protocols disagree, and only one of them is safe.

Believing the simple-query answer meant applying `city`'s released
classification to `email`'s values. Real addresses came back in the clear.
Nothing in the proxy was wrong on Postgres; the assumption underneath it was
narrower than it looked.

**Provenance is necessary but not sufficient.** A reported OID identifies *an*
origin for the field, not *the* origin. Where the two differ, the engine gets to
decide what it tells you, and one of the two engines tells you something useful
but incomplete.

## How it is closed

Not by detecting the engine, and not by trusting the extended protocol over the
simple one. The proxy decides from the statement:

```rust
// analysis/catalogs.rs
pub fn provenance_is_trustworthy(sql: &str) -> bool
```

A parsed statement containing a set operation — or a statement that will not
parse at all, since that cannot rule one out — has its provenance distrusted for
every field. Those fields are then handled exactly like genuinely computed ones:
refused by default, or released by lineage if every base column they derive from
is explicitly released.

This is why it does not cost Postgres anything. On Postgres a set-operation
field already had zero provenance and already took that path, so the check only
ever fires where the engine had already told us to be careful. `verify.sh` is
unchanged at 82 assertions, and a `UNION` over released columns is still served
under `lineage = "allow"` on both engines.

### The second half, which was not obvious

Distrusting provenance sends those fields down the opaque path, where lineage
decides them. But lineage was computed only when some field *lacked* provenance
— an optimisation that was exactly right until "lacks provenance" stopped being
the same question as "will be planned without provenance".

On Postgres the two are the same set, so this was invisible. On CockroachDB the
fields carry an OID right up to the moment we decline to believe it, so lineage
never ran and every set operation was refused, including ones over released
columns that Postgres serves. Safe, and worse than Postgres for no reason. The
gate now asks the question the planner actually asks.

Both halves are asserted in `scripts/test-cockroach.sh`, which includes a
direct-connection control proving CockroachDB really does report the
leak-enabling provenance — so the test fails if a future CockroachDB release
changes this and the suite quietly stops testing anything.

## The same bug, hidden in a view — and Postgres has it too

Deciding from the statement text is not enough, because the set operation can be
somewhere the statement cannot see it:

```sql
CREATE VIEW v_union AS SELECT city AS v FROM t UNION ALL SELECT email FROM t;
SELECT v FROM v_union;      -- no set operation in sight
```

`scripts/test-shapes.sh` found this after the statement-level check had already
shipped. That is the argument for the sweep rather than for the check.

The important part is what Postgres does here. It **reports provenance** — not
zero — naming `v_union.v`, the view's own column. That is honest as far as it
goes, and it is still one field with two source columns. Any rule releasing
`v_union.v` therefore releases addresses along with cities, and `v` is exactly
the column an operator would release: it looks like a city column, and
`classify` sampling it sees cities.

Running the sweep against the commit before the fix, with that rule in the
catalog, leaks on **both** engines:

```
 postgres     LEAK view_union: portland …
 cockroach    LEAK view_union: portland …
```

So this half is not a CockroachDB accommodation. Postgres was exposed by the
same underlying mistake — trusting a single reported origin for a field that has
several — and only escaped the first sweep because default-deny happened to
cover the view.

The fix: at catalog refresh the proxy reads every view definition
(`pg_get_viewdef`, available on both engines), marks the ones containing a set
operation, and propagates that to views built on them until it reaches a
fixpoint. A statement referencing any of them has its provenance distrusted.
A definition that is null, empty or unparseable is marked opaque — an engine
that will not tell us what is in a view has not told us the view is safe.

The cost on Postgres is one shape moving from *served as nulls* to *refused*,
which is the correct trade for closing a disclosure.

## Fuzzing it: a third leak, and why sqlsmith was the wrong tool

sqlsmith cannot read a CockroachDB schema — it loads `pg_catalog` and dies at
`Generating indexes...unknown type:`. Generating against Postgres and replaying
looked like the obvious workaround and does not work either: **395 of 400
statements errored**, because sqlsmith draws functions and operators from the
target's catalog and Postgres has thousands CockroachDB lacks. A campaign
erroring on 98.75% of its corpus is vacuous however it reports, and the poison
control caught exactly that.

Function soup was never what needed fuzzing. What decides masking is whether
per-field provenance can be believed, and that is a property of a query's
*shape* — how many source columns can reach one output field — not of which
scalar sits on top. Both leaks above were shapes.

`crates/fuzz/src/bin/shapegen.rs` therefore generates compositions of relational
operators (subquery, CTE, set operation, join, DISTINCT, window, aggregate,
GROUP BY, ORDER BY/LIMIT, `SELECT * FROM (…)`) over the fixture. Seeded
xorshift, no dependency, and a seed reproduces a corpus exactly. On CockroachDB
it produces **zero engine errors** where sqlsmith's corpus produced 98.75%.

Almost all of it is SQL both engines accept, which is what makes one corpus
replayable against both. The exception is `ROLLUP`, `CUBE` and `GROUPING SETS`:
CockroachDB rejects them (`unimplemented: this syntax`, issue 46280) and one
disclosure lived in exactly that reader, so they are generated under the
default `postgres` dialect and suppressed under `portable`. Every script that
replays one corpus against both engines — `test-fuzz-cockroach.sh`,
`test-differential.sh`, `soak.sh` — passes `portable` and then asserts the
corpus is free of those three spellings, because an engine error is not a
failure in those campaigns and a corpus that silently stopped parsing would
still report a pass.

It found a third disclosure on its first run:

```sql
SELECT c0, row_number() OVER (ORDER BY c0) AS c1
  FROM (SELECT c0, count(*) AS c1
          FROM (SELECT r5.v AS c0 FROM fz.v_mixed r5) q5
         GROUP BY c0) q5
```

Only under `lineage = "allow"`. The view-taint check worked: it distrusted the
provenance and sent the field down the opaque path. **Lineage then released
it** — it resolved the expression to `fz.v_mixed.v`, found the catalog's
`mask = "none"` rule, and handed over what provenance had just refused to.

The taint had reached the provenance decision and not the lineage decision.
`resolve` now refuses any source column belonging to a set-operation view
(guard 5). This is engine-independent — shared code, no engine branch — and is
pinned by a unit test that fails when the guard is removed.

The lesson is narrower than "add a guard": a safety property established in one
decision path is not established in the others, and the two paths here were
written months apart.

## Both protocols, on both engines

Every end-to-end suite except `binary` spoke simple query. Given that the whole
first disclosure was a *disagreement between protocols*, that was half a test.
`crates/fuzz/src/bin/extended.rs` replays a generated corpus through
Parse/Bind/Execute with binary results and the same canary oracle — driving
Describe-derived plans, `Bind` result-format re-stamping and the type-aware
decode/encode path, none of which `simple_query` touches.

Zero leaks on both engines. CockroachDB refuses more of the same corpus than
Postgres does (141 served of 600 against 179), which is the expected shape of
distrusting provenance the engine reports more freely.

## Integer widths are not portable, and that hid a gap

A bare `int` is int4 on Postgres and **int8 on CockroachDB**. The fixture used
bare `int`, so the same file produced different column types per engine and a
typed driver could not read both — which is how the binary suite failed on
CockroachDB, as a deserialisation error rather than a masking error.

The interesting part is what it exposed. `mask.rs` has handled int8 since it was
written and a unit test covers it, but **no end-to-end suite had ever produced
one**, because Postgres's `int` is int4 and every fixture used it. Widths are
explicit now, and `fz.people.salary_big int8` gives the 64-bit binary path its
first end-to-end coverage on either engine.

That is the general form of what porting to a second engine buys: not only
"does it work there", but "which of our assumptions were the first engine's
defaults wearing a disguise".

## Other differences found

| | Postgres | CockroachDB |
|---|---|---|
| set-operation provenance | zero | first branch, simple query only |
| `pg_size_pretty` | present | absent |
| declarative partitioning | `PARTITION BY LIST` | rejected; different syntax |
| catalog queries the resolver runs | work | work unchanged |

The catalog resolver needed no changes: `pg_class` / `pg_namespace` /
`pg_attribute` with `relkind = ANY('{r,v,m,p,f}')` resolves against CockroachDB
as-is. Pseudonyms are keyed by HMAC over the value, not by anything the engine
supplies, so the same row yields the same pseudonym on both — a Postgres copy
and a CockroachDB cluster stay correlatable. That is asserted rather than
assumed.

## What is not covered

- **CockroachDB is tested on one version**, v25.4.14, pinned in the suite and
  checked at startup. Postgres gets 13 through 17.
- **CockroachDB's own SQL extensions are unswept.** The generated campaign now
  runs against CockroachDB (see below), but its corpus is portable by
  construction, so `AS OF SYSTEM TIME`, changefeeds and `SHOW` variants have
  never been generated. A CockroachDB-only construct that reassigns provenance
  would not have been found.
- **The Phase 0 provenance spike is Postgres-only, and would not have caught
  this anyway.** `crates/spike` enumerates which SQL shapes carry provenance,
  but it reads it via Parse + Describe — the *extended* protocol, where
  CockroachDB reports zero for a set operation. Pointed at CockroachDB it would
  have said "opaque, safe" about the exact statement that leaked. Sweeping
  shapes was the right instinct; sweeping them over the wrong protocol is how
  the disclosure survived being looked for. `scripts/test-shapes.sh` sweeps the
  simple-query path and asserts on values rather than on reported provenance,
  which is why it found both bugs. The spike remains useful for *why* a shape
  behaves as it does, and it now carries the `view_union` shapes that showed
  Postgres reports the view's own column.
- **No other pgwire-speaking engine has been tried.** Anything that reports
  provenance more loosely than Postgres does is in the same category as the leak
  above, and the mitigation is the same: distrust the statement shape, do not
  trust the engine to have declined.

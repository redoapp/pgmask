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
// analysis.rs
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
- **No CockroachDB-specific SQL surface has been swept.** The generated-SQL
  campaign runs against Postgres only, so CockroachDB's own extensions — `AS OF
  SYSTEM TIME`, changefeeds, `SHOW` variants — have not been through the fuzzer.
  A construct that erases or reassigns provenance in a way set operations do not
  would not have been found.
- **The Phase 0 provenance spike is Postgres-only.** `crates/spike` enumerates
  which SQL shapes carry provenance and which erase it — precisely the tool that
  would have found the union leak, had it ever been pointed at CockroachDB. Its
  fixture uses declarative partitioning, materialized views and plpgsql, none of
  which port unchanged, so it has not been. That gap is how the leak survived,
  and it is worth closing before adding a third engine rather than after.
- **No other pgwire-speaking engine has been tried.** Anything that reports
  provenance more loosely than Postgres does is in the same category as the leak
  above, and the mitigation is the same: distrust the statement shape, do not
  trust the engine to have declined.

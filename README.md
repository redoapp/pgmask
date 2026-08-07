# pgmask

A fail-closed column masking proxy for Postgres. Point your connection string at
pgmask instead of the database; it rewrites sensitive column values in result sets
according to a policy catalog, and refuses anything it cannot classify.

```
$ psql -p 55432 -c 'SELECT id, email, name, phone, city, internal_note FROM demo.customers LIMIT 2'
 id |       email       |    name    |  phone   |  city  | internal_note
----+-------------------+------------+----------+--------+---------------
  1 | user1@example.com | Customer 1 | 555-0101 | Denver | note 1
  2 | user2@example.com | Customer 2 | 555-0102 | Austin | note 2

$ psql -p 6432 -c 'SELECT id, email, name, phone, city, internal_note FROM demo.customers LIMIT 2'
 id |          email           | name |  phone   |  city  | internal_note
----+--------------------------+------+----------+--------+---------------
  1 | e4ad0ccc6148@example.com | ***  | ****0101 | Denver |
  2 | 05045c648bac@example.com | ***  | ****0102 | Austin |

$ psql -p 6432 -c 'SELECT lower(email) FROM demo.customers'
ERROR:  pgmask: output column "lower" has no column provenance, so it cannot be classified
HINT:  Select the underlying column directly. Expressions, set operations
       (UNION/INTERSECT/EXCEPT), recursive CTEs and SETOF-returning functions
       all erase provenance.
```

**Status: MVP working.** All 18 acceptance criteria pass end-to-end against a real
Postgres — see [`docs/mvp.md`](docs/mvp.md) and `examples/demo/verify.sh`. Not yet
production-ready: no TLS, and the limits below are real.

## How it works

Postgres's `RowDescription` carries, per output field, the table OID and column
attnum it came from — and `0` for both when the field is a computed expression.
That is engine-authoritative provenance, free, with no SQL parsing.

The governing rule: **bind the masking plan to the `RowDescription`, never to the
statement.** Every row-producing path in the protocol emits one first, so cursors,
`FETCH`, multi-statement queries, resumed portals and re-executed prepared
statements are all covered without special handling. Exactly two paths emit rows
*without* one — `COPY ... TO STDOUT` and the legacy `FunctionCall` message — and
both are refused. A `DataRow` arriving with no active plan is never forwarded.

We decode only four message types and forward everything else byte-for-byte.
Bytes we never interpret are bytes we cannot misinterpret.

## Try it

```bash
./examples/demo/verify.sh     # postgres in podman, 50k rows, all 18 assertions
```

Or by hand:

```bash
podman run -d --name pgmask-demo -e POSTGRES_PASSWORD=demo -e POSTGRES_DB=demo \
  -p 55432:5432 docker.io/library/postgres:17
psql -h localhost -p 55432 -U postgres -d demo -f examples/demo/schema.sql
cargo run --release -p pgmask -- examples/demo/catalog.toml
psql -h localhost -p 6432 -U postgres -d demo
```

Benchmarks:

```bash
DIRECT_URL=postgres://postgres:demo@localhost:55432/demo \
PROXY_URL=postgres://postgres:demo@localhost:6432/demo \
  cargo run -p bench --release -- 10000 300
```

## Configuration

```toml
listen  = "127.0.0.1:6432"
backend = "127.0.0.1:55432"
catalog_dsn   = "postgres://..."   # used once at startup to resolve OIDs
pseudonym_key = "..."              # rotating invalidates every pseudonym issued

unclassified      = "mask"   # mask | allow    — default-deny
unclassified_mask = "null"
opaque            = "reject" # reject | mask   — fields with no provenance

[[column]]
relation = "demo.customers"
column   = "email"
mask     = "pseudonym"   # none | null | redact | partial | hash | pseudonym
```

Masks: `pseudonym` is keyed, deterministic and shape-preserving, so joins still
work and an email still looks like an email. That determinism is also an
equality-and-frequency oracle — usually the point, but choose it deliberately.

The catalog is keyed on `(OID, attnum)`, never on output column name, which any
query can rename. Views need their own entries: Phase 0 found that Postgres
reports the *view's* OID, not the base table's.

If a configured column does not exist, the proxy refuses to start. A half-loaded
catalog is a catalog with unknown coverage.

## Performance

0.29 µs per masked row; interactive latency overhead within noise; bulk scans
~2.4× slower than direct. The first working version was 3.98 µs/row — the fix
that mattered was coalescing writes into one buffer, replacing a syscall per row.
Full numbers and methodology in [`docs/benchmarks.md`](docs/benchmarks.md).

## Known limits

- **`SELECT 1` is rejected.** A literal has no table, so it has no provenance, and
  a constant is indistinguishable from `lower(email)` at the protocol level.
  Health checks that use it will fail. Fixing this properly needs Phase 6 parsing.
- **Set operations, recursive CTEs and `SETOF` functions are rejected** — Phase 0
  measured that they erase provenance. Expected to be the main source of
  rejections in practice; instrument by cause before deciding on Phase 6.
- **Rejection happens after execution.** The backend already ran the query; the
  data never reaches the client, but the work was done, and inside an explicit
  transaction the client and server disagree about whether the statement
  succeeded.
- **No TLS.** `SSLRequest` is answered `N`; use `sslmode=disable`.
- **Non-text types accept only `mask = "null"`.** Text-family types are
  byte-identical in text and binary formats so they mask correctly either way;
  anything else is refused rather than guessed at.
- **One global policy.** No per-principal exceptions yet.
- Masking is a disclosure control on the projection. It does not defend against
  predicate oracles, join-key re-identification, small-cell aggregates or
  differencing — recorded as reviewed and accepted in
  [`docs/handoff.md` §11](docs/handoff.md).

## Layout

```
docs/handoff.md            the build plan — read this first
docs/mvp.md                MVP goal, acceptance criteria, scope boundaries
docs/benchmarks.md         performance methodology and results
docs/phase0-results.md     generated provenance spike output

crates/proxy/protocol.rs   wire framing and the four message types we decode
crates/proxy/session.rs    the per-connection state machine
crates/proxy/catalog.rs    config and (OID, attnum) resolution
crates/proxy/mask.rs       masking algorithms
crates/spike/              Phase 0 provenance spike
crates/bench/              latency and throughput harness
examples/demo/             schema, catalog, and the acceptance script
```

## Phase 0

The design rests on provenance surviving real queries, so that was measured
before anything was built. 37 query shapes on PG 17.10: 22 full provenance, 3
partial, 12 opaque. It survives subqueries (flattened and not), CTEs including
`MATERIALIZED`, views, matviews, partitioned parents, `LATERAL`, cursors, temp
tables and no-op casts. Results in
[`docs/phase0-results.md`](docs/phase0-results.md), analysis in
[`docs/handoff.md` §4](docs/handoff.md).

Rerun against the target major version before trusting it there — provenance is a
planner property, not a documented guarantee.

```bash
DATABASE_URL=postgres://... cargo run -p spike -- --md docs/phase0-results.md
```

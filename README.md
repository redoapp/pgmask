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

## Where this stands

| | |
|---|---|
| Phase 0 — provenance spike | done, **GO** ([results](docs/phase0-results.md)) |
| MVP — masking, fail-closed | done ([goal](docs/mvp.md)) |
| Phase 4 — security boundary | done ([what it found](docs/phase4.md)) |
| Catalog freshness + rejection metrics | done |
| Per-principal policy, semantic types, type-aware masks | done |
| Validated against a real database | done ([Neon run](examples/neon/README.md)) |
| **Phase 1 — classification catalog + CI gate** | **open, and the largest item left** |
| Phase 6 — parser rules | open; priority revised by measurement, not guesswork |

117 assertions across five suites: 55 unit, 18 adversarial, 8 resilience, 7 TLS,
29 demo. The adversarial suite drives a raw wire client and asserts no sentinel
byte ever crosses the boundary.

**What to do next, in order.** Phase 1 is the gate on this being useful — the
enforcement mechanism is in good shape and the policy it enforces still has to
be written. Then decide Phase 6 from the measured causes (aggregates first, not
set operations). The limits below are real and unchanged.

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

Fields with no provenance are refused — except for a short allowlist of
expression shapes positively known to carry no column value (`SELECT 1`,
`now()`, `count(*)`). That rule is an allowlist rather than a search for column
references because it converts refusals into acceptances, so unsoundness there
means a leak; see [`crates/proxy/src/analysis.rs`](crates/proxy/src/analysis.rs).
It cut the false-rejection rate on a real workload from 23% to 6%.

## Try it

```bash
./examples/demo/verify.sh        # acceptance criteria, 50k rows, 18 assertions
./scripts/test-integration.sh    # canary + adversarial + resilience, 23 tests
./scripts/test-tls.sh            # TLS on both legs via a real psql, 7 assertions
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
catalog_dsn   = "postgres://..."   # resolves names to OIDs, at boot and refresh
pseudonym_key = "..."              # rotating invalidates every pseudonym issued

unclassified      = "mask"   # mask | allow    — default-deny
unclassified_mask = "null"
opaque            = "reject" # reject | mask   — fields with no provenance

tls_cert    = "/path/proxy.crt"   # omit both to serve plaintext
tls_key     = "/path/proxy.key"
backend_tls = "disable"           # disable | require — see the note below

catalog_refresh_seconds     = 30  # OIDs are not stable across DDL
catalog_refresh_min_seconds = 5   # floor on miss-triggered refreshes
metrics_interval_seconds    = 60  # 0 disables

# Who is who. Members are usernames Postgres verified, never merely claimed.
[[role]]
name    = "support"
members = ["support_sam"]

# Describe a kind of data once, reference it from every column that holds it.
[[semantic_type]]
name    = "email"
mask    = "pseudonym"
keep    = 3
by_role = { support = "inner" }

[[column]]
relation = "demo.customers"
column   = "email"
type     = "email"          # or an inline `mask =`, which overrides the type
```

### Masks

| Mask | Effect | Applies to |
|---|---|---|
| `none` | passthrough — an explicit decision | any |
| `null` | type-correct NULL | **any type, any format** |
| `redact` | constant `***` | text |
| `partial` | keep the last `keep` chars — `****0101` | text |
| `inner` | keep `keep` at each end — `12**56` | text |
| `outer` | keep the middle — `**34**` | text |
| `range` | mask `[start, end)` | text |
| `hash` | HMAC-SHA256, hex | text |
| `pseudonym` | keyed, deterministic, shape-preserving | text, uuid |
| `date-year` | truncate to 1 January | date, timestamp, timestamptz |
| `date-month` | truncate to the 1st | date, timestamp, timestamptz |
| `numeric-bucket` | floor to a multiple of `bucket` | int2/4/8, float4/8, numeric (text) |
| `ip-prefix` | keep the network — `203.0.113.0` | text, inet/cidr (text) |

Type and format compatibility is checked once when the result set is described,
so a misconfiguration refuses cleanly instead of dying halfway through a stream.
Negative numbers floor *downward* (`-37` with bucket 10 → `-40`), because
rounding toward zero would reveal more than the bucket size promises.

`pseudonym` is deterministic, so joins still work and an email still looks like
an email. That determinism is also an equality-and-frequency oracle — usually
the point, but choose it deliberately.

### Semantic types and pseudonym domains

A semantic type names a kind of data once and supplies its mask, parameters and
per-role overrides. It also becomes the default **pseudonym domain**, which
decides what stays linkable: two columns of the same type pseudonymise
identically so joins keep working, while an `account_id` that happens to equal a
`phone` will not, so the two columns cannot be linked by comparing masked values.

### Per-principal policy

`by_role` on a column or a semantic type gives the same column different
treatment for different people — support sees a partial email, everyone else a
pseudonym. Roles come from the username **Postgres verified**, never one the
client claimed, and a session that has not authenticated holds no roles at all.

When a principal holds several roles with different masks, **the most
restrictive wins**. Adding a role must never widen access.

The catalog is keyed on `(OID, attnum)`, never on output column name, which any
query can rename. Views need their own entries: Phase 0 found that Postgres
reports the *view's* OID, not the base table's.

If a configured column does not exist, the proxy refuses to start. A half-loaded
catalog is a catalog with unknown coverage. Unknown config keys are also a
startup failure: TOML puts any key written after a `[[column]]` block *inside*
that block, so a misplaced `tls_cert` would otherwise silently leave you running
in plaintext.

### Catalog drift

pg_class OIDs are **not stable across DDL**. `CREATE OR REPLACE VIEW` keeps a
relation's OID; `DROP VIEW; CREATE VIEW` — what a lot of migration tooling emits
— does not. A catalog pinned at boot silently stops classifying those columns:
under default-deny they turn to NULL, and under `unclassified = "allow"` they
stop being masked at all.

So the catalog re-resolves on a timer, and sooner when the hot path sees a
relation OID it does not recognise (rate-limited by
`catalog_refresh_min_seconds`). Every difference is logged:

```
catalog: demo.customer_directory.email moved (oid.attnum 16393.2 -> 16397.2)
         — relation recreated, classification restored
catalog: COVERAGE LOST for demo.customers.ssn (was oid.attnum 16385.7)
         — the relation or column no longer exists; those values are now unclassified
```

If a refresh fails, the previous snapshot is kept rather than cleared — clearing
would be fail-closed in the narrow sense and would mask every column in the
database the moment Postgres blinked. Failures are logged and counted.

### Rejection metrics

Every refusal is bucketed by cause, because the numbers decide whether the
Phase 6 parser is worth building:

```
pgmask metrics: result_sets_masked=2 fields_masked=3 rejections=3 \
  opaque_named_like_column=1 opaque_anonymous=1 opaque_function=1 \
  set_op_like_share=33%
```

`tableID = 0` says "not a stored column" and nothing else, so the cause cannot be
recovered exactly without parsing. But Postgres names output columns predictably,
and the name buckets them well enough to steer a decision: `?column?` is a
literal or operator, `count`/`string_agg` an aggregate, `lower` a function — and
an opaque field named exactly like a column we classify is very likely a set
operation, recursive CTE or `SETOF` function, because all three preserve the
source name while losing provenance.

**`set_op_like_share` is the number to watch.** If a week of real traffic puts it
low, the parser is not worth a quarter. If it is high, build the two-rule version
in `docs/handoff.md` rather than a general lineage engine.

This inference is deliberately confined to counters. Matching on a column name
would be unsound for enforcement — any query can alias anything to anything — so
nothing here changes what gets masked.

### TLS, and one constraint worth knowing

Postgres negotiates TLS with an `SSLRequest` packet rather than ALPN or a
separate port; pgmask handles that on both legs.

**Use `backend_tls = "disable"` if your clients authenticate with SCRAM.**
`SCRAM-SHA-256-PLUS` binds authentication to the TLS certificate of the endpoint
the client is talking to, and pgmask terminates TLS and re-originates — so the
client binds to our certificate and the backend checks its own. That is channel
binding working as designed; catching an endpoint that re-originates TLS is
exactly its purpose. Stripping the mechanism does not help either, because SCRAM
detects the downgrade.

Postgres only advertises `-PLUS` on a TLS connection of its own, so a plaintext
backend leg means plain `SCRAM-SHA-256`, clients authenticate normally, and the
client-to-pgmask hop is still encrypted. Put pgmask next to the database and
secure that hop by placement. The unworkable combination is detected and
explained rather than failing opaquely. Full reasoning in
[`docs/phase4.md`](docs/phase4.md).

## Performance

0.22–0.29 µs per masked row across three runs; interactive latency overhead
within noise; bulk scans ~2.4× slower than direct. The first working version was
3.98 µs/row, and the fix that mattered was not algorithmic — it was coalescing
writes into one buffer, replacing a `write` syscall per row. Methodology and the
full optimisation trail in [`docs/benchmarks.md`](docs/benchmarks.md).

## Against a real database

`examples/neon/` runs pgmask read-only in front of a live Neon branch of a real
internal-tools database (~380k rows) under three policies. It found four bugs —
hardcoded TLS SNI, a `NoTls` catalog connection, `channel_binding=require` in the
provider's own DSN, and libpq refusing `-PLUS` over a plaintext link — and it
refuted the assumption behind our Phase 6 plan: set operations are 7% of
rejections, expressions and aggregates are 80%. Write-up in
[`examples/neon/README.md`](examples/neon/README.md).

## Measured against real workloads

| corpus | refused | note |
|---|---|---|
| 31 hand-written queries, real Neon branch | 32% | [write-up](examples/neon/README.md) |
| **TPC-DS, 99 queries** | **90%** | [write-up](examples/tpcds/README.md) |

`crates/corpus` measures this against any directory of SQL, using `Parse` +
`Describe` so it needs **no data** — only the DDL. The gap between the two rows
is the point: pgmask is usable today for row-level lookup workloads and not for
analytical ones, and which you have decides whether Phase 6 is optional.

## Known limits

- **Expressions over a column are rejected** — `lower(email)`, `email || ''`,
  `coalesce(domain, …)`, `to_json(row)`. Each emits the real value, so these are
  correct refusals, but they are also the largest source of friction.
  `SELECT 1`, `now()` and `count(*)` used to be refused too; they are now served
  (see below).
- **Anything taking a column as an argument is refused conservatively**, even
  when it is harmless — `avg(deals)`, `date_trunc('month', created_at)`. Opening
  that door means classifying functions, and `max(email)` returns a real email
  address.
- **Set operations, recursive CTEs and `SETOF` functions are rejected** — Phase 0
  measured that they erase provenance. Expected to be the main source of
  rejections in practice; instrument by cause before deciding on Phase 6.
- **Rejection happens after execution.** The backend already ran the query; the
  data never reaches the client, but the work was done, and inside an explicit
  transaction the client and server disagree about whether the statement
  succeeded.
- **SCRAM channel binding is unsupported**, unavoidably — see above.
- **Backend TLS does not verify the server certificate** (matching libpq's
  `sslmode=require`): it stops a passive listener, not an active one.
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

crates/proxy/protocol.rs   wire framing and the message types we decode
crates/proxy/session.rs    the per-connection state machine, and Vetted
crates/proxy/catalog.rs    config and (OID, attnum) resolution
crates/proxy/mask.rs       masking algorithms, semantic-type domains
crates/proxy/metrics.rs    rejection causes and counters
crates/proxy/tls.rs        TLS on both legs
crates/proxy/tests/        canary, adversarial and resilience suites
crates/spike/              Phase 0 provenance spike
crates/bench/              latency and throughput harness
examples/demo/             schema, catalog, and the acceptance script
scripts/                   integration and TLS test drivers
```

## How the guarantee is enforced

`Batch::client` — the only route to the client socket — accepts a `Vetted`, and
its four constructors are the complete list of ways bytes can get there. Adding a
"just forward it" path is a compile error rather than a code-review question.

The backend direction has **no catch-all**: control messages are allowlisted and
anything unrecognised is refused, because a message we cannot classify may carry
row data. That arm exists because the canary test caught `CopyData` escaping
through a `_ =>` that looked harmless.

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

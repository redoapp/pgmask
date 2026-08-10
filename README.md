# pgmask

A fail-closed column masking proxy for Postgres. Point your connection string at
pgmask instead of the database; it rewrites sensitive column values in result sets
according to a policy catalog, and refuses anything it cannot classify.

**What it does and does not do.** It guarantees a masked value does not appear
in a result set. It does *not* stop a determined client reconstructing one by
inference: the filter side is ungoverned, so `count(*)` with a `LIKE` predicate
recovers a full address in about 300 queries. The one route that returned every
value at once — `sum(x) GROUP BY <unique key>`, where each group is a single row
and the summary is that row — is refused as of v0.1.16; the same shape through a
`WHERE` clause is not, because whether a predicate matches one row is a property
of the data rather than of the statement. `./scripts/test-inference.sh`
enumerates what remains, measured against the demo fixture. Treat this as a
control against incidental exposure — an analyst who is not attacking you — not
as containment for one who is.

```
$ psql -p 55432 -c 'SELECT id, email, name, phone, city, internal_note FROM demo.customers ORDER BY id LIMIT 2'
 id |       email       |    name    |  phone   |  city  | internal_note
----+-------------------+------------+----------+--------+---------------
  1 | user1@example.com | Customer 1 | 555-0101 | Denver | note 1
  2 | user2@example.com | Customer 2 | 555-0102 | Austin | note 2

$ psql -p 6432 -c 'SELECT id, email, name, phone, city, internal_note FROM demo.customers ORDER BY id LIMIT 2'
 id |               email               | name |  phone   |  city  | internal_note
----+-----------------------------------+------+----------+--------+---------------
  1 | c22b1ef44518c300@8dedb655.invalid | ***  | ****0101 | Denver |
  2 | c8080392aa49c538@8dedb655.invalid | ***  | ****0102 | Austin |

$ psql -p 6432 -c 'SELECT lower(email) FROM demo.customers'
ERROR:  pgmask: output column "lower" has no column provenance, so it cannot be classified
HINT:  Select the underlying column directly. Expressions, set operations
       (UNION/INTERSECT/EXCEPT), recursive CTEs and SETOF-returning functions
       all erase provenance.
```

The address is pseudonymised on both sides of the `@`: the local part alone is
not the identifying half of a work address, and the domain names an employer.
Both map deterministically, so the same person is the same pseudonym everywhere
and "group by employer" still works without naming one.

**v0.1.24**, MIT licensed — see [CHANGELOG.md](CHANGELOG.md) for what is and is not
done, and [LICENSE](LICENSE).

## Where this stands

| | |
|---|---|
| Phase 0 — provenance spike | done, **GO** ([results](docs/phase0-results.md)) |
| MVP — masking, fail-closed | done ([goal](docs/mvp.md)) |
| Phase 4 — security boundary | done ([what it found](docs/phase4.md)) |
| Catalog freshness + rejection metrics | done |
| Per-principal policy, semantic types, type-aware masks | done |
| Validated against a real database | done ([Neon run](examples/neon/README.md)) |
| Phase 1 — catalog discovery (`crates/classify`) | done ([what it found](docs/classification.md)) |
| GUI clients — Harlequin, Beekeeper's stack, psql `\d` | done, opt-in ([how](docs/gui-clients.md)) |
| `classify --check` — CI gate on catalog drift | done ([who owns what](docs/responsibilities.md)) |
| Phase 6 — lineage (`lineage = "allow"`) | done, opt-in; TPC-DS refusals 55% → 26% ([measured](docs/lineage-estimate.md)) |
| CockroachDB v25.4 | supported, fuzzed on both protocols; closed three disclosures ([why](docs/engines.md)) |

`./scripts/test-all.sh` runs thirteen suites and reports one line each, with a
skipped suite counted as a failure: 265 cargo tests, 31 adversarial and resilience
tests against a real Postgres, 88 demo assertions, 7 TLS,
115 across Postgres 13–17, 34 against CockroachDB, a 44-shape canary sweep over
both engines, a generated-SQL campaign on Postgres and a generated-shape campaign
on CockroachDB, both of which must report zero leaks. The adversarial cargo suite drives a raw wire
client and asserts no sentinel byte ever crosses the boundary.

### Who owns what

**The catalog belongs to whoever deploys this, not to pgmask.** They know which
of their columns are sensitive; we do not, and a proxy that shipped opinions
about someone else's schema would be wrong more often than useful.

What pgmask owes them instead:

- **A safe default.** An unclassified column is masked, so a catalog that is
  incomplete costs utility, never exposure.
- **Tools to build and keep the catalog.** `classify` reads a live schema and
  proposes one, naming what it cannot decide rather than guessing — on TPC-DS it
  surfaced 46 sensitive columns a hand-written catalog had missed, including
  every special-category demographic column.
- **Loud misconfiguration.** Unknown config keys are refused, degenerate mask
  parameters are refused, and a classification that stops resolving logs a
  warning rather than silently ceasing to mask.

**What to do next.** `./scripts/test-fuzz.sh` is the standing answer to having
no second reviewer: each seed contributes a sqlsmith corpus and a `shapegen`
corpus, replayed across 4 policy combinations, with **no masked value reaching
the client in any of them**. (Executions are 4x the corpus — the same SQL runs
under each policy.)

Count *executed*, not generated. Roughly a third of what sqlsmith emits runs at
all: measured on this fixture, 123 of 400 statements execute and the other 277
are `anymultirange is not a multirange type`, `cannot determine element type of
"anyarray"`, `operator does not exist: point = point` and kin — the type
resolver, not the masker. `shapegen` executes 397 of 400. Adding it to the main
replay took the served fraction from 12% to 35% of statements and the masked
values actually reached from 26 thousand to 21 million. The generated total is
the less interesting number and this file used to quote only that. One of the four configurations masks *nothing*, where the proxy must
be a byte-exact mirror of the database — that asks "did it corrupt anything it
should not have touched", which a leak oracle is structurally blind to. It
refuses to pass on a technicality: a poison run with masking removed must trip
the oracle first, a run that never reached masked data exits VACUOUS, the
harness refusal count is cross-checked against the proxy's own metrics, and the
fixture is verified unchanged. Beyond that: more fixture shapes,
and someone other than Claude reading `analysis.rs` and `lineage.rs`.

`scripts/test-fuzz.sh` also runs 12 binary-result-format checks, 21,600
per-principal assertions across 24 concurrent sessions of three principals, and
60 reads taken while a view is dropped and recreated underneath the catalog. Everything else
that drives the proxy end to end speaks the simple query protocol, which is
text-only — the first suite to ask for binary found two bugs, one of which broke
every driver that prefers it.

Coverage was last measured at **79%** overall at v0.1.0 and is not re-measured
per release, so treat it as indicative rather than current — several suites and
a good deal of code have landed since. Measure it by sourcing
`cargo llvm-cov show-env --export-prefix` before running the suites. What is
worth measuring is coverage *of the generated corpus alone*: "the fuzzer found
nothing" and "the fuzzer never executed that code" look identical from outside,
and that distinction has cost this project a real disclosure. Phase 6 lineage is done — measured at converting about a third
of refusals, see [docs/lineage-estimate.md](docs/lineage-estimate.md). The
limits below are real and unchanged.

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
Bytes we never interpret are bytes we cannot misinterpret. That is also why the
framing is hand-written rather than taken from `pgwire` or `postgres-protocol`:
both model the protocol as a closed enum, so an unrecognised tag is an error
rather than something to pass along, and neither can emit the modified backend
messages a masking proxy exists to produce. `pgwire` is a dev-dependency
instead — `tests/differential.rs` makes it a second opinion on the
`RowDescription` fields that decide masking.

Fields with no provenance are refused — except for a short allowlist of
expression shapes positively known to carry no column value (`SELECT 1`,
`now()`, `count(*)`). That rule is an allowlist rather than a search for column
references because it converts refusals into acceptances, so unsoundness there
means a leak; see [`crates/proxy/src/analysis.rs`](crates/proxy/src/analysis.rs).
It cut the false-rejection rate on a real workload from 23% to 6%.

**Provenance is necessary but not sufficient.** Where one output field draws
from several source columns, the reported OID names at most one of them.
Postgres declines to answer in that case and reports zero; CockroachDB answers
with the first branch, which leaked a masked column through a `UNION` until
v0.1.1. The proxy now distrusts provenance for any statement containing a set
operation, on every engine, and handles those fields as computed ones. See
[docs/engines.md](docs/engines.md).

## Try it

```bash
./scripts/test-all.sh            # everything; a skipped suite counts as a failure
./examples/demo/verify.sh        # acceptance criteria against a real Postgres
./scripts/test-fuzz.sh           # 24k generated statements x 4 policies, asserts nothing leaks
./scripts/test-integration.sh    # canary + adversarial + resilience, 31 tests
./scripts/test-tls.sh            # TLS on both legs via a real psql, 7 assertions
./scripts/test-versions.sh       # 23 assertions x Postgres 13,14,15,16,17
./scripts/test-cockroach.sh      # 34 assertions against CockroachDB v25.4
./scripts/test-shapes.sh         # 43 query shapes, canary sweep, both engines
./scripts/test-fuzz-cockroach.sh # generated shapes, both protocols, CockroachDB
./scripts/test-differential.sh   # same corpus through both engines, compared
cargo llvm-cov --release --summary-only   # coverage, after running the above
cargo audit && cargo machete              # advisories and unused deps
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
  cargo run -p bench --bin bench --release -- 10000 300
```

## Deploying it: the part that is not code

**A proxy is only a control if the database is not reachable around it.** Every
guarantee below assumes the backend's port is closed to the people the masking
is for. If an analyst can put the real host in their connection string, they get
unmasked data and pgmask never sees the query. Nothing in this process can
detect or prevent that, and no amount of hardening here changes it.

So the deployment is the boundary, not the binary:

- The Postgres port reachable **only** from the proxy — security group, network
  policy, `pg_hba.conf`, or all three.
- The proxy's own credentials to the backend distinct from anyone else's, so
  revoking human direct access does not revoke the proxy's.
- `tls_cert`/`tls_key` set. pgmask warns loudly without them, because a masking
  proxy reachable in plaintext is a boundary anyone on the path can read around.

Treat the catalog file as production configuration. A column dropped from it
stops being masked at the next refresh, and the log line saying so is a `warn`
that nobody reads if nothing is watching `pgmask_rejections_total` and the
coverage warnings.

## Operating it

Config, migrations and deploy ordering: [docs/operations.md](docs/operations.md).
The short version — there is no unsafe deploy ordering, config and migration can
land in either order, and `classify --check` turns every kind of schema drift
into a build failure including a column type change, which is the one that
otherwise surfaces as a production outage.


Logs are `tracing`, structured, on stderr, filtered by `PGMASK_LOG` (falling
back to `RUST_LOG`, defaulting to `info`). Each connection gets a span, so every
line it emits carries its peer:

```
INFO pgmask listening listen=127.0.0.1:6432 backend=127.0.0.1:55432 classified_columns=20 …
WARN no tls_cert/tls_key — clients connect in plaintext, and a masking proxy reachable in plaintext is not a security boundary
INFO session{peer=127.0.0.1:53295}: session closed user=postgres authenticated=true roles=0 masked_fields=10 rejected_result_sets=0
```

With `metrics_listen` set, `/metrics` serves Prometheus text. Rejection *causes*
are a label rather than a metric each, so adding a cause needs no exporter
change:

```
pgmask_rejections_total{cause="opaque_aggregate"} 1
pgmask_rejections_total{cause="opaque_function"} 1
pgmask_values_masked_total 10
pgmask_fields_rescued_total 2
pgmask_sessions_total 3
```

`pgmask_fields_masked_total` counts *columns carrying a mask* per result set;
`pgmask_values_masked_total` counts values actually rewritten. Two assertions in
`verify.sh` check that no metric or log line ever contains a column value or the
pseudonym key.

## Configuration

```toml
listen  = "127.0.0.1:6432"
backend = "127.0.0.1:55432"
catalog_dsn   = "postgres://..."   # resolves names to OIDs, at boot and refresh
pseudonym_key = "..."              # rotating invalidates every pseudonym issued

unclassified      = "mask"   # mask | allow    — default-deny
unclassified_mask = "null"
opaque            = "reject" # reject | mask   — fields with no provenance
lineage           = "refuse" # refuse | allow  — trace expressions to base columns

tls_cert    = "/path/proxy.crt"   # omit both to serve plaintext
tls_key     = "/path/proxy.key"
backend_tls = "disable"           # disable | require — see the note below

catalog_refresh_seconds     = 30  # OIDs are not stable across DDL
catalog_refresh_min_seconds = 5   # floor on miss-triggered refreshes
metrics_interval_seconds    = 60  # summary log line; 0 disables
metrics_listen = "127.0.0.1:9464"  # Prometheus /metrics; omit to open no port

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
| `scrub` | replace identifiers inside free text — `called <EMAIL>` | text |

### `scrub` is the one mask that reveals

Every other mask hides by default, so a gap costs utility. `scrub` shows the
value minus what it recognised, so **a gap is a disclosure**. It replaces
structured identifiers — address, phone, card, IBAN, UK NHS number, NINO, SSN,
UK postcode, IP, MAC, crypto address, URL, uuid — and it does not catch a
person's name, a street address, or `alice [at] acme [dot] com`.

Where a checksum exists it is applied, because in a mask that *reveals* a false
positive rewrites readable text into a placeholder that was never there. Luhn
for cards, mod-97 for IBANs (via `iban_validate`, which carries the per-country
length table), mod-11 for NHS numbers. The entity set follows
[Presidio](https://github.com/microsoft/presidio)'s predefined recognizers,
which is MIT licensed and validates the same fields for the same reason. On realistic support notes that is roughly half of
what a human would call sensitive; the misses are pinned as assertions in
`mask.rs` so the limit stays documented rather than assumed.

Use it when someone has to read the note and you accept that. It costs about
1 microsecond per value, and it is ranked as barely-more-restrictive-than-`none`
so a role holding both `scrub` and `redact` still gets `redact`.

Type and format compatibility is checked once when the result set is described,
so a misconfiguration refuses cleanly instead of dying halfway through a stream.

Dates and timestamps are decoded and re-encoded through `postgres-types`'
`FromSql`/`ToSql` with jiff's civil types, and `numeric` through `rust_decimal`,
rather than through epoch arithmetic and `f64` of our own. Three defects came
out of the hand-rolled version — an overflow at the microsecond extremes, a
narrowing cast that moved a date instead of coarsening it, and a dropped `BC`
era — and the library's types are range-checked, so an unrepresentable value now
fails to decode rather than wrapping.
Negative numbers floor *downward* (`-37` with bucket 10 → `-40`), because
rounding toward zero would reveal more than the bucket size promises.

`pseudonym` is deterministic, fixed-width (64 bits), and pseudonymises an
email's **domain** as well as its local part — for business data the domain
names the company, and with one contact there it names the person. Domains map
deterministically, so colleagues still group together without the employer being
named; `keep_domain = true` opts back in.

Determinism is also an equality-and-frequency oracle: an analyst can count
distinct subjects, join them across tables, and spot the outlier. Usually the
point, but choose it deliberately.

Parameters that would leave a value unchanged are refused at startup —
`numeric-bucket` with `bucket = 1` and `range` with `end <= start` both used to
pass the value through while looking configured.

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

**The snapshot's unique keys fail open, unlike everything else in it.** An
unknown column is masked, because unclassified means deny; but a relation whose
unique keys are not yet in the snapshot simply has none, and the singleton-group
guard has nothing to fire on. A table created after the last refresh therefore
serves `sum(x) GROUP BY <its key>` until the next one, up to
`catalog_refresh_seconds`. Found by a test that created its fixture after
starting the proxy: the cases that ran before the refresh were served and the
ones after were refused, splitting exactly on the boundary. The window is
bounded by the refresh interval and needs DDL inside it, so it is recorded
rather than closed — closing it means refusing aggregates over every relation
the snapshot does not know, which includes every temp table.

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
| **TPC-DS, 99 queries** | **55%** (was 90%) | [write-up](examples/tpcds/README.md) |

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
- **Summaries over classified columns are released** — `sum`, `avg`, `count`,
  ranking windows, `date_trunc`. The bar is "you cannot read an anonymised
  value", not "no information flows": a group of one row makes `sum(salary)`
  that person's salary, which is accepted on the same terms as the predicate
  oracles below. `summaries = "refuse"` reverts it.
- **Functions that return a stored value are never released** — `min`, `max`,
  `mode`, `percentile_*`, `string_agg`, `array_agg`, `first_value`, `lag`,
  `lead`. `max(email)` is an email address.
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
- **One catalog with per-principal role overrides.** A principal may receive a
  stricter mask through any matching role; overlapping roles resolve to the
  most restrictive mask deterministically.
- Masking is a disclosure control on the projection. It does not defend against
  predicate oracles, join-key re-identification, small-cell aggregates or
  differencing — recorded as reviewed and accepted in
  [`docs/handoff.md` §11](docs/handoff.md). The single exception is the
  statically decidable one: a released reducing aggregate whose `GROUP BY`
  covers a declared unique key, or whose `GROUP BY` cannot be read at all, is
  refused. Column references, ordinals and `ROLLUP`/`CUBE`/`GROUPING SETS` are
  read, and so is an output alias, which denotes whatever its target computes;
  an expression is not, and falls back to asking whether the statement names
  every column of some key at all. Separately, a summary of a column the query
  groups *on* is that column — `sum(x)/count(*)` is `x` within a constant
  group — so a reducing aggregate whose input the grouping could reach is
  refused regardless of any key. Ungrouped groupings, non-key
  groupings and coarse date buckets are served unchanged.

## Layout

```
docs/handoff.md            the build plan — read this first
docs/mvp.md                MVP goal, acceptance criteria, scope boundaries
docs/benchmarks.md         performance methodology and results
docs/phase0-results.md     generated provenance spike output

crates/proxy/protocol.rs   wire framing and the message types we decode
crates/proxy/plan_state.rs statement/portal/Describe plan lifecycle
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

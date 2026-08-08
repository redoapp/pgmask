# Changelog

## 0.1.0 — first release

MIT licensed.

A fail-closed column masking proxy for Postgres. Point a connection string at
pgmask instead of the database and sensitive column values are rewritten on the
way back out. Nothing else about how people work changes: same client, same SQL,
one different host and port.

**Status: usable for engineers working against a copy of production data. Not
yet something to put in front of production as a compliance control** — see
[what is not done](#what-is-not-done).

### How it decides what to mask

Postgres's `RowDescription` carries, per output field, the table OID and column
attnum it came from — and zero for both when the field is computed. That is
engine-authoritative provenance, free, with no SQL parsing.

The governing rule is that **the masking plan is bound to the `RowDescription`,
never to the statement.** Every row-producing path emits one first, so cursors,
`FETCH`, multi-statement queries and re-executed prepared statements are covered
without special handling. The only two paths that emit rows without one —
`COPY ... TO STDOUT` and the legacy `FunctionCall` message — are refused.

### What it does

- **Fourteen masks**: `none`, `null`, `redact`, `partial`, `inner`, `outer`,
  `range`, `hash`, `pseudonym`, `date-year`, `date-month`, `numeric-bucket`,
  `ip-prefix`, `scrub`. Dates and timestamps go through `postgres-types` with jiff, and
  `numeric` through `rust_decimal`, rather than epoch arithmetic of our own.
- **Deterministic pseudonyms**, so masked data stays joinable. Keyed by HMAC,
  domain-separated per semantic type so unrelated columns cannot be linked.
- **Per-principal policy.** The same column resolves differently by role, keyed
  on the username Postgres authenticated — never one a client merely claimed.
- **Default-deny.** A column with no rule is masked, so an incomplete catalog
  costs utility and never exposure.
- **Lineage** (`lineage = "allow"`, off by default): an expression is released
  when every base column it derives from is explicitly released. Cuts refusals
  on TPC-DS from 55% to 26%.
- **System catalogs** (`system_catalogs = "allow"`, off by default), so DBeaver,
  Harlequin, DataGrip and psql's `\d` work.
- **Structured logging** via `tracing`, and a Prometheus endpoint.
- **`classify`**, which reads a live schema and proposes a catalog, naming what
  it cannot decide rather than guessing. `classify --check` fails a build on
  catalog drift.

### Verified

| suite | what it covers |
|---|---|
| 190 cargo tests | units, properties, adversarial wire client, differential vs `pgwire` |
| 82 demo assertions | end-to-end against a real Postgres, 50k rows |
| 115 version assertions | 23 checks x Postgres 13, 14, 15, 16, 17 |
| 7 TLS assertions | TLS on both legs through a real psql |
| 11 binary-format checks | every type-aware mask over the extended protocol |
| 21,600 role assertions | 24 concurrent sessions, 3 principals |
| 96,000 generated statements | sqlsmith x 4 policy configurations |

The generated-SQL campaign asserts that **no masked value ever reaches the
client** and refuses to pass on a technicality: a poison run with masking
removed must trip the oracle first, every query also runs against the database
so a run that never reached masked data reports as vacuous, the harness refusal
count is cross-checked against the proxy's own metrics, and one configuration
masks nothing so the proxy must be a byte-exact mirror.

Coverage across all suites is 79%, with the modules that decide masking highest:
`analysis.rs` 98%, `lineage.rs` 97%, `mask.rs` 94%, `session.rs` 85%.

### What is not done

- **Nobody but Claude has reviewed this.** Everything above was written and
  assessed by the same author. The test suite is deliberately built so that
  finding nothing is hard to fake, but it is not a substitute for a reader.
- **It has never seen production traffic.** All measurement is TPC-DS, a
  synthetic fixture, and one read-only database branch. No soak test.
- **26% of TPC-DS is still refused**, even with lineage on. Row-level lookup
  work is comfortable; heavy analytical SQL is not.
- **`min()`/`max()` over an explicitly released column are refused.** Correct in
  general, over-strict here, and unfixed.
- **DBeaver and DataGrip have not been driven** — only their query shapes and,
  for Beekeeper, its driver stack.
- **TLS is off in every shipped configuration.** The proxy warns at startup, and
  a masking proxy reachable in plaintext is not a boundary.

### The requirement that is not code

**A proxy is only a control if the database is not reachable around it.** Every
guarantee here assumes the backend's port is closed to the people the masking is
for. If someone can put the real host in their connection string, they get
unmasked data and pgmask never sees the query. Nothing in this process can
detect or prevent that. See the deployment section of the README.

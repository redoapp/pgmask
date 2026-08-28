# pgmask

pgmask is a fail-closed column-masking proxy for PostgreSQL. Point a PostgreSQL
client at pgmask instead of the database. pgmask masks classified columns,
masks unclassified columns by default, and rejects result fields it cannot
classify safely.

> [!IMPORTANT]
> pgmask prevents masked values from appearing directly in query results. The
> default posture does not stop a determined client from inferring values with
> filters, ordering, or repeated queries. Use `posture = "hostile"` for an
> adversarial client, and read the [security model](docs/security.md) before
> deployment.

Current version: **v0.2.9**. Licensed under the [MIT License](LICENSE).

## Install

Prebuilt `pgmask` and `classify` binaries for Linux (amd64 and arm64) and
Apple Silicon macOS are attached to [GitHub Releases](https://github.com/redoapp/pgmask/releases).
The shell installer places them in `CARGO_HOME/bin` (`~/.cargo/bin` by default).
Pin the tag, then confirm the binary:

```bash
curl --proto '=https' --tlsv1.2 -LsSf \
  https://github.com/redoapp/pgmask/releases/download/v0.2.7/pgmask-installer.sh | sh
pgmask --version
```

`classify` is a separate artifact (`classify-installer.sh` on the same
release). Each GitHub Release also carries CycloneDX SBOMs
(`pgmask.cdx.xml`, `classify.cdx.xml`). Verify an archive against
GitHub's build provenance, and the ELF against rustsec once you have
`cargo audit`:

```bash
gh attestation verify pgmask-x86_64-unknown-linux-gnu.tar.xz --repo redoapp/pgmask
cargo audit bin pgmask
```

Or build from source with Rust 1.97.1 (`rust-toolchain.toml` pins that
channel):

```bash
cargo build --release -p pgmask
```

## What pgmask provides

- Column policies resolved from PostgreSQL table OIDs and column numbers.
- Default-deny handling for columns missing from the catalog.
- Deterministic pseudonyms, redaction, partial masks, date truncation, numeric
  buckets, IP prefixes, and type-correct `NULL` values.
- Per-principal policies based on the username PostgreSQL authenticated.
- Read-only SQL enforcement and fail-closed handling of unsupported query
  shapes and protocol messages.
- Optional lineage for expressions and optional metadata access for GUI clients.
- Structured logs, Prometheus metrics, catalog refresh, SIGHUP config reload, and a catalog drift
  check for CI.

pgmask is tested against PostgreSQL 13–17 and CockroachDB 25.4. See the
[engine notes](docs/engines.md) for compatibility details.

## Quick start

Requirements: Rust, Podman, and `psql`.

Run the complete demo:

```bash
./examples/demo/verify.sh
```

A Chatwoot-shaped JSON/JSONB corpus (real schema names and app SQL) lives in
[examples/chatwoot](examples/chatwoot):

```bash
./examples/chatwoot/verify.sh
```

Or start it manually:

```bash
podman run -d --name pgmask-demo \
  -e POSTGRES_PASSWORD=demo \
  -e POSTGRES_DB=demo \
  -p 55432:5432 \
  docker.io/library/postgres:17

PGPASSWORD=demo psql -h localhost -p 55432 -U postgres -d demo \
  -f examples/demo/schema.sql

cargo run --release -p pgmask -- examples/demo/catalog.toml
```

In another terminal, connect through pgmask:

```bash
PGPASSWORD=demo psql -h localhost -p 6432 -U postgres -d demo
```

Direct column reads are masked according to the catalog. Unsafe expressions
fail closed:

```sql
SELECT id, email, phone FROM demo.customers LIMIT 2;

SELECT lower(email) FROM demo.customers;
-- ERROR: pgmask: output column "lower" has no column provenance
```

## How it works

PostgreSQL sends a `RowDescription` before each result set. Each field includes
the source table OID and column number, or zero when the field is computed.
pgmask binds a masking plan to that description and applies it to every
following row.

The main rule is: **bind policy to the result description, never only to SQL
text**. Prepared statements, portals, and repeated executions therefore use the
policy attached to their own result fields.

SQL analysis handles cases where provenance alone is incomplete. For example,
pgmask distrusts provenance for set operations and known opaque views. Anything
that cannot be proved safe follows the configured opaque policy.

See the [build handoff](docs/handoff.md) for the design history and the
[safety assessment](docs/safety-assessment.md) for the detailed audit record.

## Deploy safely

The deployment is part of the security boundary:

1. Block users from connecting directly to PostgreSQL.
2. Give pgmask a database role with `SELECT` and no write privileges. Prefer a
   read replica when possible.
3. Require client TLS with `tls_cert` and `tls_key`.
4. Protect the backend hop. Use `verify-full` when authentication permits it.
   Client TLS and backend TLS cannot both use SCRAM channel binding through a
   TLS-terminating proxy; that deployment requires a protected plaintext
   backend hop or a different authentication method.
5. Use real PostgreSQL authentication. Do not use `trust` with per-principal
   mask relaxations.
6. Keep `unclassified = "mask"` and run `classify --check` in CI.
7. Treat every `mask = "none"` rule as an access grant.

See [Security](docs/security.md), [Operations](docs/operations.md), and
[Policy ownership](docs/responsibilities.md).

## Configuration

The complete example is [examples/demo/catalog.toml](examples/demo/catalog.toml).

```toml
listen = "127.0.0.1:6432"
backend = "127.0.0.1:55432"
catalog_dsn = "postgres://postgres:password@127.0.0.1:55432/app"
pseudonym_key = "replace-with-at-least-16-random-bytes"

# Safe defaults.
unclassified = "mask"
opaque = "reject"
lineage = "refuse"
summaries = "allow"
posture = "default"
system_catalogs = "refuse"

# Client and backend transport.
tls_cert = "/run/secrets/pgmask.crt"
tls_key = "/run/secrets/pgmask.key"
# Client TLS plus SCRAM requires a protected plaintext backend hop.
backend_tls = "disable"
# Use verify-full when backend authentication does not offer SCRAM-PLUS.
# backend_tls = "verify-full"
# backend_ca = "/run/secrets/backend-ca.pem"

catalog_refresh_seconds = 30
catalog_refresh_min_seconds = 5
metrics_listen = "127.0.0.1:9464"

[[role]]
name = "support"
members = ["support_sam"]

[[semantic_type]]
name = "email"
mask = "pseudonym"
by_role = { support = "inner" }
keep = 3

[columns."app.customers"]
email = { type = "email" }
id = { mask = "none" }

[columns."app.events".payload]
mask = "json"
# Keep the document useful for structural debugging: unmentioned strings,
# numbers and booleans become "", 0 and false. Omit this to keep the default
# allowlist (unlisted scalars become JSON null).
json_unlisted = "shape-only"
# Refuse before parsing or allocating an unexpectedly large/deep document.
json_max_bytes = 1048576
json_max_depth = 64
json = [
  # Release arbitrary current and future profile fields...
  { pointer = "/profile", mask = "none" },
  # ...except for narrower policies, which take precedence.
  { pointer = "/profile/email", mask = "partial", keep = 4 },
  { pointer = "/profile/name", mask = "redact" },
  # `*` applies to every array element; an exact index would override it.
  { pointer = "/items/*/account_id", mask = "pseudonym", domain = "account" },
]
# Protect exact object-key names wherever they appear. The pointer above still
# wins specifically at /profile/email.
json_keys = [
  { key = "email", mask = "redact" },
  { key = "token", mask = "null" },
]
```

The compact `[columns."schema.relation"]` form groups simple rules by table;
a nested column table holds longer JSON or role-specific policy. The original
`[[column]]` form remains supported, and both forms may coexist, but defining
the same column twice is a startup error.

Unknown configuration keys, invalid mask parameters, duplicate column rules,
and unresolved configured columns are startup errors.

Send `SIGHUP` to reload the file without dropping connections. A parse or
resolution failure keeps the previous policy. `listen`, `backend`,
`catalog_dsn`, and `metrics_listen` still need a restart.

### Policy controls

| Setting | Default | Behavior |
|---|---|---|
| `unclassified` | `mask` | Type-aware masking for columns missing from the catalog. `allow` is an incremental-rollout escape hatch. |
| `unclassified_mask` | `type-aware` | Which mask `unclassified = "mask"` applies. `null` restores strict `NULL` for every unclassified value, giving up the equality-preserving pseudonyms. |
| `opaque` | `reject` | Reject computed or otherwise unclassified result fields. `mask` replaces them with `NULL`. |
| `lineage` | `refuse` | When enabled, release an expression only if all resolved source columns are explicitly released and the output shape cannot hide a nested query. |
| `summaries` | `allow` | Allow supported reducing aggregates, while applying the source column's policy when required. |
| `posture` | `default` | `hostile` refuses masked-column use outside a bare projection and forces summaries off. |
| `system_catalogs` | `refuse` | `allow` enables approved metadata queries needed by GUI clients and `psql` `\d`. |

`lineage = "allow"` improves compatibility but is less conservative: an
incomplete lineage result could release data. It is off by default. A release
now also requires the output expression to be a closed shape (no scalar
subquery in the field). A masked column named anywhere in the statement,
including as `u&"…"`, still blocks release.

`system_catalogs = "allow"` is required for most GUI clients. pgmask still
rejects catalog relations that may contain user values or SQL text. See
[GUI clients](docs/gui-clients.md).

### Masks

| Mask | Result | Supported values |
|---|---|---|
| `none` | Pass through unchanged | Any |
| `null` | Type-correct `NULL` | Any |
| `redact` | Constant `***` | Text |
| `partial`, `inner`, `outer`, `range` | Keep selected characters | Text |
| `hash` | Deterministic HMAC digest | Text |
| `pseudonym` | Deterministic, shape-preserving pseudonym | Text, UUID |
| `date-year`, `date-month` | Truncated date or timestamp | Date and timestamp types |
| `numeric-bucket` | Floor to a configured bucket | Integers, floats, and text-format `numeric` |
| `ip-prefix` | Remove the host portion | Text and text-format `inet` or `cidr` |
| `scrub` | Replace recognized identifiers in free text | Text |
| `json` | Recursively mask JSON Pointer policies; unlisted scalars follow `json_unlisted` | `json`, `jsonb` |

`scrub` reveals all text it does not recognize. It does not reliably identify
names, street addresses, or obfuscated identifiers. Use it only when readable
free text is required and partial disclosure is acceptable.

`json` preserves object keys, arrays, and nesting while applying ordinary
masks at JSON Pointers, including `/items/*` for every array element.
`json_unlisted` is `null` by default (allowlist: strip unlisted values);
`shape-only` keeps types without values; `pass-through` is denylist mode and
releases unlisted scalars, including keys added later. `json_keys` protects an
exact, case-sensitive object-key name at any depth, making denylist catalogs
practical without changing JSON Pointer or array-`*` semantics. A pointer at
the current path overrides a key rule; a key rule overrides an inherited
parent grant. Pointer policies are
compiled into a trie. Documents over `json_max_bytes` (1 MiB by default) or
`json_max_depth` (64 by default) refuse before parsing. Literal SQL extracts
use the same pointer policy; construction stays opaque. See
[JSON and JSONB masking](docs/json-masking.md).

Pseudonyms preserve equality. This keeps joins useful, but also exposes
frequency and repeated identity. Semantic types act as pseudonym domains:
columns in the same domain remain linkable; columns in different domains do
not. They are output aliases, not blind indexes: pgmask does not translate a
pseudonym supplied in a query back to its source value, and an emitted
pseudonym cannot be used to look up a row unless another system maintains that
mapping.

## Query behavior

- Plain classified columns use their catalog policy.
- Unclassified text and UUID values become column-scoped pseudonyms; dates and
  timestamps reduce to a year; text-format IPs reduce to a network prefix.
  Numeric, boolean, structured, binary, custom, and unsupported wire types
  become `NULL`. A value or format the chosen default mask cannot transform
  (an `infinity` timestamp, a non-ISO `DateStyle`, a binary-bound IP), a column
  the catalog has not resolved yet, or a character column too narrow to hold a
  pseudonym also becomes `NULL` rather than an error. Set
  `unclassified_mask = "null"` for strict `NULL` across the board. For a
  catalog-resolved `NOT NULL` column—including a constraint inherited through
  a domain chain—the automatic policy instead rejects the result before its row
  description if its type has only a `NULL` fallback; value-specific mask
  failures reject rather than introducing a new `NULL`. This is deliberately
  source-conservative: an outer join can make a `NOT NULL` source nullable in
  that particular result, but pgmask may still reject it because pgwire does
  not describe result nullability. An explicit `unclassified_mask = "null"`
  remains an operator choice and can still return `NULL`. Constraint DDL is
  reflected after the next catalog refresh, like other source metadata.
- Safe scalar values such as literals, `now()`, and `count(*)` pass through.
- Expressions over masked columns, value-returning aggregates such as `max`,
  set operations, recursive common table expressions, and set-returning
  functions are rejected unless a conservative rule proves them safe. JSON
  operators (`->`, `->>`, JSONPath), constructors, and aggregates over a
  classified JSON column are refused unless they are a **literal extract**
  (`->`, `->>`, `#>`/`#>>`, JSONB subscripting,
  `json[b]_extract_path[_text]`) of one
  schema-qualified column, in which case that column's pointer policy is
  applied to the result. JSONPath, constructors, and aggregates stay refused.
  See [JSON and JSONB masking](docs/json-masking.md).
- Supported one-column reductions such as `sum`, `avg`, variance, and boolean
  reductions inherit the source policy only for a bare column over explicitly
  schema-qualified named relations. Other shapes remain opaque unless lineage
  proves all inputs are released.
- Views need their own catalog entries because PostgreSQL reports the view's OID.
- SQL `COPY`, writes, row locks, procedural statements, SQL cursors, and SQL
  prepared-statement commands are rejected. Drivers may use the PostgreSQL
  extended protocol normally.

Some rejection decisions happen after PostgreSQL executes a query but before
pgmask forwards the result. Use database permissions and a read-only upstream
to control side effects and resource use.

## Catalog workflow

Generate a draft from a schema-equivalent database:

```bash
DSN=postgres://... cargo run --release -p classify -- \
  --schema public --sample 200 > catalog-draft.toml
```

Review every proposed rule. The classifier never treats an apparently ordinary
column as proof that it is safe.

Check the reviewed catalog in CI:

```bash
DSN=postgres://... classify --check \
  --catalog catalog.toml --schema public
```

The check fails for missing rules, stale rules, an empty schema, and masks that
do not support the current column type. See [Policy ownership](docs/responsibilities.md).

## Operations

- Catalog names are re-resolved periodically because PostgreSQL OIDs can change
  after DDL.
- The catalog file itself is read only at startup. Restart pgmask after editing
  policy.
- `SIGTERM` stops new connections and closes existing sessions without draining.
- Logs are written to stderr. `PGMASK_LOG` controls the filter and falls back to
  `RUST_LOG`.
- `metrics_listen` exposes Prometheus metrics at `/metrics`. Alert on catalog
  coverage warnings and rejection spikes.

See the [operations guide](docs/operations.md) for deployment order, schema
changes, CI checks, and monitoring.

## Test and benchmark

Run the release gate:

```bash
cargo install --locked cargo-deny cargo-machete
./scripts/test-all.sh
```

Useful focused suites:

```bash
./scripts/test-integration.sh       # real PostgreSQL adversarial tests
./scripts/test-cockroach.sh         # CockroachDB compatibility
./scripts/test-fuzz.sh              # generated SQL and policy combinations
./scripts/test-plan-state-fuzz.sh   # protocol-state fuzzing; requires nightly
./scripts/test-inference.sh         # measures known inference routes
```

Performance methodology and current results are in [Benchmarks](docs/benchmarks.md).

## Documentation

Start with the [documentation index](docs/README.md).

- [Security model](docs/security.md)
- [Operations](docs/operations.md)
- [JSON and JSONB masking](docs/json-masking.md)
- [Policy ownership and catalog workflow](docs/responsibilities.md)
- [GUI clients](docs/gui-clients.md)
- [PostgreSQL and CockroachDB](docs/engines.md)
- [Detailed safety assessment](docs/safety-assessment.md): the chronological
  record of ten disclosures and remaining verification gaps.
- [Changelog](CHANGELOG.md)

Historical phase reports and design records are listed separately in the
documentation index.

## Get help

Open a GitHub issue with the pgmask version, database engine and version,
relevant configuration with secrets removed, the rejected SQL shape, and the
full pgmask error.

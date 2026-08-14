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

Current version: **v0.1.92**. Licensed under the [MIT License](LICENSE).

## What pgmask provides

- Column policies resolved from PostgreSQL table OIDs and column numbers.
- Default-deny handling for columns missing from the catalog.
- Deterministic pseudonyms, redaction, partial masks, date truncation, numeric
  buckets, IP prefixes, and type-correct `NULL` values.
- Per-principal policies based on the username PostgreSQL authenticated.
- Read-only SQL enforcement and fail-closed handling of unsupported query
  shapes and protocol messages.
- Optional lineage for expressions and optional metadata access for GUI clients.
- Structured logs, Prometheus metrics, catalog refresh, and a catalog drift
  check for CI.

pgmask is tested against PostgreSQL 13–17 and CockroachDB 25.4. See the
[engine notes](docs/engines.md) for compatibility details.

## Quick start

Requirements: Rust, Podman, and `psql`.

Run the complete demo:

```bash
./examples/demo/verify.sh
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
unclassified_mask = "null"
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

[[column]]
relation = "app.customers"
column = "email"
type = "email"

[[column]]
relation = "app.customers"
column = "id"
mask = "none"
```

Unknown configuration keys, invalid mask parameters, duplicate column rules,
and unresolved configured columns are startup errors.

### Policy controls

| Setting | Default | Behavior |
|---|---|---|
| `unclassified` | `mask` | Mask columns missing from the catalog. `allow` is an incremental-rollout escape hatch. |
| `opaque` | `reject` | Reject computed or otherwise unclassified result fields. `mask` replaces them with `NULL`. |
| `lineage` | `refuse` | When enabled, release an expression only if all resolved source columns are explicitly released. |
| `summaries` | `allow` | Allow supported reducing aggregates, while applying the source column's policy when required. |
| `posture` | `default` | `hostile` refuses masked-column use outside a bare projection and forces summaries off. |
| `system_catalogs` | `refuse` | `allow` enables approved metadata queries needed by GUI clients and `psql` `\d`. |

`lineage = "allow"` improves compatibility but is less conservative: an
incomplete lineage result could release data. It is off by default.

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

`scrub` reveals all text it does not recognize. It does not reliably identify
names, street addresses, or obfuscated identifiers. Use it only when readable
free text is required and partial disclosure is acceptable.

Pseudonyms preserve equality. This keeps joins useful, but also exposes
frequency and repeated identity. Semantic types act as pseudonym domains:
columns in the same domain remain linkable; columns in different domains do
not.

## Query behavior

- Plain classified columns use their catalog policy.
- Unclassified columns use `unclassified_mask`, which defaults to `NULL`.
- Safe scalar values such as literals, `now()`, and `count(*)` pass through.
- Expressions over masked columns, value-returning aggregates such as `max`,
  set operations, recursive common table expressions, and set-returning
  functions are rejected unless a conservative rule proves them safe.
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

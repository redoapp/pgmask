# Operations

This guide covers schema changes, policy deployment, restarts, and monitoring.
Read the [security model](security.md) before production deployment.

## Deployment checklist

- Block direct user access to PostgreSQL.
- Use a `SELECT`-only database role or a read replica.
- Require client TLS and protect the backend hop.
- Keep `unclassified = "mask"`.
- Run `classify --check` against the migrated schema.
- Alert on coverage warnings and rejection metrics.

## Schema and policy order

Schema and policy changes can deploy in either order under default-deny:

| Order | Temporary behavior |
|---|---|
| Schema first | New columns use the type-aware default-deny policy. |
| Policy first | New rules remain unresolved until the columns exist. |

Both orders reduce utility rather than expose an unclassified value. This does
not make an incorrect `mask = "none"` safe.

Common schema changes behave as follows:

| Change | Runtime behavior | `classify --check` |
|---|---|---|
| Add a column | Type-aware fallback until classified | Reports a missing rule |
| Rename a column | New name uses type-aware fallback; old rule is unresolved | Reports both |
| Drop a column | Rule becomes unresolved | Reports a stale rule |
| Recreate a relation | OIDs refresh; unknown OIDs use default policy | No policy change required |
| Change a column type | Incompatible masks reject the result set | Reports the mismatch |

## CI check

Run the drift check after migrations against a schema-equivalent database:

```bash
DSN=postgres://... classify --check \
  --catalog catalog.toml \
  --schema public
```

The command exits nonzero when:

- A database column has no catalog rule.
- A catalog rule matches no column.
- A mask does not support the current column type.
- The selected schema has no columns.

To inspect new columns, generate a draft and review the diff:

```bash
DSN=postgres://... classify \
  --schema public \
  --sample 200 > catalog-draft.toml
```

The classifier is a starting point, not an approval step. See
[policy ownership](responsibilities.md).

## Catalog refresh and reload

pgmask resolves relation and column names to PostgreSQL OIDs at startup. It
re-resolves them every `catalog_refresh_seconds` and may refresh sooner after an
unknown OID, limited by `catalog_refresh_min_seconds`.

If a refresh fails, pgmask keeps the previous snapshot. If a rule stops
resolving, pgmask logs a coverage warning and applies the unclassified policy.

The policy file is not reloaded. Restart pgmask after changing it.

## JSON columns

Classify stored `json` / `jsonb` columns with `mask = "json"` and JSON Pointer
rules. Array policies use `/items/*/field` rather than one rule per index.
Set `json_unmatched` to `null` (default), `type-placeholders`, or `none`.
`json_max_bytes` (1 MiB) and `json_max_depth` (64) refuse oversized documents
before parsing; tune them per column for expected payloads.
Literal extracts (`payload->>'email'`, `payload->'profile'`,
`payload['profile']['email']`) are masked with the same pointer policy when
the path is a literal and the relation is schema-qualified. `jsonb_pretty(payload)`
and JSONPath stay refused as opaque expressions. Views need their own JSON
rules. See [JSON and JSONB masking](json-masking.md).

## Rolling restart

`SIGTERM` stops new connections and closes existing sessions without draining.
Run multiple instances behind a TCP load balancer if sessions must survive a
rolling deployment.

Use a health check that opens a PostgreSQL connection through pgmask. A process
check alone does not verify backend connectivity or catalog loading.

## Logs

pgmask writes structured logs to stderr. `PGMASK_LOG` controls filtering and
falls back to `RUST_LOG`; the default is `info`.

Each connection has a span containing the peer and session outcome. Do not log
catalog secrets or query values around pgmask. pgmask's own tests assert that
masked values and the pseudonym key do not appear in its logs or metrics.

Alert on:

- `coverage lost` warnings.
- Repeated catalog refresh failures.
- Plaintext client sessions when TLS is expected.
- Spikes in rejected result sets or mask type mismatches.
- Rate-limit and notice-flood events.

## Metrics

Set `metrics_listen` to expose Prometheus text at `/metrics`. No metrics port is
opened by default.

Useful metrics include:

- `pgmask_rejections_total{cause="..."}`
- `pgmask_values_masked_total`
- `pgmask_fields_masked_total`
- `pgmask_fields_rescued_total`
- `pgmask_sessions_total`

Interpret a zero masking rate with traffic as a policy or routing warning. A
zero rate without traffic is normal.

## Release verification

Run the full repository gate before release:

```bash
./scripts/test-all.sh
```

A skipped suite fails the gate. Focused real-database and engine checks are
listed in the [README](../README.md#test-and-benchmark).

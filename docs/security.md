# Security model

Read this before deploying pgmask. The detailed findings and test history are
in the [safety assessment](safety-assessment.md).

## Security property

pgmask is designed to prevent a value governed by a masking rule from appearing
directly in a result field. It binds policy to PostgreSQL result metadata,
masks each data row, and rejects results it cannot classify safely.

This property assumes:

- Users cannot connect around pgmask to the database.
- PostgreSQL authenticates the user.
- The catalog correctly marks every column that may be released with
  `mask = "none"`.
- Unclassified columns keep the default `null` mask.
- pgmask and its configuration are not compromised.

An omitted catalog entry fails closed by default. An incorrect `mask = "none"`
entry does not: pgmask treats it as an explicit release.

## Threat postures

| Posture | Intended client | Behavior |
|---|---|---|
| `default` | A non-adversarial analyst | Masks result fields but permits filters, ordering, and supported summaries. These can reveal information by inference. |
| `hostile` | A client that may probe masked data | Refuses masked or unclassified column use outside a bare projection and disables summaries. This closes the measured direct-value inference routes, but is not a general information-flow proof. |

Use rate limits with hostile posture to make repeated probes more expensive:

```toml
posture = "hostile"
rate_limit_per_minute = 60
rate_limit_burst = 10
max_notices_per_exchange = 32
```

Ordering a masked column remains allowed, so relative order can still leak.
Deterministic masks also reveal equality and frequency.

## Required deployment controls

1. Restrict the database port to pgmask. A user who can reach PostgreSQL
   directly can bypass all masking.
2. Give pgmask a `SELECT`-only database role or connect it to a read replica.
   pgmask rejects writes, but database permissions are the stronger control.
3. Require TLS from clients. Setting `tls_cert` and `tls_key` requires TLS by
   default; set `require_client_tls = false` only for a deliberate plaintext
   deployment.
4. Protect the backend hop. pgmask receives unmasked rows from PostgreSQL.
5. Use real PostgreSQL authentication. `trust` authentication makes a claimed
   username appear authenticated and defeats per-principal restrictions.
6. Run `classify --check` against a migrated, schema-equivalent database before
   deployment.
7. Alert on catalog coverage warnings and rejection spikes.

## Transport and authentication

`backend_tls` has three modes:

| Mode | Encryption | Server authentication |
|---|---|---|
| `disable` | No | No |
| `require` | Yes | No |
| `verify-full` | Yes | Yes |

Prefer `verify-full` when the authentication path supports it. Use `backend_ca`
for a private certificate authority.

There is one important constraint: SCRAM channel binding cannot cross a proxy
that terminates client TLS and starts a separate backend TLS connection. The
client binds to pgmask's certificate, while PostgreSQL verifies its own.

For SCRAM authentication with client TLS, use `backend_tls = "disable"` and
place pgmask beside PostgreSQL on a protected network or local socket. Otherwise
use an authentication method that does not require channel binding. pgmask
detects the unsupported both-TLS SCRAM case and rejects it with an explanation.

pgmask derives masking roles from the startup username after PostgreSQL sends
`AuthenticationOk`. `SET ROLE` and `SET SESSION AUTHORIZATION` do not change
masking policy during the session.

## Catalog safety

- Keep `unclassified = "mask"` and `unclassified_mask = "null"`.
- Review `mask = "none"` like an access-control grant.
- Use semantic types to keep repeated policy consistent.
- Give unrelated identifiers different pseudonym domains.
- Restart pgmask after changing the catalog file.
- Treat catalog refresh warnings as policy drift, even when default-deny still
  hides the affected values.

`classify` proposes policy; it does not decide whether data is safe. Sampling
never prints values, but the output still requires human review.

## Query and protocol limits

- Some unsafe result shapes are rejected only after PostgreSQL executes the
  query. The result does not reach the client, but the database work occurred.
- SQL writes, row locks, `COPY`, procedural statements, SQL cursors, and SQL
  prepared-statement commands are rejected. Use database privileges as the
  primary write control.
- Multi-statement simple-query messages fail closed. Send one statement per
  message or use the extended protocol.
- Set operations, recursive common table expressions, set-returning functions,
  and expressions over masked columns are normally opaque.
- `lineage = "allow"` may release an expression when every resolved source is
  explicitly released. It is off by default because incomplete lineage is a
  release risk.
- `system_catalogs = "allow"` releases approved metadata needed by GUI clients.
  Known catalogs containing sampled values or SQL text remain blocked.
- Views need their own rules. pgmask also marks views containing set operations
  as opaque.

## Mask limits

- `scrub` reveals text it does not recognize. It misses names, street addresses,
  and many obfuscated identifiers.
- Pseudonyms are deterministic. They preserve equality, joins, and frequency.
- Partial masks intentionally reveal part of a value.
- Numeric buckets can return an exact value when the source lies on a bucket
  boundary.
- Counts and supported summaries still reveal aggregate information in default
  posture.

## Out of scope

pgmask does not provide:

- Database authentication or authorization.
- Network isolation.
- Protection after the proxy or database host is compromised.
- Differential privacy, minimum group sizes, or protection from differencing.
- A proof that arbitrary sequences of allowed queries reveal no information.
- Automatic approval of the policy catalog.

Use PostgreSQL privileges, network controls, query governance, and auditing for
those requirements.

## Evidence

The release gate includes unit, property, adversarial, real-database,
cross-engine, generated-SQL, and protocol-state tests. Poison controls verify
that the leak detectors can fail.

Run the complete gate with:

```bash
./scripts/test-all.sh
```

Tests reduce risk; they are not a security proof. The chronological
[safety assessment](safety-assessment.md) records previous disclosures, test
gaps, and unverified areas.

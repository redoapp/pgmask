# Security Policy

pgmask is a fail-closed masking proxy. A vulnerability is anything that lets a
value the catalog marks as masked appear in a result field, or that lets a
client pick a different principal's policy than PostgreSQL authenticated.

## Reporting a vulnerability

**Do not open a public GitHub issue** for a suspected disclosure.

Report through GitHub's private advisory form:

https://github.com/redoapp/pgmask/security/advisories/new

Include:

- pgmask version (`pgmask --version`) and PostgreSQL version
- A catalog snippet and the SQL (or protocol sequence) that produces the leak
- What crossed the client boundary (the raw bytes, not a driver decode)

We will acknowledge receipt and work with you on a fix and a coordinated
changelog entry. The [safety assessment](docs/safety-assessment.md) is the public
record of past disclosures.

## What is in scope

- A classified or default-deny column appearing in a DataRow, ErrorResponse,
  NoticeResponse, or other forwarded backend message
- A plan built under one policy surviving a reload or catalog refresh that
  tightened it
- Authentication or role confusion (a claimed username beating a verified one)
- A configured TLS or `require_client_tls` setting that a client can decline
  without being counted

## What is not a vulnerability

These are documented limits of the security model, not oversights:

- Inference under `posture = "default"` (filters, ordering, group-of-one
  summaries). Use `posture = "hostile"` for an adversarial client.
- An incorrect `mask = "none"` in the catalog. That is an explicit release.
- Direct connections to PostgreSQL that bypass pgmask. Deployment must block
  that path.
- Metrics or logs that an operator chooses to expose on a non-loopback
  address.

See the [security model](docs/security.md) before production deployment.

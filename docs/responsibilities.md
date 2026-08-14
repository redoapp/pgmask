# Policy ownership

pgmask enforces a masking policy. It does not decide which data is sensitive.

## Operator responsibilities

The operator owns:

- The catalog and every `mask = "none"` decision.
- Membership in pgmask roles.
- Catalog review after schema changes.
- The `classify --check` gate in CI.
- Database authentication and authorization.
- Network isolation that prevents direct database access.
- TLS, secrets, monitoring, and incident response.

An omitted column is hidden by default. A sensitive column marked `none` is
released because pgmask treats that rule as an explicit decision.

## pgmask responsibilities

pgmask owns:

- PostgreSQL wire framing and result-set policy binding.
- Type-correct masking and deterministic pseudonyms.
- Default-deny behavior for unclassified columns.
- Fail-closed handling of unsupported result and protocol shapes.
- Catalog name-to-OID refresh.
- Rejection, coverage, and transport diagnostics.

The current property and its limits are defined in the
[security model](security.md).

## Build a catalog

A useful default-deny catalog names every column that users need to see,
including ordinary columns released with `mask = "none"`.

Generate a draft:

```bash
DSN=postgres://... cargo run --release -p classify -- \
  --schema public \
  --sample 200 > catalog-draft.toml
```

The classifier groups columns into four review states:

| State | Meaning |
|---|---|
| Confirmed | The name and sampled values support the proposal. |
| Likely | The name strongly supports the proposal. |
| Needs a human | The schema or sample is suspicious but ambiguous. |
| Ordinary | No rule found evidence of sensitivity. This is not proof that the column is safe. |

Sampling checks values in memory and does not print them. It can recognize only
a limited set of structured values. Business meaning still requires a human.

Review the draft by asking:

1. Should the column be visible at all?
2. What is the least revealing useful mask?
3. Must equality or joins survive masking?
4. Which authenticated principals need a different mask?
5. Does free text require `scrub`, and is its incomplete detection acceptable?

Use semantic types for repeated data classes. Give unrelated identifiers
different pseudonym domains so equal source values cannot be linked across
domains.

## Keep the catalog current

Run this after migrations in CI:

```bash
DSN=postgres://... classify --check \
  --catalog catalog.toml \
  --schema public
```

The check fails for missing rules, stale rules, an empty schema, and masks that
do not support the current database type.

The review loop is:

1. Apply migrations to a schema-equivalent database.
2. Run `classify --check`.
3. Generate a draft for new or changed columns.
4. Review and update the catalog.
5. Run the check again.
6. Deploy the catalog and restart pgmask.

At runtime, unresolved rules produce warnings and fall back to the unclassified
policy. See the [operations guide](operations.md).

## Role behavior

`[[role]]` maps PostgreSQL startup usernames to pgmask policy names. The mapping
is resolved after PostgreSQL authentication and remains fixed for the session.
Database commands such as `SET ROLE` do not change it.

When several pgmask roles match one principal, the most restrictive mask wins.
Adding a role cannot widen access through an overlap.

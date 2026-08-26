# JSON and JSONB masking

This is the operator and analyst guide for `mask = "json"` on stored `json` and
`jsonb` columns. The [README](../README.md) shows a short configuration
example. Policy still binds to PostgreSQL `RowDescription` provenance (table
OID + column number), never to SQL text.

## What it does

pgmask walks the stored document, keeps every object key and array length, and
applies ordinary masks at RFC 6901 JSON Pointers. A pointer's policy is
inherited by its whole subtree until a more-specific pointer overrides it.

Masks apply only to a stored classified column that still has provenance in
the result. `SELECT payload FROM app.events` is the intended path. JSON that
Postgres constructs or extracts (`payload->>'email'`, `json_agg(payload)`,
`to_jsonb(t)`) is opaque: pgmask refuses it under the default `opaque =
"reject"` policy. That is the same rule as `lower(email)`, not a JSON-only
restriction.

## Configuration

```toml
[[column]]
relation = "app.events"
column = "payload"
mask = "json"
# Optional. Keep unmatched scalar types visible without their values.
json_type_placeholders = true
json = [
  { pointer = "/profile", mask = "none" },
  { pointer = "/profile/email", mask = "partial", keep = 4 },
  { pointer = "/profile/name", mask = "redact" },
  { pointer = "/items/*/account_id", mask = "pseudonym", domain = "account" },
]
```

Views need their own entries. PostgreSQL reports the view OID, not the base
table. A `NOT NULL` identifier column on the same relation should be catalogued
explicitly (`mask = "none"` when it is a public key). Leaving it unclassified
can refuse `SELECT *` because the type-aware fallback would otherwise invent a
SQL NULL for a `NOT NULL` column.

`classify` does not invent pointer policies. A JSON column that looks ordinary
is still default-denied as a whole cell until a human writes a `json` rule.

## Pointers

Pointers start with `/`. Empty root `""` is refused. `~0` and `~1` decode to
`~` and `/` as in RFC 6901.

pgmask extends matching with one extra segment: `*` matches every element of
an **array**. In an object, `*` is the literal key `"*"`, so a document that
happens to contain that key remains addressable.

| Pointer | Matches |
|---|---|
| `/profile/email` | That object field only |
| `/items/0/account_id` | Index 0 only |
| `/items/*/account_id` | `account_id` on every array element |
| `/items/*/token` plus `/items/0/token` | Wildcard for every element; exact index 0 wins |
| `/*` | The object key `"*"`, not every field |

There is no `**`, no object-key wildcard, and no slice (`0:10`). Duplicate
pointers and equally-specific overlapping wildcards (`/items/*/id` together
with `/items/0/*`) are startup errors: config order must not decide a
disclosure.

## Unmatched leaves

When no pointer and no inherited parent policy apply:

| Setting | Unmatched string | number | boolean | JSON null |
|---|---|---|---|---|
| default (omit both options) | `null` | `null` | `null` | `null` |
| `json_type_placeholders = true` | `""` | `0` | `false` | `null` |
| `json_default = "null"` | `null` | `null` | `null` | `null` |
| `json_default = "none"` | original value | original | original | `null` |

`json_type_placeholders` and `json_default` are mutually exclusive. Use
placeholders when analysts need to see *shape* (is this field a number? was it
present?) without seeing the value. Use `json_default = "none"` only when
unmentioned values are intentionally public; that includes keys added after
the catalog was written.

Objects and arrays are never replaced as a whole. They are always walked, and
the leaf rule above applies to each scalar.

## How to inspect a large document

SQL extraction is refused, so drill in after the result leaves pgmask.

```sql
-- Served, masked. Use this.
SELECT payload
FROM app.events
WHERE payload @> '{"kind":"checkout"}';

-- Also served when provenance survives: aliases, joins, CTEs, subqueries,
-- views with their own rules, and a same-type no-op `payload::jsonb`.
```

Then inspect the masked JSON in the client (`jq`, the driver, a GUI). Typical
refusals:

```sql
SELECT payload->>'email' FROM app.events;
SELECT payload #>> '{profile,email}' FROM app.events;
SELECT jsonb_path_query(payload, '$.items[*].account_id') FROM app.events;
SELECT jsonb_pretty(payload) FROM app.events;
SELECT jsonb_each(payload) FROM app.events;
SELECT json_agg(payload) FROM app.events;
SELECT payload::text FROM app.events;
SELECT payload FROM app.events UNION ALL SELECT payload FROM app.events;
```

`WHERE` predicates still run on the backend. Containment filters such as `@>`
do not mask the stored document; they only restrict which rows come back. That
is the same accepted predicate-oracle limit as `WHERE email = '…'` on a text
column. Hostile posture refuses masked-column use outside a bare projection.

## Fail-closed cases

pgmask refuses the result set rather than passing a value it cannot honour:

- Malformed JSON text, or binary `jsonb` with a version byte other than `1`.
- A leaf mask that cannot apply to the JSON type (`partial` on a number,
  `numeric-bucket` on a string).
- `mask = "json"` on a non-json column (plan-time type mismatch).
- Recursive `json` as `json_default` or as a nested pointer mask.

Binary pgwire is supported. PostgreSQL `json` binary is UTF-8 JSON text.
`jsonb` binary is version byte `1` plus JSON text. Key order and whitespace may
change because the document is re-serialized.

## Operator review

Treat `{ pointer = "/profile", mask = "none" }` as a grant of every current and
future leaf under `/profile`, unless a narrower pointer overrides it. Review it
the same way as a column-level `mask = "none"`.

`json_type_placeholders` discloses JSON types and the presence of keys. That
is usually what a debugger needs; it is still a disclosure relative to
defaulting every unmatched leaf to `null`.

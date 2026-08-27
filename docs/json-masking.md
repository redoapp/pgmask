# JSON and JSONB masking

This is the operator and analyst guide for `mask = "json"` on stored `json` and
`jsonb` columns. The [README](../README.md) shows a short configuration
example. Policy still binds stored columns to the `RowDescription` (table OID +
column number). Literal JSON extracts are attributed from an allowlist of SQL
shapes the same way reducing aggregates are: the statement names a path, it
does not release on its own.

## What it does

pgmask walks the stored document, keeps every object key and array length, and
applies ordinary masks at RFC 6901 JSON Pointers. A pointer's policy is
inherited by its whole subtree until a more-specific pointer overrides it.

Masks apply only to a stored classified column that still has provenance in
the result, and to **literal JSON extracts** of that column. `SELECT payload
FROM app.events` is the stored-column path. `SELECT payload->>'email'`,
`payload->'profile'`, and `payload['profile']['email']` are attributed from
the statement: the extract path must be literals, the relation must be
schema-qualified, and the pointer policy of the stored column is applied to
the result. JSON that Postgres constructs
(`json_agg(payload)`, `to_jsonb(t)`, `jsonb_path_query`) stays opaque.

## Configuration

```toml
[[column]]
relation = "app.events"
column = "payload"
mask = "json"
# Optional. Keep unmatched scalar types visible without their values.
json_unmatched = "type-placeholders"
# Optional resource bounds; these are the defaults.
json_max_bytes = 1048576
json_max_depth = 64
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

Array wildcards require runtime array evidence. A document walk has the actual
parent value, and `payload->0` uses PostgreSQL's integer array operator. Text
paths (`#>` / `#>>` and `json[b]_extract_path[_text]`) do not distinguish array
index `0` from object key `"0"`. If such a segment could enter a `*` pointer
branch, pgmask refuses the extract rather than guess. Use an integer `-> 0`
or `[0]` step when traversing a configured array wildcard.

## Unmatched leaves

When no pointer and no inherited parent policy apply, `json_unmatched`
chooses one behavior:

| Setting | Unmatched string | number | boolean | JSON null |
|---|---|---|---|---|
| default / `json_unmatched = "null"` | `null` | `null` | `null` | `null` |
| `json_unmatched = "type-placeholders"` | `""` | `0` | `false` | `null` |
| `json_unmatched = "none"` | original value | original | original | `null` |

Use placeholders when analysts need to see *shape* (is this field a number?
was it present?) without seeing the value. Use `json_unmatched = "none"` only
when unmentioned values are intentionally public; that includes keys added
after the catalog was written.

Objects and arrays are never replaced as a whole. They are always walked, and
the leaf rule above applies to each scalar.

## Resource limits

`json_max_bytes` defaults to 1,048,576 bytes and counts the encoded JSON
payload (not the binary-jsonb version byte). `json_max_depth` defaults to 64
and counts nested objects and arrays, with the root container at depth 1.
Values over either limit refuse the result set.

Both checks run before `serde_json` constructs a value tree. The depth
preflight understands quoted strings and escapes, so braces inside strings do
not count as nesting. `json_max_depth` must be between 1 and 128; the byte
limit must be at least 1.

Pointer rules are compiled into a trie when the catalog loads. Walking a node
follows only its exact-key and array-wildcard edges instead of scanning every
configured rule.

## How to inspect a large document

Literal extracts are served when the path can be mapped to a pointer:

```sql
-- Served, masked with the pointer policy.
SELECT payload->>'public' FROM app.events;
SELECT payload->'profile' FROM app.events;
SELECT payload->'profile'->>'email' FROM app.events;
SELECT payload['profile']['email'] FROM app.events;  -- jsonb, same pointer policy as ->
SELECT payload['items'][0] FROM app.events;          -- integer index, like -> 0
SELECT payload #>> '{profile,email}' FROM app.events;
SELECT jsonb_extract_path_text(payload, 'profile', 'email') FROM app.events;

-- Whole stored columns are also served when RowDescription provenance
-- survives: aliases, joins, CTEs, subqueries, views with their own rules, and
-- a same-type no-op `payload::jsonb`.
SELECT payload
FROM app.events
WHERE payload @> '{"kind":"checkout"}';
```

Literal extracts are attributed from the SQL text, so their owner must be a
schema-qualified named relation. An extract *inside* a CTE or subquery may be
served when the outer query uses `SELECT *`, preserving the analyzed target
slot. Extracting from a CTE/subquery-owned JSON column, or selecting a named
extract alias through that outer range, is refused rather than guessing its
base relation.

A text extract (`->>`, `#>>`, `*_extract_path_text`) of a node that still has
**child** pointer policies is refused: PostgreSQL has already serialized the
object, so pgmask cannot apply `/profile/email` to `payload->>'profile'`. Use
`->` so the result stays `json`/`jsonb` and can be walked, or extract the leaf.

Inspect the masked JSON in the client (`jq`, the driver, a GUI) when you need
the whole document. Typical refusals:

```sql
SELECT payload->>'profile' FROM app.events; -- child policies under /profile
SELECT jsonb_path_query(payload, '$.items[*].account_id') FROM app.events;
SELECT jsonb_pretty(payload) FROM app.events;
SELECT jsonb_each(payload) FROM app.events;
SELECT json_agg(payload) FROM app.events;
SELECT payload::text FROM app.events;
SELECT payload FROM app.events UNION ALL SELECT payload FROM app.events;
SELECT payload->>'email' FROM events; -- relation is not schema-qualified
```

`WHERE` predicates still run on the backend. Containment filters such as `@>`
do not mask the stored document; they only restrict which rows come back. That
is the same accepted predicate-oracle limit as `WHERE email = '…'` on a text
column. Hostile posture treats a literal JSON extract as a projection of the
column; a second mention in `WHERE` still refuses.

## Fail-closed cases

pgmask refuses the result set rather than passing a value it cannot honour:

- Malformed JSON text, or binary `jsonb` with a version byte other than `1`.
- A leaf mask that cannot apply to the JSON type (`partial` on a number,
  `numeric-bucket` on a string).
- A `->>` / `#>>` extract of a path that still has child pointer policies.
- `mask = "json"` on a non-json column (plan-time type mismatch).
- Recursive `json` as a nested pointer mask.

Binary pgwire is supported. PostgreSQL `json` binary is UTF-8 JSON text.
`jsonb` binary is version byte `1` plus JSON text. Key order and whitespace may
change because the document is re-serialized.

## Operator review

Treat `{ pointer = "/profile", mask = "none" }` as a grant of every current and
future leaf under `/profile`, unless a narrower pointer overrides it. Review it
the same way as a column-level `mask = "none"`.

`json_unmatched = "type-placeholders"` discloses JSON types and the presence
of keys. That is usually what a debugger needs; it is still a disclosure
relative to defaulting every unmatched leaf to `null`.

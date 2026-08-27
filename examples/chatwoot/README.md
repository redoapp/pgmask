# Chatwoot golden fixture

A reduced [Chatwoot](https://github.com/chatwoot/chatwoot) schema, seed, and
pgmask catalog for running **realistic support-inbox SQL** through the proxy.
JSONB is the point: widget session blobs, custom attributes, automation rules,
and Chatwoot's `json` (not jsonb) `messages.content_attributes`.

This is not a dump of production and not an allowlist expansion. Queries that
Chatwoot generates and that pgmask refuses stay refused. The corpus records
that, so debugging a live Chatwoot-shaped database does not depend on guessing
which shapes were never tried.

See [SOURCES.md](SOURCES.md) for upstream files.

## Run

```bash
./examples/chatwoot/verify.sh
```

Needs `psql`, a Postgres the same way [scripts/test-integration.sh](../../scripts/test-integration.sh)
finds one, and a `pgmask` binary (the script `cargo build`s it).

## What the catalog is trying to do

A support engineer still has to answer "which inbox is failing?", "what
content type is affected?", "which automation shape ran?", and "which city is
this contact in?" without reading emails, phones, names, transcripts, external
ids, SSNs, Stripe ids, device fingerprints, or checkout referer tokens.

| Surface | Policy |
|---|---|
| `contacts.email` / `phone_number` / `name` | semantic types (pseudonym / pseudonym / redact) |
| Contact/channel/conversation/message/order ids | domain-separated pseudonyms |
| Widget public keys (`company_name`, `city`, browser family/version, …) | `mask = "json"` pointer `none` |
| Widget device name | redact |
| `created_at_ip` | `ip-prefix` |
| `referer`, `mail_subject`, email subject, SSN, Stripe ids | redact |
| Evolving custom keys | `json_unmatched = "type-placeholders"` |
| Message/automation/free-text fields | redact (regex scrubbing cannot reliably find names) |
| `contact_directory` view | **own** `[[column]]` rows — Postgres reports the view OID |

`NOT NULL` keys are `mask = "none"` so `SELECT *` is a real JSON-masking path
rather than a type-aware-fallback refusal.

## Corpus

[queries.sql](queries.sql) is the pin. Each case declares `@expect: served`,
`refused`, or `error`. [probe.py](probe.py) first proves **36 forbidden source
values** are observable directly, then scans every proxied result for them.
`verify.sh` also starts a deliberately releasing second proxy: the poison
control must expose the email or the leak detector is not trusted.
Refusal-shaped attacks carry `@direct_expect` controls: the same SQL must be
valid and often expose its poison directly before a pgmask refusal counts.
Every served SELECT must emit an observable row (`[NULL]` is explicit), and
the source scan is case-insensitive.

The main policy uses `posture = "hostile"`. Email equality/grouping and masked
JSON predicates refuse. This is stronger than result-byte masking, but it is
not a general information-flow proof: simple `ORDER BY` on a masked column is
allowed and exposes relative order, and deterministic pseudonyms expose
equality/frequency. `DISTINCT` over a redacted column still exposes how many
distinct source classes exist (the returned values are all `***`). Production
still needs rate limiting and no route around the proxy; see
[the security model](../../docs/security.md).

Chatwoot's Arel is unqualified (`FROM "contacts"`). Two cases cover that:

1. As written against this fixture → Postgres `undefined_table`, and pgmask
   **withholds** the error text (`SQL can choose it`).
2. With `search_path=chatwoot` → pgmask refuses extract attribution (it does
   not guess `search_path`).
3. Schema-qualified unsorted projection → served, city/company released, PII
   not. The app's `ORDER BY` JSON expression refuses under hostile posture.

That is the debugging loop this dataset is for: take the SQL the app ran,
qualify it, see whether the catalog answers the ops question without a leak.

## What a first run showed

Pinned by `./examples/chatwoot/verify.sh` against pgmask 0.1.99
(145 SQL cases):

| Kind | Count | What happened |
|---|---|---|
| Served | 79 | Queue/delivery/status counts, timeline envelopes, dashboard FILTER counts, message `today`/`chat`, pseudonym correlation, whole masked JSON, `SELECT *`, view OIDs, literal extract spellings, tag-id filtering, and documented order/cardinality disclosures |
| Refused | 64 | Unqualified/app JSON ordering, containment/custom-attribute membership, label-name `EXISTS`, masked JOIN/NATURAL/LATERAL/HAVING/subqueries/windows/grouping, JSON casts/constructors/JSONPath/parent text, dynamic or ambiguous keys, aggregates/fingerprints/recursive CTEs, SRFs, COPY and set operations |
| Error | 2 | Unqualified `FROM "contacts"` and JSON-only bracket subscripting — backend messages withheld |
| Protocol | 6 | Extended binds for released extract, masked scalar/JSON predicates and masked ordering; same-session refusal recovery; mid-session `search_path` |
| Poison control | 1 | A release-policy proxy exposes the source email, proving the detector can see a leak |

The raw-wire integration suite separately sends Chatwoot's reported
double-encoded JSON string scalar in PostgreSQL's **binary OID-114 format**.
Its release control exposes the inner email; the real policy emits exactly the
empty string type-placeholder, including through `SELECT *`.

No forbidden source value appeared through the main proxy. Message bodies and
subjects become `***`; email/phone/order/external ids become deterministic
pseudonyms; IPs become prefixes; unknown JSON leaves retain only type/shape.

The `IS NULL` refusal is the useful debugging lesson: Chatwoot's
`valid_first_reply?` SQL is an expression. Project
`additional_attributes->'campaign_id'` and inspect the JSON `null`; do not wrap
the extract in SQL.

Other runbook lessons found by the live corpus:

- Hostile posture is conservative by **identifier spelling** before result
  OIDs exist. `inboxes.name` grouping and Chatwoot's label-name `EXISTS` query
  refuse because `name` is sensitive on other relations. Group by inbox/tag id
  and resolve the released label/name separately.
- A released JSON pointer is not used to bless hostile predicates. Filtering
  `additional_attributes->>'city'` refuses; Chatwoot's synchronized scalar
  `location` is the safe configured workaround.
- `store ..., coder: JSON` over Chatwoot's native `json`/`jsonb` columns has
  been reported to create string scalars. The fixture reproduces it: whole
  cells reveal only `""`, while `->>` silently returns SQL NULL.
- `conditions[0]['attribute_key']` refuses at the runtime-shape-ambiguous
  subscript; `conditions->0->>'attribute_key'` proves the array step and serves.

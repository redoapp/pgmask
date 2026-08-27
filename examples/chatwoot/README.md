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

A support engineer still has to answer "which city is this contact in?" and
"did this message come from a campaign?" without reading emails, phones, IPs,
SSNs, Stripe ids, or checkout referer tokens.

| Surface | Policy |
|---|---|
| `contacts.email` / `phone_number` / `name` | semantic types (pseudonym / partial / redact) |
| Widget public keys (`company_name`, `city`, `browser`, …) | `mask = "json"` pointer `none` |
| `created_at_ip` | `ip-prefix` |
| `referer`, `mail_subject`, `ssn`, Stripe ids | `redact` |
| Evolving custom keys | `json_unmatched = "type-placeholders"` |
| `messages.content` | `scrub` (identifiers, not names in prose) |
| `contact_directory` view | **own** `[[column]]` rows — Postgres reports the view OID |

`NOT NULL` keys are `mask = "none"` so `SELECT *` is a real JSON-masking path
rather than a type-aware-fallback refusal.

## Corpus

[queries.sql](queries.sql) is the pin. Each case declares `@expect: served`,
`refused`, or `error`. [probe.py](probe.py) also scans every result for canary
tokens (`alice.cw-canary@inbox.test`, `203.0.113.77`, `CANARYSTRIPE`, …).

Chatwoot's Arel is unqualified (`FROM "contacts"`). Two cases cover that:

1. As written against this fixture → Postgres `undefined_table`, and pgmask
   **withholds** the error text (`SQL can choose it`).
2. With `search_path=chatwoot` → pgmask refuses extract attribution (it does
   not guess `search_path`).
3. Schema-qualified rewrite → served, city/company released, PII not.

That is the debugging loop this dataset is for: take the SQL the app ran,
qualify it, see whether the catalog answers the ops question without a leak.

## What a first run showed

Pinned by `./examples/chatwoot/verify.sh` against pgmask 0.1.99 (33 cases):

| Kind | Count | What happened |
|---|---|---|
| Served | 25 | Health checks, schema-qualified `->>'company_name'` / `->>'city'`, JSONB `['city']` / `['country']` (SyncAttributes), IP prefix, referer redact, nested `browser->os`, whole JSON blobs, `SELECT *`, the directory **view**, `GROUP BY` city extract, mixed `->` then `['browser_name']`, `json` `content_attributes` extracts, `additional_attributes->'campaign_id'` |
| Refused | 7 | Unqualified extract even with `search_path`, `jsonb_pretty` / `jsonb_each` / `to_jsonb`, UNION, subquery alias of an extract, `(extract) IS NULL` |
| Error | 1 | Unqualified `FROM "contacts"` with no search_path — backend `undefined_table`, message withheld |

Canaries (`alice.cw-canary@inbox.test`, `203.0.113.77`, `078-05-4391`,
`CANARYSTRIPE`, `CANARYREF`, `CANARYHOOK`, `555-867-5309`) did not appear in
any proxied result. Message body became `Call me at <PHONE>.` under `scrub`.

The `IS NULL` refusal is the useful debugging lesson: Chatwoot's
`valid_first_reply?` SQL is an expression. Project
`additional_attributes->'campaign_id'` and inspect the JSON `null`; do not wrap
the extract in SQL.

# Experiment: pgmask in front of a real Neon branch

pgmask pointed at a non-production branch of a real internal-tools database
(383k CRM companies, 482 users), read-only, under three policy configurations.
The point was to find out what breaks against real schema and real workload
rather than against a demo we wrote ourselves.

Four things broke. All four were pgmask's fault, and all four are now fixed.

## Setup

The connection is read-only twice over: a non-production branch, and a DSN
carrying `options=-c default_transaction_read_only=on` so the **server** refuses
writes rather than trusting the harness to only issue `SELECT`s. Verified:

```
psql "$DSN" -c 'CREATE TABLE x(i int)'
ERROR:  cannot execute CREATE TABLE in a read-only transaction
```

The DSN lives in a file outside the repo and is never rendered into a committed
config — `catalog.template.toml` carries placeholders.

```bash
# one proxy per policy, all against the same backend
#   strict     6441   unclassified=mask  opaque=reject
#   rollout    6442   unclassified=allow opaque=reject
#   permissive 6443   unclassified=allow opaque=mask
python3 examples/neon/corpus.py
```

## What broke, and what it taught us

**1. TLS SNI was hardcoded.** `upgrade_backend` passed the literal `"postgres"`
as the TLS server name. Neon routes connections *by SNI*, so the handshake never
reached the endpoint. Any managed Postgres that multiplexes databases behind one
address has this property.

**2. Catalog resolution could not speak TLS.** `catalog_dsn` connected with
`NoTls`, so the proxy could not start against Neon, RDS with `rds.force_ssl`, or
Cloud SQL — the databases it is most useful in front of.

**3. `channel_binding=require` in the DSN.** Neon puts it in every connection
string it hands out. tokio-postgres honours it and fails with "server did not use
channel binding". pgmask now rewrites it to `disable` and says so, because
channel binding can never be satisfied through something that terminates TLS.

**4. A plaintext client cannot be offered `-PLUS` at all.** This corrected an
earlier conclusion. libpq does not quietly fall back when the server advertises
`SCRAM-SHA-256-PLUS` over a non-SSL connection — it aborts:

> server offered SCRAM-SHA-256-PLUS authentication over a non-SSL connection

So the rule is conditional, not absolute:

| client leg | backend leg | outcome |
|---|---|---|
| plaintext | TLS | server offers `-PLUS`; **must strip it**, then the client sends gs2 `n` and the server accepts |
| TLS | TLS | stripping makes the client send gs2 `y`, which the server correctly reads as a downgrade. No fix |
| TLS | plaintext | server never offers `-PLUS`. Works |

Stripping was implemented, then removed after testing only the both-TLS case,
and is now back — correctly gated on the client leg being plaintext. Testing one
branch of a three-way matrix and generalising was the mistake.

## Results

31 query shapes typical of analytical work against this schema:

| policy | served | refused | other error |
|---|---|---|---|
| strict | 14 | 15 | 2 |
| rollout | 14 | 15 | 2 |
| permissive | 29 | 0 | 2 |

**48% of a realistic corpus is refused** under a fail-closed policy.

`strict` and `rollout` are identical here because every column the corpus touches
is already classified — default-deny costs nothing once the catalog covers the
query surface, which is a genuinely encouraging result for the Phase 1 effort.

### The hypothesis was wrong

We built the rejection counters to answer one question: is Phase 6 worth it, and
which rule first? We assumed set operations dominated. They do not.

```
rejections=15  opaque_function=7  opaque_aggregate=5
               opaque_anonymous=2  opaque_named_like_column=1
               set_op_like_share=7%
```

- **Expressions 47%** — `lower()`, `||`, `coalesce()`, `date_trunc()`, `to_json()`
- **Aggregates 33%** — `count(*)`, `avg()`, `string_agg()`, and `GROUP BY x, count(*)`
- **Literals 13%** — `SELECT 1`, `now()`
- **Set operations 7%** — one `EXCEPT`

Had we built the two-rule Phase 6 from the handoff — zero-column expressions plus
set operations — we would have addressed **20%** of real rejections and left the
other 80% untouched.

### `opaque = "mask"` does not rescue this

Permissive refuses nothing, but that number is misleading:

```
SELECT count(*) FROM crm.companies                     -> (empty)
SELECT 1                                               -> (empty)
SELECT lifecycle_stage, count(*) ... GROUP BY 1        -> customer|
```

The aggregate is nulled. The query is served and useless. Nulling an opaque
field converts a loud failure into a silent empty result, which for an analytical
workload is worse than the refusal.

### Revised Phase 6 priority

By measured frequency, not by guess:

1. **Value-suppressing aggregates.** `count(*)`, `count(col)`, `avg`, `sum` emit
   no source value and can be allowed; `string_agg`, `array_agg`, `json_agg` dump
   every value and must not be. Provenance cannot tell them apart, but a parse
   tree distinguishes them by function name alone — cheap, and it unblocks
   `GROUP BY x, count(*)`, the single most common analytical shape there is.
2. **Zero-column expressions.** No `ColumnRef` anywhere in the target entry means
   it cannot leak a column. Fixes `SELECT 1` health checks.
3. **Per-field opaque handling** where the opaque field's inputs are provably
   non-sensitive, rather than refusing the whole result set.
4. **Set operations.** Last, on this evidence.

One case worth noticing: `date_trunc('month', created_at)` is refused, while
pgmask's own `date-month` mask does exactly that transformation. A caller
coarsening data *for* us still gets refused, because provenance cannot see intent.

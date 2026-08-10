# Postgres Masking Proxy — Build Handoff

**Status:** built. This is the original plan, kept because several of its
predictions turned out to be wrong and the corrections are the useful part.
**Shape:** Rust, 1:1 pgwire interceptor, fail-closed column masking
**Estimated:** ~9–10 weeks of proxy work, plus a classification track that never ends

## How to read this

The plan is preserved as written. Where reality disagreed, the correction is
inline and dated. For current state start at [`../README.md`](../README.md); the
four places this document was wrong:

| § | Predicted | Actual |
|---|---|---|
| 4 — Phase 0 | provenance might collapse through CTEs/subqueries | survives far further; **GO**. 22/37 shapes full provenance |
| 4 — Phase 6 | set operations dominate rejections | **7%**. Expressions 47%, aggregates 33% ([Neon run](../examples/neon/README.md)) |
| 6 — catalog | OID staleness noted as required behaviour | shipped only after it was demonstrated silently nulling a recreated view |
| 9 / [phase4](phase4.md) | channel binding unfixable through a terminating proxy | true only when *both* legs are TLS; a plaintext client leg both can and must strip `-PLUS` |

The estimate held up better than the predictions: the proxy took roughly the
predicted effort, and the parts that ran long were the ones called out as
open-ended.

---

## 1. What we are building

A transparent Postgres proxy. Clients point their connection string at it instead of at
the database. It inspects result sets in flight and replaces sensitive column values with
masked ones, according to a policy catalog, before the bytes reach the client.

**Explicit non-goals.** Write these down now so nobody re-litigates them in month two:

- **Not a pooler or a sharder.** One client connection maps to exactly one backend
  connection. If pooling is needed, pgbouncer goes *behind* us.
- **Not anonymization.** This is dynamic data masking. It does not provide a privacy
  guarantee. See §11.
- **Not a SQL review or approval workflow.** No ticket queues, no human-in-the-loop.
- **Not a lineage engine.** Phase 6 only, and only if measurements demand it.

---

## 2. The core mechanism

Postgres's `RowDescription` message carries, for every field in a result set, the **table
OID** and **column attribute number** it came from — and `0` for both when the field is
not a plain reference to a stored column.

That gives us engine-authoritative provenance for free: field 3 *is* `contacts.email`;
field 4 is some computed expression whose inputs we cannot see. We mask what we can
identify and **refuse what we cannot**.

### The single most important design rule

> **Bind the masking plan to the `RowDescription`, never to the statement that caused it.**

Plans are constructed when a `RowDescription` arrives and applied to the `DataRow`s that
follow it. Never cached against a query string, prepared statement, or request.

This one rule collapses most of the bypass surface. Every row-producing path in the
protocol — multi-statement simple queries, cursors and `FETCH`, functions and `DO` blocks
returning rows, re-`Bind` of an old prepared statement, suspended and resumed portals —
emits a `RowDescription` first, and is therefore covered automatically without special
handling.

Exactly two paths produce data rows *without* one:

1. `COPY ... TO STDOUT` (`CopyOutResponse` / `CopyData`)
2. The legacy `FunctionCall` protocol message

Both are **blocked outright**. That is the entire bypass surface, and it is small enough
to close on day one.

Corollary, and it must be enforced in code: **a `DataRow` arriving with no active plan is
a bug or an attack.** Never pass it through. *(Shipped as: suppress the result
set and return an error, which is equally fail-closed on data and leaves the
session usable. `COPY` still closes the connection, being unrecoverable
mid-stream.)*

---

## 3. Architecture

```
  clients (psql, pgx, JDBC, BI, apps)
        │  connection string points here
        ▼
  ┌──────────────────────────────┐
  │  masking proxy  (Rust)       │
  │   • 1:1, no multiplexing     │
  │   • auth passthrough         │
  │   • RowDescription → plan    │
  │   • DataRow rewrite          │
  └──────────────────────────────┘
        │
        ▼   (optional)
     pgbouncer
        │
        ▼
     Postgres
```

**Crates:**

| Purpose | Crate |
|---|---|
| Frontend protocol (we are the server) | `pgwire` |
| Backend leg (we are the client) | `tokio-postgres` |
| Wire type codecs, text + binary | `postgres-types`, `postgres-protocol` |
| SQL parsing — Phase 6 only | `pg_query.rs` (libpg_query, Postgres's real grammar) |

Do not use `sqlparser-rs`. For a security boundary, use the actual Postgres grammar.

Do not fork pgdog or pgcat. Their complexity is pooling and sharding, which we have
deliberately excluded; we would inherit a permanent merge burden for machinery we do not
want.

### Authentication

**Pass SCRAM straight through.** We do not terminate auth and we hold no credentials.

1. Read `user` and `database` from `StartupMessage`. Treat the username as *claimed*.
2. Forward the entire auth exchange opaquely in both directions.
3. On `AuthenticationOk` from the backend, the username becomes **verified** — Postgres
   just vouched for it. Only now may it be used for policy lookup.

Postgres keeps doing authn and its own grants stay intact as defense in depth. mTLS/client
certs are the better path for service accounts and can be added later.

---

## 4. Phase 0 — the provenance spike (1 week, GO/NO-GO)

**Nothing else starts until this is done.** The entire design rests on how far
`RowDescription` provenance survives, and that is an empirical question.

Build a throwaway harness that runs each shape below against a representative database and
records, per output field: `table_oid`, `attnum`, `type_oid`, format code.

Shapes to test:

- `SELECT col FROM t` — the baseline
- `SELECT * FROM t`
- `SELECT t.col FROM t JOIN u ON ...` — both sides
- `SELECT col FROM t WHERE ...` with and without an index-only plan
- Simple subquery: `SELECT col FROM (SELECT col FROM t) q`
- Non-flattenable subquery (add `OFFSET 0` or a volatile function to defeat pullup)
- `WITH cte AS (SELECT col FROM t) SELECT col FROM cte`
- `WITH RECURSIVE ...`
- `UNION`, `UNION ALL`, `INTERSECT`, `EXCEPT`
- `SELECT * FROM a_view` — **does it report the view OID or the base table OID?**
- Nested views
- `LEFT JOIN LATERAL`
- Window function over a sensitive column
- `GROUP BY col` returning the grouped column
- Aggregates: `count(*)`, `count(col)`, `sum(col)`, `string_agg(col, ',')`
- `SELECT col::text`, `SELECT lower(col)`, `SELECT col || ''`
- `SELECT COALESCE(col, '')`
- `CASE WHEN ... THEN col ELSE NULL END`
- Set-returning function in the target list
- `SELECT * FROM some_plpgsql_function()`
- `DECLARE c CURSOR FOR SELECT col FROM t; FETCH ALL FROM c`
- Materialized view
- Partitioned table (parent vs child OID?)
- Temp table
- Extended protocol `Describe` on a prepared statement — same answers as execution?

**Decision rules:**

| Outcome | Consequence |
|---|---|
| Provenance survives simple refs, joins, views, cursors | **GO** as designed |
| Views report view OID, not base table | GO; catalog must carry view entries (§6) |
| Provenance collapses to 0 through CTEs/subqueries | GO, but expect a high rejection rate — Phase 6 moves up and total cost roughly doubles |
| Partitioned tables report child OIDs | GO; catalog resolution must walk partition hierarchies |
| Provenance is broadly unreliable | **NO-GO** on this design; reopen buy-vs-build |

### Results — run 2026-08-07, PostgreSQL 17.10

**Verdict: GO as designed.** 22 shapes full provenance, 3 partial (per-field, handled
natively), 12 opaque. Full table in `docs/phase0-results.md`; rerun with `cargo run -p spike -- --md docs/phase0-results.md`.

Provenance survives **much** further than the design assumed. It holds through:

- flattenable *and* non-flattenable subqueries (`OFFSET 0` does not defeat it)
- CTEs, including `AS MATERIALIZED`
- views, nested views, and materialized views
- partitioned parents, `LATERAL`, `DISTINCT`, cursors + `FETCH`, temp tables
- the extended protocol (`Parse`/`Bind`/`Execute` agrees with simple query)
- **`email::text`** — a no-op cast stays a bare Var and does *not* launder provenance

It is lost on:

- **all set operations** — `UNION`, `UNION ALL`, `INTERSECT`, `EXCEPT`
- recursive CTEs
- functions returning `SETOF <table>` or `TABLE(...)`
- ordinary expressions, as expected: `lower()`, `||`, `COALESCE`, `CASE`, aggregates

Cross-validated on two independent client stacks (node-postgres and
tokio-postgres) with identical results, which also confirms the Rust dependency:
**`tokio_postgres::Column` exposes `table_oid()` and `column_id()`** as
`Option<u32>` / `Option<i16>`. No lower-level `postgres-protocol` access needed
for the backend leg.

### Every shape was describable without executing

All 37 shapes — including `FETCH ALL FROM <cursor>` — returned their full column
list from `Parse`+`Describe` alone, with no `Execute`. That is stronger than §5
assumed, and it opens a design option:

> For simple-query-protocol clients, the proxy can issue its **own** `Parse` +
> `Describe` on the backend before forwarding the `Query`, and reject
> pre-execution.

That buys uniform pre-execution rejection for *all* clients rather than only
extended-protocol ones, at the cost of one extra backend round trip per
statement. Worth prototyping in Phase 3 and measuring; if the latency is
acceptable it removes the simple-vs-extended asymmetry from the design entirely.

Caveat to test: a synthesized `Parse` of a multi-statement simple `Query` will
fail (`Parse` accepts one statement), so the proxy would need to either split
them or fall back to post-execution masking for that case.

### Decisions this resolves

| Question | Answer | Consequence |
|---|---|---|
| Views: view OID or base table? | **View OID** (`v_t`, and `v_nested` for nested) | §6 view entries move from conditional to **required** |
| Partitioned parent: parent or child OID? | **Parent** (`p`) | No hierarchy walking needed. Direct partition queries report the child, so catalog both |
| Do CTEs/subqueries survive? | **Yes, both** | Phase 6 stays deferred |
| Temp tables? | Resolve to `pg_temp_N.*` | Per-session OIDs, uncatalogable → fail-closed, as designed |

### Measuring it, rather than guessing

Shipped 2026-08-07: rejections are bucketed by cause and reported as
`set_op_like_share`. The bucketing is heuristic — Postgres names output columns
predictably enough that `?column?`, `count`, `lower` and a preserved column name
land in different buckets — and confined to counters, never enforcement.

**Measured 2026-08-07 against a real Neon branch (~380k CRM rows, 31 query
shapes) — the guess was wrong.** Set operations are 7% of rejections.
Expressions are 47% and aggregates 33%. Full write-up in
`examples/neon/README.md`. Revised priority, by frequency:

**TPC-DS, 2026-08-07: 90% refused** (69 of 77 judged), essentially all of it
aggregates over columns. Set operations scored 0%. Our own 31-query corpus
measured 32% and was far too easy. See `examples/tpcds/README.md`. The aggregate
rule is not optional for analytical workloads — it is the whole difference
between usable and not.

0. **Shipped 2026-08-07**: zero-argument safe shapes (`SELECT 1`, `now()`,
   `count(*)`) as an allowlist, not a column-reference search. False-rejection
   rate 23% -> 6% on the Neon corpus. Everything below is still open.
1. **Value-suppressing aggregates** — `count`/`avg`/`sum` emit no source value
   and can be allowed; `string_agg`/`array_agg`/`json_agg` dump every value and
   must not be. A parse tree separates them by function name alone, and it
   unblocks `GROUP BY x, count(*)`.
2. **Zero-column expressions** — fixes `SELECT 1` health checks.
3. **Per-field opaque handling** rather than refusing the whole result set.
4. **Set operations** — last, on this evidence.

Note also that `opaque = "mask"` does not rescue an analytical workload: it nulls
the aggregate and serves a useless answer, which is worse than a refusal.

The original two-rule plan below would have covered 20% of real rejections.
Kept for the reasoning, not the priority:

1. **Zero-column expressions.** If a target-list entry references no `ColumnRef`
   at all, it cannot leak a column. Sound, roughly 100 lines, and it fixes
   `SELECT 1`, `SELECT now()` and every health check.
2. **Set operations, without name resolution.** Do not try to resolve each
   branch's columns yourself — that is where the full lineage engine hides.
   Split the statement at the set operator and `Parse`+`Describe` each branch as
   its own statement; Postgres returns real provenance per branch, and arity is
   guaranteed to match, so merge positionally and take the most restrictive mask.
   This reuses the primitive Phase 0 already validated instead of adding a second
   source of truth.

Both rules turn rejections into acceptances, so a wrong merge is a leak rather
than a false pass. Add set-operation cases to the canary suite *before* the rule,
not after.

### The one real gap: set operations

`UNION ALL` is common in analytical SQL and goes fully opaque. This is now the single
largest expected driver of Phase 3 rejections, and the strongest argument for Phase 6 if
the shadow-mode numbers come back bad. **Instrument rejections by cause in Phase 5** so
the set-operation share is measurable on its own rather than buried in a total.

Two other notes worth carrying forward:

- `CASE WHEN ... THEN email END` is opaque while semantically leaking the column verbatim.
  Provenance cannot distinguish it from a safe expression. This is exactly why the default
  is reject-not-null, and it is the concrete example to use when defending that choice.
- `count(*)` and `string_agg(email, ',')` are indistinguishable to provenance — one is
  harmless, the other dumps every value. Policy has to separate them; the protocol cannot.

---

## 5. Connection and session state machine

### Per-connection state

```
authenticated: bool
principal: Option<String>          // set only on AuthenticationOk
search_path: String                // tracked via ParameterStatus, not by parsing SET
statements: Map<String, Statement> // name → { sql, last_row_description }
portals:    Map<String, Portal>    // name → { statement_name, active_plan }
pending:    VecDeque<Expectation>  // FIFO matching backend responses to frontend requests
copy_state: Option<CopyState>
```

**The `pending` FIFO is mandatory.** The extended protocol is pipelined: several
`Parse`/`Bind`/`Describe`/`Execute` messages can be in flight before any response arrives.
Without an ordered queue of expected responses you cannot attribute a `RowDescription` to
the portal that caused it. `Sync` → `ReadyForQuery` is the resynchronisation point.

**Track `search_path` from `ParameterStatus`, not by parsing `SET` statements.** Postgres
reports the change itself; parsing is both harder and wrong (functions can change it too).

### Frontend → backend

| Message | Action | Fail-closed rule |
|---|---|---|
| `SSLRequest` | Negotiate TLS on both legs | Refuse plaintext in production |
| `StartupMessage` | Capture `user`, `database`; forward | Principal stays unverified |
| `PasswordMessage`, SASL\* | Forward opaquely | — |
| `Query` (simple) | Enter simple-result-stream mode; forward | May contain N statements — plans come per `RowDescription`, so N is irrelevant |
| `Parse` | Record statement | Phase 6: pre-reject here |
| `Bind` | Record portal → statement | — |
| `Describe` | Push expectation | Pre-execution rejection point (see below) |
| `Execute` | Push expectation, keyed to portal | Row-limit → `PortalSuspended`; **plan must persist on the portal** |
| `Close` | Drop statement/portal state | — |
| `Sync` | Resync marker | — |
| `CopyData`/`CopyDone`/`CopyFail` | Only legal if a COPY was permitted | Otherwise terminate |
| `FunctionCall` | **Reject.** Legacy, produces data with no `RowDescription` | Always |
| `Terminate` | Tear down | — |

### Backend → frontend

| Message | Action | Fail-closed rule |
|---|---|---|
| `AuthenticationOk` | Mark principal **verified** | Policy lookups only after this |
| `ParameterStatus` | Update tracked `search_path` etc. | — |
| `RowDescription` | **Build the masking plan.** Per field: `tableID != 0` → catalog lookup → decision; `tableID == 0` → unclassifiable | Unclassifiable → per policy: reject the query or null the field. Default: reject |
| `DataRow` | Apply the active plan | **No active plan → terminate the connection.** Never pass through |
| `CopyOutResponse` | No plan is possible | Terminate unless COPY is explicitly policy-allowed |
| `NoData` | No result set | — |
| `ErrorResponse` | **Scrub before forwarding** | See below |
| `NoticeResponse` | Scrub before forwarding | Same |
| `ReadyForQuery` | Clear per-request state; pop FIFO | — |

**Error messages leak data.** A unique-violation message embeds the conflicting value:

```
ERROR: duplicate key value violates unique constraint "contacts_email_key"
DETAIL: Key (email)=(alice@example.com) already exists.
```

`DETAIL`, `HINT`, and constraint-context fields must be scrubbed or dropped when they
reference a classified column. Do not skip this; it is a live exfiltration channel and
trivially exploitable by an adversarial client.

### Pre-execution rejection

In the extended protocol, `Describe` returns `RowDescription` **before** `Execute`. So an
extended-protocol client can be refused *before* the query runs, with a proper
`ErrorResponse` and SQLSTATE that drivers surface natively.

Simple-query clients cannot be — there we mask after execution. Data never leaves the
proxy either way, but note the difference: rejected simple queries still consume database
work and still touch the data. Getting pre-execution rejection for simple queries requires
Phase 6.

---

## 6. Catalog and classification

The catalog maps `(table_oid, attnum) → classification`. This is the majority of the total
effort and it is not a coding problem.

### Source of truth

Config-as-code, keyed by `(schema, table, column)` — human-editable, reviewable, diffable.
The proxy resolves those names to OIDs at startup.

### OID resolution is a live operational hazard

`pg_class` OIDs change on DDL that rewrites a table, and on drop/recreate. If the OID map
goes stale, lookups miss and — under fail-closed — everything starts getting rejected, or
worse, a recreated table silently loses its classification.

Required behaviour:

- Refresh the OID map on a timer **and** on any lookup miss.
- **An unknown OID is treated as sensitive**, not as unclassified-therefore-fine.
- Alert on refresh failures. A proxy running on a stale map is a proxy with unknown
  coverage.

If Phase 0 shows views report their own OID, views need catalog entries too — either
classified directly, or resolved to base columns at catalog-build time.

### Default-deny and the CI gate

A column with no classification is **sensitive until declared otherwise**. Enforce it in
CI: any column reachable by the proxy that is absent from the catalog fails the build,
with an explicit exception mechanism that requires a written reason.

Bootstrap with a heuristic proposal pass — column-name patterns, type hints, value
sampling (`piicatcher` or similar) — then have humans confirm. The proposal pass is a
week; the confirmation is where the calendar time actually goes.

**This gate is the whole program.** Without it, coverage silently decays with every
migration and the proxy becomes theatre. It is also the part that will make you unpopular
with teams shipping schema changes, so get organisational buy-in *before* you turn it on,
not after.

---

## 7. Masking algorithms

**Contract:** a masking function must preserve the wire type OID *and* the format code
(text or binary) of the field it replaces. Returning a string where an `int4` was expected
breaks clients at the driver layer, below any error handling they have.

| Algorithm | Behaviour | Use for |
|---|---|---|
| `null` | Type-correct NULL | Highest sensitivity |
| `fixed` | Constant sentinel | When NULL breaks NOT NULL expectations downstream |
| `partial` | Preserve a prefix/suffix | Last-4 patterns, support workflows |
| `hash` | Non-reversible digest | Presence/equality only |
| `pseudonym` | Keyed, deterministic, format-preserving | The default for identifiers |

### Keyed pseudonyms

HMAC-SHA256 with a per-deployment key, output re-encoded into the source format so an
email still looks like an email and a UUID still parses as a UUID. Deterministic, so joins
and distinct-counts still work and analysts can reason about "same person" without knowing
who.

**State this in the policy docs:** determinism is an equality-and-frequency oracle. An
analyst can count distinct people, join them across tables, and spot the outlier with
10,000 rows. That is usually exactly what we want, but it is a real disclosure and must be
a deliberate decision per column, not a default that nobody examined.

Key management: KMS-backed, rotatable. Rotation invalidates every previously emitted
pseudonym — plan for it, since downstream consumers may have persisted them.

---

## 8. Phases and sequencing

| Phase | Work | Size | Gate |
|---|---|---|---|
| **0** | Provenance spike (§4) | 1 wk | **GO/NO-GO** |
| **1** | Catalog format, heuristic bootstrap, CI gate | 3 wk | Runs in parallel from day one |
| **2** | Proxy skeleton: 1:1, TLS both legs, auth passthrough, full passthrough, shadow logging | 1 wk | Traffic flows, nothing masked |
| **3** | Masking engine: plans from `RowDescription`, `DataRow` rewrite, fail-closed, COPY + `FunctionCall` blocked, error scrubbing | 2 wk | Masks correctly on the happy path |
| **4** | Bypass hardening, adversarial harness, driver conformance | 3 wk | **Security boundary** |
| **5** | Rollout: shadow → one client → general | 2 wk | In production |
| **6** | *Conditional:* libpg_query pre-rejection / lineage | 6+ wk | Only if Phase 5 rejection metrics justify it |

Phases 2–5 are ~8 weeks of Rust. Phase 1 is parallel and continues indefinitely.

**Team:** one Rust engineer on the proxy, one engineer on catalog/CI/classification, plus
a named data owner per schema who can actually answer "is this column sensitive." The
third role is the one projects like this forget to staff, and it is the one that
determines whether Phase 1 ever finishes.

---

## 9. Test strategy

Phase 4 is mostly this. Budget accordingly.

1. **Protocol conformance.** Drive real clients, not a hand-rolled test harness: `psql`,
   `pgx` in *both* text and binary modes, JDBC, `asyncpg`, and whichever BI tool is in
   scope. Each has its own protocol dialect and each will find something.
2. **The core property test.** Generate queries against a fixture database seeded with
   canary values in every classified column, then assert: **no canary byte ever appears in
   the client-bound stream.** Run it across every message path in §5. This single property
   test is worth more than the rest of the suite combined.
3. **Adversarial suite.** One case per bypass, minimum: `COPY` in every syntactic form,
   `FunctionCall`, multi-statement `Query`, `Execute` with row limits and resumption,
   re-`Bind` of a stale statement, cursors, `DO` blocks returning rows, refcursors,
   `search_path` switching mid-session, error-message DETAIL leakage, pipelined extended
   protocol with interleaved portals.
4. **Failure injection.** Backend dies mid-result-set; TLS renegotiation; client
   disconnects mid-`CopyData`; OID map refresh fails; catalog unavailable at startup
   (must refuse to start, not start permissively).
5. **Performance.** Establish a baseline against a direct connection. Expect the added
   latency to be dominated by the extra network hop, not by masking; if masking shows up in
   the profile, something is wrong with the `DataRow` field walk.

---

## 10. Operations

- **Failure mode is denial.** If the catalog is unavailable, the OID map is stale, or a
  plan cannot be built, the proxy refuses. It never degrades to passthrough.
- **No bypass flag.** A "disable masking" switch defeats the control and will be flipped
  during the first incident. Break-glass access is a *direct* DSN held by a small named
  group with its own audit trail — not a proxy setting.
- **Rollout order.** Shadow mode first: proxy the traffic, compute plans, log what *would*
  be masked and what *would* be rejected, change nothing. Run for two weeks. That log is
  how you find the classification gaps and measure the rejection rate before anyone is
  affected — and the rejection rate is the input to the Phase 6 decision.
- **Observability.** Per-query: principal, statement fingerprint, fields masked, fields
  rejected, latency delta. Alert on rejection-rate spikes (a schema change broke
  classification) and on OID refresh failures (coverage is now unknown).
- **Capacity.** 1:1 means connection count at the proxy equals connection count at the
  database. If that is a problem, pgbouncer goes behind us — do not solve it by adding
  pooling to the proxy.

---

## 11. Accepted limitations

Masking is a disclosure control on the **projection**. The following are known gaps,
**reviewed and accepted** as out of scope for this project. They are recorded here so the
decision stays visible and nobody later mistakes the proxy for anonymization.

- **Predicate oracles.** `WHERE email = 'alice@example.com'` returning one row confirms
  the email. `WHERE ssn LIKE '123%'` is a binary search. The filter side is ungoverned by
  this design.
- **Join-key re-identification.** Masking `name` while returning `customer_id` leaves an
  identifier that points back to the identity.
- **Small-cell aggregates.** `GROUP BY city HAVING count(*) = 1`.
- **Differencing.** Two permitted aggregate queries whose difference isolates one row.

One case was reclassified from accepted to closed. `SELECT sum(salary) FROM t GROUP BY
id` is not a small-cell problem — with `id` unique, *every* group is a single row, so the
statement returns the whole masked column in one query. That one is decidable without any
query-set accounting: the grouping is in the statement and the uniqueness is in
`pg_index`. Since v0.1.16 the session refuses a released reducing aggregate whose
`GROUP BY` covers a declared unique key, and equally one whose `GROUP BY` it cannot reduce
to column names — an unreadable grouping is one that cannot be cleared. The reader
resolves column references, ordinals (`GROUP BY 1`) and `ROLLUP`/`CUBE`/`GROUPING SETS`,
so the honest forms of that syntax are served. An expression stays unreadable, and falls
back to a lexical question the scanner can answer soundly — does the statement name every
column of some unique key? — rather than to a refusal, which had cost time-bucketed
aggregation. Ungrouped aggregates and groupings on non-key columns are served
unchanged, so ordinary analytics is unaffected. `WHERE id = 1` reaches the same
value and is still accepted: one row per query rather than the whole table in one, and
whether a predicate is singleton is a fact about the data.

Closing the rest requires query-set-level accounting — minimum group sizes, filter-side
policy, per-principal budgets, probably noise — a different and much larger project that
also costs exactness. Not planned.

**Practical consequence:** the proxy's threat model is careless or opportunistic
disclosure by an authenticated, broadly trusted principal. It is not a defence against a
determined adversary who already has query access. Scope grants accordingly — the proxy
reduces blast radius, it does not replace deciding who gets a connection string.

---

## 12. Open decisions

1. **Unclassifiable field: reject the query, or null the field?** Recommend **reject** —
   a null teaches the client nothing about why, while a rejection with a clear SQLSTATE
   tells them to select the column directly. Revisit if the rejection rate is painful for
   human clients.
2. **`COPY`: block entirely, or allow with parse-based validation?** Recommend **block
   entirely** in Phase 3 and reconsider only if a real workflow breaks.
3. **Per-principal exceptions from day one, or a single global policy?** Recommend
   **global first.** Exception policies are where masking systems accumulate their
   complexity; earn it with a concrete need.
4. **Where does the OID map live** — in-proxy cache, or a shared service if we run
   multiple instances? Recommend in-proxy with a short TTL until instance count forces
   otherwise.
5. **Are BI tools in scope?** This changes everything about the rejection-rate tolerance
   and probably forces Phase 6. Answer before Phase 5.

---

## Appendix: rejected alternatives

| Option | Why not |
|---|---|
| Fork pgdog / pgcat | Their complexity is pooling and sharding, which we deliberately exclude. We would inherit a permanent merge burden for machinery we do not want, and result-set rewriting cuts against a throughput-optimised architecture. |
| Driver-level wrapper | Enforcement by convention, not by network reachability. Rejected: the requirement is that the connection string points at the proxy. |
| Engine-native (masking views, column GRANTs, PostgreSQL Anonymizer) | Strictly stronger enforcement, but no query-shape awareness beyond what views express, no session-level policy, and it requires extension/DDL control we may not have on managed Postgres. Worth revisiting as a *complement*, not a replacement. |
| Buy (Bytebase, Immuta, Cyral) | Still the right call if BI tools and human analysts are the primary clients — their lineage engines are years of accumulated per-dialect work. Reconsider at decision 5. Note that no vendor supplies the classification catalog, so Phase 1 is unavoidable either way. |
| Tier-2 anonymization (Diffix, DP engines) | Real privacy guarantees, at the cost of exactness. Different project. |

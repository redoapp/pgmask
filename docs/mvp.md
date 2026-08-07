# MVP goal

> A Postgres proxy you can put in a connection string that provably never emits an
> unmasked classified value, for the query shapes Phase 0 proved we can reason about —
> and refuses everything else.

Phases 2 and 3 of [`handoff.md`](handoff.md), scoped to one deliverable.

## Acceptance criteria

1. `psql "host=proxy"` connects, authenticates, and runs queries.
2. A classified column comes back masked; an unclassified one comes back masked too
   (default-deny); an explicitly-allowed one comes back verbatim.
3. A query whose output has **no provenance** (`UNION`, `lower(email)`, a `SETOF` function)
   is **rejected**, not silently passed.
4. `COPY ... TO STDOUT` and the legacy `FunctionCall` message are refused — the only two
   paths that emit rows without a `RowDescription`.
5. A `DataRow` reaching the client with no active masking plan is impossible: the
   connection is killed instead.
6. Error-message `DETAIL`/`HINT` carrying classified values is scrubbed.
7. Both the simple and extended query protocols work, including prepared statements
   re-executed many times against one `Describe`.
8. Benchmarks quantify the added latency against a direct connection.

## Deliberately out of scope for the MVP

| Not in MVP | Why | Where it lands |
|---|---|---|
| TLS | Plaintext or `sslmode=disable` only; the proxy answers `SSLRequest` with `N` | Phase 4 |
| Binary format for non-text types | Text-family types are byte-identical in both formats and mask correctly; everything else accepts only `mask = "null"` and rejects otherwise | Phase 4 |
| Pre-execution rejection for simple queries | Rejection happens after the backend ran the query. Data never reaches the client, but the work was done | Phase 3 prototype (§4 of handoff) |
| Per-principal exception policies | One global catalog | Phase 5, per open decision 3 |
| Cancel-request key mapping | `CancelRequest` is forwarded blind | Phase 4 |
| CI classification gate | The catalog is hand-written | Phase 1 |

## The rejection asymmetry, stated plainly

When the proxy rejects a result set it has already let the backend execute the query. It
suppresses `RowDescription`, sends the client an `ErrorResponse` (SQLSTATE `42501`),
discards the backend's rows, and forwards the real `ReadyForQuery` so transaction state
stays consistent.

Consequence: for a rejected statement inside an explicit transaction, the client believes
the statement failed while the server believes it succeeded. Harmless for `SELECT`, and
the reason the synthesized-`Describe` prototype in handoff §4 matters.

# pgmask

A fail-closed column masking proxy for Postgres. Clients point their connection string at
pgmask instead of the database; it inspects result sets in flight and masks sensitive
column values according to a policy catalog.

**Current phase: 0 complete → 1 and 2 ready to start.**

See [`docs/handoff.md`](docs/handoff.md) for the full build plan — architecture, protocol
state machine, catalog design, test strategy, phases, and accepted limitations.

## How it works

Postgres's `RowDescription` message carries, per output field, the table OID and column
attnum it came from — and `0` for both when the field is a computed expression. That gives
us engine-authoritative provenance without parsing SQL. We mask what we can identify and
**refuse what we cannot**.

The governing rule: **bind the masking plan to the `RowDescription`, never to the
statement.** Every row-producing path in the protocol emits one first, so cursors,
multi-statement queries, resumed portals, and functions are covered without special
handling. The only two paths that produce rows *without* one — `COPY ... TO STDOUT` and
the legacy `FunctionCall` message — are blocked outright.

## Phase 0: the provenance spike

Phase 0 gated the whole design: does provenance actually survive real query shapes? It
does, further than expected. **Verdict: GO.** Results in
[`docs/phase0-results.md`](docs/phase0-results.md), analysis in
[`docs/handoff.md` §4](docs/handoff.md).

```bash
npm install
npm run pg:up          # Postgres 17 in podman on :55432
DATABASE_URL='postgres://postgres:spike@localhost:55432/spike' npm run spike:md
npm run pg:down
```

Rerun against any database by pointing `DATABASE_URL` elsewhere. **Rerun it against the
target major version before Phase 3** — provenance behaviour is a planner property and is
not guaranteed stable across releases.

Adding a shape: append to `spike/shapes.mjs`. Set `expect` to your prior (`provenance`,
`opaque`, or `unknown`) and the runner flags anything that disagrees.

### Headline results

| | |
|---|---|
| Survives | subqueries (flat and non-flat), CTEs incl. MATERIALIZED, views, nested views, matviews, partitioned parents, LATERAL, DISTINCT, cursors, temp tables, `::text` casts, extended protocol |
| Lost | **all set operations** (`UNION`/`INTERSECT`/`EXCEPT`), recursive CTEs, `SETOF <table>` functions, ordinary expressions |

Set operations are the main expected source of Phase 3 rejections. Instrument them
separately in shadow mode.

## Layout

```
docs/handoff.md            build plan — read this first
docs/phase0-results.md     generated spike output
spike/fixture.sql          relation kinds under test
spike/shapes.mjs           the query-shape matrix
spike/run.mjs              runner; prints a summary and the GO/NO-GO inputs
```

The spike is Node because it answers a question about *Postgres*, not about Rust. The
proxy itself is Rust (`pgwire` + `tokio-postgres`), starting in Phase 2.

## What this is not

Masking is a disclosure control on the projection. It does not defend against predicate
oracles, join-key re-identification, small-cell aggregates, or differencing — see
[`docs/handoff.md` §11](docs/handoff.md), where those are recorded as reviewed and
accepted. The threat model is careless disclosure by a trusted principal, not a determined
adversary who already has query access.

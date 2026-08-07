# Phase 4 — make it a security boundary

**Status: complete.** All six criteria pass. What each one cost, and what it
turned up, is recorded at the bottom.

> The MVP masks correctly. Phase 4 is about making it impossible to *not* mask:
> every protocol path closed, the invariant enforced by the compiler rather than
> by review, and the transport encrypted.

The distinction from [`mvp.md`](mvp.md) is the one from [`handoff.md`](handoff.md)
§9: an observing proxy can be sloppy, because a mishandled path is a missing log
line. An enforcing proxy cannot, because a mishandled path is a silent leak.

## Acceptance criteria

1. **Unmasked bytes are unforgeable.** The output boundary accepts only a type
   that the masking path alone can construct. "Forward a row we did not vet"
   becomes a compile error, not a review question.
2. **The canary property test.** Every classified column is seeded with a unique
   sentinel. Drive every protocol path from a raw wire client and assert that no
   sentinel byte ever appears in the bytes sent to the client. This is worth more
   than the rest of the suite combined (handoff §9.2).
3. **The adversarial suite.** One test per bypass in handoff §5, driven from a
   raw protocol client rather than a driver, because no well-behaved driver will
   send the interesting messages: every `COPY` form, `FunctionCall`,
   multi-statement simple query, `Execute` with row limits and resumption,
   re-`Bind` of a stale statement, cursors, `DO` blocks returning rows,
   `search_path` switching mid-session, and pipelined extended protocol with
   interleaved portals.
4. **TLS on both legs.** `SSLRequest` is honoured with a real handshake, and the
   backend leg can require TLS. A masking proxy reachable over plaintext is not a
   security boundary.
5. **Cancel requests work.** Keyed properly rather than forwarded blind, so
   Ctrl-C in psql cancels the query instead of silently doing nothing.
6. **Failure injection.** Backend dies mid-result-set, client disconnects
   mid-stream, catalog unavailable at startup — none of which may fail open.

## Still out of scope after Phase 4

Unchanged from the MVP, and each has its own phase:

- Per-principal exception policies (open decision 3)
- Binary format for non-text types
- Pre-execution rejection for simple queries (the synthesized-`Describe`
  prototype, handoff §4)
- The Phase 1 classification catalog and its CI gate — the largest remaining item
  overall, and not a Rust problem
- The accepted limitations in handoff §11: predicate oracles, join-key
  re-identification, small cells, differencing

## Done means

`cargo test` green including the adversarial suite, `examples/demo/verify.sh`
still 18/18, TLS demonstrated end-to-end, and the canary test proving no sentinel
escapes across every path in criterion 3.


---

# Outcome

77 assertions across five suites, all green:

| Suite | Count | What it covers |
|---|---|---|
| `cargo test` (unit) | 29 | framing, masking, plan construction |
| `tests/adversarial.rs` | 18 | the canary property test and every bypass in handoff §5 |
| `tests/resilience.rs` | 5 | cancellation, failure injection, 24 concurrent sessions |
| `scripts/test-tls.sh` | 7 | TLS on both legs, driven by a real psql |
| `examples/demo/verify.sh` | 18 | the MVP acceptance criteria, still passing |

Performance is unchanged at 0.268 µs per masked row — the `Vetted` newtype and
the allowlist cost nothing measurable.

## What the criteria turned up

**Criterion 1 (unforgeable output)** went in cleanly. `Batch::client` takes only
a `Vetted`, whose four constructors are the complete list of ways bytes reach the
client, and the private field plus module boundary is what makes that hold.

**Criterion 2 (the canary test) found a real leak on its first run.** `COPY ...
TO STDOUT` was refused correctly, but the write-batching drain loop kept
processing messages queued behind the refusal, and the `CopyData` frames fell
through a `_ =>` arm and were forwarded as control messages. Two fixes: stop
draining once something refuses, and delete the backend direction's catch-all in
favour of an explicit allowlist. An unrecognised backend message may carry row
data, and forwarding it *because* we do not know what it is inverts the design.

The negative control matters as much as the test: one case runs wide open and
asserts the sentinel IS visible, so the assertion is known to be capable of
failing.

**Criterion 4 (TLS) surfaced an architectural constraint worth knowing about.**

> **SCRAM channel binding cannot survive a TLS-terminating proxy.**

`SCRAM-SHA-256-PLUS` ties authentication to the TLS certificate of the endpoint
the client is talking to. pgmask terminates TLS and re-originates, so the client
binds to our certificate while the backend verifies against its own. That is
channel binding working exactly as designed — detecting an endpoint that
intercepts and re-originates TLS is its entire purpose, and pgmask is such an
endpoint.

Stripping `-PLUS` from the mechanism list does not rescue it: SCRAM carries a
`gs2` flag meaning "I support channel binding but the server did not offer it",
and a server that *did* offer it treats that as the downgrade attack it is. We
tried it; the failure just moves from "check failed" to "negotiation error".

**Corrected 2026-08-07 by the Neon experiment.** The rule is conditional, not
absolute — see `examples/neon/README.md`. A *plaintext* client leg in front of a
TLS backend both can and must strip `-PLUS`, because libpq aborts outright on
"SCRAM-SHA-256-PLUS authentication over a non-SSL connection" rather than
falling back. Stripping is now implemented, gated on the client leg being
plaintext. Only the both-TLS case is unfixable, and the original text below
generalised from testing that one branch alone.

The workable configuration is **client TLS, plaintext backend leg**. Postgres
only advertises `-PLUS` on a TLS connection of its own, so a plaintext backend
leg means it offers plain `SCRAM-SHA-256`, the client authenticates normally, and
the client-to-pgmask hop is still encrypted. Put the proxy next to the database
and secure that hop by placement. pgmask detects the unworkable combination and
says so explicitly rather than letting the client hit an opaque protocol error.

**Criterion 5 (cancellation) turned out to already work**, and the test explains
why rather than just asserting it: `BackendKeyData` is forwarded verbatim, so the
client holds the backend's own PID and secret, and a `CancelRequest` handed
straight through matches. No key table needed. Verified by SQLSTATE `57014`
rather than by error text.

## Two smaller findings

`deny_unknown_fields` on the config is now a security control, not tidiness. TOML
places any key written after a `[[column]]` block *inside* that block, so an
appended `tls_cert` silently became a `ColumnRule` field and the proxy came up in
plaintext without complaint. serde ignored it. A typo in a security setting must
be a startup failure.

`SELECT pg_sleep(30)` is rejected, for the same reason `SELECT 1` is — a bare
function call in the target list has no provenance. The cancellation test had to
move the sleep into the `FROM` clause. Expect this class of friction with utility
queries generally, not only with health checks.

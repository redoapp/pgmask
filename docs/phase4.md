# Phase 4 goal — make it a security boundary

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

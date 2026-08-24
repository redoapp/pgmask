# pgmask — working notes for AI agents

pgmask is a **fail-closed column-masking proxy for PostgreSQL**. Read
`docs/handoff.md` for design history and `docs/safety-assessment.md` for the
disclosure record before changing anything in `crates/proxy/src`.

## Invariants that must survive every change

- **Policy binds to the `RowDescription`** (table OID + attnum), never to SQL
  text alone. SQL analysis exists for the cases where provenance lies (set
  operations, opaque views, CockroachDB's first-branch OID) — it distrusts,
  it never releases on its own.
- **No bytes reach the client without vetting.** `Batch::client` accepts only
  a `Vetted` (session.rs); its constructors are the complete audited list of
  ways to clear bytes. Never add a way around it; a new forward path is a new
  constructor with a comment defending its claim.
- **Configured masks fail closed.** A mask that cannot honour a value refuses
  the result set. Only the *type-aware fallback* for unclassified nullable
  columns may degrade a failing value to NULL (`FieldPlan::lenient`).
- **Unknown means masked.** A lookup miss, an unresolvable name, an
  unrecognised shape — every "don't know" resolves to mask or refuse, never
  to pass. When adding a rule, ask which direction a gap leaks: over-refusal
  costs a query, over-release is a disclosure.
- **One capability table.** `MaskSpec::supports` owns mask/type compatibility.
  `classify` delegates to it; `for_unclassified` selects from it. Never write
  a second copy.
- **Comments are institutional memory.** They record measured leaks, equivalent
  mutants, and why the obvious fix was wrong. Move them with the code verbatim;
  never trim them in a refactor.

## Module seams (crates/proxy/src)

- `session.rs` — the per-connection wire state machine. One `select!` loop,
  no locking. Owns `Vetted`/`Batch` and the row-masking loop.
- `policy.rs` — "what plan does a described result set get". `Policy`,
  `plan_for`, summary attribution. Boundary type: `Rejection`.
- `plan_state.rs` — extended-protocol statement/portal/plan lifecycle,
  pipelining order, epoch invalidation. Has its own protocol-state fuzzer.
- `catalog.rs` — config, classification catalog, refresh.
  `Snapshot::names` is classified-only; `Snapshot::all_columns` is every live
  column (pseudonym-domain identity). Keep them separate.
- `mask.rs` — masking algorithms. Masks must preserve wire type and format.
- `analysis/` — SQL allowlisting; rules are allowlists of shapes, not
  searches for column refs.

## Release gates (run before claiming done)

```bash
PGMASK_ALLOW_SKIP=1 cargo test --workspace   # unit suites
./scripts/test-integration.sh                # adversarial + resilience vs real Postgres (podman)
cargo clippy --workspace --all-targets       # zero warnings; unwrap/panic denied
cargo fmt --all --check
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps --locked
./scripts/check-repo-invariants.sh           # counts, tags, changelog discipline
```

CI also runs `cargo deny --locked` against `fuzz/Cargo.toml` — the `fuzz/`
sub-workspace has its **own `Cargo.lock`**, so a workspace version bump must
also update the `pgmask` entry there or CI fails on staleness.

Database-backed tests panic without `PGMASK_TEST_PG` unless
`PGMASK_ALLOW_SKIP=1`; that is deliberate (they once passed vacuously).

## Release discipline

- Every released version gets a changelog entry **and** a git tag `vX.Y.Z`
  (the newest entry is exempt from tagging until merged). Never amend a
  released version's changelog section — add a new section and bump
  `Cargo.toml`, README ("Current version"), and `fuzz/Cargo.lock`.
- The invariants script cross-checks claimed counts (database-backed tests,
  TLS checks, disclosure count) against the code. If it fails, the claim is
  stale — fix the claim, don't game the count.
- Benchmarks: compare versions only back-to-back against the same live
  Postgres instance (`docs/benchmarks.md`); cross-instance variance exceeds
  most optimisation effects.

## Test culture

- Adversarial tests are canary-based: `assert_exercised`/`assert_served`
  guard against vacuous passes; `negative_control_the_harness_can_see_a_leak`
  proves the harness detects leaks at all. New leak-shaped tests follow that
  pattern.
- Behavior changes to masking need an end-to-end test through a real Postgres,
  not only a unit test — several past defects were only reachable on the wire
  (binary formats, pipelining, view OIDs).

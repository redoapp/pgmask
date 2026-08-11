#!/usr/bin/env bash
# Everything, in one command, with skips counted as failures.
#
#   ./scripts/test-all.sh
#
# There are thirteen suites and they were previously separate commands run in
# whatever order someone remembered. Two things went wrong repeatedly: a suite
# tore down a container the next one needed, and `cargo test` stopped at the
# first failing target so the total silently dropped by 21 without anything
# saying "failed". This runs them in a fixed order, isolates them, and reports
# one line per suite.
#
# A SKIP is a FAILURE here. A release gate that passes because a tool was
# missing is the same bug as a test that passes because the fixture was empty.
#
# Every `podman rm` here passes `-v`. The postgres image declares a VOLUME for
# its data directory, so each `podman run` creates an anonymous volume and a
# plain `podman rm` leaves it behind. Running this gate repeatedly accumulated
# 384 orphaned volumes and filled the podman machine's 150 GB disk, at which
# point CockroachDB refused to start — "out of disk space" — and three suites
# failed for reasons that had nothing to do with masking.

set -uo pipefail

# Refuse to run alongside another pgmask.
#
# The cleanup below is machine-global, not worktree-scoped: `pkill -f` matches
# every pgmask process on the host, and the container names are fixed strings
# that any checkout uses. Two sessions running this at once therefore destroy
# each other — that happened, in both directions, between this gate and an agent
# fuzzing in a separate worktree. It killed the agent's proxies and deleted its
# `pgmask-fuzz` fixture mid-run; the agent's load made three of this gate's
# suites report false failures.
#
# A git worktree isolates files. It does not isolate processes or container
# names, and this script's teardown assumes it owns both.
if pgrep -x pgmask >/dev/null 2>&1; then
  echo "FAIL: pgmask is already running, and this gate's teardown would kill it."
  echo "      Another session or agent is probably mid-run. Processes:"
  pgrep -lx pgmask | sed 's/^/        /'
  echo "      Wait for it, or stop it deliberately, then re-run."
  exit 1
fi
cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:/opt/homebrew/bin:$PATH"

pass=0
fail=0
declare -a RESULTS=()

record() { # name status detail
  local mark="ok  "
  if [[ "$2" != "0" ]]; then mark="FAIL"; fail=$((fail + 1)); else pass=$((pass + 1)); fi
  RESULTS+=("$(printf '  %s  %-34s %s' "$mark" "$1" "${3:-}")")
}

run() { # name command...
  local name="$1"; shift
  printf '==> %s\n' "$name"
  # Containers and proxies from a previous suite are the most common cause of a
  # confusing failure, so every suite starts from nothing.
  pkill -f 'target/release/pgmask' 2>/dev/null
  podman rm -f -v pgmask-demo pgmask-fuzz pgmask-crdb pgmask-shapes-pg pgmask-shapes-crdb pgmask-fuzz-crdb pgmask-diff-pg pgmask-diff-crdb pgmask-test pgmask-tls pgmask-inference pgmask-grouping-postgres pgmask-grouping-cockroach >/dev/null 2>&1
  sleep 1
  local out
  out=$("$@" 2>&1)
  local status=$?
  local summary
  summary=$(printf '%s\n' "$out" | grep -oE 'passed [0-9]+, failed [0-9]+|LEAKED +[0-9]+|test result: [A-Za-z]+' | tail -1)
  record "$name" "$status" "$summary"
  [[ "$status" == "0" ]] || printf '%s\n' "$out" | tail -12
}

echo "=== static ==="
cargo fmt --check >/dev/null 2>&1; record "cargo fmt --check" "$?"
n=$(cargo clippy --workspace --all-targets -q 2>&1 | grep -cE '^(warning|error)')
[[ "$n" == "0" ]]; record "clippy (0 findings)" "$?" "$n findings"
cargo audit >/dev/null 2>&1; record "cargo audit" "$?"

echo "=== rust tests ==="
# --no-fail-fast, or one failing target hides every target after it.
#
# PGMASK_ALLOW_SKIP is set here on purpose: 31 of these tests need a live
# Postgres, and they are run for real by the "adversarial (real Postgres)"
# suite below, which supplies one. Without the variable `require_pg!` now
# panics rather than returning Ok — it used to return Ok, which meant those 31
# reported PASS on every gate run having asserted nothing, the adversarial
# raw-wire suite among them.
# The `fuzzing` feature too, in a second run.
#
# `plan_state_fuzz` is feature-gated so `libfuzzer-sys` stays out of the main
# dependency graph, and the sequences the protocol fuzzer minimised live in it —
# including the two that reproduce the `described_sql` substitution. A plain
# `cargo test` compiles none of them: the module simply is not there, and the
# gate reported the same 183 lib tests before and after they were added. A
# regression test that does not run is a comment.
out=$(PGMASK_ALLOW_SKIP=1 cargo test --workspace --no-fail-fast -q 2>&1
      PGMASK_ALLOW_SKIP=1 cargo test -p pgmask --lib --features fuzzing --no-fail-fast -q 2>&1)
status=$?
total=$(printf '%s\n' "$out" | grep -E '^test result' | awk '{s+=$4} END {print s+0}')
skipped=$(printf '%s\n' "$out" | grep -c 'skipping by request')
record "cargo test" "$status" "$total tests ($skipped need Postgres)"
[[ "$status" == "0" ]] || printf '%s\n' "$out" | grep -E 'FAILED|panicked' | head -8

echo "=== end to end ==="
cargo build --release -q || { echo "release build failed"; exit 1; }
run "adversarial (real Postgres)" ./scripts/test-integration.sh
run "demo (verify.sh)"        env KEEP=0 ./examples/demo/verify.sh
# Asserts the limits, not the defence: each route it lists is one a client can
# still take. It belongs in the gate because it now also asserts the routes we
# closed, so undoing one is a suite failure rather than a quiet regression.
run "inference limits"        ./scripts/test-inference.sh
# The generated counterpart to the inference suite's literal strings: every way
# to spell "group by the key", crossed with every syntactic position that can
# carry one. Three disclosures in a row were spellings nobody had written down.
run "grouping spellings"      ./scripts/test-grouping.py
run "grouping spellings (CockroachDB)" ./scripts/test-grouping.py --engine=cockroach
# Does the corpus reach each release rule at all? A rule no generated statement
# can express is a rule the campaign says nothing about, and both `PURE_SCALARS`
# and `date_trunc` were in exactly that position when each produced a
# disclosure. Fails when a tracked shape is unreachable.
run "release paths reached"   bash -c './target/release/shapegen 4242 3000 postgres > /tmp/pgmask-reach.sql && ./target/release/reach /tmp/pgmask-reach.sql'
run "TLS"                     ./scripts/test-tls.sh
run "Postgres 13-17"          ./scripts/test-versions.sh
run "CockroachDB"             ./scripts/test-cockroach.sh
run "shape sweep (both engines)" ./scripts/test-shapes.sh
run "generated SQL campaign"  ./scripts/test-fuzz.sh 1500 3 3
run "generated shapes (CockroachDB)" ./scripts/test-fuzz-cockroach.sh 1200 3
run "cross-engine differential" ./scripts/test-differential.sh 800

pkill -f 'target/release/pgmask' 2>/dev/null
podman rm -f -v pgmask-demo pgmask-fuzz pgmask-crdb pgmask-shapes-pg pgmask-shapes-crdb pgmask-fuzz-crdb pgmask-diff-pg pgmask-diff-crdb pgmask-test pgmask-tls pgmask-inference pgmask-grouping-postgres pgmask-grouping-cockroach >/dev/null 2>&1

echo
echo "-------------------------------------------------------------"
printf '%s\n' "${RESULTS[@]}"
echo "-------------------------------------------------------------"
printf '  %d suites passed, %d failed\n' "$pass" "$fail"
[[ "$fail" -eq 0 ]] || exit 1

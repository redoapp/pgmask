#!/usr/bin/env bash
# Everything, in one command, with skips counted as failures.
#
#   ./scripts/test-all.sh
#
# There are seven suites and they were previously five separate commands run in
# whatever order someone remembered. Two things went wrong repeatedly: a suite
# tore down a container the next one needed, and `cargo test` stopped at the
# first failing target so the total silently dropped by 21 without anything
# saying "failed". This runs them in a fixed order, isolates them, and reports
# one line per suite.
#
# A SKIP is a FAILURE here. A release gate that passes because a tool was
# missing is the same bug as a test that passes because the fixture was empty.

set -uo pipefail
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
  podman rm -f pgmask-demo pgmask-fuzz pgmask-crdb >/dev/null 2>&1
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
out=$(cargo test --workspace --no-fail-fast -q 2>&1)
status=$?
total=$(printf '%s\n' "$out" | grep -E '^test result' | awk '{s+=$4} END {print s+0}')
record "cargo test" "$status" "$total tests"
[[ "$status" == "0" ]] || printf '%s\n' "$out" | grep -E 'FAILED|panicked' | head -8

echo "=== end to end ==="
cargo build --release -q || { echo "release build failed"; exit 1; }
run "demo (verify.sh)"        env KEEP=0 ./examples/demo/verify.sh
run "TLS"                     ./scripts/test-tls.sh
run "Postgres 13-17"          ./scripts/test-versions.sh
run "CockroachDB"             ./scripts/test-cockroach.sh
run "generated SQL campaign"  ./scripts/test-fuzz.sh 1500 3 3

pkill -f 'target/release/pgmask' 2>/dev/null
podman rm -f pgmask-demo pgmask-fuzz pgmask-crdb >/dev/null 2>&1

echo
echo "-------------------------------------------------------------"
printf '%s\n' "${RESULTS[@]}"
echo "-------------------------------------------------------------"
printf '  %d suites passed, %d failed\n' "$pass" "$fail"
[[ "$fail" -eq 0 ]] || exit 1

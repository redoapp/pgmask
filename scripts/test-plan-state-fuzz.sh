#!/usr/bin/env bash
# Fuzz the extended-query protocol state machine — the order of messages, not
# the SQL in them.
#
#   ./scripts/test-plan-state-fuzz.sh [seconds]      # default 300
#
# NEEDS A NIGHTLY TOOLCHAIN. libFuzzer's instrumentation is nightly-only, so
# this is not on ./scripts/test-all.sh and the release gate does not depend on
# it. What the gate does carry is the regression tests in
# `crates/proxy/src/plan_state_fuzz.rs`, which replay the sequences this found.
#
#   rustup toolchain install nightly
#   cargo install cargo-fuzz
#
# WHY THIS EXISTS
#
# Every other campaign here generates statements. None of them generates
# *interleavings*, and a disclosure lived in one: `described_sql` used
# `and_then(..).or_else(..)`, which collapsed "no Describe is outstanding" and
# "a Describe is outstanding whose SQL was never recorded" into a single branch,
# so the second answered with an earlier simple query's text. `SELECT 1, 2`
# reads as two literals with nothing to mask, and fields belonging to
# `SELECT upper(email), …` were released on its authority. Two messages. No
# generated statement could have found it, because both statements were
# ordinary; only the order was wrong.
#
# WHAT MAKES A PASS MEAN SOMETHING
#
# The same rule as ./scripts/test-fuzz.sh: a poison run first. This script
# reintroduces that exact bug, fuzzes the poisoned build, and REQUIRES the
# oracle to fire. Only then does it trust a clean run. A fuzz target that has
# never failed is not known to work — four separate probes reported this path
# clean while it was live, because none of them could observe the thing they
# were pointed at.

set -uo pipefail
cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:/opt/homebrew/bin:$PATH"

DURATION="${1:-300}"
POISON_DURATION="${POISON_DURATION:-60}"
TARGET=plan_state
SOURCE=crates/proxy/src/plan_state.rs
BACKUP=$(mktemp)

# Corpora are per-run and empty. A corpus carried over from the poison run
# would hand the clean run the crashing input, and a corpus carried over from a
# previous clean run would make "found it in four seconds" unfalsifiable.
POISON_CORPUS=$(mktemp -d)
CLEAN_CORPUS=$(mktemp -d)
ARTIFACTS=$(mktemp -d)

restore() {
  # Unconditional: an interrupted run must not leave the poison in the tree.
  if [[ -s "$BACKUP" ]]; then cp "$BACKUP" "$SOURCE"; fi
  rm -rf "$BACKUP" "$POISON_CORPUS" "$CLEAN_CORPUS" "$ARTIFACTS"
}
trap restore EXIT

# Exit 3, not 0. A missing toolchain is a campaign that did not run, and this
# repo has been bitten twice by a suite reporting success for doing nothing.
# PGMASK_ALLOW_SKIP=1 opts into skipping, deliberately.
missing=""
rustup toolchain list 2>/dev/null | grep -q '^nightly' || missing="nightly toolchain (rustup toolchain install nightly)"
command -v cargo-fuzz >/dev/null || missing="${missing:+$missing; }cargo-fuzz (cargo install cargo-fuzz)"
if [[ -n "$missing" ]]; then
  echo "missing: $missing"
  if [[ "${PGMASK_ALLOW_SKIP:-0}" == "1" ]]; then
    echo "PGMASK_ALLOW_SKIP=1 — skipping, and this run proves nothing"
    exit 0
  fi
  echo "FAIL: refusing to report success for a campaign that did not run."
  exit 3
fi

cp "$SOURCE" "$BACKUP"

fuzz_for() { # seconds corpus-dir
  cargo +nightly fuzz run --fuzz-dir fuzz "$TARGET" "$2" -- \
    -max_total_time="$1" -artifact_prefix="$ARTIFACTS/" -print_final_stats=1 2>&1
}

# --- 1. Poison run: the oracle must fire ------------------------------------
echo "==> poison run: reintroducing the and_then(..).or_else(..) fallback"
python3 - "$SOURCE" <<'PY' || exit 1
import sys
path = sys.argv[1]
fixed = """        match self.pending_describes.front() {
            Some(pending) => pending.sql.clone(),
            None => self.simple_sql.clone(),
        }
"""
poisoned = """        self.pending_describes
            .front()
            .and_then(|pending| pending.sql.clone())
            .or_else(|| self.simple_sql.clone())
"""
text = open(path).read()
if text.count(fixed) != 1:
    # The shape of described_sql changed. That is not a reason to skip the
    # control — it is a reason to stop, because the control no longer knows
    # what it is poisoning.
    sys.exit("FATAL: could not find described_sql's match to poison (found "
             f"{text.count(fixed)} occurrences). Update this script.")
open(path, "w").write(text.replace(fixed, poisoned))
PY

poison_out=$(fuzz_for "$POISON_DURATION" "$POISON_CORPUS")
if ! printf '%s' "$poison_out" | grep -q 'described_sql() answered'; then
  echo "FAIL: the fallback was live and the oracle did not fire in ${POISON_DURATION}s."
  echo "      Everything after this would have been a false clean sweep."
  printf '%s\n' "$poison_out" | tail -12
  exit 1
fi
echo "    oracle fired, as required:"
printf '%s\n' "$poison_out" | grep -m1 'described_sql() answered' | sed 's/^/      /'

cp "$BACKUP" "$SOURCE"

# --- 2. Clean run ------------------------------------------------------------
echo "==> clean run: ${DURATION}s from an empty corpus"
clean_out=$(fuzz_for "$DURATION" "$CLEAN_CORPUS")
status=$?
execs=$(printf '%s' "$clean_out" | grep -oE 'stat::number_of_executed_units: *[0-9]+' | grep -oE '[0-9]+$')
rate=$(printf '%s' "$clean_out" | grep -oE 'stat::average_exec_per_sec: *[0-9]+' | grep -oE '[0-9]+$')

if [[ "$status" != "0" ]]; then
  echo "FAIL: the fuzzer found a violating sequence."
  printf '%s\n' "$clean_out" | grep -E 'panicked at|^step [0-9]+:|Test unit written' | head -8
  echo
  echo "Decode it with:"
  echo "  cargo +nightly fuzz fmt --fuzz-dir fuzz $TARGET <artifact>"
  echo "  cargo +nightly fuzz tmin --fuzz-dir fuzz $TARGET <artifact>"
  echo "Then add the minimized sequence to plan_state_fuzz.rs's tests, so the"
  echo "release gate carries it without needing nightly."
  exit 1
fi

# A run that executed nothing is not a pass. libFuzzer exits 0 when it cannot
# build a single input, and that is indistinguishable from a clean sweep unless
# somebody checks.
if [[ "${execs:-0}" -lt 1000 ]]; then
  echo "VACUOUS: only ${execs:-0} inputs executed in ${DURATION}s"
  exit 2
fi

echo
printf '  %s sequences executed (%s/sec), no invariant violated\n' "${execs}" "${rate:-?}"

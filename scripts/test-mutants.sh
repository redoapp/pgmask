#!/usr/bin/env bash
# Mechanical mutation testing, as opposed to the hand-picked table.
#
#   ./scripts/test-mutants.sh [cargo-mutants args...]
#
# `scripts/test-mutations.py` breaks twenty-six guards someone thought to
# protect. That is the same blind spot as an inference suite that only knows the
# spellings it was given: it proves the guards on the list are watched and says
# nothing about the rest. `cargo mutants` mutates every function it can reach.
#
# The first run found three survivors in `analysis.rs` alone that no test
# detected — a `&&` in the context-function `bare` check whose inversion would
# release a user-defined `now(text)`, a `==` in the `COALESCE` rule whose
# inversion releases two unreadable arguments together, and a redundant early
# return that turned out to be an equivalent mutant. Writing the test for the
# second one then exposed a real defect in `grouping_may_reference`: it read an
# integer literal nested in an expression as an ordinal, so
# `GROUP BY coalesce(col, 0)` reported the grouping unbounded and refused an
# honest aggregate.
#
# WHY THE INVOCATION MATTERS
#
# Run with `-- --lib` and `catalog.rs` reports about seventy survivors, nearly
# all of them artefacts: its tests need Postgres and never ran. The number that
# means something needs the whole suite against a real server, which is what
# this script sets up. The same mistake is available in coverage — measuring
# with `PGMASK_ALLOW_SKIP=1` put `catalog.rs` at 62% when it is 88%.
#
# Slow by nature: every mutant is a build plus a test run. Not in the release
# gate for that reason; run it when the guards change.

set -uo pipefail
cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:/opt/homebrew/bin:$PATH"

CONTAINER=pgmask-mutants
PORT=55435

command -v cargo-mutants >/dev/null || {
  echo "cargo-mutants is not installed: cargo install cargo-mutants --locked"
  exit 3
}
command -v podman >/dev/null || { echo "FAIL: podman is required"; exit 3; }

cleanup() {
  [[ "${KEEP:-0}" == "1" ]] || podman rm -f -v "$CONTAINER" >/dev/null 2>&1
}
trap cleanup EXIT

echo "==> starting postgres (trust auth) on :$PORT"
podman rm -f -v "$CONTAINER" >/dev/null 2>&1
# Not `>/dev/null`: when this fails the run dies at "postgres did not start"
# with no way to tell a port clash from an image pull from a busy podman, which
# is the same self-inflicted blindness as sending a proxy log to /dev/null.
if ! podman run -d --name "$CONTAINER" \
      -e POSTGRES_HOST_AUTH_METHOD=trust \
      -p "$PORT":5432 docker.io/library/postgres:17; then
  echo "FAIL: could not start the container (see the error above)"
  exit 1
fi
for _ in $(seq 1 90); do
  podman exec "$CONTAINER" pg_isready -U postgres >/dev/null 2>&1 && break
  sleep 1
done
podman exec "$CONTAINER" pg_isready -U postgres >/dev/null 2>&1 || {
  echo "FAIL: postgres did not become ready; last lines of its log:"
  podman logs "$CONTAINER" 2>&1 | tail -10
  exit 1
}

# Serially, and with the backend reachable: the integration tests rebuild the
# canary schema in the same database, and without PGMASK_TEST_PG they skip —
# which would put us back to measuring the tests that do not need a server.
export PGMASK_TEST_PG="127.0.0.1:$PORT"
# Serial via the environment, not `-- --test-threads=1`. Args after `--` reach
# *every* cargo invocation cargo-mutants makes, including `cargo build`, which
# rejects a test-harness flag — the whole run then dies at the baseline with a
# bare `Usage:` line and zero mutants tested.
export RUST_TEST_THREADS=1

echo "==> mutating the modules that decide whether a value is released"
cargo mutants \
  --file crates/proxy/src/analysis.rs \
  --file crates/proxy/src/catalog.rs \
  --file crates/proxy/src/lineage.rs \
  --file crates/proxy/src/session.rs \
  --timeout 180 \
  "$@"
status=$?

echo
echo "-------------------------------------------------------------"
for f in caught missed timeout unviable; do
  n=$(wc -l < "mutants.out/$f.txt" 2>/dev/null | tr -d ' ')
  printf '  %-10s %s\n' "$f" "${n:-0}"
done
echo "-------------------------------------------------------------"
echo "Survivors are in mutants.out/missed.txt. Each is one of:"
echo "  * a real gap    — the code is right and no test says so; write the test"
echo "  * equivalent    — the mutation changes nothing observable; say why in a"
echo "                    comment on the function, so it is not re-litigated"
echo "  * precision     — it only widens refusal, so no leak; still worth a test,"
echo "                    because over-refusal is how the analytics queries break"
exit "$status"

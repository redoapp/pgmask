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
# Slow by nature: every mutant is a build plus a test run, and there are 827 of
# them. Not in the release gate for that reason; run it when the guards change,
# and expect to leave it overnight.

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

# Free space, checked up front. cargo-mutants copies the whole source tree into
# $TMPDIR and rebuilds in it for every mutant; the copy reached 5.4 GB here. A
# run that fills the disk dies mid-way and — before the accounting below
# existed — still printed a tidy summary. Sharding bounds the copy, so 10 GB is
# enough; without it one run burned 19 GB in 35 mutants.
free_kb=$(df -k "${TMPDIR:-/tmp}" | awk 'NR==2 {print $4}')
if [ "${free_kb:-0}" -lt 10485760 ]; then
  echo "FAIL: only $((free_kb / 1048576)) GB free on ${TMPDIR:-/tmp}; this needs 10."
  echo "      cargo-mutants rebuilds a full copy of the tree per mutant."
  echo "      \`rm -rf target/debug/incremental\` is usually the cheapest 20 GB."
  exit 1
fi

cleanup() {
  [[ "${KEEP:-0}" == "1" ]] || podman rm -f -v "$CONTAINER" >/dev/null 2>&1
  # A crashed run leaves its multi-gigabyte tree copy behind, which is how the
  # disk filled in the first place.
  rm -rf "${TMPDIR:-/tmp}"/cargo-mutants-pgmask-*.tmp 2>/dev/null
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
if ! podman exec "$CONTAINER" pg_isready -U postgres >/dev/null 2>&1; then
  # Both halves of the answer, because they are different problems and the
  # `>/dev/null 2>&1` above hides which one you have. A run failed here with the
  # container's own log reading `database system is ready to accept connections`
  # — so the server was up and it was `podman exec` that could not reach it, and
  # the message said the opposite.
  echo "FAIL: could not reach postgres in $CONTAINER."
  echo "--- what pg_isready said (empty means podman exec itself failed) ---"
  podman exec "$CONTAINER" pg_isready -U postgres 2>&1 | tail -3
  echo "--- is the container even running? ---"
  podman ps -a --filter "name=$CONTAINER" --format '{{.Names}} {{.Status}}' 2>&1 | tail -2
  echo "--- the server's own log ---"
  podman logs "$CONTAINER" 2>&1 | tail -6
  exit 1
fi

# Serially, and with the backend reachable: the integration tests rebuild the
# canary schema in the same database, and without PGMASK_TEST_PG they skip —
# which would put us back to measuring the tests that do not need a server.
export PGMASK_TEST_PG="127.0.0.1:$PORT"
# Serial via the environment, not `-- --test-threads=1`. Args after `--` reach
# *every* cargo invocation cargo-mutants makes, including `cargo build`, which
# rejects a test-harness flag — the whole run then dies at the baseline with a
# bare `Usage:` line and zero mutants tested.
export RUST_TEST_THREADS=1
# No incremental cache. Every mutant is a one-shot build, so the cache is never
# reused — and it is not free: deleting `target/debug/incremental` and starting
# a run put 12 GB of it straight back, which was most of the 19 GB that killed
# the run at mutant 35.
export CARGO_INCREMENTAL=0

# Sharded, because the scratch copy is the binding constraint.
#
# cargo-mutants rebuilds a full copy of the tree per mutant and the copy only
# grows: it reached 5.4 GB on one run and burned 19 GB in 35 mutants on the
# next, which is what killed both. Sharding bounds it — each shard gets a fresh
# copy, and the copy is deleted before the next one starts. The cost is one
# extra baseline build per shard.
#
# Set SHARDS=1 for the old single-pass behaviour when disk is plentiful.
#
# 827 mutants as of 2026-08-11 — 494 before `protocol.rs` and `mask.rs` joined
# the list. Every one is a build plus a test run, so a complete campaign is an
# overnight job, not something to slip into a working session.
#
# SHARD SIZE IS A DISK BUDGET, NOT A PROGRESS PREFERENCE
#
# Measured: a shard of 65 mutants took the free space from 13 GB to 2 GB. The
# scratch copy is rebuilt per mutant and its target directory accumulates, so
# the cost is roughly **0.17 GB per mutant** and it is only reclaimed when the
# shard ends. Twelve shards was 69 mutants each — about 12 GB — and a run died
# mid-shard with the between-shard check never getting a turn.
#
# Twenty shards is ~41 mutants, about 7 GB, which fits inside the floor below
# with room for a `cargo build` happening alongside. If you raise the mutant
# count, raise this too.
SHARDS=${SHARDS:-20}
merged=mutants.out.merged
rm -rf "$merged"; mkdir -p "$merged"
: > "$merged/caught.txt"; : > "$merged/missed.txt"
: > "$merged/timeout.txt"; : > "$merged/unviable.txt"
planned_total=0
status=0

# `protocol.rs` and `mask.rs` were absent from this list until 2026-08-11, and
# the seventh disclosure was in `protocol.rs`. I went looking there *because* I
# had written down that nothing mutated it a few hours earlier.
#
# `protocol.rs` holds `LEAKY_FIELDS` and the error/notice scrubbing — the
# difference between a unique violation saying `Key (email)=(alice@example.com)`
# and saying nothing. `mask.rs` is where the value is actually rewritten. Both
# decide what reaches the client, which is the criterion the other four are on
# this list for.
echo "==> mutating the modules that decide whether a value is released"
echo "    in $SHARDS shards, cleaning the scratch copy between each"
# 0-indexed. cargo-mutants requires k < n, so `seq 1 $SHARDS` asked for shard
# 20/20 — rejected with "shard k must be less than n" — and never asked for
# shard 0 at all. Two shards' worth, about a tenth of the campaign, untested.
for shard in $(seq 0 $((SHARDS - 1))); do
  echo "==> shard $((shard + 1)) of $SHARDS (--shard $shard/$SHARDS)"
  cargo mutants \
    --file crates/proxy/src/analysis.rs \
    --file crates/proxy/src/catalog.rs \
    --file crates/proxy/src/lineage.rs \
    --file crates/proxy/src/session.rs \
    --file crates/proxy/src/protocol.rs \
    --file crates/proxy/src/mask.rs \
    --shard "$shard/$SHARDS" \
    --timeout 180 \
    "$@"
  shard_status=$?
  [ "$shard_status" = 0 ] || status=$shard_status

  for f in caught missed timeout unviable; do
    cat "mutants.out/$f.txt" >> "$merged/$f.txt" 2>/dev/null
  done
  # How many this shard was *given*, which is what it must account for.
  n=$(python3 -c 'import json;print(len(json.load(open("mutants.out/mutants.json"))))' 2>/dev/null || echo 0)
  planned_total=$((planned_total + n))

  # A shard that produced no mutants did not run, and the accounting at the end
  # cannot see it: planned and attempted are both zero for it, so the totals
  # still agree and a campaign missing a tenth of its mutants reports
  # "814 of 814". That is the exact vacuity that check exists to prevent,
  # reached through the one case it did not cover — which is how `--shard 20/20`
  # went unnoticed.
  if [ "$n" = 0 ]; then
    echo "FAIL: shard $shard/$SHARDS produced no mutants, so it did not run."
    echo "      Its zero is invisible to the planned-vs-attempted check at the"
    echo "      end, which is why this is caught here instead."
    status=1
    break
  fi

  # The whole point of sharding: reclaim before the next shard starts.
  rm -rf "${TMPDIR:-/tmp}"/cargo-mutants-pgmask-*.tmp 2>/dev/null
  free_gb=$(df -g "${TMPDIR:-/tmp}" | awk 'NR==2 {print $4}')
  echo "    shard $shard done; ${free_gb}GB free"
  # A shard costs about 7 GB at the default size and reclaims none of it until
  # it ends, so this floor has to cover a whole shard rather than a comfortable
  # margin. Set at 6 GB it never got a turn: the shard that emptied the disk
  # went from 13 GB to 2 GB without an opportunity to check.
  if [ "${free_gb:-99}" -lt 15 ]; then
    echo "FAIL: ${free_gb}GB free after shard $shard — stopping rather than dying mid-shard."
    echo "      A shard needs ~7GB and reclaims it only at the end."
    status=1
    break
  fi
done

# Report against the merged results, not the last shard's.
rm -rf mutants.out.shardlast && mv mutants.out mutants.out.shardlast 2>/dev/null
cp -r "$merged" mutants.out
python3 -c "import json,sys;json.dump([0]*$planned_total, open('mutants.out/mutants.json','w'))"

echo
echo "-------------------------------------------------------------"
accounted=0
for f in caught missed timeout unviable; do
  n=$(wc -l < "mutants.out/$f.txt" 2>/dev/null | tr -d ' ')
  n=${n:-0}
  accounted=$((accounted + n))
  printf '  %-10s %s\n' "$f" "$n"
done
# How many were planned, against how many have an outcome.
#
# THIS IS THE POINT OF THE BLOCK. Two runs died part-way — one on a full disk —
# and both printed the four counts above and nothing else, so `45 survivors`
# was carried in docs/safety-assessment.md as if it were the whole picture when
# 200 of 493 mutants had never been attempted. A partial mutation run is worse
# than none: it reads as coverage.
planned=$(python3 -c 'import json;print(len(json.load(open("mutants.out/mutants.json"))))' 2>/dev/null)
printf '  %-10s %s of %s\n' "attempted" "$accounted" "${planned:-?}"
echo "-------------------------------------------------------------"
if [ -n "${planned:-}" ] && [ "$accounted" != "$planned" ]; then
  echo
  echo "FAIL: this run is INCOMPLETE — $((planned - accounted)) mutants were never"
  echo "      attempted, so missed.txt is not the survivor list. Do not triage it."
  echo "      Check the error above; a full disk is the usual cause."
  exit 1
fi
echo "Survivors are in mutants.out/missed.txt. Each is one of:"
echo "  * a real gap    — the code is right and no test says so; write the test"
echo "  * equivalent    — the mutation changes nothing observable; say why in a"
echo "                    comment on the function, so it is not re-litigated"
echo "  * precision     — it only widens refusal, so no leak; still worth a test,"
echo "                    because over-refusal is how the analytics queries break"
exit "$status"

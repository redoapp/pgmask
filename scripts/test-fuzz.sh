#!/usr/bin/env bash
# Replay generated SQL through pgmask and assert no masked value escapes.
#
#   ./scripts/test-fuzz.sh [statements-per-seed] [seeds] [parallelism]
#
# Queries come from sqlsmith, which reads the live schema and generates valid
# random SQL — shapes nobody would write by hand, which is the closest thing to
# an adversary available when nobody else reviews the analysis rules.
#
# Three things make a pass mean something:
#
#   the oracle needs no expected output  every masked column holds a token, or
#                                        a value whose shape the masked form
#                                        never has, so a leak is self-evident
#   a direct control                     every query also runs straight at
#                                        Postgres; a run where that saw no
#                                        masked values either is VACUOUS, not a
#                                        pass
#   a poison run first                   a catalog with masking deliberately
#                                        removed, which the oracle MUST flag.
#                                        A test that has never failed is not
#                                        known to work.

set -uo pipefail
cd "$(dirname "$0")/.."

PER_SEED="${1:-3000}"
SEEDS="${2:-8}"
PARALLEL="${3:-4}"
PG_PORT=55433   # not 55432: verify.sh keeps a container there under KEEP=1
PROXY_PORT=6470
POISON_PORT=6471
METRICS_PORT=9470
CONTAINER=pgmask-fuzz
export PGPASSWORD=demo

# Exit 3, not 0. This script is the whole generated-SQL campaign — poison run,
# mirror oracle, role bleed, DDL churn, binary format — and on a machine without
# sqlsmith the old `exit 0` reported all of it as passing while running none of
# it. A suite that reports success by doing nothing is the exact failure this
# repo keeps finding; it should not be in the harness that looks for it.
# Set PGMASK_ALLOW_SKIP=1 to opt into the old behaviour deliberately.
if ! command -v sqlsmith >/dev/null; then
  echo "sqlsmith is not installed (brew install sqlsmith)"
  if [[ "${PGMASK_ALLOW_SKIP:-0}" == "1" ]]; then
    echo "PGMASK_ALLOW_SKIP=1 — skipping, and this run proves nothing"
    exit 0
  fi
  echo "FAIL: refusing to report success for a campaign that did not run."
  exit 3
fi

cleanup() {
  for pid in ${PROXY_PID:-} ${POISON_PID:-} ${BIN_PID:-} ${ROLE_PID:-} ${DDL_PID:-} ${PROXY_PIDS[@]:-}; do kill "$pid" 2>/dev/null; done
  [[ "${KEEP:-0}" == "1" ]] || podman rm -f -v "$CONTAINER" >/dev/null 2>&1
}
trap cleanup EXIT

echo "==> postgres + fixture"
podman rm -f -v "$CONTAINER" >/dev/null 2>&1
podman run -d --name "$CONTAINER" -e POSTGRES_PASSWORD=demo -e POSTGRES_DB=fuzzdb \
  -p "$PG_PORT":5432 docker.io/library/postgres:17 >/dev/null 2>&1
for _ in $(seq 1 40); do
  psql -h localhost -p "$PG_PORT" -U postgres -d fuzzdb -tAc 'SELECT 1' >/dev/null 2>&1 && break
  sleep 1
done
psql -h localhost -p "$PG_PORT" -U postgres -d fuzzdb -q -v ON_ERROR_STOP=1 \
  -f examples/fuzz/schema.sql >/dev/null 2>&1 || { echo "FATAL: fixture failed to load"; exit 1; }
# Roles live in their own file because there is no portable spelling of
# "create it if absent" across Postgres and CockroachDB. Applied without
# ON_ERROR_STOP so a kept container is not an error.
psql -h localhost -p "$PG_PORT" -U postgres -d fuzzdb -q \
  -f examples/fuzz/roles.sql >/dev/null 2>&1
psql -h localhost -p "$PG_PORT" -U support_sam -d fuzzdb -tAc 'SELECT 1' >/dev/null 2>&1 \
  || { echo "FATAL: support_sam cannot log in — the role-bleed check would not run"; exit 1; }
cargo build --release -q || exit 1


gen() { # seed count outfile
  sqlsmith --target="postgresql://postgres:demo@localhost:$PG_PORT/fuzzdb" \
    --dry-run --exclude-catalog --seed="$1" --max-queries="$2" >"$3" 2>/dev/null
}

# --- 1. Prove the oracle can fail -------------------------------------------
#
# Unmask the 20 `redact` columns as well as the two shaped ones. Those carry the
# CANARY token directly, so the oracle fires on any query that reads one.
#
# It used to unmask only `ip-prefix` and `date-year` — two columns out of sixty —
# and that made the control depend on a random corpus happening to touch them.
# Adding one view to the fixture changed what sqlsmith generates for the fixed
# seed (it enumerates relations from the catalog), the new corpus missed both
# columns, and the control reported the oracle as broken. The control's job is
# to prove detection works, so it should not be a subtle test.
echo "==> poison run: masking removed, the oracle must fire"
sed -e 's/^mask = "ip-prefix"/mask = "none"/' -e 's/^mask = "date-year"/mask = "none"/' \
    -e 's/^mask = "redact"/mask = "none"/' \
    -e "s|55432|$PG_PORT|g" \
    -e "s/^listen = .*/listen = \"127.0.0.1:$POISON_PORT\"/" \
    -e 's/^metrics_listen.*//' examples/fuzz/catalog.toml > /tmp/pgmask-poison.toml
./target/release/pgmask /tmp/pgmask-poison.toml >/tmp/pgmask-poison.log 2>&1 &
POISON_PID=$!
sleep 2
gen 11 1200 /tmp/pgmask-poison.sql
if ! EXPECT_LEAKS=1 \
     DIRECT_URL="postgres://postgres:demo@localhost:$PG_PORT/fuzzdb" \
     PROXY_URL="postgres://postgres:demo@localhost:$POISON_PORT/fuzzdb" \
     ./target/release/fuzz /tmp/pgmask-poison.sql >/tmp/poison.out 2>&1; then
  echo "FAIL: the oracle did not fire on a deliberately unmasked catalog."
  echo "      Everything below would have been a false clean sweep."
  tail -6 /tmp/poison.out
  exit 1
fi
echo "    $(grep -o 'must fire on this run ([0-9]*' /tmp/poison.out | grep -o '[0-9]*') leaks detected, as required"
kill "$POISON_PID" 2>/dev/null; POISON_PID=""

# --- 1b. Binary result format ------------------------------------------------
# Everything else here speaks the simple query protocol, which is text-only.
# Coverage showed no end-to-end suite had ever asked for binary results, and the
# first one that did found two bugs.
echo "==> binary result format"
sed -e "s|55432|$PG_PORT|g" -e "s|^listen = .*|listen = \"127.0.0.1:$POISON_PORT\"|" \
    -e 's/^metrics_listen.*//' examples/fuzz/catalog.toml > /tmp/pgmask-binary.toml
./target/release/pgmask /tmp/pgmask-binary.toml >/tmp/pgmask-binary.log 2>&1 &
BIN_PID=$!
sleep 2
if ! DIRECT_URL="postgres://postgres:demo@localhost:$PG_PORT/fuzzdb" \
     PROXY_URL="postgres://postgres:demo@localhost:$POISON_PORT/fuzzdb" \
     ./target/release/binary; then
  kill "$BIN_PID" 2>/dev/null
  exit 1
fi
kill "$BIN_PID" 2>/dev/null

# --- 1b2. The shape corpus over the extended protocol ------------------------
# `binary` covers the extended path with a dozen hand-written assertions; this
# covers it with a generated corpus and the canary oracle. Postgres agrees with
# itself across protocols where CockroachDB does not, so this is the control
# that says so rather than an assumption.
echo "==> extended protocol: generated shapes through Parse/Bind/Execute"
./target/release/shapegen 4242 600 > /tmp/pgmask-ext.sql
sed -e "s|55432|$PG_PORT|g" -e "s|^listen = .*|listen = \"127.0.0.1:$POISON_PORT\"|" \
    -e 's|^lineage = .*|lineage = "allow"|' \
    -e 's/^metrics_listen.*//' examples/fuzz/catalog.toml > /tmp/pgmask-ext.toml
./target/release/pgmask /tmp/pgmask-ext.toml >/tmp/pgmask-ext.log 2>&1 &
BIN_PID=$!
sleep 2
ext_env=(DIRECT_URL="postgres://postgres:demo@localhost:$PG_PORT/fuzzdb"
         PROXY_URL="postgres://postgres:demo@localhost:$POISON_PORT/fuzzdb")
if ! env "${ext_env[@]}" ./target/release/extended /tmp/pgmask-ext.sql >/tmp/pgmask-ext.out 2>&1; then
  echo "FAIL: the extended-protocol replay found a leak"
  tail -20 /tmp/pgmask-ext.out
  kill "$BIN_PID" 2>/dev/null
  exit 1
fi
grep -E '^RESULT' /tmp/pgmask-ext.out | sed 's/^/    /'
kill "$BIN_PID" 2>/dev/null

sed -e 's/^mask = "redact"/mask = "none"/' /tmp/pgmask-ext.toml > /tmp/pgmask-ext-poison.toml
./target/release/pgmask /tmp/pgmask-ext-poison.toml >/tmp/pgmask-ext-poison.log 2>&1 &
BIN_PID=$!
sleep 2
if ! env "${ext_env[@]}" EXPECT_LEAKS=1 \
     ./target/release/extended /tmp/pgmask-ext.sql >/tmp/pgmask-ext-poison.out 2>&1; then
  echo "FAIL: masking was removed and the extended oracle saw nothing"
  tail -8 /tmp/pgmask-ext-poison.out
  kill "$BIN_PID" 2>/dev/null
  exit 1
fi
echo "    poison run tripped the extended oracle, as required"
kill "$BIN_PID" 2>/dev/null

# --- 1c. Per-principal masking under concurrency -----------------------------
# Sessions share one Arc<Policy> and one catalog snapshot while resolving masks
# per principal. A plan escaping its session would be a disclosure invisible to
# any single-principal test.
echo "==> per-principal masking under concurrency"
./target/release/pgmask "/tmp/pgmask-binary.toml" >/tmp/pgmask-roles.log 2>&1 &
ROLE_PID=$!
sleep 2
role_env=(DIRECT_URL="postgres://postgres:demo@localhost:$PG_PORT/fuzzdb"
          PROXY_URL="postgres://postgres:demo@localhost:$POISON_PORT/fuzzdb")
# Prove it can fail before trusting that it did not.
if env "${role_env[@]}" POISON=1 ./target/release/roles 6 40 >/tmp/roles-poison.out 2>&1; then
  echo "FAIL: the role check passed with deliberately wrong expectations."
  kill "$ROLE_PID" 2>/dev/null
  exit 1
fi
# Non-zero is not enough: a run where every session failed to *connect* also
# exits non-zero, and did, reporting a broken fixture as a working oracle. The
# poison run has to have detected actual violations.
poison_violations=$(grep -oE 'VIOLATIONS +[0-9]+' /tmp/roles-poison.out | grep -oE '[0-9]+' || echo 0)
if [[ "${poison_violations:-0}" -eq 0 ]]; then
  echo "FAIL: the poison run exited non-zero but detected no violations —"
  echo "      it failed for some other reason and is proving nothing."
  grep -E 'session failed|Error' /tmp/roles-poison.out | head -3
  kill "$ROLE_PID" 2>/dev/null
  exit 1
fi
echo "    poison run detected $poison_violations violations, as required"
if ! env "${role_env[@]}" ./target/release/roles 24 300; then
  kill "$ROLE_PID" 2>/dev/null
  exit 1
fi
kill "$ROLE_PID" 2>/dev/null

# --- 1d. DDL churn while traffic runs ----------------------------------------
# OIDs change on DROP/CREATE and the catalog refreshes on a timer, so there is a
# window where a relation the proxy knew is gone and its replacement is
# unknown. Unknown must mean masked; the risk is that it briefly means allowed.
echo "==> DDL churn during traffic"
sed -e "s|55432|$PG_PORT|g" -e "s|^listen = .*|listen = \"127.0.0.1:$POISON_PORT\"|" \
    -e 's/^catalog_refresh_seconds.*/catalog_refresh_seconds = 2/' \
    -e 's/^metrics_listen.*//' examples/fuzz/catalog.toml > /tmp/pgmask-ddl.toml
./target/release/pgmask /tmp/pgmask-ddl.toml >/tmp/pgmask-ddl.log 2>&1 &
DDL_PID=$!
sleep 2
( for _ in $(seq 1 12); do
    psql -h localhost -p "$PG_PORT" -U postgres -d fuzzdb -q \
      -c 'DROP VIEW IF EXISTS fz.v_union; CREATE VIEW fz.v_union AS SELECT id, a FROM fz.t1 UNION ALL SELECT id, a FROM fz.t2;' \
      >/dev/null 2>&1
    sleep 0.4
  done ) &
CHURN_PID=$!
churn_leaks=0
churn_reads=0
for _ in $(seq 1 60); do
  # A recreated view gets a new OID. Until the catalog catches up the proxy has
  # never heard of it, and "never heard of it" has to mean masked.
  out=$(psql -h localhost -p "$POISON_PORT" -U postgres -d fuzzdb -X -tAq \
        -c 'SELECT a FROM fz.v_union LIMIT 3;' 2>&1 || true)
  churn_reads=$((churn_reads + 1))
  case "$out" in *CANARY*) churn_leaks=$((churn_leaks + 1));; esac
done
wait "$CHURN_PID" 2>/dev/null
kill "$DDL_PID" 2>/dev/null
echo "    $churn_reads reads across 12 view recreations, $churn_leaks leaked"
[[ "$churn_leaks" -eq 0 ]] || { echo "FAIL: a masked column was readable while the catalog was stale"; exit 1; }

# --- 2. Generate corpora in parallel ----------------------------------------
echo "==> generating $SEEDS x $PER_SEED statements ($PARALLEL at a time)"
# Wait only on jobs we started here. A bare `wait` also waits for the proxy,
# which never exits — the first version of this script hung forever on it.
pids=()
for s in $(seq 1 "$SEEDS"); do
  gen $((s * 7919)) "$PER_SEED" "/tmp/pgmask-fuzz-$s.sql" &
  pids+=($!)
  if (( ${#pids[@]} >= PARALLEL )); then wait "${pids[0]}"; pids=("${pids[@]:1}"); fi
done
for pid in "${pids[@]}"; do wait "$pid"; done

# --- 3. Replay each corpus against every policy combination -----------------
#
# Volume of SQL has diminishing returns; the same 24k statements find the same
# nothing. Policy combinations do not: `opaque = "mask"` serves NULLs where
# "reject" refuses, and `lineage = "allow"` is the path where a miss is a
# disclosure. Each is a different route through plan_for, and the oracle is
# identical for all of them.
echo "==> replaying ($PARALLEL concurrent sessions) across policy combinations"
# The fourth is a different question. The first three ask "did anything leak";
# mirror masks nothing and asks "did the proxy change anything it should not
# have" — masking the wrong column, losing a row, mangling an encoding. A
# canary oracle is structurally blind to all of those.
CONFIGS=("lineage=allow opaque=reject" "lineage=refuse opaque=reject" \
         "lineage=allow opaque=mask" "mirror")
port=$PROXY_PORT
metrics=$METRICS_PORT
declare -a PROXY_PIDS=()
cfg_index=0
tot_stmt=0; tot_served=0; tot_refused=0; tot_err=0; tot_control=0; tot_leaks=0; bad=0

for cfg in "${CONFIGS[@]}"; do
  mirror_env=""
  if [[ "$cfg" == "mirror" ]]; then
    # Nothing masked, and opaque=reject so any query with an expression is
    # refused rather than nulled — which leaves exactly the queries whose
    # output all has provenance, the ones that must come back untouched.
    sed -E -e "s|^listen = .*|listen = \"127.0.0.1:$port\"|" \
           -e 's|^mask = "(.*)"$|mask = "none"|' \
           -e 's|^type = "(.*)"$|mask = "none"|' \
           -e 's|^unclassified = .*|unclassified = "allow"|' \
           -e 's|^opaque = .*|opaque = "reject"|' \
           -e "s|55432|$PG_PORT|g" \
           -e "s|^metrics_interval_seconds.*|metrics_interval_seconds = 0\nmetrics_listen = \"127.0.0.1:$metrics\"|" \
           examples/fuzz/catalog.toml > "/tmp/pgmask-fuzz-cfg$cfg_index.toml"
    mirror_env="EXPECT_MIRROR=1"
  else
  lin="${cfg#lineage=}"; lin="${lin%% *}"
  opq="${cfg##*opaque=}"
  sed -e "s|^listen = .*|listen = \"127.0.0.1:$port\"|" \
      -e "s|^lineage = .*|lineage = \"$lin\"|" \
      -e "s|^opaque = .*|opaque = \"$opq\"|" \
      -e "s|^metrics_interval_seconds.*|metrics_interval_seconds = 0\nmetrics_listen = \"127.0.0.1:$metrics\"|" \
      -e "s|55432|$PG_PORT|g" \
      examples/fuzz/catalog.toml > "/tmp/pgmask-fuzz-cfg$cfg_index.toml"
  fi
  ./target/release/pgmask "/tmp/pgmask-fuzz-cfg$cfg_index.toml" >"/tmp/pgmask-fuzz-cfg$cfg_index.log" 2>&1 &
  PROXY_PIDS+=($!)
  sleep 2

  pids=()
  for s in $(seq 1 "$SEEDS"); do
    ( env $mirror_env DIRECT_URL="postgres://postgres:demo@localhost:$PG_PORT/fuzzdb" \
      PROXY_URL="postgres://postgres:demo@localhost:$port/fuzzdb" \
      ./target/release/fuzz "/tmp/pgmask-fuzz-$s.sql" >"/tmp/pgmask-fuzz-c$cfg_index-$s.out" 2>&1; \
      echo $? > "/tmp/pgmask-fuzz-c$cfg_index-$s.status" ) &
    pids+=($!)
    if (( ${#pids[@]} >= PARALLEL )); then wait "${pids[0]}"; pids=("${pids[@]:1}"); fi
  done
  for pid in "${pids[@]}"; do wait "$pid"; done

  c_stmt=0; c_served=0; c_ref=0; c_err=0; c_ctl=0; c_leak=0
  for s in $(seq 1 "$SEEDS"); do
    line=$(grep '^RESULT' "/tmp/pgmask-fuzz-c$cfg_index-$s.out" 2>/dev/null)
    status=$(cat "/tmp/pgmask-fuzz-c$cfg_index-$s.status" 2>/dev/null || echo 1)
    if [[ -z "$line" ]]; then echo "  [$cfg] seed $s produced no result (exit $status)"; bad=1; continue; fi
    eval "${line#RESULT }"
    c_stmt=$((c_stmt+statements)); c_served=$((c_served+served)); c_ref=$((c_ref+refused))
    c_err=$((c_err+errors)); c_ctl=$((c_ctl+control)); c_leak=$((c_leak+leaks))
    [[ "$status" == "0" ]] || bad=1
  done

  # Independent count, from the proxy rather than from us.
  scraped=$(curl -s --max-time 10 "http://127.0.0.1:$metrics/metrics" \
    | awk -F' ' '/^pgmask_rejections_total\{/ {t+=$2} END {print t+0}')
  agree="agree"
  if [[ "$c_ref" != "$scraped" ]]; then agree="DISAGREE (proxy says $scraped)"; bad=1; fi

  if [[ "$cfg" == "mirror" ]]; then
    cmp=$(grep -h 'compared to direct' /tmp/pgmask-fuzz-c$cfg_index-*.out | awk '{s+=$4} END {print s+0}')
    printf '  %-28s compared %5d  divergences %3d  [%s]\n' "$cfg (masks nothing)" "$cmp" "$c_leak" "$agree"
  else
    printf '  %-28s served %5d  refused %5d  leaks %3d  [%s]\n' "$cfg" "$c_served" "$c_ref" "$c_leak" "$agree"
  fi
  tot_stmt=$((tot_stmt+c_stmt)); tot_served=$((tot_served+c_served)); tot_refused=$((tot_refused+c_ref))
  tot_err=$((tot_err+c_err)); tot_control=$((tot_control+c_ctl)); tot_leaks=$((tot_leaks+c_leak))
  port=$((port+2)); metrics=$((metrics+1)); cfg_index=$((cfg_index+1))
done

echo
echo "aggregate over $SEEDS seeds x ${#CONFIGS[@]} policy combinations"
echo "------------------------------------------------------------"
printf '  statements replayed   %8d\n' "$tot_stmt"
printf '  served                %8d\n' "$tot_served"
printf '  refused by pgmask     %8d\n' "$tot_refused"
printf '  postgres error        %8d\n' "$tot_err"
printf '  masked values visible %8d  without the proxy\n' "$tot_control"
printf '  LEAKED                %8d\n' "$tot_leaks"

rows=$(psql -h localhost -p "$PG_PORT" -U postgres -d fuzzdb -tAc 'SELECT count(*) FROM fz.t1')
[[ "$rows" == "40" ]] || { echo "FAIL: fixture changed during the run (fz.t1 = $rows, expected 40)"; exit 1; }
echo "  fixture intact, harness and proxy agree"

[[ "$tot_leaks" -eq 0 && "$bad" -eq 0 ]] || exit 1
[[ "$tot_control" -gt 0 ]] || { echo "VACUOUS: never reached a masked value"; exit 2; }
echo
echo "$tot_control masked values were readable without the proxy and none through it."

#!/usr/bin/env bash
# The generated-SQL campaign, against CockroachDB.
#
#   ./scripts/test-fuzz-cockroach.sh [statements] [seeds]
#
# sqlsmith cannot read a CockroachDB schema — it loads pg_catalog and dies at
# `Generating indexes...unknown type:`. Generating against Postgres and
# replaying was the obvious workaround and it does not work either: 395 of 400
# statements errored, because sqlsmith draws functions and operators from the
# target's catalog and Postgres has thousands CockroachDB lacks. A campaign that
# errors on 98.75% of its corpus is vacuous however it reports.
#
# The corpus therefore comes from `shapegen`, which generates compositions of
# relational operators in SQL both engines accept. That is also the better test:
# what decides masking is whether per-field provenance can be believed, which is
# a property of a query's shape — how many source columns reach one output field
# — and not of which scalar function sits on top. Both leaks found so far were
# shapes, and one of them was a shape hidden inside a view.
#
# The oracle is the same one the Postgres campaign uses: every value in the
# fixture carries the token CANARY, masking rewrites all of them, so a CANARY
# reaching the client is a leak whatever route it took.

set -uo pipefail
cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:/opt/homebrew/bin:$PATH"

PER_SEED="${1:-1500}"
SEEDS="${2:-3}"
CRDB_PORT=26262        # the engine under test
PROXY_PORT=6460
POISON_PORT=6461
CRDB=pgmask-fuzz-crdb
CRDB_VERSION="${CRDB_VERSION:-v25.4.14}"

cleanup() {
  for pid in ${PROXY_PID:-} ${POISON_PID:-}; do kill "$pid" 2>/dev/null; done
  [[ "${KEEP:-0}" == "1" ]] || podman rm -f "$CRDB" >/dev/null 2>&1
}
trap cleanup EXIT

command -v podman >/dev/null || { echo "FAIL: podman is required"; exit 3; }

echo "==> starting CockroachDB"
podman rm -f "$CRDB" >/dev/null 2>&1
podman run -d --name "$CRDB" -p "$CRDB_PORT":26257 \
  "docker.io/cockroachdb/cockroach:$CRDB_VERSION" start-single-node --insecure \
  --accept-sql-without-tls >/dev/null 2>&1

export PGPASSWORD=demo
CROOT="postgresql://root@localhost:$CRDB_PORT/defaultdb?sslmode=disable"
CDB="postgresql://root@localhost:$CRDB_PORT/fuzzdb?sslmode=disable"

for _ in $(seq 1 60); do psql -w "$CROOT" -tAc 'select 1' >/dev/null 2>&1 && break; sleep 2; done
psql -w "$CROOT" -tAc 'select 1' >/dev/null 2>&1 || { echo "FAIL: cockroachdb did not start"; exit 1; }

got=$(psql -w "$CROOT" -X -tAc 'select version()' | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' | head -1)
[[ "$got" == "$CRDB_VERSION" ]] || { echo "FAIL: wanted $CRDB_VERSION, got $got"; exit 1; }

echo "==> loading the fixture"
psql -w "$CROOT" -q -c 'CREATE DATABASE IF NOT EXISTS fuzzdb' >/dev/null 2>&1
psql -w "$CDB" -q -v ON_ERROR_STOP=1 -f examples/fuzz/schema.sql >/dev/null 2>&1 \
  || { echo "FAIL: fixture did not load on cockroachdb"; exit 1; }

# The fixture must actually hold rows. A campaign against empty tables cannot
# leak anything and would pass while testing nothing.
n=$(psql -w "$CDB" -X -tAc 'SELECT count(*) FROM fz.people' 2>/dev/null)
[[ "$n" == "60" ]] || { echo "FAIL: fixture has '$n' people rows, expected 60"; exit 1; }

cargo build --release -q || exit 1

echo "==> generating $((SEEDS * PER_SEED)) query shapes"
for s in $(seq 1 "$SEEDS"); do
  ./target/release/shapegen $((s * 7919)) "$PER_SEED" >"/tmp/crdb-fuzz-$s.sql"
done
generated=$(cat /tmp/crdb-fuzz-*.sql | grep -c ';' || true)
[[ "$generated" -gt 100 ]] || { echo "FAIL: only $generated statements generated"; exit 1; }
echo "    $generated statements"

mkcfg() { # port outfile [extra sed]
  sed -e "s|^listen = .*|listen = \"127.0.0.1:$1\"|" \
      -e "s|^backend = .*|backend = \"127.0.0.1:$CRDB_PORT\"|" \
      -e "s|^catalog_dsn = .*|catalog_dsn = \"$CDB\"|" \
      -e 's|^metrics_listen.*||' \
      ${3:+-e "$3"} \
      examples/fuzz/catalog.toml > "$2"
}

# --- the oracle must be able to fail ----------------------------------------
# With two masks removed the campaign has to trip. A run that reports nothing
# when masking is off is a run that is not looking, and that failure mode has
# already happened twice in this repo.
echo "==> poison run: masking removed, the oracle must fire"
mkcfg "$POISON_PORT" /tmp/crdb-fuzz-poison.toml
sed -i.bak -e 's/^mask = "ip-prefix"/mask = "none"/' -e 's/^mask = "date-year"/mask = "none"/' \
  /tmp/crdb-fuzz-poison.toml
./target/release/pgmask /tmp/crdb-fuzz-poison.toml >/tmp/crdb-fuzz-poison.log 2>&1 &
POISON_PID=$!
sleep 3
if DIRECT_URL="$CDB" PROXY_URL="postgresql://root@localhost:$POISON_PORT/fuzzdb?sslmode=disable" \
   EXPECT_LEAKS=1 ./target/release/fuzz "/tmp/crdb-fuzz-1.sql" >/tmp/crdb-poison.out 2>&1; then
  echo "    poison run tripped the oracle, as required"
else
  echo "FAIL: masking was removed and nothing leaked — the oracle is not working"
  tail -15 /tmp/crdb-poison.out
  exit 1
fi
kill "$POISON_PID" 2>/dev/null; POISON_PID=""

# --- binary result format ----------------------------------------------------
# Everything else here speaks simple query, which is text-only. This is also
# where the two engines' integer defaults surfaced: a bare `int` is int4 on
# Postgres and int8 on CockroachDB, so the fixture had different column types
# per engine and a typed driver could not read both. Widths are explicit now,
# and int8 gained its first end-to-end coverage as a result.
echo "==> binary result format"
mkcfg "$POISON_PORT" /tmp/crdb-binary.toml
./target/release/pgmask /tmp/crdb-binary.toml >/tmp/crdb-binary.log 2>&1 &
POISON_PID=$!
sleep 3
if ! DIRECT_URL="$CDB" PROXY_URL="postgresql://root@localhost:$POISON_PORT/fuzzdb?sslmode=disable" \
     ./target/release/binary; then
  kill "$POISON_PID" 2>/dev/null
  exit 1
fi
kill "$POISON_PID" 2>/dev/null; POISON_PID=""

# --- the same corpus over the extended protocol -------------------------------
# The two protocols do not agree on this engine — CockroachDB reports the first
# branch's provenance for a set operation on the simple-query path and zero for
# the same statement under Describe. Testing one of them is testing half.
echo "==> extended protocol: the same shapes through Parse/Bind/Execute"
mkcfg "$POISON_PORT" /tmp/crdb-ext.toml "s|^lineage = .*|lineage = \"allow\"|"
./target/release/pgmask /tmp/crdb-ext.toml >/tmp/crdb-ext.log 2>&1 &
POISON_PID=$!
sleep 3
ext_url="postgresql://root@localhost:$POISON_PORT/fuzzdb?sslmode=disable"
if ! DIRECT_URL="$CDB" PROXY_URL="$ext_url" \
     ./target/release/extended "/tmp/crdb-fuzz-1.sql" >/tmp/crdb-ext.out 2>&1; then
  echo "FAIL: the extended-protocol replay found a leak"
  tail -20 /tmp/crdb-ext.out
  kill "$POISON_PID" 2>/dev/null
  exit 1
fi
grep -E '^RESULT' /tmp/crdb-ext.out | sed 's/^/    /'
kill "$POISON_PID" 2>/dev/null; POISON_PID=""

# And it has to be able to fail, like every other oracle here.
sed -e 's/^mask = "redact"/mask = "none"/' /tmp/crdb-ext.toml > /tmp/crdb-ext-poison.toml
./target/release/pgmask /tmp/crdb-ext-poison.toml >/tmp/crdb-ext-poison.log 2>&1 &
POISON_PID=$!
sleep 3
if ! DIRECT_URL="$CDB" PROXY_URL="$ext_url" EXPECT_LEAKS=1 \
     ./target/release/extended "/tmp/crdb-fuzz-1.sql" >/tmp/crdb-ext-poison.out 2>&1; then
  echo "FAIL: masking was removed and the extended oracle saw nothing"
  tail -8 /tmp/crdb-ext-poison.out
  kill "$POISON_PID" 2>/dev/null
  exit 1
fi
echo "    poison run tripped the extended oracle, as required"
kill "$POISON_PID" 2>/dev/null; POISON_PID=""

# --- the campaign -----------------------------------------------------------
# Two policy combinations rather than the four Postgres gets. `opaque` and
# `lineage` are engine-independent decisions already covered there; what is
# specific to CockroachDB is whether its provenance can be believed, and both
# settings of `lineage` exercise that differently — refuse sends a distrusted
# field straight to a refusal, allow sends it through lineage first.
echo "==> replaying against CockroachDB"
tot_stmt=0; tot_served=0; tot_refused=0; tot_err=0; tot_control=0; tot_leaks=0; bad=0
cfg_index=0
for cfg in "lineage=allow" "lineage=refuse"; do
  lin="${cfg#lineage=}"
  mkcfg "$PROXY_PORT" "/tmp/crdb-fuzz-cfg$cfg_index.toml" "s|^lineage = .*|lineage = \"$lin\"|"
  grep -q "^lineage = \"$lin\"" "/tmp/crdb-fuzz-cfg$cfg_index.toml" \
    || { echo "FAIL: could not set lineage = $lin"; exit 1; }
  ./target/release/pgmask "/tmp/crdb-fuzz-cfg$cfg_index.toml" >"/tmp/crdb-fuzz-cfg$cfg_index.log" 2>&1 &
  PROXY_PID=$!
  sleep 3
  psql -w "postgresql://root@localhost:$PROXY_PORT/fuzzdb?sslmode=disable" -X -tAc 'select 1' >/dev/null 2>&1 \
    || { echo "FAIL: proxy did not come up for $cfg"; tail -5 "/tmp/crdb-fuzz-cfg$cfg_index.log"; exit 1; }

  pids=()
  for s in $(seq 1 "$SEEDS"); do
    ( DIRECT_URL="$CDB" \
      PROXY_URL="postgresql://root@localhost:$PROXY_PORT/fuzzdb?sslmode=disable" \
      ./target/release/fuzz "/tmp/crdb-fuzz-$s.sql" >"/tmp/crdb-fuzz-c$cfg_index-$s.out" 2>&1
      echo $? > "/tmp/crdb-fuzz-c$cfg_index-$s.status" ) &
    pids+=($!)
  done
  for pid in "${pids[@]}"; do wait "$pid"; done
  kill "$PROXY_PID" 2>/dev/null; PROXY_PID=""

  for s in $(seq 1 "$SEEDS"); do
    out="/tmp/crdb-fuzz-c$cfg_index-$s.out"
    [[ "$(cat "/tmp/crdb-fuzz-c$cfg_index-$s.status" 2>/dev/null)" == "0" ]] || bad=$((bad + 1))
    # Parse the machine-readable RESULT line, not the prose above it: the
    # human summary writes the count *before* the word ("400 statements
    # replayed"), so a `statements +[0-9]+` pattern silently scored every
    # total as zero while the run was reporting 12,175 leaks.
    res=$(grep -oE '^RESULT .*' "$out" | tail -1)
    num() { printf '%s' "$res" | grep -oE "$1=[0-9]+" | grep -oE '[0-9]+' || echo 0; }
    tot_stmt=$((tot_stmt + $(num 'statements')))
    tot_served=$((tot_served + $(num 'served')))
    tot_refused=$((tot_refused + $(num 'refused')))
    tot_err=$((tot_err + $(num 'errors')))
    tot_control=$((tot_control + $(num 'control')))
    tot_leaks=$((tot_leaks + $(num 'leaks')))
  done
  printf '    %-16s statements %-7d served %-7d refused %-7d leaked %d\n' \
    "$cfg" "$tot_stmt" "$tot_served" "$tot_refused" "$tot_leaks"
  cfg_index=$((cfg_index + 1))
done

echo
echo "CockroachDB $CRDB_VERSION — generated SQL"
echo "-----------------------------------------"
printf '  statements replayed      %8d\n' "$tot_stmt"
printf '  served                   %8d\n' "$tot_served"
printf '  refused                  %8d\n' "$tot_refused"
printf '  engine errors            %8d\n' "$tot_err"
printf '  masked values readable
    without the proxy      %8d\n' "$tot_control"
printf '  LEAKED                   %8d\n' "$tot_leaks"

# A run that never reached a masked value proves nothing, whatever it reports.
if [[ "$tot_control" -lt 100 ]]; then
  echo "FAIL: only $tot_control masked values were reachable directly — vacuous run"
  exit 1
fi
[[ "$bad" -eq 0 ]] || { echo "FAIL: $bad harness run(s) exited non-zero"; exit 1; }
[[ "$tot_leaks" -eq 0 ]] || { echo "FAIL: $tot_leaks leak(s)"; exit 1; }

# The fixture must be what it was: a campaign that mutated its own fixture is
# not measuring what it thinks.
rows=$(psql -w "$CDB" -X -tAc 'SELECT count(*) FROM fz.t1')
[[ "$rows" == "40" ]] || { echo "FAIL: fixture changed during the run (fz.t1 = $rows)"; exit 1; }

echo "passed $tot_stmt, failed 0"

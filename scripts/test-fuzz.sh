#!/usr/bin/env bash
# Replay generated SQL through pgmask and assert no masked value escapes.
#
#   ./scripts/test-fuzz.sh [statements] [seed]
#
# Queries come from sqlsmith, which reads the live schema and generates valid
# random SQL — shapes nobody would write by hand, which is the closest thing
# available to an adversary when nobody else reviews the analysis rules.
#
# The oracle needs no expected output: every text column in the fixture holds
# the token CANARY, masking rewrites all of them, so a CANARY reaching the
# client is a leak whatever route it took. Every query also runs against the
# database directly, and a run where the direct connection saw no masked values
# either is reported as VACUOUS rather than as a pass.

set -uo pipefail
cd "$(dirname "$0")/.."

COUNT="${1:-6000}"
SEED="${2:-99}"
PG_PORT=55432
PROXY_PORT=6470
CONTAINER=pgmask-fuzz
export PGPASSWORD=demo

if ! command -v sqlsmith >/dev/null; then
  echo "SKIP: sqlsmith is not installed (brew install sqlsmith)"
  exit 0
fi

cleanup() {
  [[ -n "${PROXY_PID:-}" ]] && kill "$PROXY_PID" 2>/dev/null
  [[ "${KEEP:-0}" == "1" ]] || podman rm -f "$CONTAINER" >/dev/null 2>&1
}
trap cleanup EXIT

echo "==> starting postgres"
podman rm -f "$CONTAINER" >/dev/null 2>&1
podman run -d --name "$CONTAINER" -e POSTGRES_PASSWORD=demo -e POSTGRES_DB=fuzzdb \
  -p "$PG_PORT":5432 docker.io/library/postgres:17 >/dev/null
for _ in $(seq 1 40); do
  psql -h localhost -p "$PG_PORT" -U postgres -d fuzzdb -tAc 'SELECT 1' >/dev/null 2>&1 && break
  sleep 1
done

echo "==> loading the canary fixture"
psql -h localhost -p "$PG_PORT" -U postgres -d fuzzdb -q -v ON_ERROR_STOP=1 \
  -f examples/fuzz/schema.sql >/dev/null || { echo "FATAL: fixture failed to load"; exit 1; }

echo "==> building"
cargo build --release -q || exit 1

echo "==> starting pgmask (lineage on: the path where a miss would be a leak)"
./target/release/pgmask examples/fuzz/catalog.toml >/tmp/pgmask-fuzz.log 2>&1 &
PROXY_PID=$!
sleep 3

echo "==> generating $COUNT statements with sqlsmith (seed $SEED)"
sqlsmith --target="postgresql://postgres:demo@localhost:$PG_PORT/fuzzdb" \
  --dry-run --exclude-catalog --seed="$SEED" --max-queries="$COUNT" \
  >/tmp/pgmask-fuzz.sql 2>/dev/null
echo "    $(grep -c ';$' /tmp/pgmask-fuzz.sql) statements"

DIRECT_URL="postgres://postgres:demo@localhost:$PG_PORT/fuzzdb" \
PROXY_URL="postgres://postgres:demo@localhost:$PROXY_PORT/fuzzdb" \
  ./target/release/fuzz /tmp/pgmask-fuzz.sql
status=$?

# The fixture must survive: the fuzzer connects read-only, and a shrunken table
# would mean it had been eating the very data the oracle depends on.
rows=$(psql -h localhost -p "$PG_PORT" -U postgres -d fuzzdb -tAc 'SELECT count(*) FROM fz.t1')
if [[ "$rows" != "40" ]]; then
  echo "FAIL: the fixture changed during the run (fz.t1 has $rows rows, expected 40)"
  exit 1
fi
echo "    fixture intact"
exit $status

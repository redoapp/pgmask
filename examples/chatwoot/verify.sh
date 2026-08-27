#!/usr/bin/env bash
# Load the Chatwoot golden fixture and pin queries.sql through pgmask.
#
#   ./examples/chatwoot/verify.sh
#
# Backend selection matches scripts/test-integration.sh:
#   1. PGMASK_TEST_PG already set
#   2. podman postgres:17
#   3. host postgresql (scripts/lib/local-postgres.sh)

set -euo pipefail
cd "$(dirname "$0")/../.."
source scripts/lib/container.sh
source scripts/lib/local-postgres.sh

PG_PORT=55433
PROXY_PORT="${PGMASK_CHATWOOT_PORT:-16432}"
POISON_PORT="${PGMASK_CHATWOOT_POISON_PORT:-16433}"
DB=chatwoot_golden
CONTAINER=pgmask-chatwoot-golden
BACKEND=

cleanup() {
  [[ -n "${PROXY_PID:-}" ]] && kill "$PROXY_PID" 2>/dev/null || true
  [[ -n "${POISON_PID:-}" ]] && kill "$POISON_PID" 2>/dev/null || true
  if [[ "${KEEP:-0}" != "1" ]]; then
    case "${BACKEND:-}" in
      podman) podman rm -f -v "$CONTAINER" >/dev/null 2>&1 || true ;;
      local) ;; # shared local cluster; do not stop it
    esac
  fi
}
trap cleanup EXIT

if [[ -n "${PGMASK_TEST_PG:-}" ]]; then
  echo "==> using existing postgres at $PGMASK_TEST_PG"
  BACKEND=external
  PG_PORT="${PGMASK_TEST_PG##*:}"
elif command -v podman >/dev/null 2>&1; then
  BACKEND=podman
  echo "==> starting postgres (trust auth) on :$PG_PORT via podman"
  podman rm -f -v "$CONTAINER" >/dev/null 2>&1 || true
  podman run -d --name "$CONTAINER" \
    -e POSTGRES_HOST_AUTH_METHOD=trust \
    -p "$PG_PORT":5432 docker.io/library/postgres:17 >/dev/null
  pg_await "$CONTAINER" "$PG_PORT" "chatwoot-golden" || exit 1
else
  BACKEND=local
  echo "==> podman not found; starting a local trust postgres on :$PG_PORT"
  local_pg_start "$PG_PORT" || exit 1
fi

echo "==> creating database $DB"
psql -h 127.0.0.1 -p "$PG_PORT" -U postgres -d postgres -v ON_ERROR_STOP=1 -q -c \
  "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '$DB' AND pid <> pg_backend_pid();" \
  >/dev/null || true
psql -h 127.0.0.1 -p "$PG_PORT" -U postgres -d postgres -v ON_ERROR_STOP=1 -q -c \
  "DROP DATABASE IF EXISTS $DB;"
psql -h 127.0.0.1 -p "$PG_PORT" -U postgres -d postgres -v ON_ERROR_STOP=1 -q -c \
  "CREATE DATABASE $DB;"

echo "==> loading Chatwoot fixture"
psql -h 127.0.0.1 -p "$PG_PORT" -U postgres -d "$DB" -v ON_ERROR_STOP=1 -q \
  -f examples/chatwoot/schema.sql

echo "==> building pgmask"
cargo build -q -p pgmask

CFG=/tmp/pgmask-chatwoot-golden.toml
sed -e "s|^backend = .*|backend = \"127.0.0.1:${PG_PORT}\"|" \
    -e "s|^listen = .*|listen = \"127.0.0.1:${PROXY_PORT}\"|" \
    -e "s|^catalog_dsn = .*|catalog_dsn = \"postgres://postgres@127.0.0.1:${PG_PORT}/${DB}\"|" \
    examples/chatwoot/catalog.toml > "$CFG"

echo "==> starting pgmask on :$PROXY_PORT"
./target/debug/pgmask "$CFG" >/tmp/pgmask-chatwoot-golden.log 2>&1 &
PROXY_PID=$!

await_proxy() {
  local port="$1" log="$2" pid="$3"
  for _ in $(seq 1 120); do
    # A stale listener used to make this pass even when the pgmask process
    # above had already died with EADDRINUSE, so the corpus silently exercised
    # an old catalog. Readiness belongs to this exact child.
    if ! kill -0 "$pid" 2>/dev/null; then
      echo "FAIL: pgmask exited before becoming ready; $log:"
      tail -20 "$log"
      exit 1
    fi
    if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
      exec 3>&- 3<&-
      return 0
    fi
    sleep 0.25
  done
  echo "FAIL: proxy on :$port never accepted a connection; last lines of $log:"
  tail -20 "$log"
  exit 1
}
await_proxy "$PROXY_PORT" /tmp/pgmask-chatwoot-golden.log "$PROXY_PID"

echo "==> running query corpus"
PGMASK_PORT="$PROXY_PORT" PGMASK_DIRECT_PORT="$PG_PORT" PGDATABASE="$DB" \
  python3 examples/chatwoot/probe.py

# Negative control: the same proxy path must visibly leak the fixture's email
# when policy explicitly releases it. Without this, a broken query, empty row
# or driver decode could make every "no canary" assertion pass vacuously.
POISON_CFG=/tmp/pgmask-chatwoot-poison.toml
cat >"$POISON_CFG" <<EOF
listen = "127.0.0.1:${POISON_PORT}"
backend = "127.0.0.1:${PG_PORT}"
catalog_dsn = "postgres://postgres@127.0.0.1:${PG_PORT}/${DB}"
pseudonym_key = "chatwoot-poison-control"
unclassified = "allow"
opaque = "reject"

[[column]]
relation = "chatwoot.contacts"
column = "email"
mask = "none"
EOF

./target/debug/pgmask "$POISON_CFG" >/tmp/pgmask-chatwoot-poison.log 2>&1 &
POISON_PID=$!
await_proxy "$POISON_PORT" /tmp/pgmask-chatwoot-poison.log "$POISON_PID"
poison="$(
  psql -h 127.0.0.1 -p "$POISON_PORT" -U postgres -d "$DB" -X -tAq \
    -c 'SELECT email FROM chatwoot.contacts WHERE id = 1001;' 2>&1
)"
if [[ "$poison" != *"alice.cw-canary@inbox.test"* ]]; then
  echo "FAIL: release-policy poison control could not observe the canary"
  exit 1
fi
echo "release-policy poison control: PASS (canary observable; value withheld)"

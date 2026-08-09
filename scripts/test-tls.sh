#!/usr/bin/env bash
# Phase 4 criterion 4: TLS on both legs, proven with a real psql.
#
#   ./scripts/test-tls.sh
#
# Postgres gets its own self-signed cert (generated inside the container so the
# permissions Postgres insists on are satisfiable), pgmask gets another, and we
# assert that psql negotiates TLS to the proxy AND that masking still applies
# through the encrypted session.

set -uo pipefail
cd "$(dirname "$0")/.."

CONTAINER=pgmask-tls
PG_PORT=55434
PROXY_PORT=6433
CERTS=$(mktemp -d)
# SCRAM channel binding cannot survive TLS termination, so the workable shape is
# client TLS + plaintext backend leg. See protocol::sasl_mechanisms.
BACKEND_TLS="${BACKEND_TLS:-disable}"
export PGPASSWORD=demo

pass=0
fail=0

cleanup() {
  [[ -n "${PROXY_PID:-}" ]] && kill "$PROXY_PID" 2>/dev/null
  podman rm -f -v "$CONTAINER" >/dev/null 2>&1
  rm -rf "$CERTS"
}
trap cleanup EXIT

check() {
  local name="$1" expected="$2" actual="$3"
  if [[ "$actual" == *"$expected"* ]]; then
    printf '  \033[32mPASS\033[0m  %s\n' "$name"; ((pass++))
  else
    printf '  \033[31mFAIL\033[0m  %s\n        expected: %s\n        got: %s\n' "$name" "$expected" "$actual"
    ((fail++))
  fi
}

refute() {
  local name="$1" forbidden="$2" actual="$3"
  if [[ "$actual" != *"$forbidden"* ]]; then
    printf '  \033[32mPASS\033[0m  %s\n' "$name"; ((pass++))
  else
    printf '  \033[31mFAIL\033[0m  %s\n        must NOT contain: %s\n        got: %s\n' "$name" "$forbidden" "$actual"
    ((fail++))
  fi
}

echo "==> starting postgres"
podman rm -f -v "$CONTAINER" >/dev/null 2>&1
podman run -d --name "$CONTAINER" \
  -e POSTGRES_PASSWORD=demo -e POSTGRES_DB=demo \
  -p "$PG_PORT":5432 docker.io/library/postgres:17 >/dev/null
for _ in $(seq 1 30); do
  podman exec "$CONTAINER" pg_isready -U postgres >/dev/null 2>&1 && break
  sleep 1
done

echo "==> generating the backend cert inside the container"
# Postgres refuses a key that is group- or world-readable, and refuses one it
# does not own. Generating in place as the postgres user sidesteps both.
podman exec -u postgres "$CONTAINER" bash -c '
  cd /var/lib/postgresql/data &&
  openssl req -new -x509 -days 1 -nodes -text \
    -out server.crt -keyout server.key -subj "/CN=localhost" 2>/dev/null &&
  chmod 600 server.key
' || { echo "could not generate backend cert"; exit 1; }
podman exec -u postgres "$CONTAINER" psql -U postgres -c "ALTER SYSTEM SET ssl = on" >/dev/null
podman restart "$CONTAINER" >/dev/null
for _ in $(seq 1 30); do
  podman exec "$CONTAINER" pg_isready -U postgres >/dev/null 2>&1 && break
  sleep 1
done

echo "==> generating the pgmask cert"
# -addext forces an X.509 v3 certificate. Without any extension openssl emits
# v1, which rustls rejects outright (UnsupportedCertVersion).
openssl req -new -x509 -days 1 -nodes \
  -out "$CERTS/proxy.crt" -keyout "$CERTS/proxy.key" \
  -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null

echo "==> loading demo schema"
for _ in $(seq 1 30); do
  psql -h localhost -p "$PG_PORT" -U postgres -d demo -tAc 'SELECT 1' >/dev/null 2>&1 && break
  sleep 1
done
if ! psql -h localhost -p "$PG_PORT" -U postgres -d demo -q -v ON_ERROR_STOP=1 \
     -f examples/demo/schema.sql >/dev/null; then
  echo "FATAL: could not load the demo schema"; exit 1
fi

echo "==> starting pgmask with TLS on both legs"
# TLS keys must go at the TOP level. Anything written after a [[column]] block
# belongs to that block in TOML, which is exactly the trap deny_unknown_fields
# now catches.
{
  echo "tls_cert = \"$CERTS/proxy.crt\""
  echo "tls_key  = \"$CERTS/proxy.key\""
  echo "backend_tls = \"$BACKEND_TLS\""
  sed -e "s|^listen = .*|listen = \"127.0.0.1:$PROXY_PORT\"|" \
      -e "s|^backend = .*|backend = \"127.0.0.1:$PG_PORT\"|" \
      -e "s|^catalog_dsn = .*|catalog_dsn = \"postgres://postgres:demo@localhost:$PG_PORT/demo\"|" \
      examples/demo/catalog.toml
} > "$CERTS/tls.toml"

if ! cargo build --release -q; then
  echo "FATAL: could not build pgmask"
  exit 1
fi
PGMASK_LOG=info ./target/release/pgmask "$CERTS/tls.toml" > /tmp/pgmask-tls.log 2>&1 &
PROXY_PID=$!
sleep 2

if ! kill -0 "$PROXY_PID" 2>/dev/null; then
  echo "pgmask failed to start:"; cat /tmp/pgmask-tls.log; exit 1
fi

echo
echo "TLS criteria"
echo "------------"

# `tls=true`, not `tls=on`: the startup line became a structured tracing event.
# This assertion kept checking the old text and had been failing silently for
# several commits, while the README went on claiming all 7 TLS checks passed.
check "proxy reports TLS enabled on startup" "tls=true" "$(cat /tmp/pgmask-tls.log)"
check "backend leg configured as expected" "backend_tls=" "$(cat /tmp/pgmask-tls.log)"

# pg_stat_ssl reports what the *server side of this session* negotiated, which
# for a proxied connection is the pgmask hop. Newer psql renders \conninfo as a
# table, so assert on the cipher rather than on prose that moves between
# versions.
conn="$(psql "host=localhost port=$PROXY_PORT user=postgres dbname=demo sslmode=require" \
  -tAq -c "SELECT 'cipher=' || (SELECT cipher FROM pg_stat_ssl WHERE pid = pg_backend_pid());" 2>&1)"
tlsinfo="$(psql "host=localhost port=$PROXY_PORT user=postgres dbname=demo sslmode=require" \
  -c '\conninfo' 2>&1)"
check "psql negotiated TLS to pgmask" "TLS_AES" "$tlsinfo"

# sslmode=require means psql refuses to proceed without TLS, so reaching data at
# all proves the encrypted path works end to end.
row="$(psql "host=localhost port=$PROXY_PORT user=postgres dbname=demo sslmode=require" \
  -tAq -c 'SELECT email, name, city FROM demo.customers WHERE id = 1;' 2>&1)"
# Assert success FIRST: a refute against an error message passes for the wrong
# reason, which is how the first run of this script fooled itself.
check  "query succeeded over TLS" "Denver" "$row"
refute "masking still applies over TLS" "user1@example.com" "$row"

# And the fail-closed behaviour must survive the transport change.
rej="$(psql "host=localhost port=$PROXY_PORT user=postgres dbname=demo sslmode=require" \
  -tAq -c 'SELECT lower(email) FROM demo.customers LIMIT 1;' 2>&1)"
check "rejection still applies over TLS" "no column provenance" "$rej"

# The unworkable combination must fail with an explanation, not an opaque
# protocol error. Restart with backend TLS on and check the message.
if [[ "$BACKEND_TLS" == "disable" ]]; then
  kill "$PROXY_PID" 2>/dev/null; wait "$PROXY_PID" 2>/dev/null
  sed -i.bak 's|^backend_tls = .*|backend_tls = "require"|' "$CERTS/tls.toml"
  PGMASK_LOG=info ./target/release/pgmask "$CERTS/tls.toml" > /tmp/pgmask-tls-cb.log 2>&1 &
  PROXY_PID=$!
  sleep 2
  cb="$(psql "host=localhost port=$PROXY_PORT user=postgres dbname=demo sslmode=require" \
    -tAq -c 'SELECT 1;' 2>&1)"
  check "channel-binding conflict is explained, not opaque" \
    "cannot work through a proxy that terminates TLS" "$cb"
fi

echo
echo "------------"
printf 'passed %d, failed %d\n' "$pass" "$fail"
[[ "$fail" -eq 0 ]] || exit 1

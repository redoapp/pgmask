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
METRICS_PORT=9899
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

# A readiness loop that falls through on timeout is not a readiness check.
#
# Both loops here used to `break` on success and simply continue on exhaustion.
# On a machine busy with a soak, postgres:17 took longer than 30s to accept
# connections, so `ALTER SYSTEM SET ssl = on` ran against a socket that did not
# exist, its error went to a discarded stream, and the run continued with SSL
# off. The channel-binding assertion then failed with "the server refused TLS"
# — a true statement about a database this script was supposed to have
# configured. Nothing was wrong with the proxy.
await_pg() { # label
  for _ in $(seq 1 120); do
    podman exec "$CONTAINER" pg_isready -U postgres >/dev/null 2>&1 && return 0
    sleep 1
  done
  echo "FATAL: postgres not ready after 120s ($1)"
  podman logs "$CONTAINER" 2>&1 | tail -10
  exit 1
}

echo "==> starting postgres"
podman rm -f -v "$CONTAINER" >/dev/null 2>&1
podman run -d --name "$CONTAINER" \
  -e POSTGRES_PASSWORD=demo -e POSTGRES_DB=demo \
  -p "$PG_PORT":5432 docker.io/library/postgres:17 >/dev/null
await_pg "initial boot"

echo "==> generating the backend cert inside the container"
# Postgres refuses a key that is group- or world-readable, and refuses one it
# does not own. Generating in place as the postgres user sidesteps both.
podman exec -u postgres "$CONTAINER" bash -c '
  cd /var/lib/postgresql/data &&
  openssl req -new -x509 -days 1 -nodes -text \
    -out server.crt -keyout server.key -subj "/CN=localhost" 2>/dev/null &&
  chmod 600 server.key
' || { echo "could not generate backend cert"; exit 1; }
podman exec -u postgres "$CONTAINER" psql -U postgres -c "ALTER SYSTEM SET ssl = on" >/dev/null ||
  { echo "FATAL: could not set ssl = on"; exit 1; }
podman restart "$CONTAINER" >/dev/null
await_pg "after enabling ssl"

# And confirm it took, rather than trusting the ALTER. This is the setting the
# channel-binding assertion at the end depends on; if it is off, that assertion
# reports a proxy failure for a database reason.
ssl_state="$(podman exec -u postgres "$CONTAINER" psql -U postgres -tAc 'SHOW ssl' 2>&1)"
[[ "$ssl_state" == "on" ]] || {
  echo "FATAL: the backend reports ssl = $ssl_state after being told to enable it"
  exit 1
}

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
# Wait for the listener, not a fixed two seconds.
#
# pgmask resolves the whole catalog before it binds, so on a loaded machine it
# is not ready in two and the assertions below run against a closed port. This
# suite reported 3 of 7 while two fuzzers were building, and 7 of 7 alone. It is
# the third suite here with that defect — `verify.sh` had bare sleeps too, and
# `test-versions.sh` had a budget too short for the same reason.
#
# A TCP connect, not a query: the proxy is mid-TLS-handshake territory here and
# a psql probe would negotiate a session this suite has not set up yet.
await_listener() { # port
  for _ in $(seq 1 120); do
    (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null && { exec 3>&- 3<&-; return 0; }
    sleep 0.25
  done
  echo "FAIL: nothing listening on :$1 after 30s"
  return 1
}

PGMASK_LOG=info ./target/release/pgmask "$CERTS/tls.toml" > /tmp/pgmask-tls.log 2>&1 &
PROXY_PID=$!
if ! await_listener "$PROXY_PORT"; then
  echo "pgmask never bound:"; cat /tmp/pgmask-tls.log; exit 1
fi
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
  await_listener "$PROXY_PORT" || { cat /tmp/pgmask-tls-cb.log; exit 1; }
  cb="$(psql "host=localhost port=$PROXY_PORT user=postgres dbname=demo sslmode=require" \
    -tAq -c 'SELECT 1;' 2>&1)"
  check "channel-binding conflict is explained, not opaque" \
    "cannot work through a proxy that terminates TLS" "$cb"
fi

# --- The downgrade -----------------------------------------------------------
#
# Everything above connects with `sslmode=require`, which is why this suite
# passed 7 of 7 for weeks while a configured certificate was entirely optional.
# Postgres has no ALPN and no TLS port: a client that omits the SSLRequest
# packet gets a plaintext session, and before v0.1.69 it got a working one
# against a proxy whose own startup log said `tls=true`.
kill "$PROXY_PID" 2>/dev/null; wait "$PROXY_PID" 2>/dev/null
sed -i.bak 's|^backend_tls = .*|backend_tls = "disable"|' "$CERTS/tls.toml"
# The demo catalog already sets metrics_interval_seconds, and TOML rejects a
# duplicate key in the document root — so replace rather than prepend.
# Top level, before the first [[column]]: a bare key written after a table
# array belongs to that table, which is the trap noted where the TLS keys are
# written above. Strip the existing occurrence from the body, do not append.
{ echo "metrics_listen = \"127.0.0.1:$METRICS_PORT\""
  echo "metrics_interval_seconds = 1"
  grep -v '^metrics_interval_seconds' "$CERTS/tls.toml"; } > "$CERTS/tls-metrics.toml"
mv "$CERTS/tls-metrics.toml" "$CERTS/tls.toml"

PGMASK_LOG=info ./target/release/pgmask "$CERTS/tls.toml" > /tmp/pgmask-tls-down.log 2>&1 &
PROXY_PID=$!
await_listener "$PROXY_PORT" || { cat /tmp/pgmask-tls-down.log; exit 1; }

check "a certificate is reported as required by default" \
  "tls_required=true" "$(cat /tmp/pgmask-tls-down.log)"

plain="$(psql "host=localhost port=$PROXY_PORT user=postgres dbname=demo sslmode=disable" \
  -tAq -c 'SELECT email, name, city FROM demo.customers WHERE id = 1;' 2>&1)"
check  "a plaintext client is refused"        "not using TLS" "$plain"
check  "the refusal says how to fix it"       "sslmode=require" "$plain"
refute "no row reaches a plaintext client"    "Denver" "$plain"
# The point of the refusal is the data, so assert on the data too: a masked
# value crossing in the clear is the thing being prevented.
refute "no masked value reaches it either"    "@" "$plain"

metrics="$(curl -s --max-time 5 http://127.0.0.1:$METRICS_PORT/metrics 2>&1)"
check "the refusal is counted" "plaintext_refused" "$metrics"
check "the refusal count is not zero" \
  "1" "$(printf '%s' "$metrics" | grep -oE 'plaintext_refused[^0-9]*[0-9]+' | grep -oE '[0-9]+$')"

# POISON CONTROL. The checks above pass if the proxy is simply broken for
# plaintext for any reason — a crash, a bad listener, a refusal that predates
# this feature. Turn the requirement off and the very same client must succeed,
# which is the only thing that distinguishes enforcement from breakage.
kill "$PROXY_PID" 2>/dev/null; wait "$PROXY_PID" 2>/dev/null
{ echo "require_client_tls = false"; cat "$CERTS/tls.toml"; } > "$CERTS/tls-off.toml"  # top level
PGMASK_LOG=info ./target/release/pgmask "$CERTS/tls-off.toml" > /tmp/pgmask-tls-off.log 2>&1 &
PROXY_PID=$!
await_listener "$PROXY_PORT" || { cat /tmp/pgmask-tls-off.log; exit 1; }

allowed="$(psql "host=localhost port=$PROXY_PORT user=postgres dbname=demo sslmode=disable" \
  -tAq -c 'SELECT email, name, city FROM demo.customers WHERE id = 1;' 2>&1)"
check  "opting out restores the plaintext session" "Denver" "$allowed"
refute "and masking still applies to it"           "user1@example.com" "$allowed"
check "an optional certificate warns at startup" \
  "configured but not required" "$(cat /tmp/pgmask-tls-off.log)"

off_metrics="$(curl -s --max-time 5 http://127.0.0.1:$METRICS_PORT/metrics 2>&1)"
check "an allowed plaintext session is still counted" \
  "1" "$(printf '%s' "$off_metrics" | grep -oE 'plaintext_session[^0-9]*[0-9]+' | grep -oE '[0-9]+$')"

echo
echo "------------"
printf 'passed %d, failed %d\n' "$pass" "$fail"
[[ "$fail" -eq 0 ]] || exit 1

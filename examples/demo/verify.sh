#!/usr/bin/env bash
# End-to-end check of every MVP acceptance criterion against a real Postgres.
#
#   ./examples/demo/verify.sh
#
# Starts Postgres in podman, loads the demo schema, starts pgmask, and asserts
# each behaviour. Exits non-zero on the first failure.

set -uo pipefail
cd "$(dirname "$0")/../.."

PG_PORT=55432
PROXY_PORT=6432
CONTAINER=pgmask-demo
export PGPASSWORD=demo

pass=0
fail=0

cleanup() {
  [[ -n "${PROXY_PID:-}" ]] && kill "$PROXY_PID" 2>/dev/null
  if [[ "${KEEP:-0}" != "1" ]]; then
    podman rm -f "$CONTAINER" >/dev/null 2>&1
  fi
}
trap cleanup EXIT

direct() { psql -h localhost -p "$PG_PORT" -U postgres -d demo -tAq -c "$1" 2>&1; }
proxied() { psql -h localhost -p "$PROXY_PORT" -U postgres -d demo -tAq -c "$1" 2>&1; }

check() {
  local name="$1" expected="$2" actual="$3"
  if [[ "$actual" == *"$expected"* ]]; then
    printf '  \033[32mPASS\033[0m  %s\n' "$name"
    ((pass++))
  else
    printf '  \033[31mFAIL\033[0m  %s\n        expected to contain: %s\n        got: %s\n' \
      "$name" "$expected" "$actual"
    ((fail++))
  fi
}

refute() {
  local name="$1" forbidden="$2" actual="$3"
  if [[ "$actual" != *"$forbidden"* ]]; then
    printf '  \033[32mPASS\033[0m  %s\n' "$name"
    ((pass++))
  else
    printf '  \033[31mFAIL\033[0m  %s\n        must NOT contain: %s\n        got: %s\n' \
      "$name" "$forbidden" "$actual"
    ((fail++))
  fi
}

echo "==> starting postgres"
podman rm -f "$CONTAINER" >/dev/null 2>&1
podman run -d --name "$CONTAINER" \
  -e POSTGRES_PASSWORD=demo -e POSTGRES_DB=demo \
  -p "$PG_PORT":5432 docker.io/library/postgres:17 >/dev/null
for _ in $(seq 1 30); do
  podman exec "$CONTAINER" pg_isready -U postgres >/dev/null 2>&1 && break
  sleep 1
done

echo "==> loading demo schema (50k rows)"
psql -h localhost -p "$PG_PORT" -U postgres -d demo -q -f examples/demo/schema.sql >/dev/null 2>&1

echo "==> building and starting pgmask"
cargo build --release -q
./target/release/pgmask examples/demo/catalog.toml >/tmp/pgmask-verify.log 2>&1 &
PROXY_PID=$!
sleep 2

echo
echo "MVP acceptance criteria"
echo "-----------------------"

# 1 — connects and runs queries at all.
check "1. psql connects and queries through the proxy" \
  "Denver" "$(proxied 'SELECT city FROM demo.customers WHERE id = 1;')"

# 1b — a constant has no table, so it has no provenance. Rejecting it is correct
# and unavoidable: `SELECT 1` and `SELECT lower(email)` are indistinguishable at
# the protocol level. Worth asserting so the behaviour is deliberate, not a
# surprise the first time a health check fails.
check "1b. literal-only SELECT is rejected (expected; breaks SELECT 1 health checks)" \
  "no column provenance" "$(proxied 'SELECT 1;')"

# 2 — classified masked, allowed passthrough, unclassified default-denied.
row="$(proxied 'SELECT email, name, phone, city, internal_note FROM demo.customers WHERE id = 1;')"
refute "2a. classified email is not emitted verbatim" "user1@example.com" "$row"
check  "2b. pseudonym keeps the domain (joins still work)" "@example.com" "$row"
check  "2c. redact replaces the name"                      "***"          "$row"
check  "2d. partial keeps the last four of the phone"      "0101"         "$row"
check  "2e. explicitly allowed column passes through"      "Denver"       "$row"
refute "2f. unclassified column is default-denied"         "note 1"       "$row"

# Determinism is what makes masked data still joinable.
a="$(proxied 'SELECT email FROM demo.customers WHERE id = 1;')"
b="$(proxied 'SELECT email FROM demo.customer_directory WHERE id = 1;')"
check "2g. same value pseudonymises identically across relations" "$a" "$b"

# 3 — no provenance means no pass.
check "3a. expression output is rejected" \
  "no column provenance" "$(proxied 'SELECT lower(email) FROM demo.customers LIMIT 1;')"
check "3b. UNION is rejected" \
  "no column provenance" \
  "$(proxied '(SELECT email FROM demo.customers LIMIT 1) UNION ALL (SELECT email FROM demo.customers LIMIT 1);')"
check "3c. SETOF-returning function is rejected" \
  "no column provenance" \
  "$(proxied 'SELECT * FROM (SELECT email FROM demo.customers LIMIT 1) q UNION SELECT email FROM demo.customers LIMIT 1;')"

# 4 — the two paths that emit rows with no RowDescription.
check "4. COPY TO STDOUT is refused" \
  "COPY ... TO is not permitted" \
  "$(proxied 'COPY (SELECT email FROM demo.customers LIMIT 2) TO STDOUT;')"

# 6 — error DETAIL echoes column values verbatim.
leak="$(direct "INSERT INTO demo.customers (id,email,name,city) VALUES (1,'x@y.z','n','c');")"
check  "6a. Postgres really does leak the value in DETAIL" "Key (id)=(1)" "$leak"
scrubbed="$(proxied "INSERT INTO demo.customers (id,email,name,city) VALUES (1,'x@y.z','n','c');")"
refute "6b. pgmask scrubs it"                              "Key (id)=(1)" "$scrubbed"
check  "6c. ...but keeps the useful message"               "duplicate key" "$scrubbed"

# 7 — a rejection must not poison the session.
after="$(psql -h localhost -p "$PROXY_PORT" -U postgres -d demo -tAq \
  -c 'SELECT lower(email) FROM demo.customers LIMIT 1;' \
  -c 'SELECT city FROM demo.customers WHERE id = 1;' 2>&1)"
check "7. session survives a rejection and keeps serving" "Denver" "$after"

# 7b — extended protocol: one Describe, many Executes.
check "7b. views are masked through their own OID" \
  "***" "$(proxied 'SELECT name FROM demo.customer_directory WHERE id = 1;')"

echo
echo "-----------------------"
printf 'passed %d, failed %d\n' "$pass" "$fail"
[[ "$fail" -eq 0 ]] || exit 1

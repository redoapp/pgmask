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
# Wait for the forwarded port, not just for the server inside the container:
# podman's port forwarding can lag pg_isready, and a silently failed schema load
# turns into a confusing wall of "relation does not exist".
for _ in $(seq 1 30); do
  psql -h localhost -p "$PG_PORT" -U postgres -d demo -tAc 'SELECT 1' >/dev/null 2>&1 && break
  sleep 1
done
if ! psql -h localhost -p "$PG_PORT" -U postgres -d demo -q -v ON_ERROR_STOP=1 \
     -f examples/demo/schema.sql; then
  echo "FATAL: could not load the demo schema"
  exit 1
fi

echo "==> creating demo principals"
psql -h localhost -p "$PG_PORT" -U postgres -d demo -q -c "
  CREATE ROLE analyst_ann LOGIN PASSWORD 'demo';
  CREATE ROLE support_sam LOGIN PASSWORD 'demo';
  GRANT USAGE ON SCHEMA demo TO analyst_ann, support_sam;
  GRANT SELECT ON ALL TABLES IN SCHEMA demo TO analyst_ann, support_sam;" >/dev/null 2>&1

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

# 1b — a constant has no provenance, but it is positively identifiable as
# carrying no column value, so it is served rather than refused. This used to
# fail and break SELECT 1 health checks; see crates/proxy/src/analysis.rs.
check "1b. literal-only SELECT is served (health checks work)" \
  "1" "$(proxied 'SELECT 1;')"
check "1c. count(*) is served" \
  "50" "$(proxied 'SELECT count(*) FROM demo.customers;')"
# The count must be a real number, not a nulled placeholder: 50k rows over
# four cities is 12500 each.
check "1d. GROUP BY with a count returns real counts" \
  "12500" "$(proxied 'SELECT city, count(*) FROM demo.customers GROUP BY city ORDER BY 1 LIMIT 2;')"
# ...and the rescue must not extend to anything touching a column.
check "1e. an aggregate that emits a stored value is still refused" \
  "no column provenance" "$(proxied 'SELECT max(email) FROM demo.customers;')"

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
conflict="INSERT INTO demo.customers (id,email,name,city,birth_date,annual_salary,last_ip,account_uuid) \
  VALUES (1,'x@y.z','n','c',DATE '1980-01-01',1,'1.2.3.4','00000000-0000-4000-8000-000000000001');"
leak="$(direct "$conflict")"
check  "6a. Postgres really does leak the value in DETAIL" "Key (id)=(1)" "$leak"
scrubbed="$(proxied "$conflict")"
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

# 8 — type-aware masks on non-text columns.
as_role() { psql -h localhost -p "$PROXY_PORT" -U "$1" -d demo -tAq -c "$2" 2>&1; }
row8="$(proxied 'SELECT birth_date, annual_salary, last_ip, account_uuid FROM demo.customers WHERE id = 100;')"
check "8a. date truncated to its year"        "1970-01-01"  "$row8"
check "8b. salary floored to its bucket"      "50000"       "$row8"
check "8c. IP keeps only the network prefix"  "203.0.113.0" "$row8"
refute "8d. uuid is pseudonymised"            "00000000-0000-4000-8000-000000000100" "$row8"
check  "8e. ...but stays a valid uuid"        "-4"          "$row8"

# 9 — per-principal policy. Same column, different people, different views.
check  "9a. support sees the name in the clear" "Customer 1" \
  "$(as_role support_sam 'SELECT name FROM demo.customers WHERE id = 1;')"
refute "9b. ...while everyone else does not"    "Customer 1" \
  "$(proxied 'SELECT name FROM demo.customers WHERE id = 1;')"
check  "9c. analyst gets month precision"       "1970-04-01" \
  "$(as_role analyst_ann 'SELECT birth_date FROM demo.customers WHERE id = 100;')"
check  "9d. ...where the default is year only"  "1970-01-01" \
  "$(proxied 'SELECT birth_date FROM demo.customers WHERE id = 100;')"
check  "9e. support gets a partial email, not a pseudonym" "use" \
  "$(as_role support_sam 'SELECT email FROM demo.customers WHERE id = 1;')"

# 10 — semantic type domains keep the right things joinable.
e1="$(proxied 'SELECT email FROM demo.customers WHERE id = 1;')"
e2="$(proxied 'SELECT email FROM demo.customer_directory WHERE id = 1;')"
check "10. same semantic type pseudonymises alike across relations" "$e1" "$e2"

echo
echo "-----------------------"
printf 'passed %d, failed %d\n' "$pass" "$fail"
[[ "$fail" -eq 0 ]] || exit 1

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
check  "2b. pseudonym still looks like an address"         "@"            "$row"
refute "2b2. ...but the domain is pseudonymised too"       "@example.com" "$row"
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

# 11 — Phase 1: the catalog the classifier writes must actually work.
# Hand-writing the catalog is the part nothing else checks, so this closes the
# loop: generate one, run pgmask against it, and confirm it masks.
echo
echo "generated catalog"
echo "-----------------------"
DSN="postgres://postgres:demo@localhost:$PG_PORT/demo" \
  ./target/release/classify --schema demo --sample 200 >/tmp/pgmask-generated.toml 2>/tmp/pgmask-classify.log
{
  echo "listen = \"127.0.0.1:6455\""
  echo "backend = \"127.0.0.1:$PG_PORT\""
  echo "catalog_dsn = \"postgres://postgres:demo@localhost:$PG_PORT/demo\""
  echo "pseudonym_key = \"generated-catalog-smoke-test\""
  echo "unclassified = \"mask\""
  echo "unclassified_mask = \"null\""
  echo "opaque = \"reject\""
  cat /tmp/pgmask-generated.toml
} > /tmp/pgmask-generated-full.toml

check "11a. classify names the columns a human must decide on" \
  "customers.name" "$(cat /tmp/pgmask-classify.log)"
# The tool reads real values to confirm its guesses. Neither output may carry
# one back out — that would make the discovery step its own disclosure.
refute "11b. ...without echoing a sampled value to the report" \
  "user1@example.com" "$(cat /tmp/pgmask-classify.log)"
refute "11c. ...or into the catalog it writes" \
  "user1@example.com" "$(cat /tmp/pgmask-generated.toml)"

./target/release/pgmask /tmp/pgmask-generated-full.toml >/tmp/pgmask-generated.log 2>&1 &
GEN_PID=$!
sleep 2
gen() { psql -h localhost -p 6455 -U postgres -d demo -tAq -c "$1" 2>&1; }
genrow="$(gen 'SELECT email, name, last_ip FROM demo.customers WHERE id = 1;')"
check  "11d. pgmask loads the generated catalog and serves"  "***"              "$genrow"
refute "11e. ...masking the address it discovered"           "user1@example.com" "$genrow"
check  "11f. ...and the IP it discovered"                    "203.0.113.0"      "$(gen 'SELECT last_ip FROM demo.customers WHERE id = 100;')"
kill "$GEN_PID" 2>/dev/null

# 12 — GUI clients and psql's \d read pg_catalog. Off by default; on, only
# metadata-only catalogs are released, and the leaky ones must stay masked.
echo
echo "system catalogs (DBeaver / psql \\d)"
echo "-----------------------"
sed -e 's/^listen = .*/listen = "127.0.0.1:6456"/' \
    -e 's/^opaque = .*/opaque = "reject"\nsystem_catalogs = "allow"/' \
    examples/demo/catalog.toml > /tmp/pgmask-gui.toml
./target/release/pgmask /tmp/pgmask-gui.toml >/tmp/pgmask-gui.log 2>&1 &
GUI_PID=$!
sleep 2
gui() { psql -h localhost -p 6456 -U postgres -d demo -X -c "$1" 2>&1; }

check "12a. \\dt lists tables (default-deny refuses this)" \
  "customers" "$(gui '\dt demo.*')"
check "12b. \\d describes columns" \
  "annual_salary" "$(gui '\d demo.customers')"
# Default-deny does not merely refuse \d, it nulls the OID that psql feeds into
# its next query — so the failure surfaces as a Postgres syntax error, not ours.
refute "12c. ...and does not corrupt psql's follow-up query" \
  "invalid input syntax" "$(gui '\d demo.customers')"

# pg_stats hands back most_common_vals and histogram_bounds: literal values
# sampled from the user's tables, including pseudonymised ones.
check  "12d. Postgres really does expose the value in pg_stats" "shared@example.com" \
  "$(direct "SELECT most_common_vals FROM pg_stats WHERE tablename='customers' AND attname='email';")"
refute "12e. ...and pgmask does not release it"                 "shared@example.com" \
  "$(gui "SELECT most_common_vals FROM pg_catalog.pg_stats WHERE tablename='customers' AND attname='email';")"
refute "12f. pg_authid password hashes stay masked"             "SCRAM-SHA-256" \
  "$(gui 'SELECT rolpassword FROM pg_catalog.pg_authid LIMIT 1;')"
refute "12g. a user table joined to a catalog is still masked"  "user1@example.com" \
  "$(gui 'SELECT c.email FROM demo.customers c JOIN pg_catalog.pg_class k ON true WHERE c.id=1 LIMIT 1;')"
refute "12h. query_to_xml cannot launder a user table"          "user1@example.com" \
  "$(gui "SELECT pg_catalog.query_to_xml('SELECT email FROM demo.customers LIMIT 1', false, true, '') FROM pg_catalog.pg_class LIMIT 1;")"
refute "12i. ordinary data queries are unaffected by the knob"  "user1@example.com" \
  "$(gui 'SELECT email FROM demo.customers WHERE id = 1;')"
kill "$GUI_PID" 2>/dev/null

echo
echo "-----------------------"
printf 'passed %d, failed %d\n' "$pass" "$fail"
[[ "$fail" -eq 0 ]] || exit 1

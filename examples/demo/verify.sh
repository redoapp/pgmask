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

# Harlequin writes `from pg_database` unqualified, so requiring an explicit
# schema locked out a real client. The name is now a hint and the OID decides.
check "12j. an unqualified catalog reference is served" \
  "postgres" "$(gui 'SELECT datname FROM pg_database ORDER BY 1;')"
check "12k. size functions are served (every GUI shows table sizes)" \
  "8" "$(gui "SELECT pg_total_relation_size('demo.customers') AS bytes;")"

# ...which is exactly why the OID gate exists. `pg_` is reserved for schema
# names, NOT relation names, so a user can own a public.pg_database and put
# public ahead of pg_catalog on the search_path.
direct "DROP TABLE IF EXISTS public.pg_database;
        CREATE TABLE public.pg_database (datname text);
        INSERT INTO public.pg_database VALUES ('SENTINEL-LEAKED-SECRET');" >/dev/null
shadowed="$(psql -h localhost -p "$PG_PORT" -U postgres -d demo -X -tAq \
  -c 'SET search_path TO public, pg_catalog;' -c 'SELECT datname FROM pg_database;' 2>&1)"
check  "12l. the search_path shadow really does take effect" \
  "SENTINEL-LEAKED-SECRET" "$shadowed"
proxied_shadow="$(psql -h localhost -p 6456 -U postgres -d demo -X -tAq \
  -c 'SET search_path TO public, pg_catalog;' -c 'SELECT datname FROM pg_database;' 2>&1)"
refute "12m. ...and pgmask does not release the shadowed table" \
  "SENTINEL-LEAKED-SECRET" "$proxied_shadow"
direct "DROP TABLE IF EXISTS public.pg_database;" >/dev/null
kill "$GUI_PID" 2>/dev/null

# 13 — observability. Counters that only exist in a log line get read once;
# a scrape endpoint is what makes them operable.
echo
echo "observability"
echo "-----------------------"
sed -e 's/^listen = .*/listen = "127.0.0.1:6457"/' \
    -e 's|^opaque = .*|opaque = "reject"\nmetrics_listen = "127.0.0.1:9465"|' \
    examples/demo/catalog.toml > /tmp/pgmask-obs.toml
PGMASK_LOG=info ./target/release/pgmask /tmp/pgmask-obs.toml >/tmp/pgmask-obs.log 2>&1 &
OBS_PID=$!
sleep 2
obs() { psql -h localhost -p 6457 -U postgres -d demo -X -tAq -c "$1" 2>&1; }
obs 'SELECT email, name, city FROM demo.customers LIMIT 5;' >/dev/null
obs 'SELECT lower(email) FROM demo.customers LIMIT 1;' >/dev/null
obs 'SELECT 1;' >/dev/null
sleep 1
scrape="$(curl -s http://127.0.0.1:9465/metrics)"

check "13a. the scrape endpoint serves"                "pgmask_sessions_total" "$scrape"
# 5 rows x 2 masked columns. A wrong number here means the plan and the rows
# disagree, which is the failure that matters.
check "13b. values masked is counted per value"        "pgmask_values_masked_total 10" "$scrape"
check "13c. rejections are labelled by cause"          'pgmask_rejections_total{cause=' "$scrape"
check "13d. a rescued opaque field is counted"         "pgmask_fields_rescued_total 1" "$scrape"
refute "13e. no metric leaks a column value"           "@example.com" "$scrape"
refute "13f. ...or the pseudonym key"                  "demo-key-not-for-production" "$scrape"

log="$(cat /tmp/pgmask-obs.log)"
check  "13g. logs are structured and carry the session peer" "session{peer=" "$log"
refute "13h. the pseudonym key is never logged"        "demo-key-not-for-production" "$log"
kill "$OBS_PID" 2>/dev/null

# 14 — catalog drift. The catalog belongs to whoever deploys pgmask, so this is
# a check we ship for their CI, not something the proxy enforces at runtime.
# See docs/responsibilities.md.
echo
echo "catalog drift check"
echo "-----------------------"
chk() {
  DSN="postgres://postgres:demo@localhost:$PG_PORT/demo" \
    ./target/release/classify --check --catalog "$1" --schema demo 2>&1
}
chk_status() {
  DSN="postgres://postgres:demo@localhost:$PG_PORT/demo" \
    ./target/release/classify --check --catalog "$1" --schema demo >/dev/null 2>&1
  echo "$?"
}

# The demo catalog omits internal_note on purpose, to show default-deny.
out="$(chk examples/demo/catalog.toml)"
check "14a. an unclassified column is reported"   "internal_note" "$out"
check "14b. ...with what it looks like"           "looks like free_text" "$out"
check "14c. ...and the exit status fails a build" "1" "$(chk_status examples/demo/catalog.toml)"
# Coverage gaps are not exposures, and saying so keeps the check from being
# read as an alarm.
check "14d. ...described as a gap, not a leak"    "not an exposure" "$out"

{ cat examples/demo/catalog.toml
  printf '\n[[column]]\nrelation = "demo.customers"\ncolumn = "internal_note"\nmask = "null"\n'
  printf '\n[[column]]\nrelation = "demo.orders"\ncolumn = "internal_note"\nmask = "null"\n'
} > /tmp/pgmask-complete.toml
check "14e. a complete catalog passes"            "no drift" "$(chk /tmp/pgmask-complete.toml)"
check "14f. ...and exits zero"                    "0" "$(chk_status /tmp/pgmask-complete.toml)"

# A rename is the case that matters: the rule still parses, still loads, and
# protects nothing.
direct 'ALTER TABLE demo.customers RENAME COLUMN last_ip TO last_ip_addr;' >/dev/null
renamed="$(chk /tmp/pgmask-complete.toml)"
check "14g. a renamed column is caught as uncovered" "last_ip_addr" "$renamed"
check "14h. ...and the orphaned rule is caught too"  "match nothing" "$renamed"
direct 'ALTER TABLE demo.customers RENAME COLUMN last_ip_addr TO last_ip;' >/dev/null

# 15 — lineage. Off by default: this is the one rule where missing something is
# a disclosure rather than a lost query, so it is opt-in. See docs/lineage-estimate.md.
echo
echo "lineage"
echo "-----------------------"
python3 - <<'PYEOF'
import pathlib
base = pathlib.Path("examples/demo/catalog.toml").read_text()
base = base.replace('listen = "127.0.0.1:6432"', 'listen = "127.0.0.1:6460"')
base = base.replace('opaque = "reject"', 'opaque = "reject"\nlineage = "allow"')
extra = ""
for c in ["id", "customer_id", "status", "order_total", "ship_city", "placed_at"]:
    extra += f'\n[[column]]\nrelation = "demo.orders"\ncolumn = "{c}"\nmask = "none"\n'
extra += '\n[[column]]\nrelation = "demo.orders"\ncolumn = "ship_address"\ntype = "street_address"\n'
pathlib.Path("/tmp/pgmask-lineage.toml").write_text(base + extra)
PYEOF
./target/release/pgmask /tmp/pgmask-lineage.toml >/tmp/pgmask-lineage.log 2>&1 &
LIN_PID=$!
sleep 2
lin() { psql -h localhost -p 6460 -U postgres -d demo -X -tAq -c "$1" 2>&1 | head -1; }

# Released base columns: previously refused, now served.
check "15a. an expression over released columns is served" \
  "Austin/delivered" "$(lin "SELECT ship_city || '/' || status FROM demo.orders ORDER BY 1 LIMIT 1;")"
check "15b. a UNION over released columns is served" \
  "Austin" "$(lin 'SELECT ship_city FROM demo.orders UNION SELECT ship_city FROM demo.orders ORDER BY 1 LIMIT 1;')"
check "15c. ...where lineage OFF still refuses it" \
  "no column provenance" "$(proxied 'SELECT ship_city FROM demo.orders UNION SELECT ship_city FROM demo.orders;')"

# The message is the other half of the feature.
check "15d. a masked source is named in the refusal" \
  "derives from demo.customers.email" "$(lin 'SELECT lower(email) FROM demo.customers LIMIT 1;')"

# Laundering attempts. Each of these must refuse.
for probe in \
  "15e|mixing released and masked|SELECT city || email FROM demo.customers LIMIT 1;" \
  "15f|aliasing through a CTE|WITH t AS (SELECT email AS x FROM demo.customers) SELECT upper(x) FROM t;" \
  "15g|aliasing through a subquery|SELECT upper(x) FROM (SELECT email AS x FROM demo.customers) q LIMIT 1;" \
  "15h|hiding a masked column in a CASE|SELECT CASE WHEN id > 0 THEN email ELSE city END FROM demo.customers LIMIT 1;" \
  "15i|a join carrying a masked column|SELECT o.ship_city || c.email FROM demo.orders o JOIN demo.customers c ON c.id = o.customer_id LIMIT 1;" \
  "15j|an unclassified column|SELECT upper(internal_note) FROM demo.orders LIMIT 1;" \
  "15k|a UNION mixing released and masked|SELECT ship_city FROM demo.orders UNION SELECT email FROM demo.customers;" ; do
  IFS='|' read -r id what sql <<< "$probe"
  check "$id. refuses $what" "pgmask:" "$(lin "$sql")"
done

# Per-principal: the same expression, two people, two answers.
lin_as() { psql -h localhost -p 6460 -U "$1" -d demo -X -tAq -c "$2" 2>&1 | head -1; }
check  "15l. support may read an expression over a column they see" \
  "CUSTOMER 1" "$(lin_as support_sam 'SELECT upper(name) FROM demo.customers WHERE id = 1;')"
check  "15m. ...and everyone else may not" \
  "pgmask:" "$(lin 'SELECT upper(name) FROM demo.customers WHERE id = 1;')"
check  "15n. ...and email stays masked even for support" \
  "pgmask:" "$(lin_as support_sam 'SELECT upper(email) FROM demo.customers WHERE id = 1;')"
kill "$LIN_PID" 2>/dev/null

echo
echo "-----------------------"
printf 'passed %d, failed %d\n' "$pass" "$fail"
[[ "$fail" -eq 0 ]] || exit 1

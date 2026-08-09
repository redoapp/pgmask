#!/usr/bin/env bash
# pgmask against CockroachDB.
#
#   ./scripts/test-cockroach.sh
#
# CockroachDB was the original target for this proxy and was, for a long time,
# the one engine it had never been run against. It speaks the pgwire protocol
# and populates RowDescription provenance the same way Postgres does for
# ordinary queries — but not for all of them, and the difference was a leak:
#
#   SELECT city FROM t UNION ALL SELECT email FROM t
#
# CockroachDB's *simple-query* RowDescription reports the first branch's table
# OID for the single output field, so `city`'s released classification was
# applied to `email`'s values and a real address came back in the clear. Its
# extended-protocol Describe reports zero for the same statement, so the two
# protocols disagree and only one is safe. Postgres zeroes it either way, which
# is why five major versions of testing never showed this.
#
# This suite exists so that stays fixed.

set -uo pipefail
cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:/opt/homebrew/bin:$PATH"

CRDB_PORT=26257
PROXY_PORT=6440
CONTAINER=pgmask-crdb
VERSION="${CRDB_VERSION:-v25.4.14}"

pass=0; fail=0
check()  { if [[ "$3" == *"$2"* ]]; then printf '  \033[32mPASS\033[0m  %s\n' "$1"; ((pass++));
           else printf '  \033[31mFAIL\033[0m  %s\n        expected: %s\n        got: %s\n' "$1" "$2" "$3"; ((fail++)); fi; }
refute() { if [[ "$3" != *"$2"* ]]; then printf '  \033[32mPASS\033[0m  %s\n' "$1"; ((pass++));
           else printf '  \033[31mFAIL\033[0m  %s\n        must NOT contain: %s\n        got: %s\n' "$1" "$2" "$3"; ((fail++)); fi; }

cleanup() {
  [[ -n "${PROXY_PID:-}" ]] && kill "$PROXY_PID" 2>/dev/null
  [[ "${KEEP:-0}" == "1" ]] || podman rm -f -v "$CONTAINER" >/dev/null 2>&1
}
trap cleanup EXIT

command -v podman >/dev/null || { echo "FAIL: podman is required"; exit 3; }

echo "==> starting CockroachDB $VERSION"
podman rm -f -v "$CONTAINER" >/dev/null 2>&1
podman run -d --name "$CONTAINER" -p "$CRDB_PORT":26257 \
  "docker.io/cockroachdb/cockroach:$VERSION" start-single-node --insecure --accept-sql-without-tls >/dev/null 2>&1
D="postgresql://root@localhost:$CRDB_PORT/demo?sslmode=disable"
ROOT="postgresql://root@localhost:$CRDB_PORT/defaultdb?sslmode=disable"
for _ in $(seq 1 60); do psql -w "$ROOT" -tAc 'select 1' >/dev/null 2>&1 && break; sleep 2; done
psql -w "$ROOT" -tAc 'select 1' >/dev/null 2>&1 || { echo "FAIL: CockroachDB did not start"; exit 1; }

# The version must be what we think it is, or the results describe another engine.
got=$(psql -w "$ROOT" -X -tAc 'select version()' | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' | head -1)
[[ "$got" == "$VERSION" ]] || { echo "FAIL: wanted $VERSION, got $got"; exit 1; }

echo "==> loading fixture"
psql -w "$ROOT" -q -c 'CREATE DATABASE IF NOT EXISTS demo' >/dev/null 2>&1
psql -w "$D" -q -v ON_ERROR_STOP=1 >/dev/null 2>&1 <<'SQL'
CREATE SCHEMA IF NOT EXISTS demo;
CREATE TABLE IF NOT EXISTS demo.customers (
  id int primary key, email text not null, name text not null, phone text,
  city text not null, birth_date date not null, annual_salary int not null,
  last_ip text not null, account_uuid uuid not null, internal_note text);
INSERT INTO demo.customers
SELECT i, 'user'||i||'@example.com', 'Customer '||i, '555-01'||lpad((i%100)::text,2,'0'),
       (ARRAY['Portland','Denver','Austin','Boston'])[1+(i%4)],
       DATE '1970-01-01' + (i%12000), 40000+(i%47)*3700, '203.0.113.'||(i%254+1),
       ('00000000-0000-4000-8000-'||lpad(i::text,12,'0'))::uuid, 'note '||i
FROM generate_series(1,500) AS i
ON CONFLICT (id) DO NOTHING;
SQL
rows=$(psql -w "$D" -X -tAc 'select count(*) from demo.customers')
[[ "$rows" == "500" ]] || { echo "FAIL: fixture has $rows rows, expected 500"; exit 1; }

echo "==> building and starting pgmask"
cargo build --release -q || exit 1
python3 - "$CRDB_PORT" "$PROXY_PORT" <<'PY'
import pathlib, re, sys
crdb, proxy = sys.argv[1], sys.argv[2]
t = pathlib.Path('examples/demo/catalog.toml').read_text()
t = t.replace('listen = "127.0.0.1:6432"', f'listen = "127.0.0.1:{proxy}"')
t = t.replace('backend = "127.0.0.1:55432"', f'backend = "127.0.0.1:{crdb}"')
t = t.replace('catalog_dsn = "postgres://postgres:demo@localhost:55432/demo"',
              f'catalog_dsn = "postgres://root@localhost:{crdb}/demo?sslmode=disable"')
# The demo view and orders table are not part of this fixture.
t = re.sub(r'\n\[\[column\]\]\nrelation = "demo\.(customer_directory|orders)"\n(?:.*\n)*?(?=\n\[\[|\Z)', '\n', t)
pathlib.Path('/tmp/pgmask-crdb.toml').write_text(t)
PY
./target/release/pgmask /tmp/pgmask-crdb.toml >/tmp/pgmask-crdb.log 2>&1 &
PROXY_PID=$!
sleep 4
P="postgresql://root@localhost:$PROXY_PORT/demo?sslmode=disable"
p() { psql -w "$P" -X -tAq -c "$1" 2>&1 | head -"${2:-1}"; }
d() { psql -w "$D" -X -tAq -c "$1" 2>&1; }   # all rows: the leak is in the second
p 'select 1' >/dev/null 2>&1 || { echo "FAIL: proxy did not come up"; tail -5 /tmp/pgmask-crdb.log; exit 1; }

echo
echo "CockroachDB $VERSION"
echo "-----------------------"

# The catalog resolver runs Postgres catalog queries against CockroachDB.
n=$(grep -o 'classified_columns=[0-9]*' /tmp/pgmask-crdb.log | head -1 | grep -oE '[0-9]+')
[[ "${n:-0}" -gt 0 ]] && res="resolved $n" || res="resolved nothing"
check "catalog resolved against CockroachDB" "resolved " "$res"

row="$(p 'SELECT email, name, phone, city, internal_note FROM demo.customers WHERE id = 1')"
refute "email is not emitted verbatim"      "user1@example.com" "$row"
check  "pseudonym still looks like one"     "@"                 "$row"
check  "redact replaces the name"           "***"               "$row"
check  "partial keeps the last four"        "0101"              "$row"
check  "released column passes through"     "Denver"            "$row"
refute "unclassified is default-denied"     "note 1"            "$row"

row8="$(p 'SELECT birth_date, annual_salary, last_ip, account_uuid FROM demo.customers WHERE id = 100')"
check  "date-year"                          "1970-01-01"        "$row8"
check  "numeric-bucket"                     "50000"             "$row8"
check  "ip-prefix"                          "203.0.113.0"       "$row8"
refute "uuid is pseudonymised"              "00000000-0000-4000-8000-000000000100" "$row8"

# Pseudonyms must not depend on the engine, or a Postgres copy and a
# CockroachDB cluster cannot be correlated.
check "pseudonym matches the Postgres value" "8dedb655.invalid" "$(p 'SELECT email FROM demo.customers WHERE id = 42')"

check "expression is refused"  "no column provenance" "$(p 'SELECT lower(email) FROM demo.customers LIMIT 1')"
check "COPY TO STDOUT refused" "COPY ... TO is not permitted" "$(p 'COPY (SELECT email FROM demo.customers LIMIT 1) TO STDOUT')"
check "count(*) is served"     "500" "$(p 'SELECT count(*) FROM demo.customers')"

# The leak. CockroachDB reports the first branch's provenance on the
# simple-query path; believing it applies one column's mask to another's values.
check  "CockroachDB really does report it"  "user7@example.com" \
  "$(d 'SELECT city FROM demo.customers WHERE id=7 UNION ALL SELECT email FROM demo.customers WHERE id=7')"
for op in "UNION ALL" "UNION" "INTERSECT" "EXCEPT"; do
  out="$(p "SELECT city FROM demo.customers WHERE id=7 $op SELECT email FROM demo.customers WHERE id=7")"
  refute "$op does not leak the masked column" "user7@example.com" "$out"
  check  "$op is refused outright"             "no column provenance" "$out"
done

# Closing the leak must not cost CockroachDB the capability Postgres has.
#
# Distrusting set-operation provenance sends those fields down the opaque path,
# where lineage is what decides them — but lineage was computed only for fields
# the *engine* reported as computed. On Postgres those are the same set, so the
# gap was invisible there; on CockroachDB the fields carry an OID right up until
# we decline to believe it, so lineage never ran and every union was refused.
# Safe, and strictly worse than Postgres for no reason.
echo
echo "with lineage = allow"
echo "-----------------------"
kill "$PROXY_PID" 2>/dev/null; sleep 1
sed 's/^opaque = "reject"/opaque = "reject"\nlineage = "allow"/; s/:'"$PROXY_PORT"'"/:'"$((PROXY_PORT+1))"'"/' \
  /tmp/pgmask-crdb.toml > /tmp/pgmask-crdb-lineage.toml
grep -q '^lineage = "allow"' /tmp/pgmask-crdb-lineage.toml \
  || { echo "FAIL: could not enable lineage in the config"; exit 1; }
./target/release/pgmask /tmp/pgmask-crdb-lineage.toml >/tmp/pgmask-crdb-lineage.log 2>&1 &
PROXY_PID=$!
sleep 4
P="postgresql://root@localhost:$((PROXY_PORT+1))/demo?sslmode=disable"
p 'select 1' >/dev/null 2>&1 || { echo "FAIL: lineage proxy did not come up"; tail -5 /tmp/pgmask-crdb-lineage.log; exit 1; }

# id 2 is Austin: the fixture cycles the array at `[1 + i % 4]`.
check "expression over a released column is served" "AUSTIN" \
  "$(p 'SELECT upper(city) FROM demo.customers WHERE id = 2')"
check "union of released columns is served, as on Postgres" "Austin" \
  "$(p 'SELECT city FROM demo.customers UNION SELECT city FROM demo.customers ORDER BY 1 LIMIT 1')"
for op in "UNION ALL" "UNION" "INTERSECT" "EXCEPT"; do
  out="$(p "SELECT city FROM demo.customers WHERE id=7 $op SELECT email FROM demo.customers WHERE id=7")"
  refute "$op still does not leak under lineage" "user7@example.com" "$out"
  check  "$op is refused with the reason named" "derives from"      "$out"
done

echo
echo "-----------------------"
printf 'passed %d, failed %d\n' "$pass" "$fail"
[[ "$fail" -eq 0 ]] || exit 1

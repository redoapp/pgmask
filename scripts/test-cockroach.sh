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
source "$(dirname "$0")/lib/container.sh"
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
# Refuse to run against somebody else's database.
#
# A container named `crdb`, left over from a session two days earlier, held
# 26257. This script's `podman run` then failed — silently, into /dev/null — and
# every query went to that stale server instead. `CREATE TABLE IF NOT EXISTS`
# was a no-op against its old schema, so the suite reported 34 of 34 while
# testing a fixture it had not created. It only surfaced when the catalog gained
# a column the stale table lacked.
#
# A suite that quietly tests the wrong database is worse than one that fails.
if lsof -nP -iTCP:"$CRDB_PORT" -sTCP:LISTEN >/dev/null 2>&1; then
  echo "FAIL: something already listens on :$CRDB_PORT — this suite would have"
  echo "      run against it instead of its own fixture. Offending container:"
  podman ps --format '  {{.Names}} {{.Ports}}' | grep "$CRDB_PORT" || true
  exit 1
fi
# `--store=type=mem`: CockroachDB's own init step could not dial the node it had
# just started, and the container exited 1 — four suites in one gate run. Not
# resources (6.4 GB free, other containers using 60 MB) and not the image (the
# version is pinned and the arch is native). It is disk latency inside the
# podman VM: with an on-disk store the init exceeds its internal timeout, and
# the node's own log reports "node might be overloaded" for 0.5s raft writes.
# In memory it is ready in 20s. These containers are thrown away at the end of
# the suite, so there is nothing for a durable store to buy.
podman run -d --name "$CONTAINER" -p "$CRDB_PORT":26257 \
  "docker.io/cockroachdb/cockroach:$VERSION" start-single-node --insecure \
  --accept-sql-without-tls --store=type=mem,size=2GiB >/dev/null 2>&1
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
-- Every column the demo catalog declares, `lookup_key` included. A stand-in
-- that carries a subset does not start: the proxy resolves the whole catalog
-- before it binds and refuses on a column that does not exist, because a
-- half-loaded catalog has unknown coverage. That is the right behaviour and the
-- reason this list has to track examples/demo/catalog.toml.
CREATE TABLE IF NOT EXISTS demo.customers (
  id int primary key, email text not null, name text not null, phone text,
  city text not null, birth_date date not null, annual_salary int not null,
  last_ip text not null, account_uuid uuid not null, internal_note text,
  lookup_key text);
INSERT INTO demo.customers
SELECT i, 'user'||i||'@example.com', 'Customer '||i, '555-01'||lpad((i%100)::text,2,'0'),
       (ARRAY['Portland','Denver','Austin','Boston'])[1+(i%4)],
       DATE '1970-01-01' + (i%12000), 40000+(i%47)*3700, '203.0.113.'||(i%254+1),
       ('00000000-0000-4000-8000-'||lpad(i::text,12,'0'))::uuid, 'note '||i,
       'user'||i||'@example.com'
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
PGMASK_LOG=info ./target/release/pgmask /tmp/pgmask-crdb.toml >/tmp/pgmask-crdb.log 2>&1 &
PROXY_PID=$!
P="postgresql://root@localhost:$PROXY_PORT/demo?sslmode=disable"
# All rows by default, not just the first.
#
# This used to be `head -1`, and the eight "$op does not leak the masked column"
# refutes below read a two-row result whose leak is on row *two* — so every one
# of them passed no matter what the proxy did. The direct control right beside
# them already kept all rows, with a comment saying why.
p() { psql -w "$P" -X -tAq -c "$1" 2>&1 | head -"${2:-40}"; }
d() { psql -w "$D" -X -tAq -c "$1" 2>&1; }   # all rows: the leak is in the second
proxy_await "$P" "cockroach main" || { tail -5 /tmp/pgmask-crdb.log; exit 1; }

echo
echo "CockroachDB $VERSION"
echo "-----------------------"

# The catalog resolver runs Postgres catalog queries against CockroachDB.
# Assert the number, not a word both branches contain: this was
#   [[ n -gt 0 ]] && res="resolved $n" || res="resolved nothing"
#   check "..." "resolved " "$res"
# and "resolved nothing" contains "resolved ", so it could never fail.
n=$(grep -o 'classified_columns=[0-9]*' /tmp/pgmask-crdb.log | head -1 | grep -oE '[0-9]+')
[[ "${n:-0}" -gt 0 ]] && res="yes" || res="no ($n)"
check "catalog resolved against CockroachDB" "yes" "$res"

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

# The byte-for-byte cross-engine property is exercised by
# `test-differential.sh`, against two live engines and a shared corpus. Keep
# this engine-specific suite independent of a hard-coded digest, which changes
# whenever the pseudonym format or domain separation changes legitimately.
check "pseudonym has the masked email format" ".invalid" \
  "$(p 'SELECT email FROM demo.customers WHERE id = 42')"

# The 2026-08-11 diagnostic disclosures, on the other engine.
#
# The fixes are wire-level — LEAKY_FIELDS, the withheld primary message, the
# ParameterStatus allowlist — so they should hold whatever speaks the protocol.
# "Should" is why this is here. CockroachDB v25 has its own PL/pgSQL, and
# measured on v25.4.14 it accepts `DO $$ ... RAISE EXCEPTION $$` and returns the
# text, exactly as Postgres does. `scram_iterations` does not exist here, so
# that one channel is Postgres-only and is not checked.
raise_do="DO \$\$ BEGIN RAISE EXCEPTION '%', (SELECT email FROM demo.customers WHERE id = 1); END \$\$;"
check  "CockroachDB really does carry it in an error" "user1@example.com" "$(d "$raise_do")"
refute "...and the proxy withholds it"                "user1@example.com" "$(p "$raise_do")"
check  "...refusing DO before it reaches the backend" "read-only" "$(p "$raise_do")"

notice_do="DO \$\$ BEGIN RAISE NOTICE '%', (SELECT email FROM demo.customers WHERE id = 1); END \$\$;"
refute "a notice does not carry it either" "user1@example.com" "$(p "$notice_do")"

# The LEAKY_FIELDS channels that exist on this engine. Measured on v25.4.14:
# `USING DETAIL` and `USING HINT` carry a value, and the `CONTEXT` traceback does
# not exist — a DO-block error reports only LOCATION, and `EXECUTE` inside
# PL/pgSQL is unimplemented ("stmt_dyn_exec is not yet supported"), so the
# dynamic-SQL route into a traceback has nowhere to start. Checking `W` here
# would be checking a channel the engine cannot open.
for f in DETAIL HINT; do
  usingf="DO \$\$ BEGIN RAISE EXCEPTION 'boom' USING $f = \
    (SELECT email FROM demo.customers WHERE id = 1); END \$\$;"
  check  "CockroachDB really does carry it in $f" "user1@example.com" "$(d "$usingf")"
  refute "...and the proxy drops $f"              "user1@example.com" "$(p "$usingf")"
done

appname="DO \$\$ BEGIN PERFORM set_config('application_name', \
  (SELECT email FROM demo.customers WHERE id = 1), false); END \$\$;"
refute "application_name is not reportable here either" "user1@example.com" "$(p "$appname")"

check "expression is refused"  "no column provenance" "$(p 'SELECT lower(email) FROM demo.customers LIMIT 1')"
check "COPY TO STDOUT hits the read-only gate" "read-only" \
  "$(p 'COPY (SELECT email FROM demo.customers LIMIT 1) TO STDOUT')"
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
P="postgresql://root@localhost:$((PROXY_PORT+1))/demo?sslmode=disable"
proxy_await "$P" "cockroach lineage" || { tail -5 /tmp/pgmask-crdb-lineage.log; exit 1; }

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

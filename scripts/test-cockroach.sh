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
check_match() { if [[ "$3" =~ $2 ]]; then printf '  \033[32mPASS\033[0m  %s\n' "$1"; ((pass++));
                else printf '  \033[31mFAIL\033[0m  %s\n        expected pattern: %s\n        got: %s\n' "$1" "$2" "$3"; ((fail++)); fi; }
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
# The demo view and orders table are not part of this fixture. The catalog
# spells a relation as a `[columns."demo.orders"]` table; drop each such table
# up to the next header. (This used to match the older `[[column]]` blocks and
# silently matched nothing once the catalog changed shape, so pgmask refused to
# start on eleven columns the fixture lacks and the suite never ran a check.)
t = re.sub(r'(?ms)^\[columns\."demo\.(customer_directory|orders)"\]\n.*?(?=^\[|\Z)', '', t)
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
pv() { psql -w "$P" -X -tAq -v VERBOSITY=verbose -c "$1" 2>&1 | head -"${2:-40}"; }
d() { psql -w "$D" -X -tAq -c "$1" 2>&1; }   # all rows: the leak is in the second
proxy_await "$P" "cockroach main" || { tail -5 /tmp/pgmask-crdb.log; exit 1; }

echo
echo "CockroachDB $VERSION"
echo "-----------------------"

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
check_match "pseudonym has the complete masked email format" \
  '^[0-9a-f]{16}@[0-9a-f]{8}\.invalid$' \
  "$(p 'SELECT email FROM demo.customers WHERE id = 42')"

# The 2026-08-11 diagnostic disclosures, on the other engine.
#
# CockroachDB can put classified values in diagnostic fields, as the direct
# controls prove. The current frontend allowlist refuses every DO block before
# it reaches those backend channels; assert that stable protocol decision here.
# Wire scrubbing itself is exercised directly by the session and protocol tests.
raise_do="DO \$\$ BEGIN RAISE EXCEPTION '%', (SELECT email FROM demo.customers WHERE id = 1); END \$\$;"
check  "CockroachDB really does carry it in an error" "user1@example.com" "$(d "$raise_do")"
refute "the frontend refusal withholds it"            "user1@example.com" "$(p "$raise_do")"
check  "DO is refused with insufficient privilege"   "42501" "$(pv "$raise_do")"

notice_do="DO \$\$ BEGIN RAISE NOTICE '%', (SELECT email FROM demo.customers WHERE id = 1); END \$\$;"
refute "the notice-producing DO is withheld too" "user1@example.com" "$(p "$notice_do")"

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
  refute "the frontend refusal withholds $f"      "user1@example.com" "$(p "$usingf")"
done

appname="DO \$\$ BEGIN PERFORM set_config('application_name', \
  (SELECT email FROM demo.customers WHERE id = 1), false); END \$\$;"
refute "application_name is not reportable here either" "user1@example.com" "$(p "$appname")"

check "expression is refused"  "no column provenance" "$(p 'SELECT lower(email) FROM demo.customers LIMIT 1')"
check "COPY TO STDOUT is refused with insufficient privilege" "42501" \
  "$(pv 'COPY (SELECT email FROM demo.customers LIMIT 1) TO STDOUT')"
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

# CockroachDB's catalogs are virtual. Two things follow that Postgres never
# showed, and both broke Beekeeper Studio's connect on this engine only:
#
#   * a virtual table reports its OID in RowDescription, but a cast of one
#     (`t.oid::integer`) has no provenance, so the metadata path's OID check
#     has nothing to inspect and the parse-tree name check stands alone. It
#     required every relation to be schema-qualified; Beekeeper's `getTypes`
#     writes `FROM pg_type t`.
#   * `crdb_internal` holds 113 engine tables named `tables`, `ranges`, `jobs`,
#     `zones`, `databases`. Loaded as *user* relations, they made the lexical
#     backstop refuse any catalog query spelling one of those tokens — which
#     is every `information_schema.tables` read there is.
echo
echo "with system_catalogs = allow"
echo "-----------------------"
kill "$PROXY_PID" 2>/dev/null; sleep 1
sed 's/^opaque = "reject"/opaque = "reject"\nsystem_catalogs = "allow"/; s/:'"$PROXY_PORT"'"/:'"$((PROXY_PORT+2))"'"/' \
  /tmp/pgmask-crdb.toml > /tmp/pgmask-crdb-catalogs.toml
grep -q '^system_catalogs = "allow"' /tmp/pgmask-crdb-catalogs.toml \
  || { echo "FAIL: could not enable system_catalogs in the config"; exit 1; }
./target/release/pgmask /tmp/pgmask-crdb-catalogs.toml >/tmp/pgmask-crdb-catalogs.log 2>&1 &
PROXY_PID=$!
P="postgresql://root@localhost:$((PROXY_PORT+2))/demo?sslmode=disable"
proxy_await "$P" "cockroach catalogs" || { tail -5 /tmp/pgmask-crdb-catalogs.log; exit 1; }

# Beekeeper's getTypes, verbatim shape: a bare `pg_type` beside a qualified
# `pg_namespace`, and a cast that erases the only provenance there was.
types="$(p "SELECT n.nspname AS schema, t.oid::integer AS typeid FROM pg_type t \
  LEFT JOIN pg_catalog.pg_namespace n ON n.oid = t.typnamespace WHERE t.typname = 'int8'")"
check  "bare pg_type beside a cast is served"  "pg_catalog"           "$types"
refute "and is not refused for provenance"     "no column provenance" "$types"

# The sidebar. Every column of this came back masked while
# `crdb_internal.tables` was a user relation.
check  "information_schema.tables is served" "customers" \
  "$(p "SELECT table_name FROM information_schema.tables WHERE table_schema = 'demo'")"
check  "information_schema.columns is served" "email" \
  "$(p "SELECT column_name FROM information_schema.columns WHERE table_name = 'customers' AND column_name = 'email'")"
# An alias that spells an engine table's bare name.
check  "an alias named like crdb_internal.ranges is served" "customers" \
  "$(p "SELECT relname AS ranges FROM pg_catalog.pg_class WHERE relname = 'customers'")"

# The engine schema itself stays closed: not a user relation, not a system
# catalog, and its token alone loses the metadata path.
check  "CockroachDB really does answer crdb_internal" "demo" \
  "$(d "SELECT database_name FROM crdb_internal.tables WHERE name = 'customers'")"
refute "crdb_internal is not released"          "demo" \
  "$(p "SELECT database_name FROM crdb_internal.tables WHERE name = 'customers'")"
refute "crdb_internal hidden in a predicate closes the fast path" "customers" \
  "$(p "SELECT relname FROM pg_catalog.pg_class WHERE relname = 'customers' AND EXISTS (SELECT 1 FROM crdb_internal.tables)")"
# And the setting releases metadata, not data.
refute "user columns stay masked under system_catalogs = allow" "user1@example.com" \
  "$(p 'SELECT email FROM demo.customers WHERE id = 1')"

echo
echo "-----------------------"
printf 'passed %d, failed %d\n' "$pass" "$fail"
[[ "$fail" -eq 0 ]] || exit 1

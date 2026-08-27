#!/usr/bin/env bash
# One corpus, two engines, compare what the proxy did.
#
#   ./scripts/test-differential.sh [statements]
#
# Every other oracle here needs someone to have predicted the bug: the canary
# oracle needs a token in the right column, the shape matrix needs the shape to
# have been thought of. `shapegen` closed one gap and opened another — it
# explores what its author imagined, so its blind spots are his.
#
# This one needs no prediction. Both engines hold byte-identical fixture data,
# and masking is supposed to be a property of the data and the catalog, not of
# the engine. So for any statement both proxies serve, the masked output must
# match, and a difference is a defect by construction.
#
# It matters most for pseudonyms. They are deterministic so that a Postgres copy
# and a CockroachDB cluster of the same data stay joinable; if one engine yields
# a different pseudonym for the same row that property is gone, and no
# single-engine test can see it.

set -uo pipefail
cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:/opt/homebrew/bin:$PATH"

COUNT="${1:-800}"
PG_PORT=55449
CRDB_PORT=26266
PG_PROXY=6482
CRDB_PROXY=6483
SKEW_PROXY=6484
PG=pgmask-diff-pg
CRDB=pgmask-diff-crdb
CRDB_VERSION="${CRDB_VERSION:-v25.4.14}"

cleanup() {
  for pid in ${PG_PID:-} ${CRDB_PID:-} ${SKEW_PID:-}; do kill "$pid" 2>/dev/null; done
  [[ "${KEEP:-0}" == "1" ]] || podman rm -f -v "$PG" "$CRDB" >/dev/null 2>&1
}
trap cleanup EXIT

command -v podman >/dev/null || { echo "FAIL: podman is required"; exit 3; }

echo "==> starting both engines"
podman rm -f -v "$PG" "$CRDB" >/dev/null 2>&1
podman run -d --name "$PG" -e POSTGRES_PASSWORD=demo -e POSTGRES_DB=fuzzdb \
  -p "$PG_PORT":5432 docker.io/library/postgres:17 >/dev/null 2>&1
# `--store=type=mem`: CockroachDB's own init step could not dial the node it had
# just started, and the container exited 1 — four suites in one gate run. Not
# resources (6.4 GB free, other containers using 60 MB) and not the image (the
# version is pinned and the arch is native). It is disk latency inside the
# podman VM: with an on-disk store the init exceeds its internal timeout, and
# the node's own log reports "node might be overloaded" for 0.5s raft writes.
# In memory it is ready in 20s. These containers are thrown away at the end of
# the suite, so there is nothing for a durable store to buy.
podman run -d --name "$CRDB" -p "$CRDB_PORT":26257 \
  "docker.io/cockroachdb/cockroach:$CRDB_VERSION" start-single-node --insecure \
  --store=type=mem,size=2GiB \
  --accept-sql-without-tls >/dev/null 2>&1

export PGPASSWORD=demo
PGURL="postgresql://postgres:demo@localhost:$PG_PORT/fuzzdb"
CROOT="postgresql://root@localhost:$CRDB_PORT/defaultdb?sslmode=disable"
CDB="postgresql://root@localhost:$CRDB_PORT/fuzzdb?sslmode=disable"

for _ in $(seq 1 60); do psql -w "$PGURL" -tAc 'select 1' >/dev/null 2>&1 && break; sleep 1; done
for _ in $(seq 1 60); do psql -w "$CROOT" -tAc 'select 1' >/dev/null 2>&1 && break; sleep 2; done
psql -w "$PGURL" -tAc 'select 1' >/dev/null 2>&1 || { echo "FAIL: postgres did not start"; exit 1; }
psql -w "$CROOT" -tAc 'select 1' >/dev/null 2>&1 || { echo "FAIL: cockroachdb did not start"; exit 1; }
psql -w "$CROOT" -q -c 'CREATE DATABASE IF NOT EXISTS fuzzdb' >/dev/null 2>&1

echo "==> loading one fixture into both"
psql -w "$PGURL" -q -v ON_ERROR_STOP=1 -f examples/fuzz/schema.sql >/dev/null 2>&1 \
  || { echo "FAIL: fixture did not load on postgres"; exit 1; }
psql -w "$CDB" -q -v ON_ERROR_STOP=1 -f examples/fuzz/schema.sql >/dev/null 2>&1 \
  || { echo "FAIL: fixture did not load on cockroachdb"; exit 1; }

# The comparison is only meaningful if the two sides really do hold the same
# data. Check it rather than assume the same file produced the same rows —
# integer widths already differed silently once.
for pair in "postgres:$PGURL" "cockroach:$CDB"; do
  name="${pair%%:*}"; url="${pair#*:}"
  sum=$(psql -w "$url" -X -tAc \
    "SELECT count(*) || ':' || sum(length(email)) || ':' || sum(annual_salary) FROM fz.people")
  [[ -n "${expect:-}" && "$sum" != "$expect" ]] && {
    echo "FAIL: the two engines do not hold the same data ($expect vs $sum)"; exit 1; }
  expect="$sum"
  echo "    $name: $sum"
done

cargo build --release -q || exit 1

mkcfg() { # port backend_port dsn outfile [extra sed]
  sed -e "s|^listen = .*|listen = \"127.0.0.1:$1\"|" \
      -e "s|^backend = .*|backend = \"127.0.0.1:$2\"|" \
      -e "s|^catalog_dsn = .*|catalog_dsn = \"$3\"|" \
      -e 's|^metrics_listen.*||' \
      -e 's|^lineage = .*|lineage = "allow"|' \
      ${5:+-e "$5"} \
      examples/fuzz/catalog.toml > "$4"
}

mkcfg "$PG_PROXY"   "$PG_PORT"   "$PGURL" /tmp/pgmask-diff-pg.toml
mkcfg "$CRDB_PROXY" "$CRDB_PORT" "$CDB"   /tmp/pgmask-diff-crdb.toml
./target/release/pgmask /tmp/pgmask-diff-pg.toml   >/tmp/pgmask-diff-pg.log   2>&1 &
PG_PID=$!
./target/release/pgmask /tmp/pgmask-diff-crdb.toml >/tmp/pgmask-diff-crdb.log 2>&1 &
CRDB_PID=$!
sleep 4

# `portable`: one corpus, two engines. `ROLLUP`, `CUBE` and `GROUPING SETS`
# parse on Postgres and not on CockroachDB, so they would show up here as
# "one served, one errored" — an engine difference wearing a defect's clothes.
./target/release/shapegen 777 "$COUNT" portable > /tmp/pgmask-diff.sql
# Pseudonym equality is the highest-value cross-engine property, so do not
# leave its presence to the generated corpus. This bare classified projection
# is served on both engines and must produce byte-identical masked output.
printf '%s\n' 'SELECT email FROM fz.people WHERE id = 1;' >> /tmp/pgmask-diff.sql
if grep -qE 'ROLLUP\(|CUBE\(|GROUPING SETS' /tmp/pgmask-diff.sql; then
  echo "FAIL: the corpus contains Postgres-only syntax; the comparison would be"
  echo "      measuring which engine can parse it, not what the proxy masked."
  exit 1
fi

A="postgresql://postgres:demo@localhost:$PG_PROXY/fuzzdb"
B="postgresql://root@localhost:$CRDB_PROXY/fuzzdb?sslmode=disable"

echo "==> comparing"
if ! A_NAME=postgres B_NAME=cockroach A_URL="$A" B_URL="$B" \
     ./target/release/differential /tmp/pgmask-diff.sql >/tmp/pgmask-diff.out 2>&1; then
  echo "FAIL: the engines produced different masked output"
  tail -25 /tmp/pgmask-diff.out
  exit 1
fi
grep -E 'both served|both refused|one served|RESULT' /tmp/pgmask-diff.out | sed 's/^/  /'

pg_email=$(psql -w "$A" -X -tAq -c 'SELECT email FROM fz.people WHERE id = 1' 2>&1)
crdb_email=$(psql -w "$B" -X -tAq -c 'SELECT email FROM fz.people WHERE id = 1' 2>&1)
[[ "$pg_email" =~ ^[0-9a-f]{16}@[0-9a-f]{8}\.invalid$ ]] \
  || { echo "FAIL: explicit Postgres pseudonym has the wrong shape: $pg_email"; exit 1; }
[[ "$crdb_email" == "$pg_email" ]] \
  || { echo "FAIL: explicit cross-engine pseudonyms differ: $pg_email vs $crdb_email"; exit 1; }
echo "  explicit pseudonym is well-formed and identical on both engines"

# --- the control -------------------------------------------------------------
# A comparison that cannot fail is not comparing. Point the second side at a
# proxy whose catalog masks one column differently and the values must diverge.
echo "==> control: a deliberately skewed catalog must produce mismatches"
mkcfg "$SKEW_PROXY" "$CRDB_PORT" "$CDB" /tmp/pgmask-diff-skew.toml \
  '/^name = "email"$/,/^$/ s|^mask = "pseudonym"|mask = "null"|'
grep -A2 '^name = "email"' /tmp/pgmask-diff-skew.toml | grep -q '^mask = "null"' \
  || { echo "FAIL: could not skew the explicit pseudonym case"; exit 1; }
./target/release/pgmask /tmp/pgmask-diff-skew.toml >/tmp/pgmask-diff-skew.log 2>&1 &
SKEW_PID=$!
sleep 3
if ! A_NAME=postgres B_NAME=skewed A_URL="$A" \
     B_URL="postgresql://root@localhost:$SKEW_PROXY/fuzzdb?sslmode=disable" \
     EXPECT_MISMATCH=1 ./target/release/differential /tmp/pgmask-diff.sql \
     >/tmp/pgmask-diff-skew.out 2>&1; then
  echo "FAIL: the two sides were configured differently and nothing differed"
  tail -12 /tmp/pgmask-diff-skew.out
  exit 1
fi
echo "    $(grep -oE 'value_mismatch=[0-9]+' /tmp/pgmask-diff-skew.out) — the comparison can fail"

compared=$(grep -oE 'compared=[0-9]+' /tmp/pgmask-diff.out | grep -oE '[0-9]+')
echo
echo "-----------------------"
echo "passed $compared, failed 0"

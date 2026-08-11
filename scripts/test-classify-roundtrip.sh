#!/usr/bin/env bash
# The catalog `classify` writes must load, start a proxy, and mask.
#
#   ./scripts/test-classify-roundtrip.sh
#
# Nothing connected the two crates. `classify --check` compares an existing
# catalog against a schema, and `validate_spec` checks a `MaskSpec` in memory,
# but the actual artefact — the TOML a person copies out of their terminal — was
# never fed back to the thing that has to read it.
#
# That is the seam where a change in one crate breaks the other silently:
# `classify` learned to emit `range` with `start`/`end` for postcodes, and
# whether `pgmask` accepts that combination was a matter of reading two files
# and believing they agreed.
#
# WHAT THIS ASSERTS, IN ORDER
#
#   1. The draft parses as a pgmask config, once a connection header is added.
#      It is a *fragment* on purpose — no `backend`, `listen` or `catalog_dsn`,
#      because `classify` cannot know them — and this documents the four lines
#      an operator has to supply.
#   2. The proxy starts with it. Config load runs `validate_spec` over every
#      emitted parameter, so a bucket of 1 or an empty range window fails here.
#   3. It masks. A pseudonymised address does not come back.
#   4. **And it serves.** A column nobody classified as sensitive still arrives
#      intact, because a catalog that masks everything would pass 3 for the
#      wrong reason.
set -uo pipefail
cd "$(dirname "$0")/.."

CONTAINER=pgmask-roundtrip
PG_PORT=55437
PROXY_PORT=6438
pass=0
fail=0

cleanup() {
  [[ -n "${PROXY_PID:-}" ]] && kill "$PROXY_PID" 2>/dev/null
  [[ "${KEEP:-0}" == "1" ]] || podman rm -f -v "$CONTAINER" >/dev/null 2>&1
  rm -f /tmp/pgmask-roundtrip.toml /tmp/pgmask-roundtrip.log
}
trap cleanup EXIT

check() {
  local name="$1" expected="$2" actual="$3"
  if [[ "$actual" == *"$expected"* ]]; then
    printf '  \033[32mPASS\033[0m  %s\n' "$name"; pass=$((pass + 1))
  else
    printf '  \033[31mFAIL\033[0m  %s\n        expected to contain: %s\n        got: %s\n' \
      "$name" "$expected" "$actual"; fail=$((fail + 1))
  fi
}
refute() {
  local name="$1" forbidden="$2" actual="$3"
  if [[ "$actual" == *"$forbidden"* ]]; then
    printf '  \033[31mFAIL\033[0m  %s\n        found: %s\n' "$name" "$forbidden"; fail=$((fail + 1))
  else
    printf '  \033[32mPASS\033[0m  %s\n' "$name"; pass=$((pass + 1))
  fi
}

command -v podman >/dev/null || { echo "FAIL: podman is required"; exit 3; }
command -v psql >/dev/null || { echo "FAIL: psql is required"; exit 3; }

echo "==> building"
cargo build -q -p classify -p pgmask || { echo "FAIL: build"; exit 1; }

echo "==> starting postgres on :$PG_PORT"
podman rm -f -v "$CONTAINER" >/dev/null 2>&1
podman run -d --name "$CONTAINER" -e POSTGRES_HOST_AUTH_METHOD=trust \
  -p "$PG_PORT":5432 docker.io/library/postgres:17 >/dev/null || exit 1
for _ in $(seq 1 90); do
  podman exec "$CONTAINER" pg_isready -U postgres >/dev/null 2>&1 && break
  sleep 1
done
podman exec "$CONTAINER" pg_isready -U postgres >/dev/null 2>&1 || {
  echo "FAIL: postgres did not start"; podman logs "$CONTAINER" 2>&1 | tail -5; exit 1
}

# One row of each shape `classify` has a rule for, plus a column it must leave
# alone.
#
# `warehouse_label` is the control, and picking it took two tries. `city` was
# the obvious choice and is wrong: `classify` matches `^city$` with its `geo`
# rule and proposes `redact`, so it came back `***` — classified, not
# unclassified. A control has to be a name no rule matches.
#
# The salary is 68450, not 68000. A `numeric-bucket` of 1000 floors 68000 to
# itself, so the first version of this asserted the mask had failed when it had
# worked exactly as specified. Bucketing does not hide a value that sits on a
# bucket boundary — see the note on `Mask::NumericBucket`.
podman exec -i "$CONTAINER" psql -U postgres -q <<'SQL'
CREATE SCHEMA rt;
CREATE TABLE rt.people (
  id            int PRIMARY KEY,
  email         text,
  phone         text,
  zip           char(5),
  annual_salary int,
  last_ip       text,
  birth_date    date,
  city          text,
  warehouse_label text
);
INSERT INTO rt.people VALUES
  (1, 'alice@example.com', '+1 555 010 0101', '94103', 68450,
      '203.0.113.7', DATE '1980-06-15', 'Portland', 'Bay 14');
SQL

echo "==> classify writes a draft"
DSN="postgres://postgres@127.0.0.1:$PG_PORT/postgres" \
  ./target/debug/classify --schema rt >/tmp/pgmask-roundtrip.draft 2>/dev/null
status=$?
[[ "$status" == 0 ]] || { echo "FAIL: classify exited $status"; exit 1; }

# The four lines classify cannot know. Anything else here would be this test
# papering over a gap in what the tool emits.
{
  echo "listen        = \"127.0.0.1:$PROXY_PORT\""
  echo "backend       = \"127.0.0.1:$PG_PORT\""
  echo "catalog_dsn   = \"postgres://postgres@127.0.0.1:$PG_PORT/postgres\""
  echo "pseudonym_key = \"roundtrip-key-long-enough\""
  # A column with no rule must still arrive, or check 4 cannot tell a working
  # catalog from one that masks the whole table.
  echo "unclassified  = \"allow\""
  echo
  cat /tmp/pgmask-roundtrip.draft
} >/tmp/pgmask-roundtrip.toml

echo "==> the proxy starts with it"
./target/debug/pgmask /tmp/pgmask-roundtrip.toml >/tmp/pgmask-roundtrip.log 2>&1 &
PROXY_PID=$!
for _ in $(seq 1 60); do
  grep -q "listening" /tmp/pgmask-roundtrip.log 2>/dev/null && break
  kill -0 "$PROXY_PID" 2>/dev/null || break
  sleep 0.5
done
if ! kill -0 "$PROXY_PID" 2>/dev/null; then
  echo "  FAIL  the proxy exited while loading the draft"
  tail -5 /tmp/pgmask-roundtrip.log
  exit 1
fi
printf '  \033[32mPASS\033[0m  the emitted draft loads and the proxy starts\n'
pass=$((pass + 1))

q() { psql -h 127.0.0.1 -p "$PROXY_PORT" -U postgres -d postgres -X -tAq -c "$1" 2>&1; }

echo "==> and it masks"
refute "the address is not served"    "alice@example.com" "$(q 'SELECT email FROM rt.people')"
refute "the exact salary is not served" "68450"            "$(q 'SELECT annual_salary FROM rt.people')"
check  "and it is bucketed, not withheld" "68000"          "$(q 'SELECT annual_salary FROM rt.people')"
refute "the postcode keeps no tail"   "94103"             "$(q 'SELECT zip FROM rt.people')"
check  "the postcode keeps its prefix" "94"               "$(q 'SELECT zip FROM rt.people')"
refute "the address is not served raw" "203.0.113.7"      "$(q 'SELECT last_ip FROM rt.people')"
refute "the birth date is not exact"  "1980-06-15"        "$(q 'SELECT birth_date FROM rt.people')"

echo "==> and it serves what nobody classified"
check "an unclassified column arrives intact" "Bay 14" "$(q 'SELECT warehouse_label FROM rt.people')"
check "and a classified one still does not"  "***"    "$(q 'SELECT city FROM rt.people')"

echo
echo "-----------------------"
printf 'passed %d, failed %d\n' "$pass" "$fail"
[[ "$fail" -eq 0 ]] || exit 1

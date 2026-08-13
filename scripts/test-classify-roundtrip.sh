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
source "$(dirname "$0")/lib/container.sh"

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
pg_await "$CONTAINER" "$PG_PORT" "classify round trip" || exit 1

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

# --- the drift gate ---------------------------------------------------------
#
# `--check` is what operators are told to put in CI, and nothing exercised it:
# no script ran it and it cannot be unit-tested, because it compares a catalog
# file against a live schema. Its contract has two halves and they fail for
# different reasons —
#
#   * a column in the database with no rule is masked by default-deny, so it is
#     safe and invisible; somebody finds out when a dashboard goes blank
#   * a rule matching nothing means the relation or column was renamed or
#     dropped: not a leak, but a rule you believe is protecting you and is not
#
# — so both are checked, and the no-drift case first, or "it exits non-zero" is
# equally consistent with it always exiting non-zero.
echo "==> the drift gate"
chk() {
  DSN="postgres://postgres@127.0.0.1:$PG_PORT/postgres" \
    ./target/debug/classify --check --catalog /tmp/pgmask-roundtrip.toml --schema rt 2>&1
  return $?
}

# A freshly generated catalog does NOT pass `--check`, and that is the contract
# rather than a bug — but it is worth having written down, because the first
# version of this test asserted the opposite and I believed it.
#
# `classify` deliberately emits no rule for a column it judged ordinary: it says
# in its own report that nothing verified those are harmless, so emitting
# `mask = "none"` would be the tool claiming exactly what it disclaims.
# `--check` then reports them as undecided, because default-deny masks them and
# somebody finds out when a dashboard goes blank.
#
# So the operator's loop is: generate, decide the ordinary columns explicitly,
# and only then is `--check` green. Both ends of that are checked here.
chk >/tmp/pgmask-roundtrip.check 2>&1
status=$?
if [[ $status != 0 ]]; then
  printf '  \033[32mPASS\033[0m  %s\n' "a fresh catalog reports the columns nobody has decided"
  pass=$((pass + 1))
else
  printf '  \033[31mFAIL\033[0m  %s\n' "a fresh catalog passed --check with ordinary columns unruled"
  fail=$((fail + 1))
fi
check "and it names them"  "no rule"        "$(cat /tmp/pgmask-roundtrip.check)"

# --- the claim `--check` makes about unruled columns -------------------------
#
# It told operators that unruled columns are "a coverage gap and not an
# exposure" because "default-deny masks them" — unconditionally, while holding
# the parsed catalog that decides it. Against `unclassified = "allow"`, the
# documented incremental-rollout posture, that is false: those columns are
# served in plaintext. Measured on a live proxy, an undeclared view over a
# classified table returned a real address while `--check` called it safe.
#
# Both postures are asserted, because a gate that always says "exposure" is as
# useless as one that never does.
# --- the column-rename trap: a released column that holds sensitive data -----
#
# --check compares rules to schema *shape*, which a rename leaves intact, so it
# cannot see that `ssn` and `city` swapped names and sensitive data now sits
# under a released column. Sampling the released columns is the only thing that
# catches it — and only with --sample, so this asserts both halves.
echo "==> --check --sample flags a released column that turned sensitive"
psql "postgres://postgres@127.0.0.1:$PG_PORT/postgres" -X -q >/dev/null 2>&1 <<'SQL'
CREATE SCHEMA rt2;
CREATE TABLE rt2.t (id int PRIMARY KEY, label text);
INSERT INTO rt2.t SELECT g, '111-22-' || lpad(g::text, 4, '0') FROM generate_series(1, 40) g;
SQL
cat > /tmp/pgmask-rt2.toml <<TOML
listen        = "127.0.0.1:$PROXY_PORT"
backend       = "127.0.0.1:$PG_PORT"
catalog_dsn   = "postgres://postgres@127.0.0.1:$PG_PORT/postgres"
pseudonym_key = "roundtrip-key-not-for-production"
[[column]]
relation = "rt2.t"
column   = "id"
mask     = "none"
[[column]]
relation = "rt2.t"
column   = "label"
mask     = "none"
TOML

# Without --sample: structure passes, and it must SAY it did not look at values.
nosample=$(DSN="postgres://postgres@127.0.0.1:$PG_PORT/postgres" \
  ./target/debug/classify --check --catalog /tmp/pgmask-rt2.toml --schema rt2 2>&1)
check "without --sample the rename trap is invisible" "no drift" "$nosample"
check "and it says to pass --sample"                  "run with --sample" "$nosample"

# With --sample: the released `label` column is 100% SSN-shaped -> must fail.
withsample=$(DSN="postgres://postgres@127.0.0.1:$PG_PORT/postgres" \
  ./target/debug/classify --check --catalog /tmp/pgmask-rt2.toml --schema rt2 --sample 40 2>&1)
ws_status=$?
check "with --sample the released column is flagged" "RELEASED column(s) hold sensitive" "$withsample"
check "and it names the column"                      "rt2.t.label" "$withsample"
if [[ "$ws_status" -ne 0 ]]; then
  printf '  \033[32mPASS\033[0m  %s\n' "--sample fails the build on the trap"; pass=$((pass + 1))
else
  printf '  \033[31mFAIL\033[0m  %s\n' "--sample exited 0 on a sensitive released column"; fail=$((fail + 1))
fi

echo "==> what --check claims about unruled columns"
# This suite's own catalog already sets `unclassified = "allow"` (see where it
# is written above) so that the "arrives intact" test can work — so it is the
# allow posture, and the deny posture is the one that has to be constructed.
#
# The first cut of this had it backwards, built an "allow" catalog that was
# already allow, and compared the deny half against the same file. Both halves
# then described the same posture and two assertions failed for a reason that
# had nothing to do with the code under test.
{ echo 'unclassified = "mask"'
  grep -v '^unclassified' /tmp/pgmask-roundtrip.toml; } > /tmp/pgmask-roundtrip-deny.toml
grep -q '^unclassified = "mask"' /tmp/pgmask-roundtrip-deny.toml \
  || { echo "FAIL: could not build the deny-posture catalog"; exit 1; }

allow_out=$(chk)
allow_status=$?
check  "unclassified=allow is reported as plaintext" "SERVED IN PLAINTEXT" "$allow_out"
# "not an exposure" would never match: that wording wraps across a newline, so
# the refute passed whatever the code did. Match a phrase that is really on one
# line and really differs between the two postures.
refute "and is not called merely a coverage gap"     "coverage gap"        "$allow_out"
# Likewise the exit code: a coverage gap already failed the gate before this
# change, so "exits non-zero" is true in both postures and discriminates
# nothing. The reason it fails is the assertion worth making.
check  "and fails for the right reason" "served in plaintext under" "$allow_out"

# The other half. A gate that always cries exposure is as useless as one that
# never does, so default-deny must still read as a coverage gap.
deny_out=$(DSN="postgres://postgres@127.0.0.1:$PG_PORT/postgres" \
  ./target/debug/classify --check --catalog /tmp/pgmask-roundtrip-deny.toml --schema rt 2>&1)
refute "default-deny is not called plaintext" "SERVED IN PLAINTEXT" "$deny_out"
check  "default-deny still says default-deny masks them" "default-deny masks them" "$deny_out"


# Decide them, the way an operator would, and it goes green.
{
  echo
  for col in id warehouse_label; do
    echo "[[column]]"
    echo "relation = \"rt.people\""
    echo "column   = \"$col\""
    echo "mask     = \"none\""
    echo
  done
} >>/tmp/pgmask-roundtrip.toml
chk >/tmp/pgmask-roundtrip.check 2>&1
if [[ $? == 0 ]]; then
  printf '  \033[32mPASS\033[0m  %s\n' "and goes green once they are decided explicitly"
  pass=$((pass + 1))
else
  printf '  \033[31mFAIL\033[0m  %s\n' "explicit none rules did not satisfy --check"
  head -8 /tmp/pgmask-roundtrip.check; fail=$((fail + 1))
fi

# Nothing to compare is not "no drift". `--check --schema <typo>` exited 0 with
# "every column has a rule and every rule matches", because zero columns satisfy
# every assertion vacuously — in the command operators put in CI.
DSN="postgres://postgres@127.0.0.1:$PG_PORT/postgres" \
  ./target/debug/classify --check --catalog /tmp/pgmask-roundtrip.toml \
  --schema definitely_not_a_schema >/tmp/pgmask-roundtrip.check 2>&1
if [[ $? != 0 ]]; then
  printf '  \033[32mPASS\033[0m  %s\n' "an empty schema fails rather than passing vacuously"
  pass=$((pass + 1))
else
  printf '  \033[31mFAIL\033[0m  %s\n' "a schema that does not exist reported no drift"
  fail=$((fail + 1))
fi

podman exec -i "$CONTAINER" psql -U postgres -q \
  -c "ALTER TABLE rt.people ADD COLUMN home_email text;" 2>/dev/null
chk >/tmp/pgmask-roundtrip.check 2>&1
status=$?
if [[ $status != 0 ]]; then
  printf '  \033[32mPASS\033[0m  %s\n' "a new column in the database fails the build"
  pass=$((pass + 1))
else
  printf '  \033[31mFAIL\033[0m  %s\n' "a new column did not fail the build"; fail=$((fail + 1))
fi
check "and it names the column" "home_email" "$(cat /tmp/pgmask-roundtrip.check)"

podman exec -i "$CONTAINER" psql -U postgres -q \
  -c "ALTER TABLE rt.people DROP COLUMN home_email;" \
  -c "ALTER TABLE rt.people RENAME COLUMN email TO email_address;" 2>/dev/null
chk >/tmp/pgmask-roundtrip.check 2>&1
status=$?
if [[ $status != 0 ]]; then
  printf '  \033[32mPASS\033[0m  %s\n' "a rule that matches nothing fails the build"
  pass=$((pass + 1))
else
  printf '  \033[31mFAIL\033[0m  %s\n' "a renamed column did not fail the build"; fail=$((fail + 1))
fi
check "and it names the rule that went stale" "email" "$(cat /tmp/pgmask-roundtrip.check)"

echo
echo "-----------------------"
printf 'passed %d, failed %d\n' "$pass" "$fail"
[[ "$fail" -eq 0 ]] || exit 1

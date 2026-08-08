#!/usr/bin/env bash
# Cross-version conformance check.
#
#   ./scripts/test-versions.sh            # 13 14 15 16 17
#   VERSIONS="13 17" ./scripts/test-versions.sh
#   KEEP=1 ./scripts/test-versions.sh     # leave containers running
#
# examples/demo/verify.sh proves the whole acceptance suite against Postgres 17
# only. This runs the subset of behaviours whose implementation touches
# something version-dependent — the auth handshake (md5 on 13, SCRAM from 14),
# type-aware masks, the error-DETAIL scrubber, the COPY refusal, and the
# psql \d / \dt catalog queries, which psql rewrites per server version —
# against every supported major and reports a pass/fail matrix.
#
# Ports are deliberately disjoint from verify.sh (55432/6432/6455/6456/6457/6460)
# and test-fuzz.sh so both can run at once:
#   host postgres  555<major>   e.g. 55513
#   proxy          66<major>    e.g. 6613
#   proxy (gui)    68<major>    e.g. 6813
# Container name is pgver-<major>.

set -uo pipefail
cd "$(dirname "$0")/.."

VERSIONS="${VERSIONS:-13 14 15 16 17}"
IMAGE_PREFIX="${IMAGE_PREFIX:-docker.io/library/postgres}"
RESULTS="${RESULTS:-/tmp/pgmask-versions-results.tsv}"
export PGPASSWORD=demo
# Never let libpq sit on a wedged proxy for the default two hours.
export PGCONNECT_TIMEOUT=10

# Every assertion this script can run, in report order. Kept explicit so a
# version that dies during setup is reported as a column of ERRORs rather than
# silently vanishing from the matrix.
ALL_IDS=(
  A01 A02 A03 A04 A05 A06 A07 A08 A09
  A10 A11 A12 A13 A14 A15
  A16 A17 A18
  A19 A20 A21
  A22 A23
)
declare -A DESC=(
  [A01]="connects and serves a query"
  [A02]="count(*) returns the real row count"
  [A03]="classified email is not emitted verbatim"
  [A04]="pseudonymised email still looks like an address"
  [A05]="...and its domain is pseudonymised too"
  [A06]="redact replaces the name"
  [A07]="partial keeps the last four of the phone"
  [A08]="explicitly allowed column passes through"
  [A09]="unclassified column is default-denied"
  [A10]="date-year truncates to the year"
  [A11]="numeric-bucket floors to the bucket"
  [A12]="ip-prefix keeps only the network prefix"
  [A13]="uuid is pseudonymised"
  [A14]="...but stays a valid uuid"
  [A15]="Postgres really leaks the value in DETAIL (control)"
  [A16]="pgmask scrubs the DETAIL value"
  [A17]="...but keeps the useful message"
  [A18]="COPY TO STDOUT is refused"
  [A19]="\\dt lists tables (system_catalogs=allow)"
  [A20]="\\d describes columns"
  [A21]="...and does not corrupt psql's follow-up query"
  [A22]="role auth works: support sees the name in the clear"
  [A23]="role auth works: analyst gets month precision"
)

pass=0
fail=0
V=""          # major under test, used by record()
PROXY_PID=""
GUI_PID=""
CONTAINER=""

cleanup() {
  [[ -n "$PROXY_PID" ]] && kill "$PROXY_PID" 2>/dev/null
  [[ -n "$GUI_PID" ]] && kill "$GUI_PID" 2>/dev/null
  if [[ "${KEEP:-0}" != "1" ]]; then
    for v in $VERSIONS; do podman rm -f "pgver-$v" >/dev/null 2>&1; done
  fi
}
trap cleanup EXIT

record() { printf '%s\t%s\t%s\n' "$V" "$1" "$2" >> "$RESULTS"; }

# An assertion whose expected string is empty passes against anything, and an
# assertion whose actual string is empty passes every refute(). Both have shipped
# here before, so both are hard errors rather than silent passes.
check() {
  local id="$1" name="$2" expected="$3" actual="$4"
  if [[ -z "$expected" ]]; then
    printf '  \033[31mBUG \033[0m  %s %s\n        vacuous: expected string is empty\n' "$id" "$name"
    ((fail++)); record "$id" VACUOUS; return
  fi
  if [[ "$actual" == *"$expected"* ]]; then
    printf '  \033[32mPASS\033[0m  %s %s\n' "$id" "$name"
    ((pass++)); record "$id" PASS
  else
    printf '  \033[31mFAIL\033[0m  %s %s\n        expected to contain: %s\n        got: %s\n' \
      "$id" "$name" "$expected" "${actual:-<empty>}"
    ((fail++)); record "$id" FAIL
  fi
}

# refute() additionally demands the query produced *something*. A connection
# refused, a timeout, or an empty result all satisfy "does not contain the
# secret" while proving nothing.
refute() {
  local id="$1" name="$2" forbidden="$3" actual="$4"
  if [[ -z "$forbidden" ]]; then
    printf '  \033[31mBUG \033[0m  %s %s\n        vacuous: forbidden string is empty\n' "$id" "$name"
    ((fail++)); record "$id" VACUOUS; return
  fi
  if [[ -z "${actual//[[:space:]]/}" ]]; then
    printf '  \033[31mFAIL\033[0m  %s %s\n        vacuous: the query returned nothing, so the refutation proves nothing\n' \
      "$id" "$name"
    ((fail++)); record "$id" EMPTY; return
  fi
  if [[ "$actual" != *"$forbidden"* ]]; then
    printf '  \033[32mPASS\033[0m  %s %s\n' "$id" "$name"
    ((pass++)); record "$id" PASS
  else
    printf '  \033[31mFAIL\033[0m  %s %s\n        must NOT contain: %s\n        got: %s\n' \
      "$id" "$name" "$forbidden" "$actual"
    ((fail++)); record "$id" FAIL
  fi
}

# A version that could not be brought up is a failed run, not an absent one.
abort_version() {
  local why="$1"
  printf '  \033[31mERROR\033[0m %s\n' "$why"
  for id in "${ALL_IDS[@]}"; do record "$id" ERROR; ((fail++)); done
}

echo "==> building pgmask"
if ! cargo build --release -q; then
  echo "FATAL: cargo build failed"
  exit 1
fi
for bin in ./target/release/pgmask; do
  [[ -x "$bin" ]] || { echo "FATAL: $bin missing after build"; exit 1; }
done

: > "$RESULTS"

for V in $VERSIONS; do
  PG_PORT="555$V"
  PROXY_PORT="66$V"
  GUI_PORT="68$V"
  CONTAINER="pgver-$V"
  CAT="/tmp/pgmask-ver-$V.toml"
  GUICAT="/tmp/pgmask-ver-$V-gui.toml"
  LOG="/tmp/pgmask-ver-$V.log"
  GUILOG="/tmp/pgmask-ver-$V-gui.log"
  PROXY_PID=""
  GUI_PID=""

  echo
  echo "======================================================================"
  echo "Postgres $V   (pg=$PG_PORT proxy=$PROXY_PORT gui=$GUI_PORT)"
  echo "======================================================================"

  direct()  { psql -h localhost -p "$PG_PORT"    -U postgres -d demo -X -tAq -c "$1" 2>&1; }
  proxied() { psql -h localhost -p "$PROXY_PORT" -U postgres -d demo -X -tAq -c "$1" 2>&1; }
  gui()     { psql -h localhost -p "$GUI_PORT"   -U postgres -d demo -X       -c "$1" 2>&1; }
  as_role() { psql -h localhost -p "$PROXY_PORT" -U "$1"     -d demo -X -tAq -c "$2" 2>&1; }

  podman rm -f "$CONTAINER" >/dev/null 2>&1
  if ! podman run -d --name "$CONTAINER" \
       -e POSTGRES_PASSWORD=demo -e POSTGRES_DB=demo \
       -p "$PG_PORT":5432 "$IMAGE_PREFIX:$V" >/dev/null 2>/tmp/pgmask-ver-$V-podman.err; then
    abort_version "could not start container: $(cat /tmp/pgmask-ver-$V-podman.err)"
    continue
  fi

  # pg_isready inside the container can go green before podman's port forward
  # is live, so wait on the forwarded port too.
  up=0
  for _ in $(seq 1 60); do
    if psql -h localhost -p "$PG_PORT" -U postgres -d demo -tAc 'SELECT 1' >/dev/null 2>&1; then
      up=1; break
    fi
    sleep 1
  done
  if [[ "$up" != 1 ]]; then
    abort_version "postgres $V never accepted a connection on $PG_PORT"
    podman logs "$CONTAINER" 2>&1 | tail -20
    podman rm -f "$CONTAINER" >/dev/null 2>&1
    continue
  fi

  server_version="$(direct 'SHOW server_version;')"
  echo "    server_version = $server_version"
  case "$server_version" in
    "$V"*) ;;
    *) abort_version "image $IMAGE_PREFIX:$V reports server_version '$server_version'"
       podman rm -f "$CONTAINER" >/dev/null 2>&1; continue ;;
  esac
  echo "    password_encryption = $(direct 'SHOW password_encryption;')"

  echo "--> loading demo schema"
  if ! psql -h localhost -p "$PG_PORT" -U postgres -d demo -q -v ON_ERROR_STOP=1 \
       -f examples/demo/schema.sql > "/tmp/pgmask-ver-$V-schema.log" 2>&1; then
    abort_version "demo schema failed to load; see /tmp/pgmask-ver-$V-schema.log"
    tail -20 "/tmp/pgmask-ver-$V-schema.log"
    podman rm -f "$CONTAINER" >/dev/null 2>&1
    continue
  fi
  rows="$(direct 'SELECT count(*) FROM demo.customers;')"
  if [[ "$rows" != "50000" ]]; then
    abort_version "demo schema loaded but demo.customers holds '$rows' rows, not 50000"
    podman rm -f "$CONTAINER" >/dev/null 2>&1
    continue
  fi

  echo "--> creating demo principals"
  if ! psql -h localhost -p "$PG_PORT" -U postgres -d demo -q -v ON_ERROR_STOP=1 -c "
        CREATE ROLE analyst_ann LOGIN PASSWORD 'demo';
        CREATE ROLE support_sam LOGIN PASSWORD 'demo';
        GRANT USAGE ON SCHEMA demo TO analyst_ann, support_sam;
        GRANT SELECT ON ALL TABLES IN SCHEMA demo TO analyst_ann, support_sam;" \
        > "/tmp/pgmask-ver-$V-roles.log" 2>&1; then
    abort_version "could not create demo principals; see /tmp/pgmask-ver-$V-roles.log"
    tail -20 "/tmp/pgmask-ver-$V-roles.log"
    podman rm -f "$CONTAINER" >/dev/null 2>&1
    continue
  fi

  echo "--> rendering catalogs"
  sed -e "s|^listen = .*|listen = \"127.0.0.1:$PROXY_PORT\"|" \
      -e "s|^backend = .*|backend = \"127.0.0.1:$PG_PORT\"|" \
      -e "s|^catalog_dsn = .*|catalog_dsn = \"postgres://postgres:demo@localhost:$PG_PORT/demo\"|" \
      examples/demo/catalog.toml > "$CAT"
  sed -e "s|^listen = .*|listen = \"127.0.0.1:$GUI_PORT\"|" \
      -e "s|^opaque = .*|opaque = \"reject\"\nsystem_catalogs = \"allow\"|" \
      "$CAT" > "$GUICAT"
  # A silently unrendered catalog would point every version at 55432 and make
  # the whole matrix a re-run of verify.sh against 17.
  if ! grep -q "127.0.0.1:$PROXY_PORT" "$CAT" || ! grep -q "127.0.0.1:$PG_PORT" "$CAT" \
     || ! grep -q "127.0.0.1:$GUI_PORT" "$GUICAT" || ! grep -q 'system_catalogs = "allow"' "$GUICAT"; then
    abort_version "catalog rendering did not take effect"
    podman rm -f "$CONTAINER" >/dev/null 2>&1
    continue
  fi

  echo "--> starting pgmask"
  ./target/release/pgmask "$CAT" > "$LOG" 2>&1 &
  PROXY_PID=$!
  ./target/release/pgmask "$GUICAT" > "$GUILOG" 2>&1 &
  GUI_PID=$!
  ready=0
  for _ in $(seq 1 30); do
    if psql -h localhost -p "$PROXY_PORT" -U postgres -d demo -tAc 'SELECT 1' >/dev/null 2>&1 \
       && psql -h localhost -p "$GUI_PORT" -U postgres -d demo -tAc 'SELECT 1' >/dev/null 2>&1; then
      ready=1; break
    fi
    sleep 1
  done
  if [[ "$ready" != 1 ]]; then
    abort_version "pgmask never served on $PROXY_PORT/$GUI_PORT"
    echo "--- $LOG"; tail -20 "$LOG"
    echo "--- $GUILOG"; tail -20 "$GUILOG"
    kill "$PROXY_PID" "$GUI_PID" 2>/dev/null
    podman rm -f "$CONTAINER" >/dev/null 2>&1
    continue
  fi

  echo
  # --- connectivity ---------------------------------------------------------
  check A01 "${DESC[A01]}" "Denver" "$(proxied 'SELECT city FROM demo.customers WHERE id = 1;')"
  check A02 "${DESC[A02]}" "50000"  "$(proxied 'SELECT count(*) FROM demo.customers;')"

  # --- basic masking --------------------------------------------------------
  row="$(proxied 'SELECT email, name, phone, city, internal_note FROM demo.customers WHERE id = 1;')"
  refute A03 "${DESC[A03]}" "user1@example.com" "$row"
  check  A04 "${DESC[A04]}" "@"                 "$row"
  refute A05 "${DESC[A05]}" "@example.com"      "$row"
  check  A06 "${DESC[A06]}" "***"               "$row"
  check  A07 "${DESC[A07]}" "0101"              "$row"
  check  A08 "${DESC[A08]}" "Denver"            "$row"
  refute A09 "${DESC[A09]}" "note 1"            "$row"

  # --- type-aware masks -----------------------------------------------------
  row8="$(proxied 'SELECT birth_date, annual_salary, last_ip, account_uuid FROM demo.customers WHERE id = 100;')"
  check  A10 "${DESC[A10]}" "1970-01-01"  "$row8"
  check  A11 "${DESC[A11]}" "50000"       "$row8"
  check  A12 "${DESC[A12]}" "203.0.113.0" "$row8"
  refute A13 "${DESC[A13]}" "00000000-0000-4000-8000-000000000100" "$row8"
  check  A14 "${DESC[A14]}" "-4"          "$row8"

  # --- error DETAIL scrubbing ----------------------------------------------
  conflict="INSERT INTO demo.customers (id,email,name,city,birth_date,annual_salary,last_ip,account_uuid) \
    VALUES (1,'x@y.z','n','c',DATE '1980-01-01',1,'1.2.3.4','00000000-0000-4000-8000-000000000001');"
  check  A15 "${DESC[A15]}" "Key (id)=(1)"  "$(direct "$conflict")"
  scrubbed="$(proxied "$conflict")"
  refute A16 "${DESC[A16]}" "Key (id)=(1)"  "$scrubbed"
  check  A17 "${DESC[A17]}" "duplicate key" "$scrubbed"

  # --- COPY -----------------------------------------------------------------
  check A18 "${DESC[A18]}" "COPY ... TO is not permitted" \
    "$(proxied 'COPY (SELECT email FROM demo.customers LIMIT 2) TO STDOUT;')"

  # --- system catalogs ------------------------------------------------------
  # psql rewrites \d and \dt per server version, so this is the assertion most
  # likely to diverge across majors.
  check  A19 "${DESC[A19]}" "customers"            "$(gui '\dt demo.*')"
  dslash="$(gui '\d demo.customers')"
  check  A20 "${DESC[A20]}" "annual_salary"        "$dslash"
  refute A21 "${DESC[A21]}" "invalid input syntax" "$dslash"

  # --- per-principal policy (also exercises md5 vs SCRAM auth relaying) -----
  check A22 "${DESC[A22]}" "Customer 1"  "$(as_role support_sam 'SELECT name FROM demo.customers WHERE id = 1;')"
  check A23 "${DESC[A23]}" "1970-04-01"  "$(as_role analyst_ann 'SELECT birth_date FROM demo.customers WHERE id = 100;')"

  kill "$PROXY_PID" "$GUI_PID" 2>/dev/null
  PROXY_PID=""; GUI_PID=""
  if [[ "${KEEP:-0}" != "1" ]]; then
    podman rm -f "$CONTAINER" >/dev/null 2>&1
  fi
done

V=""

echo
echo "======================================================================"
echo "matrix"
echo "======================================================================"
{
  printf '%-5s %-52s' "" ""
  for v in $VERSIONS; do printf ' %-6s' "pg$v"; done
  printf '\n'
  for id in "${ALL_IDS[@]}"; do
    printf '%-5s %-52s' "$id" "${DESC[$id]}"
    for v in $VERSIONS; do
      s="$(awk -F'\t' -v v="$v" -v i="$id" '$1==v && $2==i {print $3}' "$RESULTS" | tail -1)"
      printf ' %-6s' "${s:-MISS}"
    done
    printf '\n'
  done
} | sed -e 's/PASS/PASS/'

echo
printf 'passed %d, failed %d   (raw results: %s)\n' "$pass" "$fail" "$RESULTS"
[[ "$fail" -eq 0 ]] || exit 1

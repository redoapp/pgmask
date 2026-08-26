#!/usr/bin/env bash
# Canary sweep over the query-shape matrix, on the simple-query protocol.
#
#   ./scripts/test-shapes.sh                # both engines
#   ./scripts/test-shapes.sh postgres
#   ./scripts/test-shapes.sh cockroach
#
# Why this exists, and why it is not the Phase 0 spike:
#
# `crates/spike` enumerates the same shapes but reads provenance via Parse +
# Describe — the *extended* protocol. CockroachDB reports zero provenance there
# for a set operation and reports the first branch's OID on the *simple* path,
# so the spike would have said "opaque, safe" about the exact statement that
# leaked. Sweeping shapes is the right idea; sweeping them through the wrong
# protocol is how the union disclosure survived being looked for.
#
# So this sweeps the dangerous path, and it does not ask the engine anything.
# It seeds a sentinel in a masked column and asserts the sentinel never comes
# back, which is the property the proxy exists to provide and is true or false
# regardless of what any engine reports about provenance.
#
# Three ways it refuses to pass on a technicality:
#   - every shape also runs directly against the database, and one that does not
#     return the sentinel there is reported VACUOUS rather than counted as a pass
#   - a POISON run releases the column, and must leak from most shapes; if the
#     oracle cannot fail it is not testing anything
#   - shapes the engine rejects are counted separately, with a floor, so a
#     fixture that silently fails to load cannot look like a clean sweep

set -uo pipefail
cd "$(dirname "$0")/.."
source "$(dirname "$0")/lib/container.sh"
export PATH="$HOME/.cargo/bin:/opt/homebrew/bin:$PATH"

ENGINES="${1:-postgres cockroach}"
CANARY='CANARY-SENTINEL'
CANARY_LC='canary-sentinel'   # outputs are case-folded before matching
# Below this many shapes actually executing, the run is not evidence.
FLOOR=25

command -v podman >/dev/null || { echo "FAIL: podman is required"; exit 3; }

total_fail=0
# Shapes that passed across the real (non-poison) runs, for the summary line.
total_ok=0

# --- the matrix -------------------------------------------------------------
# Portable across both engines. Shapes needing plpgsql, declarative
# partitioning or SETOF functions are Postgres-only and stay in crates/spike;
# what matters here is that every shape which *can* run on an engine does.
read -r -d '' SHAPES <<'EOF'
baseline|SELECT email FROM sw.t
star|SELECT * FROM sw.t
alias|SELECT email AS contact FROM sw.t
table_alias|SELECT a.email FROM sw.t a
join|SELECT t.email, u.note FROM sw.t t JOIN sw.u u ON u.t_id = t.id
left_join|SELECT t.email FROM sw.t t LEFT JOIN sw.u u ON u.t_id = t.id
distinct|SELECT DISTINCT email FROM sw.t
subquery_flat|SELECT email FROM (SELECT email FROM sw.t) q
subquery_nonflat|SELECT email FROM (SELECT email FROM sw.t OFFSET 0) q
cte|WITH c AS (SELECT email FROM sw.t) SELECT email FROM c
cte_materialized|WITH c AS MATERIALIZED (SELECT email FROM sw.t) SELECT email FROM c
cte_recursive|WITH RECURSIVE c(id, email) AS (SELECT id, email FROM sw.t WHERE id = 1 UNION ALL SELECT t.id, t.email FROM sw.t t JOIN c ON t.id = c.id + 1) SELECT email FROM c
union_all|SELECT email FROM sw.t UNION ALL SELECT email FROM sw.t
union|SELECT email FROM sw.t UNION SELECT email FROM sw.t
intersect|SELECT email FROM sw.t INTERSECT SELECT email FROM sw.t
except|SELECT email FROM sw.t EXCEPT SELECT email FROM sw.t WHERE id > 2
union_mixed|SELECT city FROM sw.t UNION ALL SELECT email FROM sw.t
union_mixed_rev|SELECT email FROM sw.t UNION ALL SELECT city FROM sw.t
union_three|SELECT city FROM sw.t UNION ALL SELECT city FROM sw.t UNION ALL SELECT email FROM sw.t
union_in_cte|WITH c AS (SELECT city AS v FROM sw.t UNION ALL SELECT email FROM sw.t) SELECT v FROM c
union_in_subquery|SELECT v FROM (SELECT city AS v FROM sw.t UNION ALL SELECT email FROM sw.t) q
union_nested|SELECT v FROM (SELECT city AS v FROM sw.t UNION SELECT email FROM sw.t) q ORDER BY 1
view|SELECT email FROM sw.v_t
view_star|SELECT * FROM sw.v_t
view_nested|SELECT email FROM sw.v_nested
view_union|SELECT v FROM sw.v_union
cast|SELECT email::text FROM sw.t
lower|SELECT lower(email) FROM sw.t
concat|SELECT email || '' FROM sw.t
coalesce|SELECT COALESCE(email, '') FROM sw.t
case_when|SELECT CASE WHEN id > 1 THEN email ELSE NULL END FROM sw.t
window|SELECT email, row_number() OVER (ORDER BY id) FROM sw.t
group_by|SELECT city, count(*) FROM sw.t GROUP BY city
aggregate|SELECT count(*), count(email), string_agg(email, ',') FROM sw.t
min_max|SELECT min(email), max(email) FROM sw.t
order_by_masked|SELECT email FROM sw.t ORDER BY email
lateral|SELECT t.email, x.note FROM sw.t t, LATERAL (SELECT note FROM sw.u WHERE t_id = t.id) x
values_join|SELECT t.email FROM sw.t t JOIN (VALUES (1),(2)) AS v(id) ON v.id = t.id
scalar_subquery|SELECT (SELECT email FROM sw.t WHERE id = 1) AS e
in_subquery|SELECT email FROM sw.t WHERE id IN (SELECT t_id FROM sw.u)
exists_sub|SELECT email FROM sw.t WHERE EXISTS (SELECT 1 FROM sw.u WHERE t_id = sw.t.id)
self_join|SELECT a.email, b.city FROM sw.t a JOIN sw.t b ON a.id = b.id
cursor_fetch|BEGIN; DECLARE swcur CURSOR FOR SELECT email FROM sw.t; FETCH ALL FROM swcur; COMMIT
multi_statement|SELECT city FROM sw.t; SELECT email FROM sw.t
EOF

# --- per-engine run ---------------------------------------------------------
run_engine() {
  local engine="$1"
  local container port proxy_port dsn
  case "$engine" in
    postgres)
      container=pgmask-shapes-pg; port=55439; proxy_port=6450
      podman rm -f -v "$container" >/dev/null 2>&1
      podman run -d --name "$container" -e POSTGRES_PASSWORD=demo -e POSTGRES_DB=demo \
        -p "$port":5432 docker.io/library/postgres:17 >/dev/null 2>&1
      dsn="postgresql://postgres:demo@localhost:$port/demo"
      ;;
    cockroach)
      container=pgmask-shapes-crdb; port=26259; proxy_port=6452
      podman rm -f -v "$container" >/dev/null 2>&1
# `--store=type=mem`: CockroachDB's own init step could not dial the node it had
# just started, and the container exited 1 — four suites in one gate run. Not
# resources (6.4 GB free, other containers using 60 MB) and not the image (the
# version is pinned and the arch is native). It is disk latency inside the
# podman VM: with an on-disk store the init exceeds its internal timeout, and
# the node's own log reports "node might be overloaded" for 0.5s raft writes.
# In memory it is ready in 20s. These containers are thrown away at the end of
# the suite, so there is nothing for a durable store to buy.
      podman run -d --name "$container" -p "$port":26257 \
        docker.io/cockroachdb/cockroach:v25.4.14 start-single-node --insecure \
        --store=type=mem,size=2GiB \
        --accept-sql-without-tls >/dev/null 2>&1
      dsn="postgresql://root@localhost:$port/demo?sslmode=disable"
      ;;
    *) echo "unknown engine $engine"; return 1 ;;
  esac

  echo
  echo "=============================================================="
  echo " $engine"
  echo "=============================================================="

  local boot="$dsn"
  [[ "$engine" == cockroach ]] && boot="postgresql://root@localhost:$port/defaultdb?sslmode=disable"
  # Two attempts, and the container's own log on failure.
  #
  # This suite runs sixth in the gate, behind five other container-heavy ones,
  # and CockroachDB failed to come up once under that load — reported as
  # "did not start" with nothing to diagnose it by. A release gate that flakes
  # teaches people to re-run it, which is the opposite of what it is for.
  local ok=0 attempt
  for attempt in 1 2; do
    for _ in $(seq 1 60); do
      PGPASSWORD=demo psql -w "$boot" -tAc 'select 1' >/dev/null 2>&1 && { ok=1; break; }
      sleep 2
    done
    [[ "$ok" == 1 ]] && break
    echo "    $engine did not answer on attempt $attempt; container log:"
    podman logs --tail 8 "$container" 2>&1 | sed 's/^/      /'
    [[ "$attempt" == 2 ]] && break
    echo "    restarting it"
    podman restart "$container" >/dev/null 2>&1
  done
  [[ "$ok" == 1 ]] || { echo "FAIL: $engine did not start"; podman rm -f -v "$container" >/dev/null 2>&1; return 1; }
  [[ "$engine" == cockroach ]] && psql -w "$boot" -q -c 'CREATE DATABASE IF NOT EXISTS demo' >/dev/null 2>&1

  export PGPASSWORD=demo
  psql -w "$dsn" -q -v ON_ERROR_STOP=1 >/dev/null <<SQL || { echo "FAIL: fixture did not load"; podman rm -f -v "$container" >/dev/null 2>&1; return 1; }
CREATE SCHEMA IF NOT EXISTS sw;
CREATE TABLE sw.t (id int primary key, email text not null, city text not null);
CREATE TABLE sw.u (id int primary key, t_id int not null, note text not null);
INSERT INTO sw.t VALUES
  (1,'$CANARY-1@example.com','Portland'),
  (2,'$CANARY-2@example.com','Denver'),
  (3,'$CANARY-3@example.com','Austin');
INSERT INTO sw.u VALUES (1,1,'note one'),(2,2,'note two'),(3,3,'note three');
CREATE VIEW sw.v_t AS SELECT id, email, city FROM sw.t;
CREATE VIEW sw.v_nested AS SELECT id, email FROM sw.v_t;
CREATE VIEW sw.v_union AS SELECT city AS v FROM sw.t UNION ALL SELECT email FROM sw.t;
SQL

  # The catalog releases city and note, masks email. `id` is released so joins
  # and ORDER BY have something to work with.
  local cat="/tmp/pgmask-shapes-$engine.toml"
  # Keep the body literal. An unquoted heredoc executes command substitutions
  # hidden in comments, so only these four explicit placeholders may vary.
  sed -e "s|@PROXY_PORT@|$proxy_port|g" \
      -e "s|@BACKEND_PORT@|$port|g" \
      -e "s|@CATALOG_DSN@|$dsn|g" \
      -e "s|@EMAIL_MASK@|$EMAIL_MASK|g" > "$cat" <<'CFG'
listen = "127.0.0.1:@PROXY_PORT@"
backend = "127.0.0.1:@BACKEND_PORT@"
catalog_dsn = "@CATALOG_DSN@"
pseudonym_key = "shape-sweep-key-1"
unclassified = "mask"
opaque = "reject"
catalog_refresh_seconds = 30

[[column]]
relation = "sw.t"
column = "id"
mask = "none"

[[column]]
relation = "sw.t"
column = "city"
mask = "none"

[[column]]
relation = "sw.t"
column = "email"
mask = "@EMAIL_MASK@"

[[column]]
relation = "sw.u"
column = "id"
mask = "none"

[[column]]
relation = "sw.u"
column = "t_id"
mask = "none"

[[column]]
relation = "sw.u"
column = "note"
mask = "none"

# The trap. `sw.v_union.v` is one output column drawing from two source columns,
# one released and one masked, and *both* engines report provenance for it —
# Postgres names the view's own column, CockroachDB names the first branch's
# base column. Either way a rule here is a rule on a field that is sometimes an
# address, so releasing it releases addresses.
#
# This is the rule an operator would plausibly write: `v` looks like a city
# column, `classify` would sample it and see cities. Without the view-taint
# check the proxy honours it and leaks on Postgres too, which is why that check
# is not a CockroachDB concession.
[[column]]
relation = "sw.v_union"
column = "v"
mask = "none"
CFG

  # PGMASK_BIN lets this run against another build — how the view-taint check
  # was shown to be load-bearing rather than merely present, by pointing it at
  # the commit before the fix and watching view_union leak on both engines.
  local bin="${PGMASK_BIN:-./target/release/pgmask}"
  [[ -n "${PGMASK_BIN:-}" ]] || cargo build --release -q || return 1
  "$bin" "$cat" >"/tmp/pgmask-shapes-$engine.log" 2>&1 &
  local pid=$!
  local P="postgresql://postgres:demo@localhost:$proxy_port/demo"
  [[ "$engine" == cockroach ]] && P="postgresql://root@localhost:$proxy_port/demo?sslmode=disable"
  proxy_await "$P" "shapes/$engine" || {
    tail -5 "/tmp/pgmask-shapes-$engine.log"
    kill "$pid" 2>/dev/null; podman rm -f -v "$container" >/dev/null 2>&1; return 1; }

  local clean=0 leaked=0 refused=0 vacuous=0 unsupported=0 executed=0
  local -a leaks=() vacuums=()

  while IFS='|' read -r id sql; do
    [[ -z "$id" ]] && continue
    local direct proxied
    # Case-folded, because `lower(email)` returns the sentinel in lower case and
    # a case-sensitive match called that shape vacuous — reporting the one shape
    # most likely to transform a value as "not tested".
    direct="$(psql -w "$dsn" -X -tAq -c "$sql" 2>&1 | tr '[:upper:]' '[:lower:]')"
    proxied="$(psql -w "$P"  -X -tAq -c "$sql" 2>&1 | tr '[:upper:]' '[:lower:]')"

    # A shape the engine itself rejects tells us nothing about masking.
    if [[ "$direct" != *"$CANARY_LC"* ]]; then
      if [[ "$direct" == *error* ]]; then
        unsupported=$((unsupported + 1))
      else
        vacuous=$((vacuous + 1)); vacuums+=("$id")
      fi
      continue
    fi
    executed=$((executed + 1))

    local verdict
    if [[ "$proxied" == *"$CANARY_LC"* ]]; then
      leaked=$((leaked + 1)); leaks+=("$id: $(printf '%s' "$proxied" | head -1 | cut -c1-60)")
      verdict=LEAK
    elif [[ "$proxied" == *"pgmask:"* ]]; then
      refused=$((refused + 1)); verdict=refused
    else
      clean=$((clean + 1)); verdict=clean
    fi
    # Per-shape verdicts, for telling a deliberate refusal apart from a
    # regression. The aggregate counts moved by one after a change here and
    # guessing which shape it was cost more than printing them.
    [[ -n "${SHOW_ALL:-}" ]] && printf '    %-10s %s\n' "$verdict" "$id"
  done <<< "$SHAPES"

  kill "$pid" 2>/dev/null
  [[ "${KEEP:-0}" == "1" ]] || podman rm -f -v "$container" >/dev/null 2>&1

  printf '  shapes that reached the sentinel   %3d\n' "$executed"
  printf '    masked or otherwise clean        %3d\n' "$clean"
  printf '    refused by the proxy             %3d\n' "$refused"
  printf '    LEAKED                           %3d\n' "$leaked"
  printf '  not evidence: %d unsupported by engine, %d vacuous\n' "$unsupported" "$vacuous"
  [[ "${#vacuums[@]}" -gt 0 ]] && printf '    vacuous: %s\n' "${vacuums[*]}"
  for l in "${leaks[@]}"; do printf '    \033[31mLEAK\033[0m %s\n' "$l"; done

  if [[ "$POISONED" == 1 ]]; then
    # The control: with the column released, the sweep must light up. A poison
    # run that stays clean means the oracle is not looking at anything.
    if [[ "$leaked" -lt 5 ]]; then
      printf '  \033[31mFAIL\033[0m poison run leaked only %d shapes — the oracle is not working\n' "$leaked"
      return 1
    fi
    printf '  \033[32mok\033[0m   poison run leaked %d shapes, so the oracle can fail\n' "$leaked"
    return 0
  fi

  if [[ "$executed" -lt "$FLOOR" ]]; then
    printf '  \033[31mFAIL\033[0m only %d shapes reached the sentinel, floor is %d\n' "$executed" "$FLOOR"
    return 1
  fi
  if [[ "$leaked" -gt 0 ]]; then
    printf '  \033[31mFAIL\033[0m %d shape(s) leaked a masked value\n' "$leaked"
    return 1
  fi
  printf '  \033[32mok\033[0m   no shape leaked\n'
  total_ok=$((total_ok + executed))
  return 0
}

for engine in $ENGINES; do
  EMAIL_MASK="pseudonym"; POISONED=0
  run_engine "$engine" || total_fail=$((total_fail + 1))
  echo
  echo "  --- poison control ($engine): email released, leaks are expected ---"
  EMAIL_MASK="none"; POISONED=1
  run_engine "$engine" >/tmp/poison-"$engine".out 2>&1
  poison_status=$?
  # Relabelled: `test-all.sh` scrapes the last "LEAKED n" it sees, and the
  # poison control's count is not this suite's result.
  grep -E 'poison run|reached the sentinel|LEAKED' /tmp/poison-"$engine".out \
    | sed -e 's/LEAKED/leaked-as-expected/' -e 's/^/  /'
  [[ "$poison_status" == 0 ]] || total_fail=$((total_fail + 1))
done

echo
echo "-----------------------"
printf 'passed %d, failed %d\n' "$total_ok" "$total_fail"
[[ "$total_fail" -eq 0 ]] || exit 1

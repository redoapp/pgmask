#!/usr/bin/env bash
# What an adversarial client can still reconstruct.
#
#   ./scripts/test-inference.sh
#
# Every other suite here asks the same question: does a masked value appear in
# the output? That is the property the proxy enforces, and it enforces it well —
# tens of thousands of generated statements find nothing. Read that with the
# caveat the campaign itself now prints: what matters is how many *executed* and
# were served, not how many were generated, and for a long time the extended
# path discarded every value it could not decode as text before the detectors
# ran.
#
# It is not the property people assume it has.
#
# This suite asks the other question: can a client *reconstruct* a masked value
# without it ever appearing? The answer is yes, and these are the routes. They
# are not bugs — every one of them follows from the design — but they were
# folklore in a doc comment, and folklore does not get re-checked when the
# design changes.
#
# So each is asserted as *currently possible*. That reads backwards for a
# security suite, and it is deliberate: if someone later governs the filter
# side, these fail loudly and the person doing it learns that the threat model
# moved, rather than discovering it from a stale README.
#
# The scale claim in the header is measured, not estimated: run it and read the
# query count.

set -uo pipefail
cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:/opt/homebrew/bin:$PATH"

PG_PORT=55501
PROXY_PORT=6541
CONTAINER=pgmask-inference

recoverable=0; governed=0; fail=0
# `possible` reads as a PASS when the attack works, because what is being
# asserted is the limitation, not the defence.
possible() {
  if [[ "$3" == *"$2"* ]]; then printf '  \033[33mRECOVERABLE\033[0m  %s\n' "$1"; ((recoverable++))
  else printf '  \033[32mGOVERNED\033[0m     %s\n        (expected to recover %s, got: %s)\n' "$1" "$2" "$3"; ((fail++)); fi
}
# The other direction: something that used to be recoverable and now is not.
#
# Requires a refusal, not merely a different answer. Asserting only "the true
# value is absent" would pass on any output at all — including a silently wrong
# number, which is a worse failure than either serving or refusing.
governed() {
  if [[ "$3" == *"$2"* ]]; then
    printf '  \033[31mREGRESSED\033[0m    %s\n        recovered %s\n' "$1" "$2"; ((fail++))
  elif [[ "$3" != *"pgmask:"* ]]; then
    printf '  \033[31mNOT REFUSED\033[0m  %s\n        expected a refusal, got: %s\n' "$1" "$3"; ((fail++))
  else
    printf '  \033[32mGOVERNED\033[0m     %s\n' "$1"; ((governed++))
  fi
}

cleanup() {
  [[ -n "${PROXY_PID:-}" ]] && kill "$PROXY_PID" 2>/dev/null
  [[ "${KEEP:-0}" == "1" ]] || podman rm -f -v "$CONTAINER" >/dev/null 2>&1
}
trap cleanup EXIT

command -v podman >/dev/null || { echo "FAIL: podman is required"; exit 3; }

podman rm -f -v "$CONTAINER" >/dev/null 2>&1
podman run -d --name "$CONTAINER" -e POSTGRES_PASSWORD=demo -e POSTGRES_DB=demo \
  -p "$PG_PORT":5432 docker.io/library/postgres:17 >/dev/null 2>&1
export PGPASSWORD=demo
D="postgresql://postgres:demo@localhost:$PG_PORT/demo"
for _ in $(seq 1 60); do psql -w "$D" -tAc 'select 1' >/dev/null 2>&1 && break; sleep 1; done
psql -w "$D" -tAc 'select 1' >/dev/null 2>&1 || { echo "FAIL: postgres did not start"; exit 1; }
psql -w "$D" -q -v ON_ERROR_STOP=1 -f examples/demo/schema.sql >/dev/null 2>&1 \
  || { echo "FAIL: fixture did not load"; exit 1; }

cargo build --release -q || exit 1
sed -e "s|^listen = .*|listen = \"127.0.0.1:$PROXY_PORT\"|" \
    -e "s|^backend = .*|backend = \"127.0.0.1:$PG_PORT\"|" \
    -e "s|^catalog_dsn = .*|catalog_dsn = \"$D\"|" \
    -e 's|^metrics_listen.*||' examples/demo/catalog.toml > /tmp/pgmask-inference.toml
./target/release/pgmask /tmp/pgmask-inference.toml >/tmp/pgmask-inference.log 2>&1 &
PROXY_PID=$!
sleep 3
P="postgresql://postgres:demo@localhost:$PROXY_PORT/demo"
p() { psql -w "$P" -X -tAq -c "$1" 2>&1 | head -3 | tr '\n' ' '; }
psql -w "$P" -X -tAc 'select 1' >/dev/null 2>&1 || { echo "FAIL: proxy did not come up"; exit 1; }

# Ground truth, read directly. Never printed — only compared against.
TRUE_EMAIL=$(psql -w "$D" -X -tAq -c 'SELECT email FROM demo.customers WHERE id=1')
TRUE_SALARY=$(psql -w "$D" -X -tAq -c 'SELECT annual_salary FROM demo.customers WHERE id=1')

echo
echo "what an adversarial client can reconstruct"
echo "------------------------------------------"

# The masking itself works. Establish that first, or the rest means nothing.
masked=$(p 'SELECT email, annual_salary FROM demo.customers WHERE id=1')
if [[ "$masked" == *"$TRUE_EMAIL"* ]]; then
  echo "  FAIL: the projection itself leaked; this suite assumes it does not"; exit 1
fi
printf '  \033[32mok\033[0m           the projection is masked: %s\n' "${masked:0:44}"

# 1. An aggregate grouped by a unique key is one row per row. Governed since
#    v0.1.16: a released summary over a singleton group is the value itself.
governed "sum() GROUP BY a unique key" \
  "$TRUE_SALARY" "$(p 'SELECT sum(annual_salary) FROM demo.customers GROUP BY id ORDER BY id LIMIT 1')"
governed "...including a superset of the key" \
  "$TRUE_SALARY" "$(p 'SELECT sum(annual_salary) FROM demo.customers GROUP BY id, city LIMIT 1')"
# The same attack written four other ways. Each is a shape the grouping reader
# resolves down to `id`, rather than a shape it refuses for being opaque —
# the distinction matters, because the opaque route refuses the honest queries
# below too.
#
# `GROUP BY 1` with `sum(...)` as the *only* target is not this test: Postgres
# rejects it outright ("aggregate functions are not allowed in GROUP BY"), so
# the assertion would pass on a server error without the proxy deciding
# anything. It did, until `governed` began requiring a pgmask refusal.
governed "...through an ordinal" \
  "$TRUE_SALARY" "$(p 'SELECT id, sum(annual_salary) FROM demo.customers GROUP BY 1 ORDER BY 1 LIMIT 1')"
governed "...through ROLLUP" \
  "$TRUE_SALARY" "$(p 'SELECT id, sum(annual_salary) FROM demo.customers GROUP BY ROLLUP(id) ORDER BY 1 LIMIT 1')"
governed "...through GROUPING SETS" \
  "$TRUE_SALARY" "$(p 'SELECT sum(annual_salary) FROM demo.customers GROUP BY GROUPING SETS ((id),(city)) LIMIT 1')"
# An expression grouping cannot be read, so the lexical backstop decides it:
# the statement names `id`, so it may be grouping by the key, so it is refused.
# `id::text` and `id+0` separate every row exactly as `id` does.
governed "...through an expression over the key" \
  "$TRUE_SALARY" "$(p 'SELECT sum(annual_salary) FROM demo.customers GROUP BY id::text LIMIT 1')"
governed "...through arithmetic on the key" \
  "$TRUE_SALARY" "$(p 'SELECT sum(annual_salary) FROM demo.customers GROUP BY (id+0) LIMIT 1')"
governed "...through a function of a cast of the key" \
  "$TRUE_SALARY" "$(p 'SELECT sum(annual_salary) FROM demo.customers GROUP BY upper(id::text) LIMIT 1')"

# An output alias denotes whatever its target computes, and reading only the
# alias name released every salary — the original disclosure with two extra
# characters. Postgres resolves an alias in any grouping *element*, which
# includes inside ROLLUP and GROUPING SETS but not inside an expression, so all
# three spellings are here.
governed "...through an output alias" \
  "$TRUE_SALARY" "$(p 'SELECT id AS c, sum(annual_salary) FROM demo.customers GROUP BY c ORDER BY 1 LIMIT 1')"
governed "...through an alias inside ROLLUP" \
  "$TRUE_SALARY" "$(p 'SELECT id AS c, sum(annual_salary) FROM demo.customers GROUP BY ROLLUP(c) ORDER BY 1 LIMIT 1')"
governed "...through an alias inside GROUPING SETS" \
  "$TRUE_SALARY" "$(p 'SELECT id AS c, sum(annual_salary) FROM demo.customers GROUP BY GROUPING SETS ((c)) ORDER BY 1 LIMIT 1')"
# The wrapper that put the two halves of the guard on different statements.
# `analyze_inspected` unwraps `SELECT * FROM (…)` and judges the subquery's
# targets, while the grouping was read from the outer clause — empty for a
# wrapper — so this served every salary in the table until 0.1.31.
governed "...through a SELECT * wrapper" \
  "$TRUE_SALARY" "$(p 'SELECT * FROM (SELECT id, sum(annual_salary) FROM demo.customers GROUP BY id ORDER BY 1 LIMIT 1) q')"
governed "...through two nested wrappers" \
  "$TRUE_SALARY" "$(p 'SELECT * FROM (SELECT * FROM (SELECT id, sum(annual_salary) FROM demo.customers GROUP BY id) a) b LIMIT 1')"

governed "...through a quoted alias" \
  "$TRUE_SALARY" "$(p 'SELECT id AS "C", sum(annual_salary) FROM demo.customers GROUP BY "C" ORDER BY 1 LIMIT 1')"

# The residual cost of the backstop, pinned so it stays visible. The grouping
# here is a coarse date bucket and cannot be singleton, but the statement names
# `id` in its filter and the lexer cannot tell where a name is used. Narrow, and
# the price of not walking an expression tree to find out.
governed "(cost) an expression grouping, key named in the filter" \
  "$TRUE_SALARY" "$(p "SELECT date_trunc('month', placed_at), sum(order_total) FROM demo.orders WHERE id > 5 GROUP BY 1 LIMIT 1")"

# Real aggregation is untouched, which is the whole point of doing it this way
# rather than by turning summaries off. Every shape the guard reads has an
# honest counterpart on a non-key column, and refusing those would be a far
# larger regression than the disclosure is worth.
served() {
  if [[ "$2" == *"pgmask:"* ]]; then
    printf '  \033[31mREFUSED\033[0m      %s\n        %s\n' "$1" "${2:0:96}"; fail=$((fail+1))
  else
    printf '  \033[32mok\033[0m           %s\n' "$1"
  fi
}
served "ungrouped sum"       "$(p 'SELECT sum(annual_salary) FROM demo.customers')"
served "GROUP BY a non-key"  "$(p 'SELECT city, sum(annual_salary) FROM demo.customers GROUP BY city')"
served "...by ordinal"       "$(p 'SELECT city, sum(annual_salary) FROM demo.customers GROUP BY 1')"
served "...by ROLLUP"        "$(p 'SELECT city, sum(annual_salary) FROM demo.customers GROUP BY ROLLUP(city)')"
served "...by CUBE"          "$(p 'SELECT city, sum(annual_salary) FROM demo.customers GROUP BY CUBE(city)')"
served "...by GROUPING SETS" "$(p 'SELECT city, sum(annual_salary) FROM demo.customers GROUP BY GROUPING SETS ((city),())')"
served "count(*) by the key" "$(p 'SELECT id, count(*) FROM demo.customers GROUP BY id LIMIT 1')"
# The one query that distinguishes reading an ordinal from falling back to the
# lexer, and therefore the only behavioural evidence that ordinal resolution
# does anything. Read: the grouping is `city`, not a key, so it is served.
# Unread: the grouping is opaque, the backstop scans the whole statement, `id`
# is named in the filter, and it is refused.
#
# Added because the mutation harness reported `ordinal grouping unread` as
# SURVIVED. Breaking ordinal resolution is *safe* — the backstop catches what it
# misses — so nothing failed, and a purely precision-preserving guard had no
# test at all.
served "an ordinal grouping with a key named in the filter" \
  "$(p 'SELECT city, sum(annual_salary) FROM demo.customers WHERE id > 5 GROUP BY 1 LIMIT 1')"
# Time bucketing is the ordinary analytics query, and the reason the unreadable
# case falls back to the lexer instead of refusing outright. `date_trunc` over a
# coarse literal unit is deliberately released, so these were served before the
# singleton-group guard existed and must stay served after it.
served "date_trunc bucket, by ordinal" \
  "$(p "SELECT date_trunc('month', placed_at), sum(order_total) FROM demo.orders GROUP BY 1 LIMIT 1")"
served "date_trunc bucket, by expression" \
  "$(p "SELECT date_trunc('month', placed_at), sum(order_total) FROM demo.orders GROUP BY date_trunc('month', placed_at) LIMIT 1")"
served "avg over a coarse bucket" \
  "$(p "SELECT date_trunc('year', placed_at), avg(order_total) FROM demo.orders GROUP BY 1 LIMIT 1")"
served "an expression grouping on a non-key" \
  "$(p 'SELECT sum(annual_salary) FROM demo.customers GROUP BY upper(city) LIMIT 1')"
served "a wrapped aggregate on a non-key column" \
  "$(p 'SELECT * FROM (SELECT city, sum(annual_salary) FROM demo.customers GROUP BY city LIMIT 1) q')"
served "an alias of a non-key column" \
  "$(p 'SELECT city AS c, sum(annual_salary) FROM demo.customers GROUP BY c LIMIT 1')"
served "a date bucket reached through its alias" \
  "$(p "SELECT date_trunc('month', placed_at) AS m, sum(order_total) FROM demo.orders GROUP BY m LIMIT 1")"

# 2. The same thing with a filter instead of a grouping. Not governed and not
#    governable statically: whether `WHERE id=1` matches one row is a property
#    of the data, not the statement. It costs a query per row rather than one
#    query for the table, which is the whole of what guard 1 buys.
possible "sum() filtered to one row is that row" \
  "$TRUE_SALARY" "$(p 'SELECT sum(annual_salary) FROM demo.customers WHERE id=1')"

# 3. Ordering by a masked column and projecting a released one.
possible "ORDER BY a masked column ranks the rows" \
  "$(psql -w "$D" -X -tAq -c 'SELECT id FROM demo.customers ORDER BY email LIMIT 1')" \
  "$(p 'SELECT id FROM demo.customers ORDER BY email LIMIT 1')"

# 4. The filter side is ungoverned, so equality confirms a guess.
possible "WHERE on a masked column confirms a guess" \
  "1" "$(p "SELECT count(*) FROM demo.customers WHERE id=1 AND email='$TRUE_EMAIL'")"

# 5. An error is a one-bit channel that needs no aggregate at all.
#
# Detected by comparing the two branches, not by looking for "division by zero"
# in the output. That is what this used to do, and when the proxy started
# withholding error text the check reported GOVERNED — while the channel was
# untouched. An oracle that reads a message is measuring the message; this one
# is a *difference*, so the test has to be a difference too.
oracle_true=$(p "SELECT 1/(CASE WHEN (SELECT email FROM demo.customers WHERE id=1) LIKE 'user1%' THEN 0 ELSE 1 END)")
oracle_false=$(p "SELECT 1/(CASE WHEN (SELECT email FROM demo.customers WHERE id=1) LIKE 'zzzz%' THEN 0 ELSE 1 END)")
if [[ "$oracle_true" != "$oracle_false" ]]; then
  printf '  \033[33mRECOVERABLE\033[0m  %s\n' "an error discloses a predicate"
  ((recoverable++))
else
  printf '  \033[32mGOVERNED\033[0m     %s\n        (both branches returned: %s)\n' \
    "an error discloses a predicate" "$oracle_true"
  ((fail++))
fi

# 6. And the whole value, character by character, through the proxy only.
echo
echo "  full recovery of one masked value, proxy only:"
recovered=$(python3 - "$P" <<'PY'
import subprocess, sys, os
url = sys.argv[1]
env = dict(os.environ, PGPASSWORD="demo")
def count(where):
    out = subprocess.run(["psql", "-w", url, "-X", "-tAq", "-c",
        f"SELECT count(*) FROM demo.customers WHERE id=1 AND {where}"],
        capture_output=True, text=True, env=env)
    return out.stdout.strip()
alphabet = "abcdefghijklmnopqrstuvwxyz0123456789@._-"
got, queries = "", 0
for _ in range(32):
    for ch in alphabet:
        queries += 1
        if count(f"email LIKE '{got}{ch}%'") == "1":
            got += ch
            break
    else:
        break
print(f"{got}\t{queries}")
PY
)
value=${recovered%%$'\t'*}; queries=${recovered##*$'\t'}
possible "$queries count(*) queries recover the address" "$TRUE_EMAIL" "$value"

echo
echo "------------------------------------------"
printf '%d still recoverable, %d governed, %d unexpected\n' "$recoverable" "$governed" "$fail"
# Any change here is worth a human deciding about, in either direction.
[[ "$fail" -eq 0 ]] || {
  echo
  echo "Something that used to be recoverable no longer is. That is good news,"
  echo "but the threat model in analysis.rs and README.md describes the old"
  echo "behaviour — update them, then update this suite."
  exit 1
}

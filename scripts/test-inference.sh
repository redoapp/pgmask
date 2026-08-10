#!/usr/bin/env bash
# What an adversarial client can still reconstruct.
#
#   ./scripts/test-inference.sh
#
# Every other suite here asks the same question: does a masked value appear in
# the output? That is the property the proxy enforces, and it enforces it well —
# 176,000 generated statements found nothing.
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
# The ordinal names `id`, so this is the same attack written differently — and
# pgmask cannot resolve `1` to a column, so it refuses on the weaker ground that
# a grouping it cannot read is one it cannot clear.
#
# `GROUP BY 1` with `sum(...)` as the *only* target is not this test: Postgres
# rejects it outright ("aggregate functions are not allowed in GROUP BY"), so
# the assertion would pass on a server error without the proxy deciding
# anything. It did, until `governed` began requiring a pgmask refusal.
governed "...and the same attack through an ordinal" \
  "$TRUE_SALARY" "$(p 'SELECT id, sum(annual_salary) FROM demo.customers GROUP BY 1 ORDER BY 1 LIMIT 1')"

# The cost of that conservatism, pinned so it is visible: grouping by a non-key
# through an ordinal is harmless and is refused anyway.
governed "(cost) an unreadable grouping is refused even on a non-key" \
  "$TRUE_SALARY" "$(p 'SELECT city, sum(annual_salary) FROM demo.customers GROUP BY 1 LIMIT 1')"

# Real aggregation is untouched, which is the whole point of doing it this way.
if [[ "$(p 'SELECT sum(annual_salary) FROM demo.customers')" == *"pgmask:"* ]]; then
  echo "  FAIL: an ungrouped aggregate must still be released"; fail=$((fail+1))
else
  printf '  \033[32mok\033[0m           a real aggregate is still served\n'; governed=$((governed+1))
fi

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
possible "an error discloses a predicate" \
  "division by zero" \
  "$(p "SELECT 1/(CASE WHEN (SELECT email FROM demo.customers WHERE id=1) LIKE 'user1%' THEN 0 ELSE 1 END)")"

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

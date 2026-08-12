#!/usr/bin/env bash
# A long campaign using a grammar nobody here wrote.
#
#   ./scripts/soak-sqlsmith.sh [hours] [queries-per-round]     # default 4, 400
#   tail -f /tmp/pgmask-sqlsmith-soak.status
#
# `soak.sh` runs `shapegen` for hours. This runs **sqlsmith** for hours, which
# is the same idea against a grammar I did not write — the distinction that
# matters, because before v0.1.36 `shapegen` could not express two of the six
# original disclosures and no amount of running it would have found them.
#
# One container for the whole run and a fresh seed per round. sqlsmith builds
# from catalog OIDs, so a new seed against the *same* catalog is what varies the
# corpus; recreating the container each round would be slower and would also
# change the OIDs, making a seed meaningless as a label.
#
# EVERY ROUND CHECKS ITS OWN CONTROLS
#
# A round that reaches no masked data, or serves no masked value, is not a clean
# round — it is a round that measured nothing, and averaging it into a total is
# how 500,000 statements come to mean less than they look like. Such a round
# aborts the run rather than being counted.
#
# DO NOT RUN THE RELEASE GATE OR THE MUTATION CAMPAIGN ALONGSIDE THIS.
# `test-all.sh` removes `pgmask-*` containers by name and kills proxies.
set -uo pipefail
cd "$(dirname "$0")/.."
source "$(dirname "$0")/lib/container.sh"

HOURS="${1:-4}"
PER_ROUND="${2:-400}"
CONTAINER=pgmask-sqlsmith-soak
PG_PORT=55441
PROXY_PORT=6443
STATUS=/tmp/pgmask-sqlsmith-soak.status
: >"$STATUS"

say() { printf '%s  %s\n' "$(date -u +%H:%M:%S)" "$*" | tee -a "$STATUS"; }

cleanup() {
  [[ -n "${PROXY_PID:-}" ]] && kill "$PROXY_PID" 2>/dev/null
  [[ "${KEEP:-0}" == "1" ]] || podman rm -f -v "$CONTAINER" >/dev/null 2>&1
}
trap cleanup EXIT

command -v sqlsmith >/dev/null || { say "FAIL: sqlsmith is required"; exit 3; }
cargo build -q --release -p pgmask || { say "FAIL: build"; exit 1; }

podman rm -f -v "$CONTAINER" >/dev/null 2>&1
podman run -d --name "$CONTAINER" -e POSTGRES_HOST_AUTH_METHOD=trust \
  -p "$PG_PORT":5432 docker.io/library/postgres:17 >/dev/null || exit 1
pg_await "$CONTAINER" "$PG_PORT" "sqlsmith soak" || exit 1

# Same schema and catalog as the gate's single-shot suite, so a finding here is
# reproducible with `./scripts/test-sqlsmith.sh`.
sed -n '/^CREATE SCHEMA smith;/,/^ANALYZE;/p' scripts/test-sqlsmith.sh |
  podman exec -i "$CONTAINER" psql -U postgres -q
# The fixture has to be the fixture. Verified, not assumed.
#
# A soak run reported 165 canary-carrying lines through the proxy and it was a
# false positive: that container's `city` column contained `CANARYNAME…`, and
# `city` is deliberately *released*, so the proxy was correctly passing through
# a column that happened to hold the token the check greps for. Bisecting to the
# statement and diffing direct against proxied is what exposed it — the direct
# output read `CANARYNAME150|CANARYNAME150`, which no correct fixture produces.
#
# A canary check is only as good as the assumption that canaries appear *only*
# in masked columns. That assumption is now tested rather than trusted.
fixture_ok=$(psql "host=127.0.0.1 port=$PG_PORT user=postgres dbname=postgres" -X -tAq -c "
  SELECT count(*) FROM smith.people
   WHERE id BETWEEN 1 AND 200
     AND email = 'CANARYMAIL' || id || '@example.com'
     AND full_name = 'CANARYNAME' || id
     AND note = 'CANARYNOTE' || id
     AND city IN ('Portland','Denver','Austin')" 2>/dev/null)
if [[ "${fixture_ok:-0}" != "200" ]]; then
  say "FAIL: the fixture is not what this test assumes (${fixture_ok:-0}/200 rows correct)."
  say "      A canary in a released column reads as a leak. Recreate the container."
  exit 1
fi

sed -n '/^listen        =/,/^mask     = "date-month"/p' scripts/test-sqlsmith.sh |
  sed "s/\$PROXY_PORT/$PROXY_PORT/; s/\$PG_PORT/$PG_PORT/" >/tmp/pgmask-sqlsmith-soak.toml
grep -q '^\[\[column\]\]' /tmp/pgmask-sqlsmith-soak.toml || {
  say "FAIL: could not lift the catalog out of test-sqlsmith.sh"; exit 1
}

sed -n '/^SELECT email, full_name, note/,/^SELECT city, email/p' scripts/test-sqlsmith.sh \
  >/tmp/pgmask-sqlsmith-soak-plain.sql
[[ -s /tmp/pgmask-sqlsmith-soak-plain.sql ]] || {
  say "FAIL: could not lift the control statements"; exit 1
}

./target/release/pgmask /tmp/pgmask-sqlsmith-soak.toml >/tmp/pgmask-sqlsmith-soak.log 2>&1 &
PROXY_PID=$!
for _ in $(seq 1 60); do
  grep -q "listening" /tmp/pgmask-sqlsmith-soak.log 2>/dev/null && break
  kill -0 "$PROXY_PID" 2>/dev/null || break
  sleep 0.5
done
kill -0 "$PROXY_PID" 2>/dev/null || {
  say "FAIL: the proxy exited"; tail -5 /tmp/pgmask-sqlsmith-soak.log; exit 1
}

DIRECT="host=127.0.0.1 port=$PG_PORT user=postgres dbname=postgres"
CANARIES='CANARYMAIL|CANARYNAME|CANARYNOTE'
deadline=$(( $(date +%s) + HOURS * 3600 ))
round=0
tot_q=0 tot_direct=0 tot_served=0 tot_leaked=0

#
# THE CORPUS IS REPLAYED READ-ONLY, AND THAT IS NOT A PRECAUTION
#
# sqlsmith generates DML. Roughly one statement in ten is a `delete`, `update`
# or `insert` against the schema it read, and replaying a 500-query corpus
# emptied `smith.people` outright — 200 rows before, 0 after, on both sides.
#
# Everything strange about the early runs was this. Canary counts collapsing
# from 353 to 123 to 1 across rounds; "no masked value was served" aborts once
# the table was empty; and the false positive that looked like a tenth
# disclosure, where `city` held `CANARYNAME…` because an sqlsmith `update` had
# written `full_name` into it. The fixture was not mysteriously wrong. The
# corpus was rewriting it.
#
# `default_transaction_read_only=on` in the replay session refuses the DML and
# serves the SELECTs, so every round sees the same data. sqlsmith has no flag
# for this; `--exclude-catalog` only keeps it out of `pg_catalog`.
replay() {  # port, file
  PGOPTIONS='-c default_transaction_read_only=on' \
  psql "host=127.0.0.1 port=$1 user=postgres dbname=postgres" \
    -X -q -A -t -v ON_ERROR_STOP=0 -f "$2" 2>&1
}

say "starting: ${HOURS}h, $PER_ROUND queries a round, sqlsmith grammar"
while [[ "$(date +%s)" -lt "$deadline" ]]; do
  round=$((round + 1))
  seed=$((round * 7919))

  sqlsmith --target="$DIRECT" --dry-run --exclude-catalog --seed="$seed" \
    --max-queries="$PER_ROUND" >/tmp/pgmask-sqlsmith-soak.sql 2>/dev/null
  n=$(grep -c ';' /tmp/pgmask-sqlsmith-soak.sql 2>/dev/null || echo 0)
  if [[ "$n" -lt $((PER_ROUND / 2)) ]]; then
    say "ABORT round $round: sqlsmith produced $n statements, expected ~$PER_ROUND"
    exit 1
  fi

  { replay "$PG_PORT" /tmp/pgmask-sqlsmith-soak.sql
    replay "$PG_PORT" /tmp/pgmask-sqlsmith-soak-plain.sql; } >/tmp/soak-smith.direct
  # The controls go to their own file as well as the combined one, so an abort
  # can say whether they ran at all rather than leaving it to be bisected.
  #
  # This also fixed an intermittent failure and I cannot tell you why. Written
  # as `{ replay corpus; replay plain; } >file`, the second replay's output went
  # missing from round 3 onward — the proxy log showed no session for it, and the
  # run aborted on "no masked value was served" having measured nothing. As two
  # invocations with their own redirections it has run clean since. The
  # difference is real and the mechanism is not established; if this recurs,
  # start there rather than assuming the proxy.
  replay "$PROXY_PORT" /tmp/pgmask-sqlsmith-soak.sql >/tmp/soak-smith.proxied
  replay "$PROXY_PORT" /tmp/pgmask-sqlsmith-soak-plain.sql >/tmp/soak-smith.plain
  cat /tmp/soak-smith.plain >>/tmp/soak-smith.proxied

  d=$(grep -cE "$CANARIES" /tmp/soak-smith.direct || true)
  p=$(grep -cE "$CANARIES" /tmp/soak-smith.proxied || true)
  m=$(grep -cE '@[0-9a-f]{8}\.invalid|\*\*\*' /tmp/soak-smith.proxied || true)

  # A round that measured nothing must not be averaged into a total.
  if [[ "$d" -eq 0 ]]; then
    say "ABORT round $round: the corpus reached no masked data (direct canaries 0)"
    exit 1
  fi
  if [[ "$m" -eq 0 ]]; then
    say "ABORT round $round: no masked value was served, so nothing observable ran"
    say "  the control replay returned $(wc -l </tmp/soak-smith.plain | tr -d ' ') lines:"
    head -4 /tmp/soak-smith.plain | sed 's/^/    /' | tee -a "$STATUS"
    exit 1
  fi
  if [[ "$p" -ne 0 ]]; then
    say "LEAK in round $round (seed $seed): $p canary-carrying lines through the proxy"
    grep -nE "$CANARIES" /tmp/soak-smith.proxied | head -5 | tee -a "$STATUS"
    cp /tmp/pgmask-sqlsmith-soak.sql "/tmp/pgmask-sqlsmith-leak-$seed.sql"
    say "corpus saved to /tmp/pgmask-sqlsmith-leak-$seed.sql"
    exit 1
  fi

  tot_q=$((tot_q + n))
  tot_direct=$((tot_direct + d))
  tot_served=$((tot_served + m))
  say "round $round: $tot_q queries, $tot_direct reached masked data, $tot_served masked values served, $tot_leaked leaks"
done

say "done: $round rounds, $tot_q queries, $tot_direct direct canary lines, $tot_served masked values served, 0 leaks"

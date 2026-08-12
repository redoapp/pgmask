#!/usr/bin/env bash
# A long-running campaign, for when the question is "is this safe" rather than
# "did this change break something".
#
#   ./scripts/soak.sh [hours]          # default 4
#
# DO NOT RUN THE RELEASE GATE AT THE SAME TIME. `scripts/test-all.sh` runs
# `pkill -f 'target/release/pgmask'` between suites and will kill this soak's
# proxies. The soak now aborts when that happens rather than counting the
# remaining rounds as clean, but the run is still lost.
#
# The release gate runs a fixed corpus and finishes in minutes. This runs a
# fresh corpus every round, for hours, across both wire protocols and both
# engines, and keeps a running total you can read while it works:
#
#   tail -f /tmp/pgmask-soak.status
#
# IT PROVES THE ORACLE CAN FAIL BEFORE IT TRUSTS A CLEAN RUN
#
# Round zero unmasks the catalog and requires the campaign to leak. If it does
# not, the run aborts and reports nothing else, because every clean round after
# that would be evidence of nothing. This is not hypothetical caution: three
# times in one day a detector here reported clean because the value never
# reached it — `int8`, then `numeric`, then `timestamptz`, each dropped by a
# type ladder one layer below the canaries. A campaign that cannot see is
# indistinguishable from a proxy that does not leak.
#
# WHAT A CLEAN RUN DOES AND DOES NOT MEAN
#
# It means: across N generated statements, no masked value appeared in a result
# set, on either protocol, on either engine, under four policy combinations.
#
# It does not mean the proxy is safe against an adversary. Reconstruction by
# inference is out of scope by design and `scripts/test-inference.sh` measures
# what remains — a full address in 313 counting queries, predicate oracles,
# error channels. It also cannot speak for rules no generated statement can
# express; `./target/release/reach` fails when a release path has no corpus
# behind it, and that is the check that bounds this one.

set -uo pipefail
cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:/opt/homebrew/bin:$PATH"

HOURS="${1:-4}"
PG_PORT=55701
PG_PROXY=6701
CRDB_PORT=55702
CRDB_PROXY=6702
PG_C=pgmask-soak-pg
CRDB_C=pgmask-soak-crdb
STATUS=/tmp/pgmask-soak.status
export PGPASSWORD=demo

cleanup() {
  killall pgmask 2>/dev/null
  [[ "${KEEP:-0}" == "1" ]] || podman rm -f -v "$PG_C" "$CRDB_C" >/dev/null 2>&1
}
trap cleanup EXIT

command -v podman >/dev/null || { echo "FAIL: podman is required"; exit 3; }

# Refuse to run against somebody else's database. A stale container holding one
# of these ports would silently become the fixture — that happened, and a suite
# reported 34 of 34 for a day against a database it had not created.
for port in "$PG_PORT" "$CRDB_PORT" "$PG_PROXY" "$CRDB_PROXY"; do
  if lsof -nP -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1; then
    echo "FAIL: something already listens on :$port — this soak would have used it"
    podman ps --format '  {{.Names}} {{.Ports}}' | grep "$port" || true
    exit 1
  fi
done

say() { printf '%s  %s\n' "$(date -u +%H:%M:%S)" "$*" | tee -a "$STATUS"; }

: > "$STATUS"
say "soak starting, budget ${HOURS}h"
cargo build --release -q || { echo "FAIL: build"; exit 1; }

# --- fixtures ---------------------------------------------------------------
podman run -d --name "$PG_C" -e POSTGRES_PASSWORD=demo -e POSTGRES_DB=fuzzdb \
  -p "$PG_PORT":5432 docker.io/library/postgres:17 >/dev/null || exit 1
# `--store=type=mem`: CockroachDB's own init step could not dial the node it had
# just started, and the container exited 1 — four suites in one gate run. Not
# resources (6.4 GB free, other containers using 60 MB) and not the image (the
# version is pinned and the arch is native). It is disk latency inside the
# podman VM: with an on-disk store the init exceeds its internal timeout, and
# the node's own log reports "node might be overloaded" for 0.5s raft writes.
# In memory it is ready in 20s. These containers are thrown away at the end of
# the suite, so there is nothing for a durable store to buy.
podman run -d --name "$CRDB_C" -p "$CRDB_PORT":26257 \
  docker.io/cockroachdb/cockroach:v25.4.14 start-single-node --insecure \
  --store=type=mem,size=2GiB >/dev/null || exit 1

PG="postgresql://postgres:demo@localhost:$PG_PORT/fuzzdb"
for _ in $(seq 1 90); do psql -w "$PG" -tAc 'select 1' >/dev/null 2>&1 && break; sleep 1; done
psql -w "$PG" -q -v ON_ERROR_STOP=1 -f examples/fuzz/schema.sql >/dev/null 2>&1 \
  || { echo "FAIL: postgres fixture"; exit 1; }

CRDB="postgresql://root@localhost:$CRDB_PORT/defaultdb?sslmode=disable"
for _ in $(seq 1 90); do psql -w "$CRDB" -tAc 'select 1' >/dev/null 2>&1 && break; sleep 1; done
psql -w "$CRDB" -q -f examples/fuzz/schema.sql >/tmp/soak-crdb-fixture.log 2>&1
rows=$(psql -w "$CRDB" -X -tAc 'SELECT count(*) FROM fz.people' 2>/dev/null)
[[ "${rows:-0}" -gt 0 ]] || {
  echo "FAIL: CockroachDB fixture is empty — the soak would have run against nothing"
  tail -5 /tmp/soak-crdb-fixture.log
  exit 1
}
say "fixtures up"

mkcfg() { # port backend out dsn [unmask]
  # The DSN as well as the port. Rewriting only the port left CockroachDB's
  # proxy pointing at `postgres:demo@...` and it died on password auth — the
  # catalog_dsn is a separate connection from the backend address.
  sed -e "s|55432|$2|g" -e "s|^listen = .*|listen = \"127.0.0.1:$1\"|" \
      -e "s|^catalog_dsn = .*|catalog_dsn = \"$4\"|" \
      -e 's|^lineage = .*|lineage = "allow"|' -e 's/^metrics_listen.*//' \
      examples/fuzz/catalog.toml > "$3"
  # The poison configuration: strip every mask so the oracle must fire.
  [[ "${5:-}" == "unmask" ]] && sed -i '' -e 's/^mask = .*/mask = "none"/' "$3"
}

wait_proxy() { for _ in $(seq 1 120); do
    (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null && { exec 3>&- 3<&-; return 0; }
    sleep 0.25; done; return 1; }

# --- round zero: prove the oracle can fail ----------------------------------
say "round 0: poison control"
mkcfg "$PG_PROXY" "$PG_PORT" /tmp/soak-poison.toml "$PG" unmask
(./target/release/pgmask /tmp/soak-poison.toml >/tmp/soak-poison.log 2>&1 &)
wait_proxy "$PG_PROXY" || { echo "FAIL: poison proxy"; tail -5 /tmp/soak-poison.log; exit 1; }
# Round zero runs against Postgres alone, so it gets the full dialect —
# `ROLLUP`, `CUBE` and `GROUPING SETS` included. The soak proper below shares
# one corpus with CockroachDB and cannot.
./target/release/shapegen 1 800 postgres > /tmp/soak-poison.sql 2>/dev/null
poison=$(DIRECT_URL="$PG" PROXY_URL="postgresql://postgres:demo@localhost:$PG_PROXY/fuzzdb" \
  ./target/release/extended /tmp/soak-poison.sql 2>&1 | grep -oE "leaks=[0-9]+" | cut -d= -f2)
killall pgmask 2>/dev/null; sleep 1
if [[ "${poison:-0}" -eq 0 ]]; then
  say "ABORT: the oracle found nothing with masking removed — it is blind, and"
  say "       every clean round after this would have meant nothing."
  exit 1
fi
say "round 0: ${poison} leaks with masking removed — the oracle can fail"

# --- the soak ---------------------------------------------------------------
mkcfg "$PG_PROXY"   "$PG_PORT"   /tmp/soak-pg.toml   "$PG"
mkcfg "$CRDB_PROXY" "$CRDB_PORT" /tmp/soak-crdb.toml "$CRDB"
(./target/release/pgmask /tmp/soak-pg.toml   >/tmp/soak-pg.log   2>&1 &)
(./target/release/pgmask /tmp/soak-crdb.toml >/tmp/soak-crdb.log 2>&1 &)
wait_proxy "$PG_PROXY"   || { echo "FAIL: pg proxy";   tail -5 /tmp/soak-pg.log;   exit 1; }
wait_proxy "$CRDB_PROXY" || { echo "FAIL: crdb proxy"; tail -5 /tmp/soak-crdb.log; exit 1; }

deadline=$(( $(date +%s) + HOURS * 3600 ))
round=0; stmts=0; leaks=0; served=0; refused=0

while (( $(date +%s) < deadline )); do
  round=$(( round + 1 ))
  seed=$(( round * 7919 + 13 ))
  # One corpus, replayed against both engines below, so it has to parse on
  # both: CockroachDB rejects the Postgres-only grouping syntax outright.
  ./target/release/shapegen "$seed" 2000 portable > /tmp/soak-corpus.sql 2>/dev/null

  for engine in pg crdb; do
    if [[ "$engine" == pg ]]; then D="$PG"; P="postgresql://postgres:demo@localhost:$PG_PROXY/fuzzdb"
    else D="$CRDB"; P="postgresql://root@localhost:$CRDB_PROXY/defaultdb?sslmode=disable"; fi
    out=$(DIRECT_URL="$D" PROXY_URL="$P" ./target/release/extended /tmp/soak-corpus.sql 2>&1)
    r=$(printf '%s' "$out" | grep -oE "^RESULT.*")

    # A round that did not run is not a round that found nothing.
    #
    # This counted 2,000 statements per engine whether or not the harness had
    # executed anything, so when the release gate's `pkill -f
    # 'target/release/pgmask'` killed these proxies mid-soak, the loop went on
    # reporting "0 leaks" — 800,000 statements of fiction in under a minute,
    # served and refused frozen at the values from the last real round. Exactly
    # the vacuity this soak's round zero exists to prevent, in the soak itself.
    if [[ -z "$r" ]]; then
      say "ABORT: no RESULT from $engine on seed $seed — the harness did not run."
      say "       Nothing after the last real round can be believed."
      printf '%s\n' "$out" | tail -6 | tee -a "$STATUS"
      exit 1
    fi
    n=$(printf '%s' "$r" | grep -oE "leaks=[0-9]+" | cut -d= -f2)
    s=$(printf '%s' "$r" | grep -oE "served=[0-9]+" | cut -d= -f2)
    f=$(printf '%s' "$r" | grep -oE "refused=[0-9]+" | cut -d= -f2)
    # A RESULT that served and refused nothing is a connection that produced no
    # verdicts, which is the same emptiness wearing a well-formed line.
    if [[ "${s:-0}" -eq 0 && "${f:-0}" -eq 0 ]]; then
      say "ABORT: $engine seed $seed served and refused nothing — no verdicts were reached."
      printf '%s\n' "$out" | tail -6 | tee -a "$STATUS"
      exit 1
    fi
    stmts=$(( stmts + 2000 )); leaks=$(( leaks + ${n:-0} ))
    served=$(( served + ${s:-0} )); refused=$(( refused + ${f:-0} ))
    if [[ "${n:-0}" -ne 0 ]]; then
      say "LEAK on $engine, seed $seed — corpus kept at /tmp/soak-leak-$seed.sql"
      cp /tmp/soak-corpus.sql "/tmp/soak-leak-$seed.sql"
      printf '%s\n' "$out" | grep -A 2 "leaked" | head -20 | tee -a "$STATUS"
      exit 1
    fi
    # An undecodable value is a value no detector saw. The harness fails on it;
    # surface it here too rather than let a nonzero exit scroll past.
    if printf '%s' "$out" | grep -q "UNDECODABLE"; then
      say "BLIND SPOT on $engine, seed $seed:"
      printf '%s' "$out" | grep -A 4 "UNDECODABLE" | tee -a "$STATUS"
      exit 1
    fi
  done

  say "round $round: $stmts statements, $served served, $refused refused, $leaks leaks"
done

say "-------------------------------------------------------------"
say "soak complete: $round rounds, $stmts statements, 0 leaks"
say "  served $served   refused $refused"
say "  both protocols, Postgres 17 and CockroachDB v25.4.14"
say "  the oracle was proven able to fail before any of this was believed"

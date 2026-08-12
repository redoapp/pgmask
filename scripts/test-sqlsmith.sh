#!/usr/bin/env bash
# Adversarial SQL from a grammar nobody here wrote.
#
#   ./scripts/test-sqlsmith.sh [queries]        # default 2000
#
# Every other campaign in this repository generates SQL from `shapegen`, which
# I wrote — so it explores the shapes I thought of. That is not a small caveat:
# before v0.1.36 the generator could not express `SELECT * FROM (…)` or
# `GROUPING SETS` at all, and two of the six disclosures were unreachable by it
# for that reason alone. The grammar was the binding constraint, not volume.
#
# sqlsmith is an independent generator: it reads the live catalog, builds
# semantically-valid random queries against whatever schema it finds, and has
# found hundreds of real bugs in PostgreSQL itself. It knows nothing about
# pgmask and has no opinion about which shapes are interesting.
#
# HOW IT RUNS
#
# sqlsmith generates against a *direct* connection (`--dry-run`, so nothing is
# executed there) and the corpus is replayed through the proxy. Pointing it at
# the proxy instead would not work: it introspects `pg_catalog` to learn the
# schema, which the proxy refuses by default, so it would find no tables and
# generate nothing — the failure would look exactly like "no leaks found".
#
# THE CONTROL IS THE POINT
#
# The same corpus is replayed **direct** as well, and the run fails if that does
# not surface canaries. Without it, "no canary through the proxy" is equally
# consistent with a corpus that never touched a masked column — which is the
# likelier outcome, since most of what sqlsmith emits errors out.
set -uo pipefail
cd "$(dirname "$0")/.."

QUERIES="${1:-2000}"
CONTAINER=pgmask-sqlsmith
PG_PORT=55439
PROXY_PORT=6441
SEED="${SEED:-1}"
# `--seed` alone does not reproduce a corpus: sqlsmith builds from the catalog
# it reads, and the OIDs differ every time the schema is created, so the same
# seed against a fresh container yields different SQL. Observed direct canary
# counts of 353, 123 and 1 across three runs at seed 1. Treat each run as an
# independent sample rather than a repeatable one.

cleanup() {
  [[ -n "${PROXY_PID:-}" ]] && kill "$PROXY_PID" 2>/dev/null
  [[ "${KEEP:-0}" == "1" ]] || podman rm -f -v "$CONTAINER" >/dev/null 2>&1
}
trap cleanup EXIT

command -v sqlsmith >/dev/null || { echo "FAIL: sqlsmith is required (brew install sqlsmith)"; exit 3; }
command -v podman >/dev/null   || { echo "FAIL: podman is required"; exit 3; }
command -v psql >/dev/null     || { echo "FAIL: psql is required"; exit 3; }

echo "==> building"
cargo build -q --release -p pgmask || { echo "FAIL: build"; exit 1; }

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

# A schema wide enough for sqlsmith to build joins and subqueries out of, with a
# distinctive token in every masked column. Types are varied on purpose: a
# generator that only ever sees `text` will only ever produce text expressions.
podman exec -i "$CONTAINER" psql -U postgres -q <<'SQL'
CREATE SCHEMA smith;
CREATE TABLE smith.people (
  id int PRIMARY KEY,
  email text NOT NULL,
  full_name text NOT NULL,
  city text NOT NULL,
  salary int NOT NULL,
  born date NOT NULL,
  account uuid NOT NULL,
  note text NOT NULL
);
CREATE TABLE smith.orders (
  id int PRIMARY KEY,
  person_id int REFERENCES smith.people(id),
  total int NOT NULL,
  ship_city text NOT NULL,
  placed timestamptz NOT NULL
);
CREATE VIEW smith.people_v AS SELECT id, email, city, salary FROM smith.people;
INSERT INTO smith.people
SELECT g,
       'CANARYMAIL' || g || '@example.com',
       'CANARYNAME' || g,
       (ARRAY['Portland','Denver','Austin'])[1 + g % 3],
       90000 + g,
       DATE '1980-01-01' + g,
       ('00000000-0000-4000-8000-' || lpad(g::text, 12, '0'))::uuid,
       'CANARYNOTE' || g
FROM generate_series(1, 200) g;
INSERT INTO smith.orders
SELECT g, 1 + g % 200, 1000 + g,
       (ARRAY['Portland','Denver','Austin'])[1 + g % 3],
       TIMESTAMPTZ '2024-01-01' + (g || ' hours')::interval
FROM generate_series(1, 200) g;
ANALYZE;
SQL

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
  echo "FAIL: the fixture is not what this test assumes (${fixture_ok:-0}/200 rows correct)."
  echo "      A canary in a released column reads as a leak. Recreate the container."
  exit 1
fi

cat >/tmp/pgmask-sqlsmith.toml <<EOF
listen        = "127.0.0.1:$PROXY_PORT"
backend       = "127.0.0.1:$PG_PORT"
catalog_dsn   = "postgres://postgres@127.0.0.1:$PG_PORT/postgres"
pseudonym_key = "sqlsmith-key-long-enough"
unclassified  = "mask"
summaries     = "allow"

[[column]]
relation = "smith.people"
column   = "id"
mask     = "none"

[[column]]
relation = "smith.people"
column   = "city"
mask     = "none"

[[column]]
relation = "smith.people"
column   = "email"
mask     = "pseudonym"

[[column]]
relation = "smith.people"
column   = "full_name"
mask     = "redact"

[[column]]
relation = "smith.people"
column   = "salary"
mask     = "numeric-bucket"
bucket   = 1000

[[column]]
relation = "smith.people"
column   = "born"
mask     = "date-year"

[[column]]
relation = "smith.people"
column   = "account"
mask     = "pseudonym"

[[column]]
relation = "smith.people"
column   = "note"
mask     = "null"

[[column]]
relation = "smith.people_v"
column   = "id"
mask     = "none"

[[column]]
relation = "smith.people_v"
column   = "city"
mask     = "none"

[[column]]
relation = "smith.people_v"
column   = "email"
mask     = "pseudonym"

[[column]]
relation = "smith.people_v"
column   = "salary"
mask     = "numeric-bucket"
bucket   = 1000

[[column]]
relation = "smith.orders"
column   = "id"
mask     = "none"

[[column]]
relation = "smith.orders"
column   = "person_id"
mask     = "none"

[[column]]
relation = "smith.orders"
column   = "total"
mask     = "numeric-bucket"
bucket   = 100

[[column]]
relation = "smith.orders"
column   = "ship_city"
mask     = "none"

[[column]]
relation = "smith.orders"
column   = "placed"
mask     = "date-month"
EOF

echo "==> generating $QUERIES queries with sqlsmith (seed $SEED)"
DIRECT="host=127.0.0.1 port=$PG_PORT user=postgres dbname=postgres"
sqlsmith --target="$DIRECT" --dry-run --exclude-catalog --seed="$SEED" \
  --max-queries="$QUERIES" >/tmp/pgmask-sqlsmith.sql 2>/dev/null
generated=$(grep -c ';' /tmp/pgmask-sqlsmith.sql 2>/dev/null || echo 0)

# Statements the proxy will definitely *serve*, replayed in their own session.
#
# NOT appended to the sqlsmith corpus, which is where they were first and why
# the poison reported zero. Several refusal paths close the connection —
# `out.close = true` for a COPY stream, an unrecognised backend message, a row
# with no active plan — and psql then fails every remaining statement in the
# file. Anything at the end of a long corpus therefore never runs, and the run
# reports whatever the truncated prefix happened to produce. It also explains
# direct canary counts of 353, 123 and 1 across runs: each replay died at a
# different statement.
#
# Without these the harness cannot be poisoned, which I found by trying: with
# every mask released it still reported zero canaries through the proxy. The
# reason is that sqlsmith writes expression-heavy SQL, and the proxy refuses a
# field with no column provenance whatever the catalog says — so releasing a
# mask cannot make a refused statement return data, and a corpus of refusals is
# indistinguishable from a corpus that is being masked correctly.
#
# A plain column reference has provenance and is served, so it is the only kind
# of statement whose masking is actually observable. sqlsmith supplies the
# adversarial breadth; these five make the result mean something.
cat >/tmp/pgmask-sqlsmith-plain.sql <<'PLAIN'
SELECT email, full_name, note FROM smith.people ORDER BY id LIMIT 5;
SELECT p.email, o.total FROM smith.people p JOIN smith.orders o ON o.person_id = p.id ORDER BY p.id LIMIT 5;
SELECT email FROM smith.people_v ORDER BY id LIMIT 5;
SELECT * FROM smith.people ORDER BY id LIMIT 5;
SELECT city, email FROM smith.people WHERE id < 10 ORDER BY id;
PLAIN
if [[ "$generated" -lt $((QUERIES / 2)) ]]; then
  echo "FAIL: sqlsmith produced $generated statements, expected about $QUERIES."
  echo "      It introspects the catalog to find tables; if it found none it"
  echo "      emits little and every leak check below passes for that reason."
  exit 1
fi
echo "    $generated statements"

echo "==> starting the proxy"
./target/release/pgmask /tmp/pgmask-sqlsmith.toml >/tmp/pgmask-sqlsmith.log 2>&1 &
PROXY_PID=$!
for _ in $(seq 1 60); do
  grep -q "listening" /tmp/pgmask-sqlsmith.log 2>/dev/null && break
  kill -0 "$PROXY_PID" 2>/dev/null || break
  sleep 0.5
done
kill -0 "$PROXY_PID" 2>/dev/null || {
  echo "FAIL: the proxy exited"; tail -5 /tmp/pgmask-sqlsmith.log; exit 1
}

# Replay in one psql session per side, continuing past errors. Most of what
# sqlsmith emits fails on types or functions, which is expected and fine — the
# ones that succeed are the sample.
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
replay() {
  PGOPTIONS='-c default_transaction_read_only=on' \
  psql "host=127.0.0.1 port=$1 user=postgres dbname=postgres" \
    -X -q -A -t -v ON_ERROR_STOP=0 -f /tmp/pgmask-sqlsmith.sql 2>&1
}

# Two sessions per side. A connection the proxy closes mid-corpus must not take
# the controls with it.
replay_plain() {
  PGOPTIONS='-c default_transaction_read_only=on' \
  psql "host=127.0.0.1 port=$1 user=postgres dbname=postgres" \
    -X -q -A -t -v ON_ERROR_STOP=0 -f /tmp/pgmask-sqlsmith-plain.sql 2>&1
}

echo "==> replaying direct (the control)"
{ replay "$PG_PORT"; replay_plain "$PG_PORT"; } >/tmp/pgmask-sqlsmith.direct
echo "==> replaying through the proxy"
{ replay "$PROXY_PORT"; replay_plain "$PROXY_PORT"; } >/tmp/pgmask-sqlsmith.proxied

canaries='CANARYMAIL|CANARYNAME|CANARYNOTE'
d_hits=$(grep -cE "$canaries" /tmp/pgmask-sqlsmith.direct || true)
p_hits=$(grep -cE "$canaries" /tmp/pgmask-sqlsmith.proxied || true)
d_rows=$(wc -l </tmp/pgmask-sqlsmith.direct | tr -d ' ')
p_rows=$(wc -l </tmp/pgmask-sqlsmith.proxied | tr -d ' ')

echo
echo "-------------------------------------------------------------"
printf '  generated        %s\n' "$generated"
printf '  direct output    %s lines, %s carrying a canary\n' "$d_rows" "$d_hits"
printf '  proxied output   %s lines, %s carrying a canary\n' "$p_rows" "$p_hits"
printf '  masked values served %s\n' "$(grep -cE '@[0-9a-f]{8}\.invalid|\*\*\*' /tmp/pgmask-sqlsmith.proxied || true)"
echo "-------------------------------------------------------------"

# The masked forms have to be visible too, or "no canary" is equally consistent
# with the proxy refusing every one of the five statements above.
served=$(grep -cE '@[0-9a-f]{8}\.invalid|\*\*\*' /tmp/pgmask-sqlsmith.proxied || true)

fail=0
if [[ "$served" -eq 0 ]]; then
  echo "FAIL: no masked value appears in the proxied output, so nothing"
  echo "      observable was served and the zero below is meaningless."
  fail=1
fi
if [[ "$d_hits" -eq 0 ]]; then
  echo "FAIL: the control found no canaries directly, so this corpus never"
  echo "      reached a masked column and the proxy result means nothing."
  echo "      Raise the query count or widen the schema."
  fail=1
fi
if [[ "$p_hits" -ne 0 ]]; then
  echo "FAIL: $p_hits canary-carrying lines came through the proxy:"
  grep -nE "$canaries" /tmp/pgmask-sqlsmith.proxied | head -5 | sed 's/^/        /'
  fail=1
fi
[[ "$fail" -eq 0 ]] && echo "  no canary crossed the boundary, and the control proves it could have."
exit "$fail"

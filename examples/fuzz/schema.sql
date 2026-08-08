-- Fixture for the generated-SQL fuzzer.
--
-- sqlsmith picks relations uniformly, so the schema has to be wide enough that
-- `--exclude-catalog` does not starve, and every table has to hold rows —
-- a query against an empty table cannot leak anything, and a run of those is a
-- vacuous pass.
--
-- Every text column here contains the token CANARY. Masking rewrites all of
-- them, so a CANARY reaching the client is a leak, whatever route it took.
DROP SCHEMA IF EXISTS fz CASCADE;
CREATE SCHEMA fz;

CREATE TABLE fz.t1 (id int primary key, a text, b text, n int, d date, u uuid);
CREATE TABLE fz.t2 (id int primary key, a text, b text, n int, d date, u uuid);
CREATE TABLE fz.t3 (id int primary key, a text, b text, n int, d date, u uuid);
CREATE TABLE fz.t4 (id int primary key, a text, b text, n int, d date, u uuid);
CREATE TABLE fz.t5 (id int primary key, a text, b text, n int, d date, u uuid);
CREATE TABLE fz.t6 (id int primary key, a text, b text, n int, d date, u uuid);
CREATE TABLE fz.t7 (id int primary key, a text, b text, n int, d date, u uuid);
CREATE TABLE fz.t8 (id int primary key, a text, b text, n int, d date, u uuid);

-- Small tables, so random joins still return rows instead of exploding.
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['t1','t2','t3','t4','t5','t6','t7','t8'] LOOP
    EXECUTE format($f$
      INSERT INTO fz.%I (id, a, b, n, d, u)
      SELECT i,
             'CANARY-%s-a-' || i,
             'CANARY-%s-b-' || i,
             i * 7,
             DATE '1980-03-04' + i,
             ('00000000-0000-4000-9000-' || lpad(i::text, 12, '0'))::uuid
        FROM generate_series(1, 40) AS i$f$, t, t, t);
  END LOOP;
END $$;

-- PII-shaped, so the type-aware masks are exercised and not just `redact`.
-- Values are chosen so the masked form is *recognisably different*: dates are
-- never 1 January, addresses never end .0, uuids carry a fixed prefix. The
-- masked output of each is a shape the raw value never has, which is what lets
-- the oracle check them without an expected-output file.
CREATE TABLE fz.people (
  id            int primary key,
  email         text not null,
  full_name     text not null,
  phone         text not null,
  city          text not null,
  birth_date    date not null,
  annual_salary int  not null,
  last_ip       text not null,
  account_uuid  uuid not null,
  note          text
);

INSERT INTO fz.people
SELECT i,
       'CANARY-mail-' || i || '@fuzz.example',
       'CANARY-name-' || i,
       '555-77' || lpad((i % 100)::text, 2, '0'),
       (ARRAY['Leeds','Derby','Truro','Ely'])[1 + (i % 4)],
       -- never 1 January, so a year-truncated value is distinguishable
       DATE '1975-02-03' + (i * 11),
       41111 + i * 137,
       -- never .0, so a /24-masked value is distinguishable
       '198.51.100.' || (1 + (i % 250)),
       ('00000000-0000-4000-a000-' || lpad(i::text, 12, '0'))::uuid,
       'CANARY-note-' || i
  FROM generate_series(1, 60) AS i;

ANALYZE fz.people;

-- A view and a join view, because those lose provenance differently.
CREATE VIEW fz.v_union AS SELECT id, a FROM fz.t1 UNION ALL SELECT id, a FROM fz.t2;
CREATE VIEW fz.v_join  AS SELECT x.id, x.a AS xa, y.b AS yb FROM fz.t3 x JOIN fz.t4 y ON y.id = x.id;

ANALYZE fz.t1; ANALYZE fz.t2; ANALYZE fz.t3; ANALYZE fz.t4;
ANALYZE fz.t5; ANALYZE fz.t6; ANALYZE fz.t7; ANALYZE fz.t8;

-- Two principals, so concurrent sessions can be checked for role bleed: the
-- same column resolves differently per person, and a plan escaping its session
-- would be a disclosure that no single-principal test can see.
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'support_sam') THEN
    CREATE ROLE support_sam LOGIN PASSWORD 'demo';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'analyst_ann') THEN
    CREATE ROLE analyst_ann LOGIN PASSWORD 'demo';
  END IF;
END $$;
GRANT USAGE ON SCHEMA fz TO support_sam, analyst_ann;
GRANT SELECT ON ALL TABLES IN SCHEMA fz TO support_sam, analyst_ann;

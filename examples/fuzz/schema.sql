-- Fixture for the generated-SQL fuzzer.
--
-- Integer widths are always explicit. A bare `int` is int4 on Postgres and
-- int8 on CockroachDB, so the same fixture produced different column types per
-- engine and a typed driver could not read both. `salary_big` is deliberately
-- int8 on both.
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

CREATE TABLE fz.t1 (id int4 primary key, a text, b text, n int4, d date, u uuid);
CREATE TABLE fz.t2 (id int4 primary key, a text, b text, n int4, d date, u uuid);
CREATE TABLE fz.t3 (id int4 primary key, a text, b text, n int4, d date, u uuid);
CREATE TABLE fz.t4 (id int4 primary key, a text, b text, n int4, d date, u uuid);
CREATE TABLE fz.t5 (id int4 primary key, a text, b text, n int4, d date, u uuid);
CREATE TABLE fz.t6 (id int4 primary key, a text, b text, n int4, d date, u uuid);
CREATE TABLE fz.t7 (id int4 primary key, a text, b text, n int4, d date, u uuid);
CREATE TABLE fz.t8 (id int4 primary key, a text, b text, n int4, d date, u uuid);

-- Small tables, so random joins still return rows instead of exploding.
--
-- Written out rather than looped in plpgsql: CockroachDB has no DO block, and
-- this fixture has to load on both engines from one file.

INSERT INTO fz.t1 (id, a, b, n, d, u)
SELECT i, 'CANARY-t1-a-' || i, 'CANARY-t1-b-' || i, i * 7,
       DATE '1980-03-04' + i,
       ('00000000-0000-4000-9000-' || lpad(i::text, 12, '0'))::uuid
  FROM generate_series(1, 40) AS i;
INSERT INTO fz.t2 (id, a, b, n, d, u)
SELECT i, 'CANARY-t2-a-' || i, 'CANARY-t2-b-' || i, i * 7,
       DATE '1980-03-04' + i,
       ('00000000-0000-4000-9000-' || lpad(i::text, 12, '0'))::uuid
  FROM generate_series(1, 40) AS i;
INSERT INTO fz.t3 (id, a, b, n, d, u)
SELECT i, 'CANARY-t3-a-' || i, 'CANARY-t3-b-' || i, i * 7,
       DATE '1980-03-04' + i,
       ('00000000-0000-4000-9000-' || lpad(i::text, 12, '0'))::uuid
  FROM generate_series(1, 40) AS i;
INSERT INTO fz.t4 (id, a, b, n, d, u)
SELECT i, 'CANARY-t4-a-' || i, 'CANARY-t4-b-' || i, i * 7,
       DATE '1980-03-04' + i,
       ('00000000-0000-4000-9000-' || lpad(i::text, 12, '0'))::uuid
  FROM generate_series(1, 40) AS i;
INSERT INTO fz.t5 (id, a, b, n, d, u)
SELECT i, 'CANARY-t5-a-' || i, 'CANARY-t5-b-' || i, i * 7,
       DATE '1980-03-04' + i,
       ('00000000-0000-4000-9000-' || lpad(i::text, 12, '0'))::uuid
  FROM generate_series(1, 40) AS i;
INSERT INTO fz.t6 (id, a, b, n, d, u)
SELECT i, 'CANARY-t6-a-' || i, 'CANARY-t6-b-' || i, i * 7,
       DATE '1980-03-04' + i,
       ('00000000-0000-4000-9000-' || lpad(i::text, 12, '0'))::uuid
  FROM generate_series(1, 40) AS i;
INSERT INTO fz.t7 (id, a, b, n, d, u)
SELECT i, 'CANARY-t7-a-' || i, 'CANARY-t7-b-' || i, i * 7,
       DATE '1980-03-04' + i,
       ('00000000-0000-4000-9000-' || lpad(i::text, 12, '0'))::uuid
  FROM generate_series(1, 40) AS i;
INSERT INTO fz.t8 (id, a, b, n, d, u)
SELECT i, 'CANARY-t8-a-' || i, 'CANARY-t8-b-' || i, i * 7,
       DATE '1980-03-04' + i,
       ('00000000-0000-4000-9000-' || lpad(i::text, 12, '0'))::uuid
  FROM generate_series(1, 40) AS i;

-- PII-shaped, so the type-aware masks are exercised and not just `redact`.
-- Values are chosen so the masked form is *recognisably different*: dates are
-- never 1 January, addresses never end .0, uuids carry a fixed prefix. The
-- masked output of each is a shape the raw value never has, which is what lets
-- the oracle check them without an expected-output file.
CREATE TABLE fz.people (
  id            int4 primary key,
  email         text not null,
  full_name     text not null,
  phone         text not null,
  city          text not null,
  birth_date    date not null,
  -- Explicit widths. A bare `int` is int4 on Postgres and int8 on
  -- CockroachDB, so the binary suite could not decode the same column on
  -- both engines — and int8 had no end-to-end coverage anywhere as a
  -- result, though the mask handles it.
  annual_salary int4 not null,
  salary_big    int8 not null,
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
       9000000000 + i * 137,
       -- never .0, so a /24-masked value is distinguishable
       '198.51.100.' || (1 + (i % 250)),
       ('00000000-0000-4000-a000-' || lpad(i::text, 12, '0'))::uuid,
       'CANARY-note-' || i
  FROM generate_series(1, 60) AS i;

ANALYZE fz.people;

-- A view and a join view, because those lose provenance differently.
CREATE VIEW fz.v_union AS SELECT id, a FROM fz.t1 UNION ALL SELECT id, a FROM fz.t2;
CREATE VIEW fz.v_join  AS SELECT x.id, x.a AS xa, y.b AS yb FROM fz.t3 x JOIN fz.t4 y ON y.id = x.id;

-- The armed trap: one output column drawing from a released column and a masked
-- one. Both engines report provenance for `v` — Postgres names the view's own
-- column, CockroachDB names the first branch's base column — so releasing `v`
-- releases addresses. The catalog does release it, deliberately.
--
-- fz.v_union was not this: its `a` is masked by an explicit `redact` rule, so
-- the campaign had generated queries against a union view for as long as this
-- fixture existed without ever being able to catch the bug.
CREATE VIEW fz.v_mixed AS
  SELECT id, city AS v FROM fz.people
  UNION ALL
  SELECT id, email FROM fz.people;

ANALYZE fz.t1; ANALYZE fz.t2; ANALYZE fz.t3; ANALYZE fz.t4;
ANALYZE fz.t5; ANALYZE fz.t6; ANALYZE fz.t7; ANALYZE fz.t8;

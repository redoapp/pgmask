-- Phase 0 provenance spike fixture.
--
-- Creates every relation kind whose RowDescription provenance behaviour we need
-- to know before committing to the masking-proxy design. Idempotent: drop and
-- recreate the whole schema on each run so results are reproducible.

DROP SCHEMA IF EXISTS spike CASCADE;
CREATE SCHEMA spike;
SET search_path TO spike;

-- Base tables ---------------------------------------------------------------

CREATE TABLE t (
  id     int PRIMARY KEY,
  email  text,
  name   text,
  city   text
);

CREATE TABLE u (
  id    int PRIMARY KEY,
  t_id  int REFERENCES t(id),
  note  text
);

INSERT INTO t VALUES
  (1, 'alice@example.com', 'Alice', 'Portland'),
  (2, 'bob@example.com',   'Bob',   'Portland'),
  (3, 'carol@example.com', 'Carol', 'Denver');

INSERT INTO u VALUES
  (10, 1, 'first'),
  (11, 1, 'second'),
  (12, 2, 'third');

-- Views ---------------------------------------------------------------------

CREATE VIEW v_t AS SELECT id, email, name, city FROM t;
CREATE VIEW v_nested AS SELECT id, email, name FROM v_t;
CREATE MATERIALIZED VIEW mv_t AS SELECT id, email, name FROM t;

-- A view whose *definition* contains a set operation. The statement selecting
-- from it looks innocent, so whatever provenance the engine reports here is
-- reported for a field with two different source columns.
CREATE VIEW v_union AS SELECT city AS v FROM t UNION ALL SELECT email FROM t;
CREATE VIEW v_over_union AS SELECT v FROM v_union;

-- Partitioned table ---------------------------------------------------------

CREATE TABLE p (
  id     int,
  region text,
  email  text
) PARTITION BY LIST (region);

CREATE TABLE p_west PARTITION OF p FOR VALUES IN ('west');
CREATE TABLE p_east PARTITION OF p FOR VALUES IN ('east');

INSERT INTO p VALUES (1, 'west', 'w@example.com'), (2, 'east', 'e@example.com');

-- Functions -----------------------------------------------------------------

-- Returns a table type: does provenance survive out of a set-returning
-- plpgsql function?
CREATE FUNCTION f_setof_t() RETURNS SETOF t AS $$
  SELECT * FROM t;
$$ LANGUAGE sql STABLE;

-- Returns an anonymous record shape.
CREATE FUNCTION f_table_out()
RETURNS TABLE (out_id int, out_email text) AS $$
  SELECT id, email FROM t;
$$ LANGUAGE sql STABLE;

-- Set-returning function used in the target list.
CREATE FUNCTION f_srf() RETURNS SETOF int AS $$
  SELECT generate_series(1, 3);
$$ LANGUAGE sql IMMUTABLE;

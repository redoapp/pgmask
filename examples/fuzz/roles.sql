-- Principals for the role-bleed check, applied separately.
--
-- Not in schema.sql because there is no portable spelling: Postgres has no
-- CREATE ROLE IF NOT EXISTS, CockroachDB has no DO block. Applied without
-- ON_ERROR_STOP so re-running against a kept container is not an error.
CREATE ROLE support_sam LOGIN PASSWORD 'demo';
CREATE ROLE analyst_ann LOGIN PASSWORD 'demo';
GRANT USAGE ON SCHEMA fz TO support_sam, analyst_ann;
GRANT SELECT ON ALL TABLES IN SCHEMA fz TO support_sam, analyst_ann;

-- Demo schema for the pgmask example.
--
-- Deliberately mixed: classified columns, an explicitly-allowed column, and one
-- column left out of the catalog entirely so default-deny is visible.

DROP SCHEMA IF EXISTS demo CASCADE;
CREATE SCHEMA demo;

CREATE TABLE demo.customers (
  id       int PRIMARY KEY,
  email    text NOT NULL,
  name     text NOT NULL,
  phone    text,
  city     text NOT NULL,
  -- Non-text columns, to exercise the type-aware masks.
  birth_date    date NOT NULL,
  annual_salary int NOT NULL,
  last_ip       text NOT NULL,
  account_uuid  uuid NOT NULL,
  -- Never added to catalog.toml, so default-deny should null it out.
  internal_note text
);

CREATE VIEW demo.customer_directory AS
  SELECT id, email, name, city FROM demo.customers;

INSERT INTO demo.customers (
  id, email, name, phone, city,
  birth_date, annual_salary, last_ip, account_uuid, internal_note
)
SELECT
  i,
  'user' || i || '@example.com',
  'Customer ' || i,
  '555-01' || lpad((i % 100)::text, 2, '0'),
  (ARRAY['Portland', 'Denver', 'Austin', 'Boston'])[1 + (i % 4)],
  DATE '1970-01-01' + ((i % 12000) || ' days')::interval,
  40000 + (i % 47) * 3700,
  '203.0.113.' || (i % 254 + 1),
  ('00000000-0000-4000-8000-' || lpad(i::text, 12, '0'))::uuid,
  'note ' || i
FROM generate_series(1, 50000) AS i;

-- A second table, so the demo has joins — which is where a masking proxy
-- either stays useful or stops being useful.
--
-- It is seeded with three real defects, because "can you still debug behind
-- the mask?" is only answerable against something that is actually broken:
--   * ~40 orders whose customer_id points at nobody (a bad ETL run)
--   * a batch stamped in the future (a timezone bug)
--   * a handful of customers sharing one address (duplicate signups)
CREATE TABLE demo.orders (
  id            integer PRIMARY KEY,
  customer_id   integer NOT NULL,
  status        text    NOT NULL,
  order_total   numeric(10,2) NOT NULL,
  ship_city     text    NOT NULL,
  placed_at     timestamptz NOT NULL,
  ship_address  text,
  internal_note text
);

-- A stable hash, so city and status are independent. Deriving both from
-- `i % 4` made every Boston order a refund, which looks like a finding and is
-- an artefact of the seed.
INSERT INTO demo.orders (id, customer_id, status, order_total, ship_city, placed_at, ship_address, internal_note)
SELECT
  i,
  -- every 500th order is an orphan: no such customer.
  CASE WHEN i % 500 = 0 THEN 900000 + i ELSE 1 + (i % 5000) END,
  -- refunds run at ~6% everywhere except Denver, where they run at ~30%.
  -- A real anomaly, so the demo has something worth finding.
  CASE
    WHEN city.name = 'Denver' AND (h.v >> 8) % 100 < 30 THEN 'refunded'
    WHEN city.name <> 'Denver' AND (h.v >> 8) % 100 < 6  THEN 'refunded'
    ELSE (ARRAY['placed','shipped','delivered'])[1 + (h.v >> 16) % 3]
  END,
  (10 + (i % 900))::numeric,
  city.name,
  -- orders 19000-19100 are stamped two years ahead: the timezone bug.
  CASE WHEN i BETWEEN 19000 AND 19100
       THEN TIMESTAMPTZ '2027-03-01' + (i || ' minutes')::interval
       ELSE TIMESTAMPTZ '2025-01-01' + (i || ' minutes')::interval END,
  i || ' Example Street',
  'internal ' || i
FROM generate_series(1, 20000) AS i
CROSS JOIN LATERAL (
  SELECT ('x' || substr(md5('o' || i::text), 1, 8))::bit(32)::int & 2147483647 AS v
) AS h
CROSS JOIN LATERAL (
  SELECT (ARRAY['Portland','Denver','Austin','Boston'])[1 + (h.v & 3)] AS name
) AS city;

-- Duplicate signups: five customers share one address.
UPDATE demo.customers SET email = 'shared@example.com' WHERE id IN (7, 4007, 8007, 12007, 16007);

-- Force a full-table sample for `email`. The default statistics target samples
-- 30k of 50k rows, so whether five duplicates reach `most_common_vals` is a
-- coin flip — and verify.sh uses that entry as the negative control proving
-- pg_stats really does leak. A flaky control is worse than none.
ALTER TABLE demo.customers ALTER COLUMN email SET STATISTICS 1000;

ANALYZE demo.customers;
ANALYZE demo.orders;

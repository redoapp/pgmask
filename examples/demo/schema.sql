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

ANALYZE demo.customers;

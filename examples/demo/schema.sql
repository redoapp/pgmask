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
  -- Never added to catalog.toml, so default-deny should null it out.
  internal_note text
);

CREATE VIEW demo.customer_directory AS
  SELECT id, email, name, city FROM demo.customers;

INSERT INTO demo.customers (id, email, name, phone, city, internal_note)
SELECT
  i,
  'user' || i || '@example.com',
  'Customer ' || i,
  '555-01' || lpad((i % 100)::text, 2, '0'),
  (ARRAY['Portland', 'Denver', 'Austin', 'Boston'])[1 + (i % 4)],
  'note ' || i
FROM generate_series(1, 50000) AS i;

ANALYZE demo.customers;

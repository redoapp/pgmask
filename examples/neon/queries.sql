-- A corpus of query shapes typical of analytical work against this database.
--
-- The point is not that every one succeeds. It is to measure, on real schema
-- and real data, what fraction a fail-closed proxy refuses and why — the number
-- that decides whether the Phase 6 parser is worth building.
--
-- One statement per line. Lines starting with `--` are ignored.

-- Plain column reads
SELECT id, name, domain, owner_email, lifecycle_stage FROM crm.companies LIMIT 5;
SELECT name, owner_name, created_at FROM crm.companies WHERE lifecycle_stage = 'customer' LIMIT 5;
SELECT id, email, name, role, created_at FROM auth."user" LIMIT 5;
SELECT * FROM crm.companies LIMIT 3;
SELECT DISTINCT lifecycle_stage FROM crm.companies LIMIT 20;
SELECT name, estimated_monthly_sales, num_open_deals FROM crm.companies WHERE num_open_deals > 0 LIMIT 5;

-- Joins
SELECT c.name, c.owner_email, u.name FROM crm.companies c JOIN auth."user" u ON u.email = c.owner_email LIMIT 5;
SELECT c.name, c.lifecycle_stage FROM crm.companies c JOIN crm.companies p ON p.id = c.parent_company_id LIMIT 5;

-- Ordering and windows
SELECT name, estimated_monthly_sales FROM crm.companies ORDER BY estimated_monthly_sales DESC NULLS LAST LIMIT 5;
SELECT name, num_open_deals, row_number() OVER (ORDER BY num_open_deals DESC) FROM crm.companies LIMIT 5;

-- Subqueries and CTEs
SELECT name FROM (SELECT name FROM crm.companies LIMIT 5) q;
SELECT name FROM (SELECT name FROM crm.companies OFFSET 0 LIMIT 5) q;
WITH c AS (SELECT name, owner_email FROM crm.companies LIMIT 5) SELECT name, owner_email FROM c;
WITH c AS MATERIALIZED (SELECT name FROM crm.companies LIMIT 5) SELECT name FROM c;

-- Grouping and aggregates
SELECT lifecycle_stage, count(*) FROM crm.companies GROUP BY lifecycle_stage LIMIT 10;
SELECT count(*) FROM crm.companies;
SELECT owner_email, count(*) FROM crm.companies GROUP BY owner_email ORDER BY 2 DESC LIMIT 5;
SELECT avg(num_open_deals) FROM crm.companies;
SELECT string_agg(name, ',') FROM (SELECT name FROM crm.companies LIMIT 3) q;

-- Set operations
SELECT name FROM crm.companies LIMIT 3 UNION ALL SELECT name FROM crm.companies LIMIT 3;
SELECT owner_email FROM crm.companies LIMIT 3 UNION SELECT email FROM auth."user" LIMIT 3;
SELECT lifecycle_stage FROM crm.companies EXCEPT SELECT 'customer';

-- Expressions over columns
SELECT lower(owner_email) FROM crm.companies LIMIT 3;
SELECT name || ' (' || lifecycle_stage || ')' FROM crm.companies LIMIT 3;
SELECT coalesce(domain, 'unknown') FROM crm.companies LIMIT 3;
SELECT date_trunc('month', created_at) FROM crm.companies LIMIT 3;
SELECT to_json(c) FROM crm.companies c LIMIT 2;

-- Health checks and metadata
SELECT 1;
SELECT now();
SELECT current_database();
SELECT table_name FROM information_schema.tables WHERE table_schema = 'crm' LIMIT 5;

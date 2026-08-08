# GUI clients: DBeaver, DataGrip, pgAdmin, psql `\d`

**Short answer: yes, with `system_catalogs = "allow"`. It is off by default.**

```toml
system_catalogs = "allow"
```

Then point the client at pgmask's host and port like any Postgres server. No
driver setting, no JDBC parameter — it is the wire protocol, so the connection
string is the only thing that changes.

## Why it did not work before

A GUI client reads the catalog before it will show you a single table. Those
queries were failing two different ways, and the second one is the bad one.

**Refused.** Catalog SQL is mostly expressions —
`pg_catalog.pg_get_userbyid(c.relowner)`, `format_type(a.atttypid, a.atttypmod)`,
`pg_get_indexdef(i.indexrelid)`. None has column provenance, so `opaque =
"reject"` refuses the whole result set. `\dt` failed on the `Owner` column.

**Silently corrupted.** The fields that *do* have provenance point at
`pg_class`, `pg_attribute` and friends — relations no catalog file lists, so
default-deny masks them to NULL. psql's `\d` runs a query, takes the OID from
the answer, and interpolates it into a second query. Masked to NULL, that
becomes:

```
ERROR:  invalid input syntax for type oid: ""
LINE 5: WHERE c.oid = '';
```

Default-deny did not refuse. It handed back a well-formed but wrong answer and
let the client build its next query out of it. That is worse than a refusal, and
it is the reason this needed fixing rather than documenting as a limitation.

## The rule

A result set is released when the statement is a `SHOW`, or when **every
relation it reads is an explicitly qualified, metadata-only system catalog.**
Nothing from a user table can appear in the output of a query that reads no user
table, so the fields need no provenance.

It fails closed on every edge:

| | |
|---|---|
| a user table anywhere — join, subquery, scalar subselect | not released |
| an unqualified `pg_class` | not released |
| a statement naming no relation at all | not released |
| unparseable, or more than one statement | not released |
| a CTE reference | released only if declared in the same statement |

Qualification is required rather than inferred. Postgres reserves the `pg_`
schema-name prefix — `CREATE SCHEMA pg_evil` is refused by the server — so
`pg_catalog.x` cannot be spoofed. But `search_path` is the client's to set, and
reading the qualification that psql, DBeaver and DataGrip all already write is a
better rule than trusting resolution order.

## `pg_catalog` is not uniformly safe

This is the part worth knowing before turning the knob on. Some catalogs contain
**values sampled out of your tables**, and they are denied by name.

Measured on the demo database, where `email` is pseudonymised, `birth_date` is
masked to its year and `last_ip` to its /24:

```sql
SELECT most_common_vals FROM pg_stats WHERE tablename='customers' AND attname='email';
--  {shared@example.com}          <- the exact address the proxy hides

SELECT histogram_bounds FROM pg_stats WHERE tablename='customers' AND attname='birth_date';
--  {1970-01-01,1970-04-11,…}     <- exact dates, not years

SELECT histogram_bounds FROM pg_stats WHERE tablename='customers' AND attname='last_ip';
--  {203.0.113.1,203.0.113.100,…} <- exact addresses, not /24s
```

Releasing `pg_catalog` wholesale would have handed back the values the proxy
exists to hide. The denied list is in `LEAKY_SYSTEM_CATALOGS`:

- `pg_statistic`, `pg_statistic_ext_data`, `pg_stats`, `pg_stats_ext`,
  `pg_stats_ext_exprs` — sampled values
- `pg_stat_activity`, `pg_stat_statements`, `pg_prepared_statements` — other
  sessions' SQL text, literals included
- `pg_largeobject` — blob contents
- `pg_authid`, `pg_shadow`, `pg_user_mapping(s)`, `pg_subscription` — password
  hashes and connection strings
- `pg_file_settings`, `pg_hba_file_rules`, `pg_ident_file_mappings`,
  `pg_backend_memory_contexts` — host configuration

`pg_statistic_ext` is deliberately **not** on the list: it records which
extended-statistics objects exist, while the values live in
`pg_statistic_ext_data`. `\d` reads the former, so denying both would have
broken table description for no gain.

A denied catalog does not get a special error — it simply drops out of the rule
and meets default-deny like anything else, which nulls it.

## Functions that take SQL as a string

`query_to_xml('SELECT email FROM demo.customers', …)` has no `RangeVar` for
`customers` in the parse tree, so a relation-based rule cannot see it. Without a
denylist the whole thing is bypassable in one call. `CATALOG_ESCAPE_FUNCTIONS`
covers the `*_to_xml` family, `dblink`, `pg_read_file`, `pg_ls_dir`,
`pg_stat_file` and the large-object accessors.

## What it does not change

Turning this on does not touch how your data is masked. It releases engine
metadata — the shape of the database, not its contents. Every masking assertion
in `verify.sh` passes identically with the knob on, and three assertions exist
specifically to prove it: a user table joined to `pg_class` is still masked,
`query_to_xml` cannot launder one, and an ordinary `SELECT email` is unaffected.

## Known gaps

- **Query results in the grid are still subject to the rules.** DBeaver will
  connect, browse and describe, but a query it generates with an expression in
  the target list gets refused like any other. Clicking "view data" on a table
  issues a plain `SELECT * FROM t`, which works.
- **`information_schema` is not a reserved name.** A superuser could in
  principle replace it. `pg_catalog` cannot be, and a principal that can drop
  `information_schema` is not one this proxy is defending against.
- **Untested against DBeaver itself.** The bootstrap shapes it sends —
  `pg_database`, `pg_namespace` with a `pg_description` LEFT JOIN, `pg_class`
  with `pg_get_expr`/`pg_get_partkeydef`, `pg_attribute` with `format_type`,
  `pg_index` with `pg_get_indexdef`, `information_schema.columns`, `pg_settings`,
  `SHOW`, `version()`, `current_schema()` — were each run through the proxy and
  all pass. That is evidence, not proof; the client itself has not been driven.

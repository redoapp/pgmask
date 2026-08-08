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

## The rule: two gates, and both must hold

A result set is released when the statement is a `SHOW`, or when **both**:

1. **The parse tree** shows every relation it reads is a system catalog by name,
   none of them on the leaky list, and no function that takes SQL as a string.
2. **The OIDs** in the `RowDescription` all belong to relations that really live
   in `pg_catalog` or `information_schema`, checked against the live database.

Each gate covers what the other cannot. The parse tree sees relations that never
become an output field — a user table in a subquery, or inside `query_to_xml`.
The OIDs settle what a name cannot: whether `pg_database` *is* `pg_database`.

It fails closed on every edge:

| | |
|---|---|
| a user table anywhere — join, subquery, scalar subselect | not released |
| a bare name that is not catalog-shaped | not released |
| a name that looks like a catalog but resolves elsewhere | not released (gate 2) |
| a statement naming no relation at all | not released |
| unparseable, or more than one statement | not released |
| all fields are expressions, and any relation was unqualified | not released |
| a CTE reference | released only if declared in the same statement |

### Why it is not just qualification

The first version required every relation to be written `pg_catalog.pg_class`,
justified by "every real client already writes it." **That was wrong, and two
clients disproved it.** Harlequin issues `from pg_database` and
`join pg_namespace s`; Beekeeper's bundle references `pg_database` unqualified
too. Requiring qualification locked out working clients.

Accepting a bare `pg_database` on the name alone would be worse. Postgres
reserves the `pg_` prefix for **schema** names — `CREATE SCHEMA pg_evil` is
refused — but **not for relation names**:

```sql
CREATE TABLE public.pg_database (datname text);   -- succeeds
INSERT INTO public.pg_database VALUES ('SENTINEL-LEAKED-SECRET');
SET search_path TO public, pg_catalog;
SELECT datname FROM pg_database;                  -- reads the user's table
```

Direct, that returns `SENTINEL-LEAKED-SECRET`. Through pgmask it comes back
NULL: gate 1 says "looks like a catalog", gate 2 says "that OID is not a system
relation", and the statement falls through to ordinary default-deny. Both halves
of that are asserted in `verify.sh` — the leak is proven to exist before the
defence against it is checked.

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

## Table sizes

Every GUI shows them, and `pg_total_relation_size('demo.customers')` has no
relation in its `FROM` at all, so the catalog rule never sees it. Size functions
are released by name instead (`SIZE_FUNCTIONS`): they take a relation and return
a byte count, so unlike `min(email)` no argument can come back out whatever is
inside. They do disclose approximate row counts, which is the same order of
disclosure as `count(*)` and already accepted.

## What was actually tested

| client | how | result |
|---|---|---|
| **psql** `\dt` `\d` `\l` `\dn` | driven directly | works |
| **Harlequin** 2.8 (psycopg3) | adapter driven in-process, catalog tree walked and compared against a direct connection | **identical tree**: 2 databases, 3 relations, all columns |
| **Beekeeper's stack** (node-postgres + knex) | nine introspection probes plus `knex.columnInfo()`, compared against direct | **identical on all nine** |
| **DBeaver** | bootstrap query shapes reconstructed and replayed | all pass |

Harlequin was the client that broke the first design, and it broke it the
quiet way. Through the proxy its catalog tree came back with every label
`None` — no error, no refusal, just an empty database browser. The database
names had provenance, pointed at `pg_database`, matched no catalog entry, and
were masked to NULL. Same failure mode as psql's `\d`, found only because the
client was actually run.

## Known gaps

- **Beekeeper Studio itself has not been driven.** Its Postgres client is
  minified into a 13 MB Electron bundle and static extraction of its SQL was not
  reliable enough to build a claim on, so what is tested above is the driver
  stack it is built on, not the app. If you have it installed, pointing it at
  the proxy is the real test.
- **DBeaver and DataGrip have not been driven either** — only reconstructed
  query shapes. Evidence, not proof.
- **Query results in the grid are still subject to the rules.** A client will
  connect, browse and describe, but a query it generates with an expression in
  the target list gets refused like any other. "View data" on a table issues a
  plain `SELECT * FROM t`, which works.
- **`information_schema` is not a reserved schema name.** A superuser could in
  principle replace it. `pg_catalog` cannot be, and a principal who can drop
  `information_schema` is not one this proxy defends against.

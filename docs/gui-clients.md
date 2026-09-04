# GUI clients and metadata queries

Most PostgreSQL GUI clients query system catalogs before showing databases,
tables, or columns. Enable approved metadata access with:

```toml
system_catalogs = "allow"
```

The default is `refuse`. No driver or connection-string option is required.

## Beekeeper Studio

Beekeeper Studio fails to connect when that setting is off, with:

```
pgmask: output column "schema" has no column provenance, so it cannot be classified
```

The first query after TCP connect is `SELECT CURRENT_SCHEMA() AS schema`. That
call has no table OID — it is a session context function, not a stored column —
so default opaque policy refuses it unless the rescue path identifies it. Current
pgmask rescues `CURRENT_SCHEMA()` / `current_schema()` the same way it rescues
`now()` and `current_database()`, including over node-postgres's unnamed
extended protocol.

Connect does not stop there. Beekeeper then loads types:

```sql
SELECT n.nspname as schema, t.typname as typename, t.oid::integer as typeid
FROM pg_type t
LEFT JOIN pg_catalog.pg_namespace n ON n.oid = t.typnamespace
...
```

`oid::integer` has no provenance. That field is named `typeid`, and it is why
`system_catalogs = "allow"` is required: the metadata path releases the whole
result once every named relation is an approved catalog. After connect, the
sidebar's `information_schema.schemata` / `information_schema.tables` /
`information_schema.columns` reads need the same setting.

The same setting covers the pane queries that have no table to bind to:

```sql
SELECT pg_get_viewdef($1::regclass, true)
SELECT pg_indexes_size('…'), pg_relation_size('…'), obj_description('…'::regclass)
```

Those look up a catalog object by `regclass`. They are not session context
functions, so default-deny still refuses them. DBeaver and DataGrip issue the
same helpers *with* a `FROM pg_class` / `FROM pg_proc`, which the metadata
path already released.

JDBC GUIs (DBeaver, DataGrip) also call `DatabaseMetaData.getSQLKeywords`:

```sql
select string_agg(word, ',') from pg_catalog.pg_get_keywords()
```

`pg_get_keywords()` is a set-returning function in `FROM`, not a catalog
table. The metadata path treats that helper SRF as the catalog read.

Query cancel (`SELECT pg_cancel_backend(...)`) stays refused: pgmask is
read-only, and that call is not a catalog lookup.

Use the [GUI example catalog](../examples/demo/catalog-gui.toml) as a starting
point (`system_catalogs = "allow"` is already set there).

## Supported behavior

The metadata path is tested with:

| Client path | Coverage |
|---|---|
| `psql` `\dt`, `\d`, `\l`, `\dn` | Driven directly |
| Harlequin 2.8 with psycopg 3 | Catalog tree compared with a direct connection |
| node-postgres and Knex | Introspection queries compared with a direct connection |
| DBeaver | Reconstructed bootstrap query shapes |
| Beekeeper Studio | Connect sequence, sidebar catalogs, view SQL (`pg_get_viewdef` with no `FROM`), table properties (`obj_description`) driven on the wire |
| JDBC `getSQLKeywords` | `pg_get_keywords()` SRF driven on the wire |

DBeaver and DataGrip have not been driven as complete desktop applications.
Their ordinary table views work when they issue a plain `SELECT`; generated
expressions still follow normal pgmask policy.

## Release rule

A metadata result is released only when both checks pass:

1. SQL analysis finds only approved system-catalog relations and trusted helper
   functions.
2. Result-field OIDs resolve to live `pg_catalog` or `information_schema`
   relations.

The two checks prevent an unqualified user table such as `public.pg_database`
from being mistaken for the real catalog. Unparseable SQL, multiple statements,
unknown catalog relations, and user tables fail closed.

`SHOW` statements use the same metadata path. Zero-argument session context
functions (`CURRENT_SCHEMA()`, `current_database()`, `version()`, `now()`,
`pg_backend_pid()`) are rescued independently of it: they cannot carry a
stored column. Catalog-object lookups with no `FROM` (`pg_get_viewdef`,
`obj_description`) use the metadata path, not that rescue.

## Blocked catalogs

`system_catalogs = "allow"` does not release every system relation. pgmask
blocks catalogs that can contain user values, SQL text, credentials, connection
strings, file contents, or host configuration.

Important blocked groups include:

- Statistics values: `pg_statistic`, `pg_stats`, and extended-statistics data.
- Session SQL: `pg_stat_activity`, prepared statements, cursors, replication
  state, and similar extension views.
- Credentials and endpoints: `pg_authid`, user mappings, subscriptions, and
  foreign-server options.
- Stored bytes: large objects and TOAST relations.
- Host configuration: HBA, identity mappings, file settings, and backend memory
  contexts.
- Unknown `pg_catalog` or `information_schema` relations.

Blocked catalogs are rejected before execution with the `leaky_catalog` cause.
The full allowlist and deny rules live in
[`catalog_surface.rs`](../crates/proxy/src/analysis/catalog_surface.rs).

## Blocked functions

Functions that accept SQL text or read server state can bypass relation-based
analysis. pgmask blocks these on the metadata path, including:

- `query_to_xml` and related XML exporters.
- `dblink`, `crosstab`, and `connectby` families.
- Server file and directory functions.
- Large-object readers.
- Activity, replication-slot, WAL, and raw-page dump functions.

Target-list functions use an allowlist of catalog formatting, description,
comment, privilege, and `to_reg*` helpers. Size functions are allowed because
they return byte counts rather than stored column values.

## Security effect

Enabling metadata access releases database structure, object names, privileges,
and approximate table sizes. It does not change user-table masking policy.

Do not enable it when database structure itself is sensitive. See the
[security model](security.md) for deployment requirements.

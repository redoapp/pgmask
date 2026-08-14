# GUI clients and metadata queries

Most PostgreSQL GUI clients query system catalogs before showing databases,
tables, or columns. Enable approved metadata access with:

```toml
system_catalogs = "allow"
```

The default is `refuse`. No driver or connection-string option is required.

## Supported behavior

The metadata path is tested with:

| Client path | Coverage |
|---|---|
| `psql` `\dt`, `\d`, `\l`, `\dn` | Driven directly |
| Harlequin 2.8 with psycopg 3 | Catalog tree compared with a direct connection |
| node-postgres and Knex | Introspection queries compared with a direct connection |
| DBeaver | Reconstructed bootstrap query shapes |

DBeaver, DataGrip, and Beekeeper Studio have not been driven as complete desktop
applications. Their ordinary table views work when they issue a plain
`SELECT`; generated expressions still follow normal pgmask policy.

## Release rule

A metadata result is released only when both checks pass:

1. SQL analysis finds only approved system-catalog relations and trusted helper
   functions.
2. Result-field OIDs resolve to live `pg_catalog` or `information_schema`
   relations.

The two checks prevent an unqualified user table such as `public.pg_database`
from being mistaken for the real catalog. Unparseable SQL, multiple statements,
unknown catalog relations, and user tables fail closed.

`SHOW` statements use the same metadata path.

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

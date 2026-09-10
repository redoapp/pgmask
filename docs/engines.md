# PostgreSQL and CockroachDB

pgmask is tested against PostgreSQL 13–17 and CockroachDB 25.4. It uses the
PostgreSQL wire protocol and does not switch policy by engine.

## Shared rule

Each `RowDescription` field may report a source table OID and column number.
pgmask uses that provenance only when one source column can account for the
field. Query shape and catalog state can make reported provenance untrustworthy.

## Set operations

For this query, one output field has two possible source columns:

```sql
SELECT city FROM customers
UNION ALL
SELECT email FROM customers;
```

PostgreSQL reports no provenance. CockroachDB 25.4 may report the first branch's
provenance on the simple-query protocol and no provenance on the extended
protocol. Trusting the first branch could apply `city` policy to `email` values.

pgmask therefore distrusts provenance for set operations on every engine. The
field follows opaque policy unless optional lineage proves that all sources are
explicitly released.

## Views

A view can hide a set operation from the outer SQL statement. Both engines may
report the view's own column as provenance.

During catalog refresh, pgmask parses view definitions, marks views containing
set operations as opaque, and propagates that state through dependent views.
Unreadable or unparseable view definitions are opaque.

Views need their own catalog entries because the result metadata names the view,
not necessarily its base table.

## Protocol coverage

The test suites exercise:

- Simple-query and Parse/Bind/Execute flows.
- Text and binary result formats.
- Set operations, subqueries, common table expressions, joins, windows,
  aggregates, grouping, and views.
- Generated portable SQL on both engines.
- Engine-specific diagnostic channels where available.

This matters because CockroachDB's set-operation provenance differs between the
simple and extended protocols.

## Known differences

| Area | PostgreSQL | CockroachDB 25.4 |
|---|---|---|
| Bare `int` | `int4` | `int8` |
| Set-operation provenance | No source | May report the first branch for simple queries |
| `ROLLUP`, `CUBE`, grouping sets | Supported | Unsupported in the tested version |
| Declarative partition syntax | PostgreSQL form | Different syntax |
| Some catalog helpers | Available | Missing, including `pg_size_pretty` |
| Catalog tables | Real relations with real OIDs | Virtual; `RowDescription` reports an OID above 2³¹, and a cast of one (`oid::integer`) has no provenance |
| Engine schemas | `pg_catalog`, `information_schema`, `pg_toast` | Also `crdb_internal` (113 tables) and `pg_extension`; neither is a user relation nor a system catalog, and the metadata path refuses them |

Fixtures use explicit integer widths so both binary decoding paths are tested.
Portable generated corpora exclude unsupported grouping syntax and assert that
the exclusion occurred.

## Validation

Run the CockroachDB suite:

```bash
./scripts/test-cockroach.sh
```

Run the shared shape and generated-SQL campaigns:

```bash
./scripts/test-shapes.sh
./scripts/test-fuzz-cockroach.sh
./scripts/test-differential.sh
```

The CockroachDB suite pins one tested release. CockroachDB-specific SQL such as
changefeeds and `AS OF SYSTEM TIME` is not broadly generated. Other
PostgreSQL-wire-compatible engines are untested and must not be assumed safe
without the same provenance and protocol checks.

# Running it: config, migrations, and deploys

pgmask sits in front of a database that will keep changing under it. This is
what happens when it does.

## The property that makes this tractable

**There is no unsafe deploy ordering.** Config and migration can land in either
order, and both windows are degraded rather than exposed:

| you deploy | what happens in between |
|---|---|
| migration first, config second | the new column is unclassified, so default-deny masks it. Someone sees a blank column. |
| config first, migration second | the rule resolves to nothing and is logged as unresolved. It starts working when the column appears. |

That is worth knowing before you design a release process around it: you do not
need a lockstep deploy, and there is no window where the wrong ordering leaks
something. You only need to close the gap before people complain about blanks.

## What each kind of migration does

| migration | runtime behaviour | caught by `classify --check`? |
|---|---|---|
| add a column | masked by default-deny | yes — reported as having no rule |
| rename a column | old rule matches nothing, new name masked | yes — both halves, as uncovered *and* as a stale rule |
| drop a column | rule matches nothing | yes — stale rule |
| drop and recreate a table | new OID; refreshed within `catalog_refresh_seconds`, masked meanwhile | n/a — resolves itself |
| **change a column's type** | **the proxy refuses every result set containing it** | **yes** |

That last row is the one that bites. A `date-year` mask on a column that became
`text` is not a coverage gap that quietly hides data — it is an outage, and
without the check it surfaces as the first user's query failing:

```
ERROR:  pgmask: mask DateYear on demo.customers.birth_date cannot be applied to type OID 25
```

`classify --check` validates every rule's mask against the column's current
type, so a type-changing migration fails the build instead:

```
1 rule(s) name a mask the column's current type cannot take. This is
not a coverage gap — the proxy refuses these result sets at runtime:
  demo.customers.birth_date  mask `date-year` vs text
```

## The pipeline to build

Run this in CI against a schema-equivalent database — the one your migrations
have already been applied to:

```bash
DSN=postgres://… classify --check --catalog catalog.toml --schema public
```

Non-zero on any of: a column with no rule, a rule matching nothing, or a rule
whose mask no longer fits. Wire it after your migration step and before deploy,
and every one of the rows above becomes a build failure rather than a discovery.

To see what a new column *should* be classified as, run the proposing mode
against the same database and read the diff:

```bash
DSN=postgres://… classify --schema public --sample 200 > proposed.toml
```

## Rolling the proxy

`SIGTERM` stops it accepting new connections and exits. In-flight sessions are
not drained — each holds its own backend connection, and waiting for the longest
query would stall a deploy — so run more than one instance behind whatever
routes to it if you care about not dropping sessions.

**Changing the catalog file requires a restart.** The refresher re-resolves
names to OIDs on `catalog_refresh_seconds`, which handles DDL, but it does not
re-read the file. Adding a rule for a new column is a deploy, not a reload.
That is a real limitation; a `SIGHUP` reload is the obvious fix and is not built.

## What to watch

The proxy already tells you when coverage changes, at `warn`:

```
catalog: coverage lost for demo.customers.email (was oid.attnum 16385.2) —
the relation or column no longer exists; those values are now unclassified
```

Alert on that line. It is the runtime signal that a migration moved something
out from under a rule, and it is deliberately a warning rather than a refusal
because the values are still masked — you have lost coverage, not containment.

From `/metrics`, the useful signals are `pgmask_rejections_total` by cause — a
spike in `mask_type_mismatch` is a type-changing migration that got past CI —
and `pgmask_values_masked_total` going to zero, which means either nobody is
querying or a catalog stopped resolving.

There is no gauge for "rules currently unresolved". There should be; it is not
built.

## Catalog hygiene

Treat the catalog as production configuration, in the same repository and review
process as the migrations it tracks. Two things follow from that:

- **Review a `mask = "none"` the way you would review a permission grant.** It
  is the only setting here that can expose something; everything else fails
  towards hiding.
- **Keep it complete rather than minimal.** Under default-deny, a column absent
  from the catalog comes back blank, so "only list the sensitive ones" produces
  a database where most columns are empty. `classify` emits an entry for every
  column for this reason.

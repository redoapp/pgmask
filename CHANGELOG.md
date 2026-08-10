# Changelog

## 0.1.20 — the same product, on the other engine

CockroachDB resolves an output alias in a grouping exactly as Postgres does, so
the 0.1.18 disclosure existed there too and had never been exercised: the
generated grouping product ran on Postgres only. It runs on both now — 144 key
spellings refused, 0 leaked, 28 non-key served, 0 over-refused. `ROLLUP`, `CUBE`
and `GROUPING SETS` are unsupported on CockroachDB, so those 252 statements are
rejected by the server and stay Postgres-only.

Getting there took three diagnoses, and only the first was about the proxy.

The proxy resolves the whole catalog at startup and refuses to run when a
declared column is missing — "a half-loaded catalog has unknown coverage". The
CockroachDB stand-in carried four of the ten columns the demo catalog declares.
That is correct fail-closed behaviour, not a bug.

`demo.orders` and `demo.customer_directory` are not in that fixture either, so
their rules name columns that cannot exist; they are stripped, as
`test-cockroach.sh` already does.

The last one was a missing trailing newline. The strip regex ends its match on
`(?=\n\[\[|\Z)` and consumes whole `.*\n` lines, so when the rewritten catalog
was joined without a final newline the last `[[column]]` block could never reach
`\Z` and survived — exactly one declared-but-absent column, and the proxy
refused to start.

The reason that was found rather than guessed at: the suite had been sending the
proxy's stdout to `/dev/null`, so a precise startup error arrived as "proxy did
not come up". The log is kept now and printed on failure. Three rounds of
guessing bought one small change to the harness that would have answered it
immediately.

## 0.1.19 — the campaign could not have found it

A summary of a column the query *groups on* is that column. Within a group it is
constant, so `sum(x)/count(*)` is `x` exactly — every group, any data, no unique
key involved, which is why the key test added in 0.1.16 never fired:

```sql
SELECT annual_salary AS g0, sum(annual_salary) AS c0 FROM fz.people GROUP BY 1
```

Found by the generated poison campaign rather than by review, and only after
two independent reasons it could not have been found before.

WHY 176,000 STATEMENTS REPORTED CLEAN

The generator's only `GROUP BY` arm projected `count(*)`, which discloses
nothing whatever it is grouped by. No generated statement could reach a reducing
aggregate over a grouping at all — the shape was outside the grammar, so the
clean runs said nothing about it. That is the second time this generator has
been missing precisely the arm that mattered; the windowed-aggregate arm was
added in 0.1.5 for the same reason.

The extended harness then read values with `try_get::<Option<String>>` and
dropped every column it could not decode as text. `sum(int4)` returns `int8`, so
the numeric poison detector could never fire on that path — and neither could
the date or uuid ones. The 0.1.11 note that both harnesses now share
`fuzz::oracle` was true and insufficient: sharing detectors does not help if the
values never reach them, and that fix was verified with `ip-prefix`, which
happens to sit on a `text` column. Values are now rendered through a type ladder
before the oracle sees them.

With both fixed the poison control worked: 480 leaked values with the rule
removed, 0 with it.

TWO WRONG FIXES FIRST, BOTH CAUGHT BY MEASUREMENT

Refusing whenever a *masked* column is grouped closed the hole and refused every
grouped aggregate in the fixture — under a default-deny catalog almost every
column is masked, so that is `summaries = "refuse"` by another route. The
grouping suite's non-vacuity guard failed the run outright: nothing was served,
so refusal proved nothing.

Comparing only the aggregate's plain-column argument halved the leaks, 480 to
240. `GROUP BY coalesce(annual_salary, 0)` is an expression, so the comparison
was skipped.

What works is bounding *every column the grouping could reference*, where an
unrecognised node means "could be anything" and refuses. That inversion is what
makes walking an arbitrary expression sound here when the rest of this module
will not do it: the other walks prove a column is absent and are unsound the
moment they miss a node, while this one only has to avoid under-collecting.

THE LIBRARY IS THE UNSAFE OPTION HERE

`pg_query::ParseResult::nodes()` is a generated traversal and the obvious way to
avoid hand-rolling this. Measured against the same groupings, it silently finds
nothing under `ARRAY[...]`, `GROUPING SETS`, `OVER (PARTITION BY ...)` or
`xmlelement(...)` — four misses, each a release. The table is recorded on
`grouping_may_reference`.

It is still used, as an oracle rather than an implementation:
`library_traversal_finds_no_column_this_misses` asserts our walker never returns
a narrower column set than `nodes()` does, so a hole in ours fails the build.

The mutation run then reported `ordinal grouping unread` as SURVIVED, which was
correct and worth the entry. Since 0.1.17 the lexical backstop catches whatever
the reader cannot resolve, so breaking ordinal resolution is *safe* — it only
costs precision, and nothing asserted precision. The distinguishing query is
`SELECT city, sum(annual_salary) … WHERE id > 5 GROUP BY 1`: read, the grouping
is `city` and it is served; unread, the backstop scans the whole statement,
finds `id` in the filter, and refuses. It is now pinned, and the mutation is
caught. 24 mutations, 0 survived.

## 0.1.18 — a name in the clause is not the column being grouped on

0.1.17 read the `GROUP BY` and got the wrong answer for two spellings, both
disclosures, both confirmed against a live server rather than argued about:

```sql
SELECT id AS c, sum(annual_salary) FROM demo.customers GROUP BY c
SELECT id AS c, sum(annual_salary) FROM demo.customers GROUP BY ROLLUP(c)
```

Postgres resolves an output alias in a grouping element, so both group by `id`,
one row per group. The reader saw the literal name `c`, found it in no unique
key, and released every salary — the original 0.1.16 disclosure with two extra
characters.

A bare name in a grouping element is now resolved as an output alias as well as
a column, collecting both names. Which one Postgres picks is not decidable here
— it prefers an input column of that name and only then the alias, and knowing
whether the input column exists needs the relation's columns — so collecting
both over-refuses in the shadowed case and cannot under-refuse in either.

Where the resolution applies was measured, not assumed. `GROUP BY ROLLUP(c)`
resolves the alias, because a grouping set nests grouping elements;
`GROUP BY c+0` reports `column "c" does not exist`, because an expression is not
one. The first cut used "at the top of the item", which is the wrong axis and
left the `ROLLUP` spelling open.

THE PATTERN, WRITTEN DOWN

Three releases in, the recurring defect is one mistake: treating *a name
appearing in the `GROUP BY`* as *the column being grouped on*. SQL separates
those four ways, and each was found separately and late — ordinals and stars in
0.1.17, aliases here. Anyone extending this should start from the list rather
than from the parse tree:

| spelling | denotes | handled by |
|---|---|---|
| `GROUP BY col` | that column | read directly |
| `GROUP BY 1` | an output column by position | ordinal resolution, refused if any target is a star |
| `GROUP BY alias` | whatever the target computes | alias resolution, in grouping elements only |
| `GROUP BY expr` | not decidable here | the session's lexical backstop |

Four mutations now cover the reader — unreadable-releases, ordinal-unread,
alias-unresolved, alias-unresolved-inside-a-grouping-set — because every one of
these was a live disclosure and none of them was caught by an existing suite.

GENERATING THE SPELLINGS INSTEAD OF REMEMBERING THEM

The deeper problem is that `test-inference.sh` only proves the spellings someone
already thought of are refused, which is the guarantee that kept failing.
`scripts/test-grouping.py` crosses 22 expressions — 16 that are the primary key
under a different spelling, 6 on a non-key column — with 14 syntactic positions
and adversarial aliases, one of which shadows a real column so that Postgres
prefers the input column over the alias. It asks the server whether each
grouping is actually one row per group rather than trusting the list.

It would have caught all three releases' worth of defects: `alias`,
`alias-in-rollup`, `alias-in-cube`, `alias-in-sets`, `quoted-alias` and
`ordinal` are all positions in the cross product.

Result: **256 key spellings refused, 0 leaked; 66 non-key spellings served, 0
over-refused by this guard.** The 60 non-key refusals are the pre-existing
expression-target rule, and separating those out required a differential — is
the plainest spelling of the same query refused too? — because the first version
of the script attributed all 60 to the guard and made its cost look several
times larger than it is.

## 0.1.17 — the guard was blunter than the problem

0.1.16 refused any `GROUP BY` it could not reduce to column names, reasoning
that a grouping we cannot read is one we cannot clear. Sound, and blunt enough
to break the most ordinary analytics query there is:

```sql
SELECT date_trunc('month', placed_at), sum(order_total) FROM orders GROUP BY 1
```

`date_trunc` over a coarse literal unit is *deliberately* released — that rule
predates the guard — so this was served before 0.1.16 and refused after it. The
claim in that release that expression groupings "were already refused anyway"
was drawn from one probe of `upper(city)` and does not generalise.

Two changes. The reader now resolves a column reference, an ordinal into the
target list, and `ROLLUP`/`CUBE`/`GROUPING SETS` over either, unioning names
across every set — safe, because each set is a subset of the union. Reading
these *strengthens* the guard as much as it relaxes it: the attack is
expressible in all of them, and 0.1.16 caught them only by finding them
illegible.

What still cannot be read now falls back to the lexical backstop instead of to a
refusal. It asks the weaker question the scanner can answer soundly — does the
statement name every column of some unique key? A grouping can only reference a
column the text mentions, so a key the text never names is a key the grouping
cannot cover. `GROUP BY id::text`, `GROUP BY (id+0)` and `GROUP BY
upper(id::text)` all name `id` and are refused; the `date_trunc` query names no
key column and is served.

The residual cost is a key column named *elsewhere* in a statement with an
expression grouping — `WHERE id > 5 … GROUP BY date_trunc(…)` — since the lexer
cannot tell where a name is used. Narrow, and pinned in the inference suite
rather than left to be discovered.

THINGS THAT DID NOT WORK, RECORDED SO THEY ARE NOT RETRIED

Walking the expression to collect its columns is the obvious answer and is
unsound here for the reason this module already documents: missing one node type
in a traversal releases a value.

Deparsing the group clause and lexing *that* looked like the sound version of
the same idea. It is not usable: `deparse` on a synthetically constructed tree
aborts the process from C on an invalid enum discriminant — `TRAP: failed
Assert("false")`, not an `Err` — so a grouping we cannot read would become a
crash rather than a refusal.

An ordinal is also refused whenever any target is a star. A star expands to
however many columns its relation has, so positions after it shift by an unknown
amount and `GROUP BY 2` can name one column while `target_list[1]` holds
another; if the real one is a key and the reported one is not, that releases.
`positions_are_trustworthy` already refuses such statements, so this is
unreachable today — checked anyway, because depending on a neighbouring guard to
stay sound is how the misaligned-star disclosure got in.

A nested grouping construct stays unreadable for a different reason.
`ROLLUP(a, CUBE(b, c))` does not parse as a nested `GroupingSet` — the raw parse
tree is not the analysed tree, only the outermost construct is resolved, and the
inner `CUBE` arrives as an ordinary `FuncCall`. Reading it would mean matching on
a function name, and `cube` is a real function from a real extension.

Three mutations added: releasing on an unreadable grouping, losing ordinal
resolution, and dropping the lexical fallback. The second is the first mutation
here that fails when the proxy becomes *more* restrictive, which is the right
shape for a change whose entire risk is over-refusal.

## 0.1.16 — a summary of one row is that row

`SELECT sum(annual_salary) FROM demo.customers GROUP BY id` returned every
salary, exactly, in a single query. It is not a small-cell problem: with `id`
unique, *every* group is one row, so the aggregate relaxation — "a reducing
aggregate cannot return a stored value whatever is inside it" — is false for the
whole result set at once. 0.1.15 recorded it as an accepted limitation. It is
the one route on that list that is decidable without query-set accounting: the
grouping is in the statement and the uniqueness is in `pg_index`.

`StatementInspection::group_by_columns` reads the top-level `GROUP BY` down to
column names, the catalog snapshot loads unique keys from `pg_index` (excluding
partial indexes, whose uniqueness is conditional), and the session withholds the
summary relaxation when the grouping covers one. A grouping that cannot be
reduced to names — `GROUP BY 1`, `GROUPING SETS`, `GROUP BY lower(a)` — is also
withheld, because a grouping we cannot read is one we cannot clear.

Scoped so ordinary analytics is untouched, which is why it is done here rather
than by turning summaries off: an ungrouped `sum`, a `sum` grouped by a non-key
column, and `count(*)` grouped by anything are all served exactly as before.

`WHERE id = 1` reaches the same value and is still accepted. Whether a predicate
matches one row is a property of the data, not of the statement, so there is
nothing sound to decide at Describe time. What the guard buys is the difference
between one query for the whole column and one query per row — and the inference
suite now asserts both halves, so undoing either is a failure rather than a
quiet regression. It joins the gate for that reason.

## 0.1.15 — measure what a client can reconstruct, and stop overclaiming

The suite asked one question — does a masked value appear in the output? — and
answered it well. It is not the question a reader assumes it answers. An
adversarial client does not need the value to appear: a grouped aggregate, an
ungoverned filter with `count(*)` (313 queries to a full address, measured), an
error used as a one-bit channel, and `ORDER BY` on a masked column all
reconstruct without disclosing. `analysis.rs` claimed the bar was "you cannot
read an anonymised value"; against an adversary that is false, and it is the
kind of false that decides whether this goes in front of regulated data. Both it
and the README now say what is true. `scripts/test-inference.sh` pins the routes.

## 0.1.14 — a detector that cannot be read is not a detector

A 3000-statement corpus reported 8,221 leaks, all false. The numeric canary
flagged any integer in the `annual_salary` range, and `row_number()` walks
straight through it. Tightening to exact-sequence membership still left 60 — an
int4 salary is indistinguishable from an ordinal by value alone — so the fixture
moved to `900000000 + i * 137` instead, which no ordinal reaches under the
statement timeout. The opposite failure mode to the day's other fixes, and just
as disabling: a real escape would have been three lines inside the noise.

## 0.1.13 — would we find out if a fix were undone?

`scripts/test-mutations.py` breaks each guard on purpose and requires the
narrowest suite to fail: 16 caught, 0 survived, 0 stale. Not in `test-all.sh`,
because it edits source and a gate that can leave the tree modified is a worse
hazard than the coverage. Python rather than bash because the first version
split its Rust-source table on `|`, straight through `|t| t.strip_suffix(...)` —
the harness had the defect it exists to find.

## 0.1.12 — a plan outliving the snapshot it was decided against

Statement and portal plans deliberately outlive their result set; nothing tied
them to the catalog snapshot they were resolved against. A refresh re-resolves
names to OIDs, and `DROP TABLE; CREATE TABLE` recycles one — so a plan cached
across that boundary applies the previous mapping's classification, which is a
different column's mask. Every other DDL direction already failed closed.
`PlanState` now drops cached statement and portal plans when the catalog
generation changes, keeping only the in-flight plan whose rows are already being
served.

## 0.1.11 — ambiguous principals, a blind oracle, ornamental checks

A startup packet naming `user` twice is refused rather than guessed at: pgmask
took the first and PostgreSQL takes the last, so masking resolved one identity
while the backend authenticated another. The extended-protocol oracle carried a
private one-token canary list and could not see any type-aware mask — the same
blind spot that let the windowed-aggregate disclosure through, reintroduced on
the other protocol; both harnesses now share `fuzz::oracle`. Eight CockroachDB
refutes truncated to `head -1` while the leak is on row two, so they passed
regardless of what the proxy did. Plus README numbers that did not reconcile.

## 0.1.10 — the channels that carry values around the masking

Three backend messages carry free text a client can steer to a stored value, and
none produces a RowDescription — so no plan, no refusal, no masking. `RAISE
NOTICE '%', (SELECT email …)` prints the address while the same column read
through the proxy is a pseudonym. Notice primary messages and
NotificationResponse are withheld; ParameterStatus is forwarded only for
reportable GUCs whose values cannot carry row data, `application_name`
deliberately excluded. An *error's* message is kept — Postgres composes it from
its own text, and an opaque proxy is a much worse trade.

## 0.1.9 — the release allowlists

`pg_size_pretty`, `pg_size_bytes` and `pg_column_size` take a *value*, not a
relation: `pg_size_pretty(salary % 10000)` with `pg_size_pretty(salary / 10000)`
reconstructs any bigint exactly. Moved to `PURE_SCALARS`, released only when
every argument is. A star over a zero-column relation expands to none, so target
count could match field count while every later position was shifted — a star
now makes positional correspondence unprovable. Set-returning functions in
`FROM` are refused outside three argument-driven generators, because the SRFs
behind `pg_stat_activity` match no relation rule. In the catalog: `for_roles`
iterated a `HashSet` so equal-ranked masks resolved differently per connection;
duplicate rules for one column are refused (which found a real duplicate in
`catalog-gui.toml`); `pseudonym_key` must be at least 16 bytes.

## 0.1.8 — five defects from an independent audit

Three protocol-legal disclosures with no error and no `Close`: `Parse` replacing
a statement left the previous plan cached, a Describe answered with an error left
its FIFO slot forever, and `described_sql` was a scalar while Describes are a
queue. Each Describe now carries its frontend Sync epoch — clearing on
`ReadyForQuery` is wrong under pipelining and ate live slots. Two masks failed
open (`range` with both bounds past the length, `outer` with `keep = 0`), and
`unclassified_mask` — the entire content of default-deny — was never validated,
so it returned undeclared columns verbatim while logging `unclassified=Mask`.
0.1.6's lexical backstop also missed quoted and keyword-shaped identifiers.

## 0.1.7 — the same gap, in the other release path

Having built a tool for the walker gap, the obvious next question was where else
a *release* decision depends on a tree walk. There are three: the analysis
allowlist, lineage (backstopped in 0.1.6), and `system_catalogs = "allow"`.

The third had never been fuzzed — nothing generates catalog queries — and it has
the largest blast radius, because it serves an entire result set unmasked.

**It has the same gap.** This is judged metadata-only while reading a user
table:

```sql
SELECT relname, count(*) OVER (PARTITION BY (SELECT email FROM demo.customers LIMIT 1))
  FROM pg_catalog.pg_class;
```

Not a value disclosure as it stands. The fast path ANDs the text check with an
engine-authoritative OID check, and a window clause influences ordering and
partitioning rather than what is projected — so the values that come back are
still `pg_class`'s. But the OID check only inspects fields that *have*
provenance, which leaves the text check standing alone for computed ones, and
the text check walks a tree with a known hole.

Fixed with the same lexical check as the lineage backstop: a statement naming a
known user relation as an *identifier* does not get the fast path. GUI clients
are unaffected, and for a pleasing reason — psql's introspection passes table
names as string literals, not identifiers, so `\d demo.customers` and `\dt`
still work.

## 0.1.6 — stop adding guards shaped like the last bug

No new disclosure. This closes the *class* that produced three of the five.

Lineage inverts the safety property: everywhere else a shape pgmask fails to
recognise is a shape it refuses, but here a source column the resolver fails to
notice becomes "nothing masked found, release it". Three disclosures came from
exactly that — a set operation, a view whose definition contained one, and a
scalar subquery `sqllineage` does not descend into — and each was closed with a
guard aimed at that construct. Guards aimed at constructs only ever cover the
constructs someone thought of, and the third arrived after the first two were
fixed.

**Guard 6 does not ask about constructs.** It asks whether a masked column's
name appears in the statement at all. If none does, no output field can carry a
masked value however the expressions nest and whatever the resolver resolved.
The resolver and the backstop must both agree before anything is released, and
they fail independently.

Two design choices worth stating:

- **Lexical, not syntactic.** The first implementation walked `pg_query`'s parse
  tree for column references. The new containment test caught it missing `id` in
  `sum(n) OVER (ORDER BY id …)` — the walker does not enter a `WindowDef`, which
  is the traversal gap `analysis.rs` has warned about since it was written. A
  backstop with a blind spot is not a backstop, so it now reads the **token
  stream**, where every identifier in the text is present by construction.
- **No name resolution.** An earlier version matched each name against the
  relations the statement mentions, which made it depend on the tree walk
  finding every `RangeVar` — the same completeness assumption that had already
  failed twice. Comparing bare names against every masked column in the catalog
  needs no traversal to be complete.
- Applied as a **downgrade of `Release`**, not an early return, so a field the
  resolver correctly identified as `Blocked` still names the column it derives
  from. An early return threw that message away.

Guard 5 (the scalar-subquery check from 0.1.5) is **removed** — the backstop
subsumes it and is not construct-shaped, and keeping both would be exactly the
accumulation this release is about. `SELECT upper(city) FROM t WHERE x IN
(SELECT …)` releases again as a result.

### The premise is tested, not assumed

`tests/lineage_superset.rs` asserts that every source column `sqllineage`
reports is one the backstop saw, across every construct the generator emits plus
the three that leaked. 37 comparisons, no violations. `SELECT *` is skipped and
documented: there the resolver names columns absent from the text and is the
complete side of the pair.

Verified to be able to fail: crippling the backstop makes it report 4
violations.

### Cost

Measured on a 1000-statement generated corpus: `lineage = "refuse"` serves 245,
`lineage = "allow"` serves 348. Unchanged by the backstop — the utility lineage
adds survives it. Over-refusal is real in principle (a masked `city` in one
relation blocks an expression over a released `city` in another) and did not
bite on this corpus.

**Lineage remains opt-in and off by default.** No amount of guarding changes
that it inverts the safety property; this makes the inversion survivable, not
sound.

## 0.1.5 — a windowed aggregate is not a summary

**Fixes the most serious disclosure so far.** It needs no unusual
configuration, no view, and no second engine:

```sql
SELECT sum(annual_salary)
         OVER (ORDER BY id ROWS BETWEEN CURRENT ROW AND CURRENT ROW)
  FROM fz.people;
```

returned **exact salaries** through a `numeric-bucket` column — 41248, 41385,
41522, where the plain column reads 25000. Under the *strictest* settings,
`lineage = "refuse"` and `opaque = "reject"`, because a `Releasable` verdict
short-circuits both.

`sum` is on the reducing-aggregate allowlist: it cannot return a value it
consumed, so what is inside it does not matter. That reasoning is sound for an
aggregate and false for a window function, where **the caller chooses the
frame** and a frame of one row makes every reducing aggregate the identity.
`count(*)` in the arm above already tested `over`; this arm did not.

This is not the group-of-one trade the module header accepts. A group of one is
incidental to the data; a frame of one is a thing the client writes down.

Every windowed aggregate is now refused — analysing frames to find the safe ones
is exactly the prove-absence reasoning the module refuses to do. `count(*) OVER
(…)` is deliberately still released: a frame changes which rows it counts, never
that it returns a count. Two existing tests asserted the vulnerable behaviour and
have been corrected.

### And a fifth: lineage released on a partial source set

The same campaign run also leaked a raw `date`, by a different route. Reduced:

```sql
SELECT min((SELECT d FROM fz.t8 LIMIT 1 OFFSET 3)) OVER (PARTITION BY subq.c0)
  FROM (SELECT id AS c0 FROM fz.v_join) subq
```

`sqllineage` does not descend into a `SubLink`, so the only source it reported
was `fz.v_join.id` — released. Lineage released the field on that basis, and the
value came from `fz.t8.d`, which is masked and which appears nowhere in the
sources it enumerated.

This is the third bug of one shape: **lineage releasing on an incomplete source
set** (after the set-operation view, and the view column released by rule).
`resolve` now refuses any statement containing a scalar subquery (guard 6). The
check is statement-level on purpose — locating which output field owns a given
`SubLink` means reproducing the target-list correspondence built elsewhere, and
getting *that* wrong is a leak. It costs lineage on `WHERE id IN (SELECT …)`,
which is utility, not safety. `upper(city)` still resolves and releases.

### How it was found, and what that says

The generated campaign found it, not review — and only by accident. The
statement that surfaced it reached a *date* column as well as a salary, and the
harness had a date detector and **no numeric one**. A campaign that reached only
salaries would have reported clean.

- The harness gains bucket detectors for `annual_salary` and `salary_big`.
- `shapegen` gains a windowed-aggregate arm; it had none, so no generated shape
  could reach this. Verified by reverting the fix: the corpus now reports 62
  leaks, correctly attributed, and 0 with the fix.

### The cross-engine differential

Every other oracle here needs someone to have predicted the bug: the canary
oracle needs a token planted in the right column, the shape matrix needs the
shape to have been thought of. `shapegen` closed one gap and opened another —
it explores what its author imagined, so its blind spots are his.

`scripts/test-differential.sh` needs no prediction. Both engines hold
byte-identical fixture data, and **masking is a property of the data and the
catalog, not of the engine**, so for any statement both proxies serve the masked
output must match. A difference is a defect by construction.

It matters most for pseudonyms: they are deterministic so a Postgres copy and a
CockroachDB cluster of the same data stay joinable. Until now that property was
asserted on one row in one suite; it is now checked across 157 served statements
of a generated corpus, and the run verifies the two fixtures really are
identical before comparing rather than assuming one file produced the same rows.

Result: 157 compared, 0 value mismatches, 84 decision mismatches — all in the
direction of CockroachDB refusing what Postgres serves, which is what
distrusting its provenance is supposed to look like. The control, a deliberately
skewed catalog, produces 141 mismatches, so the comparison can fail.

### Coverage said where the generator was not looking

Measured against the decision modules, a 2000-statement generated corpus reached
**19.6% of `mask.rs`**. The cause was one line of the generator: its column pool
was text and small integers, so no generated shape ever selected a `date`,
`uuid`, `inet` or `int8`. `date-year`, `ip-prefix`, uuid pseudonyms and 64-bit
bucketing had unit tests and fixed end-to-end checks, but no *shape* variety at
all — and shape variety is where all three leaks so far have lived.

Widening the pool took `mask.rs` from 19.6% to **33.1%** under the same corpus.
Projecting typed columns naively also put 230 engine errors into a corpus that
had been running at zero (a `date` in a `UNION` against text, `string_agg` over
a date), so the generator now tracks whether its projected column may be
non-text and keeps set operations and `string_agg` on text. Errors: 19 of 2000.

The lesson worth keeping: *"the fuzzer found nothing"* and *"the fuzzer never
executed that code"* look identical from the outside. Coverage is what tells
them apart, and it should be measured against the generated corpus alone rather
than the whole suite, which hides the gap behind unit tests.

## 0.1.4 — the other protocol, and the other integer width

No disclosure this time. Two coverage holes, both found by pointing existing
suites at the second engine.

### The extended protocol was one twelfth tested

Every end-to-end suite except `binary` speaks simple query. That is one protocol
of two, and **the two do not agree** — CockroachDB reports the first branch's
provenance for a set operation on the simple-query path and zero for the same
statement under `Describe`. A disagreement between protocols is what the first
disclosure here was made of, so testing one of them was testing half.

New `extended` binary replays a generated corpus through Parse/Bind/Execute with
binary results and the same canary oracle, with the same non-vacuity and poison
controls. It runs on both engines: Postgres serves 179 of 600 shapes and
CockroachDB 141, zero leaks on either, and both poison controls fire.

### int8 had no end-to-end coverage at all

`mask.rs` has handled int8 since it was written and a unit test covers it, but
no suite had ever produced one: Postgres's `int` is int4, so the fixture only
ever made four-byte integers. CockroachDB's `int` is int8, which surfaced this
as a driver deserialisation failure rather than a masking failure.

- Every integer width in the fuzz fixture is now explicit, so the same file
  produces the same column types on both engines.
- New `fz.people.salary_big int8` under `numeric-bucket`, asserted in the binary
  suite. `binary` is now 12 checks and runs on CockroachDB too, where all of
  them pass — including the pseudonym matching Postgres's byte for byte.

## 0.1.3 — fuzzing CockroachDB, and a third leak

**Fixes a disclosure reachable under `lineage = "allow"` on both engines.**
0.1.2 distrusted provenance for statements touching a set-operation view, which
sends those fields down the opaque path — where lineage decides them. Lineage
had not been told:

```sql
SELECT c0, row_number() OVER (ORDER BY c0) AS c1
  FROM (SELECT c0, count(*) AS c1
          FROM (SELECT r5.v AS c0 FROM fz.v_mixed r5) q5
         GROUP BY c0) q5
```

It resolved the expression to `fz.v_mixed.v`, found the catalog's `mask =
"none"` rule, and released what the provenance check had just refused to.
`resolve` now refuses any source column belonging to a set-operation view
(guard 5), pinned by a unit test that fails when the guard is removed.

A safety property established in one decision path is not established in the
others. The two paths here were written months apart.

### CockroachDB is now fuzzed

sqlsmith cannot read a CockroachDB schema (`Generating indexes...unknown
type:`), and generating against Postgres then replaying does not work either —
**395 of 400 statements errored**, because sqlsmith draws functions from the
target's catalog. A campaign erroring on 98.75% of its corpus is vacuous however
it reports; the poison control caught it.

New `shapegen` generates compositions of relational operators — subquery, CTE,
set operation, join, DISTINCT, window, value-returning aggregate, GROUP BY,
ORDER BY/LIMIT — in SQL both engines accept. Seeded xorshift, no new dependency.
On CockroachDB it produces **zero engine errors**, and it found the leak above
on its first run.

- New suite `scripts/test-fuzz-cockroach.sh`, wired into `test-all.sh`.
- `examples/fuzz/schema.sql` is now portable (no plpgsql `DO` blocks) and loads
  on both engines; roles moved to `examples/fuzz/roles.sql`, since neither
  `CREATE ROLE IF NOT EXISTS` nor `DO` is portable.
- The fuzz fixture gains `fz.v_mixed`, a union view mixing a released and a
  masked column, with the catalog deliberately releasing its output column. The
  existing `fz.v_union` was masked by an explicit `redact` rule, so the campaign
  had been generating queries against a union view for as long as the fixture
  existed without being able to catch the bug.
- **The role-bleed poison check accepted any non-zero exit.** When the roles
  fixture broke, 16 failed *connections* read as "violations detected" and the
  check reported the oracle as working. It now requires the poison run to have
  detected actual violations.
- **The campaign's poison control was too narrow to be reliable.** It unmasked
  two columns out of sixty and so depended on a random corpus happening to touch
  them. Adding one view to the fixture changed what sqlsmith generates for the
  fixed seed — it enumerates relations from the catalog — the new corpus missed
  both, and the control reported the oracle as broken on a run where nothing was
  wrong. It now also unmasks the twenty `redact` columns, which carry the canary
  token directly: 572 leaks detected where there had been 0. A control whose job
  is to prove detection works should not itself be a subtle test.

## 0.1.2 — set operations hidden in views

**Fixes a disclosure on Postgres as well as CockroachDB.** 0.1.1 decided
trustworthiness from the statement text, which cannot see this:

```sql
CREATE VIEW v_union AS SELECT city AS v FROM t UNION ALL SELECT email FROM t;
SELECT v FROM v_union;      -- no set operation in sight
```

Postgres reports provenance here naming `v_union.v` — the view's own column —
so it is one field with two source columns, and a rule releasing `v` releases
addresses along with cities. That is the rule an operator would write: `v` looks
like a city column, and `classify` sampling it sees cities. Run against the
0.1.1 binary with that rule present, the sweep leaks on **both** engines.

At catalog refresh the proxy now reads every view definition (`pg_get_viewdef`,
available on both engines), marks those containing a set operation, propagates
that to views built on them to a fixpoint, and distrusts provenance for any
statement referencing one. A definition that is null, empty or unparseable is
marked opaque: an engine that will not say what is in a view has not said the
view is safe.

Cost on Postgres is one shape moving from served-as-nulls to refused.

- New suite: `scripts/test-shapes.sh`, a canary sweep of 43 query shapes over
  the **simple-query** protocol against both engines, wired into `test-all.sh`.
  It asserts on values, not on reported provenance, and its catalog deliberately
  releases the union view's column so the trap is armed rather than covered by
  default-deny. `PGMASK_BIN` points it at another build — how the fix was shown
  to be load-bearing rather than merely present.
- The Phase 0 spike would **not** have caught either bug: it reads provenance
  via Parse + Describe, and CockroachDB reports zero there for a set operation.
  0.1.1 claimed otherwise; that claim was wrong. The spike gains the
  `view_union` shapes that established what Postgres reports.
- 229 cargo tests, up from 220.

## 0.1.1 — CockroachDB

**Fixes a disclosure.** CockroachDB reports the *first branch's* table OID and
attnum for a set operation's output field on the simple-query path, where
Postgres reports zero. Believing it applied one column's classification to
another column's values:

```sql
SELECT city FROM customers UNION ALL SELECT email FROM customers
```

returned real addresses in the clear. Five major Postgres versions of testing
never showed this, because Postgres declines to name an origin for a field that
has several.

The fix decides from the statement rather than from the engine: a parsed
statement containing a set operation — or one that will not parse, since that
cannot rule one out — has its provenance distrusted for every field, which are
then handled as computed fields already were. **Postgres behaviour is
unchanged**; the check only fires where Postgres had already zeroed provenance.
A `UNION` over released columns is still served under `lineage = "allow"` on
both engines.

- CockroachDB v25.4 is now a supported and tested engine, with a suite of 34
  assertions (`scripts/test-cockroach.sh`) wired into `test-all.sh`. It includes
  a direct-connection control proving CockroachDB really does report the
  leak-enabling provenance, so the suite cannot quietly stop testing anything.
- The lineage gate now asks whether a field *will be planned* without
  provenance, not whether the engine reported it as computed. Those are the same
  set on Postgres and are not on CockroachDB, where every set operation was
  being refused — safe, and needlessly worse than Postgres.
- New: [docs/engines.md](docs/engines.md).

## 0.1.0 — first release

MIT licensed.

A fail-closed column masking proxy for Postgres. Point a connection string at
pgmask instead of the database and sensitive column values are rewritten on the
way back out. Nothing else about how people work changes: same client, same SQL,
one different host and port.

**Status: usable for engineers working against a copy of production data. Not
yet something to put in front of production as a compliance control** — see
[what is not done](#what-is-not-done).

### How it decides what to mask

Postgres's `RowDescription` carries, per output field, the table OID and column
attnum it came from — and zero for both when the field is computed. That is
engine-authoritative provenance, free, with no SQL parsing.

The governing rule is that **the masking plan is bound to the `RowDescription`,
never to the statement.** Every row-producing path emits one first, so cursors,
`FETCH`, multi-statement queries and re-executed prepared statements are covered
without special handling. The only two paths that emit rows without one —
`COPY ... TO STDOUT` and the legacy `FunctionCall` message — are refused.

### What it does

- **Fourteen masks**: `none`, `null`, `redact`, `partial`, `inner`, `outer`,
  `range`, `hash`, `pseudonym`, `date-year`, `date-month`, `numeric-bucket`,
  `ip-prefix`, `scrub`. Dates and timestamps go through `postgres-types` with jiff, and
  `numeric` through `rust_decimal`, rather than epoch arithmetic of our own.
- **Deterministic pseudonyms**, so masked data stays joinable. Keyed by HMAC,
  domain-separated per semantic type so unrelated columns cannot be linked.
- **Per-principal policy.** The same column resolves differently by role, keyed
  on the username Postgres authenticated — never one a client merely claimed.
- **Default-deny.** A column with no rule is masked, so an incomplete catalog
  costs utility and never exposure.
- **Lineage** (`lineage = "allow"`, off by default): an expression is released
  when every base column it derives from is explicitly released. Cuts refusals
  on TPC-DS from 55% to 26%.
- **System catalogs** (`system_catalogs = "allow"`, off by default), so DBeaver,
  Harlequin, DataGrip and psql's `\d` work.
- **Structured logging** via `tracing`, and a Prometheus endpoint.
- **`classify`**, which reads a live schema and proposes a catalog, naming what
  it cannot decide rather than guessing. `classify --check` fails a build on
  catalog drift, including a column type change that would make a mask
  unapplicable — the one migration that otherwise surfaces as a production
  outage.
- **`scrub`**, which replaces identifiers inside free text with placeholders
  (`called <EMAIL>`) while leaving the sentence readable. Structured
  identifiers only, with checksums where one exists; it does not catch a
  person's name, and its limits are asserted as tests rather than described.
- **One command to verify everything**: `./scripts/test-all.sh`. A skipped
  suite counts as a failure.

### Verified

| suite | what it covers |
|---|---|
| 220 cargo tests | units, properties, adversarial wire client, differential vs `pgwire` |
| 82 demo assertions | end-to-end against a real Postgres, 50k rows |
| 115 version assertions | 23 checks x Postgres 13, 14, 15, 16, 17 |
| 7 TLS assertions | TLS on both legs through a real psql |
| 11 binary-format checks | every type-aware mask over the extended protocol |
| 21,600 role assertions | 24 concurrent sessions, 3 principals |
| 96,000 generated statements | sqlsmith x 4 policy configurations |

The generated-SQL campaign asserts that **no masked value ever reaches the
client** and refuses to pass on a technicality: a poison run with masking
removed must trip the oracle first, every query also runs against the database
so a run that never reached masked data reports as vacuous, the harness refusal
count is cross-checked against the proxy's own metrics, and one configuration
masks nothing so the proxy must be a byte-exact mirror.

Coverage across all suites is 79%, with the modules that decide masking highest:
`analysis.rs` 98%, `lineage.rs` 97%, `mask.rs` 94%, `session.rs` 85%.

### Hardening

`overflow-checks` is on in release, `unsafe_code` is forbidden, and `unwrap`
and `panic` are denied in the library and binaries. Clearing the resulting
lints found three reachable panics — a zero-length `Describe` frame, a
`numeric` at the decimal limit under `numeric-bucket`, and a UTF-8 boundary in
the test harness — each reproduced against the pre-fix code before being
fixed. A fourth, pre-existing, was found by a property test: bucket masking
clamped an out-of-range boundary and served a value that was not a bucket.

### What is not done

- **Nobody but Claude has reviewed this.** Everything above was written and
  assessed by the same author. The test suite is deliberately built so that
  finding nothing is hard to fake, but it is not a substitute for a reader.
- **It has never seen production traffic.** All measurement is TPC-DS, a
  synthetic fixture, and one read-only database branch. No soak test.
- **26% of TPC-DS is still refused**, even with lineage on. Row-level lookup
  work is comfortable; heavy analytical SQL is not.
- **Masked values do not round-trip.** Masking happens on the way out only;
  pasting a pseudonym back into a `WHERE` clause matches nothing. Join on the
  key inside one query, or filter by the real value. Making it round-trip needs
  inbound SQL rewriting and a reversible tokeniser, which is a different
  security posture, not a small change.
- **Changing the catalog needs a restart.** OIDs refresh on a timer; the file
  is read once at boot. No `SIGHUP` reload.
- **`min()`/`max()` over an explicitly released column are refused.** Correct in
  general, over-strict here, and unfixed.
- **DBeaver and DataGrip have not been driven** — only their query shapes and,
  for Beekeeper, its driver stack.
- **TLS is off in every shipped configuration.** The proxy warns at startup, and
  a masking proxy reachable in plaintext is not a boundary.

### The requirement that is not code

**A proxy is only a control if the database is not reachable around it.** Every
guarantee here assumes the backend's port is closed to the people the masking is
for. If someone can put the real host in their connection string, they get
unmasked data and pgmask never sees the query. Nothing in this process can
detect or prevent that. See the deployment section of the README.

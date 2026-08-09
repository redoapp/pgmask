# Changelog

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

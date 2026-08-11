# Safety assessment

Written 2026-08-10, after a day that found six disclosures in code which had
been passing a thirteen-suite release gate. Read the dates: this is a snapshot,
and the reason to distrust it is at the bottom.

## What is actually guaranteed

**A masked value does not appear in a projection.** This is the property the
proxy enforces and the one the campaigns test. It holds under sustained
generated load across both wire protocols and both engines.

Everything below qualifies that sentence.

## What is explicitly not guaranteed

**Reconstruction by inference.** Out of scope by design, measured rather than
hand-waved. `scripts/test-inference.sh` runs the attacks and reports which still
work:

| route | status |
|---|---|
| `count(*)` with a `LIKE` predicate | recovers a full address in **313 queries** |
| `WHERE` on a masked column | confirms a guess exactly |
| an error as a one-bit channel | `1/(CASE WHEN … THEN 0 ELSE 1 END)` |
| `ORDER BY` a masked column | ranks rows by it |
| `sum(x)` filtered to one row | is that row |

The last one is the boundary: pgmask refuses a summary whose *grouping* makes
every group one row, because that is decidable from the statement and the
catalog. It cannot refuse one whose *filter* does, because whether a predicate
matches one row is a property of the data. What the guard buys is the difference
between one query for a whole column and one query per row.

**Anything the operator's catalog does not declare**, unless `unclassified` is
left at its default of masking. The catalog is the operator's; `classify`
proposes one and `classify --check` is the drift gate. Three defects were found
in that tool today — see below — so treat a catalog generated before
2026-08-10 as unreviewed.

**Byte-length side channels.** `pg_column_size(email)` returns an exact length
and no detector covers it. The campaigns generate the shape and cannot tell
whether it leaked.

## What was found on 2026-08-10

Six disclosures, all in the release rules — the paths that turn a refusal into
an acceptance.

| # | disclosure | found by |
|---|---|---|
| 1 | `sum(x) GROUP BY <unique key>` returns every value, one query | review |
| 2 | the same through an output alias, `GROUP BY c` | review |
| 3 | the same through `ROLLUP(alias)` | testing the fix for 2 |
| 4 | `sum(x) GROUP BY x` — a summary of the column you group on | the generated campaign |
| 5 | `date_trunc('day', birth_date)` on a year-masked column | enumerating unreached release paths |
| 6 | `SELECT * FROM (…)` around any of the above | an audit hunting overstated comments |

**Five of six were found by reading, not by the campaign.** The one the campaign
found needed two harness fixes before it could see it.

Number 6 is the one to weigh. It defeated the guard built for number 1, survived
thirteen gate runs used to validate the fixes for 2–5, and was protected by a
comment asserting the case could not arise — written by the same person who then
tested eleven spellings of the grouping without once wrapping one.

## The instruments were wrong more often than the code

This is the finding that should shape how much weight a green run carries.

| instrument | was reporting |
|---|---|
| extended harness type ladder | dropped `int8`, then `numeric`, then `timestamptz` before any detector saw them |
| the shape generator | had no arm for a reducing aggregate over a grouping — the shape of disclosure 4 |
| `test-cockroach.sh` | ran against a **two-day-old foreign container** on a clashing port; 34/34 for a full day |
| `verify.sh` | dropped 22 of 88 assertions under CPU load |
| `test-versions.sh` | lost a version's readiness under load, scoring 23 failures |
| `soak.sh` (first cut) | counted **800,000 statements it never ran** as clean |
| `classify --sample` | could confirm a name guess but never make one |
| `classify --check` | told operators to delete a rule protecting a materialised view |
| coverage measurement | reported `catalog.rs` at 62.6% when it is 88.4% |
| a mutation-kill check | reported two mutants killed after mutating the wrong line |

Every one produced a confident answer about something it was not measuring.
Several were built specifically to prevent that.

## What the current suites do and do not bound

`./scripts/test-all.sh` — 17 suites. Green means no regression in what is
covered. It does not bound what is uncovered.

`./scripts/soak.sh [hours]` — sustained fresh corpora, both engines, both
protocols. **Round zero unmasks the catalog and must leak**, or the run aborts;
a round producing no result aborts too.

`./target/release/reach` — fails when a release rule has no generated statement
behind it. This is the check that bounds the campaigns: two of today's
disclosures were in rules nothing could reach.

`./scripts/test-mutants.sh` — mechanical mutation. Found seven predicates whose
only proof lived in a shell script `cargo test` cannot invoke.

`./scripts/test-mutations.py` — 26 hand-picked guards, each verified to fail
when broken.

## If you read one thing before deploying this

**Only Claude has reviewed this security analysis.** Six rule-level disclosures
in a single day, four found by reading code rather than by any test, is the
argument for a second reader — not the test counts above.

A human adversary should start with `crates/proxy/src/analysis.rs`, and should
distrust the comments. They are unusually detailed and load-bearing, which makes
them read as specifications; two of today's disclosures were sitting behind a
comment that asserted the case could not happen.

## Still unverified

- Nine findings from an internal audit, mostly documentation overstating code.
- Remaining mutation survivors, untriaged.
- `classify` has validators for email, phone and IP only. National IDs, card
  numbers, IBANs, names, addresses and dates of birth cannot be found by content.
- Its phone validator accepts any 7–15 punctuated digits, which is also every
  national ID and IPv4 address. Content discovery therefore proposes withholding
  rather than a mask; that is a workaround, not a fix.
- No fixture exercises partitioned tables, inheritance, domains or generated
  columns.
- Production validation has never run: the intended host is a read-write primary
  and no read-only path has been supplied.

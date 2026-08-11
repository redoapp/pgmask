# Safety assessment

Written 2026-08-10, after a day that found six disclosures in code which had
been passing a thirteen-suite release gate. Updated 2026-08-11; the gate is
nineteen suites now, which changes nothing about the argument below — the
thirteen were green through all six. Read the dates: this is a snapshot, and the
reason to distrust it is at the bottom.

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
proposes one and `classify --check` is the drift gate. Four defects were found
in that tool on 2026-08-10 and a fifth on 2026-08-11 — see below — so treat a
catalog generated before **2026-08-11** as unreviewed.

The 08-11 one moves the date on its own: until then content discovery could not
recognise a card number, an IBAN or a national ID under any name, so a catalog
drafted before it had no chance of proposing anything for a column holding
them. A name match was the only route, and the operator would see nothing at
all for a column called `col_7`.

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
found needed two harness fixes before it could see it. The seventh, a day later,
was also found by reading — in the one release-relevant module no campaign
covers.

Number 6 is the one to weigh. It defeated the guard built for number 1, survived
thirteen gate runs used to validate the fixes for 2–5, and was protected by a
comment asserting the case could not arise — written by the same person who then
tested eleven spellings of the grouping without once wrapping one.

## What was found on 2026-08-11

A seventh disclosure, in `protocol.rs` — a module neither the mutation harness
nor any fuzzer touches, which is where I went looking *because* I had recorded
that gap a few hours earlier.

| # | disclosure | found by |
|---|---|---|
| 7a | `RAISE EXCEPTION '%', (SELECT email …)` returns the value in the error message | reading `scrub_diagnostic` |
| 7b | a value interpolated into dynamic SQL comes back in the `CONTEXT` traceback | testing the fix for 7a |
| 7c | `USING ERRCODE = upper(substr(email,1,5))` returns five characters per query | asking what else `RAISE` can choose |

**This is the notice disclosure again, through the other message type.** The
notice channel was found, fixed, and checked in both directions in
`examples/demo/verify.sh`. The error channel next to it was checked in *one*
direction — the old check `16e` asserted that a backend error's text survived —
and the comment beside the code said Postgres "composes error messages from its
own text rather than from a row". `RAISE` accepts an expression for the message.
The comment was the thing that made it invisible, for the second time.

7c is worth its own line because it is faster than the inference attacks this
design puts out of scope: five characters per query is roughly five queries for
an address, against 313 for the documented `count(*)` predicate oracle.

What it costs: an error's message is now always withheld, and its `SQLSTATE` is
withheld too when a `CONTEXT` field proves the error came through user SQL.
Ordinary errors — missing relation, division by zero, bad cast — carry no
`CONTEXT` and keep their codes, so `42P01` and `23505` still reach the client.
An application whose PL/pgSQL raises custom SQLSTATEs for business logic will
lose them. That is over-withholding, in the direction that does not disclose,
and it is visible to whoever runs it.

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
| `classify` content discovery | could not see a card number at all — 16 digits is past `looks_like_phone`'s ceiling and no other detector existed |
| `classify`'s own new IBAN tests | four structural guards, zero coverage: every invalid example failed mod-97 too |
| rustdoc | never run by the gate; a doc link to a function that was never written survived indefinitely |
| `classify --check` | told operators to delete a rule protecting a materialised view |
| coverage measurement | reported `catalog.rs` at 62.6% when it is 88.4% |
| a mutation-kill check | reported two mutants killed after mutating the wrong line |
| `test-mutants.sh` | printed a complete-looking summary for a run that attempted 102 of 494 mutants, twice |
| `verify.sh` | checked the notice channel both ways and the error channel next to it only in the direction that preserved the leak |
| `assert_no_canary` | looks for the whole token, so five characters of it through a SQLSTATE read as clean |

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
- **Mutation coverage is unknown, and the number previously quoted here was
  wrong.** Two runs died part-way — the second on a full disk — and both printed
  their four outcome counts and nothing else, so "45 survivors" was carried
  here as a finding when 200 of 493 mutants had never been attempted. The
  script now compares planned against attempted and refuses to report a partial
  run. A complete run has not finished yet; until it does, treat mutation
  coverage of the release rules as unmeasured rather than as 45 known gaps.
- The mutation harness does not mutate `protocol.rs` or `mask.rs`. It covers
  `analysis.rs`, `catalog.rs`, `lineage.rs` and `session.rs`. `LEAKY_FIELDS` —
  the error-field scrubbing that stops a unique violation echoing a masked value
  back — is in `protocol.rs`, and the masks themselves are in `mask.rs`. Both
  decide what reaches the client and neither is being mutated.
- `classify` can find seven shapes by content: card numbers (Luhn), IBANs
  (mod-97), US Social Security numbers (SSA allocation rules), email, IP, phone,
  and free text by absence. Names, street addresses, dates of birth, non-US
  national IDs and passport numbers still cannot be found by content — those are
  a name match or nothing.
- Its phone validator accepts any 7–15 punctuated digits, which is also every
  national ID and IPv4 address. Content discovery therefore proposes withholding
  rather than a mask; that is a workaround, not a fix. The checksum-backed
  detectors are not affected — those are specific enough to name — but the
  proposal is still `null` for all of them, because a card and a bank account
  are not distinguishable by content and the operator has to say which.
- Partitioned tables, inheritance, domain-typed columns and generated columns
  now have a canary fixture and two tests: one that nothing escapes through
  them, one recording what each actually does so the first cannot pass by
  refusing everything. Four poison controls, all firing. Two of my predictions
  were wrong — a domain masks normally, because Postgres reports the base type
  OID in `RowDescription`, and a partitioned parent is masked by the parent's
  rule. Reading a partition by name falls to default-deny.
- Production validation has never run: the intended host is a read-write primary
  and no read-only path has been supplied.

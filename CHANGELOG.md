# Changelog

## 0.1.46 — the campaign's first real finding, and two mutants that are not one

Triage of the 827-mutant campaign, at the halfway mark. Three categories, and
the interesting thing is that they are genuinely different from what a day of
reading found.

TWO UNTESTED BOUNDARIES, IN THE DISCLOSURE DIRECTION

`partial`, `inner` and `outer` floor a value that is too short for the window
they keep: `checked_sub(...).filter(|n| *n > 0)`. Relaxing that to `>= 0` at
`len == keep` — or `keep * 2` for `inner` — makes the masked run zero characters
long, so `partial` emits the whole value and `inner` emits head plus tail, which
is also the whole value.

Both survived. Every existing test sat strictly inside or strictly outside the
window and none sat *on* it. A four-character value under `keep = 4` would have
come back verbatim.

`outer` at the same boundary is an **equivalent** mutant: `kept = 0` gives
`"*" * keep` twice, which is exactly the `len` stars the else branch produces.
Said so on the function rather than leaving it to be re-derived.

And `truncate_date_text`'s `year > 9999` survived relaxation to `>= 9999`: the
refusal tests use 10000 and 5874897, the acceptance tests use 2024, nothing sat
on the edge. Over-refusing 9999 would be safe and still wrong — jiff represents
it.

This is what mutation testing is for, and it is a different class from the nine
disclosures: those were missing *cases*, these are untested *boundaries* in
logic that exists.

FOUR MUTANTS THAT ARE NOT A FINDING

`resolve_snapshot` returns early when `rules.is_empty()`, building a second
`Snapshot`, and the campaign reports all four of its fields as deletable with
nothing noticing.

They are equivalent on that path. With no rules nothing is classified, so
default-deny answers every question before those fields are consulted:
`opaque_views` refuses a read that is masked anyway, `unique_keys` only
qualifies a summary and a summary needs a released column, `relation_columns`
backs "does this mention a masked column" and there are none. The one that could
differ is `system_relations` under `system_catalogs = "allow"`, and that
direction is over-refusal.

`an_empty_catalog_masks_everything_and_still_refuses` is added anyway, because
the property is real and was untested — an operator whose catalog failed to load
is exactly who default-deny is for. **It does not kill those mutants**, verified
by poisoning all four; claiming otherwise would be the same mistake as a
green suite that never ran.

A NOTE ON THE CAMPAIGN'S OWN VALIDITY

cargo-mutants copies the tree when it starts, so these results are against
v0.1.43 and not the current tree. `delete field unique_keys` was a genuine
survivor there and is caught now by the v0.1.44 work — confirmed by patching
both construction sites rather than assumed. Anything triaged from this run has
to be re-checked against the tree it will be fixed in.

## 0.1.45 — `SET ROLE` does nothing here, and nothing said so

Before this, no test, script or document in the repository mentioned `SET ROLE`.

`[[role]]` maps a startup principal to pgmask role names, resolved once at
`AuthenticationOk` and never revisited, so `SET ROLE`, `SET SESSION
AUTHORIZATION` and `RESET ROLE` change what the database will let a session read
and change nothing about which mask pgmask applies.

That is the safe direction — a client cannot switch into another role's looser
mask — and it is not what the name suggests. An operator who granted someone a
Postgres role expecting the mask to follow would be configuring nothing, and
would find out from a leak rather than from an error. The README says so now, in
the same section as the promise it qualifies.

Pinned by a test whose fixture is the shape that would matter: a role whose
`by_role` mask *releases* the column, and a principal who is not a member. Four
attempts to reach it — `SET ROLE` to the connecting user, `SET ROLE` to the
privileged role, `SET SESSION AUTHORIZATION`, `SET LOCAL ROLE` — and none does.

The control is half the test: `start_proxy_as_member` connects a principal who
*is* a member and asserts the value comes through in the clear. Without it,
"the canary did not appear" is equally consistent with the role's mask never
releasing anything. Both directions poison-controlled — granting membership
produces a real leak the test catches, and breaking the control fails with "the
`analyst` mask must actually release, or this test asserts nothing".

## 0.1.44 — disclosure 1 again, through the other half of the guard

Disclosures 1-4 and 6 were spellings of the *grouping*. These are spellings of
the *uniqueness*.

The singleton-group guard refuses `sum(x) GROUP BY <unique key>` because one row
per group makes the sum the value. It reads declared keys from `pg_index`, and
two shapes were invisible to it. Both returned `987654321` — the exact value —
through the proxy.

`UNIQUE (lower(label))`. `indkey` holds `0` for an expression, and the query
inner-joined it to `pg_attribute`, so a pure expression index matched no
attribute, produced no group, and vanished. `lower(label)` unique implies
`label` unique, so `GROUP BY label` is provably one row per group from the
catalog alone — it was decidable and simply was not being read.

`UNIQUE (label) WHERE label IS NOT NULL`. Partial indexes were excluded, reasoned
as "they are only unique over the rows matching their predicate". True, and an
argument for the opposite conclusion: a key makes the guard *refuse*, so leaving
one out is the releasing direction.

THE FIRST FIX WAS MUCH WORSE THAN THE BUG

`pg_depend` gives the exact base columns of an index, so the obvious move was to
replace `indkey` with it. That took the generated campaigns from 0 leaks to
**480 and 660**.

A constraint-backed index — every `PRIMARY KEY` and every `UNIQUE` constraint —
has no direct index-to-column dependency at all. The dependency runs through
`pg_constraint`. Measured on Postgres 17: `pg_depend` returns nothing for
`t_pkey` and `t_u_key`, and the columns only for a plain `CREATE UNIQUE INDEX`.
So nearly every real unique key vanished and the guard stopped firing on almost
every table.

Caught by the campaigns, which is what they are for. Nothing else in the gate
noticed — the adversarial suite went on passing, because its fixture indexes are
the shapes I had just been thinking about rather than the ordinary ones.

The design that is actually right: `indkey` is the source, always, and
`pg_depend` only *adds* the base columns of expressions, and only for
non-partial indexes — a partial index's predicate columns are dependencies too,
and `UNIQUE (label) WHERE salary > 0` yields `label,salary`, wider than the
truth, which releases.

A `PRIMARY KEY` and a `UNIQUE` constraint are now fixtures in their own right,
so removing the `indkey` arm fails a test rather than a campaign.

THREE WAYS THIS TEST NEARLY MEANT NOTHING

`max(salary)` instead of `sum`: `max` can return a stored value whatever the
grouping, so it is refused unconditionally and every case came back refused,
including the ones that leak.

No served control: with everything refused, "refused" proves nothing. Adding a
grouping with no unique key behind it is what showed the fix was not a blanket.

And the control column named `label`: unique keys are held unscoped — a flat
list of column-name sets, deliberately, because `group_by_columns` yields bare
names — so a key on *any* relation refuses that name everywhere. That made the
control refuse, and separately let the partial index on one table satisfy the
expression-index case on another, so reverting half the fix broke nothing.
Renaming the fixture columns is what made both halves poison-controllable.

## 0.1.43 — a postcode mask that kept the identifying half

`classify` proposed `partial` for anything matching `zip|postal|postcode`, and
emitted `keep = 4` alongside it. `partial` keeps the *last* characters. A
five-digit US ZIP came back as `*1234`.

Four of five characters, and the wrong four: the leading digits of a ZIP are a
broad region, the trailing ones narrow it to a neighbourhood. The mask kept
exactly the part that identifies.

Now `range` from offset 2, which keeps the coarse prefix — `94103` -> `94***`,
`SW1A 1AA` -> `SW******`, `K1A 0B1` -> `K1*****` — and masks outright anything
shorter than the window. The emitted `end = 64` reads as nonsense until you know
`end` is clamped to the value's length, so a test in `mask.rs` pins those exact
shapes: the proposal lives in one crate and the clamp in another, and if the
clamp ever stops clamping, a postcode column starts arriving verbatim.

FIVE OF SEVEN TEXT-ONLY MASKS WERE UNCHECKED

Found while making that change. `mask_fits` decides whether a proposed mask can
apply to a column's type — it exists because TPC-DS has `c_birth_year` as an
integer and a date mask cannot decode an int4. It had arms for `partial` and
`redact` and fell through to `_ => true` for `inner`, `outer`, `range`, `hash`
and `scrub`.

So `--check` accepted any of those on an integer column, and the proxy refused
the result set at runtime — the outage the function exists to prevent, for five
of the seven masks it applies to. Noticed only because `range` had no arm and I
was about to propose it.

A HAND-WRITTEN LIST, DRIFTING ON CUE

`every_pattern_compiles_and_every_mask_is_one_pgmask_knows` checked rule masks
against an array of mask names typed out by hand. Moving `postal_code` to
`range` failed it: the mask was valid, the list had never heard of it.

The list is derived from the type now, and a `Mask` variant that `ALL_MASKS` has
not been told about fails to compile rather than passing a test that quietly
covers one fewer mask.

## 0.1.42 — the allowlist was right and was reviewed with the wrong question

`ParameterStatus` is governed by an allowlist of GUC names, written after
`application_name` was found carrying a masked address. Twelve names, each one
checked for whether a client can set it.

None was checked for what *shape of value* it accepts.

```sql
DO $$ BEGIN PERFORM set_config('scram_iterations',
         (SELECT annual_salary FROM demo.employees LIMIT 1)::text, false); END $$;
```

`scram_iterations` takes an arbitrary integer over a 31-bit range, so it carried
the number verbatim in a `ParameterStatus` that no `RowDescription` governs.
Measured: `987001`, derived from a masked column, arrived through the proxy.

Every other entry is a boolean, a fixed vocabulary, an existing role name, or
server-fixed — a few bits each, the covert-channel category the assessment puts
out of scope. `scram_iterations` was the only one that carries a *value*, and it
fits any integer-valued masked column: a salary, an age, a count.

Removed. What that costs: libpq reads it to hash a new password client-side and
falls back to 4096 without it. Setting a password through a masking proxy is not
the workload this is for.

THE CONTROL WAS THE HARD PART

The first probe used `SELECT set_config(...)` and reported all four GUCs clean.
They were clean because the proxy refuses that statement outright for having no
provenance — nothing had run. Including a reportable GUC set to a *constant* as
a positive control is what exposed it: the control came back empty too, and an
empty control is the tell.

The test keeps that control and fails on it explicitly — "the control did not
arrive, so nothing below is being tested" — verified by pointing it at a
withheld GUC.

NOT IN THE DEMO, AND WHY

`examples/demo/verify.sh` does not check this. psql never surfaces a
`ParameterStatus`, and the only way to observe one from a psql script is `SHOW`,
which is a provenance-free result set the proxy refuses — so a check written
there passes whether the channel is open or closed. It lives in the adversarial
suite, which reads the wire directly. Writing a check that cannot fail would
have been worse than writing none.

## 0.1.41 — my own fix, one hour old, with the same hole in it

`from_user_sql = !notice && has_field(body, b'W')`.

That `!notice` was written while thinking about errors. `RAISE NOTICE 'x' USING
ERRCODE` takes an expression exactly as `RAISE EXCEPTION` does, so the SQLSTATE
channel closed in 0.1.40 stayed open through `NOTICE`, `WARNING` and `INFO` —
measured, five characters of the canary came back through all three.

The notice is the *worse* of the two. It does not abort the transaction, so

```sql
DO $$ BEGIN FOR i IN 1..10 LOOP
  RAISE NOTICE 'x' USING ERRCODE = <five characters of the value>;
END LOOP; END $$;
```

carries the whole value in a single statement, where the error variant costs one
query per five characters. Withholding it costs nothing: a notice's text is
already replaced unconditionally, so its SQLSTATE has nothing left to qualify.

Found by re-reading the fix rather than by any test, which is the fourth time
that has been the finding method here and the second time in one day that the
thing being re-read was mine.

WHERE THIS STOPS

Written into the assessment rather than left implied, because otherwise these
fixes read as claiming more than they deliver.

What they close is the direct echo of value *bytes* — a message written by
`RAISE`, a `CONTEXT` reproducing a dynamic statement, a `SQLSTATE` set from
`upper(substr(email, 1, 5))`.

What they do not, and no wire proxy can: a client that can execute a `DO` block
with a loop can *encode* a value into anything the protocol lets it vary — how
many notices it emits, which severity each carries, how long the statement
takes, how many rows come back. Severity alone is about two bits per notice and
a loop emits as many as it likes. Closing that means refusing `DO` blocks and
user-defined functions outright, which is a different product.

The line is whether the channel carries the value or carries a message the
attacker encoded. pgmask stops the first.

## 0.1.40 — the notice disclosure again, through the error message

`RAISE NOTICE '%', (SELECT email …)` returning the address was found, fixed, and
checked in both directions in the demo. `RAISE EXCEPTION` is the same channel
through the other message type, and it was open.

```
DO $$ BEGIN RAISE EXCEPTION '%', (SELECT email FROM canary.subjects LIMIT 1); END $$;
```

returned the value verbatim while the same column read as a pseudonym.

WHY IT STAYED HIDDEN

The demo checked the notice both ways — control that the value really is
reachable, then that the proxy withholds it — and checked the error next to it
in one direction only: `16e. a backend error still says what went wrong`. That
check asserted the behaviour that carried the leak.

Beside the code, a comment: Postgres "composes error messages from its own text
rather than from a row". `RAISE` accepts an expression for the message. Second
time in this project a comment asserting a case could not arise is what kept it
from being tested — the first was disclosure 6.

Meanwhile `session.rs` already said, twenty lines away, that "every free-text
diagnostic field can be SQL-controlled (`RAISE` accepts expressions for Message,
Detail, Hint and object names), so rebuild the message from constrained fields
plus fixed text." The code did not do that. Two comments, one right and one
wrong, and the wrong one was the one next to the branch.

TWO MORE, FOUND BY PULLING THE THREAD

`CONTEXT` reproduces the text of a statement PL/pgSQL ran, so a value
interpolated into dynamic SQL comes straight back inside it. `W` joins
`LEAKY_FIELDS`, next to `q`, which was already there for the same reason.

And `USING ERRCODE` takes an expression. A SQLSTATE is five characters of
`[0-9A-Z]`, so `upper(substr(email, 1, 5))` returns five characters of the value
per query — about five queries for an address, against the 313 the documented
`count(*)` predicate oracle needs. Faster than the inference routes this design
declares out of scope, so it is closed rather than documented.

The code is kept when the error has no `CONTEXT` and replaced when it has one:
`RAISE` only exists inside PL/pgSQL and a function frame always produces one,
while ordinary errors produce none. Measured on Postgres 17 rather than assumed.

THE GATE'S LARGEST SUITE COULD NOT FAIL

While fixing the above, a property test began failing and the gate reported
`ok  cargo test  489 tests`. The count was real. The verdict was not:

```bash
out=$(cargo test --workspace ... 2>&1
      cargo test -p pgmask --lib --features fuzzing ... 2>&1)
status=$?          # <- the SECOND command's status, only
```

`$?` after a command substitution holding two commands is the last one's. For as
long as that was written that way, the workspace run — every integration test in
`crates/proxy/tests/`, including the adversarial suite when Postgres is
available — could not fail the gate. Only the lib-only second run was reported.

Both statuses now. Poison-controlled by planting a failure in the workspace run:
combined status 101 where it was 0.

That is the fourth exit status lost to a pipeline or a substitution in a day —
three in throwaway harnesses, one baked into the gate.

A PROPERTY THAT WAS A PROXY FOR THE REAL ONE

The failing test asserted `scrubbed.len() <= original.len()` — "if it can grow
the message it is rewriting content rather than dropping fields". Replacing the
message with fixed text makes that false by design, and length was never what
mattered. Restated as **a value that came in must not come out**, with
distinctive tokens so a match cannot be coincidence.

Writing it caught a second thing: asserted unconditionally, it fails, because
`C` is forwarded when there is no `CONTEXT`. That is correct, and it rests on a
measured property of Postgres rather than anything the proxy enforces. The
property now says so and tests both branches.

WHAT IT COSTS

An error's message is always withheld now. `42P01` and `23505` still reach the
client, which is the machine-readable half and what every driver surfaces. An
application whose PL/pgSQL raises custom SQLSTATEs for business logic loses
them — over-withholding, in the direction that does not disclose, and visible to
whoever runs it.

Three demo checks asserted the old behaviour and now assert the new contract in
both directions. `assert_no_canary` looks for the whole token, so it would have
called the SQLSTATE channel clean; the test checks for a five-character prefix
as well.

## 0.1.39 — the mutation runs were a fifth of a run

`45 survivors` has been sitting in the safety assessment as a known quantity.
It was never the survivor list. Two runs died part-way and both printed their
four outcome counts — caught, missed, timeout, unviable — and nothing else, so
a run that attempted 293 of 493 mutants read exactly like a complete one. The
second died on a full disk at 102 of 494.

A partial mutation run is worse than no run. It reads as coverage.

`test-mutants.sh` now counts what it planned against what it attempted and
refuses to report anything if they differ. Verified against the crashed run
still on disk rather than a synthetic one: 102 of 494, exit 1.

Two supporting fixes, both causes rather than symptoms:

* A free-space precheck. cargo-mutants copies the whole tree into `$TMPDIR` and
  rebuilds in it per mutant; the copy reached 5.4 GB. The run needs 20 GB and
  now says so before starting the container instead of dying at mutant 102.
* Cleanup of that copy, which a crash leaves behind. The 5.4 GB orphan from the
  crash was itself part of why the disk was full.

WHAT THE HARNESS STILL DOES NOT LOOK AT

`protocol.rs` and `mask.rs` are not in the mutated file list. `LEAKY_FIELDS` is
in `protocol.rs` — the error-field scrubbing that stops a unique violation
echoing `Key (email)=(alice@example.com)` back to the client — and the masks
themselves are in `mask.rs`. Both decide what reaches the client. Recorded, not
yet fixed: adding them changes what a complete run costs, and no complete run
has finished yet.

## 0.1.38 — four relations that were never a plain table

Partitioned tables, inheritance, domain-typed columns and generated columns had
no fixture. Each breaks a different assumption the plan binding makes, and each
had been probed once by hand and written down as a gap rather than pinned.

They are in the canary schema now, carrying the same canary as everything else,
under two tests. One sweeps sixteen statements and insists nothing escapes. The
other records what each statement *does* — served or refused — because a sweep
where every query errors is also canary-free, and only the second test tells the
two apart.

TWO OF MY PREDICTIONS WERE WRONG

I expected a **domain** column to be refused: `is_text_family` has never heard
of an OID allocated at `CREATE DOMAIN` time, so I reasoned the masker would
reject the result set and the operator would be pushed toward marking the column
allowed to get their query back. It masks normally. Postgres reports the *base*
type OID in `RowDescription`, so the masker never sees the domain.

I also expected the partitioned parent to be the hazard, since a
`RowDescription` for a read through the parent carries the partition's table
OID. A read through the parent is masked by the parent's rule. Reading the
partition *by name* falls to default-deny — safe, and a utility cost the
operator can see.

Inheritance matches partitioning in both directions, including the child's row
arriving through the parent, masked. A cast off a domain column is refused for
losing provenance, which is the general rule and nothing to do with domains.

Nothing was found. That is the result, and it is worth having as a fixture
rather than as a memory of having once checked: four poison controls — allowing
the column on each parent, and allowing the generated column — fail both tests,
so the fixture is live rather than accidentally quiet.

## 0.1.37 — a checksum is what makes content discovery worth running

CONTENT DISCOVERY COULD NOT SEE A CARD NUMBER

`classify --sample` advertises itself as catching "a column called `notes` full
of email addresses". It could find three shapes, because discovery iterated the
name rules that happened to carry a confirmation validator — email, phone, IP.
A column of card numbers under a meaningless name matched **nothing**. Not a
wrong proposal: none. `looks_like_phone` stops at 15 digits and a 16-digit PAN
sailed past it; an IBAN has letters in it.

Three checksum-backed detectors close that: Luhn for cards, mod-97 for IBANs,
and the SSA's own allocation rules for US Social Security numbers. The checksum
is the point. A shape test matches about one string of digits in one, so it can
corroborate a name and little else; Luhn rejects nine in ten and mod-97 rejects
ninety-six in ninety-seven, which is specific enough to make a claim about a
column nobody named.

Verified against a fixture rather than only in unit tests: 60 rows each of
Luhn-valid PANs, SSNs, IBANs, ordinary prose, and — the load-bearing negative —
16-digit numbers with a deliberately wrong checksum. The first three are
proposed `null` and flagged for review; the last two stay silent. That last
column is the proof the detector is reading the checksum and not the length.

Discovery still proposes `null` whatever matched. Knowing values are payment
instruments does not say whether the column is a card, an IBAN or a bank
account, and those get different treatment.

TWO LISTS, WHICH IS THE THING THAT WENT WRONG

Name rules and content detectors are now separate lists, because they answer
different questions — "the column is called `ssn`, what mask?" versus "the
column is called `col_7`, what is in it?". Splitting them creates a way to drift,
so a test asserts every confirmation validator is also a detector, and another
asserts every detector's label is a type the rules know.

The precise checks are listed first so a US SSN reports as "national_id or
phone" rather than "phone". The first cut deduplicated those labels through a
`BTreeSet`, which sorts alphabetically and silently threw that ordering away —
caught by a poison control that reordered the list and changed nothing.

Discovery also issues one query per column now instead of one per detector,
which would have been six after this change. The values are still counted and
dropped inside the sampling function; the caller receives labels and rates.

TWELVE GUARDS, TWELVE POISON CONTROLS, TWO SURVIVORS

Deleting the length bound from the card check broke no test: the too-short and
too-long examples failed Luhn as well, so only the checksum was rejecting them.
Replaced with numbers that are Luhn-valid at 12, 13, 19 and 20 digits, which
pins both edges exactly.

Worse in the IBAN check — all four structural guards were unexercised, every
invalid example failing mod-97 too. Fixed by searching for strings that satisfy
mod-97 and violate exactly one rule each: `GB8212` folds to 1 in six characters.

Both are the same failure the vacuous soak was: an assertion that passes for a
reason other than the one it names.

A POSTGRES YEAR IS NOT FOUR DIGITS

`truncate_date`'s text path read `&text[0..4]`. Against Postgres 17,
`'10000-06-15'::date` masked with `date-year` came back as `1000-01-01` — a
well-formed date nine thousand years from the real one, with nothing for the
client to notice. `date` reaches `5874897-12-31` and Postgres renders every
digit.

Second defect on the same line of reasoning: the era suffix was appended after a
timezone slice that ran to the end of the string, so
`0044-03-15 10:00:00+00 BC` came back as `...+00 BC BC`.

Parsed by delimiter now, and wide years are **refused** rather than coarsened.
jiff's civil date stops at ±9999, so the binary path already fails on them;
letting text succeed would mean the same stored value masking differently
depending on which protocol the client used, which
`binary_date_truncation_agrees_with_the_text_path` exists to forbid. This is a
behaviour change: a masked date column holding a year above 9999 now errors in
text as it already did in binary.

Four of the five guards in the rewrite are load-bearing under poison control.
The fifth — scoping the timezone search to the time field instead of the old
`rfind(...).filter(|i| *i > 10)` — is not, because the year bound twenty lines
above makes the two equivalent, and the doc comment says so rather than
implying it fixes something reachable.

RUSTDOC WAS NEVER RUN

`[`referenced_relations`]` sat in `analysis.rs` pointing at a function nobody
ever wrote, and four usage lines rendered `<seed>` as an unclosed HTML tag. The
gate ran fmt, clippy, audit and seventeen suites, and none of them look at doc
links. It runs rustdoc with warnings fatal now.

Four other documentation corrections, all found by an earlier audit and none
made until now: `floor_within` still carried a paragraph describing the clamping
it stopped doing two releases ago; `LEAKY_FIELDS` claimed to drop fields "when
the message mentions anything we are masking" while the code drops them
unconditionally, which is the safer behaviour the doc talked a reader out of;
the `Scrub` doc listed seven of the ten placeholders it emits.

## 0.1.36 — a fuzzer for the state machine, and the shapes the grammar could not say

Two parallel efforts, both required to prove themselves by reverting a real fix
and finding it again.

THE GRAMMAR COULD NOT EXPRESS TWO OF SIX DISCLOSURES

Measured over 5,000 generated statements before this: `SELECT * FROM (…)`
appeared **0 times**, `ROLLUP`/`GROUPING SETS` **0 times**. The soak could have
run for a year without finding 0.1.31 or 0.1.18. Volume was never the binding
constraint; grammar was.

Now 1,747 star wrappers per 5,000 (622 doubly nested), and the grouping-set
spellings behind a `postgres` dialect argument so the cross-engine campaigns
stay portable — CockroachDB rejects all three outright. `reach` tracks both, so
losing them fails the run instead of going quiet.

Poison control: deleting the unwrap loop from `group_by_columns` takes the
campaign from 0 leaks to **2,880**, on 10 of 10 seeds. At a flat 30% wrap rate
one seed in ten found nothing, so the top-level wrap is weighted toward
statements that group. Executable rate held: 400/400 on Postgres, no new
CockroachDB errors.

A FUZZER FOR THE PROTOCOL STATE MACHINE

Every campaign here fuzzes SQL shapes; `described_sql` substituting an unrelated
statement's text was an interleaving bug. `cargo-fuzz` over `PlanState` finds it
in ~4 seconds from an empty corpus, minimises it to two operations, and reaches
100% region coverage of `plan_state.rs`. It independently rediscovered the
non-UTF-8 `ParseUndecodable` precondition nobody pointed it at, and a portal-side
variant of the same bug.

`libfuzzer-sys` and `arbitrary` live in a workspace-excluded crate; the proxy
gains an off-by-default `fuzzing = []` feature and nine `#[cfg]`-gated lines.
Nothing compiles into the binary.

The oracle sits *inside* the crate as a child module because it needs private
fields for ground truth — an external target would infer "is a Describe
outstanding" from the function under test and agree with any answer it gave.
Parse texts and simple-query texts are disjoint pools, so a substitution is
detectable in both directions.

THE REGRESSIONS WERE NOT RUNNING

The minimised sequences were reported as carried by `test-all.sh`. They were not:
the module is feature-gated and the gate runs plain `cargo test`, so it compiled
none of them and reported the same 183 lib tests before and after they were
added. The gate runs the feature now — 470 tests, and reverting `described_sql`
fails four of them.

Caught because the test count did not move when a patch that adds tests was
applied. The same signal that exposed the vacuous soak.

TWO MORE INSTRUMENT FIXES

The shared oracle could not read `900000137.00000000`: `parse::<i64>()` fails on
it, so the simple-query harness saw 420 leaks where the extended harness saw 540
on an identical corpus. Fifth instance of a value not reaching a detector.
Normalised in the oracle so both harnesses see it; a genuine two-row average is
still correctly ignored.

And this gate destroyed concurrent work. Its teardown is machine-global —
`pkill -f` matches every pgmask on the host, and the container names are fixed
strings any checkout uses — so the agent fuzzing in a separate worktree lost its
proxies and its `pgmask-fuzz` fixture mid-run, while its load made three of this
gate's suites report false failures. A worktree isolates files, not processes.
The gate refuses now, naming the offending PID.

## 0.1.35 — evidence that made the proposal worse

`classify` on a `phone bigint` column, which is an ordinary way to store one:

```
  without --sample   name suggests phone, but a `partial` mask cannot apply to
                     bigint — pick another          [[column]]   # NEEDS REVIEW
  with --sample 200  confirmed by sampled values    [[column]]
```

Sampling casts to text, reads 100% phone-shaped values, and overwrote both the
verdict and the note — so the emitted entry lost its review marker and the proxy
refuses that result set at runtime. Adding evidence produced a worse proposal,
and it removed the warning that `mask_fits` exists to raise.

Sampling confirms a *shape*; it cannot vouch for a *type*. Those were conflated.
`confidence_after_sampling` is a pure function now, testable without a database,
and the note is appended rather than replaced — the incompatibility is the more
actionable half.

Fourth `classify` defect today. Two of the four made the tooling actively
harmful rather than merely incomplete: one proposed `partial` for national IDs,
publishing their last four digits, and one told operators a rule protecting a
materialised view was dead.

A THIRD SUITE THAT FAILED UNDER LOAD

`test-tls.sh` reported 3 of 7 while two fuzzers were building, and 7 of 7 alone.
Two bare `sleep 2`s after starting a proxy, and a `kill -0` check that proves
the process exists rather than that it is bound — pgmask resolves the whole
catalog before binding, so those are seconds apart under load. It waits on the
listener now, verified at 7 of 7 under twelve CPU spinners.

That is three suites with the same defect: `verify.sh`, `test-versions.sh`, and
this one. All three produced false *failures*, never false passes, which is the
safe direction — but three separate diagnoses today went into confirming that a
red gate was actually green.

## 0.1.34 — the four spelling disclosures were one property all along

Every disclosure in the analysis layer has been the same query written
differently:

```
  0.1.16   SELECT id, sum(salary) FROM t GROUP BY id
  0.1.18   ... GROUP BY <an alias of id>
  0.1.18   ... GROUP BY ROLLUP(<an alias of id>)
  0.1.31   SELECT * FROM ( ... GROUP BY id )
```

Each was fixed by adding a literal string to a list, which only protects against
spellings someone thought of. Four rounds is enough to conclude the list is the
wrong shape.

The property needs no list: **a rewrite that does not change what a query
returns must not lose a grouped column.** `crates/proxy/tests/analysis_properties.rs`
generates the rewrites — star wrappers, nested wrappers, output aliases,
ordinals, `ROLLUP`, an alias inside a `ROLLUP` — and requires the reader's answer
for each to still cover the plain form's.

`proptest` was already a dependency, used for the `RowDescription` parser and the
masks. It had never been pointed at `analysis.rs`, which is where all six
disclosures were. No new crate: `shapegen` hand-rolls its RNG rather than take
`rand`, and that posture is worth keeping.

THE FIRST VERSION WAS DECORATION

It compared `analyze(plain)` against `analyze(rewritten)` and passed against
*three reverted disclosures*. The singleton-group decision is not made in
`analyze`: `session` combines the reader with the catalog's unique keys and
passes the verdict down as a `Relaxations` flag, so both spellings returned
`Releasable`, the comparison found no difference, and nothing tripped.

Re-aimed at `group_by_columns` — the function whose answer actually differed
between spellings — reverting the 0.1.31 wrapper fix and the 0.1.18 alias fix
both fail the property now.

Reverting the 0.1.17 ordinal fix does *not*, and that is correct: breaking
ordinal resolution makes the reader return unbounded, which refuses. A safety
property should not fire on over-refusal, and the precision regression is pinned
separately in the inference suite.

The only reason I know these work is that real fixes were reverted and failure
required. They passed before that check too.

## 0.1.33 — tooling that told operators to delete a working defence

`classify --check` reported this, against a live materialised view whose column
the proxy was masking correctly:

```
1 rule(s) match nothing in the database. The column was renamed or
dropped, and the rule is protecting nothing:
  t.mv_contacts.email
```

An operator following that advice removes masking from a materialised view — a
denormalised reporting matview being a classic place for a copy of a masked
column to live. The rule was live: the proxy resolves `relkind = ANY('{r,v,m,p,f}')`.
`classify` walked `information_schema`, which omits materialised views entirely
(they are not in the SQL standard) and reports foreign tables as `'FOREIGN'`.

The two components disagreed about what a relation *is*. `classify` walks
`pg_catalog` with the proxy's own `relkind` set now, so they agree by
construction. Verified in both directions: the matview is proposed, and the
correct rule is no longer condemned.

Third defect in `classify` today, all in the component the product boundary
rests on — *the catalog belongs to whoever deploys the proxy; we ship the
tooling* — and the one whose coverage was lowest in the repo at 47.6%.

THE SOAK COUNTED ROUNDS IT NEVER RAN

Worth recording in full, because it is the failure this whole file is about and
I wrote it. `soak.sh` exists to prove the oracle can fail before believing a
clean run. Underneath that guard, the loop added 2,000 statements per engine
whether or not the harness executed anything. When the release gate's
`pkill -f 'target/release/pgmask'` killed the soak's proxies mid-run, it went on
reporting **800,000 statements, 0 leaks** in under a minute, with `served` and
`refused` frozen at the last real values. The only thing that caught it was two
numbers not moving between progress lines.

Two guards now, each verified by causing the failure: a round with no `RESULT`
aborts, and a `RESULT` that served *and* refused nothing aborts — a well-formed
line reporting no verdicts is the same emptiness better dressed.

ALSO

`test-versions.sh` lost a version's readiness under gate load and scored its 23
assertions as failures — correct behaviour, budget too short for five Postgres
containers and ten proxies starting together. Two minutes now, not thirty
seconds. It never passed anything it had not run, which is the difference
between it and `verify.sh`.

The lineage backstop's doc claimed the name comparison "cannot be wrong in the
unsafe direction". True for an explicitly classified column; for an unclassified
one the check also requires the relation's name to appear. Not a leak — no
exploit constructed — but an overstated guarantee is how the `SELECT *` wrapper
survived a day of grouping work.

## 0.1.32 — a soak, and a round zero that has to fail

`scripts/soak.sh [hours]` runs a fresh 2,000-statement corpus every round for as
long as it is given, over both wire protocols, against Postgres 17 and
CockroachDB v25.4.14, with a running total in `/tmp/pgmask-soak.status`.

**Round zero unmasks the catalog and requires the campaign to leak.** If it does
not, the run aborts and reports nothing further. A clean round from a detector
that cannot see is indistinguishable from a proxy that does not leak, and this
codebase produced that exact false clean three times in one day — `int8`,
`numeric` and `timestamptz`, each dropped by a type ladder one layer below the
canaries. Measured on the first run: 817,016 leaks with masking removed.

It also aborts on a blind spot rather than counting it clean: a value in a type
the harness cannot decode stops the run and names the type.

On a leak it stops and keeps the corpus at `/tmp/soak-leak-<seed>.sql`, so the
finding is reproducible rather than a number in a log.

Two harness bugs found while smoke-testing it, both this session's recurring
shape. `mkcfg` rewrote the backend port but not `catalog_dsn`, so the
CockroachDB proxy died on Postgres credentials. And the CockroachDB fixture load
was silent, so an empty fixture would have soaked against nothing — it verifies
`fz.people` is populated before starting.

WHAT A CLEAN SOAK MEANS

That no masked value appeared in a result set, across the statements it ran, on
both protocols and both engines. Not that the proxy is safe against an
adversary: inference is out of scope by design and `test-inference.sh` measures
what remains. Not that untested rules are sound either — `reach` fails when a
release path has no generated statement behind it, and that is the check which
bounds this one.

## 0.1.31 — the guard read one statement while the analysis judged another

```sql
SELECT id, sum(annual_salary) FROM demo.customers GROUP BY id            -- refused
SELECT * FROM (SELECT id, sum(annual_salary) FROM demo.customers
               GROUP BY id) q                                            -- served
```

The second returned `1|43700` — the real salary — against the shipped demo
catalog. The 0.1.16 disclosure, restored in full by wrapping it, and present
through every gate run used to validate the five fixes after it.

`analyze_inspected` unwraps `SELECT * FROM (subselect)` and classifies the
*subquery's* target list, so the released aggregate can sit inside the subquery.
`group_by_columns` read the *outer* group clause, which is empty for a wrapper,
and reported "no grouping". Two halves of one guard, looking at two different
statements. It reads the grouping after unwrapping now.

The comment on that function argued the case could not arise:

> Only the top level is inspected, which is sufficient — an aggregate inside a
> subquery is not the released field; the outer field referencing it has no
> provenance and is judged on its own.

Already false when written: the unwrapping is forty lines away in the same
module. I wrote that justification, believed it, and tested eleven spellings of
the grouping without once wrapping any of them.

It was found by an audit hunting *confident comments* rather than bugs — the
generalisation of 0.1.30, where `classify`'s doc claimed a capability the code
did not have.

ALSO: `described_sql` substituted an unrelated statement's text

`.and_then(..).or_else(..)` collapsed "no Describe outstanding" and "a Describe
is outstanding whose SQL was never recorded" into one branch, so the second fell
back to the last simple query. `SELECT 1, 2` reads as two literals and would
release fields belonging to `SELECT upper(email), …`. Same failure class as the
pipelined-Describe fix in 0.1.8, on a path it did not cover. A pending Describe
carries no SQL when the statement could not be decoded — a non-UTF-8 client
encoding — while the backend accepted the Parse anyway.

Three comments asserted it already failed closed, including the one on the test
written to pin it. That test passed vacuously: `simple_sql` was `None` in its
fixture, so the fallback had nothing to substitute. Given a simple query first,
it fails against the old code.

## 0.1.30 — `--sample` could confirm a guess but never make one

`classify` proposes a catalog from column names and, with `--sample`, checks the
values. Its own module doc says why:

> With `--sample` it reads data, because a column called `notes` full of email
> addresses …

It could not do that. Sampling ran only for columns whose *name* had already
matched a rule:

```rust
let matched = rules.iter().find(|rule| rule.pattern.is_match(&lower))
```

so it could confirm or downgrade a name-based guess and never make one. A `text`
column named `plain_key` holding fifty thousand real addresses drew no proposal
and not even a review flag. Neither did `search_key`, nor `sort_hint` full of
phone prefixes.

WHY THIS IS WORSE THAN AN ORDINARY BUG

The product boundary is that the catalog belongs to whoever deploys the proxy,
and we ship the mechanism plus the tooling that proposes one. A proposal tool
that cannot find PII in a column with an unhelpful name leaves a hole the
operator has no way to see: `classify --check`, the drift gate, cannot flag a
column `classify` does not know exists. Under `unclassified = "allow"` that is a
live disclosure; under default-deny it is a column masked by luck rather than by
decision.

Sampling now runs for columns whose name says nothing, proposing on an 80%
content match — as `NeedsReview`, never `Clear`, because the name gave no
corroboration and this file already argues that silently masking on content
alone trains people to override the tool.

Found while testing a hypothesis that was wrong. Generated columns looked like
the sharp shape — a stored column with real provenance whose value derives from
a masked one — and they are not: default-deny nulls an undeclared one, and
`classify` proposes `type = "email"` for `email_lower` from its name. The
layered defences held exactly as designed. Testing *why* they held is what
surfaced this.

REGRESSION COVERAGE

`demo.customers.lookup_key` holds addresses under a name that announces nothing.
Plain, not generated: the derivation was never the problem, and a column
populated by application code is both likelier and the same shape — encoding the
wrong hypothesis in the fixture would have been quietly misleading.

Three assertions, each failing for a different reason: that the column is found
at all, that the proposed type is the one the values are, and that it is flagged
for a human rather than decided alone.

Adding it failed `classify --check` immediately, because the shipped catalog did
not declare the new column. That is the drift gate doing its job on the first
change that gave it something to catch.

## 0.1.29 — a suite whose answer depended on the machine

`verify.sh` reported 66 of 88 while a mutation pass was running, and 88 of 88 on
the same commit once the machine was quiet. Six proxy startups waited with a
bare `sleep 2`, and pgmask resolves the whole catalog against Postgres before it
binds — on a loaded machine that is not two seconds, so every assertion in the
block ran against a closed port.

`scripts/test-fuzz.sh` already waits for the listener and explains why. The fix
was never carried across, which is the same shape as the `exit 0` this project
diagnosed in one release path and left standing in the other.

Verified against the condition that caused it rather than by reading: 88 of 88
with twelve CPU spinners running.

THE FIRST FIX WAS WORSE THAN THE BUG

It probed with `SELECT 1` through the proxy. Assertion 13d asserts
`pgmask_fields_rescued_total 1` exactly, and the probe query was itself
analysed, rescued and counted — a readiness check that corrupted the
measurement it existed to make reliable. It is a bare TCP connect now.

Third distinct way an instrument gave a confident wrong answer today: a value
dropped before the detector (`int8`, `numeric`, `timestamptz`), an answer that
depended on machine load, and a probe that changed what it measured.

WHY A FLAKY SUITE IS NOT JUST NOISE

It failed 22 assertions under load. With different timing it could as easily
have passed ones it had not earned — a proxy that never came up looks identical
to one that answered correctly if nothing checks. That is the same failure as
every other instrument problem here: the answer turning on something other than
the property under test.

## 0.1.28 — seven predicates that only one suite was watching

`cargo mutants` replaced each of these function bodies with a constant and
`cargo test` stayed green:

| predicate | what the constant does |
|---|---|
| `aggregate_argument_is_grouped -> false` | reopens 0.1.19's summary-of-a-grouped-column disclosure |
| `statement_references_masked_column -> false` | disables the lineage backstop *and* the mask gate on fine `date_trunc` |
| `is_system_relation -> true` | every relation reads as `pg_catalog`, so the fast path serves user tables unmasked |
| `is_parseable -> true` | trusts input the parser rejected |
| lexer word test, `&&` to `\|\|` | the backstop under lineage, the catalog fast path and the grouping guard |
| lexer quoted-name handling | 0.1.8 fixed a porous version of exactly this |
| `pseudonym_key` floor, `<` to `<=` | 0.1.9's sixteen-byte minimum, its boundary never asserted |

All seven are pinned now, and each was verified by applying the mutation and
requiring the new test to fail — not by assuming it would.

WHAT THEY HAVE IN COMMON

Every one is covered end-to-end by the shell campaigns, and not at all by
`cargo test`. `cargo mutants` only runs cargo tests, so it found precisely the
set where the unit suite leans on a suite it cannot invoke.

That is a different failure from the rest of today. The instrument was not
blind — `test-fuzz.sh` would have caught most of these. But it is not the
instrument anyone runs before pushing, and `cargo test` would have stayed green
while `is_system_relation` returned `true` for every OID.

TWO MORE HARNESS MISTAKES ON THE WAY

`-- --test-threads=1` reaches *every* cargo invocation cargo-mutants makes,
including `cargo build`, which rejects a test-harness flag; the run died at the
baseline with a bare `Usage:` line and zero mutants tested. `RUST_TEST_THREADS`
is the right mechanism.

The container start was piped to `/dev/null`, so a failure surfaced only as
"postgres did not start" — the third diagnosis today slowed by a log sent to
nowhere, after the proxy log in the CockroachDB work and the dropped values in
the extended harness. It prints the error and the last lines of the Postgres log
now.

## 0.1.27 — mechanical mutation, and two measurements I got wrong first

Two things claimed in 0.1.26's notes and not delivered: real line coverage, and
mutation testing that is not a hand-picked list. Both are here, and both
produced a wrong answer before a right one.

COVERAGE

Measured with `PGMASK_ALLOW_SKIP=1`, `catalog.rs` reads 62.6% and looks like the
weakest module in the proxy. That is not its coverage; it is the coverage of the
tests that do not need a database. Run against a real Postgres with
`--test-threads=1`, as `scripts/test-integration.sh` does, it is **88.4%**.

| lineage | mask | metrics | plan_state | catalog | protocol | session |
|---|---|---|---|---|---|---|
| 98.2 | 94.5 | 93.8 | 92.3 | 88.4 | 86.4 | 80.7 |

`tls.rs` reads 5.8% and that is also an artefact: the TLS suite exercises the
proxy as a subprocess, which this instrumentation does not see.

MUTATION

`scripts/test-mutations.py` breaks twenty-six guards someone thought to protect
— the same blind spot as an inference suite that only knows the spellings it was
given. `cargo mutants` mutates every function it can reach: **352 mutants, 222
caught, 111 missed**.

The `catalog.rs` survivors are the coverage mistake again, from the other side:
run with `-- --lib`, its tests never ran. `scripts/test-mutants.sh` now sets up
the invocation that means something and says why.

Three survivors in `analysis.rs` were worth acting on:

- The `bare` check for context functions, `&&` to `||`. A real gap: inverted, a
  context function *with arguments* releases, and `CREATE FUNCTION
  public.now(text)` returning its argument is a shape an ordinary user can
  create. Pinned.
- The `COALESCE` rule, `==` to `!=`. A real gap: inverted, two unreadable
  arguments release together. Pinned.
- `unwrap_star_over_subquery`'s early return. **Equivalent**, not a gap — both
  conditions are re-enforced by slice patterns in the same function. Recorded on
  the function so it is not re-litigated, rather than pinned with a test that
  would assert a shape refused for other reasons.

A DEFECT IN CODE FROM EARLIER TODAY

Writing the second test surfaced one. `grouping_may_reference` treated an
integer literal *nested in an expression* as an ordinal into the target list, so
`GROUP BY coalesce(col, 0)` resolved `0` to nothing and reported the grouping
unbounded — refusing an honest aggregate — while `GROUP BY col + 1` resolved `1`
to the first target and pulled its columns in. Safe in both directions and wrong
in both. An integer is an ordinal only as a grouping *element*; descending into
an expression now clears that flag, as it already did for output aliases.

Fourteen more survivors are `grouping_may_reference` arms, all precision-only:
deleting one makes the grouping unbounded, which refuses. They are pinned by
asserting that every node type the function claims to read is read — the same
shape of test as the ordinal-resolution one in 0.1.19, and for the same reason.

Poison control re-run after the walker change: 0 leaks with the
summary-of-a-grouped-column rule, 1,740 without.

## 0.1.26 — was this rule ever consulted?

The leak oracle answers "did anything escape". No suite answered "was this rule
reached at all", and a release rule no generated statement can express is a rule
the campaign is silent about however many statements it runs. `PURE_SCALARS`
(0.1.9) and `date_trunc` (0.1.23) were each in that position when they leaked,
and both were found by reading code rather than by the campaign.

`crates/fuzz/src/bin/reach.rs` replays a corpus through `analysis` alone — no
server, no proxy — and fails when a tracked release shape is unreachable. In the
gate as "release paths reached". Verified both directions: 3,000 statements
reach all thirteen and exit 0; a 40-statement corpus reports `date_trunc`,
`size formatter`, `pure scalar` and `string_agg` unreachable and exits 1.

Two things the probe got wrong first, both worth recording because both would
have produced a confident, false number.

It passed `field_count = 1`, so `analyze` collapsed nearly everything to
`Unknown` on a positional mismatch and it claimed 99 of 3,000 statements were
releasable. It reads the real target-list length now.

After that fix the number was still 99, and the temptation was to report it as a
finding. It is not one: `Unknown` from the allowlist does not mean refused, it
means "a plain column projection, which provenance decides". The labels now say
"released by the allowlist alone" and "left to provenance or lineage", which is
what the counters measure. A misleading headline in a security suite is worth
about what a blind detector is.

## 0.1.25 — a value nobody could decode is not a value that did not leak

Three disclosures hid in one line of the extended harness, which returned
`None` both for "this column was NULL" and for "I could not decode this type".
The second is a blind spot; the first is nothing. Conflating them meant the
oracle reported clean on values it had never seen:

  0.1.19  `sum(int4)` is `int8`          hid the singleton-group disclosure
  0.1.21  `avg` is `numeric`             recorded as a comment and left
  0.1.24  `date_trunc` is `timestamptz`  broke that release's own poison control

Each fix added a type, and each time the next type was equally silent.
`interval`, `bytea`, `json`, arrays and CockroachDB's own types were all queued
up behind it.

An undecodable value is now an event with a name. `render` returns
`Value`/`Null`/`Undecodable`, the run tallies them by type from
`row.columns()[i].type_().name()`, prints them, and **fails**:

```
  UNDECODABLE, so never scanned:
     6884  date
Error: 6884 value(s) of type date could not be decoded, so no detector saw them
```

Verified the way the rest of this is: by deleting the `date` decoder and
requiring the failure. Before this change that same deletion reported
`leaks=0` and passed.

This is the fix that should have been made after the first instance rather than
the third. Adding a type closes one hole; making the hole audible closes the
class.

## 0.1.24 — generate the release paths, and make the control fail first

Every rule in `classify` that turns a refusal into an acceptance, and whether a
generated statement could reach it before this release:

| release path | reachable |
|---|---|
| literals, `count(*)`, reducing aggregates, ranking windows | yes |
| `SqlvalueFunction`, `CONTEXT_FUNCTIONS`, `SIZE_FUNCTIONS` | no |
| `date_trunc` | **no** — 0.1.23's disclosure |
| `PURE_SCALARS` | **no** — 0.1.9's disclosure |

Two of the three unreachable paths had each already cost a disclosure, both
found by reading code. The new arm emits them, and emits the *unsafe* spellings
alongside the safe ones — `date_trunc('day', …)` next to `'year'`,
`pg_size_pretty(<value>)` next to nothing at all. An arm that only produces the
releasable form asserts nothing, which is exactly what the grouped-aggregate arm
did for a full release while projecting `count(*)`.

THE CONTROL FAILED, WHICH IS WHY IT EXISTS

First run of the poison control — revert 0.1.23, require the campaign to find
it — reported **zero leaks**. The arm could not see the bug it was built for.
`date_trunc` returns `timestamptz`, and the harness type ladder decoded
`String`, integers, floats, bool, uuid, `civil::Date` and `Decimal`. The value
was discarded one layer below the detector.

That is the third instance of the same failure in this codebase:

  0.1.19  `sum(int4)` -> `int8` dropped        hid the singleton-group leak
  0.1.21  `avg` -> `numeric` dropped           recorded as a comment, not fixed
  0.1.24  `date_trunc` -> `timestamptz` dropped  broke this arm's own control

With `civil::DateTime` and `Timestamp` added: 1,550 leaks reverted, 0 with the
fix. The arm can now rediscover 0.1.23.

WHAT THE ARM DELIBERATELY DOES NOT EMIT

`version()`, `current_database()`, `pg_backend_pid()` and
`pg_size_pretty(pg_table_size(t))` were in the first cut and produced twelve
cross-engine mismatches — `20` vs `20.5` from integer versus decimal division,
and two version banners. None was a masking difference. This corpus is shared
with the differential, whose premise is that the same fixture and catalog give
the same masked output, and these are properties of the engine and the session.
None of them takes a column, so none can leak one; unit tests cover that path.
`round(sum(x)::numeric / …)` stays, with the cast that makes both engines agree.

`shapegen` runs 398 of 400 statements after all this, up from 378 — the arm
needed real date columns rather than whatever `typed_col` returned, since
`date_trunc` over a uuid is an engine error and not a test.

## 0.1.23 — coarsening below the mask is not coarsening

`date_trunc` was released for any unit "at or above a day". The fixture's
`birth_date` is masked to its year, and through the proxy:

```
  plain birth_date                 1975-01-01   the mask
  date_trunc('day',  birth_date)   1975-02-14   the whole value
  date_trunc('week', birth_date)   1975-02-10   a seven-day window
```

The rule was written as "coarse enough to lose the day". Soundness needs "at
least as coarse as the mask", and this module cannot see the mask — the field is
computed, so it has no provenance and no classification.

Found by enumerating which release paths a generated statement can reach.
`date_trunc` was one of three that nothing in the corpus could produce, and two
of those three have now produced a disclosure — the other was `PURE_SCALARS` in
0.1.9.

TRIMMING THE LIST WAS TOO EXPENSIVE

Restricting the units to year and coarser also refused
`date_trunc('month', placed_at)` on a column the operator set to `mask = "none"`
— the demo catalog runs without lineage, so there was no second chance to
release it, and ordinary time bucketing broke.

Year and coarser are now released unconditionally, because year is the coarsest
date mask on offer and nothing finer can escape through it. Finer units are
released only when the statement names no masked column at all, which is the
same lexical backstop the lineage and catalog paths use. Both directions
measured: the three fine units refused over `birth_date`, and
`date_trunc('month', placed_at)` and the month-bucket-with-sum query still
served.

The pair of booleans threading through `classify` became a `Relaxations` struct
on the way through. This was the second flag, and the call sites had stopped
saying what `true, false` meant.

## 0.1.22 — count what executed, not what was generated

Measured on the fuzz fixture, sqlsmith runs **123 of every 400 statements**. The
other 277 are `anymultirange is not a multirange type`, `cannot determine
element type of "anyarray"`, `cannot cast type unknown to anyenum`, `operator
does not exist: point = point` — polymorphic catalog functions called with
ill-typed arguments. They exercise the type resolver, not the masker.
`shapegen` runs 397 of 400, and generates the thing that actually decides
masking: how many source columns can reach one output field.

So the shape corpus is appended to each seed of the main replay, not just to the
600-statement extended run it fed before. Appended, not substituted — sqlsmith
reaches operators and functions nobody here would think to write, which is its
whole value. Effect on one run:

| | before | after |
|---|---|---|
| served | 2,083 / 18,000 (12%) | 6,741 / 19,200 (35%) |
| Postgres errors | 73% | 37% |
| masked values reached | 26,153 | 21,557,391 |

`shapegen`'s own error rate fell from 5.5% to 0.75% along the way, and the cause
was one mistake made twice: the windowed-aggregate arm and the grouped-aggregate
arm both return `bigint`/`numeric` while declaring `typed: false` — the exact
flag introduced to stop a date being paired with text under a set operation. The
residue is `min(uuid)`/`max(uuid)`, which Postgres does not have; the shape does
not record which typed column it carries, and 3 in 400 does not justify the
refactor that would fix it.

The README claimed "24,000 statements, 96,000 executions" and counted
*generated*. It now reports the executed and served fractions, because that is
the number someone deciding whether to trust this would want.

## 0.1.21 — a value the harness cannot decode is a value the oracle never sees

0.1.19 restricted the generator to `sum` and said why in a comment: `avg` over
an integer returns `numeric`, the harness could not decode it, and an `avg`
disclosure would have been generated and then discarded before any detector
ran. That is a documented hole, not a closed one, and it is the same shape as
the defect that hid the singleton-group leak — `sum(int4)` is `int8`, and int8
was being dropped too.

`rust_decimal` was already a workspace dependency; the fuzz crate now enables
its `db-tokio-postgres` feature and renders `numeric` through the same type
ladder. `avg` is back in the generator: 60 `avg` disclosure shapes per 1500
statements.

Verified the way the rest of this is verified rather than by inspection: with
the guard removed the campaign reports 180 leaked salaries through `avg` alone,
and 0 with it restored. `avg` over a singleton group returns
`900000137.00000000`, so the values are normalised before the integer detector
sees them.

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

# Safety assessment

> [!NOTE]
> This is a chronological audit record. Use the concise
> [security model](security.md) for current deployment guidance. Version counts,
> test counts, and open questions below describe the date of each entry.

Written 2026-08-10, after a day that found six disclosures in code which had
been passing a thirteen-suite release gate. Updated 2026-08-11; the gate is
nineteen suites now, which changes nothing about the argument below — the
thirteen were green through all six. Read the dates: this is a snapshot, and the
reason to distrust it is at the bottom.

## What is actually guaranteed

**A masked value does not appear in a projection.** This is the property the
proxy enforces and the one the campaigns test. It holds under sustained
generated load across both wire protocols and both engines.

Everything below qualifies that sentence, and the first qualification is the
largest: it is a statement about what the proxy *sends to a client*, not about
where the data is. The proxy reads unmasked rows to mask them.

## What is explicitly not guaranteed

**Reconstruction by inference.** Out of scope by design, measured rather than
hand-waved. `scripts/test-inference.sh` runs the attacks and reports which still
work:

| route | status |
|---|---|
| `count(*)` with a `LIKE` predicate | recovers a full address in **313 queries** |
| `WHERE` on a masked column | confirms a guess exactly |
| an error as a one-bit channel | `1/(CASE WHEN … THEN 0 ELSE 1 END)` |
| `ORDER BY` a masked column | ranks rows by it (accepted: cells stay masked) |
| `sum(x)` filtered to one row | the bucketed floor — capped by the column's mask |

The last one used to read "is that row", and that reading was the remaining
unmasked-output path. It is closed since v0.1.92: a reducing aggregate over a
masked column is masked with that column's own mask before it leaves the proxy,
so a singleton sum is indistinguishable from the column's own masked value. The
guard still refuses a summary whose *grouping* makes every group one row,
because that is decidable from the statement and the catalog, and it is kept
even though the summary would now be served masked — see the 2026-08-14 record
above. A *filter* that matches one row is a property of the data and cannot be
refused; masking is what handles it, and it is now handled.

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

**The connection between the proxy and the database.** This qualifies the one
sentence at the top, so it belongs here rather than only in the README's
limitations list, where it was.

The proxy reads *unmasked* rows from the backend and masks them on the way out.
So everything the guarantee is about is in the clear on that hop, and
`backend_tls` offers two settings: `disable`, plaintext, and `require`,
encryption without certificate verification — libpq's `sslmode=require`, with
libpq's caveat. The verifier is named `AcceptAnyServerCert` rather than
something reassuring.

Neither setting authenticates the database. An attacker who can intercept the
proxy-to-database connection reads every masked column unmasked, and no rule in
`analysis` has anything to say about it. Put the proxy where that hop is
short — a unix socket, a sidecar, a private subnet — and treat "pgmask is in
front of it" as saying nothing about network position.

**Multi-statement simple queries are refused, not masked.** A single `Query`
message carrying more than one statement — `SET search_path = x; SELECT ...`,
the pattern a lot of ORMs open a connection with — fails closed with "output
column has no column provenance". pgmask cannot reliably pair the Nth
RowDescription with the Nth statement (`analysis::provenance_is_trustworthy`
returns false for anything but a single parsed statement), so it treats every
field as opaque rather than risk serving the second result set under the first
statement's plan. Verified fail-closed in both postures: `reject` refuses,
`mask` nulls, neither serves the value. It is a real compatibility limitation
and not a leak — but send one statement per `Query`, or use the extended
protocol, if a client depends on the combined form.

**Who the client is.** pgmask does not authenticate anybody. It forwards the
authentication exchange to Postgres and watches for `AuthenticationOk`, and the
principal it resolves masking policy from is the `user` in the startup packet.
That is the right division of labour, and it has a consequence worth stating
plainly: **role relaxations are exactly as strong as the backend's `pg_hba.conf`
and no stronger.**

A backend that authenticates with `trust` hands out `AuthenticationOk` to
whoever asks. Every `[[role]]` relaxation then becomes self-service — a client
picks `user=analyst`, gets `AuthenticationOk`, and pgmask applies the looser
mask because from its side that principal *was* authenticated. The proxy is
behaving correctly and the deployment is wide open.

The parts pgmask does control are in place: an unauthenticated session can only
ever get the default (most restrictive) classification, and a startup packet
naming `user` twice is refused rather than guessed at, because the backend
resolves the duplicate one way and a naive reader the other. Both are tested.
Neither helps if the backend authenticates nobody. If you use `[[role]]`, read
`pg_hba.conf` first.

**Byte-length side channels.** `pg_column_size(email)` returns an exact length
and no detector covers it. The campaigns generate the shape and cannot tell
whether it leaked.

**Covert channels available to a client that can run arbitrary PL/pgSQL.** This
boundary matters for reading the 2026-08-11 fixes correctly, and it is not the
same line as "inference".

What was closed there is the *direct echo of value bytes*: an error or notice
message written by `RAISE`, a `CONTEXT` reproducing a dynamic statement, and a
`SQLSTATE` set from `upper(substr(email, 1, 5))`. Those carry the value itself.

What is not closed, and cannot be by a wire proxy: a client that can execute a
`DO` block with a loop can *encode* a value into anything the protocol lets it
vary — how many notices it emits, which severity each one carries, how long the
statement takes, how many rows come back. Severity alone is roughly two bits per
notice and a loop emits as many as it likes. Closing those would mean refusing
`DO` blocks and user-defined functions outright, which is a different product.
`rate_limit_per_minute` (off by default) is the blunt instrument that makes a
few-hundred-query campaign expensive without inventing that interpreter.
`max_notices_per_exchange` (also off by default) caps NOTICE/INFO/WARNING
messages between `ReadyForQuery` markers. Under every posture, mutating SQL
(`INSERT`/`UPDATE`/`DELETE`/DDL/`DO`/`CALL`/…) is refused outright —
measured exfil via `INSERT … SELECT` and DML rowcount oracles. Under
`posture = "hostile"`, masked columns outside bare projections are refused
as well. As of 0.1.79, `SELECT` of non-allowlisted / non-`pg_catalog` functions is
refused before execution, and `FOR UPDATE` joins the read-only gate. As of
0.1.80 the read-only gate is a fail-closed statement allowlist (closing
`CREATE VIEW` / `LOAD` / `CHECKPOINT` and other DDL the denylist missed).
As of 0.1.81, hostile also treats unclassified columns (including on
uncatalogued tables) like masked ones for predicates — closing
`WHERE internal_note = …` / `WHERE token = …` after default-deny masks the
projection. As of 0.1.82, hostile predicate checks and leaky-catalog reads
(`pg_stats`, `pg_authid`, …) are refused at the frontend before Postgres runs
them — closing the remaining execute-then-refuse timing/error channel for
those paths. As of 0.1.85, cleartext `ORDER BY` of masked columns is an
accepted residual (cells stay masked on the wire; 0.1.83/0.1.84 briefly
refused it). As of 0.1.86, hostile also refuses whole-row casts/refs
(`t::text`, `format('%s', t)`, aggregate `FILTER` on row text) that embed
cleartext without naming masked columns. As of 0.1.87, hostile also closes
unicode-escaped identifiers (`u&"email"`) and `ORDER BY email = '…'` membership
oracles (only simple `ORDER BY email` stays accepted). As of 0.1.88, also
NATURAL JOIN / `FROM t AS x(c1,c2,…)` renames / unicode `USING` &
`PARTITION BY`. As of 0.1.89, also `ARRAY`/`CASE`/`LIMIT`/`(t).col`/
`xmlforest` containers around unicode-escaped masked names. As of 0.1.91, also
`JOIN … ON`, `BooleanTest` (`IS TRUE`), JSON constructors (`JSON_OBJECT` /
`JSON_ARRAY`), and `xmlserialize` around those names. As of 0.1.92, also
aggregate `ORDER BY` / `WITHIN GROUP`, window frame offsets, `JSON_VALUE` /
`JSON_TABLE`, `PREPARE`/`DECLARE` bodies, whole-row refs nested in
`ARRAY`/JSON/XML/`LIMIT`, CTE `SEARCH`/`CYCLE` column lists, whole-row
refs inside `json_arrayagg` / `json_objectagg` / `JSON_SERIALIZE` / `IS JSON`,
and join/rename via `PREPARE` or `(SELECT *) AS t(c1,c2,…)` / CTE column lists.
SQL `PREPARE`/`EXECUTE`/`DEALLOCATE` and `DECLARE`/`FETCH`/`CLOSE` are now
refused on every posture (`sql_prepare_cursor`); ordinary `SELECT` (including
`SELECT … FETCH FIRST n ROWS`) and protocol Parse/Bind stay allowed. `EXPLAIN`
of those same SELECTs is allowed; `EXPLAIN` of a predicate oracle is not.
`pg_cursors` and `pg_stat_wal_receiver` join the leaky-catalog refuse list
(session SQL text / replication conninfo). Unknown `pg_stat_*` views are
leaky too (`pg_stat_monitor` and the next extension were metadata-only);
core counter / progress views stay allowed. `pg_show_plans` /
`pg_query_state` and fork `*_stat_activity` / `*_stat_statements` views
in `pg_catalog` are the same dump without that prefix. Citus
`citus_lock_waits` / `citus_stat_tenants` / `pg_dist_*` (authinfo,
background-task SQL, shard range keys) were still metadata-only.
Catalog-shaped RangeVars are classified once against the vanilla
PostgreSQL 18 surface (every official heap/view/IS relation is
metadata-safe XOR leaky); classified-leaky names are leaky in any
schema, and an unnamed `pg_catalog` / `information_schema` relation is
leaky.
Residual
disclosure under hostile + read-only SELECT is the intentional mask surface
(partial phone, salary buckets, filters on columns with `mask = "none"`, and
cleartext sort order among masked projections).
Default posture still allows predicate oracles on masked columns by design.

The distinction is whether the channel carries the value or carries a message
the attacker encoded. pgmask stops the first.

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

Numbered 7, 8 and 9 to continue the list above, and the letters are not
decoration: 7 is four separate channels and 9 is two. "Ten disclosures" is the
numbering, not the count of ways a value got out — that is 14, 6 in the
release rules, 7 here, and 1 in the transport the day after. Where a count
appears elsewhere in the repository it means the numbering.

I wrote "fourteen" in the first draft of this paragraph without counting the
rows, in a document whose subject is numbers asserted with more confidence than
the measurement behind them.

A seventh disclosure, in `protocol.rs` — a module neither the mutation harness
nor any fuzzer touches, which is where I went looking *because* I had recorded
that gap a few hours earlier.

| # | disclosure | found by |
|---|---|---|
| 7a | `RAISE EXCEPTION '%', (SELECT email …)` returns the value in the error message | reading `scrub_diagnostic` |
| 7b | a value interpolated into dynamic SQL comes back in the `CONTEXT` traceback | testing the fix for 7a |
| 7c | `USING ERRCODE = upper(substr(email,1,5))` returns five characters per query | asking what else `RAISE` can choose |
| 7d | the same through `RAISE NOTICE`/`WARNING`/`INFO`, which a loop repeats freely | re-reading the fix for 7c |
| 8 | `set_config('scram_iterations', (SELECT annual_salary …))` echoes the number in a `ParameterStatus` | enumerating every field forwarded verbatim |
| 9a | `UNIQUE (lower(label))` was invisible to the loader, so `sum(x) GROUP BY label` was released one row at a time | asking what the singleton guard reads |
| 9b | partial unique indexes were excluded outright, same effect | reading the reason given for excluding them |

**This is the notice disclosure again, through the other message type.** The
notice channel was found, fixed, and checked in both directions in
`examples/demo/verify.sh`. The error channel next to it was checked in *one*
direction — the old check `16e` asserted that a backend error's text survived —
and the comment beside the code said Postgres "composes error messages from its
own text rather than from a row". `RAISE` accepts an expression for the message.
The comment was the thing that made it invisible, for the second time.

7c is worth its own line because it is faster than the inference attacks this
design puts out of scope: five characters per query is roughly five queries for
an address, against 313 for the documented `count(*)` predicate oracle. 7d is
faster still — a notice does not abort the transaction, so a loop emits as many
as it likes and the whole value arrives in one statement.

**8 is the one that says the most about method.** `ParameterStatus` is governed
by an allowlist of GUC names, added after `application_name` was found carrying
an address. Every entry had been checked for whether a client can set it. None
had been checked for *what shape of value it accepts*, and `scram_iterations`
takes an arbitrary 31-bit integer — so unlike every other entry, which is a
boolean or a fixed vocabulary worth a few bits, it carries the number itself.
Any integer-valued masked column: a salary, an age, a count.

The allowlist was the right design and it was reviewed with the wrong question.

**9 is disclosure 1 again, through the other half of the guard.** Disclosures
1–4 and 6 were spellings of the *grouping*; these are spellings of the
*uniqueness*. The guard refuses `sum(x) GROUP BY <unique key>` because one row
per group makes the sum the value — and it reads the keys from `pg_index` with
an inner join on `indkey`, which holds `0` for an expression. A pure expression
index matched no attribute, produced no group, and vanished. `lower(label)`
unique implies `label` unique, so this was decidable from the catalog and simply
was not being read.

Partial indexes were excluded deliberately, reasoned as "they are only unique
over the rows matching their predicate". True, and an argument for the opposite
conclusion: a key that is present makes the guard *refuse*, so leaving one out
is the releasing direction. Both measured returning `987654321` — the exact
value — through the proxy.

Worth recording alongside: unique keys are held **unscoped**, a flat list of
column-name sets with no relation attached, because `group_by_columns` yields
bare names and resolving each to a relation is the provenance work the analysis
refuses to guess at. That is conservative and correct, and it also nearly hid
this: naming a fixture column `label` let a key from a *different* table satisfy
the test, so reverting half the fix broke nothing.

A narrow gap remains and is documented in the loader: a *partial* index whose
key is purely an expression is still missed. `indkey` gives nothing for it, and
`pg_depend` cannot substitute because a partial index's predicate columns are
dependencies too — measured, `UNIQUE (label) WHERE salary > 0` yields
`label,salary`, a wider key than the truth, which is the releasing direction.

What it costs: an error's message is now always withheld, and its `SQLSTATE` is
withheld too when a `CONTEXT` field proves the error came through user SQL.
Ordinary errors — missing relation, division by zero, bad cast — carry no
`CONTEXT` and keep their codes, so `42P01` and `23505` still reach the client.
An application whose PL/pgSQL raises custom SQLSTATEs for business logic will
lose them. That is over-withholding, in the direction that does not disclose,
and it is visible to whoever runs it.

## What was found on 2026-08-12

| # | disclosure | found by |
|---|---|---|
| 10 | a configured TLS certificate was entirely optional: `sslmode=disable` got a working plaintext session, silently | reading `tls.rs`, the one module the 08-11 sweep never opened |

This one is not a masking bypass, and saying so first is the honest framing. The
invariant held throughout: no unmasked value ever reached a plaintext client
that would not have reached a TLS one. What failed is the sentence at the top of
`tls.rs` — *"a masking proxy reachable over plaintext is not a security
boundary"* — which the module states as a principle and does not enforce.

Postgres has no ALPN and no TLS port. A client asks to upgrade with an
`SSLRequest` packet, and one that never asks simply proceeds in the clear. The
proxy tracked that as `client_tls`, used it to decide whether to strip SCRAM
channel binding, and used it for nothing else. There was no setting that could
require TLS, no refusal, no warning, and no counter. The startup log printed
`tls=true`, because the accessor behind it — named `has_client_tls`, which reads
as a property of a connection — returned `self.tls.is_some()`, a property of the
configuration.

So an operator who generated a certificate, wired it into the config, and read
their own startup log confirming TLS had no way to discover that some client was
connecting with `sslmode=disable`. Masked output is not public output: partial
masks are partial deliberately, a pseudonym is a stable identifier across
queries, and the SCRAM exchange and the client's SQL cross the same wire.

Worse in one specific way: the channel-binding strip *smooths the path*. That
code exists so pgmask can sit in front of a TLS-only managed Postgres, and its
effect is to make the plaintext client work well. The downgrade had no friction
to run into, which is why it needed a gate rather than an inconvenience.

The fix is `require_client_tls`, defaulting to **true whenever `tls_cert` is
set**. Configuring a certificate and not requiring it is the shape of a mistake
rather than of a decision, so the default is fail-closed and the operator who
genuinely wants mixed-mode writes `require_client_tls = false` — which now warns
at startup and counts those sessions as `pgmask_plaintext_sessions_total`.
Setting it true
without a certificate is refused at load: that refuses every connection, which
is fail-closed and useless, and reads at a glance like the strictest setting
rather than the broken one.

**Why the 08-11 sweep missed it.** That sweep enumerated everything that reaches
the client and asked what shape of value each thing could carry. It was a
question about *contents*, and it was answered well. Nothing in it asked about
the transport those contents travel over, so `tls.rs` was never opened. The
method had a blind spot exactly the width of its own framing.

**Why seven passing TLS tests missed it.** `test-tls.sh` connects with
`sslmode=require` in every assertion, which is the correct way to test that TLS
works and structurally incapable of testing that it is required. A suite that
only ever exercises the good path measures the good path. It now tests the
downgrade, with a poison control: turn `require_client_tls` off and the same
refused client must succeed, because otherwise "refused" is indistinguishable
from "broken".

**And the suite was concealing a second failure.** Its two `pg_isready` loops
broke on success and fell through on timeout. Run on a machine busy with a soak,
Postgres took longer than the 30s budget, so `ALTER SYSTEM SET ssl = on` ran
against a socket that did not exist, its error went to a discarded stream, and
the run continued with SSL off — after which the channel-binding assertion
failed reporting that the server refused TLS. A true statement about a database
the script was supposed to have configured, and nothing to do with the proxy.
Both loops now abort, and `SHOW ssl` is read back before anything depends on it.

### The extended-protocol plan cache is safe across a refresh

A cached statement or portal plan could, in principle, outlive a catalog
refresh and mask the wrong data. It does not. Driven with a raw wire client:
Parse + Describe + Bind + Execute a statement (masked correctly), reshape the
table from another connection, wait for the refresh, then re-Execute the same
portal and re-Bind the cached statement. Both are refused —
`invalidate_if_stale` clears the plans on the generation bump, so the following
DataRows arrive with no described result set and fail closed. The `SELECT *`
column-reorder variant is refused one layer earlier, by the backend's own
"cached plan must not change result type". Neither served a byte.

### What the same sweep did *not* find

The 08-11 disclosures came from one method: enumerate everything that reaches
the client and ask, of each, what shape of value it can carry. Reporting where
that came up empty matters as much as where it did not, because otherwise the
method reads as infallible.

* **The backend message dispatch is sound.** It is an explicit allowlist with no
  catch-all — an unrecognised tag is refused and the connection closed. Each of
  the twelve forwarded-verbatim tags was checked: `CommandComplete` carries a
  row count (the inference category), `ParameterDescription` carries the
  client's own parameter types, `NegotiateProtocolVersion` echoes option names
  from the client's own startup packet. None carries row data.
* **The `Vetted` invariant holds by construction.** Its constructors are
  module-private, and every `Vetted::control` call site is provably not a
  `DataRow`: the dispatch routes `B_DATA_ROW` to `handle_data_row` before the
  control arm, `b'D'` is absent from `BACKEND_CONTROL_TAGS`, and the two calls
  outside the dispatch are guarded by a `ReadyForQuery` tag check and the
  `RowDescription` handler respectively.
* Worth knowing anyway: both `Vetted` invariants are `debug_assert`, so they are
  compiled out of the shipped binary. They are currently redundant —
  `unmasked_row`'s assert is exactly the `!changed` condition its only caller
  tests — so nothing rests on them at runtime. If a call site is ever added,
  that stops being true silently.
* **The metrics endpoint and the logs carry no row data.** `metrics_listen`
  opens unauthenticated HTTP, so it is worth being specific: every label is a
  `&'static str` from a fixed `Cause` enum, so no column name, value or
  statement text can reach it — which also means no unbounded cardinality.
  `classify_opaque` takes an output field *name* and returns a `Cause`, so the
  name does not escape into a label either. Of the sixteen log calls in the
  proxy, the ones that could carry something carry counts, the connecting
  principal, and errors from the proxy's own I/O and its own catalog queries
  against `pg_catalog`. A backend `ErrorResponse` is forwarded as bytes and
  never becomes a logged Rust error, which matters now that its text can be
  SQL-chosen.
* **Channel binding had no test of any kind, and now has three.**
  `strip_channel_binding` and `sasl_mechanisms` decide whether authentication
  downgrades, and nothing in the repository mentioned `-PLUS`,
  `Cause::ChannelBinding` or either function outside its own definition. The
  mutation campaign flagged both `session.rs` guards that call them, which is
  what an untested function looks like from the outside. Not a disclosure — the
  proxy terminates TLS, so stripping is the only way a plaintext client
  connects, and that trade is documented — but an authentication-integrity
  behaviour with a security rationale and no coverage.
* **The partial-reveal masks have length floors.** `partial`, `inner`, `outer`
  and `range` each mask outright rather than passing through a value too short
  for their window, and `range` was the one whose absence of that guard had
  already been found and fixed.

### SQL from a grammar nobody here wrote

Added 2026-08-11, and it is the answer to the sharpest criticism of everything
above: every campaign in this repository generates from `shapegen`, which I
wrote, so it explores the shapes I thought of. That is not hypothetical —
before v0.1.36 the generator could not express `SELECT * FROM (…)` or
`GROUPING SETS`, and two of the six original disclosures were unreachable by it
for that reason alone.

`scripts/test-sqlsmith.sh` uses **sqlsmith**, which reads the live catalog and
builds semantically-valid random queries against whatever it finds. It has found
hundreds of bugs in PostgreSQL itself and knows nothing about pgmask.

It took four attempts to make the harness say anything true, and each failure is
worth more than the eventual pass:

1. Pointing sqlsmith at the proxy finds no tables — it introspects `pg_catalog`,
   which the proxy refuses — so it generates nothing and reports no leaks.
2. Releasing one column as a poison does not fire, because a 150-query corpus
   may never touch that column.
3. Releasing *every* mask still does not fire, because sqlsmith writes
   expression-heavy SQL and the proxy refuses a field with no provenance
   whatever the catalog says. A corpus of refusals is indistinguishable from a
   corpus being masked correctly.
4. Control statements appended to the corpus never ran: several refusal paths
   close the connection, and psql then fails everything after that point. This
   also explains direct canary counts of 353, 123 and 1 across runs — each
   replay died at a different statement.

What it asserts now: the corpus must reach masked data (the direct replay has to
surface canaries), masked values must actually be *served* through the proxy
(or nothing observable happened), and no canary may cross. Verified in both
directions — releasing every mask produces 47 canary-carrying lines.

`--seed` does not reproduce a corpus: sqlsmith builds from catalog OIDs, which
differ per container. Each run is an independent sample.

**The first campaign that ran to its own deadline (2026-08-12):** 516 rounds,
**258,000 queries**, 2,964,017 replayed lines that reached masked data, 245,119
masked values served through the proxy, **0 leaks**. It matters that it *ended*
rather than aborting: every round asserts that it reached masked data and served
a masked value, so a run reaching its deadline is 516 rounds each of which
measured something. Earlier campaigns stopped early on exactly those assertions,
which is how the DML problem below was found.

What that does and does not buy: it is 258,000 statements from a grammar written
by someone else against a policy that refuses most of what it generates. It is
evidence that the release rules hold under SQL nobody here imagined. It is not
evidence about anything sqlsmith cannot express, and its own harness reported
something untrue six times before it reported this.

**And the cause of all of it: sqlsmith generates DML.** Roughly one statement in
ten is a `delete`, `update` or `insert` against the schema it read. Replaying a
500-query corpus emptied `smith.people` outright — 200 rows before, 0 after.

That single fact explains every anomaly above: canary counts collapsing from 353
to 123 to 1 as the table was progressively destroyed; "no masked value was
served" once it was empty; and the false positive below, where `city` held
`CANARYNAME…` because an sqlsmith `update` had written `full_name` into it.
**Every sqlsmith number produced before this fix was measuring a table being
destroyed underneath it.** The replay now runs with
`default_transaction_read_only=on`, and the fixture is verified intact — 200 of
200 rows — after six rounds where it used to be gone by the third.

**It also reported a leak that was not one, and that is the fifth failure worth
recording.** A soak round flagged 165 canary-carrying lines through the proxy.
The container's `city` column contained `CANARYNAME…`, and `city` is
deliberately *released* — so the proxy was correctly passing through an unmasked
column that happened to hold the token the check greps for. Bisecting to the
statement and diffing direct against proxied is what exposed it: the direct
output read `CANARYNAME150|CANARYNAME150`, which no correct fixture produces.

A canary check is only as sound as the assumption that canaries appear *only* in
masked columns. Both scripts now verify all 200 fixture rows before trusting any
result, and abort otherwise. A false positive here is not harmless: it would
have been reported as a tenth disclosure.

### Mutation testing would not have found any of the ten

Worth stating because the opposite conclusion is the tempting one. Disclosure 7
was in `protocol.rs`, which nothing mutated, and I went looking there *because*
I had written that down — so it reads as "the missing instrument was the cause".
It was not.

A mutant changes existing logic and asks whether a test notices. Every one of
the ten disclosures is a **missing case**, not wrong logic:

* `LEAKY_FIELDS` did not contain `W`.
* The error branch did not replace the message at all.
* `from_user_sql` had `!notice` in it.
* `scram_iterations` was on an allowlist.
* The unique-key query never selected expression indexes.

There is nothing to mutate in code that was never written.

An earlier draft of this section quoted a survivor count from a campaign that
was still running — "killed every mutant in both files" — and it was false
within the hour. **Do not put a running total in a document.** The final numbers
belong here when the run finishes; until then the claim is that the campaign is
incomplete, which is what `test-mutants.sh` now refuses to let a partial run
obscure.

The qualitative point stands and does not depend on the count. Mutation testing
found a class reading did not — untested *boundaries* in logic that exists, such
as the `partial` and `inner` length floors, where a value exactly as long as the
window it keeps came back verbatim. Reading found a class mutation testing
cannot: *cases* that were never written. Neither substitutes for the other, and
all ten disclosures were of the second kind.

So adding them was right, and it closes a different gap than the one that let
disclosure 7 through. What found all nine was reading, and what made reading
productive was choosing where to read: the paths that reach the client, taken
one at a time, asking of each what shape of value it can carry.

## What was recorded on 2026-08-14

A reclassification, not a disclosure. The remaining unmasked-output path was a
documented accepted limitation: a *reducing* aggregate over a masked column was
served exact whenever its input set collapsed to one row — `sum(salary) WHERE
id = 1` returned the exact salary, and was written down as a property of the
data rather than of the statement. Disclosures 1–4, 6 and 9 had refused their
*grouping* forms; the *filter* forms could not be refused, because whether a
predicate matches one row is undecidable from the statement.

Closed in v0.1.92 by policy, not by refusing more: a reducing aggregate over a
masked column is now masked with that column's *own* mask on its way out, so a
singleton sum is the bucketed floor — byte-identical to what the column itself
returns — whatever a predicate or `GROUP BY` collapses the set to. A sum over a
released column is still exact, and `count(*)/count(col)` are unaffected.
Boolean reductions join the masked family because each is the identity over a
singleton set. The classification is finer than the two-valued
`Releasable`/`Unknown` split: `Safety::Summary` for the value-reducing family,
`Releasable` for the tally family (a count never degrades into its input).

The effort fell on the *shape*, not the numbers: one new verdict, propagated
through one shared source-policy path. An aggregate is maskable only when it
reduces one bare column over explicitly schema-qualified named FROM ranges;
unqualified ranges need `search_path`, and transformed or multi-source inputs
cannot safely inherit one input's mask. Optional lineage may prove full release
but a blocked lineage source no longer selects a mask. This removed the
`grouping_may_reference`/`aggregate_argument_is_grouped` walkers (no reducing
aggregate is directly released now; attributable one-column summaries are
masked and the rest stay opaque, so the grouped/ungrouped distinction they drew
lost its point) — a net deletion.

Two consequences the reader should weigh:

* **The singleton *grouping* guard is now partly redundant.** It still refuses
  `sum(salary) GROUP BY <unique key>` even when an explicitly qualified summary
  could be served masked. It stays in place until removing it is separately
  validated against the DB-backed adversarial suite; refusing a query that
  would serve masked is over-restriction in a safe direction. Recorded here so
  the redundancy is a decision, not a drift to "simplify later".
* **An expression *over* a summary is refused, not masked.** `sum(a)/sum(b)`,
  `round(sum(a), 1)`, `sum(a) OVER (...)`. The bare aggregate is special-cased
  as maskable; a wrapper is treated like any other opaque expression over a
  masked column and refused under `opaque = "reject"`. That matches the module's
  long-standing rule that an expression over a masked column cannot be masked
  after the fact, and keeps the special case one branch wide instead of a
  tri-state through every classify arm.
* **An expression *inside* a summary is also refused when it touches a masked
  source.** `sum(a * 1000)` cannot inherit `a`'s bucket after amplification, and
  `regr_avgx(y, x)` cannot inherit `y`'s mask when it returns an average of `x`.
  Only one bare argument column is eligible for summary masking.

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
| **the gate's own `cargo test`** | `out=$(a; b); status=$?` reports only `b`, so every integration test was unenforced |
| `test-inference.sh` | detected the error oracle by grepping for "division by zero", so withholding error text read as the channel closing |
| the generated campaign | counted 20,034 ordinary SQL errors as proxy refusals, because the withheld text began `pgmask:` |
| `scrubbing_only_removes` | asserted a length bound as a stand-in for "does not rewrite content" |
| `test-mutants.sh` again | `--shard k/n` is 0-indexed; the loop ran `1..20`, so a tenth was never tested and the accounting still said "814 of 814" |
| `test-sqlsmith.sh` | reported zero leaks four separate ways while measuring nothing, then reported a leak that was not one |
| sqlsmith itself | generates DML; a 500-query corpus emptied the fixture, and every earlier figure was measuring a table being destroyed |
| `git tag` | fourteen releases the changelog called shipped had no tag at all |
| the gate's skip counter | printed "(0 need Postgres)" on every run ever made, with 41 skipping — libtest captures `eprintln!` from a passing test, so the line it counted never existed |
| seven `pg_isready` loops | answered YES against the socket-only init server, then fell through on timeout, so "ready" and "timed out" were the same outcome |
| four `sleep 4`s | called a proxy that was still resolving its catalog "did not come up" |
| `classify --check` again | told operators unruled columns were "not an exposure" **without reading the setting that decides it** — while holding the parsed catalog |
| two of the three tests written for that fix | one matched a phrase that wraps across a newline, one asserted an exit code that was non-zero in both postures; both passed whatever the code did |
| `multi_statement_simple_query_stays_masked` | named for masking, asserted only canary-absence — which a fail-closed *refusal* satisfies as readily, so it could not tell "each set masked by its own plan" from "whole query rejected" |
| the local gate itself | one machine, one timing profile: a concurrent-DDL race that fails reliably on a Linux runner never reproduced here in seventy releases |

Every one produced a confident answer about something it was not measuring.
Several were built specifically to prevent that.

## What the current suites do and do not bound

`./scripts/test-all.sh` — 21 suites. Green means no regression in what is
covered. It does not bound what is uncovered.

`./scripts/soak.sh [hours]` — sustained fresh corpora, both engines, both
protocols. **Round zero unmasks the catalog and must leak**, or the run aborts;
a round producing no result aborts too.

`./target/release/reach` — fails when a release rule has no generated statement
behind it. This is the check that bounds the campaigns: two of today's
disclosures were in rules nothing could reach.

`./scripts/test-mutants.sh` — mechanical mutation, 827 mutants. The first
complete run scored 620 caught, 157 missed, 10 timed out, 40 unviable. Triage of
it produced six real test gaps, every one "logic that exists and was never
verified" rather than anything reading would surface.

`./scripts/test-sqlsmith.sh [queries]` and `./scripts/soak-sqlsmith.sh [hours]`
— the same idea against a grammar nobody here wrote. Read the section above on
the six ways this harness reported something untrue before trusting a number
from it.

`./scripts/test-mutations.py` — 26 hand-picked guards, each verified to fail
when broken.

**Under `allow`, DDL that moves a masked column briefly releases it.** An
`ALTER TABLE ... DROP COLUMN x; ADD COLUMN x` gives `x` a new attnum while the
table OID is unchanged. The proxy's snapshot, resolved to the old attnum, then
misses on the new one — and under `allow` a miss releases. So a column the
operator *explicitly* masked is served in the clear until the catalog
re-resolves.

Measured on a live proxy: before the fix below, every query leaked for the full
refresh interval (30s by default), because a known table OID nudged no refresh.
The fix nudges a refresh on any lookup miss, not only unknown relations, which
bounds the window to `catalog_refresh_min_seconds` (5s by default). The residual
is inherent to an asynchronous catalog under `allow`: a genuinely new column is
released there by design, and a reshaped one is indistinguishable from a new one
until the refresh lands. **Default-deny is not affected** — a miss masks, with
no dependence on refresh timing, and
`a_reshaped_masked_column_stays_masked_under_default_deny` pins that. Mask
anything sensitive rather than leaving it to `allow`.

## Point it at a read-only upstream

The single highest-value deployment choice, and the one that makes most of the
write-side hardening moot: **give pgmask a connection that cannot write in the
first place** — a physical read replica / hot standby, or a role with `SELECT`
and nothing else.

pgmask refuses writes by inspecting SQL: it parses each statement and rejects
DML, DDL, `DO`, `CALL`, and untrusted functions. That is a real layer, but it
is a parser-based denylist, and `is_write_statement` returns false for anything
`pg_query` cannot parse — a statement Postgres executes but the bundled parser
does not recognise would be forwarded to a read-write backend.

A read-only upstream removes that whole question. Verified against a live
backend: connect through pgmask as a `SELECT`-only role and the escape that
defeats a per-session read-only GUC —
`SET default_transaction_read_only = off; INSERT ...` — is refused by privilege
alone, 0 rows written, before pgmask's parser or any backend flag is consulted.
A hot standby is stronger still: writes are physically impossible, per session,
with no GUC to flip.

What this does **not** buy is anything on the masking side. A read-only role
still reads unmasked rows, so the proxy still has to mask them, and every
disclosure in this document is about that path. A read-only upstream closes the
write surface completely and the read surface not at all.

So the order of guards, strongest first:

1. **A read-only role or replica upstream.** The database refuses writes. Use
   this if you can; it is free and unbypassable.
2. **pgmask's write refusal.** Defense in depth for when (1) is not available —
   e.g. pgmask in front of a writable primary with a privileged role, which is
   exactly the risky case. Parser-based, so treat it as a strong filter rather
   than a guarantee.
3. Setting `default_transaction_read_only` on the backend session is **not** a
   guarantee: it is a per-session GUC the client can turn off
   (`SET default_transaction_read_only = off`, `BEGIN READ WRITE`). It is worth
   having as a default, but it does not replace (1).

## If you read one thing before deploying this

One more, added 2026-08-12 and worth its own line: the counter that was
supposed to make the skipping visible had never once counted a skip. It was
added *because* 41 tests had previously reported PASS while asserting nothing,
and it reported `0 need Postgres` from the day it was written. The defect was
found only because a CI assertion failed and the first reading of that failure
was wrong.

**Only Claude has reviewed this security analysis.** Ten disclosures over three
days across fourteen channels, *all* of them found by reading rather than by any
test, is the argument for a second reader — not the test counts above.

The rate is the thing to weigh, and it has not plateaued. The draft of this
paragraph one day earlier said the rate "had not clearly plateaued"; number 10
arrived the next morning, in the one module the preceding sweep never opened,
and the sweep missed it because it asked what values could reach the client and
never asked what carried them. Each sweep has found the previous sweep's frame.

A human adversary should start with `crates/proxy/src/analysis/`, and should
distrust the comments. They are unusually detailed and load-bearing, which makes
them read as specifications; two of today's disclosures were sitting behind a
comment that asserted the case could not happen.

## Still unverified

- Nine findings from an internal audit, mostly documentation overstating code.
- **Mutation coverage, first complete run (2026-08-11): `attempted 827 of 827`.**
  620 caught, 157 missed, 10 timed out, 40 unviable — a 79.8% kill rate on
  viable mutants. The preceding run covered 19 shards of 20 and killed 71.9%;
  the difference is the six test gaps triage found and closed, measured rather
  than claimed. Survivors by file: `session.rs` 55, `catalog.rs` 45, `mask.rs`
  27, `protocol.rs` 14, `analysis.rs` 12, `lineage.rs` 4 — `protocol.rs` fell
  from 54 as the channel-binding, result-format and startup-frame tests landed.
  The remaining survivors are the categories documented in place: config
  accessors and defaults, logging conditions, depth caps, and guards no engine
  can reach. Caveat: sqlsmith harness work was running alongside, so the 10
  timeouts may be contention rather than genuinely slow mutants.
- *(historical)* **The number previously quoted here was wrong.** Two runs died part-way — the second on a full disk — and both printed
  their four outcome counts and nothing else, so "45 survivors" was carried
  here as a finding when 200 of 493 mutants had never been attempted. The
  script now compares planned against attempted and refuses to report a partial
  run. A complete run has not finished yet; until it does, treat mutation
  coverage of the release rules as unmeasured rather than as 45 known gaps.
- `protocol.rs` and `mask.rs` joined the mutated file list on 2026-08-11, taking
  the campaign from 494 mutants to 827 — two thirds of the release-relevant
  surface had never been mutated. See the note above on why that would not have
  found any of the ten disclosures.
- Two `classify` defects fixed 2026-08-11 that were proposals rather than
  disclosures, but would have become disclosures in a deployed catalog:
  `postal_code` was proposed as `partial`, which keeps the *last* characters —
  with the emitted `keep = 4` a five-digit ZIP masked to `*1234`, four of five,
  narrowing a state to a neighbourhood. And `mask_fits` covered `partial` and
  `redact` but fell through to "fits anything" for `inner`, `outer`, `range`,
  `hash` and `scrub`, so `--check` accepted five of the seven text-only masks on
  an integer column and the proxy refused the result set at runtime.
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
- **`SET ROLE` has no effect on masking, and that is now documented rather than
  merely true.** `[[role]]` maps a startup principal to pgmask role names,
  resolved once at authentication; the database's own role state is unrelated.
  Safe direction, but an operator who grants a Postgres role expecting the mask
  to follow is configuring nothing. Pinned by a test with a live control.
- **Lineage inverts the safety property and is off by default** (`lineage =
  "refuse"`). It is the one place where failing to notice a source column
  releases rather than refuses, which is why it carries seven documented
  guards: existence, empty sources, field-count, parse, opaque views, a
  name-based backstop, and an allowlist of output shapes whose sources the
  resolver is trusted to have finished. Read on 2026-08-11 and nothing found;
  that is a reading, not a proof, and it is the module to hand a second
  reviewer first if you intend to turn it on. On 2026-08-25 the backstop was
  found not to name unicode-escaped identifiers (`u&"email"` / `u&"e\006dail"`),
  so a released column concatenated with a masked one inside a scalar subquery
  came through in the clear under the shipped GUI catalog. Closed by decoding
  those encodings in the lexer (and failing the scan on `UESCAPE`) and by
  refusing to `Release` any output expression that contains a `SubLink` (or
  any node kind not on the allowlist), even when the subquery names only
  released columns. The first shape-allowlist still stopped at the outermost
  target list, so wrapping the concat as `SELECT x FROM (SELECT city ||
  (SELECT a FROM t AS t(id, a, …)) AS x)` made the described field a
  `ColumnRef` and the FROM alias list hid `email` from the backstop; that
  wrap leaked through the GUI catalog until 0.1.96, which follows subquery
  and CTE aliases to the inner expression. A FROM colnames list without a
  SubLink is a second hole of the same family: `SELECT upper(city) FROM
  customers AS t(id, city, …)` binds `city` to email, Guard 6 never sees
  `email`, and a closed ColumnRef on the RangeVar used to Release. Closed
  in 0.1.96 by treating that list as incomplete. Not numbered in the tables
  above, because both are reachable only with lineage inverted from the
  default.
- On 2026-08-25 a protocol disclosure, independent of lineage: after
  `PortalSuspended`, DataRows for a *different* named portal were masked
  with the suspended portal's plan. An all-passthrough first page
  (`ship_city, id`) plus a same-arity classified second page (`email, name`)
  took `Vetted::unmasked_row` and released the values. The comment that
  Postgres refuses a second portal while one is suspended was wrong.
  Closed in 0.1.97 by binding `streaming_plan` to the portal that is
  actually producing rows. A sibling, found on the same day: resume of
  that named portal after Sync, without `BEGIN`, fails `34000` (portal
  gone with the implicit transaction) but left the passthrough plan as a
  zombie `pending_executes` owner; the next same-arity classified portal
  took `unmasked_row` again. Closed in the same release by discarding the
  result owner when an ErrorResponse completes an Execute. The resume-only
  epoch stamp missed every later-epoch error that is not A's own Execute:
  simple Query `1/0` (H10a), Describe of the dead portal (H5b, 34000 on
  Describe not resume), Parse `SELECT !!!`, Bind of a missing statement.
  After `PortalSuspended`, `ReadyForQuery Idle` now discards the owner
  (named portals of an implicit transaction are gone); InTxn does not.
  `discard_failed_epoch` also drops older-epoch Executes while
  `suspended`. Not numbered in the tables above.
  A further sibling, still without PortalSuspended: two full Executes
  (`max_rows=0`) that reuse one portal name. Bind of the second statement
  overwrote `portal_plans` before the first DataRows were judged;
  `execute` treated the second Execute as a resume, so `streaming_plan`
  applied the new all-passthrough plan to the classified first result.
  `unmasked_row` released the values. Unnamed portal `""` and binary Bind
  leaked the same way. Closed in the same release by snapshotting the
  plan onto the owner at Execute and treating a Bind in between as a new
  result set. Pass-then-class over-masked (fail-closed); two different
  portal names, and a Sync between the two PBEs, were already safe.
  A further sibling, found after that release: `Close` of the portal
  (or of the classified statement) dropped the bind-generation counter,
  so a later Bind of the same name started at `1` again and collided
  with the unfinished Execute. In one Sync `pending.plan` is still
  `None`; `streaming_plan` treated the rebound all-passthrough plan as
  current and `unmasked_row` released the values. Closed in 0.1.98 by
  keeping the name's generation for the life of in-flight Executes.
  Without Close the 0.1.97 refuse still holds.
- The 2026-08-11 diagnostic fixes are now exercised on **both engines**, for the
  channels each engine actually has. Measured on CockroachDB v25.4.14: `DO $$ …
  RAISE EXCEPTION $$` carries a value exactly as on Postgres, and so do
  `USING DETAIL` and `USING HINT`. Two do *not* exist there — a `CONTEXT`
  traceback is never emitted (a DO-block error reports only `LOCATION`) and
  `EXECUTE` inside PL/pgSQL is unimplemented, so the dynamic-SQL route into a
  traceback has nowhere to start; and `scram_iterations` is not a CockroachDB
  setting. Those are not checked there, because checking a channel the engine
  cannot open is how a suite comes to report 43 of 43 while testing nothing.
- Production validation has never run: the intended host is a read-write primary
  and no read-only path has been supplied.

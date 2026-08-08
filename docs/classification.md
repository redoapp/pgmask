# Phase 1: writing down what is sensitive

Everything else in pgmask enforces a list. This is about producing the list.

The enforcement machinery was always the easy half. Provenance comes free from
the wire protocol, default-deny covers anything not on the list, and the
adversarial suite says nothing crosses the boundary unvetted. But the list
itself was written by hand, and **nothing said what it had forgotten.**

`crates/classify` walks a schema, proposes a classification for every column,
and prints two things: a catalog draft on stdout, and on stderr a coverage
report naming what a human still has to decide.

```bash
DSN=postgres://… cargo run -p classify --release -- --schema public --sample 200
```

## It never prints a value

`--sample` reads data, because a column called `notes` full of email addresses
is exactly what name matching misses. Sampled values are counted against a
shape check and dropped inside `sample_column`; only the verdict and the match
rate are ever printed. A discovery tool that echoed the data it found would be
self-defeating.

## Four verdicts, and only one of them is silence

| verdict | meaning |
|---|---|
| **confirmed** | the name matched *and* sampled values agreed |
| **likely** | the name is conclusive on its own |
| **NEEDS A HUMAN** | something is suspicious that a name cannot settle |
| **ordinary** | nothing suggests sensitivity |

The report always ends by saying how many columns landed in `ordinary` and that
**nothing has verified they are harmless.** Default-deny masks them regardless,
so a miss costs utility rather than safety — but "the tool didn't flag it" is
not the same claim as "somebody looked."

## Measured against the two schemas we have

Both runs were graded against a catalog that had already been written by hand,
which is the only way to find out what hand-writing misses.

### demo — 19 columns

The tool found two classifications the hand-written catalog had:

- **`customers.name`** — the confident `person_name` rule requires
  `first_name` / `full_name` / `customer_name`. A bare `name` matches none of
  them, and the first version of the tool called it *ordinary*.
- **`customers.account_uuid`** — no rule for opaque identifiers existed at all.

The wrong fix is adding `^name$` to the confident list: on a company table that
is a company name, and a tool that over-classifies gets overridden wholesale.
The fix was a third tier — patterns that *raise* a question a name cannot answer
become **NeedsReview with a proposal attached**, never silence.

It also flagged `customers.internal_note`, which the hand-written catalog omits
on purpose to demonstrate default-deny. Both behaviours are correct: the note is
masked either way, and now somebody is asked about it.

### TPC-DS — 429 columns across 25 tables

The hand-written catalog for TPC-DS had **12** columns. The tool proposes
**58**, and the gap is not padding:

| what the hand-written catalog missed | columns |
|---|---|
| `cd_gender`, `cd_marital_status`, `cd_education_status`, `cd_credit_rating` | special-category data, missed entirely |
| `s_*`, `cc_*`, `w_*`, `web_*` street/city/county/state/zip | only `customer_address` was covered; four more address blocks were not |
| `s_manager`, `cc_manager`, `web_manager`, `*_market_manager` | employee names |
| `hd_income_band_sk`, `ib_income_band_sk` | income |
| `wp_url`, `cp_description` | free text and a URL |

Reviewing 429 columns by hand is the kind of task that gets done once, badly,
and never revisited. That is the whole argument for the tool.

## What the same run found wrong with the tool

Running it against a 429-column schema exposed four defects in its own rules,
all of which are now pinned by tests in `crates/classify/src/main.rs`:

1. **An unanchored pattern.** `ip_addr` matched `cs_sh|ip_addr|_sk` and proposed
   an IP-prefix mask for an integer surrogate key. Anchored to `(^|_)ip_addr`.
2. **A mask that cannot decode the type.** `c_birth_year` is an `integer`; the
   `birth` rule proposed `date-year`, which would have failed at runtime. Masks
   are now checked against the declared type (`mask_fits`), and a mismatch
   becomes a review item rather than a broken catalog entry.
3. **A column too narrow to hold the value.** `p_channel_email` is `char(1)`, a
   Y/N flag for whether a promotion ran over the email channel. The name
   matches, and with no data loaded there was nothing to sample — but a
   one-character column cannot hold an address. Checking the declared width
   (`width_permits`) settles it without reading a single row.
4. **The two outputs disagreeing.** The width check demoted `p_channel_email` to
   *ordinary* in the report while still emitting a catalog entry for it. A
   proposal with no confidence must carry no type, or neither output can be
   trusted.

A fifth was noise rather than error. A blanket `_name$` pattern flagged
`d_day_name` ("Monday"), `d_quarter_name`, `i_product_name`, `p_promo_name` and
`w_warehouse_name` — 17 review items that are obviously not people. It was
withdrawn in favour of a targeted list. **A tool that cries wolf gets ignored
wholesale, which is a worse outcome than one that asks fewer questions.**

## The generated catalog actually runs

The loop closes: `examples/demo/verify.sh` generates a catalog with `classify`,
starts pgmask against it, and asserts the masking works. No hand-editing.

The generated catalog turns out **stricter** than the hand-written one — it
proposes redacting `city`, where the hand-written catalog says `mask = "none"`
as a deliberate decision. That is the right direction for a default: the tool
proposes caution and a human relaxes it, rather than the tool proposing
exposure and a human having to notice.

## What this does not do

- **It cannot read intent.** `s_manager` is a person's name and `w_warehouse_name`
  is not, and only the schema's owner knows that. The tool asks; it does not
  decide.
- **It does not watch for drift.** A column added tomorrow is masked by
  default-deny and will not appear in any report until somebody re-runs this.
  Wiring it into CI — fail the build when a new column is neither classified nor
  explicitly marked ordinary — is the remaining piece of Phase 1, and it is the
  part that keeps the catalog honest after the first pass.
- **Name matching is a prior, not evidence.** `--sample` is what turns a guess
  into a verdict, and it only exists for the four types with a cheap shape check
  (email, phone, IP, and free text by absence). Everything else is a name.

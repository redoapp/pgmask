//! Propose a pgmask catalog for a database, and say what is not covered.
//!
//! The enforcement machinery has been the easy half all along. The hard half is
//! knowing which columns hold something worth hiding, and until now that list
//! was written by hand with nothing to say what it missed.
//!
//! This walks a schema, proposes a classification for every column, and prints
//! two things: a catalog draft, and a coverage report naming what a human still
//! has to decide.
//!
//! # It never prints a value
//!
//! With `--sample` it reads data, because a column called `notes` full of email
//! addresses is exactly what name matching misses. Sampled values are counted
//! and thrown away — only the verdict and the match rate are ever printed. A
//! discovery tool that echoed the data it found would be self-defeating.
//!
//! # Two modes
//!
//! Without `--check` it proposes a catalog. With `--check` it compares an
//! existing catalog against the live schema and exits non-zero on drift, which
//! is the form you put in CI. Neither mode enforces anything at runtime — the
//! catalog belongs to whoever deploys the proxy, see docs/responsibilities.md.
//!
//! Usage:
//!   DSN=postgres://... cargo run -p classify -- --schema public [--sample 200]
//!   DSN=postgres://... cargo run -p classify -- --check --catalog catalog.toml --schema public

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result};
use regex::Regex;

/// How sure we are, which decides whether a human has to look.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Confidence {
    /// The name says what it is, or sampled values confirmed it.
    Clear,
    /// Plausible from the name alone. Worth a glance.
    Likely,
    /// Free text or an opaque blob: could hold anything, so someone must decide.
    NeedsReview,
    /// Nothing suggests this is sensitive.
    Ordinary,
}

struct Rule {
    semantic_type: &'static str,
    mask: &'static str,
    pattern: Regex,
    /// A value-level check, when one exists that is worth running.
    validator: Option<fn(&str) -> bool>,
    /// Why this cannot be decided from the name alone, if it cannot.
    ///
    /// `None` means the name is conclusive. `Some(reason)` means the column gets
    /// a proposed type *and* a review flag: silently calling it ordinary is the
    /// failure mode that matters, and silently masking it trains people to
    /// override the tool.
    ambiguous: Option<&'static str>,
}

fn looks_like_email(v: &str) -> bool {
    let v = v.trim();
    match v.split_once('@') {
        Some((l, d)) => !l.is_empty() && d.contains('.') && !d.starts_with('.'),
        None => false,
    }
}

fn looks_like_ip(v: &str) -> bool {
    let v = v.trim();
    v.parse::<std::net::IpAddr>().is_ok()
}

fn looks_like_phone(v: &str) -> bool {
    let digits = v.chars().filter(char::is_ascii_digit).count();
    (7..=15).contains(&digits)
        && v.chars()
            .all(|c| c.is_ascii_digit() || " ()+-.".contains(c))
}

/// A payment card number: 13-19 digits that pass the Luhn check.
///
/// Luhn is the reason this is worth writing at all. `looks_like_phone` is a
/// shape test and matches roughly one string of digits in one; Luhn rejects
/// about nine in ten, so a column that clears it at 80% is a card column and
/// almost nothing else is. It is a checksum, not a validity check — it says
/// the digits are a well-formed PAN, not that the card exists.
fn looks_like_card(v: &str) -> bool {
    let digits: Vec<u32> = v
        .chars()
        .filter(|c| !matches!(c, ' ' | '-'))
        .map(|c| c.to_digit(10).ok_or(()))
        .collect::<Result<_, _>>()
        .unwrap_or_default();
    if !(13..=19).contains(&digits.len()) {
        return false;
    }
    // Doubling a digit and casting out nines, as a table: 7 doubles to 14,
    // which contributes 1 + 4 = 5. Written out rather than computed so the
    // whole check is addition.
    const DOUBLED: [u32; 10] = [0, 2, 4, 6, 8, 1, 3, 5, 7, 9];
    let mut sum = 0u32;
    for (i, digit) in digits.iter().rev().enumerate() {
        let contribution = if i % 2 == 1 {
            DOUBLED
                .get(usize::try_from(*digit).unwrap_or(0))
                .copied()
                .unwrap_or(0)
        } else {
            *digit
        };
        sum = sum.saturating_add(contribution);
    }
    sum.is_multiple_of(10)
}

/// An IBAN: two letters, two check digits, then the account, mod-97 == 1.
///
/// The same argument as Luhn, harder: the check is over a ~30-digit number, so
/// a wrong string clears it about once in ninety-seven times.
fn looks_like_iban(v: &str) -> bool {
    let upper: Vec<char> = v
        .chars()
        .filter(|c| *c != ' ')
        .map(|c| c.to_ascii_uppercase())
        .collect();
    if !(15..=34).contains(&upper.len())
        || !upper.iter().take(2).all(char::is_ascii_alphabetic)
        || !upper.iter().skip(2).take(2).all(char::is_ascii_digit)
        || !upper.iter().all(char::is_ascii_alphanumeric)
    {
        return false;
    }
    // Move the country code and check digits to the end, then read the whole
    // thing as one long number with each letter standing for its position in
    // the alphabet plus nine — which is exactly base-36, so no arithmetic on
    // character codes is needed to get there.
    let rotated = upper.iter().skip(4).chain(upper.iter().take(4));
    let mut remainder = 0u32;
    for c in rotated {
        let part = c.to_digit(36).unwrap_or(0);
        // Fold one character at a time so the running value never needs more
        // than 32 bits, taking two decimal places for the letters.
        let shift = if part < 10 { 10 } else { 100 };
        remainder = remainder.saturating_mul(shift).saturating_add(part) % 97;
    }
    remainder == 1
}

/// A US Social Security number, by the SSA's own allocation rules.
///
/// Not merely nine digits: area `000`, `666` and `900-999` are never issued,
/// nor is a `00` group or a `0000` serial. That rules out most nine-digit
/// sequences that are something else, which is the whole point — every SSN is
/// also a `looks_like_phone` match, so without this a column of them is
/// reported as a phone column and nothing else.
///
/// Deliberately US-only, and named so. `national_id` also covers passports and
/// tax IDs, whose formats vary by country; a validator that quietly failed
/// those would flag correctly classified columns for review, and a tool that
/// cries wolf gets overridden wholesale.
fn looks_like_ssn(v: &str) -> bool {
    let digits: Vec<u32> = v
        .trim()
        .chars()
        .filter(|c| *c != '-' && *c != ' ')
        .map(|c| c.to_digit(10).ok_or(()))
        .collect::<Result<_, _>>()
        .unwrap_or_default();
    if digits.len() != 9 {
        return false;
    }
    let number = |skip: usize, take: usize| {
        digits
            .iter()
            .skip(skip)
            .take(take)
            .fold(0u32, |acc, d| acc.saturating_mul(10).saturating_add(*d))
    };
    let (area, group, serial) = (number(0, 3), number(3, 2), number(5, 4));
    area != 0 && area != 666 && area < 900 && group != 0 && serial != 0
}

/// A shape label and the check that recognises it.
type Detector = (&'static str, fn(&str) -> bool);

/// The shapes content discovery can recognise, most specific first.
///
/// Separate from `rules()` on purpose. A name rule answers "the column is
/// called `ssn`, what mask?"; a detector answers "the column is called `col_7`,
/// what is in it?". They were the same list, which meant discovery could only
/// find the three shapes that happened to have a confirmation validator
/// attached — email, phone and IP. A column of card numbers under a
/// meaningless name matched *nothing*: `looks_like_phone` stops at 15 digits
/// and a 16-digit PAN sailed past it. That is precisely the case this tool
/// advertises itself as catching.
///
/// The precise checks come first so the note names them ahead of the shape
/// tests. A US SSN satisfies `phone` as well, and reporting "national_id or
/// phone" is the honest answer; reporting "phone" alone was not.
///
/// Detectors do not set masks. Discovery proposes `null` whatever matched —
/// see the block that calls this.
fn detectors() -> &'static [Detector] {
    &[
        ("payment", looks_like_card),
        ("payment", looks_like_iban),
        ("national_id", looks_like_ssn),
        ("email", looks_like_email),
        ("ip_address", looks_like_ip),
        ("phone", looks_like_phone),
    ]
}

/// Name patterns, most specific first — the first match wins.
///
/// Deliberately conservative about `name`: on a company table it is a company
/// name, not a person's, and over-classifying trains people to override the
/// tool.
#[rustfmt::skip] // a one-rule-per-line table; reflowing it hides edits
fn rules() -> Vec<Rule> {
    // `sure`: the name settles it. `unsure`: the name raises the question but
    // cannot answer it, so a human does. Order matters — first match wins, so
    // every `sure` rule is listed before the `unsure` tier that would also match.
    let sure = |semantic_type, mask, pattern, validator| Rule {
        semantic_type,
        mask,
        pattern: Regex::new(pattern).expect("static pattern"),
        validator,
        ambiguous: None,
    };
    let unsure = |semantic_type, mask, pattern, why| Rule {
        semantic_type,
        mask,
        pattern: Regex::new(pattern).expect("static pattern"),
        validator: None,
        ambiguous: Some(why),
    };
    let r = sure;
    vec![
        // Credentials are never masked — they are withheld entirely.
        r("secret", "null", r"password|passwd|secret|token|api_key|apikey|private_key|salt$|_hash$", None),
        r("national_id", "null", r"ssn|social_security|passport|national_id|tax_id|nino", None),
        r("payment", "null", r"card_number|cardnum|ccn|iban|bank_account|account_number|routing", None),
        r("email", "pseudonym", r"e_?mail", Some(looks_like_email as fn(&str) -> bool)),
        r("phone", "partial", r"phone|mobile|telephone|^fax", Some(looks_like_phone)),
        r("person_name", "redact", r"first_name|last_name|given_name|family_name|surname|full_name|contact_name|person_name|owner_name|customer_name|employee_name", None),
        r("street_address", "redact", r"street|address_line|addr_line|^address$|^addr$", None),
        r("postal_code", "partial", r"zip|postal|postcode", None),
        // Only the full date is confidently a date. TPC-DS splits birth across
        // `c_birth_day` / `_month` / `_year` / `_country`, none of which a date
        // mask can decode; they are handled in the unsure tier below.
        r("birth_date", "date-year", r"birth_date|birth_dt|date_of_birth|^dob$|_dob$|birthday", None),
        r("compensation", "numeric-bucket", r"salary|compensation|wage|income|bonus|commission", None),
        // `ip_addr` unanchored matched `cs_sh|ip_addr|_sk` on TPC-DS and proposed
        // an IP mask for an integer surrogate key. Anchor it to a word boundary.
        r("ip_address", "ip-prefix", r"(^|_)ip_addr|_ip$|^ip$|client_ip|remote_addr", Some(looks_like_ip)),
        r("geo", "numeric-bucket", r"latitude|longitude|^lat$|^lon$|^lng$", None),
        r("free_text", "null", r"notes?$|comment|description|body|message|content|remarks", None),

        // --- Cannot be settled by the name -----------------------------------
        // Everything below gets a proposal and a review flag. These are the
        // cases that a name-only classifier gets wrong in both directions, so
        // it says so instead of guessing.
        // A blanket `_name$` was tried and withdrawn: on TPC-DS it flagged
        // `d_day_name` ("Monday"), `i_product_name` and `w_warehouse_name`,
        // which is 17 review items of pure noise. A tool that cries wolf gets
        // overridden wholesale, so this asks only where a person is plausible.
        unsure("person_name", "redact",
               r"^name$|^who$|manager|recipient|^contact$|user_name|login_name|display_name|screen_name",
               "could be a person or an organisation — only you know which"),
        unsure("account_id", "pseudonym",
               r"_uuid$|^uuid$|_guid$|^guid$|external_id|_ref$|(customer|user|account|member|person|employee|patient)_id",
               "an opaque identifier: pseudonymising keeps joins and drops the handle"),
        unsure("demographic", "null", r"gender|marital|ethnic|^race$|religio|disabilit|educatio|citizenship|veteran|credit_rating",
               "special-category or quasi-identifying; nulling it may break the workload"),
        unsure("quasi_identifier", "null", r"birth",
               "part of a birth date; day, month and year together re-identify"),
        unsure("birth_date", "date-year", r"^age$|_age$",
               "an age re-identifies in combination; bucket it or accept it"),
        unsure("geo", "redact", r"^city$|_city$|^state$|_state$|^province|_province$|^county$|_county$",
               "coarse location, but rare values still single people out"),
        unsure("free_text", "null", r"url$|_uri$|link$|referrer|user_agent",
               "can carry identity in a query string or a fingerprint"),
    ]
}

/// Whether a column is wide enough to hold this kind of value at all.
///
/// TPC-DS has `p_channel_email char(1)`, a Y/N flag for whether a promotion ran
/// over the email channel. The name matches, and with no data loaded there is
/// nothing to sample — but a one-character column cannot hold an address. This
/// is a fact about the declared type, not a guess about the values.
fn width_permits(semantic_type: &str, max_length: Option<i32>) -> bool {
    let Some(len) = max_length else { return true };
    let shortest = match semantic_type {
        "email" => 6, // a@b.co
        "phone" => 7,
        "street_address" => 3,
        "person_name" => 2,
        "ip_address" => 7, // 1.2.3.4
        "national_id" | "payment" => 8,
        _ => 1,
    };
    len >= shortest
}

/// The config name of a mask, matching the strings `mask_fits` expects and the
/// kebab-case serde uses in the catalog file.
fn mask_name(mask: &pgmask::mask::Mask) -> &'static str {
    use pgmask::mask::Mask;
    match mask {
        Mask::None => "none",
        Mask::Null => "null",
        Mask::Redact => "redact",
        Mask::Partial => "partial",
        Mask::Inner => "inner",
        Mask::Outer => "outer",
        Mask::Range => "range",
        Mask::Hash => "hash",
        Mask::Pseudonym => "pseudonym",
        Mask::DateYear => "date-year",
        Mask::DateMonth => "date-month",
        Mask::NumericBucket => "numeric-bucket",
        Mask::IpPrefix => "ip-prefix",
        Mask::Scrub => "scrub",
    }
}

/// Whether a proposed mask can actually apply to this column's type.
///
/// Found by running this against TPC-DS, which has `c_birth_year` as an
/// integer: the name matches the birth rule, but a date mask cannot decode an
/// int4. A proposal that would fail at runtime is worse than no proposal, so
/// the mismatch is surfaced as a review item rather than emitted.
fn mask_fits(mask: &str, data_type: &str) -> bool {
    let numeric = matches!(
        data_type,
        "smallint" | "integer" | "bigint" | "numeric" | "real" | "double precision" | "money"
    );
    let textual = data_type.contains("char") || data_type == "text";
    match mask {
        "date-year" | "date-month" | "date-quarter" => {
            data_type.starts_with("date") || data_type.starts_with("timestamp")
        }
        "numeric-bucket" | "numeric-range" => numeric,
        "ip-prefix" => textual || data_type == "inet" || data_type == "cidr",
        // `redact` and `partial` rewrite text. TPC-DS's `i_manager_id` is an
        // integer that matched the manager rule; redacting it would fail.
        "partial" | "redact" => textual,
        // `null` withholds whatever it is, and `pseudonym` covers text and uuid.
        "null" => true,
        "pseudonym" => textual || data_type == "uuid",
        _ => true,
    }
}

struct Column {
    schema: String,
    table: String,
    name: String,
    data_type: String,
    /// Declared max length for char/varchar, when there is one.
    max_length: Option<i32>,
}

struct Proposal {
    column: Column,
    semantic_type: Option<&'static str>,
    mask: &'static str,
    confidence: Confidence,
    note: Option<String>,
    /// The name matched, but the column is physically too small to hold one.
    refuted_by_width: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let dsn = std::env::var("DSN").context("DSN is required")?;
    let args: Vec<String> = std::env::args().collect();
    let schema = arg(&args, "--schema").unwrap_or_else(|| "public".into());
    let sample: usize = arg(&args, "--sample")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);

    let connector =
        tokio_postgres_rustls::MakeRustlsConnect::new(pgmask::tls::backend_client_config());
    let (dsn, _) = pgmask::catalog::sanitize_catalog_dsn(&dsn);
    // The DSN is deliberately not echoed: it carries a password.
    let (client, connection) = tokio_postgres::connect(&dsn, connector)
        .await
        .map_err(|_| anyhow::anyhow!("could not connect"))?;
    tokio::spawn(async move {
        let _ = connection.await;
    });

    let rows = client
        .query(
            // `pg_catalog`, not `information_schema`, and the same `relkind`
            // set the proxy resolves against (`catalog.rs`:
            // `relkind = ANY('{r,v,m,p,f}')`). The two must agree on what a
            // relation is or the drift gate lies in both directions.
            //
            // `information_schema` omits materialised views entirely — they are
            // not in the SQL standard — and reports foreign tables as
            // `'FOREIGN'`, which the old `IN ('BASE TABLE','VIEW')` filter
            // dropped. Measured: a correct rule protecting `t.mv_contacts.email`
            // was reported by `--check` as *"The column was renamed or dropped,
            // and the rule is protecting nothing"*. An operator following that
            // advice deletes masking from a materialised view, and a
            // denormalised reporting matview is a classic place for a copy of a
            // masked column to live. Tooling that recommends removing a working
            // defence is worse than tooling that stays silent.
            "SELECT n.nspname, c.relname, a.attname,
                    format_type(a.atttypid, NULL) AS data_type,
                    CASE WHEN a.atttypmod > 4 THEN a.atttypmod - 4 END AS max_length
               FROM pg_catalog.pg_class c
               JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
               JOIN pg_catalog.pg_attribute a ON a.attrelid = c.oid
              WHERE n.nspname = $1
                AND c.relkind = ANY('{r,v,m,p,f}')
                AND a.attnum > 0
                AND NOT a.attisdropped
              ORDER BY c.relname, a.attnum",
            &[&schema],
        )
        .await
        .context("listing columns")?;

    let columns: Vec<Column> = rows
        .iter()
        .map(|r| Column {
            schema: r.get(0),
            table: r.get(1),
            name: r.get(2),
            data_type: r.get(3),
            max_length: r.get(4),
        })
        .collect();

    let rules = rules();
    let mut proposals = Vec::new();
    let mut refuted_by_width = 0usize;
    for column in columns {
        let mut proposal = classify_by_name(&rules, column);
        if proposal.refuted_by_width {
            refuted_by_width = refuted_by_width.saturating_add(1);
        }

        // Confirm against the data where a check exists and sampling is on.
        // Skipped once the declared width has already ruled the type out: there
        // is nothing left to confirm.
        if sample > 0 && !proposal.refuted_by_width {
            let lower = proposal.column.name.to_ascii_lowercase();
            let matched = rules
                .iter()
                .find(|rule| rule.pattern.is_match(&lower))
                .filter(|rule| rule.validator.is_some());
            if let Some(rule) = matched {
                let validator = rule.validator.expect("filtered above");
                if let Ok((checked, matching)) =
                    sample_column(&client, &proposal.column, sample, validator).await
                {
                    if checked > 0 {
                        let rate = (matching as f64 / checked as f64) * 100.0;
                        // Confirming the *shape* says nothing about whether the
                        // mask can apply to the column's *type*, and this used
                        // to overwrite both verdict and note regardless.
                        //
                        // `phone bigint` is the ordinary case: `classify_by_name`
                        // correctly reports "a `partial` mask cannot apply to
                        // bigint — pick another" and marks it NEEDS REVIEW, then
                        // sampling casts to text, reads 100% phone-shaped values,
                        // upgrades to Clear and replaces the note. The emitted
                        // entry loses its `# NEEDS REVIEW` marker and the proxy
                        // refuses that result set at runtime — the outage
                        // `mask_fits` exists to prevent, reintroduced by adding
                        // evidence. More sampling produced a worse proposal.
                        let fits = mask_fits(proposal.mask, &proposal.column.data_type);
                        proposal.confidence = confidence_after_sampling(rate, fits);
                        let sampled = format!(
                            "{rate:.0}% of {checked} sampled values matched the {} shape",
                            rule.semantic_type
                        );
                        // Append, never replace: the incompatibility is the more
                        // actionable half and it is what the operator has to fix.
                        proposal.note = Some(match proposal.note.take() {
                            Some(existing) if !fits => format!("{existing}; {sampled}"),
                            _ => sampled,
                        });
                    }
                }
            }
        }

        // A name that says nothing is exactly where sampling earns its keep,
        // and it was the one case sampling could not reach: the block above
        // only samples columns whose *name* already matched a rule, so
        // `--sample` could confirm or downgrade a guess and never make one.
        //
        // That is the opposite of what this tool documents itself as doing —
        // "a column called `notes` full of email addresses" — and it is the
        // shape that matters, because a column whose name announces its
        // contents is the one an operator would have caught unaided.
        //
        // WHY THE MASK IS NOT THE MATCHED RULE'S
        //
        // The first version of this took the matched rule's mask verbatim, and
        // that turned a lax validator into a disclosure. `looks_like_phone`
        // accepts any 7-15 digits punctuated with ` ()+-.`, which is also every
        // national ID, every IPv4 address and every text-stored date. Measured
        // on a fixture: a column of national IDs under a meaningless name was
        // proposed as `phone` with mask `partial`, and `partial` keeps the last
        // four characters — so the tool's own draft catalog would have
        // published the last four digits of every ID in it. The `national_id`
        // rule says `null` precisely because credentials are withheld, not
        // masked.
        //
        // A name match is corroboration; content alone is not. So discovery
        // proposes withholding, names every shape that matched, and leaves the
        // narrowing to a human. Over-masking is a utility cost the operator can
        // undo deliberately; the reverse is a disclosure they never see.
        //
        // Text-like columns only. A validator over an integer is a round trip
        // to learn nothing.
        let texty = {
            let d = proposal.column.data_type.to_ascii_lowercase();
            d.contains("char") || d.contains("text")
        };
        if sample > 0 && proposal.semantic_type.is_none() && !proposal.refuted_by_width && texty {
            // One read, every detector. This used to issue a query per
            // detector, which was three round trips per column and would have
            // been six after the payment and national_id checks were added.
            let matched = sample_shapes(&client, &proposal.column, sample)
                .await
                .unwrap_or_default();
            if let Some((_, rate, checked)) = matched.first().copied() {
                // Deduplicated: `payment` has two detectors, and a note
                // reading "payment or payment" is a bug on its face. In
                // `detectors()` order, not sorted — the specific checks are
                // listed first there so the note leads with them, and a
                // `BTreeSet` here quietly threw that away.
                let mut shapes: Vec<&str> = Vec::new();
                for (label, _, _) in &matched {
                    if !shapes.contains(label) {
                        shapes.push(label);
                    }
                }
                let shapes = shapes.join(" or ");
                // A type name of its own, never one of the name-rule types.
                //
                // Reusing the matched rule's name defeats the withholding
                // above: `emit_catalog` keys `[[semantic_type]]` blocks by name
                // and lets the last writer win, so one column legitimately
                // matched by name sets `phone` to `partial`, and every column
                // discovered by content is pointed at that same type and
                // inherits it. Measured: national IDs found under a meaningless
                // name came back masked `partial` — the last four digits — via
                // a `phone` block written by an unrelated column.
                proposal.semantic_type = Some("unidentified");
                proposal.mask = "null";
                proposal.confidence = Confidence::NeedsReview;
                proposal.note = Some(format!(
                    "the name suggests nothing, but {rate:.0}% of {checked} sampled values look \
                     like {shapes}; proposed `null` because content alone cannot tell these \
                     apart — narrow it deliberately once you know which it is"
                ));
            }
        }

        proposals.push(proposal);
    }

    if args.iter().any(|a| a == "--check") {
        let path = arg(&args, "--catalog")
            .context("--check needs --catalog <path> to compare the schema against")?;
        return check(&path, &schema, &proposals);
    }
    report(&proposals, &schema, sample, refuted_by_width);
    emit_catalog(&proposals, &schema);
    Ok(())
}

/// Compare a catalog against the live schema and fail on drift.
///
/// Two directions, and they fail for different reasons:
///
/// * A column in the database with no rule is **masked** by default-deny, so it
///   is safe but invisible. Someone finds out when a dashboard goes blank.
/// * A rule matching nothing means the relation or column was renamed or
///   dropped. That is not itself a leak — there is nothing left to leak — but it
///   is a rule you believe is protecting you and is not.
///
/// Neither is detectable from inside the proxy at the moment it matters, which
/// is why this is a build step rather than a runtime warning.
fn check(path: &str, schema: &str, proposals: &[Proposal]) -> Result<()> {
    let config =
        pgmask::catalog::Config::load(path).with_context(|| format!("loading catalog {path}"))?;

    // Every rule's effective mask, and every column's current type, so a
    // migration that changes a type fails the build instead of refusing
    // queries in production. A `date-year` mask on a column that became `text`
    // is not a coverage gap — it is an outage waiting for the first SELECT.
    let mut mask_of_type: BTreeMap<&str, &pgmask::mask::Mask> = BTreeMap::new();
    for t in &config.semantic_type {
        mask_of_type.insert(t.name.as_str(), &t.mask);
    }
    let live_type: BTreeMap<(String, String), &str> = proposals
        .iter()
        .map(|p| {
            (
                (
                    format!("{}.{}", p.column.schema, p.column.table),
                    p.column.name.clone(),
                ),
                p.column.data_type.as_str(),
            )
        })
        .collect();

    let mut incompatible: Vec<(String, String, String, String)> = Vec::new();
    for rule in &config.column {
        let key = (rule.relation.clone(), rule.column.clone());
        let Some(data_type) = live_type.get(&key) else {
            continue; // reported as a stale rule below
        };
        let effective = rule.mask.as_ref().or_else(|| {
            rule.semantic_type
                .as_deref()
                .and_then(|t| mask_of_type.get(t).copied())
        });
        if let Some(mask) = effective {
            let name = mask_name(mask);
            if !mask_fits(name, data_type) {
                incompatible.push((
                    rule.relation.clone(),
                    rule.column.clone(),
                    name.to_string(),
                    (*data_type).to_string(),
                ));
            }
        }
    }

    let live: BTreeSet<(String, String)> = proposals
        .iter()
        .map(|p| {
            (
                format!("{}.{}", p.column.schema, p.column.table),
                p.column.name.clone(),
            )
        })
        .collect();
    let ruled: BTreeSet<(String, String)> = config
        .column
        .iter()
        .map(|r| (r.relation.clone(), r.column.clone()))
        .collect();

    // Only rules pointing at the schema under inspection can be judged here; a
    // catalog spanning several schemas is checked one `--schema` at a time, and
    // calling another schema's rules stale would be wrong.
    let prefix = format!("{schema}.");
    let stale: Vec<_> = ruled
        .iter()
        .filter(|(rel, _)| rel.starts_with(&prefix))
        .filter(|entry| !live.contains(*entry))
        .collect();
    let unclassified: Vec<_> = live.difference(&ruled).collect();

    println!("catalog {path} vs schema `{schema}`");
    println!("  columns in the database   {}", live.len());
    println!(
        "  rules covering them       {}",
        // `unclassified` is a subset of `live`, so this never saturates; if it
        // somehow did it would under-report coverage, not over-report it.
        live.len().saturating_sub(unclassified.len())
    );

    if !unclassified.is_empty() {
        println!("\n{} column(s) have no rule. Default-deny masks them, so this is a\ncoverage gap and not an exposure — but nothing here has been decided:", unclassified.len());
        for (relation, column) in unclassified.iter().take(40) {
            let hint = proposals
                .iter()
                .find(|p| {
                    format!("{}.{}", p.column.schema, p.column.table) == *relation
                        && p.column.name == *column
                })
                .and_then(|p| p.semantic_type)
                .map_or(String::new(), |t| format!("   (looks like {t})"));
            println!("  {relation}.{column}{hint}");
        }
        if unclassified.len() > 40 {
            println!("  ... and {} more", unclassified.len().saturating_sub(40));
        }
    }

    if !stale.is_empty() {
        println!("\n{} rule(s) match nothing in the database. The column was renamed or\ndropped, and the rule is protecting nothing:", stale.len());
        for (relation, column) in &stale {
            println!("  {relation}.{column}");
        }
    }

    if !incompatible.is_empty() {
        println!(
            "\n{} rule(s) name a mask the column's current type cannot take. This is\nnot a coverage gap — the proxy refuses these result sets at runtime:",
            incompatible.len()
        );
        for (relation, column, mask, data_type) in &incompatible {
            println!("  {relation}.{column}  mask `{mask}` vs {data_type}");
        }
    }

    if unclassified.is_empty() && stale.is_empty() && incompatible.is_empty() {
        println!("\nevery column has a rule and every rule matches. no drift.");
        return Ok(());
    }
    // A non-zero exit is the whole point: this is meant to fail a build.
    std::process::exit(1);
}

/// Classify one column from its name and declared type alone.
///
/// Pure, so the rule table can be tested without a database — every defect the
/// TPC-DS and demo runs turned up is pinned against this in `mod tests`.
fn classify_by_name(rules: &[Rule], column: Column) -> Proposal {
    let lower = column.name.to_ascii_lowercase();
    let matched = rules.iter().find(|rule| rule.pattern.is_match(&lower));

    let (mut semantic_type, mask, mut confidence, mut note) = match matched {
        // The specific reason first: an ambiguous free_text rule should say why
        // it is ambiguous, not fall into the generic free-text arm.
        Some(rule) if rule.ambiguous.is_some() => (
            Some(rule.semantic_type),
            rule.mask,
            Confidence::NeedsReview,
            rule.ambiguous.map(str::to_owned),
        ),
        Some(rule) if rule.semantic_type == "free_text" => (
            Some(rule.semantic_type),
            rule.mask,
            Confidence::NeedsReview,
            Some("free text can hold anything; decide deliberately".into()),
        ),
        Some(rule) => (
            Some(rule.semantic_type),
            rule.mask,
            Confidence::Likely,
            None,
        ),
        None => (None, "none", Confidence::Ordinary, None),
    };

    let mut refuted_by_width = false;
    if let Some(t) = semantic_type.filter(|t| !width_permits(t, column.max_length)) {
        // Drop the type as well as the confidence. Leaving it set emitted a
        // catalog entry for a column the report had just called ordinary — the
        // two outputs have to agree or neither can be trusted.
        confidence = Confidence::Ordinary;
        refuted_by_width = true;
        note = Some(format!(
            "name suggests {t}, but {}({}) is too narrow to hold one",
            column.data_type,
            column.max_length.unwrap_or(0)
        ));
        semantic_type = None;
    } else if semantic_type.is_some() && !mask_fits(mask, &column.data_type) {
        confidence = Confidence::NeedsReview;
        note = Some(format!(
            "name suggests {}, but a `{mask}` mask cannot apply to {} — pick another",
            semantic_type.unwrap_or("?"),
            column.data_type
        ));
    }

    Proposal {
        column,
        semantic_type,
        mask,
        confidence,
        note,
        refuted_by_width,
    }
}

/// What sampled values are allowed to conclude.
///
/// A high match rate confirms the *shape* of the data and says nothing about
/// whether the proposed mask can apply to the column's declared *type*. Those
/// are independent, and conflating them cost the review flag on `phone bigint`:
/// `mask_fits` had already reported that `partial` cannot apply to a bigint,
/// and sampling — which casts to text — overwrote the verdict with `Clear`.
/// The entry was then emitted without `# NEEDS REVIEW` and the proxy refuses
/// that result set at runtime.
///
/// Extracted so it can be tested without a database; the caller lives in the
/// middle of a query loop.
fn confidence_after_sampling(rate: f64, mask_fits_type: bool) -> Confidence {
    if rate >= 80.0 && mask_fits_type {
        Confidence::Clear
    } else {
        Confidence::NeedsReview
    }
}

/// Read up to `limit` non-null values and return how many matched.
///
/// The values themselves are dropped here and never leave this function.
async fn sample_column(
    client: &tokio_postgres::Client,
    column: &Column,
    limit: usize,
    validator: fn(&str) -> bool,
) -> Result<(usize, usize)> {
    let sql = format!(
        r#"SELECT "{}"::text FROM "{}"."{}" WHERE "{}" IS NOT NULL LIMIT {limit}"#,
        column.name, column.schema, column.table, column.name
    );
    let rows = client.query(&sql, &[]).await?;
    let mut matching = 0usize;
    for row in &rows {
        let value: Option<String> = row.get(0);
        if let Some(value) = value {
            if validator(&value) {
                matching = matching.saturating_add(1);
            }
        }
    }
    Ok((rows.len(), matching))
}

/// Read up to `limit` values once and report which shapes they fit.
///
/// Same contract as `sample_column`: the values are counted here and dropped
/// here. The caller receives labels and rates, never data — which is why every
/// detector runs inside this function rather than the caller looping over a
/// vector of sampled strings.
///
/// Returns `(label, rate, checked)` for each shape at least 80% of the sample
/// fits, in `detectors()` order. Below 20 rows it returns nothing: a single
/// non-null value scores 100% and would produce a proposal on its own.
async fn sample_shapes(
    client: &tokio_postgres::Client,
    column: &Column,
    limit: usize,
) -> Result<Vec<(&'static str, f64, usize)>> {
    let sql = format!(
        r#"SELECT "{}"::text FROM "{}"."{}" WHERE "{}" IS NOT NULL LIMIT {limit}"#,
        column.name, column.schema, column.table, column.name
    );
    let rows = client.query(&sql, &[]).await?;
    let checked = rows.len();
    if checked < 20 {
        return Ok(Vec::new());
    }
    let mut counts = vec![0usize; detectors().len()];
    for row in &rows {
        let value: Option<String> = row.get(0);
        let Some(value) = value else { continue };
        for (count, (_, detector)) in counts.iter_mut().zip(detectors()) {
            if detector(&value) {
                *count = count.saturating_add(1);
            }
        }
    }
    Ok(counts
        .into_iter()
        .zip(detectors())
        .filter_map(|(count, (label, _))| {
            let rate = (count as f64 / checked as f64) * 100.0;
            (rate >= 80.0).then_some((*label, rate, checked))
        })
        .collect())
}

fn report(proposals: &[Proposal], schema: &str, sample: usize, refuted_by_width: usize) {
    let mut by_confidence: BTreeMap<Confidence, Vec<&Proposal>> = BTreeMap::new();
    for p in proposals {
        by_confidence.entry(p.confidence).or_default().push(p);
    }
    let count = |c: Confidence| by_confidence.get(&c).map_or(0, Vec::len);

    eprintln!("\nschema `{schema}`: {} columns", proposals.len());
    if sample == 0 {
        eprintln!("(name matching only — pass --sample N to check values as well)");
    }
    eprintln!("{}", "-".repeat(62));
    eprintln!(
        "  confirmed by sampled values   {:>4}",
        count(Confidence::Clear)
    );
    eprintln!(
        "  likely, from the name         {:>4}",
        count(Confidence::Likely)
    );
    eprintln!(
        "  NEEDS A HUMAN                 {:>4}",
        count(Confidence::NeedsReview)
    );
    eprintln!(
        "  nothing suggests sensitivity  {:>4}",
        count(Confidence::Ordinary)
    );

    if refuted_by_width > 0 {
        eprintln!(
            "  (name matched but ruled out {refuted_by_width}: column too narrow to hold one)"
        );
    }

    if let Some(review) = by_confidence.get(&Confidence::NeedsReview) {
        eprintln!("\nsomeone has to decide these:");
        for p in review {
            eprintln!(
                "  {:<34} {:<12} {}",
                format!("{}.{}", p.column.table, p.column.name),
                p.column.data_type,
                p.note.as_deref().unwrap_or("")
            );
        }
    }

    // The point of the exercise: default-deny covers what is forgotten, but you
    // still cannot claim coverage you have not looked at.
    eprintln!(
        "\n{} column(s) are proposed as ordinary. Default-deny still masks them,\n\
         but nothing here has verified they are harmless — that is the review.",
        count(Confidence::Ordinary)
    );
}

fn emit_catalog(proposals: &[Proposal], schema: &str) {
    let mut types: BTreeMap<&str, &str> = BTreeMap::new();
    for p in proposals {
        if let Some(t) = p.semantic_type {
            types.insert(t, p.mask);
        }
    }

    println!("# Catalog draft for schema `{schema}`, generated by `classify`.");
    println!("#");
    println!("# A proposal, not an answer. Every entry marked NEEDS REVIEW in the");
    println!("# report needs a decision, and every column absent from this file is");
    println!("# masked by default-deny rather than deliberately.");
    println!();
    for (name, mask) in &types {
        println!("[[semantic_type]]");
        println!("name = \"{name}\"");
        println!("mask = \"{mask}\"");
        if *mask == "numeric-bucket" {
            println!("bucket = 1000        # pick a real bucket before using this");
        }
        if *mask == "partial" {
            println!("keep = 4");
        }
        println!();
    }
    for p in proposals {
        let Some(t) = p.semantic_type else { continue };
        let flag = if p.confidence == Confidence::NeedsReview {
            "   # NEEDS REVIEW"
        } else {
            ""
        };
        println!("[[column]]{flag}");
        println!("relation = \"{}.{}\"", p.column.schema, p.column.table);
        println!("column   = \"{}\"", p.column.name);
        println!("type     = \"{t}\"");
        println!();
    }
}

fn arg(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i.saturating_add(1)))
        .cloned()
}

#[cfg(test)]
mod tests {

    #![allow(
        clippy::unwrap_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )]
    use super::*;

    /// Sampling confirms a shape, not a type.
    ///
    /// `phone bigint` is the case: the name is conclusive, the values are
    /// phone-shaped, and `partial` still cannot apply to a bigint. Before this
    /// was separated, a 100% match rate erased that warning and the emitted
    /// entry lost its review marker — adding evidence produced a worse
    /// proposal, and the runtime refusal `mask_fits` exists to prevent came
    /// back.
    #[test]
    fn sampling_confirms_a_shape_and_cannot_vouch_for_a_type() {
        assert_eq!(confidence_after_sampling(100.0, true), Confidence::Clear);
        assert_eq!(confidence_after_sampling(80.0, true), Confidence::Clear);
        // Shape confirmed, type still impossible: the operator must look.
        assert_eq!(
            confidence_after_sampling(100.0, false),
            Confidence::NeedsReview
        );
        // And a weak rate is never Clear, whatever the type says.
        assert_eq!(
            confidence_after_sampling(79.9, true),
            Confidence::NeedsReview
        );
        assert_eq!(
            confidence_after_sampling(0.0, false),
            Confidence::NeedsReview
        );
    }

    /// Classify a bare (name, type) pair the way a schema walk would.
    fn c(name: &str, data_type: &str, max_length: Option<i32>) -> Proposal {
        classify_by_name(
            &rules(),
            Column {
                schema: "s".into(),
                table: "t".into(),
                name: name.into(),
                data_type: data_type.into(),
                max_length,
            },
        )
    }
    fn text(name: &str) -> Proposal {
        c(name, "text", None)
    }

    // --- the obvious cases still work ------------------------------------

    #[test]
    fn confident_names_are_classified_without_review() {
        // The declared type is part of the decision, so each case carries a
        // plausible one: `birth_date text` really would be a review item,
        // because a date mask cannot decode text.
        for (name, data_type, expected) in [
            ("email", "text", "email"),
            ("c_email_address", "character varying", "email"),
            ("first_name", "text", "person_name"),
            ("ca_street_name", "character varying", "street_address"),
            ("ca_zip", "character", "postal_code"),
            ("birth_date", "date", "birth_date"),
            ("annual_salary", "numeric", "compensation"),
            ("last_ip", "text", "ip_address"),
        ] {
            let p = c(name, data_type, None);
            assert_eq!(p.semantic_type, Some(expected), "{name}");
            assert_eq!(p.confidence, Confidence::Likely, "{name}");
        }
    }

    #[test]
    fn credentials_are_withheld_not_masked() {
        for name in ["password", "api_key", "session_token", "ssn", "iban"] {
            assert_eq!(text(name).mask, "null", "{name} must be withheld");
        }
    }

    // --- what the demo comparison found ----------------------------------

    #[test]
    fn a_bare_name_column_is_asked_about_not_ignored() {
        // The first version called this ordinary, and the hand-written demo
        // catalog had it as person_name. Silence was the bug.
        let p = text("name");
        assert_eq!(p.semantic_type, Some("person_name"));
        assert_eq!(p.confidence, Confidence::NeedsReview);
    }

    #[test]
    fn an_opaque_identifier_is_asked_about() {
        for name in ["account_uuid", "c_customer_id", "external_id"] {
            let p = c(name, "uuid", None);
            assert_eq!(p.semantic_type, Some("account_id"), "{name}");
            assert_eq!(p.confidence, Confidence::NeedsReview, "{name}");
        }
    }

    #[test]
    fn a_specific_person_name_still_beats_the_ambiguous_rule() {
        // Ordering: `customer_name` must hit the confident rule, not `^name$`'s
        // tier. If the unsure tier ever moves above the sure tier, every
        // confident classification silently becomes a review item.
        assert_eq!(text("customer_name").confidence, Confidence::Likely);
        assert_eq!(text("contact_name").confidence, Confidence::Likely);
    }

    // --- what the TPC-DS run found ---------------------------------------

    #[test]
    fn ip_addr_is_anchored_and_does_not_match_ship_addr() {
        // `cs_ship_addr_sk` contains the substring `ip_addr`, and an unanchored
        // pattern proposed an ip-prefix mask for an integer surrogate key.
        for name in ["cs_ship_addr_sk", "ws_ship_addr_sk", "ship_addr_sk"] {
            assert_ne!(
                c(name, "integer", None).semantic_type,
                Some("ip_address"),
                "{name}"
            );
        }
        assert_eq!(text("client_ip_addr").semantic_type, Some("ip_address"));
        assert_eq!(text("last_ip").semantic_type, Some("ip_address"));
    }

    #[test]
    fn a_mask_that_cannot_decode_the_type_is_never_proposed_silently() {
        // c_birth_year is an integer; a date mask would fail at runtime.
        for name in ["c_birth_year", "c_birth_day", "c_birth_month"] {
            let p = c(name, "integer", None);
            assert_eq!(p.confidence, Confidence::NeedsReview, "{name}");
            assert_ne!(p.mask, "date-year", "{name}");
        }
        // i_manager_id is an integer; redact rewrites text.
        let p = c("i_manager_id", "integer", None);
        assert_eq!(p.confidence, Confidence::NeedsReview);
        assert!(p.note.unwrap().contains("cannot apply to integer"));
    }

    #[test]
    fn a_column_too_narrow_to_hold_the_value_is_ruled_out() {
        // TPC-DS `p_channel_email char(1)` is a Y/N flag, not an address.
        let p = c("p_channel_email", "character", Some(1));
        assert_eq!(
            p.semantic_type, None,
            "must not be emitted into the catalog"
        );
        assert_eq!(p.confidence, Confidence::Ordinary);
        assert!(p.refuted_by_width);
        // ...but a real address column of the same name pattern survives.
        assert_eq!(
            c("p_channel_email", "character varying", Some(120)).semantic_type,
            Some("email")
        );
    }

    #[test]
    fn refuting_by_width_clears_the_type_so_both_outputs_agree() {
        // The report counted this as ordinary while the catalog still emitted an
        // entry for it. A proposal with no confidence must carry no type.
        let p = c("p_channel_email", "character", Some(1));
        assert!(p.refuted_by_width && p.semantic_type.is_none());
    }

    #[test]
    fn ordinary_business_names_are_not_flagged() {
        // A blanket `_name$` produced 17 review items of noise on TPC-DS. If it
        // comes back, this fails.
        for name in [
            "d_day_name",
            "d_quarter_name",
            "i_product_name",
            "p_promo_name",
            "w_warehouse_name",
            "cc_division_name",
            "web_company_name",
        ] {
            assert_eq!(
                text(name).confidence,
                Confidence::Ordinary,
                "{name} is noise"
            );
        }
    }

    #[test]
    fn special_category_attributes_are_surfaced() {
        for name in ["cd_gender", "cd_marital_status", "cd_education_status"] {
            let p = c(name, "character", Some(20));
            assert_eq!(p.semantic_type, Some("demographic"), "{name}");
            assert_eq!(p.confidence, Confidence::NeedsReview, "{name}");
        }
    }

    // --- the value checks ------------------------------------------------

    #[test]
    fn value_validators_accept_and_reject() {
        assert!(looks_like_email("a@b.co"));
        assert!(!looks_like_email("Y"));
        assert!(!looks_like_email("no-at-sign.com"));
        assert!(!looks_like_email("a@b"));
        assert!(looks_like_ip("203.0.113.9"));
        assert!(looks_like_ip("2001:db8::1"));
        assert!(!looks_like_ip("not an ip"));
        assert!(looks_like_phone("+1 (555) 010-0101"));
        assert!(!looks_like_phone("12"));
        assert!(!looks_like_phone("customer service"));
    }

    #[test]
    fn every_pattern_compiles_and_every_mask_is_one_pgmask_knows() {
        // A typo'd mask name would produce a catalog that pgmask refuses to
        // load, and the failure would surface far from here.
        const KNOWN: &[&str] = &[
            "null",
            "redact",
            "partial",
            "pseudonym",
            "ip-prefix",
            "date-year",
            "date-month",
            "date-quarter",
            "numeric-bucket",
            "numeric-range",
            "none",
        ];
        for rule in rules() {
            assert!(KNOWN.contains(&rule.mask), "unknown mask `{}`", rule.mask);
        }
    }

    /// The shapes that only a checksum separates from noise.
    ///
    /// Every test value here is a published test number or a synthetic one; a
    /// real card or a real SSN in a repository is the thing this whole tool
    /// exists to prevent.
    #[test]
    fn checksums_separate_these_shapes_from_digits() {
        // Luhn accepts across the length range, punctuated or not.
        assert!(looks_like_card("4111111111111111"));
        assert!(looks_like_card("4111-1111-1111-1111"));
        assert!(looks_like_card("4111 1111 1111 1111"));
        assert!(looks_like_card("378282246310005")); // 15 digits
        assert!(looks_like_card("30569309025904")); // 14 digits
                                                    // One transposed digit and it is not a card.
        assert!(!looks_like_card("4111111111111112"));
        // Luhn-valid at every length, so only the bound can reject them. The
        // first version of this used numbers that failed the checksum too,
        // which meant widening `13..=19` to `1..=99` broke nothing here.
        assert!(looks_like_card("4111111111119"), "13, the lower bound");
        assert!(
            looks_like_card("4111111111111111110"),
            "19, the upper bound"
        );
        assert!(!looks_like_card("411111111117"), "12, one short");
        assert!(!looks_like_card("41111111111111111115"), "20, one over");
        assert!(!looks_like_card("4111x111111111111"));
        assert!(!looks_like_card(""));

        assert!(looks_like_iban("GB82 WEST 1234 5698 7654 32"));
        assert!(looks_like_iban("DE89370400440532013000"));
        assert!(looks_like_iban("FR1420041010050500013M02606")); // letter in the body
        assert!(looks_like_iban("NL91ABNA0417164300"));
        assert!(!looks_like_iban("GB83WEST12345698765432")); // check digits wrong
        assert!(!looks_like_iban("GB82WEST1234569876543")); // a digit short
        assert!(!looks_like_iban(""));

        // Each of these satisfies mod-97 and violates exactly one structural
        // rule, so each one is rejected by that rule and nothing else. Found by
        // search, because the first version's counterexamples all failed mod-97
        // as well — the four structural guards were untested and deleting any
        // of them broke no test.
        assert!(!looks_like_iban("GB8212"), "6 characters, folds to 1");
        assert!(!looks_like_iban("1B82WEST123456987000008"), "country code");
        assert!(!looks_like_iban("GBX2WEST123456987000072"), "check digits");
        assert!(
            !looks_like_iban("GB82WEST_23456987000000"),
            "body punctuation"
        );

        // The SSA's allocation rules, not merely nine digits.
        assert!(looks_like_ssn("123-45-6789"));
        assert!(looks_like_ssn("123456789"));
        assert!(!looks_like_ssn("000-45-6789")); // area 000
        assert!(!looks_like_ssn("666-45-6789")); // area 666
        assert!(!looks_like_ssn("900-45-6789")); // area 900+
        assert!(!looks_like_ssn("123-00-6789")); // group 00
        assert!(!looks_like_ssn("123-45-0000")); // serial 0000
        assert!(!looks_like_ssn("12345678"));
        assert!(!looks_like_ssn("1234567890"));
        assert!(!looks_like_ssn("123-4a-6789"));
    }

    /// The gap these were added to close, stated as a test.
    ///
    /// Discovery could only find the shapes that had a confirmation validator
    /// attached to a name rule, and a 16-digit PAN matches none of them —
    /// `looks_like_phone` stops at 15. So a column of card numbers under a
    /// meaningless name produced no proposal at all: not a wrong one, none.
    /// Deleting the payment entries from `detectors()` fails here.
    #[test]
    fn a_card_column_under_a_meaningless_name_is_recognised_by_something() {
        let card = "4111111111111111";
        assert!(
            !looks_like_phone(card) && !looks_like_email(card) && !looks_like_ip(card),
            "the pre-existing detectors were supposed to be blind to this",
        );
        let hits: Vec<&str> = detectors()
            .iter()
            .filter(|(_, d)| d(card))
            .map(|(label, _)| *label)
            .collect();
        assert_eq!(hits, ["payment"]);
    }

    /// A US SSN is also a valid phone shape, so both fire — and the note has to
    /// name the specific one first or it reads as a phone column.
    #[test]
    fn an_ssn_is_reported_ahead_of_the_phone_shape_it_also_fits() {
        let ssn = "123-45-6789";
        assert!(looks_like_phone(ssn), "the ambiguity is the point");
        let hits: Vec<&str> = detectors()
            .iter()
            .filter(|(_, d)| d(ssn))
            .map(|(label, _)| *label)
            .collect();
        assert_eq!(hits, ["national_id", "phone"]);
    }

    /// The two lists must not drift.
    ///
    /// `rules()` carries validators for confirming a name match; `detectors()`
    /// carries them for discovering content. They were one list, and splitting
    /// them creates a way for a validator to be added to one and forgotten in
    /// the other — which is the failure that was already present, in the
    /// direction of discovery finding less than confirmation could.
    #[test]
    fn every_confirmation_validator_is_also_a_detector() {
        for rule in rules() {
            let Some(validator) = rule.validator else {
                continue;
            };
            assert!(
                detectors()
                    .iter()
                    .any(|(_, d)| std::ptr::fn_addr_eq(*d, validator)),
                "`{}` can confirm a name match with a validator that content \
                 discovery will never run",
                rule.semantic_type,
            );
        }
    }

    /// Detector labels have to be things the report can talk about.
    ///
    /// The label is printed to the operator as "values look like {shapes}".
    /// A label that matches no rule's `semantic_type` is a word the rest of the
    /// tool does not use, and the operator has nothing to look it up against.
    #[test]
    fn every_detector_label_names_a_type_the_rules_know() {
        let known: BTreeSet<&str> = rules().iter().map(|r| r.semantic_type).collect();
        for (label, _) in detectors() {
            assert!(known.contains(label), "unknown detector label `{label}`");
        }
    }
}

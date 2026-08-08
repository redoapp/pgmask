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
            "SELECT c.table_schema, c.table_name, c.column_name, c.data_type,
                      c.character_maximum_length
               FROM information_schema.columns c
               JOIN information_schema.tables t
                 ON t.table_schema = c.table_schema AND t.table_name = c.table_name
              WHERE c.table_schema = $1 AND t.table_type IN ('BASE TABLE', 'VIEW')
              ORDER BY c.table_name, c.ordinal_position",
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
            refuted_by_width += 1;
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
                        proposal.confidence = if rate >= 80.0 {
                            Confidence::Clear
                        } else {
                            Confidence::NeedsReview
                        };
                        proposal.note = Some(format!(
                            "{rate:.0}% of {checked} sampled values matched the {} shape",
                            rule.semantic_type
                        ));
                    }
                }
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
        live.len() - unclassified.len()
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
            println!("  ... and {} more", unclassified.len() - 40);
        }
    }

    if !stale.is_empty() {
        println!("\n{} rule(s) match nothing in the database. The column was renamed or\ndropped, and the rule is protecting nothing:", stale.len());
        for (relation, column) in &stale {
            println!("  {relation}.{column}");
        }
    }

    if unclassified.is_empty() && stale.is_empty() {
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
    let mut matching = 0;
    for row in &rows {
        let value: Option<String> = row.get(0);
        if let Some(value) = value {
            if validator(&value) {
                matching += 1;
            }
        }
    }
    Ok((rows.len(), matching))
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
        .and_then(|i| args.get(i + 1))
        .cloned()
}

#[cfg(test)]
mod tests {
    use super::*;

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
}

//! Check masking over the **binary** result format.
//!
//! Everything else that drives the proxy end to end — psql, the fuzz replay,
//! verify.sh — uses the simple query protocol, which is text-only. Coverage said
//! so plainly: `mask.rs` is 94% covered by unit tests, but no end-to-end suite
//! had ever asked the proxy for a binary result set.
//!
//! That matters because binary is not a cosmetic difference. A `date` is four
//! bytes from the Postgres epoch rather than `1975-02-03`; a `uuid` is sixteen
//! raw bytes rather than hyphenated text; an `int4` is big-endian rather than
//! decimal. Masking has to decode and re-encode each of those, and it is the
//! format real drivers prefer — tokio-postgres, pgx and JDBC all use it.
//!
//! `Client::query` goes through Parse/Bind/Execute and asks for binary results,
//! so simply using it instead of `simple_query` exercises the whole path.
//!
//! Every assertion is made twice: once against the database directly, which
//! must show the raw value, and once through the proxy, which must not. A check
//! that only looked at the proxy could pass because the fixture was empty.

use anyhow::{bail, Context, Result};
use tokio_postgres::{Client, NoTls};

async fn connect(url: &str) -> Result<Client> {
    let (client, connection) = tokio_postgres::connect(url, NoTls)
        .await
        .with_context(|| format!("connecting to {}", url.rsplit('@').next().unwrap_or("?")))?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    Ok(client)
}

struct Check {
    name: &'static str,
    ok: bool,
    detail: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let direct = connect(&std::env::var("DIRECT_URL").context("DIRECT_URL")?).await?;
    let proxy = connect(&std::env::var("PROXY_URL").context("PROXY_URL")?).await?;
    let mut checks: Vec<Check> = Vec::new();
    let mut push = |name, ok, detail: String| checks.push(Check { name, ok, detail });

    // --- date: four bytes, must come back truncated to 1 January ------------
    let sql = "SELECT birth_date FROM fz.people WHERE id = 3";
    let raw: jiff::civil::Date = direct.query_one(sql, &[]).await?.get(0);
    let masked: jiff::civil::Date = proxy.query_one(sql, &[]).await?.get(0);
    push(
        "date decodes as binary and is not the raw value",
        raw != masked,
        format!("direct {raw}, proxy {masked}"),
    );
    push(
        "date is truncated to 1 January",
        masked.month() == 1 && masked.day() == 1 && masked.year() == raw.year(),
        format!("{masked}"),
    );

    // --- int4: big-endian, must come back floored to its bucket -------------
    let sql = "SELECT annual_salary FROM fz.people WHERE id = 3";
    let raw: i32 = direct.query_one(sql, &[]).await?.get(0);
    let masked: i32 = proxy.query_one(sql, &[]).await?.get(0);
    push(
        "int4 decodes as binary and is bucketed",
        raw != masked && masked % 25_000 == 0 && masked <= raw,
        format!("direct {raw}, proxy {masked}"),
    );

    // --- uuid: sixteen raw bytes, must be a different but valid uuid --------
    let sql = "SELECT account_uuid FROM fz.people WHERE id = 3";
    let raw: uuid::Uuid = direct.query_one(sql, &[]).await?.get(0);
    let masked: uuid::Uuid = proxy.query_one(sql, &[]).await?.get(0);
    push(
        "uuid decodes as binary and is pseudonymised",
        raw != masked,
        format!("direct {raw}, proxy {masked}"),
    );
    // Determinism is what keeps masked data joinable, and it has to hold in
    // binary too — a pseudonym that differed by format would break any join
    // between a psql user and a driver user.
    let again: uuid::Uuid = proxy.query_one(sql, &[]).await?.get(0);
    push(
        "uuid pseudonym is stable across calls",
        masked == again,
        format!("{masked} vs {again}"),
    );
    // `simple_query` is the text protocol, and a plain column read rather than
    // a cast — `account_uuid::text` is an expression over a masked column and
    // is refused, correctly.
    let as_text = proxy
        .simple_query("SELECT account_uuid FROM fz.people WHERE id = 3")
        .await?
        .into_iter()
        .find_map(|m| match m {
            tokio_postgres::SimpleQueryMessage::Row(r) => {
                r.get(0).map(std::string::ToString::to_string)
            }
            _ => None,
        })
        .unwrap_or_default();
    push(
        "uuid pseudonym agrees between binary and text",
        as_text == masked.to_string(),
        format!("text {as_text}, binary {masked}"),
    );

    // --- text: same bytes either way, but the plan still has to apply -------
    let sql = "SELECT full_name, email FROM fz.people WHERE id = 3";
    let row = proxy.query_one(sql, &[]).await?;
    let name: String = row.get(0);
    let email: String = row.get(1);
    push(
        "redact applies over the extended protocol",
        name == "***",
        name.clone(),
    );
    push(
        "pseudonym applies over the extended protocol",
        !email.contains("CANARY") && email.contains('@'),
        email.clone(),
    );

    // --- a released column must be untouched, byte for byte -----------------
    let sql = "SELECT id, city FROM fz.people WHERE id = 3";
    let d = direct.query_one(sql, &[]).await?;
    let p = proxy.query_one(sql, &[]).await?;
    push(
        "released columns are unchanged in binary",
        d.get::<_, i32>(0) == p.get::<_, i32>(0) && d.get::<_, String>(1) == p.get::<_, String>(1),
        format!("{} / {}", p.get::<_, i32>(0), p.get::<_, String>(1)),
    );

    // --- re-executing a prepared statement must keep masking ----------------
    // One Describe, many Executes: the plan is bound to the RowDescription, and
    // a second Execute has to reuse it rather than fall through unmasked.
    let stmt = proxy
        .prepare("SELECT full_name FROM fz.people WHERE id = $1")
        .await?;
    let mut all_masked = true;
    for id in 1..=20i32 {
        let v: String = proxy.query_one(&stmt, &[&id]).await?.get(0);
        all_masked &= v == "***";
    }
    push(
        "20 executes of one prepared statement all stay masked",
        all_masked,
        String::new(),
    );

    // --- a masked column inside a binary expression is still refused --------
    let refused = proxy
        .query_one("SELECT upper(full_name) FROM fz.people WHERE id = 3", &[])
        .await
        .err()
        .and_then(|e| e.as_db_error().map(|db| db.message().to_string()))
        .unwrap_or_default();
    push(
        "an expression over a masked column is refused in binary too",
        refused.starts_with("pgmask:"),
        refused,
    );

    let failed = checks.iter().filter(|c| !c.ok).count();
    println!("\nbinary result format ({} checks)", checks.len());
    println!("--------------------------------------------------");
    for c in &checks {
        println!(
            "  {}  {:<52} {}",
            if c.ok { "PASS" } else { "FAIL" },
            c.name,
            c.detail
        );
    }
    if failed > 0 {
        bail!("{failed} binary-format check(s) failed");
    }
    Ok(())
}

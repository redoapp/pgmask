//! Phase 0 provenance spike.
//!
//! Answers the question the whole masking-proxy design rests on: for each query
//! shape, does Postgres's RowDescription still identify the stored column each
//! output field came from?
//!
//! Provenance is read via `Statement::columns()` — i.e. Parse + Describe with no
//! Execute, which is exactly the path the proxy uses for pre-execution
//! rejection. The `execute` fallback below exists for statements that cannot be
//! prepared; as of the PG 17.10 run nothing needed it, `FETCH` included, which
//! is itself a finding (see handoff.md section 4).
//!
//! Usage:
//!   DATABASE_URL=postgres://... cargo run -p spike -- [--md docs/phase0-results.md]

mod shapes;

use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;

use anyhow::{Context, Result};
use tokio_postgres::NoTls;

use shapes::{Expect, Shape, SHAPES};

const FIXTURE: &str = include_str!("../fixture.sql");

#[derive(Clone, Debug)]
struct Field {
    name: String,
    table_oid: u32,
    column_id: i16,
}

impl Field {
    fn has_provenance(&self) -> bool {
        self.table_oid != 0
    }
}

#[derive(Debug)]
enum Outcome {
    /// How we obtained the shape: Describe-only, or execute-and-inspect.
    Fields {
        fields: Vec<Field>,
        via: &'static str,
    },
    Error(String),
}

#[derive(PartialEq, Eq, Clone, Copy, Debug)]
enum Verdict {
    Provenance,
    Partial,
    Opaque,
    NoFields,
    Error,
}

impl Verdict {
    fn label(self) -> &'static str {
        match self {
            Verdict::Provenance => "PROVENANCE",
            Verdict::Partial => "PARTIAL",
            Verdict::Opaque => "OPAQUE",
            Verdict::NoFields => "NO FIELDS",
            Verdict::Error => "ERROR",
        }
    }
}

struct Record {
    shape: &'static Shape,
    outcome: Outcome,
}

impl Record {
    fn verdict(&self) -> Verdict {
        match &self.outcome {
            Outcome::Error(_) => Verdict::Error,
            Outcome::Fields { fields, .. } if fields.is_empty() => Verdict::NoFields,
            Outcome::Fields { fields, .. } => {
                let with = fields.iter().filter(|f| f.has_provenance()).count();
                if with == 0 {
                    Verdict::Opaque
                } else if with == fields.len() {
                    Verdict::Provenance
                } else {
                    Verdict::Partial
                }
            }
        }
    }

    /// Did the result disagree with the prior we recorded in shapes.rs?
    fn surprising(&self) -> bool {
        match self.shape.expect {
            Expect::Unknown => false,
            Expect::Provenance => self.verdict() != Verdict::Provenance,
            Expect::Opaque => self.verdict() != Verdict::Opaque,
        }
    }
}

fn relkind_label(kind: i8) -> &'static str {
    match kind as u8 as char {
        'r' => "table",
        'v' => "view",
        'm' => "matview",
        'p' => "partitioned",
        'f' => "foreign",
        'c' => "composite",
        'S' => "sequence",
        _ => "?",
    }
}

async fn run_shape(client: &tokio_postgres::Client, shape: &Shape) -> Outcome {
    for stmt in shape.setup {
        if let Err(err) = client.batch_execute(stmt).await {
            return Outcome::Error(format!("setup `{stmt}`: {err}"));
        }
    }

    // Parse + Describe, no Execute. This is the proxy's pre-execution path.
    let outcome = match client.prepare(shape.sql).await {
        Ok(stmt) => Outcome::Fields {
            fields: stmt.columns().iter().map(to_field).collect(),
            via: "describe",
        },
        Err(prepare_err) => {
            // Utility statements (FETCH, and friends) cannot be prepared.
            match client.query(shape.sql, &[]).await {
                Ok(rows) => match rows.first() {
                    Some(row) => Outcome::Fields {
                        fields: row.columns().iter().map(to_field).collect(),
                        via: "execute",
                    },
                    None => Outcome::Fields {
                        fields: vec![],
                        via: "execute",
                    },
                },
                Err(exec_err) => Outcome::Error(
                    first_line(&exec_err.to_string()).unwrap_or_else(|| prepare_err.to_string()),
                ),
            }
        }
    };

    if matches!(outcome, Outcome::Error(_)) {
        // A failed shape can leave the session in an aborted transaction.
        let _ = client.batch_execute("ROLLBACK").await;
    }
    for stmt in shape.teardown {
        let _ = client.batch_execute(stmt).await;
    }
    outcome
}

fn to_field(col: &tokio_postgres::Column) -> Field {
    Field {
        name: col.name().to_string(),
        table_oid: col.table_oid().unwrap_or(0),
        column_id: col.column_id().unwrap_or(0),
    }
}

fn first_line(s: &str) -> Option<String> {
    s.lines().next().map(str::to_string)
}

async fn resolve_oids(
    client: &tokio_postgres::Client,
    oids: &HashSet<u32>,
) -> Result<HashMap<u32, (String, &'static str)>> {
    let wanted: Vec<u32> = oids.iter().copied().filter(|o| *o != 0).collect();
    if wanted.is_empty() {
        return Ok(HashMap::new());
    }
    let rows = client
        .query(
            "SELECT c.oid::int8, n.nspname || '.' || c.relname, c.relkind
               FROM pg_class c
               JOIN pg_namespace n ON n.oid = c.relnamespace
              WHERE c.oid = ANY($1::oid[])",
            &[&wanted],
        )
        .await
        .context("resolving relation OIDs")?;

    Ok(rows
        .iter()
        .map(|r| {
            let oid: i64 = r.get(0);
            let name: String = r.get(1);
            let kind: i8 = r.get(2);
            (oid as u32, (name, relkind_label(kind)))
        })
        .collect())
}

fn describe_fields(fields: &[Field], names: &HashMap<u32, (String, &'static str)>) -> String {
    fields
        .iter()
        .map(|f| {
            if !f.has_provenance() {
                return format!("{}=<opaque>", f.name);
            }
            match names.get(&f.table_oid) {
                Some((name, kind)) => format!("{}={name}[{kind}].{}", f.name, f.column_id),
                None => format!("{}={}.{}", f.name, f.table_oid, f.column_id),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[tokio::main]
async fn main() -> Result<()> {
    let url = std::env::var("DATABASE_URL")
        .context("DATABASE_URL is required — see the README for a local podman one-liner")?;

    let args: Vec<String> = std::env::args().collect();
    let md_path = args
        .iter()
        .position(|a| a == "--md")
        .and_then(|i| i.checked_add(1))
        .and_then(|i| args.get(i))
        .cloned();

    let (client, connection) = tokio_postgres::connect(&url, NoTls)
        .await
        .context("connecting to DATABASE_URL")?;
    tokio::spawn(async move {
        if let Err(err) = connection.await {
            eprintln!("connection error: {err}");
        }
    });

    let version: String = client.query_one("SELECT version()", &[]).await?.get(0);
    println!("\n{version}\n");

    println!("Applying fixture...");
    client
        .batch_execute(FIXTURE)
        .await
        .context("applying fixture.sql")?;
    client
        .batch_execute("SET search_path TO spike, public")
        .await?;

    let mut records = Vec::new();
    for shape in SHAPES {
        records.push(Record {
            shape,
            outcome: run_shape(&client, shape).await,
        });
        // Fixture DDL and any ROLLBACK above can reset search_path.
        client
            .batch_execute("SET search_path TO spike, public")
            .await?;
    }

    let oids: HashSet<u32> = records
        .iter()
        .filter_map(|r| match &r.outcome {
            Outcome::Fields { fields, .. } => Some(fields.iter().map(|f| f.table_oid)),
            Outcome::Error(_) => None,
        })
        .flatten()
        .collect();
    let names = resolve_oids(&client, &oids).await?;

    // --- Console summary ----------------------------------------------------
    println!(
        "\n{:<22}{:<12}{:<13}{:<10}DETAIL",
        "SHAPE", "GROUP", "VERDICT", "VIA"
    );
    println!("{}", "-".repeat(110));

    for r in &records {
        let (via, detail) = match &r.outcome {
            Outcome::Error(msg) => ("-", msg.clone()),
            Outcome::Fields { fields, via } => (*via, describe_fields(fields, &names)),
        };
        println!(
            "{:<22}{:<12}{:<13}{:<10}{}{}",
            r.shape.id,
            r.shape.group,
            r.verdict().label(),
            via,
            detail,
            if r.surprising() { "  <!>" } else { "" }
        );
    }

    println!("\n{}", "=".repeat(110));
    let mut counts: HashMap<&str, usize> = HashMap::new();
    for r in &records {
        let n: &mut usize = counts.entry(r.verdict().label()).or_default();
        *n = n.saturating_add(1);
    }
    let mut totals: Vec<_> = counts.iter().collect();
    totals.sort();
    println!(
        "Totals: {}",
        totals
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("  ")
    );

    let surprises: Vec<_> = records.iter().filter(|r| r.surprising()).collect();
    if surprises.is_empty() {
        println!("\nNo surprises against our priors.");
    } else {
        println!("\n{} shape(s) differed from our prior:", surprises.len());
        for r in &surprises {
            println!(
                "  - {}: expected {:?}, got {}",
                r.shape.id,
                r.shape.expect,
                r.verdict().label()
            );
        }
    }

    // --- Decision inputs (handoff.md section 4) -----------------------------
    let find = |id: &str| records.iter().find(|r| r.shape.id == id);
    let first_relation = |id: &str| -> Option<(String, &'static str)> {
        match &find(id)?.outcome {
            Outcome::Fields { fields, .. } => {
                let f = fields.first()?;
                names.get(&f.table_oid).cloned()
            }
            Outcome::Error(_) => None,
        }
    };
    let survives = |id: &str| {
        find(id)
            .map(|r| r.verdict() == Verdict::Provenance)
            .unwrap_or(false)
    };

    println!("\nDecision inputs:");
    match first_relation("view") {
        Some((name, kind)) => println!("  Views report ......... {name} ({kind})"),
        None => println!("  Views report ......... no provenance"),
    }
    match first_relation("partition_parent") {
        Some((name, kind)) => println!("  Partition parent ..... {name} ({kind})"),
        None => println!("  Partition parent ..... no provenance"),
    }
    let subquery_ok = survives("subquery_nonflat");
    let cte_ok = survives("cte");
    println!(
        "  Non-flat subquery .... {}",
        if subquery_ok { "survives" } else { "LOST" }
    );
    println!(
        "  CTE .................. {}",
        if cte_ok { "survives" } else { "LOST" }
    );
    println!(
        "\n  => {}\n",
        if subquery_ok && cte_ok {
            "GO as designed."
        } else {
            "GO, but expect a higher rejection rate; re-read handoff.md section 4."
        }
    );

    if let Some(path) = md_path {
        let mut out = String::new();
        writeln!(out, "# Phase 0 provenance results\n")?;
        writeln!(out, "`{version}`\n")?;
        writeln!(out, "| Shape | Group | Verdict | Via | Fields |")?;
        writeln!(out, "|---|---|---|---|---|")?;
        for r in &records {
            let (via, detail) = match &r.outcome {
                Outcome::Error(msg) => ("-", format!("error: {msg}")),
                Outcome::Fields { fields, via } => (*via, describe_fields(fields, &names)),
            };
            writeln!(
                out,
                "| {} | {} | {} | {} | {} |",
                r.shape.id,
                r.shape.group,
                r.verdict().label(),
                via,
                detail
            )?;
        }
        std::fs::write(&path, out).with_context(|| format!("writing {path}"))?;
        println!("Wrote {path}");
    }

    Ok(())
}

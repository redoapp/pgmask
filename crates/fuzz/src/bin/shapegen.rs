//! A portable generator of *query shapes*, as a corpus for the replay harness.
//!
//! # Why this exists rather than sqlsmith
//!
//! sqlsmith cannot read a CockroachDB schema — it loads `pg_catalog` and dies at
//! `Generating indexes...unknown type:`. Generating against Postgres and
//! replaying was the obvious workaround and it does not work either: 395 of 400
//! statements errored, because sqlsmith draws functions and operators from the
//! target's catalog and Postgres has thousands CockroachDB does not. A campaign
//! that errors on 98.75% of its corpus is vacuous however it reports.
//!
//! The deeper point is that function soup was never what needed fuzzing here.
//! What decides masking is whether the engine's per-field provenance can be
//! believed, and that is a property of the *shape* of a query — how many source
//! columns can reach one output field — not of which scalar function sits on
//! top. Both bugs found so far were shapes: a set operation, and a set
//! operation hidden in a view.
//!
//! So this generates compositions of relational operators over the fixture,
//! using only SQL both engines accept. Every statement is expected to run.
//!
//! # Determinism
//!
//! Seeded xorshift rather than a `rand` dependency, so a seed reproduces a
//! corpus exactly and the crate gains nothing to audit.
//!
//! Usage:
//!   shapegen <seed> <count> > corpus.sql

use std::fmt::Write as _;

/// xorshift64*. Deterministic, and a seed of zero would produce nothing but
/// zeroes, so it is mapped away.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(if seed == 0 { 0x9E3779B97F4A7C15 } else { seed })
    }
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }
    /// A value in `0..n`, or 0 when `n` is 0.
    ///
    /// `checked_rem` rather than `%`: the workspace denies implicit arithmetic,
    /// and "the divisor cannot be zero here" is exactly the kind of local
    /// reasoning that stops being true when someone edits the caller.
    fn below(&mut self, n: usize) -> usize {
        let Some(n) = u64::try_from(n).ok().filter(|n| *n > 0) else {
            return 0;
        };
        usize::try_from(self.next().checked_rem(n).unwrap_or(0)).unwrap_or(0)
    }
    fn pick<'a, T>(&mut self, xs: &'a [T]) -> &'a T {
        let i = self.below(xs.len());
        // `below` is always in range for a non-empty slice; the fallback keeps
        // this total rather than relying on that.
        xs.get(i).unwrap_or_else(|| {
            xs.first()
                .expect("pick called on an empty slice — the tables below are all non-empty")
        })
    }
    fn chance(&mut self, percent: u64) -> bool {
        self.next().wrapping_rem(100) < percent
    }
}

/// A relation and the columns worth selecting from it.
///
/// Only text-ish and numeric columns, because the oracle looks for a token in
/// text and the masks under test are on these.
struct Relation {
    name: &'static str,
    text: &'static [&'static str],
    nums: &'static [&'static str],
}

const RELATIONS: &[Relation] = &[
    Relation {
        name: "fz.t1",
        text: &["a", "b"],
        nums: &["id", "n"],
    },
    Relation {
        name: "fz.t2",
        text: &["a", "b"],
        nums: &["id", "n"],
    },
    Relation {
        name: "fz.t3",
        text: &["a", "b"],
        nums: &["id", "n"],
    },
    Relation {
        name: "fz.t4",
        text: &["a", "b"],
        nums: &["id", "n"],
    },
    Relation {
        name: "fz.t5",
        text: &["a", "b"],
        nums: &["id", "n"],
    },
    Relation {
        name: "fz.t6",
        text: &["a", "b"],
        nums: &["id", "n"],
    },
    Relation {
        name: "fz.people",
        text: &["email", "full_name", "phone", "city", "last_ip", "note"],
        nums: &["id", "annual_salary"],
    },
    // The views matter more than the tables: a set operation inside one is
    // invisible in the statement that selects from it, and that was a leak on
    // both engines.
    Relation {
        name: "fz.v_union",
        text: &["a"],
        nums: &["id"],
    },
    Relation {
        name: "fz.v_join",
        text: &["xa", "yb"],
        nums: &["id"],
    },
    Relation {
        name: "fz.v_mixed",
        text: &["v"],
        nums: &["id"],
    },
];

/// One relation reference: `fz.people p3`.
struct Source {
    relation: &'static Relation,
    alias: String,
}

impl Source {
    fn text_col(&self, rng: &mut Rng) -> String {
        format!("{}.{}", self.alias, rng.pick(self.relation.text))
    }
    fn num_col(&self, rng: &mut Rng) -> String {
        format!("{}.{}", self.alias, rng.pick(self.relation.nums))
    }
}

fn source(rng: &mut Rng, n: usize) -> Source {
    Source {
        relation: rng.pick(RELATIONS),
        alias: format!("r{n}"),
    }
}

/// A scalar expression over a source. Deliberately weighted towards things that
/// *keep* a value readable — a mask that fails to fire on `COALESCE(email, '')`
/// is a leak, whereas one that fails on `count(*)` is not.
fn scalar(rng: &mut Rng, s: &Source) -> String {
    let c = s.text_col(rng);
    match rng.below(8) {
        0 => c,
        1 => format!("lower({c})"),
        2 => format!("upper({c})"),
        3 => format!("{c} || ''"),
        4 => format!("COALESCE({c}, '')"),
        5 => format!("CASE WHEN {} > 0 THEN {c} ELSE NULL END", s.num_col(rng)),
        6 => format!("substr({c}, 1, 40)"),
        _ => format!("{c}::text"),
    }
}

/// A single-relation select, the leaf every larger shape is built from.
fn leaf(rng: &mut Rng, depth: usize, n: usize) -> (String, Vec<String>) {
    let s = source(rng, n.wrapping_add(depth.wrapping_mul(10)));
    let mut cols = Vec::new();
    let count = rng.below(3).saturating_add(1);
    for i in 0..count {
        let expr = if rng.chance(35) {
            scalar(rng, &s)
        } else {
            s.text_col(rng)
        };
        cols.push(format!("{expr} AS c{i}"));
    }
    let mut sql = format!(
        "SELECT {} FROM {} {}",
        cols.join(", "),
        s.relation.name,
        s.alias
    );
    if rng.chance(30) {
        let _ = write!(
            sql,
            " WHERE {} < {}",
            s.num_col(rng),
            rng.below(400).saturating_add(5)
        );
    }
    let names: Vec<String> = (0..count).map(|i| format!("c{i}")).collect();
    (sql, names)
}

/// Wrap a query in one more relational operator.
///
/// Each arm is a construct that either preserves provenance, erases it, or —
/// the interesting case — makes one output field draw from several source
/// columns. Those last are the ones that have found bugs.
fn compose(rng: &mut Rng, depth: usize, n: usize) -> (String, Vec<String>) {
    if depth == 0 {
        return leaf(rng, depth, n);
    }
    let next = depth.saturating_sub(1);
    match rng.below(10) {
        // Subquery.
        0 => {
            let (inner, cols) = compose(rng, next, n);
            let projected = cols.first().cloned().unwrap_or_else(|| "c0".into());
            (
                format!("SELECT {projected} FROM ({inner}) q{n}"),
                vec![projected],
            )
        }
        // CTE.
        1 => {
            let (inner, cols) = compose(rng, next, n);
            let projected = cols.first().cloned().unwrap_or_else(|| "c0".into());
            (
                format!("WITH w{n} AS ({inner}) SELECT {projected} FROM w{n}"),
                vec![projected],
            )
        }
        // Set operations: one output field, two source columns. Both leaks
        // found so far were here.
        2 | 3 => {
            let op = rng.pick(&["UNION ALL", "UNION", "INTERSECT", "EXCEPT"]);
            let (left, lcols) = compose(rng, next, n);
            let (right, _) = compose(rng, next, n.wrapping_add(1));
            // Set operations require matching arity; project both to one column.
            let lc = lcols.first().cloned().unwrap_or_else(|| "c0".into());
            (
                format!("SELECT {lc} FROM ({left}) a{n} {op} SELECT c0 FROM ({right}) b{n}"),
                vec![lc],
            )
        }
        // Join.
        4 => {
            let s = source(rng, n.wrapping_add(50));
            let (inner, cols) = compose(rng, next, n);
            let lc = cols.first().cloned().unwrap_or_else(|| "c0".into());
            (
                format!(
                    "SELECT q{n}.{lc}, {} AS c1 FROM ({inner}) q{n} JOIN {} {} ON true",
                    s.text_col(rng),
                    s.relation.name,
                    s.alias
                ),
                vec![lc, "c1".into()],
            )
        }
        // DISTINCT.
        5 => {
            let (inner, cols) = compose(rng, next, n);
            let lc = cols.first().cloned().unwrap_or_else(|| "c0".into());
            (
                format!("SELECT DISTINCT {lc} FROM ({inner}) q{n}"),
                vec![lc],
            )
        }
        // ORDER BY / LIMIT.
        6 => {
            let (inner, cols) = compose(rng, next, n);
            let lc = cols.first().cloned().unwrap_or_else(|| "c0".into());
            (
                format!(
                    "SELECT {lc} FROM ({inner}) q{n} ORDER BY 1 LIMIT {}",
                    rng.below(20).saturating_add(1)
                ),
                vec![lc],
            )
        }
        // Window function: the value passes through untouched beside a rank.
        7 => {
            let (inner, cols) = compose(rng, next, n);
            let lc = cols.first().cloned().unwrap_or_else(|| "c0".into());
            (
                format!("SELECT {lc}, row_number() OVER (ORDER BY {lc}) AS c1 FROM ({inner}) q{n}"),
                vec![lc, "c1".into()],
            )
        }
        // Value-returning aggregates. min/max/string_agg return one of their
        // inputs, which is exactly what must stay refused.
        8 => {
            let (inner, cols) = compose(rng, next, n);
            let lc = cols.first().cloned().unwrap_or_else(|| "c0".into());
            let agg = rng.pick(&["min", "max", "string_agg"]);
            let call = if *agg == "string_agg" {
                format!("string_agg({lc}, ',')")
            } else {
                format!("{agg}({lc})")
            };
            (
                format!("SELECT {call} AS c0 FROM ({inner}) q{n}"),
                vec!["c0".into()],
            )
        }
        // GROUP BY, keeping the grouped value in the output.
        _ => {
            let (inner, cols) = compose(rng, next, n);
            let lc = cols.first().cloned().unwrap_or_else(|| "c0".into());
            (
                format!("SELECT {lc}, count(*) AS c1 FROM ({inner}) q{n} GROUP BY {lc}"),
                vec![lc, "c1".into()],
            )
        }
    }
}

fn main() {
    let mut args = std::env::args().skip(1);
    let seed: u64 = args.next().and_then(|v| v.parse().ok()).unwrap_or(1);
    let count: usize = args.next().and_then(|v| v.parse().ok()).unwrap_or(1000);
    let mut rng = Rng::new(seed);

    let mut out = String::new();
    for i in 0..count {
        // Depth 1..=3. Deeper nests mostly repeat shapes while getting slower to
        // plan, and CockroachDB starts timing out on the wide ones.
        let depth = rng.below(3).saturating_add(1);
        let (sql, _) = compose(&mut rng, depth, i);
        let _ = writeln!(out, "{sql};");
    }
    print!("{out}");
}

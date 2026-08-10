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
/// `text` feeds expressions and the canary scan; `nums` feeds predicates;
/// `typed` is projected as-is.
///
/// The `typed` list exists because measuring coverage said it had to. With only
/// text and small ints, a 2000-statement corpus reached **19.6% of mask.rs**:
/// no generated shape ever selected a date, uuid, inet or int8, so `date-year`,
/// `ip-prefix`, uuid pseudonyms and 64-bit bucketing were never exercised by a
/// generated query at all. They have unit tests and fixed end-to-end checks;
/// what they lacked was any shape variety, which is precisely where the leaks
/// found so far have lived.
///
/// The oracle already knows their raw forms — `00000000-0000-4000-a000-` and
/// `555-77` are canaries — so a leak through one of these is detected, not just
/// executed.
struct Relation {
    name: &'static str,
    text: &'static [&'static str],
    nums: &'static [&'static str],
    typed: &'static [&'static str],
}

const RELATIONS: &[Relation] = &[
    Relation {
        name: "fz.t1",
        text: &["a", "b"],
        nums: &["id", "n"],
        typed: &["d", "u"],
    },
    Relation {
        name: "fz.t2",
        text: &["a", "b"],
        nums: &["id", "n"],
        typed: &["d", "u"],
    },
    Relation {
        name: "fz.t3",
        text: &["a", "b"],
        nums: &["id", "n"],
        typed: &["d", "u"],
    },
    Relation {
        name: "fz.t4",
        text: &["a", "b"],
        nums: &["id", "n"],
        typed: &["d", "u"],
    },
    Relation {
        name: "fz.t5",
        text: &["a", "b"],
        nums: &["id", "n"],
        typed: &["d", "u"],
    },
    Relation {
        name: "fz.t6",
        text: &["a", "b"],
        nums: &["id", "n"],
        typed: &["d", "u"],
    },
    Relation {
        name: "fz.people",
        text: &["email", "full_name", "phone", "city", "last_ip", "note"],
        nums: &["id", "annual_salary"],
        typed: &["birth_date", "account_uuid", "salary_big"],
    },
    // The views matter more than the tables: a set operation inside one is
    // invisible in the statement that selects from it, and that was a leak on
    // both engines.
    Relation {
        name: "fz.v_union",
        text: &["a"],
        nums: &["id"],
        typed: &[],
    },
    Relation {
        name: "fz.v_join",
        text: &["xa", "yb"],
        nums: &["id"],
        typed: &[],
    },
    Relation {
        name: "fz.v_mixed",
        text: &["v"],
        nums: &["id"],
        typed: &[],
    },
];

/// A generated query and what it projects.
///
/// `typed` says the first output column may not be text. Two arms need to know:
/// a set operation requires both branches to agree on type, and `string_agg`
/// only takes text. Getting this wrong is not a masking bug but it is a wasted
/// statement — projecting dates without tracking it put 230 engine errors into
/// a 2000-statement corpus that had been running at zero.
struct Shape {
    sql: String,
    cols: Vec<String>,
    typed: bool,
}

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
    /// A date/uuid/int8 column when the relation has one, else a text column.
    ///
    /// Projected bare rather than wrapped: these are type-aware masks, and an
    /// expression over one is refused before the mask ever runs.
    fn typed_col(&self, rng: &mut Rng) -> String {
        if self.relation.typed.is_empty() {
            return self.text_col(rng);
        }
        format!("{}.{}", self.alias, rng.pick(self.relation.typed))
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
fn leaf(rng: &mut Rng, depth: usize, n: usize, allow_typed: bool) -> Shape {
    let s = source(rng, n.wrapping_add(depth.wrapping_mul(10)));
    let mut cols = Vec::new();
    let mut typed = false;
    let count = rng.below(3).saturating_add(1);
    for i in 0..count {
        let expr = if rng.chance(30) {
            scalar(rng, &s)
        } else if allow_typed && rng.chance(30) {
            typed = true;
            s.typed_col(rng)
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
    Shape {
        sql,
        cols: names,
        typed,
    }
}

/// Wrap a query in one more relational operator.
///
/// Each arm is a construct that either preserves provenance, erases it, or —
/// the interesting case — makes one output field draw from several source
/// columns. Those last are the ones that have found bugs.
fn compose(rng: &mut Rng, depth: usize, n: usize, allow_typed: bool) -> Shape {
    if depth == 0 {
        return leaf(rng, depth, n, allow_typed);
    }
    let next = depth.saturating_sub(1);
    // Every arm below projects `inner`'s first column onward, so the type flag
    // travels with it unless the arm changes the type.
    let wrap = |sql: String, cols: Vec<String>, typed: bool| Shape { sql, cols, typed };

    match rng.below(12) {
        // Subquery.
        0 => {
            let inner = compose(rng, next, n, allow_typed);
            let lc = inner.cols.first().cloned().unwrap_or_else(|| "c0".into());
            let sql = format!("SELECT {lc} FROM ({}) q{n}", inner.sql);
            wrap(sql, vec![lc], inner.typed)
        }
        // CTE.
        1 => {
            let inner = compose(rng, next, n, allow_typed);
            let lc = inner.cols.first().cloned().unwrap_or_else(|| "c0".into());
            let sql = format!("WITH w{n} AS ({}) SELECT {lc} FROM w{n}", inner.sql);
            wrap(sql, vec![lc], inner.typed)
        }
        // Set operations: one output field, two source columns. Both leaks
        // found so far were here.
        2 | 3 => {
            let op = rng.pick(&["UNION ALL", "UNION", "INTERSECT", "EXCEPT"]);
            // Text on both sides. A set operation needs the branches to agree
            // on type, and pairing a date with text is an engine error, not a
            // test — it put 230 of them into a corpus that ran at zero.
            let left = compose(rng, next, n, false);
            let right = compose(rng, next, n.wrapping_add(1), false);
            let lc = left.cols.first().cloned().unwrap_or_else(|| "c0".into());
            let sql = format!(
                "SELECT {lc} FROM ({}) a{n} {op} SELECT c0 FROM ({}) b{n}",
                left.sql, right.sql
            );
            wrap(sql, vec![lc], false)
        }
        // Join.
        4 => {
            let s = source(rng, n.wrapping_add(50));
            let inner = compose(rng, next, n, allow_typed);
            let lc = inner.cols.first().cloned().unwrap_or_else(|| "c0".into());
            let sql = format!(
                "SELECT q{n}.{lc}, {} AS c1 FROM ({}) q{n} JOIN {} {} ON true",
                s.text_col(rng),
                inner.sql,
                s.relation.name,
                s.alias
            );
            wrap(sql, vec![lc, "c1".into()], inner.typed)
        }
        // DISTINCT.
        5 => {
            let inner = compose(rng, next, n, allow_typed);
            let lc = inner.cols.first().cloned().unwrap_or_else(|| "c0".into());
            let sql = format!("SELECT DISTINCT {lc} FROM ({}) q{n}", inner.sql);
            wrap(sql, vec![lc], inner.typed)
        }
        // ORDER BY / LIMIT.
        6 => {
            let inner = compose(rng, next, n, allow_typed);
            let lc = inner.cols.first().cloned().unwrap_or_else(|| "c0".into());
            let sql = format!(
                "SELECT {lc} FROM ({}) q{n} ORDER BY 1 LIMIT {}",
                inner.sql,
                rng.below(20).saturating_add(1)
            );
            wrap(sql, vec![lc], inner.typed)
        }
        // Window function: the value passes through untouched beside a rank.
        7 => {
            let inner = compose(rng, next, n, allow_typed);
            let lc = inner.cols.first().cloned().unwrap_or_else(|| "c0".into());
            let sql = format!(
                "SELECT {lc}, row_number() OVER (ORDER BY {lc}) AS c1 FROM ({}) q{n}",
                inner.sql
            );
            wrap(sql, vec![lc, "c1".into()], inner.typed)
        }
        // Value-returning aggregates: they return one of their inputs, which is
        // exactly what must stay refused.
        8 => {
            let inner = compose(rng, next, n, allow_typed);
            let lc = inner.cols.first().cloned().unwrap_or_else(|| "c0".into());
            // `string_agg` only takes text, so it is off the table when the
            // projected column might be a date or a uuid.
            // `count` for a typed input: Postgres has no `min`/`max` for
            // `uuid`, and the shape does not record which typed column it is
            // carrying. `count` is not value-returning, so this arm loses a
            // little of its point on those, which is better than three engine
            // errors per four hundred statements.
            let agg = if inner.typed {
                *rng.pick(&["min", "max", "count"])
            } else {
                *rng.pick(&["min", "max", "string_agg"])
            };
            let call = if agg == "string_agg" {
                format!("string_agg({lc}, ',')")
            } else {
                format!("{agg}({lc})")
            };
            let sql = format!("SELECT {call} AS c0 FROM ({}) q{n}", inner.sql);
            wrap(sql, vec!["c0".into()], inner.typed && agg != "string_agg")
        }
        // A reducing aggregate used as a *window* function.
        //
        // This arm exists because its absence was a disclosure. `sum(x)` is
        // released as a summary, but over `ROWS BETWEEN CURRENT ROW AND CURRENT
        // ROW` it is the identity function and returned exact salaries through
        // a bucketed column. The generator had no windowed aggregates at all,
        // so no generated shape could reach it; a sqlsmith statement did, by
        // accident, once the fixture changed.
        9 => {
            // A numeric first column, so it cannot sit under a set operation
            // whose other branch is text. `allow_typed` is how the caller says
            // "text only"; these two arms produced `bigint` and `numeric` while
            // declaring `typed: false`, which is the same mistake the `typed` flag
            // was introduced to stop — 22 type-mismatch errors per 400 statements,
            // all `INTERSECT types bigint and text cannot be matched` and kin.
            if !allow_typed {
                return leaf(rng, depth, n, allow_typed);
            }
            let s = source(rng, n.wrapping_add(70));
            let frame = rng.pick(&[
                "ROWS BETWEEN CURRENT ROW AND CURRENT ROW",
                "ROWS BETWEEN 1 PRECEDING AND CURRENT ROW",
                "",
            ]);
            let agg = rng.pick(&["sum", "avg", "count", "min", "max"]);
            let sql = format!(
                "SELECT {agg}({}) OVER (ORDER BY {} {frame}) AS c0 FROM {} {}",
                s.num_col(rng),
                s.num_col(rng),
                s.relation.name,
                s.alias
            );
            Shape {
                sql,
                cols: vec!["c0".into()],
                // Numeric, not text: `string_agg` does not take it, and saying
                // otherwise is what offered `string_agg(bigint, unknown)` to
                // the arm above.
                typed: true,
            }
        }
        // A *reducing* aggregate over a grouping.
        //
        // This arm exists for the same reason arm 9 does, and it is the same
        // omission twice. The only GROUP BY the generator had projected
        // `count(*)`, which discloses nothing whatever it is grouped by — so no
        // generated statement could reach a summary over a grouping, and
        // 176,000 of them reported clean while `sum(annual_salary) GROUP BY id`
        // returned the whole masked column in one query.
        //
        // Grouped by a unique key, every group is one row and the summary *is*
        // the value, which lands exactly on the fixture's poison sequence and
        // trips the numeric detector. `fz.*.id` is a primary key, so half the
        // groupings drawn here are the disclosure and half are honest
        // aggregation that must keep working.
        //
        // Spellings are restricted to what both engines accept. Postgres-only
        // syntax — `ROLLUP`, `CUBE`, `GROUPING SETS`, which CockroachDB rejects
        // outright — is covered by `scripts/test-grouping.py` instead, so this
        // corpus stays at zero engine errors on both.
        10 => {
            // A numeric first column, so it cannot sit under a set operation
            // whose other branch is text. `allow_typed` is how the caller says
            // "text only"; these two arms produced `bigint` and `numeric` while
            // declaring `typed: false`, which is the same mistake the `typed` flag
            // was introduced to stop — 22 type-mismatch errors per 400 statements,
            // all `INTERSECT types bigint and text cannot be matched` and kin.
            if !allow_typed {
                return leaf(rng, depth, n, allow_typed);
            }
            // Weighted towards the relation that carries the poison. Drawn
            // uniformly, this arm reaches `sum(fz.people.annual_salary) GROUP
            // BY fz.people.id` in about one statement in forty — thin enough
            // that a clean run would mean little. The other half stays uniform
            // so honest aggregation over the rest of the fixture is still
            // generated, and the grouping is a key only some of the time, so
            // the arm produces both the disclosure and the query it must not
            // break.
            let s = if rng.chance(50) {
                Source {
                    relation: RELATIONS
                        .iter()
                        .find(|r| r.name == "fz.people")
                        .unwrap_or_else(|| {
                            RELATIONS.first().expect("RELATIONS is a non-empty const")
                        }),
                    alias: format!("r{}", n.wrapping_add(90)),
                }
            } else {
                source(rng, n.wrapping_add(90))
            };
            let value = if rng.chance(70) && s.relation.nums.contains(&"annual_salary") {
                format!("{}.annual_salary", s.alias)
            } else {
                s.num_col(rng)
            };
            let key = format!("{}.{}", s.alias, rng.pick(s.relation.nums));
            let grouped = match rng.below(6) {
                0 => key.clone(),
                1 => format!("({key})"),
                2 => format!("{key} + 0"),
                3 => format!("abs({key})"),
                4 => format!("coalesce({key}, 0)"),
                _ => format!("{key}::text"),
            };
            // Both. `avg` over int4 returns `numeric`, which the harness now
            // decodes; it was restricted to `sum` for one release because a
            // value that cannot be decoded is a value the oracle never scans.
            let agg = *rng.pick(&["sum", "avg"]);
            // Three ways to name the same grouping. The alias and the ordinal
            // are not decoration: both were live disclosures, because a name in
            // the clause is not the column being grouped on.
            let sql = match rng.below(3) {
                0 => format!(
                    "SELECT {agg}({value}) AS c0 FROM {} {} GROUP BY {grouped}",
                    s.relation.name, s.alias
                ),
                1 => format!(
                    "SELECT {grouped} AS g0, {agg}({value}) AS c0 FROM {} {} GROUP BY g0",
                    s.relation.name, s.alias
                ),
                _ => format!(
                    "SELECT {grouped} AS g0, {agg}({value}) AS c0 FROM {} {} GROUP BY 1",
                    s.relation.name, s.alias
                ),
            };
            // The summary first, deliberately. Every wrapping arm projects
            // `cols.first()` by name, so listing the grouping first meant an
            // enclosing subquery or CTE emitted `SELECT g0 FROM (...)` and
            // dropped the aggregate — the corpus carried the disclosure and
            // discarded the value before the oracle could see it. Twenty-six
            // such statements were generated and none could leak. Order here
            // does not have to match the projection: the reference is by name.
            let cols = if sql.contains("AS g0") {
                vec!["c0".into(), "g0".into()]
            } else {
                vec!["c0".into()]
            };
            Shape {
                sql,
                cols,
                // As above: `sum`/`avg` are numeric.
                typed: true,
            }
        }
        // GROUP BY, keeping the grouped value in the output.
        _ => {
            let inner = compose(rng, next, n, allow_typed);
            let lc = inner.cols.first().cloned().unwrap_or_else(|| "c0".into());
            let sql = format!(
                "SELECT {lc}, count(*) AS c1 FROM ({}) q{n} GROUP BY {lc}",
                inner.sql
            );
            wrap(sql, vec![lc, "c1".into()], inner.typed)
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
        let shape = compose(&mut rng, depth, i, true);
        let _ = writeln!(out, "{};", shape.sql);
    }
    print!("{out}");
}

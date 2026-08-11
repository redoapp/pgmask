//! A generator of *query shapes*, as a corpus for the replay harness.
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
//! So this generates compositions of relational operators over the fixture.
//! Every statement is expected to run.
//!
//! # Dialect
//!
//! Most of the corpus is SQL both engines accept, and it has to stay that way:
//! the same file is replayed against CockroachDB by `test-fuzz-cockroach.sh`,
//! `test-differential.sh` and `soak.sh`, and a statement one engine cannot
//! parse is not a test, it is a hole that reports as a pass.
//!
//! `ROLLUP`, `CUBE` and `GROUPING SETS` are the exception. CockroachDB rejects
//! them outright and they are exactly where one disclosure lived, so they are
//! generated only when the caller passes `postgres` (the default) and
//! suppressed under `portable`. An arm that cannot honour what the caller asked
//! for declines and emits a leaf instead, which is what the `typed` flag
//! already did for the arms that project a date or a bigint.
//!
//! # Determinism
//!
//! Seeded xorshift rather than a `rand` dependency, so a seed reproduces a
//! corpus exactly and the crate gains nothing to audit.
//!
//! Usage:
//!   shapegen <seed> <count> [postgres|portable] > corpus.sql

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
    /// Date/timestamp columns specifically. `typed` mixes dates with uuids and
    /// int8, and `date_trunc` over a uuid is an engine error rather than a test.
    dates: &'static [&'static str],
}

const RELATIONS: &[Relation] = &[
    Relation {
        name: "fz.t1",
        text: &["a", "b"],
        nums: &["id", "n"],
        typed: &["d", "u"],
        dates: &["d"],
    },
    Relation {
        name: "fz.t2",
        text: &["a", "b"],
        nums: &["id", "n"],
        typed: &["d", "u"],
        dates: &["d"],
    },
    Relation {
        name: "fz.t3",
        text: &["a", "b"],
        nums: &["id", "n"],
        typed: &["d", "u"],
        dates: &["d"],
    },
    Relation {
        name: "fz.t4",
        text: &["a", "b"],
        nums: &["id", "n"],
        typed: &["d", "u"],
        dates: &["d"],
    },
    Relation {
        name: "fz.t5",
        text: &["a", "b"],
        nums: &["id", "n"],
        typed: &["d", "u"],
        dates: &["d"],
    },
    Relation {
        name: "fz.t6",
        text: &["a", "b"],
        nums: &["id", "n"],
        typed: &["d", "u"],
        dates: &["d"],
    },
    Relation {
        name: "fz.people",
        text: &["email", "full_name", "phone", "city", "last_ip", "note"],
        nums: &["id", "annual_salary"],
        typed: &["birth_date", "account_uuid", "salary_big"],
        dates: &["birth_date"],
    },
    // The views matter more than the tables: a set operation inside one is
    // invisible in the statement that selects from it, and that was a leak on
    // both engines.
    Relation {
        name: "fz.v_union",
        text: &["a"],
        nums: &["id"],
        typed: &[],
        dates: &[],
    },
    Relation {
        name: "fz.v_join",
        text: &["xa", "yb"],
        nums: &["id"],
        typed: &[],
        dates: &[],
    },
    Relation {
        name: "fz.v_mixed",
        text: &["v"],
        nums: &["id"],
        typed: &[],
        dates: &[],
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

/// What the caller of an arm can accept.
///
/// Two different questions, both answered the same way: an arm that cannot
/// honour the constraint declines and emits a leaf instead. Arms 9, 10 and 11
/// already did that for `typed`, and the reason it is a *flag* and not a
/// convention is that getting it wrong is silent — the statement is generated,
/// the engine rejects it, and the corpus quietly shrinks.
#[derive(Clone, Copy)]
struct Allow {
    /// The first output column may be something other than `text`.
    ///
    /// A set operation needs its branches to agree on type, so it turns this
    /// off for both, and `string_agg` only takes text.
    typed: bool,
    /// Postgres-only syntax is acceptable, because this corpus will not be
    /// replayed against CockroachDB.
    ///
    /// `ROLLUP`, `CUBE` and `GROUPING SETS` are the whole of it today.
    /// CockroachDB rejects them outright, and the same generated corpus is
    /// replayed against both engines by `test-fuzz-cockroach.sh`,
    /// `test-differential.sh` and `soak.sh`, where an unparseable statement is
    /// not a test — it is a hole in one that reports as a pass.
    postgres_only: bool,
}

impl Allow {
    /// The same permissions, but the first column has to be text.
    fn text_only(self) -> Self {
        Self {
            typed: false,
            ..self
        }
    }
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
    /// A date column, when the relation has one.
    fn date_col(&self, rng: &mut Rng) -> Option<String> {
        if self.relation.dates.is_empty() {
            return None;
        }
        Some(format!("{}.{}", self.alias, rng.pick(self.relation.dates)))
    }
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
fn leaf(rng: &mut Rng, depth: usize, n: usize, allow: Allow) -> Shape {
    let s = source(rng, n.wrapping_add(depth.wrapping_mul(10)));
    let mut cols = Vec::new();
    let mut typed = false;
    let count = rng.below(3).saturating_add(1);
    for i in 0..count {
        let expr = if rng.chance(30) {
            scalar(rng, &s)
        } else if allow.typed && rng.chance(30) {
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
fn compose(rng: &mut Rng, depth: usize, n: usize, allow: Allow) -> Shape {
    if depth == 0 {
        return leaf(rng, depth, n, allow);
    }
    let next = depth.saturating_sub(1);
    // Every arm below projects `inner`'s first column onward, so the type flag
    // travels with it unless the arm changes the type.
    let wrap = |sql: String, cols: Vec<String>, typed: bool| Shape { sql, cols, typed };

    match rng.below(14) {
        // Subquery.
        0 => {
            let inner = compose(rng, next, n, allow);
            let lc = inner.cols.first().cloned().unwrap_or_else(|| "c0".into());
            let sql = format!("SELECT {lc} FROM ({}) q{n}", inner.sql);
            wrap(sql, vec![lc], inner.typed)
        }
        // CTE.
        1 => {
            let inner = compose(rng, next, n, allow);
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
            let left = compose(rng, next, n, allow.text_only());
            let right = compose(rng, next, n.wrapping_add(1), allow.text_only());
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
            let inner = compose(rng, next, n, allow);
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
            let inner = compose(rng, next, n, allow);
            let lc = inner.cols.first().cloned().unwrap_or_else(|| "c0".into());
            let sql = format!("SELECT DISTINCT {lc} FROM ({}) q{n}", inner.sql);
            wrap(sql, vec![lc], inner.typed)
        }
        // ORDER BY / LIMIT.
        6 => {
            let inner = compose(rng, next, n, allow);
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
            let inner = compose(rng, next, n, allow);
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
            let inner = compose(rng, next, n, allow);
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
            // whose other branch is text. `allow.typed` is how the caller says
            // "text only"; these two arms produced `bigint` and `numeric` while
            // declaring `typed: false`, which is the same mistake the `typed` flag
            // was introduced to stop — 22 type-mismatch errors per 400 statements,
            // all `INTERSECT types bigint and text cannot be matched` and kin.
            if !allow.typed {
                return leaf(rng, depth, n, allow);
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
        // `ROLLUP`, `CUBE` and `GROUPING SETS` are drawn here too, and only
        // when the caller said Postgres-only. That is not a portability
        // nicety, it is the reason 0.1.18 could not have been found by this
        // campaign: a grouping set is read by a *different* branch of
        // `group_item_columns` than a plain column reference, and until now no
        // generated statement contained one. This arm used to say the
        // Postgres-only spellings were "covered by scripts/test-grouping.py
        // instead", which is true and is not the same thing — that script
        // checks a fixed list of hand-written statements, so it can only find
        // the grouping bugs somebody already thought of, and it cannot compose
        // a grouping set with a subquery wrapper, a view or a join.
        //
        // Measured over 5,000 statements before this change: `ROLLUP`, `CUBE`
        // and `GROUPING SETS` appeared **zero** times.
        10 => {
            // A numeric first column, so it cannot sit under a set operation
            // whose other branch is text. `allow.typed` is how the caller says
            // "text only"; these two arms produced `bigint` and `numeric` while
            // declaring `typed: false`, which is the same mistake the `typed` flag
            // was introduced to stop — 22 type-mismatch errors per 400 statements,
            // all `INTERSECT types bigint and text cannot be matched` and kin.
            if !allow.typed {
                return leaf(rng, depth, n, allow);
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
            // Three ways to *name* the same grouping. The alias and the
            // ordinal are not decoration: both were live disclosures, because a
            // name in the clause is not the column being grouped on.
            //
            // Named separately from how the grouping is *spelled* below, so
            // every naming survives inside a grouping set. `GROUP BY
            // ROLLUP(g0)` resolves the output alias where `GROUP BY g0 + 0`
            // does not, which is a distinction the reader has to make and had
            // no generated statement to make it on.
            let naming = rng.below(3);
            let (projection, named) = match naming {
                0 => (String::new(), grouped.clone()),
                1 => (format!("{grouped} AS g0, "), "g0".to_string()),
                _ => (format!("{grouped} AS g0, "), "1".to_string()),
            };
            // A second key, for the multi-element sets. Drawn from the same
            // relation so the statement stays well-formed.
            let other = format!("{}.{}", s.alias, rng.pick(s.relation.nums));
            let clause = if allow.postgres_only {
                match rng.below(8) {
                    // The portable spellings still carry half the draw. This
                    // arm's subject is the singleton grouping; a grouping set
                    // is one more way to write one, not a different
                    // disclosure, and the plain forms are what CockroachDB
                    // also sees.
                    0..=3 => named,
                    4 => format!("ROLLUP({named})"),
                    5 => format!("CUBE({named})"),
                    6 => format!("GROUPING SETS (({named}))"),
                    // Several sets over two keys. `group_by_columns` unions
                    // the names across every set, and this is the shape that
                    // says whether it has to: a key present in only one set
                    // still makes that set's groups singletons, so reading one
                    // set instead of the union would release the value. The
                    // empty set is the grand total, which discloses nothing
                    // and must keep coming back.
                    //
                    // Only over the expression naming: an ordinal or an alias
                    // inside a multi-element set would have to be projected
                    // twice, and a statement that does not compile tests
                    // nothing.
                    _ if naming == 0 => {
                        format!("GROUPING SETS (({named}, {other}), ({named}), ())")
                    }
                    _ => named,
                }
            } else {
                named
            };
            let sql = format!(
                "SELECT {projection}{agg}({value}) AS c0 FROM {} {} GROUP BY {clause}",
                s.relation.name, s.alias
            );
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
        // The release paths that convert a refusal into an acceptance, which
        // nothing here could previously produce.
        //
        // Two of them have each cost a disclosure. `PURE_SCALARS` was 0.1.9 —
        // `pg_size_pretty` and `pg_column_size` take a *value*, so a modulo and
        // a divide reconstruct any bigint. `date_trunc` was 0.1.23 — released
        // for any unit "at or above a day" while the mask is a year, so
        // `date_trunc('day', birth_date)` returned the whole date. Both were
        // found by reading code, because no generated statement could reach
        // either path.
        //
        // Emits the unsafe spellings alongside the safe ones. An arm that only
        // produces the releasable form asserts nothing — that is exactly how
        // the grouped-aggregate arm sat here for a release projecting
        // `count(*)`, unable to find the thing it was added for.
        //
        // What the oracle can see here is uneven, and worth saying plainly. A
        // date truncated below its mask is caught, because the shape detector
        // knows a masked birth date is `01-01` and a leaked one is not — that
        // is 0.1.23's bug, so this arm is testable against a known leak. A byte
        // length from `pg_column_size(email)` is *not* caught: no detector
        // covers "a number derived from a value". Those statements exercise the
        // path and would catch a raw passthrough, nothing finer.
        11 => {
            // Same reason as arms 9 and 10: these project a date, a text size
            // or a numeric, none of which can sit opposite text in a set
            // operation.
            if !allow.typed {
                return leaf(rng, depth, n, allow);
            }
            let s = source(rng, n.wrapping_add(120));
            let sql = match rng.below(10) {
                // Truncation. The unit list mixes safe with unsafe on purpose.
                0..=2 => {
                    let unit = rng.pick(&[
                        "year", "decade", "century", "day", "week", "month", "quarter",
                    ]);
                    match s.date_col(rng) {
                        Some(col) => format!(
                            "SELECT date_trunc('{unit}', {col}) AS c0 FROM {} {}",
                            s.relation.name, s.alias
                        ),
                        // A view here has no date column; fall back rather
                        // than emit `date_trunc` over a uuid.
                        None => format!(
                            "SELECT pg_column_size({}) AS c0 FROM {} {}",
                            s.text_col(rng),
                            s.relation.name,
                            s.alias
                        ),
                    }
                }
                // Size formatters over a *value*, which must not be released.
                //
                // The releasable direction — `pg_size_pretty(pg_table_size(t))`
                // — is deliberately absent, along with `version()`,
                // `current_database()` and `pg_backend_pid()`. Their values are
                // properties of the engine and the session, so they differ
                // between Postgres and CockroachDB by construction, and this
                // corpus is shared with the cross-engine differential, whose
                // whole premise is that the same fixture and catalog produce
                // the same masked output. They were here for one run and
                // produced twelve spurious mismatches: `20` vs `20.5`, and two
                // version banners. None of them takes a column, so none can
                // leak one; unit tests are the right place for that path.
                3 | 4 => format!(
                    // Cast: `pg_size_pretty` overloads on bigint and numeric,
                    // so an int4 argument is ambiguous rather than wrong.
                    "SELECT pg_size_pretty({}::bigint) AS c0 FROM {} {}",
                    s.num_col(rng),
                    s.relation.name,
                    s.alias
                ),
                5 => format!(
                    "SELECT pg_column_size({}) AS c0 FROM {} {}",
                    s.text_col(rng),
                    s.relation.name,
                    s.alias
                ),
                // Pure scalars: over a column (refused) and over summaries
                // (released), which is the distinction the allowlist encodes.
                6 => {
                    let f = rng.pick(&["abs", "round", "floor", "ceil", "sign"]);
                    format!(
                        "SELECT {f}({}) AS c0 FROM {} {}",
                        s.num_col(rng),
                        s.relation.name,
                        s.alias
                    )
                }
                // `::numeric` so both engines do decimal division. Without it
                // Postgres integer-divides and CockroachDB does not — `20` vs
                // `20.5`, which is an arithmetic difference wearing a leak's
                // clothes.
                7 => format!(
                    "SELECT round(sum({})::numeric / greatest(count(*), 1), 1) AS c0 FROM {} {}",
                    s.num_col(rng),
                    s.relation.name,
                    s.alias
                ),
                // Not allowlisted, and must stay that way: `set_config` on
                // `application_name` was an out-of-band channel in 0.1.10, and
                // this is the query that would read it back.
                _ => "SELECT current_setting('application_name') AS c0".to_string(),
            };
            Shape {
                sql,
                cols: vec!["c0".into()],
                typed: true,
            }
        }
        // `SELECT * FROM (<inner>) alias`, in the middle of a nest.
        //
        // See [`star_over_subquery`] for why the shape matters. Here it is
        // buried under whatever arm drew it, which is the weaker half of the
        // test — the analysis only unwraps from the top, so an inner wrapper is
        // inert to it. It is still worth generating: `lineage` walks the whole
        // tree, and a star it cannot resolve has to end in a refusal rather
        // than in the wrong column. `main` puts the same wrapper where the
        // analysis will actually read it.
        12 => {
            let inner = compose(rng, next, n, allow);
            let cols = inner.cols.clone();
            wrap(star_over_subquery(rng, inner.sql, n), cols, inner.typed)
        }
        // GROUP BY, keeping the grouped value in the output.
        _ => {
            let inner = compose(rng, next, n, allow);
            let lc = inner.cols.first().cloned().unwrap_or_else(|| "c0".into());
            let sql = format!(
                "SELECT {lc}, count(*) AS c1 FROM ({}) q{n} GROUP BY {lc}",
                inner.sql
            );
            wrap(sql, vec![lc, "c1".into()], inner.typed)
        }
    }
}

/// `SELECT * FROM (<sql>) alias`, once or twice.
///
/// # Why this shape and not another wrapper
///
/// It is the one the analysis *unwraps*. `analyze_inspected` strips
/// `SELECT * FROM (subselect)` off the top and classifies the subquery's
/// target list, because the star means the outer target list has one entry
/// while the result set has many and positions cannot otherwise map. Every
/// other question the proxy asks of a statement therefore has to be asked of
/// the same unwrapped statement, and when one of them was not, the answer came
/// from the wrapper — an empty `GROUP BY` — while the value came from the
/// subquery. That was 0.1.31, and it returned every salary in the fixture
/// exactly:
///
///   SELECT id, sum(annual_salary) FROM people GROUP BY id           refused
///   SELECT * FROM (SELECT id, sum(annual_salary) …GROUP BY id) q    served
///
/// Measured over 5,000 generated statements before this change: **zero**
/// contained the shape, so the campaign could have run forever without
/// reaching it.
///
/// Twice, sometimes, because the unwrapping is a `while` and not an `if`. A
/// single layer cannot tell the two apart, and an `if` would restore the
/// disclosure with four more characters.
fn star_over_subquery(rng: &mut Rng, sql: String, n: usize) -> String {
    let once = format!("SELECT * FROM ({sql}) s{n}");
    if rng.chance(30) {
        return format!("SELECT * FROM ({once}) s{n}x");
    }
    once
}

fn main() {
    let mut args = std::env::args().skip(1);
    let seed: u64 = args.next().and_then(|v| v.parse().ok()).unwrap_or(1);
    let count: usize = args.next().and_then(|v| v.parse().ok()).unwrap_or(1000);
    // The dialect, and it fails loudly on anything else rather than falling
    // back to a default. A silent fallback here writes a corpus the caller did
    // not ask for, and a corpus nobody notices is wrong is this repo's most
    // expensive recurring failure.
    //
    // The default is the *superset*, deliberately. A new Postgres-only caller
    // that forgets the argument loses nothing; a new cross-engine caller that
    // forgets it gets statements CockroachDB rejects, which shows up as engine
    // errors in that campaign's own output. Both cross-engine scripts also
    // assert the corpus is free of Postgres-only syntax, so the mistake is
    // caught where it is made.
    let postgres_only = match args.next().as_deref() {
        None | Some("postgres") => true,
        Some("portable") => false,
        Some(other) => {
            eprintln!(
                "shapegen: unknown dialect {other:?}\n\
                 usage: shapegen <seed> <count> [postgres|portable]\n\
                 \n  postgres  everything, including ROLLUP/CUBE/GROUPING SETS (default)\
                 \n  portable  only SQL CockroachDB also accepts"
            );
            std::process::exit(2);
        }
    };
    let allow = Allow {
        typed: true,
        postgres_only,
    };
    let mut rng = Rng::new(seed);

    let mut out = String::new();
    for i in 0..count {
        // Depth 1..=3. Deeper nests mostly repeat shapes while getting slower to
        // plan, and CockroachDB starts timing out on the wide ones.
        let depth = rng.below(3).saturating_add(1);
        let shape = compose(&mut rng, depth, i, allow);
        // The star wrapper, at the top of the statement.
        //
        // Deliberately here and not left to arm 12 alone. Only the *outermost*
        // wrapper is the one the analysis reads: `analyze_inspected` and
        // `group_by_columns` both strip it from the top and judge what is
        // underneath, so that is where the two halves of the guard can be made
        // to disagree. Reaching the top from inside `compose` needs the arm
        // drawn at the outermost depth with the interesting arm directly
        // beneath it, which is about one statement in three hundred — thin
        // enough that a clean run would mean nothing, which is the same
        // mistake the grouped-aggregate arm made when it projected `count(*)`.
        //
        // Weighted towards statements that group, the same way arm 10 is
        // weighted towards the relation carrying the poison. The wrapper only
        // changes a verdict when the outer query has a clause the proxy would
        // read *instead of* the subquery's, and `GROUP BY` is that clause:
        // the wrapper's is empty, so a reader that stops at the top sees "no
        // grouping" over an aggregate that is one row per group. Drawn flat at
        // 30% this reached the disclosure in 9 corpora out of 10 at 600
        // statements — and the tenth is the failure this repo keeps having, a
        // clean run that looked like evidence.
        let wrap_chance = if shape.sql.contains(" GROUP BY ") {
            70
        } else {
            25
        };
        let sql = if rng.chance(wrap_chance) {
            star_over_subquery(&mut rng, shape.sql, i)
        } else {
            shape.sql
        };
        let _ = writeln!(out, "{sql};");
    }
    print!("{out}");
}

//! Microbenchmark the per-RowDescription statement-inspection path.
//!
//! Usage:
//!   cargo run -p bench --bin inspection --release -- [iterations]

use std::hint::black_box;
use std::time::{Duration, Instant};

use pgmask::analysis::{self, StatementInspection};

const SQL: &str = "WITH recent AS (\
    SELECT customer_id, sum(order_total) AS total \
      FROM demo.orders \
     WHERE status = 'delivered' \
     GROUP BY customer_id) \
SELECT c.city, r.total, count(*) OVER (PARTITION BY c.city) \
  FROM recent r JOIN demo.customers c ON c.id = r.customer_id";

fn measure(iterations: usize, mut operation: impl FnMut()) -> Duration {
    let start = Instant::now();
    for _ in 0..iterations {
        operation();
    }
    start.elapsed()
}

fn per_iteration(duration: Duration, iterations: usize) -> Duration {
    duration
        .checked_div(u32::try_from(iterations).unwrap_or(u32::MAX))
        .unwrap_or(Duration::ZERO)
}

const ALLOW_ALL: analysis::Relaxations = analysis::Relaxations {
    summaries: true,
    fine_date_trunc: true,
};

fn main() {
    let iterations = std::env::args()
        .nth(1)
        .and_then(|value| value.parse().ok())
        .filter(|iterations| *iterations > 0)
        .unwrap_or(10_000);

    // Warm the parser and allocator before either measurement.
    for _ in 0..100 {
        black_box(StatementInspection::new(SQL).output_safety(3, ALLOW_ALL));
    }

    let repeated = measure(iterations, || {
        black_box(analysis::analyze(SQL, 3, ALLOW_ALL));
        black_box(analysis::reads_only_server_metadata(SQL));
        black_box(analysis::provenance_is_trustworthy(SQL));
        black_box(analysis::every_relation_is_qualified(SQL));
        black_box(analysis::referenced_identifiers(SQL));
        black_box(analysis::referenced_identifiers(SQL));
    });
    let inspected = measure(iterations, || {
        let inspection = StatementInspection::new(black_box(SQL));
        black_box(inspection.output_safety(3, ALLOW_ALL));
        black_box(inspection.reads_only_server_metadata());
        black_box(inspection.provenance_is_trustworthy());
        black_box(inspection.every_relation_is_qualified());
        black_box(inspection.identifiers());
        black_box(inspection.identifiers());
    });

    let repeated_each = per_iteration(repeated, iterations);
    let inspected_each = per_iteration(inspected, iterations);
    let speedup = repeated.as_secs_f64() / inspected.as_secs_f64();
    println!("iterations={iterations}");
    println!("repeated parse/scan: {repeated_each:?} per result set");
    println!("one inspection:      {inspected_each:?} per result set");
    println!("speedup:             {speedup:.2}x");
}

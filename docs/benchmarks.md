# Benchmarks

Reproduce with `cargo run -p bench --bin bench --release -- <rows> <iters>`; see the README.
Numbers below: Apple silicon, Postgres 17.10 in podman, loopback, release build.
Loopback flatters the proxy — the extra hop is nearly free here and will not be
over a real network. Treat the per-row figure as the transferable one.

Two shapes, because they answer different questions:

- **latency** — a 1-row query repeated. The fixed cost of the extra hop, which is
  what interactive clients feel.
- **throughput** — one query returning 10,000 rows, two masked text columns
  (`pseudonym` + `redact`). The per-row cost of parsing and rewriting `DataRow`s,
  which is what a masking proxy could plausibly get wrong.

## Current

Three runs, so the figure is a range rather than false precision.

| | direct | pgmask | overhead |
|---|---|---|---|
| latency, 1 row (mean) | 0.184 ms | 0.182 ms | within noise |
| throughput, 10k rows (mean) | 1.99 ms | 4.90 ms | +2.91 ms |
| per masked row | — | — | **0.19–0.21 µs** (0.1.94; was 0.22–0.29) |
| rows/sec | 5.0 M | 2.0 M | 2.4× slower |

Interactive latency is free. Bulk scans cost roughly 2.4× — acceptable for the
agent and application clients the MVP targets, and the number to re-examine if
BI tools come into scope (open decision 5).

Result-set planning now parses and scans each statement once. The database-free
inspection benchmark measures **40.1 µs/result set**, versus **140.5 µs** for
the former repeated calls on the same representative join/CTE/window query — a
**3.5× speedup**. This does not change per-row masking cost.

The catalog refresh diff is measured the same database-free way, by
`measure_the_refresh_diff_against_the_shape_it_replaced` in `catalog.rs`:

```text
cargo test -p pgmask --release -- --ignored --nocapture the_refresh_diff
```

On a 15,809-rule catalog it costs **13.5 ms**, against **18.4 s** for the
per-rule scan of the names map it replaced (0.2.12; 28 ms against 25.5 s in a
debug build). That is per *refresh*, not per result set, and it does not change
per-row masking cost — but the refresher shares a core with session serving,
and at that catalog size the diff dominated the refresh.

## How it got there

The first working version cost **3.98 µs/row**. The benchmark existed before the
optimisation work, which is the only reason these were found rather than shipped.

| Change | µs/row | Δ |
|---|---|---|
| first working version | 3.98 | — |
| batch the flush; cheap hex; zero-copy passthrough | 2.39 | −40% |
| pre-keyed HMAC; direct frame build; no per-message `Vec` | 2.13 | −11% |
| **coalesce writes into one buffer** | **~0.25** | **−88%** |
| fuse decode/mask/encode into one pass; per-plan HMAC domain priming (0.1.94) | 0.19–0.21 | −10–20% |

The 0.1.94 row was measured back-to-back against 0.1.93 on **one** Postgres
instance: 0.21–0.26 µs/row before, 0.19–0.21 after, three runs each. That
pairing matters more than the absolute figures — across container instances in
the same hour, the *direct* path's mean for the same query varied from 2 ms to
4 ms (page cache and autovacuum state), which is wider than the effect. Compare
versions only against the same live backend, minutes apart.

The last row is the whole story. The first fix batched the *flush* but still
issued one `write_all` per message — a syscall per row. Copying each frame into
one contiguous buffer and issuing a single write replaced 10,000 syscalls with
one, and beat every algorithmic optimisation combined by a wide margin.

Worth remembering when the next performance question comes up: measure syscalls
before micro-optimising the work between them.

## Re-measuring

```bash
DIRECT_URL=... PROXY_URL=... cargo run -p bench --bin bench --release -- 10000 200
```

Run it more than once. Single-run numbers on a laptop vary by ~30%, which is
wider than several of the optimisations above.

The result-set planning path has a separate database-free microbenchmark:

```bash
cargo run -p bench --bin inspection --release -- 10000
```

It compares the former repeated parse/scan shape with one shared statement
inspection. This is per-result-set work, not per-row work.

## What is not measured yet

- Concurrency. Every number here is one connection. Per-connection memory and
  behaviour under hundreds of clients is unmeasured.
- Real network latency. Loopback hides the cost of the extra hop.
- Wide rows. Two masked columns; per-row cost should scale with masked-field
  count, but that is an assumption, not a measurement.
- `Hash`/`Partial` masks in bulk. Only `pseudonym` and `redact` are exercised.

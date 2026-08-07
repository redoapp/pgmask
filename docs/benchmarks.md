# Benchmarks

Reproduce with `cargo run -p bench --release -- <rows> <iters>`; see the README.
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

| | direct | pgmask | overhead |
|---|---|---|---|
| latency, 1 row (mean) | 0.184 ms | 0.182 ms | within noise |
| throughput, 10k rows (mean) | 1.99 ms | 4.90 ms | +2.91 ms |
| per masked row | — | — | **0.29 µs** |
| rows/sec | 5.0 M | 2.0 M | 2.4× slower |

Interactive latency is free. Bulk scans cost roughly 2.4× — acceptable for the
agent and application clients the MVP targets, and the number to re-examine if
BI tools come into scope (open decision 5).

## How it got there

The first working version cost **3.98 µs/row**. The benchmark existed before the
optimisation work, which is the only reason these were found rather than shipped.

| Change | µs/row | Δ |
|---|---|---|
| first working version | 3.98 | — |
| batch the flush; cheap hex; zero-copy passthrough | 2.39 | −40% |
| pre-keyed HMAC; direct frame build; no per-message `Vec` | 2.13 | −11% |
| **coalesce writes into one buffer** | **0.29** | **−86%** |

The last row is the whole story. The first fix batched the *flush* but still
issued one `write_all` per message — a syscall per row. Copying each frame into
one contiguous buffer and issuing a single write replaced 10,000 syscalls with
one, and beat every algorithmic optimisation combined by a wide margin.

Worth remembering when the next performance question comes up: measure syscalls
before micro-optimising the work between them.

## What is not measured yet

- Concurrency. Every number here is one connection. Per-connection memory and
  behaviour under hundreds of clients is unmeasured.
- Real network latency. Loopback hides the cost of the extra hop.
- Wide rows. Two masked columns; per-row cost should scale with masked-field
  count, but that is an assumption, not a measurement.
- `Hash`/`Partial` masks in bulk. Only `pseudonym` and `redact` are exercised.

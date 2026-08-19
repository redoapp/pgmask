# AGENTS.md

## Cursor Cloud specific instructions

pgmask is a single Rust product: a fail-closed column-masking proxy for
PostgreSQL (a Cargo workspace under `crates/`). Standard build/test/run commands
live in `README.md`, `.github/workflows/ci.yml`, and `scripts/`; the notes below
only capture the non-obvious environment caveats for this repo.

### Toolchain and system dependencies
- Rust is pinned to `1.97.1` via `rust-toolchain.toml`; `rustup` installs it
  automatically on the first `cargo` invocation. `cargo`, `clippy`, and `rustfmt`
  are available.
- The `pg_query` crate builds `libpg_query` from C, so a C toolchain is required.
  `clang`, `cmake`, `make`, and `pkg-config` are preinstalled in the base image.
- `psql` (postgresql-client) and `podman` are preinstalled in the base image.
  Every `scripts/test-*.sh` and `examples/demo/verify.sh` starts its own
  PostgreSQL via `podman run docker.io/library/postgres:17` and drives it with
  `psql`, so both must be present to run those suites.
- Rootless podman prints a harmless warning here: `"/" is not a shared mount,
  this could cause issues or missing mounts with rootless containers`. It works
  regardless — ignore it.

### Running the automated test suite (needs Postgres)
- Integration/adversarial/resilience tests are gated behind a `require_pg!`
  macro and connect using `PGMASK_TEST_PG=host:port`. The DSN they build is
  `postgres://postgres@host:port/db` with **no password**, so the backing
  Postgres must use **trust auth** (`POSTGRES_HOST_AUTH_METHOD=trust`).
- To mirror CI, start a trust-auth Postgres and run:
  `PGMASK_TEST_PG=127.0.0.1:5432 cargo nextest run --workspace --all-features --locked --profile ci`
  (`cargo-nextest` is preinstalled). `cargo test` also works.
- Without `PGMASK_TEST_PG`, the DB-gated tests **panic rather than skip** (by
  design). Set `PGMASK_ALLOW_SKIP=1` only if you intentionally want them skipped.

### The demo / end-to-end acceptance script
- `./examples/demo/verify.sh` is the full MVP acceptance run. Unlike the unit
  tests it uses a **password-authenticated** Postgres (to exercise SCRAM
  passthrough) and manages its own `pgmask-demo` container.
- On the current `main`, a handful of `verify.sh` assertions (e.g. 1e, 4, 6d,
  12b, 14d) fail because they assert older error-message text than the code now
  emits; pgmask still behaves correctly (it rejects the queries, just with newer
  HINT/message wording). Treat these as pre-existing script/code drift, not an
  environment problem.

### Running pgmask manually
- `cargo run --release -p pgmask -- examples/demo/catalog.toml` (or the built
  `./target/release/pgmask`). It listens on `127.0.0.1:6432` and proxies to the
  backend in the catalog. Connect a client through it, e.g.
  `PGPASSWORD=demo psql -h localhost -p 6432 -U postgres -d demo`.
- The catalog TOML is read **only at startup** — restart pgmask after editing
  policy. Logs go to stderr; `PGMASK_LOG` (falling back to `RUST_LOG`) sets the
  filter.

### Lint / static gate
- The CI `static` job (see `.github/workflows/ci.yml`) is the lint gate: `cargo
  fmt --all --check`, `cargo clippy --workspace --all-targets --all-features
  --locked -- -D warnings`, rustdoc, doctests, `cargo deny`, `cargo machete`,
  and `./scripts/check-repo-invariants.sh`.
- `cargo-deny` and `cargo-machete` are **not** preinstalled (only needed for the
  full release gate `./scripts/test-all.sh`); install on demand with
  `cargo install --locked cargo-deny cargo-machete`.

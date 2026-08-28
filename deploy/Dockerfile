# Production image: non-root, catalog bind-mounted read-only.
# Build from the repository root:
#   docker build -f deploy/Dockerfile -t pgmask:local .

FROM rust:1.97.1-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates crates
RUN cargo build --release --locked -p pgmask

FROM debian:bookworm-slim
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --no-create-home --uid 10001 pgmask
COPY --from=build /src/target/release/pgmask /usr/local/bin/pgmask
USER 10001:10001
ENTRYPOINT ["/usr/local/bin/pgmask"]
CMD ["/etc/pgmask/catalog.toml"]

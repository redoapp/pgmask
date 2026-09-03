# Production image: non-root, catalog bind-mounted read-only.
# Build from the repository root:
#   docker build -f deploy/Dockerfile -t pgmask:local .

FROM docker.io/library/rust:1.97.1-bookworm@sha256:408fe88047cef61a2087653b0c5255fa51c0f2d6d94ddedd7a2562a9b91a46f6 AS build
WORKDIR /src
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        clang \
        libclang-dev \
    && rm -rf /var/lib/apt/lists/*
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates crates
RUN cargo build --release --locked -p pgmask

FROM docker.io/library/debian:bookworm-slim@sha256:5ae3c39ebd15e229dcedd5cee596b2497182493d41ff162e824ba13fc1b2b867
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        ca-certificates \
        coreutils \
        gawk \
        grep \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --no-create-home --uid 10001 pgmask
COPY --from=build /src/target/release/pgmask /usr/local/bin/pgmask
USER 10001:10001
ENTRYPOINT ["/usr/local/bin/pgmask"]
CMD ["/etc/pgmask/catalog.toml"]

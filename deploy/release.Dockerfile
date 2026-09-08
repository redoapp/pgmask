# Release image: the published release binary, not a rebuild of it.
#
# The build context is a staging directory holding the extracted
# `pgmask-x86_64-unknown-linux-gnu.tar.xz` from the GitHub Release, whose
# checksum has already been verified against the release's own `.sha256`.
# `deploy/Dockerfile` compiles from source for local and compose use; this one
# deliberately does not, so the artifact that was tested is the artifact that
# runs. `[profile.dist]` differs from `--release`, so a rebuild here would ship
# a binary nobody checksummed.
#
# Built by .github/workflows/publish-image.yml. To reproduce by hand:
#   tar -xJf pgmask-x86_64-unknown-linux-gnu.tar.xz -C stage --strip-components=1
#   docker build -f deploy/release.Dockerfile -t pgmask:0.0.0 stage

# debian:bookworm-slim, pinned by digest. This is the same base Redo's Bazel
# build already pins, so the image an operator runs keeps the userspace it has
# been running.
FROM debian@sha256:ccb33c3ac5b02588fc1d9e4fc09b952e433d0c54d8618d0ee1afadf1f3cf2455
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --no-create-home --uid 10001 pgmask
COPY pgmask /usr/local/bin/pgmask
RUN chmod 0555 /usr/local/bin/pgmask
USER 10001:10001
ENTRYPOINT ["/usr/local/bin/pgmask"]
CMD ["/etc/pgmask/catalog.toml"]

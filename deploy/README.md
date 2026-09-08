# Deploying pgmask

pgmask is a long-running proxy, not a library. These files are the unit an
operator can copy without inventing a worse one.

## systemd

1. Install the `pgmask` binary from a [GitHub Release](https://github.com/redoapp/pgmask/releases)
   (or `cargo build --release -p pgmask`) to `/usr/local/bin/pgmask`.
2. `useradd --system --no-create-home --shell /usr/sbin/nologin pgmask`
3. Install `catalog.toml` (and TLS PEMs) under `/etc/pgmask/`, mode `0640`,
   owned by `root:pgmask`.
4. Copy `pgmask.service` to `/etc/systemd/system/`, `systemctl daemon-reload`,
   `systemctl enable --now pgmask`.

`ExecReload` sends `SIGHUP`. `ProtectSystem=strict` and an empty
`CapabilityBoundingSet` are load-bearing: the process sees unmasked rows from
Postgres, so it must not be able to write the host or bind privileged ports.

`SIGTERM` does not drain in-flight result sets. Run at least two instances
behind a TCP load balancer for a rolling restart.

Health check: open a PostgreSQL connection through pgmask (`SELECT 1`). A
process check does not prove the catalog loaded or the backend is reachable.

## Container

Every release publishes an image built from that release's own archive:

```
ghcr.io/redoapp/pgmask:<version>
```

Pin it by digest. It carries the binary and nothing else — no catalog — so the
catalog still arrives as a mount, exactly as it does under systemd. `deploy/release.Dockerfile`
copies the published archive rather than recompiling: `[profile.dist]` is not
`--release`, so a rebuild would ship a binary no checksum covers.

To build locally instead, from source:

```bash
docker build -f deploy/Dockerfile -t pgmask:local .
docker compose -f deploy/compose.yaml up --build
```

Either image runs as uid 10001, drops all capabilities, and is read-only. The
catalog is bind-mounted. Do not publish Postgres to the host; the compose file
does not.

## Metrics

Leave `metrics_listen` unset unless a scraper needs it. If you set it, bind
loopback (`127.0.0.1:9464`). A non-loopback address is warned at start: the
text is unauthenticated and the counters name SQL shapes.

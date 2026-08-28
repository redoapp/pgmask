#!/usr/bin/env bash
# Readiness probes shared by every suite that starts a database container.
#
# WHY THIS FILE EXISTS
#
# Seven suites each had their own copy of
#
#   for _ in $(seq 1 30); do
#     podman exec "$C" pg_isready -U postgres >/dev/null 2>&1 && break
#     sleep 1
#   done
#
# and all seven were wrong in the same two ways.
#
# 1. `pg_isready` answers YES before the database a suite can use exists.
#    The official postgres image runs a *temporary* server during
#    initialisation to create the cluster and run the init scripts. That
#    server listens on the unix socket only — `listen_addresses=''` — and
#    `podman exec … pg_isready` talks to exactly that socket. Measured on this
#    machine: `pg_isready` says YES at 3s, a socket query still fails at 3s and
#    succeeds at 4s, and the host TCP port is not reachable at 13s. The
#    temporary server is then shut down and the real one started, so "ready"
#    can be followed by "not ready" and the loop has already returned.
#
# 2. The loop `break`s on success and simply falls through on exhaustion, so a
#    timeout is indistinguishable from readiness. Everything after it runs
#    against a database that is not there, and reports whatever that produces.
#
# Both bit at once in `test-tls.sh`: the probe returned during the window,
# `ALTER SYSTEM SET ssl = on` hit a socket that was not accepting yet, its
# error went to a discarded stream, the fall-through carried on, and the
# channel-binding assertion later failed reporting that the server refused TLS
# — a true statement about a database the suite never configured.
#
# THE DISCRIMINATOR
#
# The temporary server is socket-only; the real server listens on TCP. So a
# query answered *over the mapped host port* is unambiguous: it cannot be the
# init server, and it proves the exact path the suite is about to use. That is
# what `pg_await` waits for, whether the suite goes on to use psql from the
# host or `podman exec`.
#
# Nothing here `break`s into a fall-through. Every path either returns 0 or
# ends the run with the container's own logs on screen.

# pg_await <container> <host_port> [label] [timeout_seconds]
pg_await() {
  local container="$1" port="$2" label="${3:-startup}" budget="${4:-180}"
  local deadline=$(($(date +%s) + budget))
  while [[ "$(date +%s)" -lt "$deadline" ]]; do
    if [[ "$(psql "host=127.0.0.1 port=$port user=postgres dbname=postgres" \
              -X -tAq -c 'SELECT 1' 2>/dev/null | tr -d '[:space:]')" == "1" ]]; then
      return 0
    fi
    sleep 1
  done
  echo "FATAL: postgres in $container was not answering on 127.0.0.1:$port after ${budget}s ($label)"
  echo "       This is the real server, not the init server — see scripts/lib/container.sh."
  "${CONTAINER_ENGINE:-podman}" logs "$container" 2>&1 | tail -15
  return 1
}

# crdb_await <container> <host_port> [label] [timeout_seconds]
#
# CockroachDB has no init-server phase, but it does accept TCP before it will
# answer SQL, so the same "answer a query on the port the suite will use" rule
# applies. `root` rather than `postgres`, and `defaultdb` rather than
# `postgres`.
crdb_await() {
  local container="$1" port="$2" label="${3:-startup}" budget="${4:-180}"
  local deadline=$(($(date +%s) + budget))
  while [[ "$(date +%s)" -lt "$deadline" ]]; do
    if [[ "$(psql "host=127.0.0.1 port=$port user=root dbname=defaultdb sslmode=disable" \
              -X -tAq -c 'SELECT 1' 2>/dev/null | tr -d '[:space:]')" == "1" ]]; then
      return 0
    fi
    sleep 1
  done
  echo "FATAL: CockroachDB in $container was not answering on 127.0.0.1:$port after ${budget}s ($label)"
  "${CONTAINER_ENGINE:-podman}" logs "$container" 2>&1 | tail -20
  return 1
}

# proxy_await <psql-dsn> [label] [timeout_seconds]
#
# pgmask resolves its entire catalog before it binds, so how long it takes to
# accept a connection scales with the catalog and with how busy the machine is.
# Suites waited on it with `sleep 2`, `sleep 3` and `sleep 4`, which is a guess
# about someone else's machine. Under the full gate those guesses expired and
# four suites reported "proxy did not come up" about a proxy that was still
# starting — indistinguishable, in the log, from one that had crashed.
#
# Poll the thing you are about to use, and fail loudly with the proxy's own log.
proxy_await() {
  local dsn="$1" label="${2:-proxy}" budget="${3:-90}"
  local deadline=$(($(date +%s) + budget))
  while [[ "$(date +%s)" -lt "$deadline" ]]; do
    if [[ "$(psql -w "$dsn" -X -tAq -c 'SELECT 1' 2>/dev/null | tr -d '[:space:]')" == "1" ]]; then
      return 0
    fi
    sleep 0.5
  done
  echo "FAIL: proxy did not answer within ${budget}s ($label)"
  return 1
}

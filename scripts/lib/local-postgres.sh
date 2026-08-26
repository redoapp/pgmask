#!/usr/bin/env bash
# Start a trust-auth Postgres on the host when no container runtime is
# available. Cloud Agent VMs typically have neither podman nor a writable
# `/var/run/postgresql`, so the cluster lives under `$HOME` and listens on
# TCP plus a unix socket in `/tmp`.
#
# The official image's init server is not in play here: there is one
# `pg_ctl start`, and readiness is a query on the host TCP port the tests
# will use — the same discriminator as `pg_await` in container.sh.

local_pg_bin() {
  if command -v pg_config >/dev/null 2>&1; then
    pg_config --bindir
  else
    echo /usr/lib/postgresql/16/bin
  fi
}

local_pg_data() {
  echo "${PGMASK_LOCAL_PGDATA:-$HOME/pgmask-local-pg}"
}

# local_pg_ready <host_port>
local_pg_ready() {
  local port="$1"
  [[ "$(psql "host=127.0.0.1 port=$port user=postgres dbname=postgres" \
        -X -tAq -c 'SELECT 1' 2>/dev/null | tr -d '[:space:]')" == "1" ]]
}

# local_pg_await <host_port> [label] [timeout_seconds]
local_pg_await() {
  local port="$1" label="${2:-local postgres}" budget="${3:-60}"
  local deadline=$(($(date +%s) + budget))
  while [[ "$(date +%s)" -lt "$deadline" ]]; do
    local_pg_ready "$port" && return 0
    sleep 1
  done
  echo "FATAL: local postgres was not answering on 127.0.0.1:$port after ${budget}s ($label)"
  local log
  log="$(local_pg_data)/server.log"
  [[ -f "$log" ]] && tail -15 "$log"
  return 1
}

# local_pg_start <host_port>
#
# Idempotent. Reuses a cluster already answering on the port. Unix sockets go
# in `/tmp` because `/var/run/postgresql` is root-owned on a stock Ubuntu
# install and pgmask's raw-wire tests only need TCP.
local_pg_start() {
  local port="$1"
  local bin data
  bin="$(local_pg_bin)"
  data="$(local_pg_data)"

  if local_pg_ready "$port"; then
    echo "==> reusing local postgres already answering on :$port"
    return 0
  fi

  command -v psql >/dev/null 2>&1 || {
    echo "FAIL: psql is required to start a local Postgres (install postgresql / postgresql-client)"
    return 1
  }
  [[ -x "$bin/initdb" && -x "$bin/pg_ctl" ]] || {
    echo "FAIL: initdb/pg_ctl not found under $bin (install postgresql)"
    return 1
  }

  mkdir -p "$data" /tmp
  if [[ ! -f "$data/PG_VERSION" ]]; then
    echo "==> initdb $data (trust auth, user postgres)"
    "$bin/initdb" -D "$data" -A trust -U postgres --locale=C.UTF-8 >/dev/null
  fi

  echo "==> starting local postgres on 127.0.0.1:$port (sockets in /tmp)"
  "$bin/pg_ctl" -D "$data" -l "$data/server.log" \
    -o "-h 127.0.0.1 -k /tmp -p $port" start >/dev/null
  local_pg_await "$port" "local start"
}

# local_pg_stop
local_pg_stop() {
  local bin data
  bin="$(local_pg_bin)"
  data="$(local_pg_data)"
  [[ -d "$data" && -x "$bin/pg_ctl" ]] || return 0
  "$bin/pg_ctl" -D "$data" -m fast stop >/dev/null 2>&1 || true
}

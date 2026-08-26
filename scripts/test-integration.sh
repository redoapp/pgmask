#!/usr/bin/env bash
# Run the adversarial suite against a real Postgres.
#
#   ./scripts/test-integration.sh [cargo test args...]
#
# Uses `trust` auth so the raw wire client does not have to implement SCRAM.
# SCRAM passthrough is covered separately by examples/demo/verify.sh, which runs
# against a password-authenticated server.
#
# Backend selection, first match:
#   1. `PGMASK_TEST_PG` already set — use it, start nothing
#   2. `podman` available — official postgres:17 image (CI / local containers)
#   3. host `postgresql` packages — a trust cluster on :55433 (Cloud Agents)

set -euo pipefail
cd "$(dirname "$0")/.."
source "$(dirname "$0")/lib/container.sh"
source "$(dirname "$0")/lib/local-postgres.sh"

CONTAINER=pgmask-test
PORT=55433
BACKEND=

cleanup() {
  if [[ "${KEEP:-0}" != "1" ]]; then
    case "$BACKEND" in
      podman) podman rm -f -v "$CONTAINER" >/dev/null 2>&1 || true ;;
      local) local_pg_stop ;;
    esac
  fi
}
trap cleanup EXIT

if [[ -n "${PGMASK_TEST_PG:-}" ]]; then
  echo "==> using existing postgres at $PGMASK_TEST_PG"
  BACKEND=external
elif command -v podman >/dev/null 2>&1; then
  BACKEND=podman
  echo "==> starting postgres (trust auth) on :$PORT via podman"
  podman rm -f -v "$CONTAINER" >/dev/null 2>&1 || true
  podman run -d --name "$CONTAINER" \
    -e POSTGRES_HOST_AUTH_METHOD=trust \
    -p "$PORT":5432 docker.io/library/postgres:17 >/dev/null
  pg_await "$CONTAINER" "$PORT" "integration" || exit 1
  export PGMASK_TEST_PG="127.0.0.1:$PORT"
else
  BACKEND=local
  echo "==> podman not found; starting a local trust postgres on :$PORT"
  local_pg_start "$PORT" || exit 1
  export PGMASK_TEST_PG="127.0.0.1:$PORT"
fi

echo "==> running adversarial suite"
# Serially: each test rebuilds the canary schema in the same database.
cargo test --test adversarial -- --test-threads=1 "$@"

echo
echo "==> running resilience suite"
cargo test --test resilience -- --test-threads=1 "$@"

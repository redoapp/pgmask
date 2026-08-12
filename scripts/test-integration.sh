#!/usr/bin/env bash
# Run the adversarial suite against a real Postgres.
#
#   ./scripts/test-integration.sh [cargo test args...]
#
# Uses `trust` auth so the raw wire client does not have to implement SCRAM.
# SCRAM passthrough is covered separately by examples/demo/verify.sh, which runs
# against a password-authenticated server.

set -euo pipefail
cd "$(dirname "$0")/.."
source "$(dirname "$0")/lib/container.sh"

CONTAINER=pgmask-test
PORT=55433

cleanup() {
  if [[ "${KEEP:-0}" != "1" ]]; then
    podman rm -f -v "$CONTAINER" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

echo "==> starting postgres (trust auth) on :$PORT"
podman rm -f -v "$CONTAINER" >/dev/null 2>&1 || true
podman run -d --name "$CONTAINER" \
  -e POSTGRES_HOST_AUTH_METHOD=trust \
  -p "$PORT":5432 docker.io/library/postgres:17 >/dev/null

pg_await "$CONTAINER" "$PORT" "integration" || exit 1

echo "==> running adversarial suite"
# Serially: each test rebuilds the canary schema in the same database.
export PGMASK_TEST_PG="127.0.0.1:$PORT"
cargo test --test adversarial -- --test-threads=1 "$@"

echo
echo "==> running resilience suite"
cargo test --test resilience -- --test-threads=1 "$@"

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

CONTAINER=pgmask-test
PORT=55433

cleanup() {
  if [[ "${KEEP:-0}" != "1" ]]; then
    podman rm -f "$CONTAINER" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

echo "==> starting postgres (trust auth) on :$PORT"
podman rm -f "$CONTAINER" >/dev/null 2>&1 || true
podman run -d --name "$CONTAINER" \
  -e POSTGRES_HOST_AUTH_METHOD=trust \
  -p "$PORT":5432 docker.io/library/postgres:17 >/dev/null

for _ in $(seq 1 30); do
  podman exec "$CONTAINER" pg_isready -U postgres >/dev/null 2>&1 && break
  sleep 1
done

echo "==> running adversarial suite"
# Serially: each test rebuilds the canary schema in the same database.
export PGMASK_TEST_PG="127.0.0.1:$PORT"
cargo test --test adversarial -- --test-threads=1 "$@"

echo
echo "==> running resilience suite"
cargo test --test resilience -- --test-threads=1 "$@"

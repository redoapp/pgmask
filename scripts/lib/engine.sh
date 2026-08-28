# Which engine the suites talk to. Prefer podman (what ./scripts/test-all.sh
# assumes). Docker is the fallback GitHub Actions actually has.
if [[ -z "${CONTAINER_ENGINE:-}" ]]; then
  if command -v podman >/dev/null 2>&1; then
    CONTAINER_ENGINE=podman
  elif command -v docker >/dev/null 2>&1; then
    CONTAINER_ENGINE=docker
  else
    echo "FAIL: podman or docker is required"
    exit 3
  fi
fi
export CONTAINER_ENGINE

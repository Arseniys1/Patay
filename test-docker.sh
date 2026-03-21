#!/usr/bin/env bash
# Run integration tests against all three backends.
# Usage: ./test-docker.sh [nginx|express|fastapi|all]
set -euo pipefail

BACKEND="${1:-all}"
PASS=0
FAIL=0

run_test() {
  local name="$1"
  local compose_files="$2"
  echo ""
  echo "════════════════════════════════════════════════════════"
  echo "  Backend: ${name}"
  echo "════════════════════════════════════════════════════════"

  # shellcheck disable=SC2086
  if docker compose $compose_files --profile test up \
      --build \
      --abort-on-container-exit \
      --exit-code-from client \
      --remove-orphans 2>&1; then
    echo "  ✓ ${name} — PASSED"
    PASS=$((PASS + 1))
  else
    echo "  ✗ ${name} — FAILED"
    FAIL=$((FAIL + 1))
  fi

  # shellcheck disable=SC2086
  docker compose $compose_files down --volumes --remove-orphans 2>/dev/null || true
}

case "$BACKEND" in
  nginx)
    run_test "nginx" "-f docker-compose.yml"
    ;;
  express)
    run_test "express" "-f docker-compose.yml -f docker-compose.express.yml"
    ;;
  fastapi)
    run_test "fastapi" "-f docker-compose.yml -f docker-compose.fastapi.yml"
    ;;
  apache)
    run_test "apache" "-f docker-compose.yml -f docker-compose.apache.yml"
    ;;
  traefik)
    run_test "traefik" "-f docker-compose.yml -f docker-compose.traefik.yml"
    ;;
  all)
    run_test "nginx"   "-f docker-compose.yml"
    run_test "express" "-f docker-compose.yml -f docker-compose.express.yml"
    run_test "fastapi" "-f docker-compose.yml -f docker-compose.fastapi.yml"
    run_test "apache"  "-f docker-compose.yml -f docker-compose.apache.yml"
    run_test "traefik" "-f docker-compose.yml -f docker-compose.traefik.yml"
    ;;
  *)
    echo "Usage: $0 [nginx|express|fastapi|apache|traefik|all]"
    exit 1
    ;;
esac

echo ""
echo "════════════════════════════════════════════════════════"
echo "  Total: ${PASS} passed, ${FAIL} failed"
echo "════════════════════════════════════════════════════════"
[ "$FAIL" -eq 0 ]

#!/usr/bin/env bash
# Exit 0 when Docker Hub answers, 1 when the registry is unreachable.
# Deploy uses this to pull base images online and keep local images offline.
set -euo pipefail

code="$(timeout 4 curl -sS -o /dev/null -w '%{http_code}' \
  --connect-timeout 3 --max-time 4 \
  https://registry-1.docker.io/v2/ 2>/dev/null || true)"

case "$code" in
  200|301|302|401) exit 0 ;;
esac
exit 1

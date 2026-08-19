# shellcheck shell=bash
# Sourced by install/upgrade/rollback. Requires ROOT and optionally KEEPPAM_HA, KEEPPAM_OBS.

keeppam_compose() {
  local args=()
  args+=(-f "$ROOT/deploy/docker-compose.yml")
  if [[ "${KEEPPAM_HA:-}" == "1" ]]; then
    args+=(-f "$ROOT/deploy/compose.ha.yml")
  fi
  if [[ "${KEEPPAM_OBS:-}" == "1" ]]; then
    args+=(--profile obs)
  fi
  docker compose "${args[@]}" "$@"
}

keeppam_wait_ready() {
  local api="${API:-http://127.0.0.1:8080}"
  local i ok=0
  for i in $(seq 1 40); do
    if curl -sf "$api/readyz" >/dev/null 2>&1 || curl -sf "$api/healthz" >/dev/null 2>&1; then
      ok=1
      break
    fi
    sleep 3
  done
  [[ "$ok" -eq 1 ]]
}

keeppam_need_docker() {
  command -v docker >/dev/null || { echo "docker not found" >&2; return 1; }
  docker compose version >/dev/null 2>&1 || { echo "docker compose plugin not found" >&2; return 1; }
}

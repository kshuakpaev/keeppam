# shellcheck shell=bash
# Sourced by install/upgrade/rollback. Requires ROOT and optionally KEEPPAM_HA, KEEPPAM_OBS, KEEPPAM_BRAND.

# KEEPPAM_BRAND=1 (default): compose.branded.yml + retag upstream → keeppam-* (T-03).
# HA brand overrides: compose.branded-ha.yml (only with KEEPPAM_HA) — never put edge/api-b
# into compose.branded.yml or Compose invents those services without the HA overlay.
# KEEPPAM_BRAND=0: upstream image names from docker-compose.yml (local make up).

keeppam_brand_on() {
  [[ "${KEEPPAM_BRAND:-1}" != "0" ]]
}

keeppam_retag() {
  keeppam_brand_on || return 0
  local map="$ROOT/deploy/image-brand-map.txt"
  [[ -f "$map" ]] || return 0
  if [[ -x "$ROOT/scripts/keeppam-retag.sh" ]]; then
    echo "== retag KeepPAM brand images =="
    "$ROOT/scripts/keeppam-retag.sh" "$map"
  fi
}

keeppam_compose() {
  local args=()
  local ha="${KEEPPAM_HA:-}"
  args+=(-f "$ROOT/deploy/docker-compose.yml")
  if [[ "$ha" == "1" ]]; then
    args+=(-f "$ROOT/deploy/compose.ha.yml")
  elif [[ "$ha" == "3" ]]; then
    args+=(-f "$ROOT/deploy/compose.ha.yml" -f "$ROOT/deploy/compose.ha3.yml")
  fi
  if keeppam_brand_on && [[ -f "$ROOT/deploy/compose.branded.yml" ]]; then
    args+=(-f "$ROOT/deploy/compose.branded.yml")
  fi
  if keeppam_brand_on && [[ "$ha" == "1" || "$ha" == "3" ]] && [[ -f "$ROOT/deploy/compose.branded-ha.yml" ]]; then
    args+=(-f "$ROOT/deploy/compose.branded-ha.yml")
  fi
  if [[ "${KEEPPAM_OBS:-}" == "1" ]]; then
    args+=(--profile obs)
  fi
  if [[ "${KEEPPAM_AI:-}" == "1" ]] && [[ -f "$ROOT/deploy/compose.ai.yml" ]]; then
    args+=(-f "$ROOT/deploy/compose.ai.yml")
  fi
  docker compose "${args[@]}" "$@"
}

keeppam_api_url() {
  local port="${KEEPPAM_API_HOST_PORT:-}"
  if [[ -z "$port" && -f "${ROOT:-}/deploy/.env" ]]; then
    port="$(grep -E '^[[:space:]]*KEEPPAM_API_HOST_PORT=' "$ROOT/deploy/.env" 2>/dev/null | tail -1 | cut -d= -f2- | tr -d ' \r"')"
  fi
  port="${port:-8080}"
  echo "http://127.0.0.1:${port}"
}

keeppam_wait_ready() {
  local api="${API:-$(keeppam_api_url)}"
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

# Append "name id" lines for rollback (branded tags preferred when brand on).
keeppam_snapshot_images() {
  local out="$1"
  local list="${2:-}"
  : > "$out"
  local img id
  if [[ -n "$list" && -f "$list" ]]; then
    while read -r img; do
      [[ -z "$img" || "$img" == \#* ]] && continue
      if id="$(docker image inspect -f '{{.Id}}' "$img" 2>/dev/null)"; then
        echo "$img $id" >> "$out"
      fi
    done < "$list"
  fi
  if keeppam_brand_on && [[ -f "$ROOT/deploy/image-brand-map.txt" ]]; then
    while IFS= read -r line || [[ -n "$line" ]]; do
      line="${line%%#*}"
      line="$(echo "$line" | tr -d ' \t')"
      [[ -z "$line" ]] && continue
      img="${line#*=}"
      [[ -z "$img" ]] && continue
      if id="$(docker image inspect -f '{{.Id}}' "$img" 2>/dev/null)"; then
        if ! grep -q "^${img} " "$out" 2>/dev/null; then
          echo "$img $id" >> "$out"
        fi
      fi
    done < "$ROOT/deploy/image-brand-map.txt"
  fi
}

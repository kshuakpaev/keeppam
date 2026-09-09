#!/bin/sh
set -eu
export DISPLAY=:99
W="${RDP_WIDTH:-1280}"
H="${RDP_HEIGHT:-800}"
HOST="${RDP_HOST:?RDP_HOST required}"
PORT="${RDP_PORT:-3389}"
USER="${RDP_USER:?RDP_USER required}"
PASS="${RDP_PASSWORD:-}"

Xvfb :99 -screen 0 "${W}x${H}x24" -ac +extension GLX +render -noreset >/tmp/xvfb.log 2>&1 &
for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
  if xdpyinfo -display :99 >/dev/null 2>&1; then
    break
  fi
  sleep 0.3
done

x11vnc -display :99 -forever -shared -nopw -rfbport 5900 -listen 0.0.0.0 -noxdamage -ncache 0 >/tmp/x11vnc.log 2>&1 &

DRIVE_ARGS=""
if [ -n "${DRIVE_PATH:-}" ]; then
  mkdir -p "$DRIVE_PATH"
  DRIVE_ARGS="/drive:KeepPAM,${DRIVE_PATH}"
fi
CLIP_ARGS="-clipboard"
if [ "${CLIPBOARD:-0}" = "1" ]; then
  CLIP_ARGS="+clipboard"
fi
APP_ARGS=""
if [ -n "${REMOTE_APP:-}" ]; then
  APP_ARGS="/app:${REMOTE_APP}"
  if [ -n "${REMOTE_APP_DIR:-}" ]; then
    APP_ARGS="${APP_ARGS} /app-workdir:${REMOTE_APP_DIR}"
  fi
  if [ -n "${REMOTE_APP_ARGS:-}" ]; then
    APP_ARGS="${APP_ARGS} /app-cmd:${REMOTE_APP_ARGS}"
  fi
fi

# FreeRDP 2: /cert-ignore; 3.x also accepts it as alias in many builds.
xfreerdp \
  "/v:${HOST}" \
  "/port:${PORT}" \
  "/u:${USER}" \
  "/p:${PASS}" \
  /cert-ignore \
  "/size:${W}x${H}" \
  /f \
  /bpp:24 \
  -grab-keyboard \
  ${CLIP_ARGS} \
  ${DRIVE_ARGS} \
  ${APP_ARGS} \
  >/tmp/xfreerdp.log 2>&1 &
XFREERDP_PID=$!

# mstsc → xrdp (RDP) → x11vnc → same Xvfb that xfreerdp paints.
xrdp --nodaemon --config /etc/xrdp/xrdp.ini >/tmp/xrdp.log 2>&1 &

wait "$XFREERDP_PID"
status=$?
kill 0 2>/dev/null || true
exit "$status"

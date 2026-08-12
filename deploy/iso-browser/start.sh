#!/bin/sh
set -eu
URL="${START_URL:-about:blank}"
export DISPLAY=:99

Xvfb :99 -screen 0 1280x800x24 -ac +extension GLX +render -noreset >/tmp/xvfb.log 2>&1 &
for i in 1 2 3 4 5 6 7 8 9 10; do
  if xdpyinfo -display :99 >/dev/null 2>&1; then
    break
  fi
  sleep 0.3
done

x11vnc -display :99 -forever -shared -nopw -rfbport 5900 -listen 0.0.0.0 >/tmp/x11vnc.log 2>&1 &

exec chromium \
  --no-sandbox \
  --disable-gpu \
  --disable-dev-shm-usage \
  --no-first-run \
  --disable-sync \
  --disable-features=TranslateUI \
  --disable-session-crashed-bubble \
  --user-data-dir=/tmp/chrome-profile \
  --window-size=1280,800 \
  --kiosk \
  "$URL"

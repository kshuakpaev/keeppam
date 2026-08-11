#!/usr/bin/env python3
"""Minimal HTTP encoder: POST /encode {"path":"/tmp/recordings/guac/<id>"} → MP4 beside recording."""
from __future__ import annotations

import json
import os
import subprocess
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


PORT = int(os.environ.get("PORT", "8099"))


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args) -> None:
        print("[%s] %s" % (self.log_date_time_string(), fmt % args), flush=True)

    def _json(self, code: int, obj: dict) -> None:
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path in ("/healthz", "/"):
            self._json(200, {"status": "ok"})
            return
        self._json(404, {"error": "not found"})

    def do_POST(self) -> None:
        if self.path != "/encode":
            self._json(404, {"error": "not found"})
            return
        try:
            n = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(n) if n else b"{}"
            data = json.loads(raw.decode() or "{}")
            path = data.get("path") or ""
            if not path or ".." in path or not os.path.isfile(path):
                self._json(400, {"error": "invalid path"})
                return
            mp4 = path + ".mp4"
            m4v = path + ".m4v"
            if os.path.isfile(mp4) and os.path.getsize(mp4) > 0:
                self._json(200, {"status": "ready", "mp4": mp4})
                return
            # Force encode even if lock present (ended sessions are unlocked).
            subprocess.run(
                ["guacenc", "-f", "-s", "1280x720", "-r", "2500000", path],
                check=True,
                capture_output=True,
                text=True,
            )
            if not os.path.isfile(m4v):
                self._json(500, {"error": "guacenc did not produce m4v"})
                return
            subprocess.run(
                [
                    "ffmpeg",
                    "-y",
                    "-i",
                    m4v,
                    "-c:v",
                    "libx264",
                    "-pix_fmt",
                    "yuv420p",
                    "-movflags",
                    "+faststart",
                    mp4,
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            try:
                os.remove(m4v)
            except OSError:
                pass
            self._json(200, {"status": "ready", "mp4": mp4})
        except subprocess.CalledProcessError as e:
            err = (e.stderr or e.stdout or str(e))[-2000:]
            self._json(500, {"error": "encode failed", "detail": err})
        except Exception as e:
            self._json(500, {"error": str(e), "detail": traceback.format_exc()[-1000:]})


if __name__ == "__main__":
    httpd = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print("guacenc encoder listening on :%d" % PORT, flush=True)
    httpd.serve_forever()

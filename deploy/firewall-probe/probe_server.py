#!/usr/bin/env python3
"""KeepPAM external-segment TCP probe agent (stand / lab). POST /probe → {reachable, detail}."""
from __future__ import annotations

import json
import os
import socket
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(os.environ.get("PORT", "8100"))
TIMEOUT = float(os.environ.get("PROBE_TIMEOUT_SEC", "4"))


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
            self._json(200, {"status": "ok", "service": "keeppam-firewall-probe"})
            return
        self._json(404, {"error": "not found"})

    def do_POST(self) -> None:
        if self.path != "/probe":
            self._json(404, {"error": "not found"})
            return
        try:
            n = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(n) if n else b"{}"
            data = json.loads(raw.decode() or "{}")
            host = str(data.get("host") or "").strip()
            port = int(data.get("port") or 0)
            if not host or port < 1 or port > 65535:
                self._json(400, {"error": "host and port required"})
                return
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(TIMEOUT)
            try:
                s.connect((host, port))
                self._json(200, {"reachable": True, "detail": "tcp connect ok"})
            except OSError as e:
                self._json(200, {"reachable": False, "detail": str(e)})
            finally:
                s.close()
        except Exception as e:
            self._json(500, {"error": str(e)})


if __name__ == "__main__":
    print("keeppam firewall-probe on :%d timeout=%ss" % (PORT, TIMEOUT), flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()

#!/usr/bin/env python3
"""HTTP encoder: POST /encode → MP4; POST /ocr → sampled frame OCR (Tesseract)."""
from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(os.environ.get("PORT", "8099"))
MAX_OCR_FRAMES = 20
OCR_LANG = os.environ.get("OCR_LANG", "eng")


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
        if self.path == "/encode":
            self._encode()
            return
        if self.path == "/ocr":
            self._ocr()
            return
        self._json(404, {"error": "not found"})

    def _read_json(self) -> dict:
        n = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(n) if n else b"{}"
        return json.loads(raw.decode() or "{}")

    def _encode(self) -> None:
        try:
            data = self._read_json()
            path = data.get("path") or ""
            if not path or ".." in path or not os.path.isfile(path):
                self._json(400, {"error": "invalid path"})
                return
            mp4 = path + ".mp4"
            m4v = path + ".m4v"
            if os.path.isfile(mp4) and os.path.getsize(mp4) > 0:
                self._json(200, {"status": "ready", "mp4": mp4})
                return
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

    def _ocr(self) -> None:
        try:
            data = self._read_json()
            path = data.get("path") or ""
            if not path or ".." in path or not os.path.isfile(path):
                self._json(400, {"error": "invalid path"})
                return
            max_frames = int(data.get("max_frames") or MAX_OCR_FRAMES)
            if max_frames < 1:
                max_frames = 1
            if max_frames > MAX_OCR_FRAMES:
                max_frames = MAX_OCR_FRAMES
            video = ensure_video(path)
            frames = ocr_video(video, max_frames)
            self._json(200, {"status": "ready", "frames": frames})
        except subprocess.CalledProcessError as e:
            err = (e.stderr or e.stdout or str(e))[-2000:]
            self._json(500, {"error": "ocr failed", "detail": err})
        except Exception as e:
            self._json(500, {"error": str(e), "detail": traceback.format_exc()[-1000:]})


def ensure_video(guac_path: str) -> str:
    mp4 = guac_path + ".mp4"
    m4v = guac_path + ".m4v"
    if os.path.isfile(mp4) and os.path.getsize(mp4) > 0:
        return mp4
    if os.path.isfile(m4v) and os.path.getsize(m4v) > 0:
        return m4v
    subprocess.run(
        ["guacenc", "-f", "-s", "1280x720", "-r", "2500000", guac_path],
        check=True,
        capture_output=True,
        text=True,
    )
    if os.path.isfile(m4v) and os.path.getsize(m4v) > 0:
        return m4v
    if os.path.isfile(mp4) and os.path.getsize(mp4) > 0:
        return mp4
    raise RuntimeError("guacenc did not produce video")


def probe_duration(path: str) -> float:
    out = subprocess.run(
        [
            "ffprobe",
            "-v",
            "error",
            "-show_entries",
            "format=duration",
            "-of",
            "default=noprint_wrappers=1:nokey=1",
            path,
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    try:
        return max(0.1, float(out.stdout.strip()))
    except ValueError:
        return 1.0


def clean_ocr(text: str) -> str:
    text = text.replace("\x0c", " ")
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def ocr_video(path: str, max_frames: int) -> list[dict]:
    dur = probe_duration(path)
    n = min(max_frames, max(1, int(dur // 30) + 1))
    frames: list[dict] = []
    last = ""
    with tempfile.TemporaryDirectory(prefix="keeppam-ocr-") as tmp:
        for i in range(n):
            if n == 1:
                t = min(1.0, dur * 0.05)
            else:
                t = (dur * i) / max(n - 1, 1)
            png = os.path.join(tmp, "f%03d.png" % i)
            subprocess.run(
                [
                    "ffmpeg",
                    "-y",
                    "-ss",
                    "%.3f" % t,
                    "-i",
                    path,
                    "-frames:v",
                    "1",
                    "-q:v",
                    "2",
                    png,
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            if not os.path.isfile(png) or os.path.getsize(png) == 0:
                continue
            ocr = subprocess.run(
                ["tesseract", png, "stdout", "-l", OCR_LANG, "--psm", "6"],
                capture_output=True,
                text=True,
            )
            text = clean_ocr(ocr.stdout or "")
            if len(text) < 3:
                continue
            if len(text) > 4000:
                text = text[:4000]
            if text == last:
                continue
            last = text
            frames.append({"offset": round(t, 2), "text": text})
            if len(frames) >= max_frames:
                break
    return frames


if __name__ == "__main__":
    httpd = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print("guacenc encoder listening on :%d" % PORT, flush=True)
    httpd.serve_forever()

"""
scanner_api.py – Minimal HTTP shim for the scanner container.

When the scanner runs as a Docker container (Req 4), backend-core sends scan
requests over HTTP instead of spawning a subprocess.  This module provides
a tiny HTTP server that:

  POST /scan  { "repo_path": "/tmp/scan/..." }
              → runs scan_repo() and returns the JSON result

Security:
  • Listens only on 0.0.0.0:5001 inside the container network
  • No network access out of the container (enforced at compose level)
  • All resource limits from security.py apply normally
  • Repo path must resolve inside /tmp/scan (enforced)
"""

from __future__ import annotations

import json
import os
import sys
import traceback
from http.server import BaseHTTPRequestHandler, HTTPServer

# Allow importing from scanner package
_dir = os.path.dirname(os.path.abspath(__file__))
_parent = os.path.dirname(_dir)
for p in (_parent, _dir):
    if p not in sys.path:
        sys.path.insert(0, p)

from scanner.pipeline import scan_repo
from scanner.security import is_safe_path

SCAN_ROOT = os.environ.get("SCAN_ROOT", "/tmp/scan")
PORT = int(os.environ.get("SCANNER_API_PORT", "5001"))


class ScanHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):  # silence default access log
        pass

    def _send_json(self, code: int, body: dict):
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        if self.path != "/scan":
            return self._send_json(404, {"error": "not found"})

        length = int(self.headers.get("Content-Length", 0))
        try:
            body = json.loads(self.rfile.read(length))
        except Exception:
            return self._send_json(400, {"error": "invalid JSON body"})

        repo_path = body.get("repo_path", "")
        if not repo_path:
            return self._send_json(400, {"error": "repo_path is required"})

        # Security: repo path must stay inside SCAN_ROOT
        if not is_safe_path(repo_path, SCAN_ROOT):
            return self._send_json(400, {
                "error": f"repo_path must be inside {SCAN_ROOT}"
            })

        try:
            result = scan_repo(repo_path)
            self._send_json(200, result)
        except Exception as exc:
            traceback.print_exc()
            self._send_json(500, {"error": str(exc), "status": "FAILED"})

    def do_GET(self):
        if self.path == "/health":
            return self._send_json(200, {"status": "ok"})
        self._send_json(404, {"error": "not found"})


if __name__ == "__main__":
    os.makedirs(SCAN_ROOT, exist_ok=True)
    server = HTTPServer(("0.0.0.0", PORT), ScanHandler)
    print(f"CryptoScan scanner API listening on :{PORT}", flush=True)
    server.serve_forever()

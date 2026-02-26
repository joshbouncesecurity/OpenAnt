"""
Generic attacker capture server for dynamic exploit testing.

Runs on port 9999. Captures and logs all incoming requests.
Used to verify SSRF, data exfiltration, and callback-based vulnerabilities.

Usage in docker-compose:
  attacker:
    build:
      context: .
      dockerfile: attacker.Dockerfile
    ports:
      - "9999:9999"
"""

import json
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer


captured_requests = []
lock = threading.Lock()


class CaptureHandler(BaseHTTPRequestHandler):
    """Captures all incoming HTTP requests and stores them."""

    def _handle(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8", errors="replace") if content_length else ""

        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "method": self.command,
            "path": self.path,
            "headers": dict(self.headers),
            "body": body,
        }

        with lock:
            captured_requests.append(entry)

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"captured": True}).encode())

    def do_GET(self):
        if self.path == "/health":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"status": "ok"}).encode())
            return
        if self.path == "/logs":
            with lock:
                data = list(captured_requests)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(data).encode())
            return
        self._handle()

    def do_POST(self):
        if self.path == "/logs/clear":
            with lock:
                captured_requests.clear()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"cleared": True}).encode())
            return
        self._handle()

    def do_PUT(self):
        self._handle()

    def do_DELETE(self):
        self._handle()

    def log_message(self, format, *args):
        pass  # suppress default stderr logging


if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", 9999), CaptureHandler)
    print("[attacker] Capture server listening on :9999", flush=True)
    server.serve_forever()

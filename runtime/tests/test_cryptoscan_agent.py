import hashlib
import hmac
import json
import random
import secrets
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import cryptoscan_agent


class CaptureHandler(BaseHTTPRequestHandler):
    batches = []
    captured = threading.Event()

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        self.batches.append(json.loads(self.rfile.read(length)))
        self.captured.set()
        self.send_response(200)
        self.end_headers()

    def log_message(self, *_args):
        pass


class CryptoScanAgentTests(unittest.TestCase):
    def test_real_calls_flush_metadata_only(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), CaptureHandler)
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()
        endpoint = f"http://127.0.0.1:{server.server_port}/api/runtime/sessions/session/events"
        try:
            cryptoscan_agent.start("session", endpoint, "T" * 43)
            for _ in range(2): random.random()
            secrets.token_bytes(24)
            hashlib.sha256(b"transient message").digest()
            hmac.new(b"transient key", b"transient payload", hashlib.sha256).digest()
            self.assertTrue(CaptureHandler.captured.wait(5), "agent did not flush within the test window")
            cryptoscan_agent.stop()

            events = [event for batch in CaptureHandler.batches for event in batch["events"]]
            algorithms = {event["algorithm"] for event in events}
            self.assertIn("Python random.random", algorithms)
            self.assertIn("SHA-256", algorithms)
            self.assertIn("HMAC-SHA-256", algorithms)
            random_event = next(event for event in events if event["algorithm"] == "Python random.random")
            self.assertGreaterEqual(random_event["count"], 2)
            self.assertIn("test_cryptoscan_agent.py:", random_event["callerScript"])
            self.assertTrue(all(set(event) == {
                "source", "algorithm", "operation", "keyInfo", "callerScript", "hostOrigin",
                "scheme", "port", "crossOrigin", "count", "timestamp",
            } for event in events))
            serialized = json.dumps(CaptureHandler.batches)
            self.assertNotIn("transient message", serialized)
            self.assertNotIn("transient key", serialized)
            self.assertNotIn("transient payload", serialized)
        finally:
            cryptoscan_agent.stop()
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    unittest.main()

"""
Unit and integration tests for Step 3: Python instrumentation tracer.
"""

import os
import json
import tempfile
import unittest
import subprocess
import sys


class TestStep3PythonTracer(unittest.TestCase):
    def test_python_tracer_hashlib_execution(self):
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as tmp:
            tmp_path = tmp.name

        try:
            env = os.environ.copy()
            env["CRYPTOSCAN_RUNTIME_OUT"] = tmp_path
            env["CRYPTOSCAN_RUN_ID"] = "test-run-python-123"

            cmd = [
                sys.executable,
                "-c",
                "import sys; sys.path.insert(0, '.'); from runtime.python_agent import tracer; import hashlib; hashlib.sha256(b'super_secret_payload_12345')"
            ]

            res = subprocess.run(cmd, env=env, capture_output=True, text=True, cwd=os.getcwd())
            self.assertEqual(res.returncode, 0)

            with open(tmp_path, "r", encoding="utf-8") as f:
                lines = [line.strip() for line in f if line.strip()]

            self.assertGreaterEqual(len(lines), 1)
            event = json.loads(lines[0])

            self.assertEqual(event["run_id"], "test-run-python-123")
            self.assertEqual(event["language"], "python")
            self.assertEqual(event["library"], "hashlib")
            self.assertEqual(event["operation"], "hash")
            self.assertEqual(event["algorithm"], "SHA-256")
            
            # Ensure zero secret leakage
            event_raw = json.dumps(event)
            self.assertNotIn("super_secret_payload_12345", event_raw)
            self.assertNotIn("b'super_secret_payload_12345'", event_raw)

        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)


if __name__ == "__main__":
    unittest.main()

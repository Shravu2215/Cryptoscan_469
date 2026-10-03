"""
Unit and integration tests for Step 4: Node.js instrumentation tracer.
"""

import os
import json
import tempfile
import unittest
import subprocess


class TestStep4NodeTracer(unittest.TestCase):
    def test_node_preload_crypto_hash(self):
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as tmp:
            tmp_path = tmp.name

        try:
            env = os.environ.copy()
            env["CRYPTOSCAN_RUNTIME_OUT"] = tmp_path
            env["CRYPTOSCAN_RUN_ID"] = "test-run-node-456"

            cmd = [
                "node",
                "--require",
                "./runtime/node_agent/preload.js",
                "-e",
                "require('crypto').createHash('sha256').update('secret_data_node');"
            ]

            res = subprocess.run(cmd, env=env, capture_output=True, text=True, cwd=os.getcwd())
            self.assertEqual(res.returncode, 0)

            with open(tmp_path, "r", encoding="utf-8") as f:
                lines = [line.strip() for line in f if line.strip()]

            self.assertGreaterEqual(len(lines), 1)
            event = json.loads(lines[0])

            self.assertEqual(event["run_id"], "test-run-node-456")
            self.assertEqual(event["language"], "node")
            self.assertEqual(event["library"], "node:crypto")
            self.assertEqual(event["operation"], "hash")
            self.assertEqual(event["algorithm"], "SHA-256")

            # Ensure zero secret leakage
            event_raw = json.dumps(event)
            self.assertNotIn("secret_data_node", event_raw)

        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)


if __name__ == "__main__":
    unittest.main()

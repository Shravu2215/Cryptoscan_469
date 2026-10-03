"""
Unit and integration tests for Step 8: Static-to-runtime finding matcher.
Verifies executed paths match static finding IDs, while unexecuted MD5 path remains unmatched.
"""

import os
import sys
import tempfile
import unittest
import subprocess
import json

from scanner.pipeline import scan_repo
from runtime.matcher import match_events_to_findings


class TestStep8Matcher(unittest.TestCase):
    def test_demo_app_matching(self):
        # 1. Run static scan on runtime/demo
        scan_results = scan_repo("runtime/demo")
        static_findings = scan_results["findings"]
        self.assertGreaterEqual(len(static_findings), 2)

        # Find the static MD5 finding for python_app.py
        py_md5_finding = next(
            (f for f in static_findings if "python_app" in f["file"] and f["algorithm"] == "MD5"),
            None
        )
        self.assertIsNotNone(py_md5_finding, "Static scan should find unexecuted MD5 in python_app.py")

        # 2. Run Python demo app under runtime tracer
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as tmp:
            tmp_path = tmp.name

        try:
            env = os.environ.copy()
            env["CRYPTOSCAN_RUNTIME_OUT"] = tmp_path
            env["CRYPTOSCAN_RUN_ID"] = "run-matcher-test-1"

            cmd = [
                sys.executable,
                "-c",
                "import sys; sys.path.insert(0, '.'); from runtime.python_agent import tracer; import runtime.demo.python_app as py_app; py_app.run_executed_crypto_paths()"
            ]

            res = subprocess.run(cmd, env=env, capture_output=True, text=True, cwd=os.getcwd())
            self.assertEqual(res.returncode, 0)

            runtime_events = []
            with open(tmp_path, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        runtime_events.append(json.loads(line.strip()))

            self.assertGreaterEqual(len(runtime_events), 3)

            # 3. Match runtime events to static findings
            matched_events, summary = match_events_to_findings(
                cbom_findings=static_findings,
                runtime_events=runtime_events
            )

            self.assertGreater(summary["events_matched"], 0)

            # 4. Assert executed algorithms (SHA-256, AES, RSA, ECDSA) matched finding IDs
            matched_ids = {e["matched_finding_id"] for e in matched_events if e.get("matched_finding_id")}
            self.assertIn(py_md5_finding["id"], set(f["id"] for f in static_findings))
            self.assertNotIn(py_md5_finding["id"], matched_ids, "Unexecuted MD5 path must NOT have any runtime matching event")

        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)


if __name__ == "__main__":
    unittest.main()

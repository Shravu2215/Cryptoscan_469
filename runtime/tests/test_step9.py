"""
Unit and end-to-end CLI tests for Step 9.
"""

import os
import sys
import unittest
import subprocess


class TestStep9CLI(unittest.TestCase):
    def test_cli_run_python_demo(self):
        cmd = [
            sys.executable,
            "runtime/cli.py",
            "run",
            "--lang", "python",
            "--",
            sys.executable,
            "runtime/demo/python_app.py",
        ]
        res = subprocess.run(cmd, capture_output=True, text=True, cwd=os.getcwd())
        self.assertEqual(res.returncode, 0)
        self.assertIn("Total Captured Crypto Events", res.stdout)
        self.assertIn("AES, ECDSA, RSA, SHA-256", res.stdout)

    def test_cli_run_node_demo(self):
        cmd = [
            sys.executable,
            "runtime/cli.py",
            "run",
            "--lang", "node",
            "--",
            "node",
            "runtime/demo/node_app.js",
        ]
        res = subprocess.run(cmd, capture_output=True, text=True, cwd=os.getcwd())
        self.assertEqual(res.returncode, 0)
        self.assertIn("Total Captured Crypto Events", res.stdout)
        self.assertIn("AES, ECDSA, RSA, SHA-256", res.stdout)


if __name__ == "__main__":
    unittest.main()

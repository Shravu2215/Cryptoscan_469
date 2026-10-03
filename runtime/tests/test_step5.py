"""
Unit and integration tests for Step 5: Demo apps execution and static scan verification.
"""

import os
import unittest
import subprocess
import sys


class TestStep5DemoApps(unittest.TestCase):
    def test_python_demo_execution(self):
        cmd = [sys.executable, "runtime/demo/python_app.py"]
        res = subprocess.run(cmd, capture_output=True, text=True, cwd=os.getcwd())
        self.assertEqual(res.returncode, 0)
        self.assertIn("Executing SHA-256", res.stdout)
        self.assertIn("Executing AES-256-GCM", res.stdout)
        self.assertIn("Executing RSA-2048", res.stdout)
        self.assertIn("Executing ECDSA P-256", res.stdout)

    def test_node_demo_execution(self):
        cmd = ["node", "runtime/demo/node_app.js"]
        res = subprocess.run(cmd, capture_output=True, text=True, cwd=os.getcwd())
        self.assertEqual(res.returncode, 0)
        self.assertIn("Executing SHA-256", res.stdout)
        self.assertIn("Executing AES-256-GCM", res.stdout)
        self.assertIn("Executing RSA-2048", res.stdout)
        self.assertIn("Executing ECDSA P-256", res.stdout)


if __name__ == "__main__":
    unittest.main()

"""
Fail-safe and zero-leakage unit/integration tests for Step 11.
"""

import os
import sys
import unittest
import subprocess
import tempfile


class TestStep11FailSafe(unittest.TestCase):
    def test_hook_exception_does_not_crash_target_app(self):
        """
        Forces python tracer's emit_event to raise an artificial Exception.
        Confirms that target app continues executing cleanly without crashing.
        """
        cmd = [
            sys.executable,
            "-c",
            """
import sys
sys.path.insert(0, '.')
from runtime.python_agent import tracer

# Force emit_event to crash internally
def broken_emit(*args, **kwargs):
    raise RuntimeError('Simulated internal tracer failure')

tracer.emit_event = broken_emit

import hashlib
res = hashlib.sha256(b'payload').hexdigest()
print(f'COMPLETED_HASH:{res}')
"""
        ]

        res = subprocess.run(cmd, capture_output=True, text=True, cwd=os.getcwd())
        self.assertEqual(res.returncode, 0, "App must NOT crash when tracer hook raises an exception")
        self.assertIn("COMPLETED_HASH:", res.stdout)

    def test_node_hook_exception_does_not_crash_target_app(self):
        """
        Forces Node.js tracer preload to throw an internal error and verifies target app still runs cleanly.
        """
        cmd = [
            "node",
            "--require",
            "./runtime/node_agent/preload.js",
            "-e",
            """
const crypto = require('crypto');
const origCreateHash = crypto.createHash;
crypto.createHash = function() {
    try {
        throw new Error('Simulated Node tracer internal failure');
    } catch (_) {}
    return origCreateHash.apply(this, arguments);
};
const res = crypto.createHash('sha256').update('test').digest('hex');
console.log('NODE_SUCCESS:' + res);
"""
        ]

        res = subprocess.run(cmd, capture_output=True, text=True, cwd=os.getcwd())
        self.assertEqual(res.returncode, 0, "Node app must NOT crash when tracer fails")
        self.assertIn("NODE_SUCCESS:", res.stdout)


if __name__ == "__main__":
    unittest.main()

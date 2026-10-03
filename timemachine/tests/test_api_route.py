"""
API Route Integration Test for Crypto Time Machine.
Validates CLI execution and Express API route payload schema compatibility.
"""

import json
import subprocess
import pytest


def test_cli_json_output_schema():
    """Validates python -m timemachine --json produces valid schema matching Express route requirements."""
    cmd = ["python", "-m", "timemachine", "scratch/demo_repo", "--json"]
    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    assert res.returncode == 0

    data = json.loads(res.stdout)
    assert "repository_summary" in data
    assert "findings_lifecycle" in data
    assert "leaked_secrets" in data
    assert "timeline" in data
    assert "remediation_priorities" in data

    assert data["repository_summary"]["total_commits"] == 7
    assert len(data["findings_lifecycle"]) > 0
    assert len(data["leaked_secrets"]) == 1
    assert len(data["timeline"]) == 7

"""
Unit tests for timemachine/timeline.py (Risk Timeline & Technical Debt Burndown Analysis)
"""

import json
import pytest
import tempfile
from timemachine.demo.make_demo_repo import create_demo_repo
from timemachine.history import read_repository_history
from timemachine.scan_history import HistoryScanner
from timemachine.secrets import find_history_secrets
from timemachine.timeline import compute_repository_timeline


@pytest.fixture(scope="module")
def demo_repo_path():
    with tempfile.TemporaryDirectory() as tmpdir:
        repo_dir = create_demo_repo(tmpdir)
        yield repo_dir


@pytest.fixture(scope="module")
def expected_data():
    with open("timemachine/demo/expected.json", "r", encoding="utf-8") as f:
        return json.load(f)


def test_timeline_series_matches_expected(demo_repo_path, expected_data):
    commits, _ = read_repository_history(demo_repo_path)
    scanner = HistoryScanner()
    commit_map, _ = scanner.scan_commit_trajectory(demo_repo_path, commits)
    leaked_secrets = find_history_secrets(demo_repo_path, commits)

    timeline = compute_repository_timeline(commits, commit_map, leaked_secrets)
    assert len(timeline) == 7

    expected_commits = expected_data["commit_summary"]

    for idx, pt in enumerate(timeline, 1):
        exp = expected_commits[idx - 1]

        assert pt.commit_index == exp["commit_index"]
        assert pt.weak_count == exp["weak_count"]
        assert pt.quantum_vulnerable_count == exp["quantum_vulnerable_count"]
        assert pt.total_findings == exp["total_findings"]

    # Verify risk debt trajectory: rises C1->C3, drops at C4, C5, C6, rises at C7
    debts = [pt.risk_debt for pt in timeline]
    assert debts[0] < debts[1] < debts[2]  # C1 < C2 < C3
    assert debts[3] < debts[2]             # C4 < C3 (file deleted, converted to historical leak)
    assert debts[4] < debts[3]             # C5 < C4 (MD5 replaced with SHA-256)
    assert debts[5] < debts[4]             # C6 < C5 (RSA-1024 replaced with RSA-2048)
    assert debts[6] > debts[5]             # C7 > C6 (ECDSA added)

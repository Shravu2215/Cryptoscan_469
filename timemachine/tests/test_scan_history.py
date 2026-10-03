"""
Unit tests for Step 4: Per-Commit History Scanner with Caching (timemachine/scan_history.py).
"""

import json
import os
import pytest
from timemachine.history import read_repository_history
from timemachine.scan_history import HistoryScanner
from timemachine.demo.make_demo_repo import create_demo_repo


@pytest.fixture(scope="module")
def demo_repo_path(tmp_path_factory):
    repo_dir = str(tmp_path_factory.mktemp("scan_test_repo"))
    create_demo_repo(repo_dir)
    return repo_dir


@pytest.fixture(scope="module")
def expected_data():
    expected_path = os.path.join(os.path.dirname(__file__), "..", "demo", "expected.json")
    with open(expected_path, "r", encoding="utf-8") as f:
        return json.load(f)


def test_scan_commit_trajectory_matches_expected(demo_repo_path, expected_data):
    commits, _ = read_repository_history(demo_repo_path)
    scanner = HistoryScanner()
    commit_map, metrics = scanner.scan_commit_trajectory(demo_repo_path, commits)

    assert len(commit_map) == 7
    expected_commits = expected_data["commit_summary"]

    for idx, commit in enumerate(commits, 1):
        findings = commit_map[commit.commit_hash]
        exp = expected_commits[idx - 1]

        weak_cnt = sum(1 for f in findings if f.is_weak)
        qv_cnt = sum(1 for f in findings if f.is_quantum_vulnerable)

        assert weak_cnt == exp["weak_count"], f"Commit C{idx} weak_count mismatch: actual {weak_cnt} vs expected {exp['weak_count']}"
        assert qv_cnt == exp["quantum_vulnerable_count"], f"Commit C{idx} qv_count mismatch: actual {qv_cnt} vs expected {exp['quantum_vulnerable_count']}"


def test_incremental_cache_hits_on_second_scan(demo_repo_path):
    commits, _ = read_repository_history(demo_repo_path)
    scanner = HistoryScanner()

    # First run
    _, metrics1 = scanner.scan_commit_trajectory(demo_repo_path, commits)
    misses1 = metrics1["cache_misses"]
    assert misses1 > 0

    # Second run with same scanner instance
    _, metrics2 = scanner.scan_commit_trajectory(demo_repo_path, commits)
    hits2 = metrics2["cache_hits"]
    assert hits2 > 0
    assert metrics2["cache_misses"] == misses1  # No new misses on second run

"""
Unit tests for timemachine/lifecycle.py
"""

import json
import pytest
import tempfile
from timemachine.demo.make_demo_repo import create_demo_repo
from timemachine.history import read_repository_history
from timemachine.scan_history import HistoryScanner
from timemachine.lifecycle import compute_findings_lifecycle, format_lifecycle_table


@pytest.fixture(scope="module")
def demo_repo_path():
    with tempfile.TemporaryDirectory() as tmpdir:
        repo_dir = create_demo_repo(tmpdir)
        yield repo_dir


@pytest.fixture(scope="module")
def expected_data():
    with open("timemachine/demo/expected.json", "r", encoding="utf-8") as f:
        return json.load(f)


def test_lifecycle_tracking_matches_expected(demo_repo_path, expected_data):
    commits, _ = read_repository_history(demo_repo_path)
    scanner = HistoryScanner()
    commit_map, _ = scanner.scan_commit_trajectory(demo_repo_path, commits)

    lifecycles = compute_findings_lifecycle(commits, commit_map)
    lc_map = {lc.finding_key: lc for lc in lifecycles}

    expected_lifecycles = expected_data["findings_lifecycle"]

    for exp in expected_lifecycles:
        fkey = exp["finding_key"]
        assert fkey in lc_map, f"Finding key {fkey} not found in lifecycle output"
        actual = lc_map[fkey]

        assert actual.algorithm == exp["algorithm"]
        assert actual.file == exp["file"]
        assert actual.introduced_commit_index == exp["introduced_commit_index"]
        assert actual.removed_commit_index == exp["removed_commit_index"]
        assert actual.exposure_commits == exp["exposure_commits"]
        assert actual.exposure_days == exp["exposure_days"]
        assert actual.still_present == exp["still_present"]


def test_format_lifecycle_table(demo_repo_path):
    commits, _ = read_repository_history(demo_repo_path)
    scanner = HistoryScanner()
    commit_map, _ = scanner.scan_commit_trajectory(demo_repo_path, commits)
    lifecycles = compute_findings_lifecycle(commits, commit_map)

    table_str = format_lifecycle_table(lifecycles)
    assert "Finding Key" in table_str
    assert "MD5" in table_str
    assert "C1" in table_str
    assert "C5" in table_str
    assert "Active" in table_str
    assert "Remediated" in table_str

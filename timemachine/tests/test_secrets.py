"""
Unit tests for timemachine/secrets.py (Leaked Secret Analysis & Zero-Exposure Redaction Verification)
"""

import json
import pytest
import re
import tempfile
from timemachine.demo.make_demo_repo import create_demo_repo
from timemachine.history import read_repository_history
from timemachine.secrets import find_history_secrets, LeakedSecret


@pytest.fixture(scope="module")
def demo_repo_path():
    with tempfile.TemporaryDirectory() as tmpdir:
        repo_dir = create_demo_repo(tmpdir)
        yield repo_dir


@pytest.fixture(scope="module")
def expected_data():
    with open("timemachine/demo/expected.json", "r", encoding="utf-8") as f:
        return json.load(f)


def test_leaked_secrets_matches_expected(demo_repo_path, expected_data):
    commits, _ = read_repository_history(demo_repo_path)
    secrets = find_history_secrets(demo_repo_path, commits)

    expected_secrets = expected_data["leaked_secrets"]
    assert len(secrets) == len(expected_secrets)

    sec = secrets[0]
    exp = expected_secrets[0]

    assert sec.file == exp["file"]
    assert sec.secret_type == exp["secret_type"]
    assert sec.added_commit_index == exp["added_commit_index"]
    assert sec.removed_commit_index == exp["removed_commit_index"]
    assert sec.present_in_history == exp["present_in_history"]
    assert sec.recommendation == "Rotate this key. Deleting a file does not remove it from Git history."
    assert len(sec.fingerprint) == 16


def test_zero_secret_exposure_redaction(demo_repo_path):
    commits, _ = read_repository_history(demo_repo_path)
    secrets = find_history_secrets(demo_repo_path, commits)

    raw_json_str = json.dumps([s.to_dict() for s in secrets])

    # Assert raw PEM key content (e.g., base64 key material) is NEVER present in outputs or dicts
    assert "MIIEowIBAAKCAQEAzDUMMYR5UEEtVl6K" not in raw_json_str
    assert "DUMMY DUMMY DUMMY" not in raw_json_str

    # Ensure no base64 key data following PRIVATE KEY-----
    pattern = re.compile(r"PRIVATE KEY-----\s+[A-Za-z0-9+/=]{10,}")
    assert not pattern.search(raw_json_str), "Found un-redacted private key content in outputs!"

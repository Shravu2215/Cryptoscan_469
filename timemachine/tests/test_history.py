"""
Unit tests for Step 3: Git History Reader (timemachine/history.py).
"""

import os
import pytest
from timemachine.history import read_repository_history, read_blob_content
from timemachine.demo.make_demo_repo import create_demo_repo


@pytest.fixture(scope="module")
def demo_repo_path(tmp_path_factory):
    repo_dir = str(tmp_path_factory.mktemp("history_test_repo"))
    create_demo_repo(repo_dir)
    return repo_dir


def test_read_repository_history_7_commits(demo_repo_path):
    commits, is_shallow = read_repository_history(demo_repo_path)
    assert len(commits) == 7
    assert is_shallow is False

    # Check commits oldest to newest
    assert commits[0].commit_index == 1
    assert "C1: Add app.py" in commits[0].message
    assert commits[0].changed_files == ["app.py"]

    assert commits[1].commit_index == 2
    assert "C2: Add RSA-1024" in commits[1].message
    assert commits[1].changed_files == ["keys.py"]

    assert commits[2].commit_index == 3
    assert "C3: Commit deploy_key.pem" in commits[2].message
    assert commits[2].changed_files == ["deploy_key.pem"]

    assert commits[3].commit_index == 4
    assert "C4: Delete deploy_key.pem" in commits[3].message
    assert commits[3].changed_files == ["deploy_key.pem"]
    assert commits[3].file_status_map["deploy_key.pem"] == "D"

    assert commits[4].commit_index == 5
    assert "C5: Replace MD5" in commits[4].message
    assert commits[4].changed_files == ["app.py"]

    assert commits[5].commit_index == 6
    assert "C6: Replace RSA-1024" in commits[5].message
    assert commits[5].changed_files == ["keys.py"]

    assert commits[6].commit_index == 7
    assert "C7: Add ECDSA" in commits[6].message
    assert commits[6].changed_files == ["sign.py"]


def test_read_blob_content(demo_repo_path):
    commits, _ = read_repository_history(demo_repo_path)
    c1 = commits[0].commit_hash
    c3 = commits[2].commit_hash

    blob1 = read_blob_content(demo_repo_path, c1, "app.py")
    assert blob1.filepath == "app.py"
    assert blob1.is_binary is False
    assert "md5" in blob1.content.lower()

    blob3 = read_blob_content(demo_repo_path, c3, "deploy_key.pem")
    assert blob3.filepath == "deploy_key.pem"
    assert "DUMMY" in blob3.content

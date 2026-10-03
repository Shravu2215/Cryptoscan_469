"""
Safe, Read-Only Git History Inspection Engine for Crypto Time Machine.
Reads Git commit history, file changes, and blob contents using read-only Git plumbing.
Never checks out working trees or executes repository code.
"""

from dataclasses import dataclass, field
import os
import re
import subprocess
import sys
from typing import List, Dict, Any, Optional, Tuple

MAX_BLOB_SIZE_BYTES = 2 * 1024 * 1024  # 2MB cap per file blob
BINARY_KEYSTORE_EXTS = {".p12", ".pfx", ".jks", ".keystore"}


@dataclass
class BlobInfo:
    filepath: str
    blob_sha: str
    size_bytes: int
    is_binary: bool
    is_keystore: bool
    keystore_type: Optional[str] = None
    content: Optional[str] = None


@dataclass
class CommitInfo:
    commit_hash: str
    short_hash: str
    author_name: str
    author_email: str
    author_date: str
    message: str
    commit_index: int
    changed_files: List[str] = field(default_factory=list)
    file_status_map: Dict[str, str] = field(default_factory=dict)  # filepath -> status ('A', 'M', 'D', 'R')
    blobs: Dict[str, BlobInfo] = field(default_factory=dict)


def run_git_command(args: List[str], cwd: str) -> str:
    """Run git plumbing command with hooks disabled."""
    env = os.environ.copy()
    if sys.platform == "win32":
        env["GIT_CONFIG_PARAMETERS"] = "'core.hooksPath=NUL'"
    else:
        env["GIT_CONFIG_PARAMETERS"] = "'core.hooksPath=/dev/null'"

    cmd = ["git"] + args
    res = subprocess.run(cmd, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, errors="replace")
    if res.returncode != 0:
        raise RuntimeError(f"Git command failed ({' '.join(args)}): {res.stderr.strip()}")
    return res.stdout.strip()


def check_is_shallow_repo(repo_path: str) -> bool:
    """Check if repository is a shallow clone."""
    try:
        res = run_git_command(["rev-parse", "--is-shallow-repository"], cwd=repo_path)
        return res.lower() == "true"
    except Exception:
        return False


def is_binary_string(data: bytes) -> bool:
    """Check if byte buffer contains binary data (NULL bytes or non-text control chars)."""
    if b"\x00" in data:
        return True
    return False


def read_blob_content(repo_path: str, commit_hash: str, filepath: str) -> BlobInfo:
    """Read a file blob at a specific commit using git cat-file / git show."""
    ext = os.path.splitext(filepath)[1].lower()
    is_ks = ext in BINARY_KEYSTORE_EXTS
    ks_type = f"{ext[1:].upper()} Keystore" if is_ks else None

    # Get blob SHA & size
    try:
        obj_info = run_git_command(["rev-parse", f"{commit_hash}:{filepath}"], cwd=repo_path)
        blob_sha = obj_info.strip()
    except Exception:
        blob_sha = ""

    try:
        size_str = run_git_command(["cat-file", "-s", f"{commit_hash}:{filepath}"], cwd=repo_path)
        size_bytes = int(size_str.strip())
    except Exception:
        size_bytes = 0

    if size_bytes > MAX_BLOB_SIZE_BYTES:
        return BlobInfo(
            filepath=filepath,
            blob_sha=blob_sha,
            size_bytes=size_bytes,
            is_binary=True,
            is_keystore=is_ks,
            keystore_type=ks_type,
            content=None,
        )

    # Read blob raw bytes via git cat-file -p
    env = os.environ.copy()
    if sys.platform == "win32":
        env["GIT_CONFIG_PARAMETERS"] = "'core.hooksPath=NUL'"
    else:
        env["GIT_CONFIG_PARAMETERS"] = "'core.hooksPath=/dev/null'"

    cmd = ["git", "cat-file", "-p", f"{commit_hash}:{filepath}"]
    res = subprocess.run(cmd, cwd=repo_path, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    if res.returncode != 0:
        return BlobInfo(
            filepath=filepath,
            blob_sha=blob_sha,
            size_bytes=size_bytes,
            is_binary=False,
            is_keystore=is_ks,
            keystore_type=ks_type,
            content=None,
        )

    raw_bytes = res.stdout
    is_bin = is_binary_string(raw_bytes) or is_ks

    if is_bin:
        return BlobInfo(
            filepath=filepath,
            blob_sha=blob_sha,
            size_bytes=len(raw_bytes),
            is_binary=True,
            is_keystore=is_ks,
            keystore_type=ks_type,
            content=None,
        )

    content_str = raw_bytes.decode("utf-8", errors="replace")
    return BlobInfo(
        filepath=filepath,
        blob_sha=blob_sha,
        size_bytes=len(raw_bytes),
        is_binary=False,
        is_keystore=is_ks,
        keystore_type=ks_type,
        content=content_str,
    )


def read_repository_history(
    repo_path: str,
    ref: str = "HEAD",
    since: Optional[str] = None,
    max_commits: int = 500,
    first_parent_only: bool = True,
) -> Tuple[List[CommitInfo], bool]:
    """
    Reads commit trajectory and changed files from oldest to newest.
    Returns (commits_list, is_shallow_warning).
    """
    abs_repo = os.path.abspath(repo_path)
    if not os.path.exists(abs_repo):
        raise FileNotFoundError(f"Git repository path not found: {abs_repo}")

    is_shallow = check_is_shallow_repo(abs_repo)

    # Build git log command
    log_args = ["log", "--reverse", "--format=%H|%an|%ae|%aI|%s"]
    if first_parent_only:
        log_args.append("--first-parent")
    if since:
        log_args.append(f"--since={since}")
    if max_commits:
        log_args.extend(["-n", str(max_commits)])
    log_args.append(ref)

    raw_log = run_git_command(log_args, cwd=abs_repo)
    if not raw_log.strip():
        return [], is_shallow

    commits: List[CommitInfo] = []
    lines = raw_log.strip().splitlines()

    for idx, line in enumerate(lines, 1):
        parts = line.split("|", 4)
        if len(parts) < 5:
            continue
        c_hash, author_name, author_email, author_date, message = parts

        commit_obj = CommitInfo(
            commit_hash=c_hash,
            short_hash=c_hash[:7],
            author_name=author_name,
            author_email=author_email,
            author_date=author_date,
            message=message,
            commit_index=idx,
        )

        # Retrieve file changes for this commit
        if idx == 1:
            # First commit: list all files in tree
            tree_output = run_git_command(["ls-tree", "-r", "--name-only", c_hash], cwd=abs_repo)
            for f_path in tree_output.splitlines():
                f_path = f_path.strip()
                if f_path:
                    commit_obj.changed_files.append(f_path)
                    commit_obj.file_status_map[f_path] = "A"
        else:
            # Subsequent commits: git diff-tree --no-commit-id --name-status -r <c_hash>
            diff_output = run_git_command(["diff-tree", "--no-commit-id", "--name-status", "-r", c_hash], cwd=abs_repo)
            for diff_line in diff_output.splitlines():
                diff_line = diff_line.strip()
                if not diff_line:
                    continue
                d_parts = diff_line.split(maxsplit=1)
                if len(d_parts) == 2:
                    status, f_path = d_parts[0], d_parts[1]
                    # Handle renames e.g. R100 old -> new
                    if status.startswith("R") and "\t" in f_path:
                        _, f_path = f_path.split("\t", 1)
                    commit_obj.changed_files.append(f_path)
                    commit_obj.file_status_map[f_path] = status[0]

        commits.append(commit_obj)

    return commits, is_shallow

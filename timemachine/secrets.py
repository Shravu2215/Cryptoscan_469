"""
Leaked Secret & Key Material Analysis in History for Crypto Time Machine.
Detects private keys and keystores committed to Git history, maintaining zero secret exposure.
"""

from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Optional
from timemachine.history import CommitInfo, read_blob_content

PEM_PATTERNS = [
    ("-----BEGIN RSA PRIVATE KEY-----", "RSA private key"),
    ("-----BEGIN EC PRIVATE KEY-----", "EC private key"),
    ("-----BEGIN PRIVATE KEY-----", "PKCS#8 private key"),
    ("-----BEGIN OPENSSH PRIVATE KEY-----", "OpenSSH private key"),
    ("-----BEGIN PGP PRIVATE KEY BLOCK-----", "PGP private key"),
]

KEYSTORE_EXTENSIONS = {
    ".p12": "PKCS#12 keystore",
    ".pfx": "PFX keystore",
    ".jks": "Java keystore",
    ".keystore": "Generic keystore",
}


@dataclass
class LeakedSecret:
    file: str
    secret_type: str
    added_commit: str
    added_commit_index: int
    added_date: str
    removed_commit: Optional[str]
    removed_commit_index: Optional[int]
    removed_date: Optional[str]
    present_in_history: bool
    fingerprint: str  # Truncated SHA-256 hash of blob (redacted fingerprint)
    recommendation: str = "Rotate this key. Deleting a file does not remove it from Git history."

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def compute_redacted_fingerprint(blob_sha: str) -> str:
    """Returns first 16 characters of blob SHA as redacted fingerprint."""
    return blob_sha[:16] if blob_sha else "0000000000000000"


def detect_secret_type(filepath: str, content: str) -> Optional[str]:
    """Detects private key pattern or keystore extension in file."""
    ext = "." + filepath.split(".")[-1].lower() if "." in filepath else ""
    if ext in KEYSTORE_EXTENSIONS:
        return KEYSTORE_EXTENSIONS[ext]

    if content:
        for pattern, stype in PEM_PATTERNS:
            if pattern in content:
                return stype

    return None


def find_history_secrets(repo_path: str, commits: List[CommitInfo]) -> List[LeakedSecret]:
    """
    Scans repo history across all commits to detect leaked keys/keystores and track their lifecycle.
    """
    file_secret_timeline: Dict[str, List[tuple]] = {}

    for commit in commits:
        for filepath in commit.changed_files:
            status = commit.file_status_map.get(filepath, "M")
            if status == "D":
                continue

            blob_info = read_blob_content(repo_path, commit.commit_hash, filepath)
            if not blob_info.content and not blob_info.is_binary:
                continue

            stype = detect_secret_type(filepath, blob_info.content or "")
            if stype:
                if filepath not in file_secret_timeline:
                    file_secret_timeline[filepath] = []
                file_secret_timeline[filepath].append((commit, blob_info, stype))

    secrets: List[LeakedSecret] = []

    for filepath, instances in file_secret_timeline.items():
        first_commit, first_blob, stype = instances[0]

        added_commit_hash = first_commit.commit_hash
        added_commit_idx = first_commit.commit_index
        added_date = first_commit.author_date

        last_commit, _, _ = instances[-1]

        removed_commit_hash = None
        removed_commit_idx = None
        removed_date = None

        # Trace commits following last appearance to locate deletion commit
        for commit in commits[last_commit.commit_index:]:  # 1-indexed to 0-based slice
            status = commit.file_status_map.get(filepath)
            if status == "D":
                removed_commit_hash = commit.commit_hash
                removed_commit_idx = commit.commit_index
                removed_date = commit.author_date
                break

        present_in_history = len(instances) > 0
        fingerprint = compute_redacted_fingerprint(first_blob.blob_sha)

        sec = LeakedSecret(
            file=filepath,
            secret_type=stype,
            added_commit=added_commit_hash,
            added_commit_index=added_commit_idx,
            added_date=added_date,
            removed_commit=removed_commit_hash,
            removed_commit_index=removed_commit_idx,
            removed_date=removed_date,
            present_in_history=present_in_history,
            fingerprint=fingerprint,
        )
        secrets.append(sec)

    return secrets

"""
Per-Commit History Scanner with Blob-SHA Caching for Crypto Time Machine.
Reuses Member 1's static scanner on in-memory Git blob contents per commit.
"""

from dataclasses import dataclass, field, asdict
import hashlib
import os
import sys
from typing import List, Dict, Any, Optional, Set, Tuple

_scanner_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scanner")
if _scanner_dir not in sys.path:
    sys.path.insert(0, _scanner_dir)

from scanner.python_analyzer import PythonAnalyzer
from scanner.js_analyzer import JSAnalyzer
from scanner.regex_analyzer import RegexAnalyzer
from scanner.dedup import dedup
from scanner.models import QuantumRisk, Severity
from timemachine.history import read_repository_history, read_blob_content, CommitInfo

WEAK_ALGORITHMS = {"MD5", "SHA-1", "DES", "RC4", "3DES", "MD4"}
QUANTUM_VULNERABLE_PREFIXES = ("RSA", "ECDSA", "ECDH", "ECDHE", "DH", "DSA", "X25519", "SECP")


@dataclass
class NormalizedHistoryFinding:
    finding_key: str           # stable ID across commits e.g. "app.py:hash_password:MD5"
    file: str
    line: int
    function: str
    algorithm: str
    key_size: Optional[int]
    rule_id: str
    rule_name: str
    severity: str
    quantum_risk: str
    classification: str        # "weak" | "quantum_vulnerable" | "both" | "ok"
    is_weak: bool
    is_quantum_vulnerable: bool
    commit_hash: str
    commit_index: int
    author_date: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def is_quantum_vulnerable_algo(algo: str) -> bool:
    if not algo:
        return False
    a = algo.upper()
    return any(a.startswith(prefix) for prefix in QUANTUM_VULNERABLE_PREFIXES)


def classify_finding(algo: str, key_size: Optional[int], quantum_risk_str: str) -> Tuple[bool, bool, str]:
    """Classifies finding into is_weak, is_quantum_vulnerable, and category name."""
    a_upper = algo.upper()
    is_weak = False
    is_qv = is_quantum_vulnerable_algo(algo) or quantum_risk_str in (QuantumRisk.QUANTUM_BROKEN.value, "Quantum-Broken", "QUANTUM_BROKEN")

    if a_upper in WEAK_ALGORITHMS or any(w in a_upper for w in ("MD5", "SHA-1", "SHA1", "DES", "RC4", "3DES", "MD4")):
        is_weak = True

    bits = key_size
    if not bits:
        m = re.search(r"RSA-(\d+)", a_upper)
        if m:
            bits = int(m.group(1))

    if a_upper.startswith("RSA") and bits and bits < 2048:
        is_weak = True

    if is_weak and is_qv:
        classification = "both"
    elif is_weak:
        classification = "weak"
    elif is_qv:
        classification = "quantum_vulnerable"
    else:
        classification = "ok"

    return is_weak, is_qv, classification


import ast


def resolve_enclosing_function(filepath: str, line_no: int, content: str, code_snippet: str = "") -> str:
    """Extracts enclosing function name using AST for Python or regex/snippet fallback."""
    ext = os.path.splitext(filepath)[1].lower()
    if ext == ".py" and content:
        try:
            tree = ast.parse(content)
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    start_line = getattr(node, "lineno", 0)
                    end_line = getattr(node, "end_lineno", start_line)
                    if start_line <= line_no <= end_line:
                        return node.name
        except Exception:
            pass

    if code_snippet:
        m = re.search(r"def\s+([a-zA-Z0-9_]+)\s*\(", code_snippet)
        if m:
            return m.group(1)

    return "module"


class HistoryScanner:
    """Scans repository history commit-by-commit with Git blob SHA caching."""

    def __init__(self, scanner_version: str = "1.0.0"):
        self.scanner_version = scanner_version
        self.py_analyzer = PythonAnalyzer()
        self.js_analyzer = JSAnalyzer()
        self.rx_analyzer = RegexAnalyzer()
        self.blob_cache: Dict[str, List[Dict[str, Any]]] = {}
        self.cache_hits = 0
        self.cache_misses = 0

    def _scan_blob(self, filepath: str, content: str, blob_sha: str) -> List[Dict[str, Any]]:
        """Scans single blob content with Member 1's analyzers, using blob_sha cache."""
        cache_key = f"{self.scanner_version}:{blob_sha}"
        if cache_key in self.blob_cache:
            self.cache_hits += 1
            return self.blob_cache[cache_key]

        self.cache_misses += 1
        raw_findings = []
        ext = os.path.splitext(filepath)[1].lower()

        if ext == ".py":
            raw_findings.extend(self.py_analyzer.analyze(filepath, content))
        elif ext in (".js", ".mjs", ".cjs", ".jsx"):
            raw_findings.extend(self.js_analyzer.analyze(filepath, content))
        elif ext in (".yml", ".yaml", ".json", ".ini", ".conf", ".env"):
            raw_findings.extend(self.rx_analyzer.analyze(filepath, content))

        raw_findings = dedup(raw_findings)
        dicts = [f.to_dict() for f in raw_findings]
        self.blob_cache[cache_key] = dicts
        return dicts

    def scan_commit_trajectory(
        self, repo_path: str, commits: List[CommitInfo]
    ) -> Tuple[Dict[str, List[NormalizedHistoryFinding]], Dict[str, Any]]:
        """
        Scans each commit in trajectory.
        Returns:
            - commit_findings_map: commit_hash -> list of NormalizedHistoryFinding
            - metrics: summary dict of cache_hits, cache_misses, total_scanned
        """
        commit_map: Dict[str, List[NormalizedHistoryFinding]] = {}

        # Maintain cumulative state of repository files across commits
        repo_file_blobs: Dict[str, str] = {}  # filepath -> blob_sha

        for commit in commits:
            # Update file state for this commit
            for filepath in commit.changed_files:
                status = commit.file_status_map.get(filepath, "M")
                if status == "D":
                    repo_file_blobs.pop(filepath, None)
                else:
                    blob_info = read_blob_content(repo_path, commit.commit_hash, filepath)
                    if blob_info.blob_sha:
                        repo_file_blobs[filepath] = blob_info.blob_sha

            # Scan active files for current commit
            commit_findings: List[NormalizedHistoryFinding] = []
            seen_finding_keys: Set[str] = set()

            for filepath, blob_sha in repo_file_blobs.items():
                if not blob_sha:
                    continue
                blob_info = read_blob_content(repo_path, commit.commit_hash, filepath)
                if not blob_info.content or blob_info.is_binary:
                    continue

                raw_findings = self._scan_blob(filepath, blob_info.content, blob_sha)

                for rf in raw_findings:
                    algo = rf.get("algorithm") or "UNKNOWN"
                    rule_id = rf.get("rule_id") or ""
                    line_no = rf.get("line") or 0
                    key_size = rf.get("key_size")

                    func = rf.get("function")
                    if not func or func in ("module", "global"):
                        func = resolve_enclosing_function(
                            filepath, line_no, blob_info.content, rf.get("code_snippet") or ""
                        )

                    # Standardize algorithm key
                    if algo == "RSA" and key_size:
                        algo = f"RSA-{key_size}"
                    elif "SECP256R1" in algo.upper() or "P-256" in algo.upper() or "P256" in algo.upper():
                        algo = "ECDSA P-256"

                    # Build stable finding key: file:function:algorithm
                    finding_key = f"{filepath}:{func}:{algo}"
                    if finding_key in seen_finding_keys:
                        continue
                    seen_finding_keys.add(finding_key)

                    qr_val = rf.get("quantum_risk") or ""
                    is_weak, is_qv, classification = classify_finding(algo, key_size, qr_val)

                    nf = NormalizedHistoryFinding(
                        finding_key=finding_key,
                        file=filepath,
                        line=rf.get("line") or 0,
                        function=func,
                        algorithm=algo,
                        key_size=key_size,
                        rule_id=rule_id,
                        rule_name=rf.get("rule_name") or rule_id,
                        severity=rf.get("severity") or "Medium",
                        quantum_risk=qr_val,
                        classification=classification,
                        is_weak=is_weak,
                        is_quantum_vulnerable=is_qv,
                        commit_hash=commit.commit_hash,
                        commit_index=commit.commit_index,
                        author_date=commit.author_date,
                    )
                    commit_findings.append(nf)

            commit_map[commit.commit_hash] = commit_findings

        metrics = {
            "total_commits": len(commits),
            "cache_hits": self.cache_hits,
            "cache_misses": self.cache_misses,
            "cached_blobs_count": len(self.blob_cache),
        }
        return commit_map, metrics


import re

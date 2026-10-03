"""
statement.py — in-toto Statement v1 generator for CryptoScan CBOM attestations.

Builds a standards-compliant in-toto Statement v1:
  https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md

The Subject is the CBOM file (sha256 digest).
The Predicate is a CryptoScan-specific predicate describing the scan result.

Usage:
    from attestation.statement import build_statement, PREDICATE_TYPE
    stmt = build_statement(cbom_path, cbom_sha256, metadata)
"""

import hashlib
import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, Optional

# in-toto Statement v1 types
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://cryptoscan.dev/attestation/cbom/v1"

# in-toto Provenance v1 (SLSA) type, used as an alternative predicate for SLSA compliance
SLSA_PREDICATE_TYPE = "https://slsa.dev/provenance/v1"


def sha256_file(path: str) -> str:
    """Compute SHA-256 hex digest of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_bytes(data: bytes) -> str:
    """Compute SHA-256 hex digest of bytes."""
    return hashlib.sha256(data).hexdigest()


def build_statement(
    cbom_path: str,
    cbom_sha256: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
    subject_name: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Build an in-toto Statement v1 for a CBOM file.

    Args:
        cbom_path:   Absolute path to the CBOM JSON file.
        cbom_sha256: Pre-computed SHA-256 hex digest (recomputed if None).
        metadata:    Optional dict of extra scan metadata (repo, commit, scanner_version…).
        subject_name: Override for the subject name (defaults to basename).

    Returns:
        dict — the full in-toto Statement v1 object (ready for JSON serialisation).
    """
    if not os.path.isfile(cbom_path):
        raise FileNotFoundError(f"CBOM file not found: {cbom_path}")

    digest = cbom_sha256 or sha256_file(cbom_path)
    name = subject_name or os.path.basename(cbom_path)

    with open(cbom_path, "r", encoding="utf-8") as f:
        cbom = json.load(f)

    # Extract summary statistics from the CBOM
    components = cbom.get("components", [])
    quantum_vulnerable = [
        c for c in components
        if _get_prop(c, "cryptoscan:quantumStatus") in ("VULNERABLE", "CRITICAL", "HIGH")
    ]
    compliant = [
        c for c in components
        if _get_prop(c, "cryptoscan:quantumStatus") in ("SAFE", "POST-QUANTUM", "COMPLIANT")
    ]
    total_findings = sum(
        len(c.get("occurrences", [])) for c in components
    ) or len(components)

    meta = metadata or {}
    scanned_at = meta.get("scanned_at") or datetime.now(timezone.utc).isoformat()

    predicate = {
        "predicateType": PREDICATE_TYPE,
        "scannerVersion": meta.get("scanner_version", "cryptoscan/1.0.0"),
        "repository": meta.get("repository", ""),
        "commit": meta.get("commit", ""),
        "branch": meta.get("branch", ""),
        "scannedAt": scanned_at,
        "cbomVersion": cbom.get("specVersion", "1.6"),
        "cbomSerialNumber": cbom.get("serialNumber", ""),
        "summary": {
            "totalComponents": len(components),
            "totalFindings": total_findings,
            "quantumVulnerableComponents": len(quantum_vulnerable),
            "compliantComponents": len(compliant),
        },
        "policy": {
            "quantumReadinessThreshold": meta.get("policy_threshold", "CRITICAL"),
        },
        # Full component fingerprint list (algorithm + file + sha256 of component JSON)
        "componentFingerprints": _build_fingerprints(components),
    }

    statement = {
        "_type": STATEMENT_TYPE,
        "subject": [
            {
                "name": name,
                "digest": {"sha256": digest},
            }
        ],
        "predicateType": PREDICATE_TYPE,
        "predicate": predicate,
    }

    return statement


def _get_prop(component: Dict[str, Any], prop_name: str) -> Optional[str]:
    """Extract a CycloneDX property value by name from a component."""
    for p in component.get("properties", []):
        if p.get("name") == prop_name:
            return p.get("value")
    return None


def _build_fingerprints(components):
    """Build a sorted list of (algorithm, file, sha256) tuples for each component."""
    fps = []
    for c in components:
        algo = c.get("name", "")
        file_path = _get_prop(c, "cryptoscan:file") or ""
        component_bytes = json.dumps(c, sort_keys=True).encode("utf-8")
        component_sha = sha256_bytes(component_bytes)
        fps.append({
            "algorithm": algo,
            "file": file_path,
            "componentSha256": component_sha,
        })
    return fps


def statement_to_json(statement: Dict[str, Any], indent: int = 2) -> str:
    """Serialise an in-toto Statement to a canonical JSON string."""
    return json.dumps(statement, indent=indent, sort_keys=False, ensure_ascii=False)

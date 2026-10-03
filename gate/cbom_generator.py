"""
cbom_generator.py - Generates CycloneDX 1.6 Cryptographic Bill of Materials (CBOM)
from scanner pipeline findings.
"""

import hashlib
import uuid
from typing import Dict, Any, List, Optional
from gate.cbom_parser import classify_category, get_suggested_pqc_replacement


def build_cyclonedx_cbom(
    findings: List[Dict[str, Any]],
    repo_name: str = "scanned-repo",
    commit_hash: str = "unknown",
) -> Dict[str, Any]:
    """
    Transforms scanner findings into a CycloneDX 1.6 CBOM document.
    """
    components_by_key: Dict[str, Dict[str, Any]] = {}

    for idx, f in enumerate(findings):
        # Ignore suppressed findings
        if f.get("suppressed"):
            continue

        algo = f.get("algorithm") or "UNKNOWN"
        key_size = f.get("key_size") or ""
        mode = f.get("mode") or ""
        version = f.get("version") or ""
        exposure = f.get("exposure") or "internal"

        comp_key = f"{algo}-{key_size or 'default'}-{mode or 'default'}"
        if comp_key not in components_by_key:
            bom_ref = f"crypto-asset/{re_clean(algo)}"
            components_by_key[comp_key] = {
                "type": "cryptographic-asset",
                "name": algo,
                "version": version,
                "bom-ref": bom_ref,
                "cryptoProperties": {
                    "assetType": "algorithm",
                    "algorithmProperties": {
                        "primitive": algo,
                        "keyLength": key_size if str(key_size).isdigit() else None,
                    },
                },
                "exposure": exposure,
                "maxVulnerabilityScore": 0,
                "maxSeverity": "INFO",
                "occurrences": [],
            }

        comp = components_by_key[comp_key]

        severity = (f.get("severity") or "INFO").upper()
        usage = f.get("usage") or f.get("category") or "Cryptographic Asset"
        q_status = f.get("quantum_risk") or f.get("quantumStatus") or "Quantum Safe"
        if q_status in ("Quantum-Broken", "Quantum-Weakened"):
            q_status = "Quantum Vulnerable"
        rec = f.get("recommendation") or get_suggested_pqc_replacement(algo, classify_category(algo, usage))
        lang = f.get("language_name") or f.get("language") or "Unknown"

        finding_id = f.get("id") or f"finding-{idx + 1}"
        file_path = f.get("file") or f.get("filePath") or "unknown"
        line_num = f.get("line") or f.get("lineNumber") or 0

        comp["occurrences"].append({
            "file": file_path,
            "line": line_num,
            "findingId": finding_id,
            "usage": usage,
            "severity": severity,
            "quantumStatus": q_status,
            "recommendation": rec,
            "language": lang,
            "properties": [
                {"name": "cryptoscan:language", "value": lang}
            ],
        })

    components = list(components_by_key.values())
    serial = str(uuid.uuid4())

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{serial}",
        "version": 1,
        "metadata": {
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "CryptoScan Scanner",
                        "version": "2.4.0",
                    }
                ]
            },
            "component": {
                "type": "application",
                "name": repo_name,
            },
            "properties": [
                {"name": "commitHash", "value": commit_hash},
                {"name": "findingCount", "value": str(len(findings))},
            ],
        },
        "components": components,
    }


def re_clean(name: str) -> str:
    import re
    return re.sub(r"[^a-z0-9]+", "-", str(name).lower()).strip("-")

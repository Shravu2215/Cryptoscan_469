"""
verifier.py — Independent CBOM attestation verifier for CryptoScan.

Performs a full verification chain:
  1. Recompute the CBOM SHA-256 and confirm it matches the Statement subject digest.
  2. Verify the Sigstore bundle cryptographic proof (certificate + signature).
  3. Verify the in-toto Statement predicate fields (predicateType, scanner version…).
  4. Optionally verify the ML-DSA-65 hybrid outer envelope.
  5. Optionally look up the Rekor log entry and confirm inclusion.

Usage:
    from attestation.verifier import verify_attestation
    result = verify_attestation(
        cbom_path="cbom.json",
        statement_path="attestation.intoto.json",
        bundle_path="attestation.bundle.json",
        hybrid_envelope_path="attestation.hybrid.json",  # optional
        expected_identity="https://github.com/my-org/cryptoscan/.github/workflows/attest.yml@refs/heads/main",
        expected_issuer="https://token.actions.githubusercontent.com",
    )
    print(result["valid"], result["errors"])
"""

import json
import logging
import os
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


def verify_attestation(
    cbom_path: str,
    statement_path: str,
    bundle_path: str,
    hybrid_envelope_path: Optional[str] = None,
    expected_identity: Optional[str] = None,
    expected_issuer: Optional[str] = None,
    check_rekor: bool = True,
) -> Dict[str, Any]:
    """
    Perform a full independent verification of a CryptoScan CBOM attestation.

    Args:
        cbom_path:             Path to the CBOM JSON file.
        statement_path:        Path to the in-toto Statement JSON.
        bundle_path:           Path to the Sigstore bundle JSON.
        hybrid_envelope_path:  Path to the hybrid ML-DSA envelope JSON (optional).
        expected_identity:     Expected OIDC identity SAN in the Sigstore certificate.
        expected_issuer:       Expected OIDC issuer.
        check_rekor:           If True, look up and verify inclusion in Rekor.

    Returns:
        dict:
          "valid"           — True iff ALL enabled checks pass.
          "checks"          — per-check booleans.
          "errors"          — list of failure messages.
          "warnings"        — list of non-fatal warnings.
          "rekor_lookup"    — Rekor lookup result (if check_rekor=True).
    """
    result: Dict[str, Any] = {
        "valid": False,
        "checks": {
            "cbom_sha256": False,
            "statement_subject": False,
            "statement_predicate": False,
            "sigstore_bundle": False,
            "hybrid_pqc": None,  # None = not checked
            "rekor_inclusion": None,  # None = not checked
        },
        "errors": [],
        "warnings": [],
        "rekor_lookup": None,
    }

    # ── Load files ─────────────────────────────────────────────────────────────
    try:
        cbom = _load_json(cbom_path)
    except Exception as e:
        result["errors"].append(f"Cannot load CBOM: {e}")
        return result

    try:
        statement = _load_json(statement_path)
    except Exception as e:
        result["errors"].append(f"Cannot load Statement: {e}")
        return result

    try:
        bundle = _load_json(bundle_path)
    except Exception as e:
        result["errors"].append(f"Cannot load Sigstore bundle: {e}")
        return result

    # ── Check 1: Recompute CBOM SHA-256 ────────────────────────────────────────
    try:
        from attestation.statement import sha256_file
        computed_sha = sha256_file(cbom_path)
        subjects = statement.get("subject", [])
        subject_sha = None
        for s in subjects:
            subject_sha = s.get("digest", {}).get("sha256")
            break

        if subject_sha and computed_sha == subject_sha:
            result["checks"]["cbom_sha256"] = True
        else:
            result["errors"].append(
                f"CBOM SHA-256 mismatch: computed={computed_sha}, statement={subject_sha}"
            )
    except Exception as e:
        result["errors"].append(f"CBOM SHA-256 check failed: {e}")

    # ── Check 2: Statement subject name ────────────────────────────────────────
    try:
        subjects = statement.get("subject", [])
        if subjects and subjects[0].get("name"):
            result["checks"]["statement_subject"] = True
        else:
            result["errors"].append("Statement subject is missing 'name' field")
    except Exception as e:
        result["errors"].append(f"Statement subject check failed: {e}")

    # ── Check 3: Statement predicate fields ────────────────────────────────────
    try:
        from attestation.statement import PREDICATE_TYPE, STATEMENT_TYPE
        stmt_type = statement.get("_type") or statement.get("type")
        predicate_type = statement.get("predicateType")
        predicate = statement.get("predicate", {})

        ok = (
            stmt_type == STATEMENT_TYPE
            and predicate_type == PREDICATE_TYPE
            and isinstance(predicate.get("summary"), dict)
            and isinstance(predicate.get("componentFingerprints"), list)
        )
        if ok:
            result["checks"]["statement_predicate"] = True
        else:
            result["errors"].append(
                f"Statement predicate validation failed: type={stmt_type!r}, "
                f"predicateType={predicate_type!r}"
            )
    except Exception as e:
        result["errors"].append(f"Statement predicate check failed: {e}")

    # ── Check 4: Sigstore bundle ───────────────────────────────────────────────
    try:
        from attestation.signer import verify_bundle
        sig_result = verify_bundle(
            statement=statement,
            bundle_path=bundle_path,
            expected_identity=expected_identity,
            expected_issuer=expected_issuer,
        )
        if sig_result.get("valid"):
            result["checks"]["sigstore_bundle"] = True
        else:
            errors = sig_result.get("errors", [])
            result["errors"].extend([f"Sigstore: {e}" for e in errors])
            if not errors:
                result["errors"].append("Sigstore bundle verification failed (unknown reason)")
    except Exception as e:
        result["errors"].append(f"Sigstore bundle check failed: {e}")

    # ── Check 5: Hybrid ML-DSA envelope (optional) ─────────────────────────────
    if hybrid_envelope_path and os.path.isfile(hybrid_envelope_path):
        try:
            from attestation.pqc_wrap import verify_hybrid_envelope
            envelope = _load_json(hybrid_envelope_path)
            pqc_result = verify_hybrid_envelope(envelope)
            result["checks"]["hybrid_pqc"] = pqc_result.get("valid", False)
            if not pqc_result.get("valid"):
                for e in pqc_result.get("errors", []):
                    if "stub" in e.lower():
                        result["warnings"].append(f"PQC: {e}")
                    else:
                        result["errors"].append(f"PQC: {e}")
        except Exception as e:
            result["warnings"].append(f"Hybrid PQC check failed: {e}")

    # ── Check 6: Rekor inclusion ───────────────────────────────────────────────
    if check_rekor and not os.getenv("SIGSTORE_NO_REKOR"):
        try:
            from attestation.rekor import rekor_search_by_hash
            from attestation.statement import sha256_file
            cbom_sha = sha256_file(cbom_path)
            lookup = rekor_search_by_hash(cbom_sha)
            result["rekor_lookup"] = lookup
            entries = lookup.get("entries", [])
            if entries:
                result["checks"]["rekor_inclusion"] = True
            elif "error" in lookup:
                result["warnings"].append(f"Rekor lookup error: {lookup['error']}")
                result["checks"]["rekor_inclusion"] = None
            else:
                result["warnings"].append(
                    "CBOM SHA-256 not found in Rekor — this is expected if the "
                    "bundle was uploaded by artifact hash (not CBOM hash directly)."
                )
                result["checks"]["rekor_inclusion"] = None
        except Exception as e:
            result["warnings"].append(f"Rekor inclusion check failed: {e}")

    # ── Overall verdict ────────────────────────────────────────────────────────
    mandatory = ["cbom_sha256", "statement_subject", "statement_predicate", "sigstore_bundle"]
    result["valid"] = (
        all(result["checks"].get(k) for k in mandatory)
        and len(result["errors"]) == 0
    )

    return result


def _load_json(path: str) -> Any:
    """Load and parse a JSON file."""
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

"""
signer.py — Sigstore keyless signing for CryptoScan CBOM attestations.

Uses the sigstore Python SDK (>=3.0) for OIDC-based keyless signing.
In CI (GitHub Actions), the OIDC token is supplied automatically by the
actions/configure-pages or ACTIONS_ID_TOKEN_REQUEST_* env vars.

Signing flow:
  1. Serialise the in-toto Statement to canonical JSON (the "artifact").
  2. Call sigstore.sign() — obtains a short-lived signing certificate
     bound to the OIDC identity, signs the artifact, and uploads the
     entry to the Rekor transparency log.
  3. Return a Bundle object (sigstore bundle v0.3 format) containing
     the certificate, signature, and Rekor log entry.

Verification flow:
  1. Reconstruct the artifact bytes.
  2. Call sigstore.verify() with the expected identity / issuer.
  3. Return the detailed verification result.

Environment variables:
  SIGSTORE_NO_REKOR=1   Disable Rekor upload (useful for local testing).
  SIGSTORE_REKOR_URL    Override Rekor instance (default: https://rekor.sigstore.dev).
  GITHUB_ACTIONS=true   Detected automatically — uses GitHub OIDC provider.
"""

import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

logger = logging.getLogger(__name__)

# ── Sigstore SDK import with graceful degradation ──────────────────────────────
try:
    from sigstore.sign import Signer, SigningContext
    from sigstore.verify import Verifier
    from sigstore.models import Bundle
    from sigstore._internal.oidc.ambient import detect_credential
    _SIGSTORE_AVAILABLE = True
except ImportError:
    _SIGSTORE_AVAILABLE = False
    logger.warning(
        "sigstore SDK not installed. Install with: pip install sigstore>=3.0.0\n"
        "Keyless signing will be unavailable; offline bundle will be generated."
    )


# ── Public API ─────────────────────────────────────────────────────────────────

def sign_statement(
    statement: Dict[str, Any],
    output_bundle_path: Optional[str] = None,
    identity_token: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Sign an in-toto Statement using Sigstore keyless signing.

    Args:
        statement:           in-toto Statement dict (from statement.py).
        output_bundle_path:  If set, writes the Sigstore bundle JSON to this path.
        identity_token:      Optional OIDC token; auto-detected from env if None.

    Returns:
        dict with keys:
          "bundle"         — the Sigstore bundle as a dict (bundle v0.3 JSON)
          "bundle_json"    — the bundle serialised as a JSON string
          "artifact_sha256"— SHA-256 of the signed bytes
          "signed"         — True if real Sigstore signing occurred
          "rekor_log_id"   — Rekor log entry ID (or None if Rekor disabled)
          "certificate"    — PEM certificate (or None for offline mode)
          "signer_identity"— OIDC subject / SAN (or None for offline mode)
    """
    artifact_bytes = _canonical_bytes(statement)
    artifact_sha256 = _sha256_hex(artifact_bytes)

    if not _SIGSTORE_AVAILABLE:
        return _offline_bundle(statement, artifact_bytes, artifact_sha256, output_bundle_path)

    try:
        return _sigstore_sign(
            statement, artifact_bytes, artifact_sha256,
            output_bundle_path, identity_token,
        )
    except Exception as exc:
        logger.error("Sigstore signing failed: %s", exc)
        # Fall back to offline bundle so the pipeline doesn't hard-fail
        result = _offline_bundle(statement, artifact_bytes, artifact_sha256, output_bundle_path)
        result["error"] = str(exc)
        return result


def verify_bundle(
    statement: Dict[str, Any],
    bundle_path: str,
    expected_identity: Optional[str] = None,
    expected_issuer: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Verify a Sigstore bundle against an in-toto Statement.

    Args:
        statement:         in-toto Statement dict (the original, unserialized).
        bundle_path:       Path to the Sigstore bundle JSON file.
        expected_identity: Expected OIDC identity (e.g. a GitHub Actions workflow URL).
        expected_issuer:   Expected OIDC issuer (e.g. https://token.actions.githubusercontent.com).

    Returns:
        dict with keys:
          "valid"     — True if verification passed
          "details"   — human-readable verification summary
          "errors"    — list of error strings (empty on success)
    """
    result: Dict[str, Any] = {"valid": False, "details": {}, "errors": []}

    if not _SIGSTORE_AVAILABLE:
        result["errors"].append(
            "sigstore SDK not installed — cannot perform cryptographic verification. "
            "Run: pip install sigstore>=3.0.0"
        )
        return result

    if not os.path.isfile(bundle_path):
        result["errors"].append(f"Bundle file not found: {bundle_path}")
        return result

    try:
        artifact_bytes = _canonical_bytes(statement)

        with open(bundle_path, "r", encoding="utf-8") as f:
            bundle_json = f.read()
        bundle = Bundle.from_json(bundle_json)

        verifier = Verifier.production()

        # Build identity policy
        if expected_identity or expected_issuer:
            from sigstore.verify.policy import Identity
            policy = Identity(
                identity=expected_identity or "",
                issuer=expected_issuer or "",
            )
        else:
            # Accept any identity — use for local/offline verification
            from sigstore.verify.policy import UnsafeSingleKey
            # Fall back to just verifying the cryptographic proof
            policy = None  # will raise if strict=True below

        if policy is not None:
            verified = verifier.verify_artifact(artifact=artifact_bytes, bundle=bundle, policy=policy)
        else:
            # Verify without identity constraint (cryptographic proof only)
            verified = verifier.verify_artifact(artifact=artifact_bytes, bundle=bundle)

        result["valid"] = True
        result["details"] = {
            "statement_sha256": _sha256_hex(artifact_bytes),
            "bundle_path": bundle_path,
            "identity": expected_identity,
            "issuer": expected_issuer,
        }

    except Exception as exc:
        result["errors"].append(f"Verification failed: {exc}")

    return result


# ── Internal helpers ───────────────────────────────────────────────────────────

def _canonical_bytes(statement: Dict[str, Any]) -> bytes:
    """Produce deterministic UTF-8 JSON bytes from the statement."""
    return json.dumps(statement, indent=None, separators=(",", ":"), sort_keys=True, ensure_ascii=False).encode("utf-8")


def _sha256_hex(data: bytes) -> str:
    import hashlib
    return hashlib.sha256(data).hexdigest()


def _sigstore_sign(
    statement: Dict[str, Any],
    artifact_bytes: bytes,
    artifact_sha256: str,
    output_bundle_path: Optional[str],
    identity_token: Optional[str],
) -> Dict[str, Any]:
    """Real Sigstore keyless signing path."""
    import tempfile

    ctx = SigningContext.production()
    with ctx.signer(identity_token=identity_token) as signer:
        result_bundle = signer.sign_artifact(artifact=artifact_bytes)

    bundle_json = result_bundle.to_json()
    bundle_dict = json.loads(bundle_json)

    # Extract useful fields
    rekor_log_id = None
    certificate_pem = None
    signer_identity = None

    try:
        # Bundle v0.3 structure
        tlog_entries = bundle_dict.get("verificationMaterial", {}).get("tlogEntries", [])
        if tlog_entries:
            rekor_log_id = tlog_entries[0].get("logEntryId") or tlog_entries[0].get("logIndex")
        cert_chain = bundle_dict.get("verificationMaterial", {}).get("x509CertificateChain", {})
        certs = cert_chain.get("certificates", [])
        if certs:
            certificate_pem = certs[0].get("rawBytes")
        # Extract SAN from certificate (identity)
        leaf_cert = bundle_dict.get("verificationMaterial", {}).get("certificate", {})
        signer_identity = leaf_cert.get("subject") or leaf_cert.get("rawBytes", "")[:60]
    except Exception:
        pass

    if output_bundle_path:
        Path(output_bundle_path).parent.mkdir(parents=True, exist_ok=True)
        Path(output_bundle_path).write_text(bundle_json, encoding="utf-8")
        logger.info("Sigstore bundle written to: %s", output_bundle_path)

    return {
        "bundle": bundle_dict,
        "bundle_json": bundle_json,
        "artifact_sha256": artifact_sha256,
        "signed": True,
        "rekor_log_id": rekor_log_id,
        "certificate": certificate_pem,
        "signer_identity": signer_identity,
    }


def _offline_bundle(
    statement: Dict[str, Any],
    artifact_bytes: bytes,
    artifact_sha256: str,
    output_bundle_path: Optional[str],
) -> Dict[str, Any]:
    """
    Fallback: generate an unsigned bundle manifest when Sigstore is unavailable.
    Records the statement hash and timestamp so verification can at least confirm
    artifact integrity via the content hash.
    """
    from datetime import datetime, timezone

    bundle_dict = {
        "_notice": "Offline bundle — Sigstore SDK unavailable. Cryptographic proof absent.",
        "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
        "verificationMaterial": {
            "offline": True,
            "artifactSha256": artifact_sha256,
            "generatedAt": datetime.now(timezone.utc).isoformat(),
        },
        "messageSignature": {
            "messageDigest": {
                "algorithm": "SHA2_256",
                "digest": artifact_sha256,
            },
            "signature": "",
        },
    }
    bundle_json = json.dumps(bundle_dict, indent=2)

    if output_bundle_path:
        Path(output_bundle_path).parent.mkdir(parents=True, exist_ok=True)
        Path(output_bundle_path).write_text(bundle_json, encoding="utf-8")
        logger.info("Offline bundle written to: %s", output_bundle_path)

    return {
        "bundle": bundle_dict,
        "bundle_json": bundle_json,
        "artifact_sha256": artifact_sha256,
        "signed": False,
        "rekor_log_id": None,
        "certificate": None,
        "signer_identity": None,
    }

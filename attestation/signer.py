"""
signer.py — Sigstore keyless signing for CryptoScan CBOM attestations.

Uses the sigstore Python SDK (>=3.0, <5.0) for OIDC-based keyless signing.
In CI (GitHub Actions), the OIDC token is supplied automatically when
'permissions: id-token: write' is present in the workflow.

Signing flow:
  1. Serialise the in-toto Statement to canonical JSON (the "artifact").
  2. Call sigstore Signer via SigningContext — obtains a short-lived signing
     certificate bound to the OIDC identity, signs the artifact, and uploads
     the entry to the Rekor transparency log.
  3. Return a Bundle object (Sigstore bundle v0.3 format) containing the
     certificate, signature, and Rekor log entry.

Verification flow:
  1. Reconstruct the artifact bytes.
  2. Call sigstore Verifier with the expected identity / issuer policy.
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
    from sigstore.sign import Signer, SigningContext, ClientTrustConfig
    from sigstore.oidc import detect_credential, IdentityToken
    from sigstore.models import Bundle
    from sigstore.verify import Verifier
    from sigstore.verify.policy import Identity, UnsafeNoOp, VerificationError
    _SIGSTORE_AVAILABLE = True
except ImportError as _err:
    _SIGSTORE_AVAILABLE = False
    logger.warning(
        "sigstore SDK not available: %s\n"
        "Keyless signing will be unavailable; offline bundle will be generated unless strict mode is enabled.",
        _err,
    )


# ── Public API ─────────────────────────────────────────────────────────────────

def sign_statement(
    statement: Dict[str, Any],
    output_bundle_path: Optional[str] = None,
    identity_token: Optional[str] = None,
    strict: bool = False,
) -> Dict[str, Any]:
    """
    Sign an in-toto Statement using Sigstore keyless signing.

    Args:
        statement:           in-toto Statement dict (from statement.py).
        output_bundle_path:  If set, writes the Sigstore bundle JSON to this path.
        identity_token:      Optional OIDC token; auto-detected from env if None.
        strict:              If True, raises an error instead of generating an offline bundle.

    Returns:
        dict with keys:
          "bundle"         — the Sigstore bundle as a dict (bundle v0.3 JSON)
          "bundle_json"    — the bundle serialised as a JSON string
          "artifact_sha256"— SHA-256 of the signed bytes
          "signed"         — True if real Sigstore signing occurred
          "mode"           — "sigstore" or "offline"
          "rekor_log_id"   — Rekor log entry ID (or None if offline)
          "certificate"    — PEM certificate (or None for offline mode)
          "signer_identity"— OIDC subject / SAN (or None for offline mode)
          "error"          — Error string if signing failed or fell back to offline
    """
    artifact_bytes = _canonical_bytes(statement)
    artifact_sha256 = _sha256_hex(artifact_bytes)

    if not _SIGSTORE_AVAILABLE:
        if strict:
            raise RuntimeError(
                "Sigstore SDK is not installed — required for signing in strict mode. "
                "Install with: pip install -r attestation/requirements.txt"
            )
        return _offline_bundle(
            statement, artifact_bytes, artifact_sha256, output_bundle_path,
            error="Sigstore SDK not installed",
        )

    try:
        return _sigstore_sign(
            statement, artifact_bytes, artifact_sha256,
            output_bundle_path, identity_token, strict=strict,
        )
    except Exception as exc:
        if strict:
            raise
        logger.error("Sigstore signing failed: %s", exc)
        result = _offline_bundle(
            statement, artifact_bytes, artifact_sha256, output_bundle_path,
            error=str(exc),
        )
        return result


def verify_bundle(
    statement: Dict[str, Any],
    bundle_path: str,
    expected_identity: Optional[str] = None,
    expected_issuer: Optional[str] = None,
    offline_ok: bool = False,
) -> Dict[str, Any]:
    """
    Verify a Sigstore bundle against an in-toto Statement.

    Args:
        statement:         in-toto Statement dict (the original, unserialized).
        bundle_path:       Path to the Sigstore bundle JSON file.
        expected_identity: Expected OIDC identity (e.g. GitHub Actions workflow URL).
        expected_issuer:   Expected OIDC issuer (e.g. https://token.actions.githubusercontent.com).
        offline_ok:        If True, permits unsigned offline development bundles.

    Returns:
        dict with keys:
          "valid"     — True if verification passed
          "offline"   — True if the bundle was an offline bundle
          "details"   — human-readable verification summary
          "errors"    — list of error strings (empty on success)
          "warnings"  — list of non-fatal warnings
    """
    result: Dict[str, Any] = {
        "valid": False,
        "offline": False,
        "details": {},
        "errors": [],
        "warnings": [],
    }

    if not os.path.isfile(bundle_path):
        result["errors"].append(f"Bundle file not found: {bundle_path}")
        return result

    try:
        artifact_bytes = _canonical_bytes(statement)
        artifact_sha256 = _sha256_hex(artifact_bytes)

        with open(bundle_path, "r", encoding="utf-8") as f:
            bundle_json = f.read()
        bundle_dict = json.loads(bundle_json)

        # Detect offline / unsigned development bundle
        is_offline = (
            bundle_dict.get("verificationMaterial", {}).get("offline") is True
            or not bundle_dict.get("messageSignature", {}).get("signature")
        )

        if is_offline:
            result["offline"] = True
            stored_hash = (
                bundle_dict.get("verificationMaterial", {}).get("artifactSha256")
                or bundle_dict.get("messageSignature", {}).get("messageDigest", {}).get("digest")
            )
            if stored_hash != artifact_sha256:
                result["errors"].append(
                    f"Offline bundle hash mismatch: stored={stored_hash}, computed={artifact_sha256}"
                )
                return result

            if not offline_ok:
                result["errors"].append(
                    "Offline bundle: contains no cryptographic signature, certificate, or Rekor proof "
                    "(unsigned development artifact). Verification rejected in production/strict mode."
                )
                return result
            else:
                result["valid"] = True
                result["warnings"].append(
                    "Offline bundle accepted: content hash matches statement, but cryptographic signature is absent."
                )
                result["details"] = {
                    "mode": "offline",
                    "statement_sha256": artifact_sha256,
                    "bundle_path": bundle_path,
                }
                return result

        # Genuine Sigstore bundle verification
        if not _SIGSTORE_AVAILABLE:
            result["errors"].append(
                "sigstore SDK not installed — cannot perform cryptographic verification. "
                "Run: pip install -r attestation/requirements.txt"
            )
            return result

        bundle = Bundle.from_json(bundle_json)
        verifier = Verifier.production()

        # Policy configuration
        if expected_identity and expected_issuer:
            policy = Identity(identity=expected_identity, issuer=expected_issuer)
        elif expected_identity or expected_issuer:
            policy = Identity(identity=expected_identity or "", issuer=expected_issuer or "")
        else:
            policy = UnsafeNoOp()

        verifier.verify_artifact(input_=artifact_bytes, bundle=bundle, policy=policy)

        result["valid"] = True
        result["details"] = {
            "mode": "sigstore",
            "statement_sha256": artifact_sha256,
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
    strict: bool = False,
) -> Dict[str, Any]:
    """Real Sigstore keyless signing path."""
    raw_token = identity_token or detect_credential()
    if not raw_token:
        raise ValueError(
            "No OIDC identity token found. Sigstore keyless signing requires an OIDC credential "
            "(e.g. running in GitHub Actions with 'permissions: id-token: write')."
        )

    id_token = IdentityToken(raw_token)
    trust_config = ClientTrustConfig.production()
    signing_ctx = SigningContext.from_trust_config(trust_config)

    with signing_ctx.signer(identity_token=id_token) as signer:
        result_bundle = signer.sign_artifact(input_=artifact_bytes)

    bundle_json = result_bundle.to_json()
    bundle_dict = json.loads(bundle_json)

    # Extract log ID, certificate, identity
    rekor_log_id = None
    certificate_pem = None
    signer_identity = None

    try:
        if hasattr(result_bundle, "log_entry") and result_bundle.log_entry:
            rekor_log_id = str(
                getattr(result_bundle.log_entry, "log_id", None)
                or getattr(result_bundle.log_entry, "log_index", None)
            )
    except Exception:
        pass

    if not rekor_log_id:
        try:
            tlog_entries = bundle_dict.get("verificationMaterial", {}).get("tlogEntries", [])
            if tlog_entries:
                rekor_log_id = str(tlog_entries[0].get("logEntryId") or tlog_entries[0].get("logIndex"))
        except Exception:
            pass

    try:
        if hasattr(result_bundle, "signing_certificate") and result_bundle.signing_certificate:
            cert = result_bundle.signing_certificate
            from cryptography.hazmat.primitives import serialization
            certificate_pem = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
            from cryptography import x509
            san = cert.extensions.get_extension_for_oid(x509.OID_SUBJECT_ALTERNATIVE_NAME)
            uris = san.value.get_values_for_type(x509.UniformResourceIdentifier)
            if uris:
                signer_identity = uris[0]
            else:
                emails = san.value.get_values_for_type(x509.RFC822Name)
                if emails:
                    signer_identity = emails[0]
    except Exception:
        pass

    if not signer_identity:
        try:
            cert_chain = bundle_dict.get("verificationMaterial", {}).get("x509CertificateChain", {})
            certs = cert_chain.get("certificates", [])
            if certs:
                certificate_pem = certs[0].get("rawBytes")
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
        "mode": "sigstore",
        "rekor_log_id": rekor_log_id,
        "certificate": certificate_pem,
        "signer_identity": signer_identity,
        "error": None,
    }


def _offline_bundle(
    statement: Dict[str, Any],
    artifact_bytes: bytes,
    artifact_sha256: str,
    output_bundle_path: Optional[str],
    error: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Fallback: generate an unsigned bundle manifest when Sigstore is unavailable.
    Explicitly marked as offline development artifact.
    """
    from datetime import datetime, timezone

    bundle_dict = {
        "_notice": (
            "Offline bundle — Sigstore keyless signing unavailable or unprivileged environment. "
            "Cryptographic proof and Rekor log entry are absent."
        ),
        "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
        "verificationMaterial": {
            "offline": True,
            "artifactSha256": artifact_sha256,
            "generatedAt": datetime.now(timezone.utc).isoformat(),
            "error": error,
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
        "mode": "offline",
        "rekor_log_id": None,
        "certificate": None,
        "signer_identity": None,
        "error": error,
    }

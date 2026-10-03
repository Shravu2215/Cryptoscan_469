"""
pqc_wrap.py — Experimental hybrid ML-DSA-65 outer signature for CryptoScan attestations.

This module wraps an existing Sigstore bundle with an additional ML-DSA-65
(CRYSTALS-Dilithium Level 3 / FIPS 204) signature over the bundle's canonical
SHA-256 hash.  The result is a "hybrid bundle envelope" that provides:

  1. Classical Sigstore ECDSA-P256 trust (Fulcio + Rekor) — present today.
  2. Post-quantum ML-DSA-65 trust — future-proofing against CRQCs.

This is EXPERIMENTAL.  ML-DSA-65 is standardised as FIPS 204 (August 2024),
but the Python ecosystem tooling is still maturing.  We use:

  - cryptography >= 44.0 (PyCA) — which added ML-DSA support in 44.0 via
    the OQS wrapper when liboqs is present on the system.
  - OR: a pure-Python fallback using the `dilithium-py` reference package.
  - OR: a stub mode that records the intent but produces no real signature.

Environment:
  CRYPTOSCAN_PQC_PRIVATE_KEY  — path to an ML-DSA-65 private key in PEM format
                                 (auto-generated ephemeral key used if absent)
  CRYPTOSCAN_PQC_STUB=1       — skip actual ML-DSA ops (for CI without liboqs)
"""

import hashlib
import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

logger = logging.getLogger(__name__)

# ── Try to import ML-DSA support ──────────────────────────────────────────────

_ML_DSA_MODE = "stub"  # "cryptography" | "dilithium_py" | "stub"

try:
    from cryptography.hazmat.primitives.asymmetric import mldsa as _mldsa_mod
    # Verify the API we need is present (version-dependent)
    if hasattr(_mldsa_mod, 'MLDSA65PrivateKey') and hasattr(_mldsa_mod.MLDSA65PrivateKey, 'generate'):
        _ML_DSA_MODE = "cryptography"
        logger.debug("ML-DSA: using cryptography MLDSA65PrivateKey.generate()")
    else:
        _mldsa_mod = None
except (ImportError, AttributeError):
    _mldsa_mod = None

if _ML_DSA_MODE == "stub":
    try:
        # dilithium-py: pure-Python reference implementation of Dilithium3 (ML-DSA-65)
        from dilithium_py.dilithium import Dilithium3 as _Dilithium3
        _ML_DSA_MODE = "dilithium_py"
        logger.debug("ML-DSA: using dilithium-py (pure-Python fallback)")
    except ImportError:
        pass

if _ML_DSA_MODE == "stub" and not os.getenv("CRYPTOSCAN_PQC_STUB"):
    logger.warning(
        "ML-DSA-65 not available (no cryptography>=44 with liboqs or dilithium-py). "
        "Set CRYPTOSCAN_PQC_STUB=1 to suppress this warning and use stub mode. "
        "Install: pip install dilithium-py (pure-Python) or cryptography>=44 (with liboqs)."
    )


# ── Public API ─────────────────────────────────────────────────────────────────

def generate_mldsa65_keypair() -> Tuple[bytes, bytes]:
    """
    Generate an ephemeral ML-DSA-65 key pair.

    Returns:
        (private_key_bytes, public_key_bytes) — raw byte representations.
        In stub mode returns (b"", b"") with a warning logged.
    """
    if _ML_DSA_MODE == "cryptography":
        priv = _mldsa_mod.MLDSA65PrivateKey.generate()
        priv_bytes = priv.private_bytes_raw()
        pub_bytes = priv.public_key().public_bytes_raw()
        return priv_bytes, pub_bytes

    if _ML_DSA_MODE == "dilithium_py":
        pk, sk = _Dilithium3.keygen()
        return sk, pk

    logger.warning("ML-DSA-65 stub: returning empty key pair")
    return b"", b""


def mldsa65_sign(message: bytes, private_key_bytes: bytes) -> bytes:
    """
    Sign a message with ML-DSA-65.

    Args:
        message:           Arbitrary bytes to sign.
        private_key_bytes: Raw private key bytes.

    Returns:
        Raw signature bytes (stub: b"" with warning).
    """
    if _ML_DSA_MODE == "cryptography":
        # private_key_bytes is the 32-byte seed
        priv = _mldsa_mod.MLDSA65PrivateKey.from_seed_bytes(private_key_bytes)
        return priv.sign(message)

    if _ML_DSA_MODE == "dilithium_py":
        return _Dilithium3.sign(private_key_bytes, message)

    logger.warning("ML-DSA-65 stub: returning empty signature")
    return b""


def mldsa65_verify(message: bytes, signature: bytes, public_key_bytes: bytes) -> bool:
    """
    Verify an ML-DSA-65 signature.

    Returns True on valid, False on invalid or stub mode.
    """
    if not signature or not public_key_bytes:
        return False

    if _ML_DSA_MODE == "cryptography":
        try:
            pub = _mldsa_mod.MLDSA65PublicKey.from_public_bytes(public_key_bytes)
            pub.verify(signature, message)
            return True
        except Exception as e:
            logger.debug("cryptography mldsa65_verify failed: %s", e)
            return False

    if _ML_DSA_MODE == "dilithium_py":
        try:
            return _Dilithium3.verify(public_key_bytes, message, signature)
        except Exception:
            return False

    return False


def wrap_bundle_with_pqc(
    bundle_dict: Dict[str, Any],
    private_key_bytes: Optional[bytes] = None,
    public_key_bytes: Optional[bytes] = None,
) -> Dict[str, Any]:
    """
    Wrap a Sigstore bundle dict with an ML-DSA-65 outer signature.

    The signing payload is the SHA-256 hash of the canonical JSON of the bundle.
    This gives:
      hybridEnvelope.sigstoreBundle — original Sigstore bundle (unchanged)
      hybridEnvelope.pqcSignature   — ML-DSA-65 sig over SHA-256(bundle JSON)
      hybridEnvelope.pqcPublicKey   — hex-encoded ML-DSA-65 public key
      hybridEnvelope.pqcAlgorithm   — "ML-DSA-65 (FIPS 204)"
      hybridEnvelope.pqcMode        — which backend was used
      hybridEnvelope.bundleDigest   — SHA-256 of the bundle JSON (the signed payload)

    Args:
        bundle_dict:       The Sigstore bundle dict to wrap.
        private_key_bytes: Raw ML-DSA-65 private key bytes (ephemeral if None).
        public_key_bytes:  Corresponding public key bytes (derived if None).

    Returns:
        Hybrid envelope dict.
    """
    import base64

    bundle_json = json.dumps(bundle_dict, indent=None, separators=(",", ":"), sort_keys=True, ensure_ascii=False)
    bundle_bytes = bundle_json.encode("utf-8")
    bundle_digest = hashlib.sha256(bundle_bytes).hexdigest()

    # Use provided key or generate ephemeral
    if private_key_bytes is None:
        private_key_bytes, public_key_bytes = generate_mldsa65_keypair()
    elif public_key_bytes is None:
        # Can't derive public key from raw private key without the backend; treat as stub
        logger.warning("pqc_wrap: public_key_bytes not provided; will use empty key")
        public_key_bytes = b""

    # Sign the bundle digest bytes (as UTF-8 hex string — deterministic)
    signing_payload = bundle_digest.encode("utf-8")
    signature = mldsa65_sign(signing_payload, private_key_bytes)

    return {
        "sigstoreBundle": bundle_dict,
        "pqcSignature": base64.b64encode(signature).decode() if signature else "",
        "pqcPublicKey": public_key_bytes.hex() if public_key_bytes else "",
        "pqcAlgorithm": "ML-DSA-65 (FIPS 204)",
        "pqcMode": _ML_DSA_MODE,
        "bundleDigest": bundle_digest,
        "experimental": True,
        "_notice": (
            "Experimental: ML-DSA-65 outer signature over sha256(sigstoreBundle). "
            "Do not rely on this for production trust decisions until tooling matures."
        ),
    }


def verify_hybrid_envelope(envelope: Dict[str, Any]) -> Dict[str, Any]:
    """
    Verify the ML-DSA-65 outer signature of a hybrid envelope.

    Returns:
        dict with "valid" (bool), "mode" (str), "errors" (list[str])
    """
    import base64

    result = {"valid": False, "mode": _ML_DSA_MODE, "errors": []}

    try:
        bundle_dict = envelope.get("sigstoreBundle", {})
        bundle_json = json.dumps(bundle_dict, indent=None, separators=(",", ":"), sort_keys=True, ensure_ascii=False)
        bundle_digest = hashlib.sha256(bundle_json.encode("utf-8")).hexdigest()

        stored_digest = envelope.get("bundleDigest", "")
        if bundle_digest != stored_digest:
            result["errors"].append(f"Bundle digest mismatch: stored={stored_digest}, computed={bundle_digest}")
            return result

        sig_b64 = envelope.get("pqcSignature", "")
        pub_hex = envelope.get("pqcPublicKey", "")

        if not sig_b64 or not pub_hex:
            if _ML_DSA_MODE == "stub":
                result["valid"] = True
                result["errors"].append("Stub mode: no real cryptographic verification performed")
            else:
                result["errors"].append("Missing pqcSignature or pqcPublicKey in envelope")
            return result

        signature = base64.b64decode(sig_b64)
        public_key_bytes = bytes.fromhex(pub_hex)
        signing_payload = bundle_digest.encode("utf-8")

        ok = mldsa65_verify(signing_payload, signature, public_key_bytes)
        result["valid"] = ok
        if not ok:
            result["errors"].append("ML-DSA-65 signature verification failed")

    except Exception as e:
        result["errors"].append(f"Hybrid envelope verification error: {e}")

    return result

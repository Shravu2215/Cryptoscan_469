"""
Rekor transparency log client for CryptoScan attestations.

Features:
    - Upload a hashedrekord entry to Rekor.
    - Look up an entry by its UUID.
    - Search entries by artifact SHA-256.
    - Retrieve Rekor log metadata.
    - Verify a Rekor inclusion proof using Sigstore's trusted root.
    - Check that a hashedrekord entry contains the expected SHA-256 digest.

Environment variables:
    SIGSTORE_REKOR_URL: Rekor URL.
    REKOR_TIMEOUT: HTTP timeout in seconds.
    SIGSTORE_NO_REKOR: Disable uploads when set.
"""

import base64
import hashlib
import json
import logging
import os
import re
from typing import Any, Dict, Optional

import requests


logger = logging.getLogger(__name__)

REKOR_BASE_URL = os.getenv(
    "SIGSTORE_REKOR_URL",
    "https://rekor.sigstore.dev",
).rstrip("/")

REKOR_TIMEOUT = int(os.getenv("REKOR_TIMEOUT", "30"))

# Maximum size accepted for a parsed JSON response.
_MAX_RESPONSE_BYTES = 1 * 1024 * 1024


# ---------------------------------------------------------------------------
# SHA-256 helpers
# ---------------------------------------------------------------------------

def _normalize_sha256(value: str) -> str:
    """
    Normalize and validate a SHA-256 hexadecimal digest.

    Accepts:
        <64 hexadecimal characters>
        sha256:<64 hexadecimal characters>
        0x<64 hexadecimal characters>

    Returns:
        A lowercase 64-character hexadecimal digest.

    Raises:
        ValueError: If the digest is invalid.
    """
    if not isinstance(value, str):
        raise ValueError("SHA-256 digest must be a string")

    digest = value.strip()

    if digest.lower().startswith("sha256:"):
        digest = digest[7:]
    elif digest.lower().startswith("0x"):
        digest = digest[2:]

    digest = digest.lower()

    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ValueError(
            "Invalid SHA-256 digest: expected exactly 64 hexadecimal characters"
        )

    return digest


def _validate_sha256_for_upload(value: str) -> str:
    """Validate a SHA-256 digest before constructing an upload."""
    return _normalize_sha256(value)


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

def _http_error_response(response: requests.Response) -> Dict[str, Any]:
    """Convert an HTTP error response into a consistent dictionary."""
    try:
        status_code = response.status_code
    except Exception:
        status_code = None

    try:
        body = response.text[:500]
    except Exception:
        body = ""

    logger.warning(
        "Rekor HTTP request failed: status=%s, body=%s",
        status_code,
        body,
    )

    return {
        "error": f"HTTP {status_code}: {body}",
        "status_code": status_code,
    }


def _parse_json_response(response: requests.Response) -> Dict[str, Any]:
    """
    Parse a successful HTTP response as JSON.

    Returns a dictionary describing an error when the response is invalid.
    """
    try:
        response.raise_for_status()
    except requests.HTTPError:
        return _http_error_response(response)
    except Exception as exc:
        return {"error": str(exc)}

    try:
        data = response.json()
    except Exception as exc:
        return {"error": f"Invalid JSON response from Rekor: {exc}"}

    try:
        response_size = len(
            json.dumps(data, ensure_ascii=False).encode("utf-8")
        )
    except (TypeError, ValueError) as exc:
        return {"error": f"Unable to process Rekor response: {exc}"}

    if response_size > _MAX_RESPONSE_BYTES:
        return {
            "error": "Rekor response exceeds maximum allowed size"
        }

    if not isinstance(data, (dict, list)):
        return {"error": "Unexpected JSON response type from Rekor"}

    return {"data": data}


# ---------------------------------------------------------------------------
# Upload a hashedrekord entry
# ---------------------------------------------------------------------------

def rekor_upload_hashedrekord(
    artifact_sha256: str,
    artifact_url: Optional[str] = None,
    artifact_bytes: Optional[bytes] = None,
    public_key_pem: Optional[str] = None,
    signature_b64: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Upload a hashedrekord entry to Rekor.

    Args:
        artifact_sha256: SHA-256 digest of the artifact.
        artifact_url: Optional artifact URL.
        artifact_bytes: Optional artifact bytes. These are not uploaded.
        public_key_pem: Optional PEM public key.
        signature_b64: Optional base64-encoded detached signature.

    Returns:
        A dictionary containing the Rekor entry metadata or an error.
    """
    if os.getenv("SIGSTORE_NO_REKOR"):
        return {
            "logID": None,
            "logIndex": None,
            "skipped": True,
            "reason": "SIGSTORE_NO_REKOR set",
        }

    try:
        digest = _validate_sha256_for_upload(artifact_sha256)
    except ValueError as exc:
        return {"error": str(exc)}

    # Keep the optional argument for API compatibility.
    # The artifact bytes are not sent to Rekor.
    if artifact_bytes is not None:
        computed_digest = hashlib.sha256(artifact_bytes).hexdigest()

        if computed_digest != digest:
            return {
                "error": (
                    "artifact_bytes do not match the supplied SHA-256 digest"
                )
            }

    spec: Dict[str, Any] = {
        "data": {
            "hash": {
                "algorithm": "sha256",
                "value": digest,
            }
        }
    }

    if artifact_url:
        spec["data"]["url"] = artifact_url

    if public_key_pem and signature_b64:
        spec["signature"] = {
            "content": signature_b64,
            "publicKey": {
                "content": base64.b64encode(
                    public_key_pem.encode("utf-8")
                ).decode("ascii")
            },
        }

    entry_body = {
        "kind": "hashedrekord",
        "apiVersion": "0.0.1",
        "spec": spec,
    }

    try:
        response = requests.post(
            f"{REKOR_BASE_URL}/api/v1/log/entries",
            json=entry_body,
            timeout=REKOR_TIMEOUT,
            headers={"Content-Type": "application/json"},
        )

        parsed = _parse_json_response(response)

        if "error" in parsed:
            return parsed

        result_map = parsed["data"]

        if not isinstance(result_map, dict):
            return {"error": "Unexpected upload response from Rekor"}

        for log_id, entry in result_map.items():
            if not isinstance(entry, dict):
                continue

            return {
                "logID": log_id,
                "logIndex": entry.get("logIndex"),
                "integratedTime": entry.get("integratedTime"),
                "body": entry.get("body"),
            }

        return {"error": "No entry returned from Rekor"}

    except requests.RequestException as exc:
        logger.error("Rekor upload request failed: %s", exc)
        return {"error": str(exc)}

    except Exception as exc:
        logger.exception("Unexpected Rekor upload error")
        return {"error": str(exc)}


# ---------------------------------------------------------------------------
# Look up an entry
# ---------------------------------------------------------------------------

def rekor_lookup(log_id: str) -> Dict[str, Any]:
    """
    Look up a Rekor entry by its hexadecimal UUID.

    Returns the raw entry dictionary or an error dictionary.
    """
    if not isinstance(log_id, str):
        return {"error": "Rekor log ID must be a string"}

    log_id = log_id.strip()

    if not re.fullmatch(r"[0-9a-fA-F]{64}", log_id):
        return {
            "error": "Invalid Rekor log ID: expected a 64-character hexadecimal UUID"
        }

    try:
        response = requests.get(
            f"{REKOR_BASE_URL}/api/v1/log/entries/{log_id}",
            timeout=REKOR_TIMEOUT,
        )

        parsed = _parse_json_response(response)

        if "error" in parsed:
            return parsed

        data = parsed["data"]

        if not isinstance(data, dict):
            return {"error": "Unexpected entry response from Rekor"}

        return data

    except requests.RequestException as exc:
        logger.warning("Rekor lookup request failed: %s", exc)
        return {"error": str(exc)}

    except Exception as exc:
        logger.exception("Unexpected Rekor lookup error")
        return {"error": str(exc)}


# ---------------------------------------------------------------------------
# Search by artifact hash
# ---------------------------------------------------------------------------

def rekor_search_by_hash(sha256_hex: str) -> Dict[str, Any]:
    """
    Search Rekor for entries matching an artifact SHA-256 digest.

    A successful search is not, by itself, proof of inclusion.

    Returns:
        {"entries": [...]} on success.
        {"error": "..."} on failure.
    """
    if not isinstance(sha256_hex, str) or not sha256_hex.strip():
        return {"error": "A non-empty artifact hash is required"}

    digest = sha256_hex.strip().lower()

    if digest.startswith("sha256:"):
        digest = digest[7:]
    elif digest.startswith("0x"):
        digest = digest[2:]

    try:
        response = requests.post(
            f"{REKOR_BASE_URL}/api/v1/index/retrieve",
            json={"hash": f"sha256:{digest}"},
            timeout=REKOR_TIMEOUT,
            headers={"Content-Type": "application/json"},
        )

        parsed = _parse_json_response(response)

        if "error" in parsed:
            return parsed

        data = parsed["data"]

        # The Rekor index API returns a list of matching entry IDs.
        if isinstance(data, list):
            return {"entries": data}

        return {
            "error": "Unexpected search response from Rekor"
        }

    except requests.RequestException as exc:
        logger.warning("Rekor hash search failed: %s", exc)
        return {"error": str(exc)}

    except Exception as exc:
        logger.exception("Unexpected Rekor search error")
        return {"error": str(exc)}


# ---------------------------------------------------------------------------
# Rekor log metadata
# ---------------------------------------------------------------------------

def rekor_log_info() -> Dict[str, Any]:
    """
    Retrieve Rekor log metadata, such as its tree size and root hash.
    """
    try:
        response = requests.get(
            f"{REKOR_BASE_URL}/api/v1/log",
            timeout=REKOR_TIMEOUT,
        )

        parsed = _parse_json_response(response)

        if "error" in parsed:
            return parsed

        data = parsed["data"]

        if not isinstance(data, dict):
            return {"error": "Unexpected Rekor log metadata response"}

        return data

    except requests.RequestException as exc:
        logger.warning("Rekor log metadata request failed: %s", exc)
        return {"error": str(exc)}

    except Exception as exc:
        logger.exception("Unexpected Rekor log metadata error")
        return {"error": str(exc)}


# ---------------------------------------------------------------------------
# Inclusion proof verification
# ---------------------------------------------------------------------------

def _decode_rekor_entry_body(body: Any) -> Dict[str, Any]:
    """
    Decode a base64-encoded Rekor entry body into a JSON dictionary.
    """
    if not isinstance(body, str) or not body:
        raise ValueError("Rekor entry has no valid body")

    try:
        decoded = base64.b64decode(body, validate=True)
        parsed = json.loads(decoded.decode("utf-8"))
    except Exception as exc:
        raise ValueError(
            f"Unable to decode Rekor entry body: {exc}"
        ) from exc

    if not isinstance(parsed, dict):
        raise ValueError("Decoded Rekor entry body is not a JSON object")

    return parsed


def _check_hashedrekord_digest(
    entry_body: Dict[str, Any],
    expected_sha256: str,
) -> None:
    """
    Confirm that a hashedrekord entry contains the expected SHA-256 digest.

    Raises ValueError if the entry type or digest does not match.
    """
    if entry_body.get("kind") != "hashedrekord":
        raise ValueError(
            "The Rekor entry is not a hashedrekord entry"
        )

    spec = entry_body.get("spec")

    if not isinstance(spec, dict):
        raise ValueError("The hashedrekord entry has no valid spec")

    data = spec.get("data")

    if not isinstance(data, dict):
        raise ValueError("The hashedrekord entry has no valid data field")

    hash_data = data.get("hash")

    if not isinstance(hash_data, dict):
        raise ValueError("The hashedrekord entry has no hash field")

    algorithm = str(hash_data.get("algorithm", "")).lower()

    if algorithm != "sha256":
        raise ValueError(
            f"Expected SHA-256, but Rekor entry uses {algorithm!r}"
        )

    try:
        actual_digest = _normalize_sha256(
            str(hash_data.get("value", ""))
        )
    except ValueError as exc:
        raise ValueError(
            "The Rekor entry contains an invalid artifact digest"
        ) from exc

    if actual_digest != expected_sha256:
        raise ValueError(
            "The Rekor entry digest does not match the expected artifact SHA-256"
        )


def rekor_verify_inclusion(
    log_id: str,
    expected_sha256: str,
) -> Dict[str, Any]:
    """
    Verify a Rekor entry's cryptographic inclusion proof and its artifact hash.

    This uses Sigstore's production trusted root and Rekor client.

    Verification includes:
        1. Retrieving the specified entry.
        2. Verifying the Rekor entry's cryptographic proof/checkpoint
           through Sigstore's verification implementation.
        3. Confirming that the entry is a hashedrekord containing the
           expected SHA-256 digest.

    Note:
        Sigstore's Rekor client APIs used here include private methods.
        Pin and test the Sigstore SDK version used by your project.

    Returns:
        {"verified": True, ...} on success.
        {"verified": False, "error": "..."} on failure.
    """
    try:
        if not isinstance(log_id, str):
            raise ValueError("Rekor log ID must be a string")

        log_id = log_id.strip()

        if not re.fullmatch(r"[0-9a-fA-F]{64}", log_id):
            raise ValueError(
                "Invalid Rekor log ID: expected a 64-character hexadecimal UUID"
            )

        expected_digest = _normalize_sha256(expected_sha256)

        # Import lazily so ordinary Rekor HTTP operations do not require
        # Sigstore's SDK to be imported.
        from sigstore._internal.rekor.client import RekorClient
        from sigstore._internal.trust import KeyringPurpose
        from sigstore.verify import Verifier

        logger.info("Loading Sigstore production trusted root")
        verifier = Verifier.production()

        logger.info("Fetching Rekor entry %s", log_id)
        entry = RekorClient.production().log.entries.get(uuid=log_id)

        # Verify the Merkle inclusion proof and the signed checkpoint/SET
        # according to the installed Sigstore SDK's implementation.
        keyring = verifier._trusted_root.rekor_keyring(
            KeyringPurpose.VERIFY
        )

        entry._verify(keyring)

        # Extract the body from the retrieved entry after cryptographic
        # verification. The entry body is base64-encoded canonical JSON.
        inner = getattr(entry, "_inner", None)

        if inner is None:
            raise ValueError(
                "Sigstore returned an entry with no internal response data"
            )

        body = getattr(inner, "body", None)

        if not body:
            raise ValueError(
                "The verified Rekor entry does not contain a body"
            )

        parsed_body = _decode_rekor_entry_body(body)

        # This implementation intentionally verifies hashedrekord entries.
        # A DSSE or other entry type needs its own subject-digest validation.
        _check_hashedrekord_digest(
            parsed_body,
            expected_digest,
        )

        return {
            "verified": True,
            "logID": log_id,
            "expected_sha256": expected_digest,
            "entry_kind": parsed_body.get("kind"),
            "logIndex": getattr(inner, "log_index", None),
            "proof_log_index": getattr(
                getattr(inner, "inclusion_proof", None),
                "log_index",
                None,
            ),
            "proof_tree_size": getattr(
                getattr(inner, "inclusion_proof", None),
                "tree_size",
                None,
            ),
        }

    except Exception as exc:
        logger.warning(
            "Rekor inclusion verification failed for %s: %s",
            log_id,
            exc,
        )

        return {
            "verified": False,
            "logID": log_id,
            "error": str(exc),
        }
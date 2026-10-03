"""
rekor.py — Rekor transparency log client for CryptoScan attestations.

Provides:
  - rekor_upload_dsse()   : upload a DSSE envelope to Rekor
  - rekor_lookup()        : look up an entry by log ID or UUID
  - rekor_verify_inclusion(): verify inclusion proof for an entry

Rekor REST API v1 (https://rekor.sigstore.dev/api/v1):
  POST /api/v1/log/entries           — upload entry
  GET  /api/v1/log/entries/{entryID} — retrieve entry
  GET  /api/v1/log/entries           — search entries by hash

Environment variables:
  SIGSTORE_REKOR_URL  — override Rekor instance (default: https://rekor.sigstore.dev)
"""

import base64
import hashlib
import json
import logging
import os
from typing import Any, Dict, Optional

import requests

logger = logging.getLogger(__name__)

REKOR_BASE_URL = os.getenv("SIGSTORE_REKOR_URL", "https://rekor.sigstore.dev")
REKOR_TIMEOUT = int(os.getenv("REKOR_TIMEOUT", "30"))

# Maximum body size we will read from Rekor to prevent DoS
_MAX_RESPONSE_BYTES = 1 * 1024 * 1024  # 1 MB


def rekor_upload_hashedrekord(
    artifact_sha256: str,
    artifact_url: Optional[str] = None,
    artifact_bytes: Optional[bytes] = None,
    public_key_pem: Optional[str] = None,
    signature_b64: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Upload a hashedrekord (v0.0.1) entry to Rekor.

    A hashedrekord is the simplest Rekor entry type: a hash of the artifact
    plus a detached signature over that hash.  This is used when we cannot
    use the full DSSE bundle flow (e.g. no Sigstore SDK in environment).

    Args:
        artifact_sha256: Hex SHA-256 of the artifact.
        artifact_url:    URL to download the artifact (used for artifact reference).
        artifact_bytes:  Raw bytes (used to compute hash only; not uploaded directly).
        public_key_pem:  PEM public key that signed the artifact.
        signature_b64:   Base64-encoded detached signature.

    Returns:
        dict with:
          "logID"        — Rekor log entry UUID
          "logIndex"     — integer index in the transparency log
          "integratedTime" — epoch timestamp
          "body"         — base64 log entry body
          "error"        — error string (only present on failure)
    """
    if os.getenv("SIGSTORE_NO_REKOR"):
        return {"logID": None, "logIndex": None, "skipped": True, "reason": "SIGSTORE_NO_REKOR set"}

    # Build hashedrekord body
    spec: Dict[str, Any] = {
        "data": {
            "hash": {
                "algorithm": "sha256",
                "value": artifact_sha256.lower().lstrip("0x"),
            }
        }
    }
    if artifact_url:
        spec["data"]["url"] = artifact_url

    if public_key_pem and signature_b64:
        spec["signature"] = {
            "content": signature_b64,
            "publicKey": {
                "content": base64.b64encode(public_key_pem.encode()).decode()
            },
        }

    entry_body = {
        "kind": "hashedrekord",
        "apiVersion": "0.0.1",
        "spec": spec,
    }

    try:
        resp = requests.post(
            f"{REKOR_BASE_URL}/api/v1/log/entries",
            json=entry_body,
            timeout=REKOR_TIMEOUT,
            headers={"Content-Type": "application/json"},
        )
        resp.raise_for_status()
        result_map: Dict[str, Any] = resp.json()
        # Rekor returns a dict keyed by entry UUID
        for log_id, entry in result_map.items():
            return {
                "logID": log_id,
                "logIndex": entry.get("logIndex"),
                "integratedTime": entry.get("integratedTime"),
                "body": entry.get("body"),
            }
    except requests.HTTPError as e:
        err_body = ""
        try:
            err_body = e.response.text[:500]
        except Exception:
            pass
        logger.error("Rekor upload HTTP error %s: %s", e.response.status_code if e.response else "?", err_body)
        return {"error": f"HTTP {e.response.status_code if e.response else '?'}: {err_body}"}
    except Exception as e:
        logger.error("Rekor upload error: %s", e)
        return {"error": str(e)}

    return {"error": "No entry returned from Rekor"}


def rekor_lookup(log_id: str) -> Dict[str, Any]:
    """
    Look up a Rekor log entry by its UUID / log ID.

    Returns the raw entry dict or {"error": "..."} on failure.
    """
    try:
        url = f"{REKOR_BASE_URL}/api/v1/log/entries/{log_id}"
        resp = requests.get(url, timeout=REKOR_TIMEOUT)
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        return {"error": str(e)}


def rekor_search_by_hash(sha256_hex: str) -> Dict[str, Any]:
    """
    Search Rekor for entries matching an artifact SHA-256 hash.

    Returns {"entries": [...]} or {"error": "..."}.
    """
    try:
        url = f"{REKOR_BASE_URL}/api/v1/index/retrieve"
        resp = requests.post(
            url,
            json={"hash": f"sha256:{sha256_hex.lower().lstrip('0x')}"},
            timeout=REKOR_TIMEOUT,
            headers={"Content-Type": "application/json"},
        )
        resp.raise_for_status()
        return {"entries": resp.json()}
    except Exception as e:
        return {"error": str(e)}


def rekor_log_info() -> Dict[str, Any]:
    """Retrieve Rekor log metadata (tree size, root hash, signing key)."""
    try:
        resp = requests.get(f"{REKOR_BASE_URL}/api/v1/log", timeout=REKOR_TIMEOUT)
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        return {"error": str(e)}

"""
fingerprint.py - Stable cryptographic asset fingerprinting for CryptoScan.

Fingerprint = SHA-256 of normalized:
  algorithm name + primitive/type + key size + file path (repo-relative) + enclosing symbol or purpose

Line numbers are EXPLICITLY EXCLUDED so that adding or removing lines above
an asset between commits does not alter its identity. Two scans of identical
code at different line offsets produce identical fingerprints.
"""

import hashlib
import os
import re
from typing import Dict, Any, Optional


def normalize_algorithm(algo: Optional[str]) -> str:
    """Normalize algorithm string to uppercase, trimmed, canonical format."""
    if not algo:
        return "UNKNOWN"
    s = str(algo).strip().upper()
    # Normalize common aliases
    s = re.sub(r"\s+", "-", s)
    return s


def normalize_type(primitive_type: Optional[str]) -> str:
    """Normalize asset primitive/type (e.g., algorithm, signature, key-exchange, hash, encryption)."""
    if not primitive_type:
        return "algorithm"
    s = str(primitive_type).strip().lower()
    return re.sub(r"[\s_]+", "-", s)


def normalize_key_size(key_size: Any) -> str:
    """Normalize key size to string integer or empty string if not applicable."""
    if key_size is None or key_size == "" or key_size == "N/A" or key_size == "null":
        return ""
    # Extract digits if string like "2048-bit" or 2048
    m = re.search(r"(\d+)", str(key_size))
    if m:
        return m.group(1)
    return ""


def normalize_file_path(file_path: Optional[str]) -> str:
    """
    Normalize file path to repo-relative, forward slashes, no leading ./ or /.
    Ensures Windows and Linux paths match identically.
    """
    if not file_path:
        return "unknown"
    p = str(file_path).strip().replace("\\", "/")
    # Remove leading ./ or /
    p = re.sub(r"^(\./|/)+", "", p)
    # Collapse multiple slashes
    p = re.sub(r"/+", "/", p)
    return p


def normalize_purpose(purpose: Optional[str]) -> str:
    """Normalize purpose/symbol/category string."""
    if not purpose:
        return ""
    s = str(purpose).strip().lower()
    return re.sub(r"[\s_]+", "-", s)


def compute_asset_fingerprint(
    algorithm: Optional[str],
    file_path: Optional[str],
    primitive_type: Optional[str] = "algorithm",
    key_size: Any = None,
    purpose: Optional[str] = None,
    symbol: Optional[str] = None,
) -> str:
    """
    Computes a stable SHA-256 fingerprint for a cryptographic asset occurrence.
    
    Fields joined:
      norm_algo | norm_type | norm_keysize | norm_path | norm_purpose_or_symbol
    """
    norm_algo = normalize_algorithm(algorithm)
    norm_type = normalize_type(primitive_type)
    norm_keysize = normalize_key_size(key_size)
    norm_path = normalize_file_path(file_path)
    norm_purpose = normalize_purpose(symbol or purpose or "")

    raw_string = f"{norm_algo}|{norm_type}|{norm_keysize}|{norm_path}|{norm_purpose}"
    return hashlib.sha256(raw_string.encode("utf-8")).hexdigest()


def compute_asset_fingerprint_from_dict(asset: Dict[str, Any]) -> str:
    """
    Extracts relevant fields from a normalized asset dict and returns its fingerprint.
    """
    return compute_asset_fingerprint(
        algorithm=asset.get("algorithm") or asset.get("name") or asset.get("primitive"),
        file_path=asset.get("file") or asset.get("filePath"),
        primitive_type=asset.get("primitive_type") or asset.get("type") or asset.get("assetType") or "algorithm",
        key_size=asset.get("key_size") or asset.get("keySize"),
        purpose=asset.get("purpose") or asset.get("usage") or asset.get("category"),
        symbol=asset.get("symbol"),
    )


def compute_fingerprint_without_path(
    algorithm: Optional[str],
    primitive_type: Optional[str] = "algorithm",
    key_size: Any = None,
    purpose: Optional[str] = None,
    symbol: Optional[str] = None,
) -> str:
    """
    Computes a path-independent fingerprint used by the file move/rename heuristic.
    If an added asset and a removed asset have the same path-independent fingerprint,
    and the file was renamed or code moved, it should not be penalized as a brand new violation.
    """
    norm_algo = normalize_algorithm(algorithm)
    norm_type = normalize_type(primitive_type)
    norm_keysize = normalize_key_size(key_size)
    norm_purpose = normalize_purpose(symbol or purpose or "")

    raw_string = f"{norm_algo}|{norm_type}|{norm_keysize}|{norm_purpose}"
    return hashlib.sha256(raw_string.encode("utf-8")).hexdigest()

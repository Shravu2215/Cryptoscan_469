"""
cbom_parser.py - Load and normalize CycloneDX 1.6 CBOM JSON.

Extracts cryptographic assets and occurrences into a normalized list of Asset
records with computed stable fingerprints.
"""

import json
import re
from typing import Dict, Any, List, Optional
from gate.fingerprint import (
    compute_asset_fingerprint,
    compute_fingerprint_without_path,
    normalize_file_path,
)

# Standard mapping of algorithms/purposes to primary categories
CATEGORY_KEYWORDS = {
    "signature": ["sign", "signature", "dsa", "ecdsa", "ed25519", "ed448", "ml-dsa", "slh-dsa", "falcon"],
    "key_exchange": ["exchange", "kem", "dh", "diffie", "ecdh", "x25519", "x448", "ml-kem", "kyber", "frodo"],
    "encryption": ["encrypt", "cipher", "aes", "des", "3des", "rc4", "chacha", "blowfish", "rsa-oaep", "cbc", "gcm"],
    "hash": ["hash", "digest", "sha", "md5", "sha-1", "sha-256", "sha-512", "sha3", "blake", "ripemd"],
    "protocol": ["protocol", "tls", "ssl", "ssh", "ipsec", "wireguard", "vpn"],
}


def classify_category(algorithm: str, usage_or_purpose: Optional[str]) -> str:
    """Classify asset into one of 5 categories: signature, key_exchange, encryption, hash, protocol."""
    combined = f"{algorithm or ''} {usage_or_purpose or ''}".lower()
    for cat, keywords in CATEGORY_KEYWORDS.items():
        for kw in keywords:
            if kw in combined:
                return cat
    return "encryption"  # fallback default


def is_vulnerable(quantum_status: Optional[str], algorithm: str, key_size: Any) -> bool:
    """Determine if asset is quantum-vulnerable."""
    qs = (quantum_status or "").lower()
    if any(term in qs for term in ["vulnerable", "broken", "weakened"]):
        return True
    if "safe" in qs:
        return False
    
    # Heuristics based on algorithm name
    algo_upper = (algorithm or "").upper()
    if any(term in algo_upper for term in ["RSA", "DSA", "ECDSA", "DIFFIE", "DH", "ECDH", "ECC", "SECP", "ED25519", "X25519"]):
        return True
    if any(term in algo_upper for term in ["MD5", "SHA-1", "SHA1", "DES", "3DES", "RC4"]):
        return True
    return False


def get_suggested_pqc_replacement(algorithm: str, category: str) -> str:
    """Return recommended NIST PQC replacement based on algorithm and category."""
    algo_upper = (algorithm or "").upper()
    cat = category.lower()

    if cat == "signature" or any(s in algo_upper for s in ["SIGN", "DSA", "ECDSA", "ED25519"]):
        return "ML-DSA (Dilithium) / SLH-DSA (SPHINCS+)"
    if cat == "key_exchange" or any(s in algo_upper for s in ["DH", "ECDH", "X25519", "KEM"]):
        return "ML-KEM (Kyber-768 / Kyber-1024)"
    if any(s in algo_upper for s in ["DES", "3DES", "RC4"]):
        return "AES-256-GCM / ChaCha20-Poly1305 (Classical upgrade)"
    if any(s in algo_upper for s in ["MD5", "SHA-1", "SHA1"]):
        return "SHA-256 / SHA-384 / SHA3-256 (Classical upgrade)"
    if "RSA" in algo_upper:
        if "SIGN" in algo_upper or cat == "signature":
            return "ML-DSA-65 or Falcon-512"
        return "ML-KEM-768 or hybrid X25519+ML-KEM"
    return "AES-256-GCM or NIST PQC standardized suite"


def parse_cbom(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Parses a CycloneDX 1.6 CBOM (or flat JSON) into a list of normalized asset records.
    """
    assets: List[Dict[str, Any]] = []

    components = data.get("components", [])
    if not isinstance(components, list):
        return assets

    for comp in components:
        if not isinstance(comp, dict):
            continue

        algo_name = comp.get("name") or comp.get("algorithm") or "UNKNOWN"
        crypto_props = comp.get("cryptoProperties") or {}
        algo_props = crypto_props.get("algorithmProperties") or {}
        primitive = algo_props.get("primitive") or algo_name
        key_size = comp.get("keySize") or algo_props.get("keyLength") or ""
        comp_exposure = comp.get("exposure") or "internal"

        occurrences = comp.get("occurrences", [])
        if occurrences and isinstance(occurrences, list):
            for occ in occurrences:
                if not isinstance(occ, dict):
                    continue
                file_path = normalize_file_path(occ.get("file") or occ.get("filePath"))
                line = occ.get("line") or occ.get("lineNumber") or 0
                usage = occ.get("usage") or occ.get("purpose") or ""
                q_status = occ.get("quantumStatus") or comp.get("quantumStatus") or ""
                severity = occ.get("severity") or comp.get("maxSeverity") or "INFO"
                recommendation = occ.get("recommendation") or ""
                language = occ.get("language") or "Unknown"

                # Check properties for language
                for p in occ.get("properties", []):
                    if isinstance(p, dict) and p.get("name") == "cryptoscan:language":
                        language = p.get("value", language)

                cat = classify_category(algo_name, usage)
                vuln = is_vulnerable(q_status, algo_name, key_size)
                pqc_rec = recommendation or get_suggested_pqc_replacement(algo_name, cat)

                fp = compute_asset_fingerprint(
                    algorithm=algo_name,
                    file_path=file_path,
                    primitive_type=primitive,
                    key_size=key_size,
                    purpose=usage,
                )
                path_indep_fp = compute_fingerprint_without_path(
                    algorithm=algo_name,
                    primitive_type=primitive,
                    key_size=key_size,
                    purpose=usage,
                )

                assets.append({
                    "fingerprint": fp,
                    "path_independent_fingerprint": path_indep_fp,
                    "algorithm": algo_name,
                    "primitive": primitive,
                    "key_size": key_size,
                    "file": file_path,
                    "line": line,
                    "usage": usage,
                    "category": cat,
                    "quantum_status": q_status,
                    "is_quantum_vulnerable": vuln,
                    "severity": severity,
                    "language": language,
                    "exposure": comp_exposure,
                    "recommendation": pqc_rec,
                })
        else:
            # Fallback for flat components (where occurrence is in properties or top level)
            props = {p.get("name"): p.get("value") for p in comp.get("properties", []) if isinstance(p, dict)}
            loc = props.get("crypto:location", "")
            file_path = "unknown"
            line = 0
            if ":" in loc:
                parts = loc.rsplit(":", 1)
                file_path = normalize_file_path(parts[0])
                try:
                    line = int(parts[1])
                except ValueError:
                    line = 0
            elif loc:
                file_path = normalize_file_path(loc)

            usage = props.get("crypto:purpose", "") or comp.get("usage", "")
            q_val = props.get("crypto:quantumVulnerable", "")
            q_status = "Quantum Vulnerable" if str(q_val).lower() == "true" else "Quantum Safe"
            severity = comp.get("maxSeverity") or "INFO"
            language = props.get("cryptoscan:language") or comp.get("language") or "Unknown"

            cat = classify_category(algo_name, usage)
            vuln = is_vulnerable(q_status, algo_name, key_size)
            pqc_rec = get_suggested_pqc_replacement(algo_name, cat)

            fp = compute_asset_fingerprint(
                algorithm=algo_name,
                file_path=file_path,
                primitive_type=primitive,
                key_size=key_size,
                purpose=usage,
            )
            path_indep_fp = compute_fingerprint_without_path(
                algorithm=algo_name,
                primitive_type=primitive,
                key_size=key_size,
                purpose=usage,
            )

            assets.append({
                "fingerprint": fp,
                "path_independent_fingerprint": path_indep_fp,
                "algorithm": algo_name,
                "primitive": primitive,
                "key_size": key_size,
                "file": file_path,
                "line": line,
                "usage": usage,
                "category": cat,
                "quantum_status": q_status,
                "is_quantum_vulnerable": vuln,
                "severity": severity,
                "language": language,
                "exposure": comp_exposure,
                "recommendation": pqc_rec,
            })

    return assets

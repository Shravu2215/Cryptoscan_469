"""Classify runtime metadata with the static scanner's shared rule profiles."""

import json
import re
import sys
from urllib.parse import urlparse
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scanner.models import QuantumRisk, Severity
from scanner.rules import (
    HASH_ALGOS,
    INSECURE_RNG,
    JWT_ALGOS,
    KDF_ALGOS,
    SAFE_CSPRNG_PROFILE,
    classify_algorithm,
    ecc_profile,
    rsa_profile,
    symmetric_profile,
)


def _plain_profile(profile):
    if not profile:
        return None
    return {
        "algorithm": profile.get("algorithm", "UNKNOWN"),
        "severity": profile.get("severity", Severity.INFO).value,
        "quantumRisk": profile.get("quantum_risk", QuantumRisk.SAFE).value,
        "recommendation": profile.get("recommendation", ""),
        "category": profile.get("category", "algorithm"),
    }


def _normalize_hash(value):
    normalized = str(value or "").lower().replace("_", "-").replace(" ", "")
    aliases = {
        "sha1": "sha1", "sha-1": "sha1", "sha256": "sha256", "sha-256": "sha256",
        "sha384": "sha384", "sha-384": "sha384", "sha512": "sha512", "sha-512": "sha512",
        "sha3": "sha3", "sha-3": "sha3", "sha3-256": "sha3", "sha-3-256": "sha3",
        "sha3-384": "sha3", "sha3-512": "sha3", "md5": "md5",
        "keccak": "sha3", "keccak256": "sha3", "keccak-256": "sha3",
    }
    return aliases.get(normalized)


def _crypto_profile(event):
    algorithm = str(event.get("algorithm") or "").strip()
    normalized = algorithm.lower().replace("_", "-")
    operation = str(event.get("operation") or "").lower()
    key_info = event.get("keyInfo") or {}
    mode = str(key_info.get("mode") or "").upper()
    key_bits = key_info.get("keySize") or key_info.get("modulusLength")

    if algorithm in {"eth_sendTransaction", "personal_sign", "eth_signTypedData", "eth_signTypedData_v3", "eth_signTypedData_v4", "eth_requestAccounts"}:
        profile = _plain_profile(ecc_profile("secp256k1", "signature"))
        profile["algorithm"] = "ECDSA secp256k1"
        return profile

    if algorithm in {"Math.random", "Non-cryptographic PRNG", "random"} or normalized.startswith("python random.") or normalized == "math.random":
        profile = dict(INSECURE_RNG)
        profile["severity"] = Severity.INFO
        profile["quantum_risk"] = QuantumRisk.SAFE
        profile["recommendation"] = "Non-cryptographic PRNG observed; this is only a risk if used for security values. Use a CSPRNG for keys, tokens, IVs, and nonces."
        return _plain_profile(profile)
    if algorithm in {"crypto.getRandomValues", "crypto.randomUUID", "secrets", "os.urandom", "uuid.uuid4", "CSPRNG"}:
        return _plain_profile(SAFE_CSPRNG_PROFILE)

    if normalized.startswith("jwt "):
        jwt_algorithm = normalized.split(" ", 1)[1]
        return _plain_profile(JWT_ALGOS.get(jwt_algorithm))
    if normalized in JWT_ALGOS:
        return _plain_profile(JWT_ALGOS[normalized])

    if "aes" in normalized:
        suffix_mode = re.search(r"aes(?:-\d+)?-(gcm|cbc|ctr|ecb|ccm|ocb)", normalized)
        cipher_mode = mode or (suffix_mode.group(1).upper() if suffix_mode else "")
        return _plain_profile(symmetric_profile("AES", cipher_mode, int(key_bits) if key_bits else None))

    if normalized.startswith("rsa") or normalized in {"rsassa-pkcs1-v1_5", "rsa-pss"}:
        return _plain_profile(rsa_profile(int(key_bits) if key_bits else None))

    if normalized in {"ecdsa", "ecdh", "ed25519", "ed448", "secp256k1", "ec", "wallet signing"}:
        curve = key_info.get("curve") or ("secp256k1" if normalized == "wallet signing" else normalized)
        purpose = "key_exchange" if normalized == "ecdh" or operation in {"derivekey", "derivebits", "key_exchange"} else "signature"
        return _plain_profile(ecc_profile(str(curve), purpose))

    digest = _normalize_hash(algorithm)
    if digest:
        weak = classify_algorithm(digest)
        if weak:
            return _plain_profile(weak)
        return _plain_profile(HASH_ALGOS.get(digest))

    if normalized in KDF_ALGOS:
        return _plain_profile(KDF_ALGOS[normalized])

    hmac_match = re.fullmatch(r"hmac[- ]?(sha[- ]?\d+|md5)?", normalized)
    if hmac_match:
        digest = _normalize_hash(hmac_match.group(1) or key_info.get("hash"))
        if digest in {"md5", "sha1"}:
            return _plain_profile(classify_algorithm(digest))
        if digest:
            return _plain_profile(HASH_ALGOS.get(digest))

    weak = classify_algorithm(algorithm)
    if weak:
        return _plain_profile(weak)
    return None


def classify_event(event):
    source = event.get("source")
    algorithm = str(event.get("algorithm") or "Observed operation")
    operation = str(event.get("operation") or "observed")
    host_origin = str(event.get("hostOrigin") or "")
    key_info = event.get("keyInfo") or {}

    if source == "crypto":
        return _crypto_profile(event)
    if source == "network":
        findings = []
        if event.get("scheme") in {"http", "ws"}:
            findings.append({
                "algorithm": "Unencrypted transport",
                "severity": Severity.HIGH.value,
                "quantumRisk": QuantumRisk.CLASSICAL_RISK.value,
                "recommendation": "Serve this request over HTTPS/WSS to protect data in transit.",
                "category": "protocol",
                "description": "Unencrypted transport (no TLS) observed",
            })
        target_host = urlparse(str(event.get("targetOrigin") or "")).hostname
        observed_host = urlparse(host_origin).hostname if host_origin else None
        if observed_host and target_host and observed_host.lower() != target_host.lower():
            findings.append({
                "algorithm": "Cross-origin host",
                "severity": Severity.INFO.value,
                "quantumRisk": QuantumRisk.SAFE.value,
                "recommendation": "Review this third-party host and its data-handling requirements.",
                "category": "network",
                "description": "Third-party host observed during this session.",
            })
        return findings
    if source == "library":
        return {
            "algorithm": algorithm,
            "severity": Severity.INFO.value,
            "quantumRisk": QuantumRisk.SAFE.value,
            "recommendation": "Review this loaded cryptographic library and verify it is current and configured securely.",
            "category": "library",
        }
    if source == "wasm":
        return {
            "algorithm": "WebAssembly module",
            "severity": Severity.INFO.value,
            "quantumRisk": QuantumRisk.SAFE.value,
            "recommendation": "WASM module loaded (possible embedded crypto, not analyzable). Review the module separately.",
            "category": "library",
        }
    if source == "tls":
        if operation in {"load", "handshake"}:
            info = event.get("keyInfo") or {}
            version = info.get("version") or algorithm
            cipher = info.get("cipherSuite") or ""
            if version in {"TLSv1", "TLSv1.1"}:
                from scanner.live_tls_analyzer import LiveTLSAnalyzer
                finding = next(
                    finding for finding in LiveTLSAnalyzer()._check_protocol(host_origin, version)
                    if finding.algorithm == version
                )
                return {
                    "algorithm": finding.algorithm,
                    "severity": finding.severity.value,
                    "quantumRisk": finding.quantum_risk.value,
                    "recommendation": finding.recommendation,
                    "category": "protocol",
                    "description": finding.message,
                }
            return {
                "algorithm": str(version),
                "severity": Severity.INFO.value,
                "quantumRisk": QuantumRisk.SAFE.value,
                "recommendation": "Negotiated TLS version and cipher observed during this session.",
                "category": "protocol",
                "description": f"{version} negotiated with {cipher}.".strip(),
            }
        if operation == "protocol":
            if algorithm in {"TLSv1", "TLSv1.1"}:
                from scanner.live_tls_analyzer import LiveTLSAnalyzer
                finding = next(
                    finding for finding in LiveTLSAnalyzer()._check_protocol(host_origin, algorithm)
                    if finding.algorithm == algorithm
                )
                return {
                    "algorithm": finding.algorithm,
                    "severity": finding.severity.value,
                    "quantumRisk": finding.quantum_risk.value,
                    "recommendation": finding.recommendation,
                    "category": "protocol",
                    "description": finding.message,
                }
            return {
                "algorithm": algorithm,
                "severity": Severity.INFO.value,
                "quantumRisk": QuantumRisk.SAFE.value,
                "recommendation": "Accepted TLS protocol version observed during this session.",
                "category": "protocol",
                "description": f"{algorithm} accepted during this session.",
            }
        if operation == "certificate":
            profile = _crypto_profile({
                "source": "crypto",
                "algorithm": algorithm,
                "operation": "sign",
                "keyInfo": key_info,
            })
            if profile:
                profile["category"] = "certificate"
                return profile
        if operation == "signature":
            signature = algorithm.lower().replace("_", "-")
            digest = next((name for name in ("sha512", "sha384", "sha256", "sha1", "md5", "sha3") if name in signature.replace("-", "")), None)
            return _crypto_profile({"source": "crypto", "algorithm": digest or algorithm, "operation": "hash"})
        if operation == "key_exchange" and "ecdhe" in algorithm.lower():
            profile = _plain_profile(ecc_profile("ECDH", "key_exchange"))
            profile["algorithm"] = "ECDHE"
            profile["category"] = "protocol"
            return profile
    return None


def classify(events):
    results = []
    for event in events:
        classified = classify_event(event)
        if isinstance(classified, list):
            results.extend((event, finding) for finding in classified)
        elif classified:
            results.append((event, classified))
    return results


if __name__ == "__main__":
    payload = json.load(sys.stdin)
    output = []
    for event, finding in classify(payload.get("events", [])):
        output.append({"event": event, "finding": finding})
    json.dump(output, sys.stdout, separators=(",", ":"))
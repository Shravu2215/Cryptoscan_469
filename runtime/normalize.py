"""
Canonical Algorithm Normalization Module for CryptoScan Runtime Tracing.
Maps raw algorithm, library, or cipher strings into standard canonical representations.
"""

import re
from typing import Optional

# Canonical mapping dictionary
ALGORITHM_MAP = {
    # Hash functions
    "md5": "MD5",
    "sha1": "SHA-1",
    "sha-1": "SHA-1",
    "sha224": "SHA-224",
    "sha-224": "SHA-224",
    "sha256": "SHA-256",
    "sha-256": "SHA-256",
    "sha_256": "SHA-256",
    "sha384": "SHA-384",
    "sha-384": "SHA-384",
    "sha_384": "SHA-384",
    "sha512": "SHA-512",
    "sha-512": "SHA-512",
    "sha_512": "SHA-512",
    "sha3_256": "SHA3-256",
    "sha3-256": "SHA3-256",
    "sha3_512": "SHA3-512",
    "sha3-512": "SHA3-512",
    "blake2b": "BLAKE2b",
    "blake2s": "BLAKE2s",
    
    # Symmetric Ciphers
    "aes": "AES",
    "aes128": "AES-128",
    "aes-128": "AES-128",
    "aes192": "AES-192",
    "aes-192": "AES-192",
    "aes256": "AES-256",
    "aes-256": "AES-256",
    "des": "DES",
    "3des": "3DES",
    "tripledes": "3DES",
    "rc4": "RC4",
    "chacha20": "ChaCha20",
    "chacha20-poly1305": "ChaCha20-Poly1305",
    
    # Asymmetric Ciphers & Signatures
    "rsa": "RSA",
    "dsa": "DSA",
    "ecdsa": "ECDSA",
    "ec": "ECDSA",
    "ecdh": "ECDH",
    "ed25519": "Ed25519",
    "ed448": "Ed448",
    "ecdh": "ECDH",
    "dh": "DH",
    
    # KDF & Password Hashing
    "pbkdf2": "PBKDF2",
    "scrypt": "scrypt",
    "argon2": "Argon2",
    "argon2i": "Argon2i",
    "argon2id": "Argon2id",
    "bcrypt": "bcrypt",
    "hkdf": "HKDF",
    
    # MAC
    "hmac": "HMAC",
    "hmac-sha256": "HMAC-SHA256",
    "hmacsha256": "HMAC-SHA256",
    "hmac-sha512": "HMAC-SHA512",
    "hmacsha512": "HMAC-SHA512",
}

VALID_OPERATIONS = {
    "hash",
    "encrypt",
    "decrypt",
    "sign",
    "verify",
    "keygen",
    "kdf",
    "hmac",
    "tls",
    "other",
}


def normalize_algorithm(raw_name: Optional[str]) -> str:
    """
    Normalizes raw algorithm/cipher strings to standard canonical form.
    E.g. 'sha256', 'SHA256', 'sha-256' -> 'SHA-256'.
    """
    if not raw_name:
        return "UNKNOWN"
    
    cleaned = raw_name.strip().lower()
    
    # Exact lookup
    if cleaned in ALGORITHM_MAP:
        return ALGORITHM_MAP[cleaned]
    
    # Strip common prefixes/suffixes (e.g. 'aes-256-gcm' -> 'AES')
    if cleaned.startswith("aes"):
        return "AES"
    if cleaned.startswith("rsa"):
        return "RSA"
    if cleaned.startswith("ecdsa") or cleaned.startswith("ec-") or cleaned == "secp256r1" or cleaned == "ec":
        return "ECDSA"
    if "sha256" in cleaned or "sha-256" in cleaned:
        return "SHA-256"
    if "sha512" in cleaned or "sha-512" in cleaned:
        return "SHA-512"
    if "sha1" in cleaned or "sha-1" in cleaned:
        return "SHA-1"
    if "md5" in cleaned:
        return "MD5"
    if "hmac" in cleaned:
        return "HMAC"
    
    # Return uppercase representation if unknown pattern
    return raw_name.strip().upper()

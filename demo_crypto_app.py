"""
CryptoScan demo app (safe, offline, deterministic).

Purpose: give the scanner something to find, both statically (reading code)
and at runtime (watching execution).

EXECUTED paths (expect: Static + Runtime = "Confirmed Active"):
  1. hash_data()        -> SHA-256
  2. aes_encrypt()      -> AES-256-GCM
  3. rsa_sign_verify()  -> RSA-2048 + PSS + SHA-256
  4. ecdsa_sign()       -> ECDSA P-256 + SHA-256

NEVER EXECUTED (expect: Static Only):
  5. legacy_weak_crypto() -> MD5, SHA-1, RSA-1024
     It is defined but never called, so a runtime trace must NOT see it.

Requires:  pip install cryptography
Run:       python demo_crypto_app.py
"""

import hashlib
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ---------------------------------------------------------------- executed --

def hash_data(data: bytes) -> str:
    """SHA-256 hash."""
    return hashlib.sha256(data).hexdigest()


def aes_encrypt(plaintext: bytes) -> bytes:
    """AES-256-GCM encryption (256-bit key)."""
    key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, None)


def rsa_sign_verify(message: bytes) -> bool:
    """RSA-2048 signature using PSS padding and SHA-256."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pss = padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH,
    )
    signature = private_key.sign(message, pss, hashes.SHA256())
    private_key.public_key().verify(signature, message, pss, hashes.SHA256())
    return True


def ecdsa_sign(message: bytes) -> bytes:
    """ECDSA on curve P-256 with SHA-256."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    return private_key.sign(message, ec.ECDSA(hashes.SHA256()))


# ----------------------------------------------------------- never executed --

def legacy_weak_crypto(data: bytes):
    """Weak algorithms. Defined but NEVER called anywhere."""
    md5_digest = hashlib.md5(data).hexdigest()
    sha1_digest = hashlib.sha1(data).hexdigest()
    weak_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    return md5_digest, sha1_digest, weak_key


# --------------------------------------------------------------------- main --

def main():
    message = b"cryptoscan demo message"
    print("SHA-256 :", hash_data(message))
    print("AES-GCM :", len(aes_encrypt(message)), "bytes")
    print("RSA-PSS :", rsa_sign_verify(message))
    print("ECDSA   :", len(ecdsa_sign(message)), "byte signature")
    # legacy_weak_crypto() is intentionally NOT called.


if __name__ == "__main__":
    main()
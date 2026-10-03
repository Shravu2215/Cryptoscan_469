# Demo file for Crypto Ratchet Gate test. Not real application code.
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, ec

def make_signing_key():
    # RSA-2048: quantum-vulnerable
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

def make_ec_key():
    # ECDSA P-256: quantum-vulnerable
    return ec.generate_private_key(ec.SECP256R1())

def legacy_checksum(data: bytes) -> str:
    # MD5: prohibited by policy
    return hashlib.md5(data).hexdigest()

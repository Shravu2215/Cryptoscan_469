"""
CryptoScan Runtime Demo Application (Python)
Demonstrates active runtime cryptographic execution paths alongside unexecuted static paths.
"""

import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


def run_executed_crypto_paths():
    print("[Python Demo] Executing SHA-256...")
    h = hashlib.sha256(b"sample_data_for_hashing")
    _ = h.hexdigest()

    print("[Python Demo] Executing AES-256-GCM...")
    key = b"01234567890123456789012345678901"
    iv = b"012345678901"
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
    encryptor = cipher.encryptor()
    _ = encryptor.update(b"secret_payload") + encryptor.finalize()

    print("[Python Demo] Executing RSA-2048 KeyGen & Sign...")
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    signature = rsa_key.sign(
        b"message_to_sign",
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    print("[Python Demo] Executing ECDSA P-256 KeyGen...")
    _ = ec.generate_private_key(ec.SECP256R1())
    print("[Python Demo] All executed paths completed successfully.")


def unexecuted_static_only_path():
    """
    This function contains a vulnerable legacy MD5 hash call
    that is NEVER executed at runtime.
    Static AST scan will flag this finding, but execution tracing will recorded 0 events for it.
    """
    if False:  # Always False -> never called at runtime
        bad_hash = hashlib.md5(b"deprecated_weak_password_hash")
        return bad_hash.hexdigest()


if __name__ == "__main__":
    run_executed_crypto_paths()

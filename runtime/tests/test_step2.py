"""
Unit tests for Step 2: Runtime event schema validation and algorithm normalization.
"""

import unittest
from runtime.normalize import normalize_algorithm
from runtime.schema import RuntimeEvent, validate_event_dict


class TestStep2Normalize(unittest.TestCase):
    def test_hash_normalization(self):
        self.assertEqual(normalize_algorithm("sha256"), "SHA-256")
        self.assertEqual(normalize_algorithm("SHA256"), "SHA-256")
        self.assertEqual(normalize_algorithm("sha-256"), "SHA-256")
        self.assertEqual(normalize_algorithm("sha_256"), "SHA-256")
        self.assertEqual(normalize_algorithm("md5"), "MD5")
        self.assertEqual(normalize_algorithm("sha512"), "SHA-512")

    def test_cipher_normalization(self):
        self.assertEqual(normalize_algorithm("aes-256-gcm"), "AES")
        self.assertEqual(normalize_algorithm("AES"), "AES")
        self.assertEqual(normalize_algorithm("rsa-2048"), "RSA")
        self.assertEqual(normalize_algorithm("secp256r1"), "ECDSA")

    def test_unknown_normalization(self):
        self.assertEqual(normalize_algorithm("custom-algo"), "CUSTOM-ALGO")
        self.assertEqual(normalize_algorithm(None), "UNKNOWN")


class TestStep2Schema(unittest.TestCase):
    def test_sample_event_validation(self):
        sample_dict = {
            "event_id": "evt-12345",
            "run_id": "run-67890",
            "timestamp": "2026-10-03T12:00:00Z",
            "language": "python",
            "library": "hashlib",
            "operation": "hash",
            "algorithm": "sha256",
            "key_size": None,
            "mode": None,
            "padding": None,
            "curve": None,
            "call_file": "app.py",
            "call_line": 42,
            "call_function": "do_hash",
            "matched_finding_id": None,
        }
        
        event = validate_event_dict(sample_dict)
        self.assertEqual(event.event_id, "evt-12345")
        self.assertEqual(event.run_id, "run-67890")
        self.assertEqual(event.algorithm, "SHA-256")
        self.assertEqual(event.operation, "hash")
        self.assertEqual(event.call_line, 42)

    def test_invalid_language_or_operation(self):
        sample_dict = {
            "run_id": "run-1",
            "language": "ruby",  # Invalid
            "library": "crypto",
            "operation": "hash",
            "algorithm": "SHA-256",
        }
        with self.assertRaises(ValueError):
            validate_event_dict(sample_dict)

        sample_dict_2 = {
            "run_id": "run-1",
            "language": "python",
            "library": "crypto",
            "operation": "magic_spell",  # Invalid
            "algorithm": "SHA-256",
        }
        with self.assertRaises(ValueError):
            validate_event_dict(sample_dict_2)


if __name__ == "__main__":
    unittest.main()

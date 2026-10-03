"""
tests/test_attestation.py — Unit tests for CryptoScan Feature 7 (Attestations).

Tests:
  1. in-toto Statement v1 structure and subject SHA-256
  2. Statement predicate field completeness
  3. Component fingerprint stability (same input → same fingerprints)
  4. Offline bundle signer (no Sigstore SDK required)
  5. Hybrid ML-DSA-65 envelope wrap/verify (stub mode)
  6. Verifier — passes when all checks succeed (mocked Sigstore)
  7. Verifier — fails when CBOM SHA-256 is tampered
  8. Rekor search by hash (mocked HTTP)
"""

import hashlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

# Ensure repo root is on sys.path
_REPO_ROOT = str(Path(__file__).parent.parent.parent)
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)


# ── Fixtures ───────────────────────────────────────────────────────────────────

SAMPLE_CBOM = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "serialNumber": "urn:uuid:test-1234",
    "metadata": {
        "component": {"name": "test-repo", "version": "1.0.0"},
    },
    "components": [
        {
            "name": "RSA",
            "type": "cryptographic-asset",
            "properties": [
                {"name": "cryptoscan:file", "value": "src/auth.py"},
                {"name": "cryptoscan:quantumStatus", "value": "VULNERABLE"},
                {"name": "cryptoscan:language", "value": "Python"},
            ],
            "occurrences": [{"file": "src/auth.py", "line": 42}],
        },
        {
            "name": "AES-256-GCM",
            "type": "cryptographic-asset",
            "properties": [
                {"name": "cryptoscan:file", "value": "src/crypto.py"},
                {"name": "cryptoscan:quantumStatus", "value": "SAFE"},
                {"name": "cryptoscan:language", "value": "Python"},
            ],
            "occurrences": [{"file": "src/crypto.py", "line": 88}],
        },
    ],
}


def _write_cbom(tmp_dir: str) -> str:
    """Write sample CBOM to a temp file and return its path."""
    cbom_path = os.path.join(tmp_dir, "cbom.json")
    with open(cbom_path, "w", encoding="utf-8") as f:
        json.dump(SAMPLE_CBOM, f)
    return cbom_path


# ── Test: in-toto Statement ────────────────────────────────────────────────────

class TestStatement(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.cbom_path = _write_cbom(self.tmp)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_statement_type(self):
        from attestation.statement import build_statement, STATEMENT_TYPE
        stmt = build_statement(self.cbom_path)
        self.assertEqual(stmt["_type"], STATEMENT_TYPE)

    def test_subject_sha256_matches_file(self):
        from attestation.statement import build_statement, sha256_file
        stmt = build_statement(self.cbom_path)
        expected_sha = sha256_file(self.cbom_path)
        self.assertEqual(stmt["subject"][0]["digest"]["sha256"], expected_sha)

    def test_subject_name_is_basename(self):
        from attestation.statement import build_statement
        stmt = build_statement(self.cbom_path)
        self.assertEqual(stmt["subject"][0]["name"], "cbom.json")

    def test_predicate_type(self):
        from attestation.statement import build_statement, PREDICATE_TYPE
        stmt = build_statement(self.cbom_path)
        self.assertEqual(stmt["predicateType"], PREDICATE_TYPE)

    def test_summary_fields(self):
        from attestation.statement import build_statement
        stmt = build_statement(self.cbom_path)
        summary = stmt["predicate"]["summary"]
        self.assertEqual(summary["totalComponents"], 2)
        self.assertGreaterEqual(summary["quantumVulnerableComponents"], 1)
        self.assertGreaterEqual(summary["compliantComponents"], 1)

    def test_component_fingerprints_count(self):
        from attestation.statement import build_statement
        stmt = build_statement(self.cbom_path)
        fps = stmt["predicate"]["componentFingerprints"]
        self.assertEqual(len(fps), 2)

    def test_component_fingerprint_stability(self):
        """Same CBOM must produce identical fingerprints across two calls."""
        from attestation.statement import build_statement
        s1 = build_statement(self.cbom_path)
        s2 = build_statement(self.cbom_path)
        self.assertEqual(
            s1["predicate"]["componentFingerprints"],
            s2["predicate"]["componentFingerprints"],
        )

    def test_custom_metadata(self):
        from attestation.statement import build_statement
        metadata = {
            "repository": "my-org/my-repo",
            "commit": "abc123",
            "branch": "main",
        }
        stmt = build_statement(self.cbom_path, metadata=metadata)
        self.assertEqual(stmt["predicate"]["repository"], "my-org/my-repo")
        self.assertEqual(stmt["predicate"]["commit"], "abc123")

    def test_file_not_found(self):
        from attestation.statement import build_statement
        with self.assertRaises(FileNotFoundError):
            build_statement("/nonexistent/path/cbom.json")

    def test_statement_to_json_is_valid_json(self):
        from attestation.statement import build_statement, statement_to_json
        stmt = build_statement(self.cbom_path)
        j = statement_to_json(stmt)
        parsed = json.loads(j)
        self.assertIn("_type", parsed)


# ── Test: Signer (offline fallback path) ──────────────────────────────────────

class TestSignerOffline(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.cbom_path = _write_cbom(self.tmp)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _get_statement(self):
        from attestation.statement import build_statement
        return build_statement(self.cbom_path)

    def test_offline_bundle_has_artifact_sha256(self):
        """Offline bundle must contain the SHA-256 of the statement bytes."""
        import attestation.signer as signer_mod
        orig = signer_mod._SIGSTORE_AVAILABLE
        signer_mod._SIGSTORE_AVAILABLE = False
        try:
            stmt = self._get_statement()
            result = signer_mod.sign_statement(stmt)
            self.assertIn("artifact_sha256", result)
            self.assertFalse(result["signed"])
            # Verify the SHA-256 matches canonical bytes
            canonical = signer_mod._canonical_bytes(stmt)
            expected_sha = signer_mod._sha256_hex(canonical)
            self.assertEqual(result["artifact_sha256"], expected_sha)
        finally:
            signer_mod._SIGSTORE_AVAILABLE = orig

    def test_offline_bundle_writes_to_file(self):
        import attestation.signer as signer_mod
        orig = signer_mod._SIGSTORE_AVAILABLE
        signer_mod._SIGSTORE_AVAILABLE = False
        try:
            stmt = self._get_statement()
            bundle_path = os.path.join(self.tmp, "test.bundle.json")
            signer_mod.sign_statement(stmt, output_bundle_path=bundle_path)
            self.assertTrue(os.path.isfile(bundle_path))
            with open(bundle_path, encoding="utf-8") as f:
                data = json.load(f)
            self.assertIn("messageSignature", data)
        finally:
            signer_mod._SIGSTORE_AVAILABLE = orig

    def test_canonical_bytes_are_deterministic(self):
        import attestation.signer as signer_mod
        stmt = self._get_statement()
        b1 = signer_mod._canonical_bytes(stmt)
        b2 = signer_mod._canonical_bytes(stmt)
        self.assertEqual(b1, b2)
        # Must be valid UTF-8 JSON
        json.loads(b1.decode("utf-8"))


# ── Test: PQC Wrap ────────────────────────────────────────────────────────────

class TestPQCWrap(unittest.TestCase):

    def test_wrap_and_verify_stub(self):
        """In stub mode wrap_bundle_with_pqc + verify_hybrid_envelope must produce a consistent digest."""
        import attestation.pqc_wrap as pqc
        bundle_dict = {"test": "bundle", "value": 42}
        envelope = pqc.wrap_bundle_with_pqc(bundle_dict)
        self.assertIn("sigstoreBundle", envelope)
        self.assertIn("bundleDigest", envelope)
        self.assertEqual(envelope["pqcAlgorithm"], "ML-DSA-65 (FIPS 204)")
        self.assertEqual(envelope["experimental"], True)

    def test_bundle_digest_is_deterministic(self):
        import attestation.pqc_wrap as pqc
        bundle_dict = {"a": 1, "b": 2}
        e1 = pqc.wrap_bundle_with_pqc(bundle_dict)
        e2 = pqc.wrap_bundle_with_pqc(bundle_dict)
        self.assertEqual(e1["bundleDigest"], e2["bundleDigest"])

    def test_verify_detects_tampered_bundle(self):
        import attestation.pqc_wrap as pqc
        bundle_dict = {"x": "original"}
        envelope = pqc.wrap_bundle_with_pqc(bundle_dict)
        # Tamper the inner bundle
        envelope["sigstoreBundle"]["x"] = "TAMPERED"
        result = pqc.verify_hybrid_envelope(envelope)
        self.assertFalse(result["valid"])
        self.assertTrue(any("digest" in e.lower() or "tamper" in e.lower() for e in result["errors"]))

    def test_cryptography_mldsa65_sign_verify(self):
        """Test ML-DSA-65 keygen, sign, verify using cryptography or dilithium-py."""
        import attestation.pqc_wrap as pqc
        if pqc._ML_DSA_MODE == "stub":
            self.skipTest("Neither cryptography>=44 nor dilithium-py available")
        sk, pk = pqc.generate_mldsa65_keypair()
        self.assertTrue(len(sk) > 0)
        self.assertTrue(len(pk) > 0)
        msg = b"CryptoScan ML-DSA-65 test payload"
        sig = pqc.mldsa65_sign(msg, sk)
        self.assertTrue(len(sig) > 0)
        self.assertTrue(pqc.mldsa65_verify(msg, sig, pk))
        # Tampered message should fail verification
        self.assertFalse(pqc.mldsa65_verify(b"Tampered payload", sig, pk))

    def test_envelope_roundtrip_verification(self):
        """Test creating a hybrid envelope and verifying it end-to-end."""
        import attestation.pqc_wrap as pqc
        bundle_dict = {"subject": "cbom.json", "scanId": "scan-123"}
        envelope = pqc.wrap_bundle_with_pqc(bundle_dict)
        res = pqc.verify_hybrid_envelope(envelope)
        self.assertTrue(res["valid"], f"Envelope verification failed: {res.get('errors')}")

    def test_dilithium_py_sign_verify(self):
        """If dilithium-py is installed, test a real key-gen, sign, verify cycle."""
        try:
            from dilithium_py.dilithium import Dilithium3
        except ImportError:
            self.skipTest("dilithium-py not installed")

        import attestation.pqc_wrap as pqc
        sk, pk = pqc.generate_mldsa65_keypair()
        msg = b"test message for ML-DSA-65"
        sig = pqc.mldsa65_sign(msg, sk)
        self.assertTrue(pqc.mldsa65_verify(msg, sig, pk))
        # Tamper: wrong message
        self.assertFalse(pqc.mldsa65_verify(b"wrong message", sig, pk))



# ── Test: Verifier (mocked Sigstore) ─────────────────────────────────────────

class TestVerifier(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.cbom_path = _write_cbom(self.tmp)

        from attestation.statement import build_statement, statement_to_json, sha256_file
        self.stmt = build_statement(self.cbom_path)
        self.stmt_path = os.path.join(self.tmp, "attestation.intoto.json")
        Path(self.stmt_path).write_text(statement_to_json(self.stmt), encoding="utf-8")
        self.cbom_sha = sha256_file(self.cbom_path)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _write_offline_bundle(self) -> str:
        """Write an offline bundle that matches the statement."""
        import attestation.signer as signer_mod
        orig = signer_mod._SIGSTORE_AVAILABLE
        signer_mod._SIGSTORE_AVAILABLE = False
        try:
            bundle_path = os.path.join(self.tmp, "attestation.bundle.json")
            signer_mod.sign_statement(self.stmt, output_bundle_path=bundle_path)
            return bundle_path
        finally:
            signer_mod._SIGSTORE_AVAILABLE = orig

    def test_cbom_sha256_check_passes(self):
        from attestation.verifier import verify_attestation
        bundle_path = self._write_offline_bundle()
        # Mock sigstore verify to return valid (avoid needing real OIDC)
        with patch("attestation.signer.verify_bundle", return_value={"valid": True, "errors": []}):
            result = verify_attestation(
                cbom_path=self.cbom_path,
                statement_path=self.stmt_path,
                bundle_path=bundle_path,
                check_rekor=False,
            )
        self.assertTrue(result["checks"]["cbom_sha256"])

    def test_verifier_fails_on_tampered_cbom(self):
        """If the CBOM is modified after signing, the SHA-256 check must fail."""
        from attestation.verifier import verify_attestation
        bundle_path = self._write_offline_bundle()

        # Tamper the CBOM
        tampered_path = os.path.join(self.tmp, "tampered.cbom.json")
        with open(self.cbom_path, encoding="utf-8") as f:
            cbom = json.load(f)
        cbom["metadata"]["component"]["version"] = "TAMPERED"
        with open(tampered_path, "w", encoding="utf-8") as f:
            json.dump(cbom, f)

        result = verify_attestation(
            cbom_path=tampered_path,
            statement_path=self.stmt_path,
            bundle_path=bundle_path,
            check_rekor=False,
        )
        self.assertFalse(result["checks"]["cbom_sha256"])
        self.assertFalse(result["valid"])

    def test_statement_predicate_check(self):
        from attestation.verifier import verify_attestation
        bundle_path = self._write_offline_bundle()
        with patch("attestation.signer.verify_bundle", return_value={"valid": True, "errors": []}):
            result = verify_attestation(
                cbom_path=self.cbom_path,
                statement_path=self.stmt_path,
                bundle_path=bundle_path,
                check_rekor=False,
            )
        self.assertTrue(result["checks"]["statement_predicate"])


# ── Test: Rekor client (mocked HTTP) ─────────────────────────────────────────

class TestRekorClient(unittest.TestCase):

    def test_rekor_search_by_hash_success(self):
        from attestation import rekor as rekor_mod
        mock_resp = MagicMock()
        mock_resp.json.return_value = ["entry-uuid-1", "entry-uuid-2"]
        mock_resp.raise_for_status.return_value = None

        with patch("requests.post", return_value=mock_resp):
            result = rekor_mod.rekor_search_by_hash("abc123")

        self.assertIn("entries", result)
        self.assertEqual(len(result["entries"]), 2)

    def test_rekor_search_by_hash_http_error(self):
        from attestation import rekor as rekor_mod
        import requests as req_lib
        mock_resp = MagicMock()
        mock_resp.status_code = 500
        mock_resp.text = "Internal Server Error"
        err = req_lib.HTTPError(response=mock_resp)

        with patch("requests.post", side_effect=err):
            result = rekor_mod.rekor_search_by_hash("deadbeef")

        self.assertIn("error", result)

    def test_rekor_search_skipped_when_env_set(self):
        from attestation import rekor as rekor_mod
        with patch.dict(os.environ, {"SIGSTORE_NO_REKOR": "1"}):
            result = rekor_mod.rekor_upload_hashedrekord("abc123")
        self.assertTrue(result.get("skipped"))

    def test_rekor_log_info_timeout(self):
        from attestation import rekor as rekor_mod
        with patch("requests.get", side_effect=Exception("timeout")):
            result = rekor_mod.rekor_log_info()
        self.assertIn("error", result)


if __name__ == "__main__":
    unittest.main(verbosity=2)

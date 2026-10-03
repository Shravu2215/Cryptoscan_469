"""
Automated tests for Check 1 (AES-ECB simulator filter) and Check 2 (key type labels).

Run: pytest scanner/tests/test_checks_1_and_2.py -v
"""
import os
import io
import pytest
import tempfile
import textwrap
from scanner.pipeline import scan_repo

FIXTURE_PATH = "C:/Users/ACER/Downloads/pqc-test-fixture.zip"

# ─────────────────────────────────────────────────────────────────────────────
# Helpers: replicate pqcSimulator.js normalizeAlgo + findingMatchesAlgo in Python
# so we can assert on the frontend filter logic without a browser.
# ─────────────────────────────────────────────────────────────────────────────
ALGO_FAMILIES = {
    'RSA-2048': 'RSA', 'RSA-3072': 'RSA', 'RSA-4096': 'RSA',
    'ECDSA P-256': 'ECDSA', 'ECDSA P-384': 'ECDSA',
    'Ed25519': 'Ed25519',
    'ECDH P-256': 'ECDH', 'X25519': 'X25519',
    'AES-ECB': 'AES-ECB',
    'AES-128': 'AES', 'AES-256-GCM': 'AES',
    'DES': 'DES', '3DES': 'DES', 'RC4': 'RC4',
    'MD5': 'MD5', 'SHA-1': 'SHA', 'SHA-256': 'SHA',
    'SHA-384': 'SHA', 'SHA3-256': 'SHA3',
    'ML-DSA-44': 'ML-DSA', 'ML-DSA-65': 'ML-DSA', 'ML-DSA-87': 'ML-DSA',
    'Falcon-512': 'Falcon', 'Falcon-1024': 'Falcon',
    'ML-KEM-512': 'ML-KEM', 'ML-KEM-768': 'ML-KEM', 'ML-KEM-1024': 'ML-KEM',
}

LIB_TO_ALGO = {
    'elliptic': 'ECDSA P-256', 'secp256k1': 'ECDSA P-256',
    'ecdsa': 'ECDSA P-256', 'node-forge': 'RSA-2048',
    'jsrsasign': 'RSA-2048', 'tweetnacl': 'Ed25519',
    'ed25519': 'Ed25519',
}


def normalize_algo(s):
    """Mirror of pqcSizes.js normalizeAlgo."""
    if not s:
        return None
    s = s.strip().upper()

    if 'ML-DSA-87' in s or 'DILITHIUM5' in s:
        return 'ML-DSA-87'
    if 'ML-DSA-65' in s or 'DILITHIUM3' in s:
        return 'ML-DSA-65'
    if 'ML-DSA-44' in s or 'DILITHIUM2' in s:
        return 'ML-DSA-44'
    if 'FALCON-512' in s or 'FALCON512' in s:
        return 'Falcon-512'
    if 'FALCON-1024' in s or 'FALCON1024' in s:
        return 'Falcon-1024'
    if 'ML-KEM-1024' in s or 'KYBER1024' in s:
        return 'ML-KEM-1024'
    if 'ML-KEM-768' in s or 'KYBER768' in s:
        return 'ML-KEM-768'
    if 'ML-KEM-512' in s or 'KYBER512' in s:
        return 'ML-KEM-512'
    if 'RSA-4096' in s or 'RSA 4096' in s or ('4096' in s and 'RSA' in s):
        return 'RSA-4096'
    if 'RSA-3072' in s or 'RSA 3072' in s or ('3072' in s and 'RSA' in s):
        return 'RSA-3072'
    if 'RSA-2048' in s or 'RSA 2048' in s or 'RSA' in s:
        return 'RSA-2048'
    if 'ECDSA P-384' in s or 'P-384' in s or 'SECP384R1' in s:
        return 'ECDSA P-384'
    if ('ECDSA P-256' in s or 'P-256' in s or 'SECP256R1' in s or
            'ECDSA' in s or s == 'EC' or s.endswith(' EC') or
            s.startswith('EC ') or ' EC ' in s):
        return 'ECDSA P-256'
    if 'ED25519' in s:
        return 'Ed25519'
    if 'ECDH' in s:
        return 'ECDH P-256'
    if 'X25519' in s:
        return 'X25519'
    # Symmetric / Hash — ECB check must come before generic AES
    if 'AES' in s and 'ECB' in s:
        return 'AES-ECB'
    if 'AES-256' in s:
        return 'AES-256-GCM'
    if 'AES-128' in s or 'AES' in s:
        return 'AES-128'
    if '3DES' in s or 'TRIPLEDES' in s:
        return '3DES'
    if 'DES' in s:
        return 'DES'
    if 'RC4' in s:
        return 'RC4'
    if 'SHA-384' in s or 'SHA384' in s:
        return 'SHA-384'
    if 'SHA3-256' in s or 'SHA3' in s:
        return 'SHA3-256'
    if 'SHA-256' in s or 'SHA256' in s:
        return 'SHA-256'
    if 'SHA-1' in s or 'SHA1' in s:
        return 'SHA-1'
    if 'MD5' in s:
        return 'MD5'
    return None


def finding_matches_algo(f, classical_key):
    """Mirror of pqcSimulator.js findingMatchesAlgo."""
    f_norm = normalize_algo(f.get('algorithm', ''))
    if not f_norm:
        lib = (f.get('library', '') or f.get('category', '') or '').lower().strip()
        f_norm = normalize_algo(LIB_TO_ALGO.get(lib)) or normalize_algo(lib)
    if not f_norm:
        snippet = (f.get('code_snippet', '') or f.get('raw_call', '') or '')
        f_norm = normalize_algo(snippet)

    sel_norm = normalize_algo(classical_key)
    if not f_norm or not sel_norm:
        return False

    f_family = ALGO_FAMILIES.get(f_norm)
    sel_family = ALGO_FAMILIES.get(sel_norm)
    if f_family and sel_family and f_family == sel_family:
        return True
    return f_norm == sel_norm


# ─────────────────────────────────────────────────────────────────────────────
# CHECK 1 TESTS — AES-ECB Simulator Filter
# ─────────────────────────────────────────────────────────────────────────────

class TestCheck1SimulatorAesEcb:
    @pytest.fixture(scope="class")
    def findings(self):
        if not os.path.exists(FIXTURE_PATH):
            pytest.skip("pqc-test-fixture.zip not present")
        return scan_repo(FIXTURE_PATH).get("findings", [])

    def test_aes_ecb_returns_exactly_2_findings(self, findings):
        """AES-ECB selection must return exactly 2 findings."""
        matches = [f for f in findings if finding_matches_algo(f, 'AES-ECB')]
        assert len(matches) == 2, (
            f"Expected 2 AES-ECB matches, got {len(matches)}: "
            + str([f.get('file') + ':' + str(f.get('line')) for f in matches])
        )

    def test_aes_ecb_exact_files_and_lines(self, findings):
        """AES-ECB must hit exactly cipherModes.js:18 and cipher_modes.py:20."""
        matches = [f for f in findings if finding_matches_algo(f, 'AES-ECB')]
        files_lines = {(f.get('file', '').replace('\\', '/'), f.get('line')) for f in matches}
        assert ('pqc-test-fixture/src/crypto/cipherModes.js', 18) in files_lines, \
            f"Missing cipherModes.js:18. Got: {files_lines}"
        assert ('pqc-test-fixture/src/crypto/cipher_modes.py', 20) in files_lines, \
            f"Missing cipher_modes.py:20. Got: {files_lines}"

    def test_aes_ecb_no_env_kms_pkcs11_nginx_etc(self, findings):
        """AES-ECB filter must NOT include .env, KMS, PKCS#11, nginx, requirements, package.json rows."""
        matches = [f for f in findings if finding_matches_algo(f, 'AES-ECB')]
        bad_keywords = ['.env', 'kms', 'pkcs11', 'hsm', 'requirements', 'package.json',
                        'nginx', 'certs', '.crt', '.key']
        for f in matches:
            path = (f.get('file', '') or '').lower()
            for kw in bad_keywords:
                assert kw not in path, \
                    f"AES-ECB filter included unwanted file: {f.get('file')} (keyword: {kw})"

    def test_aes_ecb_detection_methods(self, findings):
        """Both AES-ECB matches must be AST detections."""
        matches = [f for f in findings if finding_matches_algo(f, 'AES-ECB')]
        for f in matches:
            assert f.get('detection_method') == 'ast', \
                f"Expected 'ast' detection for {f.get('file')}, got {f.get('detection_method')}"

    def test_aes_ecb_algorithms_present(self, findings):
        """Scanner must output AES-128-ECB (JS) and AES-ECB (Python) — both normalize to AES-ECB."""
        matches = [f for f in findings if finding_matches_algo(f, 'AES-ECB')]
        algos = {f.get('algorithm') for f in matches}
        assert 'AES-128-ECB' in algos, f"Missing AES-128-ECB in ECB matches: {algos}"
        assert 'AES-ECB' in algos, f"Missing AES-ECB in ECB matches: {algos}"
        for algo in algos:
            assert normalize_algo(algo) == 'AES-ECB', \
                f"Algorithm '{algo}' does not normalize to 'AES-ECB'"

    def test_ecdsa_p256_returns_exactly_package_json_line9(self, findings):
        """ECDSA P-256 selection must return exactly package.json line 9."""
        matches = [f for f in findings if finding_matches_algo(f, 'ECDSA P-256')]
        assert len(matches) == 1, (
            f"Expected 1 ECDSA P-256 match, got {len(matches)}: "
            + str([f.get('file') + ':' + str(f.get('line')) for f in matches])
        )
        m = matches[0]
        assert 'package.json' in (m.get('file', '') or ''), \
            f"Expected package.json, got {m.get('file')}"
        assert m.get('line') == 9, \
            f"Expected line 9, got {m.get('line')}"

    def test_normalizeAlgo_aes_ecb_variants(self):
        """normalizeAlgo must map AES-128-ECB and AES-ECB both to 'AES-ECB'."""
        assert normalize_algo('AES-128-ECB') == 'AES-ECB'
        assert normalize_algo('AES-ECB') == 'AES-ECB'
        assert normalize_algo('aes-128-ecb') == 'AES-ECB'
        assert normalize_algo('AES/ECB') == 'AES-ECB'
        # Must NOT match other AES modes
        assert normalize_algo('AES-256-GCM') != 'AES-ECB'
        assert normalize_algo('AES-CBC') != 'AES-ECB'
        assert normalize_algo('AES-GCM') != 'AES-ECB'


# ─────────────────────────────────────────────────────────────────────────────
# CHECK 2 TESTS — Key Type Labels
# ─────────────────────────────────────────────────────────────────────────────

class TestCheck2KeyTypeLabels:
    @pytest.fixture(scope="class")
    def findings(self):
        if not os.path.exists(FIXTURE_PATH):
            pytest.skip("pqc-test-fixture.zip not present")
        return scan_repo(FIXTURE_PATH).get("findings", [])

    def _key_finding(self, findings, basename):
        hits = [f for f in findings if f.get('file', '').replace('\\', '/').endswith('certs/' + basename)]
        assert hits, f"No finding found for certs/{basename}"
        return hits[0]

    def test_public_gateway_api_key_is_rsa2048(self, findings):
        f = self._key_finding(findings, 'public-gateway-api.key')
        assert f['algorithm'] == 'RSA-2048', \
            f"public-gateway-api.key: expected RSA-2048, got {f['algorithm']}"

    def test_legacy_internal_service_key_is_rsa1024(self, findings):
        f = self._key_finding(findings, 'legacy-internal-service.key')
        assert f['algorithm'] == 'RSA-1024', \
            f"legacy-internal-service.key: expected RSA-1024, got {f['algorithm']}"

    def test_internal_mesh_ca_key_is_rsa2048(self, findings):
        f = self._key_finding(findings, 'internal-mesh-ca.key')
        assert f['algorithm'] == 'RSA-2048', \
            f"internal-mesh-ca.key: expected RSA-2048, got {f['algorithm']}"

    def test_no_key_labeled_elliptic_curve(self, findings):
        """No .key file may be labeled 'Elliptic Curve Private Key'."""
        key_findings = [f for f in findings if '.key' in (f.get('file') or '')]
        for f in key_findings:
            algo = (f.get('algorithm') or '').lower()
            assert 'elliptic' not in algo, \
                f"{f.get('file')} is still labeled Elliptic Curve: {f.get('algorithm')}"
            assert 'ec private' not in algo, \
                f"{f.get('file')} is labeled EC Private Key: {f.get('algorithm')}"

    def test_rsa1024_key_is_critical(self, findings):
        """RSA-1024 private key must be CRITICAL severity (too weak)."""
        f = self._key_finding(findings, 'legacy-internal-service.key')
        assert f['severity'].lower() == 'critical', \
            f"RSA-1024 key should be Critical, got {f['severity']}"

    def test_rsa2048_key_is_high_severity(self, findings):
        """RSA-2048 private keys should be HIGH severity."""
        for basename in ('public-gateway-api.key', 'internal-mesh-ca.key'):
            f = self._key_finding(findings, basename)
            assert f['severity'].lower() == 'high', \
                f"{basename}: expected High, got {f['severity']}"

    def test_key_quantum_risk_is_weakened(self, findings):
        """All RSA key files should have quantum_risk = Quantum-Weakened."""
        key_findings = [f for f in findings if '.key' in (f.get('file') or '')]
        for f in key_findings:
            assert f.get('quantum_risk') == 'Quantum-Weakened', \
                f"{f.get('file')} quantum_risk={f.get('quantum_risk')}"

    def test_cert_files_key_type_and_size(self, findings):
        """The three .crt files must show correct RSA key types and sizes."""
        expected = {
            'public-gateway-api.crt': ('RSA-2048', 2048),
            'legacy-internal-service.crt': ('RSA-1024', 1024),
            'internal-mesh-ca.crt': ('RSA-2048', 2048),
        }
        for basename, (exp_algo, exp_size) in expected.items():
            f = self._key_finding(findings, basename)
            assert f['algorithm'] == exp_algo, \
                f"{basename}: expected algo {exp_algo}, got {f['algorithm']}"
            assert f.get('key_size') == exp_size, \
                f"{basename}: expected key_size {exp_size}, got {f.get('key_size')}"

    def test_rsa1024_cert_is_quantum_weakened(self, findings):
        """RSA-1024 certificate is quantum-weakened."""
        f = self._key_finding(findings, 'legacy-internal-service.crt')
        assert f.get('quantum_risk') == 'Quantum-Weakened', \
            f"legacy cert quantum_risk={f.get('quantum_risk')}"

    def test_rsa2048_cert_is_quantum_weakened(self, findings):
        """RSA-2048 certificates are also quantum-weakened (Shor's algorithm)."""
        for basename in ('public-gateway-api.crt', 'internal-mesh-ca.crt'):
            f = self._key_finding(findings, basename)
            assert f.get('quantum_risk') == 'Quantum-Weakened', \
                f"{basename} quantum_risk={f.get('quantum_risk')}"


# ─────────────────────────────────────────────────────────────────────────────
# CHECK 2 TEST — Generated RSA / EC P-256 / Ed25519 keys
# ─────────────────────────────────────────────────────────────────────────────

class TestCheck2GeneratedKeyParsing:
    """Test that the scanner correctly identifies one RSA, one EC P-256, one Ed25519 key."""

    @pytest.fixture(scope="class")
    def generated_findings(self):
        """Generate three keys, write to a temp zip, scan, return findings."""
        try:
            from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.backends import default_backend
        except ImportError:
            pytest.skip("cryptography library not available for key generation")

        import zipfile
        import tempfile

        # Generate keys
        rsa_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        ec_key = ec.generate_private_key(ec.SECP256R1(), backend=default_backend())
        ed_key = ed25519.Ed25519PrivateKey.generate()

        def to_pem(key):
            return key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode()

        rsa_pem = to_pem(rsa_key)
        ec_pem = to_pem(ec_key)
        ed_pem = to_pem(ed_key)

        # Write a small zip with three .key files
        with tempfile.NamedTemporaryFile(suffix='.zip', delete=False) as tmp:
            tmp_path = tmp.name

        with zipfile.ZipFile(tmp_path, 'w') as zf:
            zf.writestr('generated/rsa2048.key', rsa_pem)
            zf.writestr('generated/ecp256.key', ec_pem)
            zf.writestr('generated/ed25519.key', ed_pem)

        findings = scan_repo(tmp_path).get('findings', [])
        os.unlink(tmp_path)
        return findings

    def _find(self, findings, basename):
        hits = [f for f in findings if f.get('file', '').replace('\\', '/').endswith(basename)]
        assert hits, f"No finding for {basename}. Available: {[f.get('file') for f in findings]}"
        return hits[0]

    def test_generated_rsa2048_identified(self, generated_findings):
        f = self._find(generated_findings, 'generated/rsa2048.key')
        assert f['algorithm'] == 'RSA-2048', \
            f"Generated RSA-2048 key labeled as: {f['algorithm']}"

    def test_generated_ec_p256_identified(self, generated_findings):
        f = self._find(generated_findings, 'generated/ecp256.key')
        assert 'ECDSA' in f['algorithm'] or 'P-256' in f['algorithm'] or 'EC' in f['algorithm'], \
            f"Generated EC P-256 key labeled as: {f['algorithm']}"

    def test_generated_ed25519_identified(self, generated_findings):
        f = self._find(generated_findings, 'generated/ed25519.key')
        assert 'Ed25519' in f['algorithm'] or 'ed25519' in f['algorithm'].lower(), \
            f"Generated Ed25519 key labeled as: {f['algorithm']}"

    def test_no_elliptic_curve_label_for_rsa(self, generated_findings):
        """RSA key must NOT be labeled as Elliptic Curve."""
        f = self._find(generated_findings, 'generated/rsa2048.key')
        algo = (f.get('algorithm') or '').lower()
        assert 'elliptic' not in algo, \
            f"RSA key mislabeled as elliptic curve: {f['algorithm']}"
        assert 'ec' not in algo.split('-'), \
            f"RSA key appears to contain 'EC': {f['algorithm']}"

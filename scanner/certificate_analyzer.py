"""
Certificate (X.509) and Cryptographic Key File Analyzer.

Parses .pem, .crt, .cer, .cert, .key files for:
1. Public certificates (X.509 PEM / DER): subject, issuer, signature algorithm, public key size, validity dates.
2. Hardcoded private keys (RSA, EC, DSA, OpenSSH).
3. Weak certificate signature algorithms (MD5, SHA1).
4. Short key lengths (RSA < 2048, ECC < 256).

Generates findings with detection_method="certificate".
"""
import os
import re
import sys
from datetime import datetime
from typing import List

_scanner_dir = os.path.dirname(os.path.abspath(__file__))
_parent_dir = os.path.dirname(_scanner_dir)
if _parent_dir not in sys.path:
    sys.path.insert(0, _parent_dir)
if _scanner_dir not in sys.path:
    sys.path.insert(0, _scanner_dir)

from scanner.models import Finding, Severity, QuantumRisk, Confidence

# Try importing cryptography library for precise X.509 parsing
try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False

PEM_CERT_RE = re.compile(r'-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\s]+-----END CERTIFICATE-----', re.MULTILINE)
PEM_KEY_RE = re.compile(r'-----BEGIN\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\s+KEY-----[A-Za-z0-9+/=\s]+-----END\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\s+KEY-----', re.MULTILINE)

class CertificateAnalyzer:
    """Offline analyzer for X.509 certificates and key files."""

    def analyze(self, file_path: str, source: str) -> List[Finding]:
        findings: List[Finding] = []
        fn = os.path.basename(file_path).lower()
        ext = os.path.splitext(fn)[1]

        # Check for unencrypted private key blocks first
        key_matches = list(PEM_KEY_RE.finditer(source))
        for match in key_matches:
            line_no = source[:match.start()].count('\n') + 1
            matched_str = match.group(0)
            # Parse the PEM private key block to determine actual key type and size
            if HAS_CRYPTOGRAPHY:
                from cryptography.hazmat.primitives import serialization
                from cryptography.hazmat.primitives.asymmetric import rsa as crypto_rsa, ec as crypto_ec, ed25519 as crypto_ed25519, dsa as crypto_dsa
                try:
                    private_key = serialization.load_pem_private_key(matched_str.encode('utf-8'), password=None, backend=default_backend())
                except Exception:
                    private_key = None
                if isinstance(private_key, crypto_rsa.RSAPrivateKey):
                    key_bits = private_key.key_size
                    key_type = f"RSA-{key_bits}"  # e.g., RSA-2048
                elif isinstance(private_key, crypto_ec.EllipticCurvePrivateKey):
                    curve_name = private_key.curve.name
                    # Map known curves to normalized algorithm names used elsewhere
                    if curve_name in ('secp256r1', 'prime256v1'):
                        key_type = "ECDSA P-256"
                    elif curve_name == 'secp384r1':
                        key_type = "ECDSA P-384"
                    else:
                        key_type = f"EC-{curve_name}"  # fallback for other curves
                elif isinstance(private_key, crypto_ed25519.Ed25519PrivateKey):
                    key_type = "Ed25519"
                elif isinstance(private_key, crypto_dsa.DSAPrivateKey):
                    key_bits = private_key.key_size
                    key_type = f"DSA-{key_bits}"
                else:
                    key_type = "Private Key"
            else:
                # Fallback heuristic if cryptography not available
                key_type = "Private Key"
                
                # Check explicit PKCS#1 headers
                if "-----BEGIN RSA PRIVATE KEY-----" in matched_str:
                    key_type = "RSA Private Key"
                elif "-----BEGIN EC PRIVATE KEY-----" in matched_str:
                    key_type = "EC Private Key"
                elif "-----BEGIN OPENSSH PRIVATE KEY-----" in matched_str:
                    key_type = "OpenSSH Private Key"
                
                # Try to parse DER to find PKCS#8 OIDs or infer RSA bit length
                try:
                    import base64
                    b64 = ''.join(line for line in matched_str.split('\n') if line and not line.startswith('-----'))
                    der = base64.b64decode(b64)
                    hx = der.hex()
                    
                    # rsaEncryption 1.2.840.113549.1.1.1 -> 06092a864886f70d010101
                    if '06092a864886f70d010101' in hx or 'BEGIN RSA PRIVATE KEY' in matched_str:
                        # Estimate RSA key size based on DER length
                        if len(der) > 2000:
                            key_type = "RSA-4096"
                        elif len(der) > 1500:
                            key_type = "RSA-3072"
                        elif len(der) > 800:
                            key_type = "RSA-2048"
                        elif len(der) > 400:
                            key_type = "RSA-1024"
                        else:
                            key_type = "RSA Private Key"
                            
                    # id-ecPublicKey 1.2.840.10045.2.1 -> 06072a8648ce3d0201
                    elif '06072a8648ce3d0201' in hx or 'BEGIN EC PRIVATE KEY' in matched_str:
                        # prime256v1: 1.2.840.10045.3.1.7 -> 06082a8648ce3d030107
                        if '06082a8648ce3d030107' in hx:
                            key_type = "ECDSA P-256"
                        # secp384r1: 1.3.132.0.34 -> 06052b81040022
                        elif '06052b81040022' in hx:
                            key_type = "ECDSA P-384"
                        else:
                            key_type = "EC Private Key"
                            
                    # Ed25519 1.3.101.112 -> 06032b6570
                    elif '06032b6570' in hx:
                        key_type = "Ed25519"
                        
                except Exception:
                    pass


            # Determine severity based on key type and size:
            # RSA/DSA < 2048 bits → CRITICAL (weak key); everything else → HIGH.
            key_bits_for_severity = None
            if key_type.startswith("RSA-"):
                try:
                    key_bits_for_severity = int(key_type.split("-")[1])
                except (IndexError, ValueError):
                    pass
            elif key_type.startswith("DSA-"):
                try:
                    key_bits_for_severity = int(key_type.split("-")[1])
                except (IndexError, ValueError):
                    pass
            if key_bits_for_severity is not None and key_bits_for_severity < 2048:
                key_severity = Severity.CRITICAL
                key_recommendation = (
                    f"CRITICAL: {key_type} private key is below the NIST 2048-bit minimum. "
                    f"This key is cryptographically weak and must be replaced immediately. "
                    f"Remove from source control and store in AWS KMS, HashiCorp Vault, or hardware HSM."
                )
            else:
                key_severity = Severity.HIGH
                key_recommendation = (
                    "Remove hardcoded private keys from source control. "
                    "Store keys in AWS KMS, HashiCorp Vault, or hardware HSM."
                )

            findings.append(Finding(
                file=file_path,
                line=line_no,
                column=1,
                language="certificate",
                rule_id="certificate-unencrypted-private-key",
                rule_name=f"Unencrypted {key_type}",
                category="hardcoded-secret",
                algorithm=key_type,
                severity=key_severity,
                quantum_risk=QuantumRisk.QUANTUM_WEAKENED,
                message=f"Hardcoded unencrypted {key_type} block detected in PEM file.",
                recommendation=key_recommendation,
                code_snippet=matched_str[:80] + "...",
                confidence=Confidence.CONFIRMED,
                library="X.509 / PEM Storage",
                tags=["certificate", "private-key", "pem"]
            ))

        # Check for PEM Certificate blocks
        cert_matches = list(PEM_CERT_RE.finditer(source))
        if cert_matches and HAS_CRYPTOGRAPHY:
            for match in cert_matches:
                line_no = source[:match.start()].count('\n') + 1
                pem_data = match.group(0).encode('utf-8')
                try:
                    cert = x509.load_pem_x509_certificate(pem_data, default_backend())
                    self._parse_crypto_cert(cert, file_path, line_no, findings)
                except Exception:
                    self._parse_regex_cert(source, match, file_path, line_no, findings)
        elif cert_matches:
            for match in cert_matches:
                line_no = source[:match.start()].count('\n') + 1
                self._parse_regex_cert(source, match, file_path, line_no, findings)

        return findings

    def _parse_crypto_cert(self, cert, file_path: str, line_no: int, findings: List[Finding]):
        # Signature Algorithm
        sig_algo_name = cert.signature_hash_algorithm.name.upper() if cert.signature_hash_algorithm else "UNKNOWN"
        sig_str = f"X.509 ({sig_algo_name})"

        # Public Key & Key Size
        pub_key = cert.public_key()
        key_type = "Asymmetric"
        key_size = None

        if isinstance(pub_key, rsa.RSAPublicKey):
            key_type = "RSA"
            key_size = pub_key.key_size
        elif isinstance(pub_key, ec.EllipticCurvePublicKey):
            key_type = f"ECDSA ({pub_key.curve.name})"
            key_size = pub_key.key_size
        elif isinstance(pub_key, dsa.DSAPublicKey):
            key_type = "DSA"
            key_size = pub_key.key_size

        # Evaluate Risk & Quantum Vulnerability
        severity = Severity.INFO
        q_status = QuantumRisk.QUANTUM_WEAKENED

        if "MD5" in sig_algo_name:
            severity = Severity.CRITICAL
            remediation = f"Certificate uses deprecated MD5 signature algorithm ({sig_algo_name}). Upgrade to SHA-256 or SHA-384."
        elif "SHA1" in sig_algo_name or "SHA-1" in sig_algo_name:
            severity = Severity.HIGH
            remediation = f"Certificate uses deprecated SHA-1 signature algorithm ({sig_algo_name}). Upgrade to SHA-256 or SHA-384."
        elif key_type == "RSA" and key_size and key_size < 2048:
            severity = Severity.CRITICAL
            remediation = f"RSA key size ({key_size}-bit) is below NIST minimum 2048-bit."
        elif key_type == "RSA" and key_size and key_size == 2048:
            severity = Severity.MEDIUM
            remediation = "RSA 2048-bit key detected. Plan migration to ML-DSA or ML-KEM post-quantum algorithm."
        else:
            severity = Severity.LOW
            remediation = f"X.509 Certificate with {key_type} public key detected."

        # ---------------------------------------------------------------
        # Fix 11: Expiry metadata — parse notBefore/notAfter, escalate
        # severity for expired or near-expiry certificates.
        # ---------------------------------------------------------------
        expiry_date = None
        is_expired = False
        days_until_expiry = None
        expiry_msg = ""

        try:
            # cryptography >= 42 exposes timezone-aware datetimes via not_valid_after_utc
            if hasattr(cert, "not_valid_after_utc"):
                not_after = cert.not_valid_after_utc
                now = datetime.now(not_after.tzinfo)
            else:
                not_after = cert.not_valid_after  # naive UTC datetime (older library)
                now = datetime.utcnow()

            expiry_date = not_after.strftime("%Y-%m-%d")
            delta = (not_after - now).total_seconds()
            days_until_expiry = int(delta / 86400)
            is_expired = days_until_expiry < 0

            if is_expired:
                severity = Severity.CRITICAL
                expiry_msg = f" [EXPIRED: {expiry_date} — {abs(days_until_expiry)} days ago]"
                remediation += expiry_msg
            elif days_until_expiry <= 30:
                # Escalate to at least HIGH for certs expiring very soon
                if severity.rank < Severity.HIGH.rank:
                    severity = Severity.HIGH
                expiry_msg = f" [EXPIRING SOON: {expiry_date} — {days_until_expiry} days remaining]"
                remediation += expiry_msg
            else:
                expiry_msg = f" [Valid until {expiry_date} — {days_until_expiry} days]"
        except Exception:
            expiry_date = None
            is_expired = False
            days_until_expiry = None

        subj_str = cert.subject.rfc4514_string() if cert.subject else "Unknown Subject"
        algo_label = f"{key_type}-{key_size}" if key_size else f"{key_type} Certificate"
        snippet = (
            f"Subject: {subj_str} | SigAlgo: {sig_algo_name} | KeySize: {key_size}"
            f" | Expiry: {expiry_date or 'unknown'}{expiry_msg}"
        )
        expiry_tags = (["expired"] if is_expired else []) + (
            ["expiring-soon"] if (not is_expired and days_until_expiry is not None and days_until_expiry <= 30) else []
        )

        findings.append(Finding(
            file=file_path,
            line=line_no,
            column=1,
            language="certificate",
            rule_id="certificate-x509-parsed",
            rule_name=f"X.509 Certificate ({key_type})",
            category="certificate",
            algorithm=algo_label,
            severity=severity,
            quantum_risk=q_status,
            message=f"X.509 Certificate with {key_type} key ({sig_algo_name} signature) detected.{expiry_msg}",
            recommendation=remediation,
            code_snippet=snippet,
            confidence=Confidence.CONFIRMED,
            library="X.509 Certificate PKI",
            tags=["certificate", "x509", "pki"] + expiry_tags
        ))

    def _parse_regex_cert(self, source: str, match, file_path: str, line_no: int, findings: List[Finding]):
        findings.append(Finding(
            file=file_path,
            line=line_no,
            column=1,
            language="certificate",
            rule_id="certificate-x509-pem-block",
            rule_name="X.509 Certificate Block",
            category="certificate",
            algorithm="X.509 Certificate",
            severity=Severity.MEDIUM,
            quantum_risk=QuantumRisk.QUANTUM_WEAKENED,
            message="PEM X.509 Certificate Block detected in file.",
            recommendation="Ensure X.509 certificate uses RSA >= 2048-bit or ECC >= 256-bit with SHA-256 signature algorithm.",
            code_snippet="PEM X.509 Certificate Block detected.",
            confidence=Confidence.LIKELY,
            library="X.509 Certificate PKI",
            tags=["certificate", "x509", "pem"]
        ))

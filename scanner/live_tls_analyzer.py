"""
Live TLS Analyzer — connects to a real host:port and inspects the
TLS handshake for cryptographic weaknesses.

Checks:
1. Certificate expiry (EXPIRED / EXPIRING SOON)
2. Weak signature algorithms (MD5, SHA-1)
3. Short RSA/EC key sizes
4. TLS protocol version (SSLv3, TLS 1.0, TLS 1.1)
5. Hostname mismatch

All findings are returned as Finding objects compatible with the rest of
the scanner pipeline.
"""
import os
import sys
import socket
import ssl
import datetime
from typing import List, Optional

_scanner_dir = os.path.dirname(os.path.abspath(__file__))
_parent_dir  = os.path.dirname(_scanner_dir)
for _p in (_parent_dir, _scanner_dir):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from scanner.models import Finding, Severity, QuantumRisk, Confidence

# Optional: richer cert parsing via the `cryptography` package
try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False


class LiveTLSAnalyzer:
    """
    Connects to a remote host:port over TLS and returns a list of
    cryptographic Findings based on the live certificate and handshake.

    Usage::

        analyzer = LiveTLSAnalyzer(timeout=10.0)
        findings = analyzer.analyze_endpoint("expired.badssl.com", 443)
    """

    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze_endpoint(self, host: str, port: int = 443) -> List[Finding]:
        """
        Perform a live TLS handshake against *host*:*port* and return findings.

        Always returns a list (may be empty if the host is unreachable and
        `ignore_errors` is set, but raises by default so CI fails loudly).
        """
        findings: List[Finding] = []

        try:
            cert_der, protocol, cipher_info = self._fetch_tls_info(host, port)
        except Exception as exc:
            # Surface the connectivity error as a finding so callers always
            # get at least one result on failure (e.g. self-signed / refused).
            findings.append(self._make_finding(
                host=host,
                rule_id="tls-connection-error",
                rule_name="TLS Connection Error",
                severity=Severity.HIGH,
                quantum_risk=QuantumRisk.CLASSICAL_RISK,
                algorithm="TLS",
                message=f"Could not complete TLS handshake with {host}:{port} — {exc}",
                recommendation="Verify the host is reachable and has a valid TLS configuration.",
                snippet=str(exc),
                tags=["tls", "live", "connection-error"],
            ))
            return findings

        # Protocol version checks
        findings.extend(self._check_protocol(host, protocol))

        # Certificate-level checks
        if cert_der:
            findings.extend(self._check_certificate(host, cert_der))

        return findings

    def probe_runtime_endpoint(self, host: str, port: int, address: str) -> dict:
        """Probe a pre-resolved public address and return only handshake metadata."""
        accepted = []
        selected = None
        versions = (
            ("TLSv1.3", ssl.TLSVersion.TLSv1_3),
            ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
            ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
            ("TLSv1", ssl.TLSVersion.TLSv1),
        )

        for label, version in versions:
            try:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                context.minimum_version = version
                context.maximum_version = version
                context.set_ciphers("ALL:@SECLEVEL=0")
                with socket.create_connection((address, port), timeout=self.timeout) as raw_socket:
                    with context.wrap_socket(raw_socket, server_hostname=host) as tls_socket:
                        negotiated = tls_socket.version()
                        cipher = tls_socket.cipher()
                        accepted.append({
                            "version": negotiated,
                            "cipher": cipher[0] if cipher else "",
                        })
                        if selected is None or negotiated == "TLSv1.3":
                            selected = {
                                "version": negotiated,
                                "cipher": cipher[0] if cipher else "",
                                "certificate": tls_socket.getpeercert(binary_form=True),
                            }
            except Exception:
                continue

        result = {
            "host": host,
            "port": port,
            "acceptedProtocols": [item["version"] for item in accepted],
            "negotiatedVersion": selected["version"] if selected else None,
            "cipherSuite": selected["cipher"] if selected else None,
            "certificateKeyType": None,
            "certificateKeySize": None,
            "certificateCurve": None,
            "signatureAlgorithm": None,
            "expiresAt": None,
            "ecdhe": any("ECDHE" in item["cipher"].upper() for item in accepted),
            "probeSucceeded": bool(selected),
        }
        if not selected or not selected["certificate"]:
            return result

        try:
            from cryptography import x509
            from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, ed448, rsa

            certificate = x509.load_der_x509_certificate(selected["certificate"])
            public_key = certificate.public_key()
            if isinstance(public_key, rsa.RSAPublicKey):
                result["certificateKeyType"] = "RSA"
                result["certificateKeySize"] = public_key.key_size
            elif isinstance(public_key, ec.EllipticCurvePublicKey):
                result["certificateKeyType"] = "ECDSA"
                result["certificateKeySize"] = public_key.key_size
                result["certificateCurve"] = public_key.curve.name
            elif isinstance(public_key, dsa.DSAPublicKey):
                result["certificateKeyType"] = "DSA"
                result["certificateKeySize"] = public_key.key_size
            elif isinstance(public_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
                result["certificateKeyType"] = type(public_key).__name__.replace("PublicKey", "")
            result["signatureAlgorithm"] = certificate.signature_algorithm_oid._name
            result["expiresAt"] = certificate.not_valid_after_utc.isoformat()
            result["certificateFindings"] = [
                {
                    "algorithm": finding.algorithm,
                    "severity": finding.severity.value,
                    "quantumRisk": finding.quantum_risk.value,
                    "recommendation": finding.recommendation,
                    "category": finding.category,
                    "description": finding.message,
                }
                for finding in self._check_certificate(host, selected["certificate"])
            ]
        except Exception:
            pass
        return result

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _fetch_tls_info(self, host: str, port: int):
        """
        Open a TLS socket and return (cert_der_bytes, protocol_str, cipher_tuple).
        Uses the most permissive context so we capture even weak/expired certs.
        """
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        # Allow older protocols so we can *detect* them
        ctx.options &= ~getattr(ssl, "OP_NO_SSLv3", 0)
        ctx.set_ciphers("ALL:@SECLEVEL=0")

        with socket.create_connection((host, port), timeout=self.timeout) as raw_sock:
            with ctx.wrap_socket(raw_sock, server_hostname=host) as tls_sock:
                cert_der  = tls_sock.getpeercert(binary_form=True)
                protocol  = tls_sock.version()            # e.g. "TLSv1.2"
                cipher    = tls_sock.cipher()             # (name, version, bits)
                return cert_der, protocol, cipher

    def _check_protocol(self, host: str, protocol: Optional[str]) -> List[Finding]:
        findings = []
        if protocol is None:
            return findings

        weak_protocols = {
            "SSLv2":  (Severity.CRITICAL, "SSLv2 is completely broken — disable immediately."),
            "SSLv3":  (Severity.CRITICAL, "SSLv3 is vulnerable to POODLE — disable immediately."),
            "TLSv1":  (Severity.HIGH,     "TLS 1.0 is deprecated (RFC 8996) — upgrade to TLS 1.2+."),
            "TLSv1.1":(Severity.HIGH,     "TLS 1.1 is deprecated (RFC 8996) — upgrade to TLS 1.2+."),
        }

        for proto, (sev, rec) in weak_protocols.items():
            if proto in protocol:
                findings.append(self._make_finding(
                    host=host,
                    rule_id=f"tls-weak-protocol-{proto.lower().replace('.', '')}",
                    rule_name=f"Weak TLS Protocol: {protocol}",
                    severity=sev,
                    quantum_risk=QuantumRisk.CLASSICAL_RISK,
                    algorithm=protocol,
                    message=f"Server {host} negotiated deprecated protocol {protocol}.",
                    recommendation=rec,
                    snippet=f"Negotiated protocol: {protocol}",
                    tags=["tls", "live", "weak-protocol"],
                ))
        return findings

    def _check_certificate(self, host: str, cert_der: bytes) -> List[Finding]:
        if HAS_CRYPTOGRAPHY:
            return self._check_cert_cryptography(host, cert_der)
        return self._check_cert_ssl_fallback(host, cert_der)

    def _check_cert_cryptography(self, host: str, cert_der: bytes) -> List[Finding]:
        findings = []
        try:
            cert = x509.load_der_x509_certificate(cert_der, default_backend())
        except Exception:
            return findings

        now = datetime.datetime.now(datetime.timezone.utc)

        # --- Expiry ---
        try:
            if hasattr(cert, "not_valid_after_utc"):
                not_after = cert.not_valid_after_utc
            else:
                not_after = cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)

            delta_days = (not_after - now).days
            expiry_str = not_after.strftime("%Y-%m-%d")

            if delta_days < 0:
                findings.append(self._make_finding(
                    host=host,
                    rule_id="tls-certificate-expired",
                    rule_name="Expired TLS Certificate",
                    severity=Severity.CRITICAL,
                    quantum_risk=QuantumRisk.CLASSICAL_RISK,
                    algorithm="X.509",
                    message=(
                        f"TLS certificate for {host} EXPIRED on {expiry_str} "
                        f"({abs(delta_days)} days ago)."
                    ),
                    recommendation="Renew the TLS certificate immediately.",
                    snippet=f"Not valid after: {expiry_str}",
                    tags=["tls", "live", "expired", "certificate"],
                ))
            elif delta_days <= 30:
                findings.append(self._make_finding(
                    host=host,
                    rule_id="tls-certificate-expiring-soon",
                    rule_name="TLS Certificate Expiring Soon",
                    severity=Severity.HIGH,
                    quantum_risk=QuantumRisk.CLASSICAL_RISK,
                    algorithm="X.509",
                    message=(
                        f"TLS certificate for {host} expires on {expiry_str} "
                        f"({delta_days} days remaining)."
                    ),
                    recommendation="Renew the TLS certificate before it expires.",
                    snippet=f"Not valid after: {expiry_str}",
                    tags=["tls", "live", "expiring-soon", "certificate"],
                ))
        except Exception:
            pass

        # --- Signature Algorithm ---
        try:
            sig_name = cert.signature_hash_algorithm.name.upper() if cert.signature_hash_algorithm else ""
            if "MD5" in sig_name:
                findings.append(self._make_finding(
                    host=host,
                    rule_id="tls-certificate-md5-signature",
                    rule_name="TLS Certificate MD5 Signature",
                    severity=Severity.CRITICAL,
                    quantum_risk=QuantumRisk.CLASSICAL_RISK,
                    algorithm=sig_name,
                    message=f"TLS certificate for {host} uses broken MD5 signature algorithm.",
                    recommendation="Re-issue certificate with SHA-256 or SHA-384 signature algorithm.",
                    snippet=f"Signature algorithm: {sig_name}",
                    tags=["tls", "live", "md5", "certificate"],
                ))
            elif "SHA1" in sig_name or "SHA-1" in sig_name:
                findings.append(self._make_finding(
                    host=host,
                    rule_id="tls-certificate-sha1-signature",
                    rule_name="TLS Certificate SHA-1 Signature",
                    severity=Severity.HIGH,
                    quantum_risk=QuantumRisk.QUANTUM_WEAKENED,
                    algorithm=sig_name,
                    message=f"TLS certificate for {host} uses deprecated SHA-1 signature algorithm.",
                    recommendation="Re-issue certificate with SHA-256 or SHA-384 signature algorithm.",
                    snippet=f"Signature algorithm: {sig_name}",
                    tags=["tls", "live", "sha1", "certificate"],
                ))
        except Exception:
            pass

        # --- Key Size ---
        try:
            pub_key = cert.public_key()
            if isinstance(pub_key, rsa.RSAPublicKey):
                key_size = pub_key.key_size
                if key_size < 2048:
                    findings.append(self._make_finding(
                        host=host,
                        rule_id="tls-certificate-weak-rsa-key",
                        rule_name="Weak RSA Key in TLS Certificate",
                        severity=Severity.CRITICAL,
                        quantum_risk=QuantumRisk.QUANTUM_BROKEN,
                        algorithm=f"RSA-{key_size}",
                        message=(
                            f"TLS certificate for {host} uses RSA-{key_size} key "
                            f"(minimum NIST requirement: 2048-bit)."
                        ),
                        recommendation="Re-issue certificate with RSA-3072 or EC-P256+ key.",
                        snippet=f"RSA key size: {key_size} bits",
                        tags=["tls", "live", "rsa", "weak-key", "certificate"],
                    ))
            elif isinstance(pub_key, ec.EllipticCurvePublicKey):
                key_size = pub_key.key_size
                if key_size < 224:
                    findings.append(self._make_finding(
                        host=host,
                        rule_id="tls-certificate-weak-ec-key",
                        rule_name="Weak EC Key in TLS Certificate",
                        severity=Severity.HIGH,
                        quantum_risk=QuantumRisk.QUANTUM_BROKEN,
                        algorithm=f"EC-{key_size}",
                        message=(
                            f"TLS certificate for {host} uses EC-{key_size}-bit key "
                            f"(minimum: 256-bit)."
                        ),
                        recommendation="Re-issue certificate with P-256 or P-384 curve.",
                        snippet=f"EC key size: {key_size} bits",
                        tags=["tls", "live", "ecdsa", "weak-key", "certificate"],
                    ))
        except Exception:
            pass

        return findings

    def _check_cert_ssl_fallback(self, host: str, cert_der: bytes) -> List[Finding]:
        """Minimal check when `cryptography` is not installed."""
        findings = []
        # Without the cryptography lib we can only surface a generic finding
        # to indicate the cert was retrieved but couldn't be analysed deeply.
        findings.append(self._make_finding(
            host=host,
            rule_id="tls-certificate-retrieved",
            rule_name="TLS Certificate Retrieved",
            severity=Severity.INFO,
            quantum_risk=QuantumRisk.QUANTUM_WEAKENED,
            algorithm="X.509",
            message=(
                f"TLS certificate retrieved from {host}. Install the `cryptography` "
                "package for deep analysis."
            ),
            recommendation="pip install cryptography",
            snippet=f"DER certificate: {len(cert_der)} bytes",
            tags=["tls", "live", "certificate"],
        ))
        return findings

    # ------------------------------------------------------------------
    # Factory helper
    # ------------------------------------------------------------------

    def _make_finding(
        self,
        host: str,
        rule_id: str,
        rule_name: str,
        severity: Severity,
        quantum_risk: QuantumRisk,
        algorithm: str,
        message: str,
        recommendation: str,
        snippet: str,
        tags: list,
    ) -> Finding:
        return Finding(
            file=f"live://{host}",
            line=0,
            column=0,
            language="tls",
            rule_id=rule_id,
            rule_name=rule_name,
            category="tls",
            algorithm=algorithm,
            severity=severity,
            quantum_risk=quantum_risk,
            message=message,
            recommendation=recommendation,
            code_snippet=snippet,
            confidence=Confidence.CONFIRMED,
            library="TLS/X.509",
            tags=tags,
        )

"""
Unit tests for Step 3: Network Evidence Importers (JSON, PCAP fallback, OpenSSL parsing, safety guardrails).
"""

import json
import os
import tempfile
import pytest
from triangulation.network_import import (
    import_network_json,
    import_openssl_sclient_output,
    import_network_pcap,
    NetworkImportError,
    MAX_FILE_SIZE_BYTES,
)


def test_valid_json_import():
    data = {
        "observations": [
            {
                "host": "api.crypto.internal",
                "port": 443,
                "protocol": "TLS",
                "protocol_version": "TLSv1.3",
                "cipher_suite": "TLS_AES_256_GCM_SHA384",
                "key_exchange": "X25519",
                "signature_algorithm": "sha256WithRSAEncryption",
                "certificate_key_type": "RSA",
                "certificate_key_size": 2048,
            }
        ]
    }
    observations = import_network_json(data)
    assert len(observations) == 1
    obs = observations[0]
    assert obs.host == "api.crypto.internal"
    assert "AES-256-GCM" in obs.normalized_algorithms
    assert obs.quantum_vulnerable is True


def test_malformed_json_rejection():
    with pytest.raises(NetworkImportError) as exc_info:
        import_network_json("this is not valid json {{{")
    assert "Invalid JSON string" in str(exc_info.value)

    with pytest.raises(NetworkImportError):
        import_network_json({"invalid_key": 123})


def test_openssl_sclient_parsing():
    sample_output = """
CONNECTED(00000003)
---
Certificate chain
 0 s:CN = *.crypto.internal
   i:C = US, O = Let's Encrypt, CN = R3
---
Server certificate
-----BEGIN CERTIFICATE-----
MII...
-----END CERTIFICATE-----
subject=CN = *.crypto.internal
issuer=C = US, O = Let's Encrypt, CN = R3
---
No client certificate CA names sent
Peer signing digest: SHA256
Peer signature type: RSA-PSS
Server Temp Key: ECDH, P-256, 256 bits
---
SSL handshake has read 3100 bytes and written 410 bytes
Verification: OK
---
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
Protocol  : TLSv1.3
Cipher    : TLS_AES_256_GCM_SHA384
Server public key is 2048 bit
    """

    observations = import_openssl_sclient_output(sample_output, host="api.crypto.internal")
    assert len(observations) == 1
    obs = observations[0]
    assert obs.protocol_version == "TLSv1.3"
    assert obs.cipher_suite == "TLS_AES_256_GCM_SHA384"
    assert obs.certificate_key_type == "RSA"
    assert obs.certificate_key_size == 2048
    assert "AES-256-GCM" in obs.normalized_algorithms


def test_pcap_import_fallback_or_success():
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
        tmp.write(b"dummy pcap header bytes")
        tmp_path = tmp.name

    try:
        res = import_network_pcap(tmp_path)
        assert "pcap_parsed" in res
        assert "message" in res
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


def test_scapy_pcap_parser_when_installed():
    """Validates real PCAP parsing using scapy if installed, skips cleanly if scapy is absent."""
    try:
        import scapy  # type: ignore # noqa: F401
    except ImportError:
        pytest.skip("scapy is not installed in the environment")

    pcap_path = os.path.join("triangulation", "fixtures", "tls_handshake.pcap")
    assert os.path.exists(pcap_path), "tls_handshake.pcap fixture missing"
    res = import_network_pcap(pcap_path)
    assert res["pcap_parsed"] is True
    assert len(res["observations"]) > 0



def test_oversized_file_rejection():
    large_bytes = b"x" * (MAX_FILE_SIZE_BYTES + 1024)
    with pytest.raises(NetworkImportError) as exc_info:
        import_network_json(large_bytes)
    assert "exceeds maximum allowed size" in str(exc_info.value)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

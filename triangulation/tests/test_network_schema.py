"""
Unit tests for Step 2: Network Observation Schema & Normalizer extensions.
"""

import pytest
from triangulation.network_schema import NetworkObservation
from runtime.normalize import normalize_algorithm, extract_network_algorithms


def test_network_observation_validation():
    obs = NetworkObservation(
        host="example.com",
        port=443,
        protocol="TLS",
        protocol_version="TLSv1.2",
        cipher_suite="TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        key_exchange="ECDHE",
        signature_algorithm="sha256WithRSAEncryption",
        certificate_key_type="RSA",
        certificate_key_size=2048,
    )
    d = obs.to_dict()

    assert obs.observation_id is not None
    assert "AES" in obs.normalized_algorithms
    assert "AES-256-GCM" in obs.normalized_algorithms
    assert "ECDHE" in obs.normalized_algorithms
    assert "RSA" in obs.normalized_algorithms
    assert obs.quantum_vulnerable is True


def test_normalizer_network_names():
    assert normalize_algorithm("ecdhe") == "ECDHE"
    assert normalize_algorithm("x25519") == "X25519"
    assert normalize_algorithm("X25519MLKEM768") == "X25519MLKEM768"
    assert normalize_algorithm("tls_aes_256_gcm_sha384") == "AES-256-GCM"


def test_extract_network_algorithms():
    algos = extract_network_algorithms(
        cipher_suite="TLS_AES_256_GCM_SHA384",
        key_exchange="X25519",
        signature_algorithm="sha256WithRSAEncryption",
        certificate_key_type="RSA",
    )
    assert "AES" in algos
    assert "AES-256-GCM" in algos
    assert "X25519" in algos
    assert "RSA" in algos
    assert "SHA-256" in algos


def test_from_dict_roundtrip():
    sample = {
        "observation_id": "test-obs-123",
        "capture_id": "cap-456",
        "host": "api.internal",
        "port": 8443,
        "protocol": "TLS",
        "protocol_version": "TLSv1.3",
        "cipher_suite": "TLS_AES_128_GCM_SHA256",
        "key_exchange": "X25519MLKEM768",
        "certificate_key_type": "EC",
        "certificate_key_size": 256,
    }
    obs = NetworkObservation.from_dict(sample)
    assert obs.observation_id == "test-obs-123"
    assert obs.capture_id == "cap-456"
    assert "AES-128-GCM" in obs.normalized_algorithms
    assert "X25519MLKEM768" in obs.normalized_algorithms


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

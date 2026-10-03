"""
Unit tests for Step 4: Evidence Normalization across Static, Runtime, and Network sources.
"""

import pytest
from triangulation.evidence import (
    EvidenceItem,
    normalize_static_finding,
    normalize_runtime_event,
    normalize_network_observation,
    normalize_all_evidence,
)
from triangulation.network_schema import NetworkObservation


def test_normalize_static_finding():
    finding = {
        "id": "finding-sha256-01",
        "file": "demo_crypto_app.py",
        "line": 33,
        "function": "hash_data",
        "algorithm": "SHA-256",
        "rule_id": "sha256-hash",
        "category": "hash",
    }
    item = normalize_static_finding(finding)
    assert item.source == "static"
    assert item.algorithm == "SHA-256"
    assert item.location == "demo_crypto_app.py:33:hash_data"
    assert item.finding_id == "finding-sha256-01"


def test_normalize_runtime_event():
    event = {
        "event_id": "evt-aes-99",
        "algorithm": "AES",
        "key_size": 256,
        "mode": "GCM",
        "call_file": "demo_crypto_app.py",
        "call_line": 40,
        "call_function": "aes_encrypt",
        "matched_finding_id": "finding-aes-02",
    }
    item = normalize_runtime_event(event)
    assert item.source == "runtime"
    # With key_size=256 and mode=GCM, bare "AES" is qualified to "AES-256-GCM"
    assert item.algorithm == "AES-256-GCM"
    assert item.key_size == 256
    assert item.location == "demo_crypto_app.py:40:aes_encrypt"
    assert item.finding_id == "finding-aes-02"
    assert item.raw_ref == "evt-aes-99"

    # Without mode, bare AES+256 qualifies to AES-256
    event_no_mode = {**event, "mode": None, "event_id": "evt-aes-100"}
    item2 = normalize_runtime_event(event_no_mode)
    assert item2.algorithm == "AES-256"



def test_normalize_network_observation():
    obs = NetworkObservation(
        observation_id="net-obs-77",
        host="api.crypto.internal",
        port=443,
        cipher_suite="TLS_AES_256_GCM_SHA384",
        key_exchange="X25519",
        certificate_key_type="RSA",
        certificate_key_size=2048,
    )
    items = normalize_network_observation(obs)
    assert len(items) >= 3  # AES, AES-256-GCM, RSA, X25519, SHA-384
    sources = {i.source for i in items}
    assert sources == {"network"}
    algos = {i.algorithm for i in items}
    assert "AES-256-GCM" in algos
    assert "RSA" in algos
    assert "X25519" in algos


def test_normalize_all_evidence():
    static_f = [{"id": "f1", "file": "app.py", "line": 10, "algorithm": "SHA-256"}]
    runtime_e = [{"event_id": "e1", "algorithm": "SHA-256", "call_file": "app.py", "call_line": 10, "matched_finding_id": "f1"}]
    network_o = [{"observation_id": "n1", "host": "app.local", "cipher_suite": "TLS_AES_256_GCM_SHA384"}]

    items = normalize_all_evidence(static_f, runtime_e, network_o)
    assert len(items) >= 3
    sources = {i.source for i in items}
    assert sources == {"static", "runtime", "network"}


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

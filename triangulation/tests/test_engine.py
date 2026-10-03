"""
Unit & Integration Tests for Step 5: Triangulation Engine.
Tests all 4 classification outcomes (Confirmed Active, Static Only, Runtime Only, Network Only)
and coverage notes / confidence scoring.
"""

import pytest
from triangulation.engine import run_triangulation, TriangulationResult


def test_engine_demo_crypto_app_classification():
    findings = [
        {"id": "f-sha256", "file": "demo_crypto_app.py", "line": 33, "function": "hash_data", "algorithm": "SHA-256"},
        {"id": "f-aes", "file": "demo_crypto_app.py", "line": 40, "function": "aes_encrypt", "algorithm": "AES-256-GCM"},
        {"id": "f-rsa2048", "file": "demo_crypto_app.py", "line": 45, "function": "rsa_sign_verify", "algorithm": "RSA-2048"},
        {"id": "f-ecdsa", "file": "demo_crypto_app.py", "line": 57, "function": "ecdsa_sign", "algorithm": "ECDSA"},
        {"id": "f-md5", "file": "demo_crypto_app.py", "line": 65, "function": "legacy_weak_crypto", "algorithm": "MD5"},
        {"id": "f-sha1", "file": "demo_crypto_app.py", "line": 66, "function": "legacy_weak_crypto", "algorithm": "SHA-1"},
        {"id": "f-rsa1024", "file": "demo_crypto_app.py", "line": 67, "function": "legacy_weak_crypto", "algorithm": "RSA-1024"},
    ]

    events = [
        {"event_id": "e-sha256", "algorithm": "SHA-256", "call_file": "demo_crypto_app.py", "call_line": 33, "call_function": "hash_data", "matched_finding_id": "f-sha256"},
        {"event_id": "e-aes", "algorithm": "AES", "key_size": 256, "call_file": "demo_crypto_app.py", "call_line": 40, "call_function": "aes_encrypt", "matched_finding_id": "f-aes"},
        {"event_id": "e-rsa2048", "algorithm": "RSA", "key_size": 2048, "call_file": "demo_crypto_app.py", "call_line": 45, "call_function": "rsa_sign_verify", "matched_finding_id": "f-rsa2048"},
        {"event_id": "e-ecdsa", "algorithm": "ECDSA", "call_file": "demo_crypto_app.py", "call_line": 57, "call_function": "ecdsa_sign", "matched_finding_id": "f-ecdsa"},
    ]

    results = run_triangulation("demo-scan-1", findings, events, [])
    assert len(results) == 7

    confirmed = [r for r in results if r.classification == "Confirmed Active"]
    static_only = [r for r in results if r.classification == "Static Only"]

    assert len(confirmed) == 4
    assert len(static_only) == 3

    # Verify coverage note on Static Only
    for s in static_only:
        assert "Not observed in 1 monitored run(s)" in s.coverage_note


def test_engine_runtime_only_false_negative():
    events = [
        {
            "event_id": "e-chacha",
            "algorithm": "ChaCha20-Poly1305",
            "key_size": 256,
            "call_file": "dynamic_loader.py",
            "call_line": 12,
            "call_function": "dynamic_cipher",
            "matched_finding_id": None,
        }
    ]

    results = run_triangulation("scan-rt-only", [], events, [])
    assert len(results) == 1
    res = results[0]
    assert res.classification == "Runtime Only"
    assert res.possible_static_false_negative is True
    assert "static-analysis false negative" in res.coverage_note


def test_engine_network_only_classification():
    network_obs = [
        {
            "observation_id": "n-dh-1",
            "host": "remote-auth.internal",
            "port": 8443,
            "protocol": "TLS",
            "protocol_version": "TLSv1.0",
            "cipher_suite": "TLS_DH_anon_WITH_AES_128_CBC_SHA",
            "key_exchange": "DH",
            "certificate_key_type": "DH",
            "certificate_key_size": 1024,
            "normalized_algorithms": ["DH"],
        }
    ]

    results = run_triangulation("scan-net-only", [], [], network_obs)
    assert len(results) >= 1
    res = [r for r in results if r.classification == "Network Only"][0]
    assert res.classification == "Network Only"
    assert res.location == "remote-auth.internal:8443"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

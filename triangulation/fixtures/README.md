# Triangulated Truth Test Fixtures

This directory contains test fixtures used to demonstrate and validate all 4 classification outcomes in CryptoScan's Triangulated Truth engine:

1. **Confirmed Active**: Demonstrated by `demo_crypto_app.py` executed under the Python runtime tracer (SHA-256, AES-256-GCM, RSA-2048, ECDSA P-256).
2. **Static Only**: Demonstrated by `demo_crypto_app.py` unexecuted code branch `legacy_weak_crypto()` (MD5, SHA-1, RSA-1024).
3. **Runtime Only** (`runtime_only_event.json`): Contains a runtime event for `ChaCha20-Poly1305` executed dynamically in code missed by static AST analysis, demonstrating a **Possible Static False Negative**.
4. **Network Only** (`network_only_capture.json`): Contains TLS 1.0 network traffic observations using anonymous Diffie-Hellman (`TLS_DH_anon_WITH_AES_128_CBC_SHA`), demonstrating network-observed algorithms missing from local codebase evidence.
5. **TLS PCAP Handshake** (`tls_handshake.pcap`): Binary PCAP header and TLS record fixture used to test scapy/pyshark network capture parsers.

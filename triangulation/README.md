# CryptoScan: Triangulated Truth Module (Code + Runtime + Network)

## Overview
Triangulated Truth is the correlation engine of **CryptoScan**. It synthesizes cryptographic evidence from three independent detection layers:
1. **Static AST Analysis** (`scanner/`): Identifies cryptographic calls, configurations, and hardcoded algorithms in the codebase.
2. **Runtime Execution Tracing** (`runtime/`): Captures active cryptographic operations during test or staging execution.
3. **Network Traffic Metadata** (`triangulation/`): Ingests TLS/SSH/IPsec handshake parameters, negotiated cipher suites, key exchange groups, and certificate public key types.

---

## The 4 Evidence Classification Tiers

| Classification | Description | Action / Impact |
|---|---|---|
| **Confirmed Active** | Observed in static codebase AND executed at runtime. | Priority target for PQC migration planning. |
| **Static Only** | Present in code, but NOT observed in the monitored test run. | Includes explicit coverage note: *"Not observed in N monitored run(s); code path may not have been exercised."* **Never labeled as safe or unused.** |
| **Runtime Only** | Executed at runtime, but missed by static AST analysis. | Flagged with `possible_static_false_negative = true`. |
| **Network Only** | Observed in network traffic, but no static or runtime match. | Indicates external or third-party cryptographic activity. |

---

## Hard Rules & Security Principles
- **No Secret Logging**: Only cryptographic metadata (algorithm names, key sizes, modes, curve names, TLS versions) is stored. No key bytes, plaintext, ciphertext, or packet payloads are recorded.
- **PostgreSQL Schema**: Production schema uses `provider = "postgresql"` in `backend-core/prisma/schema.prisma`.
- **Untrusted Input**: Network captures (JSON, PCAP, OpenSSL output) are capped at 10MB to prevent denial-of-service.

---

## Usage Guide

### CLI Commands
```bash
# 1. Import network evidence JSON
python -m triangulation.cli network import --file triangulation/fixtures/network_only_capture.json --scan-id scan-123 --out net_obs.json

# 2. Run Triangulation Engine
python -m triangulation.cli triangulate --scan-id scan-123 --out triangulation_result.json

# 3. Execute Evaluation Harness (Ground Truth Metrics)
python -m triangulation.cli triangulate eval
```

### API Endpoints
- `POST /api/network/captures` : Ingest network observations JSON payload.
- `GET /api/network/captures` : List network captures.
- `POST /api/triangulation/run` : Run triangulation for a scan ID.
- `GET /api/triangulation/:scanId` : Retrieve classified results for a scan ID.
- `GET /api/triangulation/:scanId/summary` : Summary card counts and coverage info.
- `GET /api/triangulation/metrics` : Retrieve precision, recall, and F1 evaluation metrics.

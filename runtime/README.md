# CryptoScan: Feature 12 — Runtime Cryptographic Intelligence & Execution Tracing

> ⚠️ **IMPORTANT WARNING:**  
> **Runtime execution tracing is designed STRICTLY for test and staging environments.**  
> Do **NOT** enable runtime tracing hooks in production environments due to trace collector overhead and potential dynamic monkeypatching side effects.

---

## 📖 Overview

Runtime Cryptographic Intelligence dynamically instruments Python and Node.js applications during test/staging execution to record which cryptographic operations actually execute at runtime. 

This provides dynamic runtime evidence that complements static AST discovery, allowing downstream features (such as **Triangulated Truth**) to correlate static findings with dynamic execution proofs and identify unexecuted static code paths.

---

## ⚡ Quick Start Demo

Run the instrumented demo applications directly from the command line:

### 1. Run Python Demo Application
```bash
python runtime/cli.py run --lang python -- python runtime/demo/python_app.py
```

### 2. Run Node.js Demo Application
```bash
python runtime/cli.py run --lang node -- node runtime/demo/node_app.js
```

### 3. Generate Evidence Report
```bash
python runtime/cli.py report --run-id <run-id-from-step-1-or-2> --out report.json
```

---

## 🖥️ CLI Usage

```bash
# Execute Python application under instrumentation
cryptoscan runtime run --lang python [--scan-id <id>] [--out events.jsonl] -- python app.py

# Execute Node.js application under instrumentation
cryptoscan runtime run --lang node   [--scan-id <id>] [--out events.jsonl] -- node app.js

# Generate evidence report from recorded run events
cryptoscan runtime report --run-id <run-id> [--out report.json]
```

---

## 🌐 REST API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/runtime/runs` | Ingest a run with events payload |
| `GET` | `/api/runtime/runs` | List recorded runs (filter by `scan_id`) |
| `GET` | `/api/runtime/runs/:run_id` | Get details for a specific run |
| `GET` | `/api/runtime/runs/:run_id/events` | Get paginated raw events for a run |
| `GET` | `/api/runtime/runs/:run_id/report` | Generate aggregated evidence report |

### Example Ingestion Request (`POST /api/runtime/runs`)
```json
{
  "run_id": "run-98765",
  "scan_id": "scan-12345",
  "language": "python",
  "command": "python app.py",
  "environment": "test",
  "events": [
    {
      "event_id": "evt-001",
      "timestamp": "2026-10-03T12:00:00Z",
      "language": "python",
      "library": "hashlib",
      "operation": "hash",
      "algorithm": "SHA-256",
      "call_file": "app.py",
      "call_line": 42,
      "call_function": "process_login"
    }
  ]
}
```

---

## 🛡️ Zero Secret Leakage & Security Safeguards

1. **Metadata-Only Collection**: No key material, plaintext, ciphertext, initialization vectors, passwords, or secrets are ever recorded or logged.
2. **Fail-Safe Execution**: Every tracer hook is wrapped in internal try/except logic. Any error within the tracer is swallowed silently to guarantee that target application behavior is never altered or broken.

---

## 🔍 Captured vs. Not Captured

### What IS Captured:
- Standard Python libraries: `hashlib`, `hmac`, `cryptography` (ciphers, hashes, RSA/EC keygen), `PyCryptodome`, `PyJWT`, `ssl`.
- Standard Node.js built-in `crypto` module (`createHash`, `createHmac`, `createCipheriv`, `createDecipheriv`, `generateKeyPair`, `createSign`, `createVerify`, `pbkdf2`), `jsonwebtoken`, `tls`.
- Metadata: `algorithm`, `key_size`, `mode`, `padding`, `curve`, `call_file`, `call_line`, `call_function`.

### What IS NOT Captured:
- Native C/C++ extensions that directly invoke OpenSSL/BoringSSL C APIs without passing through hooked Python/Node.js module functions.
- Languages other than Python and Node.js (e.g. Go, Java, Rust binaries).
- Dead or unexecuted code paths that are never reached during test execution.

---

## 📜 JSON Contracts for Triangulated Truth

### 1. Runtime Event Schema (`RuntimeEvent`)
```json
{
  "event_id": "869c1786-fb11-4461-9adc-bc3d7f0d94ae",
  "run_id": "58933dc3-51e9-4ccd-932d-6870a97d6d70",
  "timestamp": "2026-10-03T07:15:56Z",
  "language": "python",
  "library": "hashlib",
  "operation": "hash",
  "algorithm": "SHA-256",
  "key_size": null,
  "mode": null,
  "padding": null,
  "curve": null,
  "call_file": "app.py",
  "call_line": 15,
  "call_function": "compute_hash",
  "matched_finding_id": "f1"
}
```

### 2. Evidence Report JSON Structure
```json
{
  "run_id": "run-12345",
  "scan_id": "scan-67890",
  "language": "python",
  "environment": "test",
  "summary": {
    "total_events": 4,
    "unique_algorithms": ["AES", "ECDSA", "RSA", "SHA-256"],
    "quantum_vulnerable_algorithms": ["ECDSA", "RSA"],
    "unmatched_events": 0
  },
  "events": [
    {
      "algorithm": "SHA-256",
      "operation": "hash",
      "library": "hashlib",
      "key_size": null,
      "mode": null,
      "padding": null,
      "curve": null,
      "call_file": "app.py",
      "call_line": 15,
      "call_function": "compute_hash",
      "matched_finding_id": "f1",
      "count": 2,
      "first_seen": "2026-10-03T12:00:00Z",
      "last_seen": "2026-10-03T12:00:01Z",
      "is_quantum_vulnerable": false
    }
  ]
}
```

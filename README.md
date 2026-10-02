# 🔐 CryptoScan

### AI-Powered Enterprise Cryptographic Discovery & Post-Quantum Assurance Platform

CryptoScan is an end-to-end security platform that **discovers cryptographic assets, detects vulnerabilities, generates CBOMs, recommends post-quantum migration, and creates tamper-evident security proofs**.

It combines **AST-based code analysis, CycloneDX CBOM, risk assessment, Merkle integrity, RFC 3161 timestamping, post-quantum signatures, and Ethereum blockchain anchoring** into one workflow.

---

## 🚀 What It Does

```text
Source Code
    ↓
🔍 Cryptographic Discovery
    ↓
⚠️ Risk & Vulnerability Analysis
    ↓
📋 CycloneDX CBOM
    ↓
☢️ PQC Migration Recommendations
    ↓
🌲 Merkle Integrity Proof
    ↓
⏰ Trusted Timestamp + Hybrid Signature
    ↓
⛓️ Ethereum Sepolia Anchoring
    ↓
✅ Tamper Verification
```

### 🔍 Cryptographic Discovery

Detects cryptographic algorithms, hardcoded keys, insecure RNGs, weak ciphers, vulnerable key sizes, and quantum-sensitive cryptography using **Python & JavaScript AST analysis**.

### 📋 CBOM Generation

Generates a standardized **CycloneDX Cryptographic Bill of Materials** containing discovered cryptographic components, their purpose, risk, and migration recommendations.

### ☢️ Post-Quantum Readiness

Identifies cryptography vulnerable to future quantum attacks and provides migration guidance toward NIST-standardized algorithms such as **ML-KEM and ML-DSA**.

### 🛡️ Cryptographic Assurance

Creates a deterministic **Merkle Root**, protects the commitment using **ECDSA + ML-DSA-65**, and adds an **RFC 3161 trusted timestamp**.

### ⛓️ On-Chain Verification

Anchors the cryptographic commitment to **Ethereum Sepolia** through `CryptoAnchor.sol`, allowing the security state to be independently verified later.

---

## 🏗️ Architecture

```text
                    ┌──────────────┐
                    │  Dashboard   │
                    └──────┬───────┘
                           ↓
                    ┌──────────────┐
                    │ Backend Core │
                    └───┬──────┬───┘
                        ↓      ↓
                 ┌────────┐ ┌────────┐
                 │Scanner │ │  CBOM  │
                 │  AST   │ │ Engine │
                 └───┬────┘ └───┬────┘
                     └─────┬────┘
                           ↓
                    ┌──────────────┐
                    │   Integrity  │
                    │ Merkle / PQC │
                    └──────┬───────┘
                           ↓
                    ┌──────────────┐
                    │  Blockchain  │
                    │ Ethereum     │
                    │   Sepolia    │
                    └──────────────┘
```

---

## 🧰 Tech Stack

**Frontend:** HTML • CSS • JavaScript
**Backend:** Node.js • Express.js • Prisma
**Scanner:** Python AST
**CBOM:** CycloneDX
**Integrity:** Merkle Trees • RFC 3161
**Cryptography:** ECDSA • ML-DSA-65
**Blockchain:** Solidity • Hardhat • Ethereum Sepolia
**Database:** PostgreSQL / SQLite

---

## 📁 Project Structure

```text
CryptoScan/
├── backend-core/       # REST API & orchestration
├── scanner/            # Python & JS AST analysis
├── cbom-service/       # CycloneDX CBOM generation
├── integrity-service/  # Merkle, KMS, timestamp & PQ signatures
├── blockchain-module/  # Smart contracts & Sepolia
└── frontend/           # Security dashboard
```

---

## ⛓️ Live Contract

**Network:** Ethereum Sepolia
**Chain ID:** `11155111`
**Contract:** `CryptoAnchor`

`0x6BD080EfF2E516B6F02d87Cc2D11dCf8A7c86898`

---

## 🧪 Testing

All major modules include automated regression tests covering:

**Scanner • CBOM • Backend • Merkle Integrity • Timestamping • KMS • Hybrid Signatures • Smart Contracts**

---

## 🎯 Vision

> **Discover cryptography. Assess the risk. Prepare for quantum. Prove the security state.**

CryptoScan transforms cryptographic visibility from a scattered code-level problem into a **measurable, auditable, and verifiable security workflow**.

---

**🔐 CryptoScan | Enterprise Cryptographic Discovery & Assurance**

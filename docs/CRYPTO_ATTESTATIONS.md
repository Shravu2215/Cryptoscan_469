# Cryptographic Attestations (Feature 7)

**Cryptographic Attestations** provides cryptographic provenance and non-repudiation for CryptoScan's Cryptographic Bill of Materials (CBOM) scan results. By combining standard **in-toto Statement v1**, **Sigstore keyless signing**, **Rekor transparency log**, **experimental hybrid ML-DSA-65 (FIPS 204) post-quantum signatures**, and **optional Sepolia blockchain anchoring**, organizations can prove scan integrity across the software supply chain.

---

## 1. Architecture & Trust Model

```
                    ┌───────────────────────────────────┐
                    │       CryptoScan CBOM Scan        │
                    │         (cbom.json)               │
                    └─────────────────┬─────────────────┘
                                      │ sha256
                                      ▼
                    ┌───────────────────────────────────┐
                    │     in-toto Statement v1          │
                    │   (attestation.intoto.json)       │
                    │  predicate: CBOM scan metadata    │
                    └─────────────────┬─────────────────┘
                                      │
            ┌─────────────────────────┴─────────────────────────┐
            ▼                                                   ▼
┌───────────────────────────────┐               ┌───────────────────────────────┐
│     Sigstore Keyless Sign     │               │    Experimental ML-DSA-65     │
│   (ECDSA-P256 via Fulcio)     │               │  (FIPS 204 PQC Envelope)      │
│  Public Transparency Log      │               │   Future-proof against CRQC   │
│       (Rekor Log)             │               └───────────────┬───────────────┘
└───────────────┬───────────────┘                               │
                │                                               │
                └───────────────────────┬───────────────────────┘
                                        ▼
                        ┌───────────────────────────────┐
                        │      Combined Attestation     │
                        │       & Optional Sepolia      │
                        │        Blockchain Anchor      │
                        └───────────────────────────────┘
```

### Trust Guarantees
1. **Artifact Integrity:** The CBOM SHA-256 hash is bound to the in-toto Statement subject. Any modification to the CBOM invalidates the attestation.
2. **Identity & Ephemeral Keys (Sigstore):** Signed using OpenID Connect (OIDC) identities from GitHub Actions or other identity providers. No long-lived private keys to manage or compromise.
3. **Auditability (Rekor):** Public immutable record proves when the signature was created and that the certificate was valid at signing time.
4. **Post-Quantum Security (ML-DSA-65):** Optional outer signature envelope uses FIPS 204 (CRYSTALS-Dilithium Level 3) over the Sigstore bundle to protect against "harvest now, decrypt/forge later" threats.
5. **Decentralized Anchoring (Sepolia):** Attestation hash can be anchored to the Sepolia Ethereum testnet using CryptoScan's blockchain registry contract.

---

## 2. in-toto Statement v1 Specification

Statements adhere to the official [in-toto Statement v1](https://github.com/in-toto/attestation/blob/main/spec/v1.0/statement.md) specification:

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    {
      "name": "cbom.json",
      "digest": {
        "sha256": "8d95e0e5f79803cfe274d8e2531c941f79377ce9544722ec23ef614afb664715"
      }
    }
  ],
  "predicateType": "https://cryptoscan.dev/attestation/cbom/v1",
  "predicate": {
    "scanner": {
      "name": "CryptoScan",
      "version": "cryptoscan/1.0.0",
      "scanned_at": "2026-10-03T20:30:00Z"
    },
    "repository": "my-org/my-repo",
    "commit": "abc123def456",
    "branch": "main",
    "summary": {
      "total_components": 14,
      "quantum_vulnerable": 8,
      "quantum_safe": 4,
      "classical_approved": 2,
      "critical_count": 2,
      "high_count": 6
    },
    "policy": {
      "threshold": "CRITICAL"
    },
    "components": [
      {
        "fingerprint": "a3b1c2d...",
        "algorithm": "RSA",
        "quantum_status": "VULNERABLE",
        "severity": "CRITICAL"
      }
    ]
  }
}
```

---

## 3. CLI Usage

The attestation features are accessible via `cryptoscan attest` / `cryptoscan verify` or the standalone `cryptoscan-attest` executable.

### Generating an Attestation (`attest`)

```bash
cryptoscan attest \
  --cbom cbom.json \
  --out-statement attestation.intoto.json \
  --out-bundle attestation.bundle.json \
  --out-hybrid attestation.hybrid.json \
  --repo my-org/my-repo \
  --commit $(git rev-parse HEAD) \
  --branch $(git rev-parse --abbrev-ref HEAD) \
  --with-pqc
```

#### Flags:
- `--cbom <path>`: *(Required)* Path to input CycloneDX CBOM JSON.
- `--out-statement <path>`: Destination path for in-toto Statement JSON (default: `attestation.intoto.json`).
- `--out-bundle <path>`: Destination path for Sigstore bundle JSON (default: `attestation.bundle.json`).
- `--out-hybrid <path>`: Destination path for ML-DSA-65 hybrid envelope JSON (default: `attestation.hybrid.json`).
- `--with-pqc`: Sign with experimental ML-DSA-65 (FIPS 204) outer signature.
- `--with-sepolia`: Anchor the attestation hash to Ethereum Sepolia.

### Verifying an Attestation (`verify`)

```bash
cryptoscan verify \
  --cbom cbom.json \
  --statement attestation.intoto.json \
  --bundle attestation.bundle.json \
  --hybrid attestation.hybrid.json \
  --identity "https://github.com/my-org/my-repo/.github/workflows/crypto-attestation.yml@refs/heads/main" \
  --issuer "https://token.actions.githubusercontent.com"
```

#### Verification Steps Performed:
1. **CBOM SHA-256:** Verifies `sha256(cbom.json)` matches the in-toto Statement's `subject[0].digest.sha256`.
2. **Subject Match:** Validates the subject artifact name matches the CBOM filename.
3. **Predicate Structure:** Validates `_type`, `predicateType`, and mandatory summary fields.
4. **Sigstore Verification:** Validates the ECDSA signature against the ephemeral certificate, Fulcio root of trust, and expected identity/issuer SAN.
5. **Rekor Inclusion:** Checks public Rekor transparency log inclusion proof.
6. **ML-DSA-65 PQC Envelope (if provided):** Verifies the post-quantum signature against the inner bundle's SHA-256 hash.

---

## 4. GitHub Actions Integration

The workflow in `.github/workflows/crypto-attestation.yml` generates attestations automatically on every push to `main` and pull request:

```yaml
name: CryptoScan CBOM Attestation

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

permissions:
  contents: read
  id-token: write    # Required for Sigstore keyless OIDC token

jobs:
  attest:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install Dependencies
        run: |
          pip install -r attestation/requirements.txt
          pip install -r requirements.txt || true

      - name: Generate CBOM
        run: python cryptoscan scan . --out cbom.json

      - name: Generate Signed Attestation
        run: |
          python cryptoscan attest \
            --cbom cbom.json \
            --out-statement attestation.intoto.json \
            --out-bundle attestation.bundle.json \
            --out-hybrid attestation.hybrid.json \
            --repo ${{ github.repository }} \
            --commit ${{ github.sha }} \
            --branch ${{ github.ref_name }} \
            --with-pqc

      - name: Verify Attestation Self-Check
        run: |
          python cryptoscan verify \
            --cbom cbom.json \
            --statement attestation.intoto.json \
            --bundle attestation.bundle.json \
            --hybrid attestation.hybrid.json \
            --identity "https://github.com/${{ github.repository }}/.github/workflows/crypto-attestation.yml@refs/heads/${{ github.ref_name }}" \
            --issuer "https://token.actions.githubusercontent.com"

      - name: Upload Attestation Artifacts
        uses: actions/upload-artifact@v4
        with:
          name: cryptoscan-attestations
          path: |
            cbom.json
            attestation.intoto.json
            attestation.bundle.json
            attestation.hybrid.json
```

---

## 5. Experimental Post-Quantum Hybrid Envelope (ML-DSA-65)

ML-DSA-65 (FIPS 204) is the NIST-standardized primary post-quantum digital signature algorithm.

### How It Works
1. Sigstore creates the primary bundle (ECDSA-P256 + Fulcio certificate + Rekor proof).
2. The hybrid wrapper computes the canonical SHA-256 digest of the complete Sigstore bundle.
3. An ephemeral or provisioned ML-DSA-65 private key signs the canonical digest.
4. The output envelope contains:
   - `sigstoreBundle`: Full classical Sigstore bundle.
   - `pqcSignature`: Base64-encoded ML-DSA-65 signature.
   - `pqcPublicKey`: Hex-encoded ML-DSA-65 public key (1,952 bytes).
   - `pqcAlgorithm`: `"ML-DSA-65 (FIPS 204)"`.
   - `bundleDigest`: SHA-256 digest of the inner bundle.

### Implementation Engines
- **`cryptography >= 44.0`:** Uses OpenSSL 3.5 / liboqs bindings for hardware-optimized ML-DSA.
- **`dilithium-py`:** Pure-Python fallback for environments without C extensions.
- **Stub Mode:** Available for testing in restricted environments without cryptographic dependencies.

---

## 6. Sepolia Blockchain Anchoring

To anchor attestation hashes on-chain for tamper-proof public auditing:

```bash
export SEPOLIA_RPC_URL="https://sepolia.infura.io/v3/<YOUR-PROJECT-ID>"
export WALLET_PRIVATE_KEY="0x<YOUR-PRIVATE-KEY>"
export CBOM_REGISTRY_ADDRESS="0x<CONTRACT-ADDRESS>"

python cryptoscan attest \
  --cbom cbom.json \
  --with-sepolia
```

When enabled, `attestation/sepolia_anchor.py` invokes the existing `blockchain-module/scripts/anchor.js` script to anchor the scan ID and attestation hash on Ethereum Sepolia.

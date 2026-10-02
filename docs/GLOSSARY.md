# CryptoScan Domain Glossary

This document defines the core domain taxonomy used across the CryptoScan scanner, backend API, and frontend interfaces for counting, risk scoring, and reporting.

---

### Key Terminology

1. **Finding (`finding`)**
   - **Definition**: A single detection event reported by any analyzer layer (AST, regex, entropy, SCA, certificate, infra) at a specific file and line.
   - **API Field**: `summary.findings_total`
   - **Example**: `AES-128-CBC` usage detected at `checkout_controller.py:23`.

2. **Component (`component`)**
   - **Definition**: A unique cryptographic asset defined by `(algorithm + parameters + location group / file)`. Multiple findings of the same algorithm family at the same location are merged into a single component.
   - **API Field**: `summary.components_total`
   - **Example**: `AES-256-GCM` in `checkout_controller.py`.

3. **Algorithm (`algorithm`)**
   - **Definition**: A distinct cryptographic primitive or mechanism family, independent of location or key size (e.g., `AES`, `RSA`, `ECDSA`, `SHA-256`).
   - **API Field**: `summary.algorithms_total`
   - **Example**: `ECDSA`.

---

### Counting & Reconciliation Rules

- **Header Consistency**: Every frontend view (Dashboard, CBOM, Risk Analysis, Migration Plan, Repositories, Scan View) MUST read numbers directly from the unified `summary` object returned by the backend API (`summary.findings_total`, `summary.components_total`, `summary.algorithms_total`).
- **No In-Browser Recounting**: Frontend scripts MUST NOT recount raw arrays in JavaScript to compute top-level summary headers.

# Feature 12 Plan: Runtime Cryptographic Intelligence & Execution Tracing

## 1. Existing System Components & File Paths

- **CBOM Generator**:
  - `cbom-service/src/services/cbomGenerator.js` (CycloneDX 1.6 CBOM document generator)
  - `backend-core/src/services/cbomGenerator.js`
- **Finding Schema & Stable Finding IDs**:
  - `scanner/models.py` (`Finding` dataclass with `fingerprint`, `rule_id`, `call_site`)
  - `backend-core/prisma/schema.prisma` (`Finding` model with `id`, `scanId`, `filePath`, `lineNumber`, `algorithm`, `severity`, etc.)
- **Database & Migrations (PostgreSQL + Prisma)**:
  - `backend-core/prisma/schema.prisma` (Database models)
  - `backend-core/prisma/migrations/` (Prisma migration history)
- **API Framework & Routes**:
  - `backend-core/src/server.js` (Express server entry point)
  - `backend-core/src/routes/` (`scans.js`, `repos.js`, `auth.js`)
  - `backend-core/src/middleware/auth.js` (JWT authentication & authorization middleware)
- **CLI Entry Point**:
  - `scanner/cli.py` (Command-line interface for scanner)
- **Test Infrastructure**:
  - `scanner/tests/` (Python `pytest` suite)
  - `backend-core/test/` (Node.js test scripts)
- **Frontend**:
  - `frontend/` (Static dashboard, scans, findings UI)

---

## 2. Planned Additions & File Modifications

### Files to Add:
1. `runtime/PLAN.md` - Implementation plan document (this file).
2. `runtime/schema.py` & `runtime/normalize.py` - Runtime event data model, JSON schema validation, and algorithm normalizer.
3. `runtime/python_agent/tracer.py` & `runtime/python_agent/sitecustomize.py` - Python import-hook tracer capturing `hashlib`, `hmac`, `cryptography`, `Crypto` (PyCryptodome), `jwt`, `ssl` metadata without logging key/plaintext data.
4. `runtime/node_agent/preload.js` - Node.js `--require` preload script hooking `crypto`, `jsonwebtoken`, `tls`, `node-forge` with call-site stack trace extraction.
5. `runtime/demo/python_app.py` & `runtime/demo/node_app.js` - Micro-demo apps containing executed crypto paths (AES-256-GCM, RSA-2048, SHA-256, ECDSA P-256) and an unexecuted path (e.g. RSA-1024 or MD5 under `if False`).
6. `runtime/db.py` / `runtime/repository.py` & Prisma schema updates - Models `RuntimeRun` and `RuntimeEvent`.
7. `runtime/report.py` - Evidence report generator aggregating unique runtime crypto events, quantum vulnerability flags, and summaries.
8. `runtime/matcher.py` - Static-to-runtime finding matcher correlating CBOM finding IDs with runtime call sites, line tolerances, and algorithm matching.
9. `runtime/cli.py` - CLI extensions for `cryptoscan runtime run` and `cryptoscan runtime report`.
10. `runtime/routes.js` (or `backend-core/src/routes/runtime.js`) - Express API endpoints for runtime run ingestion, listing, detail, paginated events, and reports.
11. `runtime/tests/` - Comprehensive test suite covering normalization, schema validation, zero-secret logging, fail-safe exception swallowing, demo integration, matcher accuracy, and API validation.
12. `runtime/README.md` - Full documentation including test/staging warning, usage examples, captured vs non-captured limitations, and JSON contract definitions.

### Existing Files to Modify:
1. `backend-core/prisma/schema.prisma` - Add `RuntimeRun` and `RuntimeEvent` models.
2. `scanner/cli.py` - Register the `runtime` subcommand group.
3. `backend-core/src/server.js` - Register `/api/runtime` routes.

---

## 3. Key Assumptions & Safeguards

1. **Zero Secret Leakage**: No key bytes, plaintexts, ciphertexts, initialization vectors, or passwords will ever be captured or logged. Metadata only (`algorithm`, `key_size`, `mode`, `padding`, `curve`, `call_file`, `call_line`, `call_function`).
2. **Fail-Safe Instrumentation**: All tracer hooks wrapped in `try/catch` or `try/except`; tracer exceptions will be swallowed silently to prevent breaking target application behavior.
3. **Test/Staging Environment Scope**: Tracing is designated strictly for test/staging execution tracing.
4. **Additive Member 1 Compatibility**: Static scanner Finding IDs and CBOM output format remain untouched and un-mutated.

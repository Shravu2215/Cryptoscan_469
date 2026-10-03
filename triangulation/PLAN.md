# Triangulated Truth (Code + Runtime + Network) — Implementation Plan

## 1. Existing System Context & Key File Paths

- **Static Scanner**: `scanner/`
  - `scanner/cli.py`: Static scanner CLI entry point
  - `scanner/models.py`: Static finding models (`Finding`, `Severity`, `QuantumRisk`, `Confidence`, `fingerprint`)
  - `scanner/pipeline.py`: Scanner execution pipeline producing CBOM findings
- **Runtime Cryptographic Tracing**: `runtime/`
  - `runtime/schema.py`: Event schema (`RuntimeEvent`, `RuntimeRun`)
  - `runtime/normalize.py`: Algorithm canonicalization (`normalize_algorithm`)
  - `runtime/matcher.py`: Static-to-runtime event correlation (`match_events_to_findings`)
  - `runtime/report.py`: Runtime evidence report generator
- **Backend Core**: `backend-core/`
  - `backend-core/prisma/schema.prisma`: Prisma schema (`Scan`, `Finding`, `RuntimeRun`, `RuntimeEvent`) using `postgresql` provider
  - `backend-core/src/server.js`: Express server mounting routes
  - `backend-core/src/routes/runtime.js`: API endpoints for runtime runs & events
- **Frontend**: `frontend/`
  - HTML dashboards (`verification.html`, `risk-analysis.html`, `dashboard.html`)
  - Local static server setup (`frontend/server.js`)

---

## 2. Files to Add / Modify

### Module: `triangulation/`
- `triangulation/PLAN.md` (Step 1): Implementation plan and architecture document.
- `triangulation/network_schema.py` (Step 2): Data model for network observations (`NetworkObservation`, `NetworkCapture`).
- `triangulation/network_import.py` (Step 3): Network evidence parser (JSON importer, best-effort PCAP/TLS parser, OpenSSL `s_client` output converter).
- `triangulation/evidence.py` (Step 4): Unified `EvidenceItem` normalization across Static, Runtime, and Network sources.
- `triangulation/engine.py` (Step 5): Triangulation engine implementing match logic & 4-class classification (`Confirmed Active`, `Static Only`, `Runtime Only`, `Network Only`).
- `triangulation/fixtures/` (Step 6): Test fixtures for Runtime Only (`runtime_only_event.json`) and Network Only (`network_only_capture.json`) plus `triangulation/fixtures/README.md`.
- `triangulation/eval/` (Step 8): Ground truth dataset (`ground_truth.json`) and evaluation metrics script (`evaluate.py`) for precision, recall, F1, and accuracy.
- `triangulation/cli.py` (Step 9): CLI for network import, triangulation execution, and evaluation (`cryptoscan network import`, `cryptoscan triangulate`).
- `triangulation/tests/` (Step 12): Unit, safety, fail-safe, and integration test suite (`test_network_schema.py`, `test_engine.py`, `test_eval.py`, `test_integration.py`).
- `triangulation/README.md` (Step 13): Feature documentation, CLI/API contract, and usage guide.

### Backend Updates (`backend-core/`)
- `backend-core/prisma/schema.prisma` (Step 7): Add PostgreSQL-compatible Prisma models (`NetworkCapture`, `NetworkObservation`, `TriangulationResult`).
- `backend-core/src/services/triangulationStorage.js` (Step 7): DAO layer for persisting network captures & triangulation results.
- `backend-core/src/routes/network.js` & `backend-core/src/routes/triangulation.js` (Step 10): API endpoints for network captures & triangulation analysis.
- `backend-core/src/server.js`: Mount `/api/network` and `/api/triangulation` routes.

### Frontend Updates (`frontend/`)
- `frontend/triangulation.html` (Step 11): Dedicated Triangulated Truth dashboard displaying summary cards, badges, evidence details, false negative flags, metrics panel, and coverage disclaimers.

---

## 3. Key Design Principles & Assumptions

1. **Strict 4-Class Model**:
   - `Confirmed Active`: Static AND Runtime evidence present.
   - `Static Only`: Found in static analysis, NOT observed in the monitored runtime trace.
   - `Runtime Only`: Observed in runtime trace without matching static finding (`possible_static_false_negative = true`).
   - `Network Only`: Observed in network traffic, no matching static or runtime finding.
2. **Coverage Warning**:
   - Findings in `Static Only` are NEVER described as "unused" or "safe". They include a clear execution-coverage note: *"Not observed in N monitored run(s); the code path may not have been exercised."*
3. **No Secret / Payload Logging**:
   - Network evidence extracts only metadata (TLS protocol versions, cipher suite names, key exchange groups, public key sizes).
4. **PostgreSQL Compatibility**:
   - Prisma schema maintains `provider = "postgresql"`. Teammate models (`ThreatScenario`, `SensitiveDataField`, `MigrationSchedule`) remain intact and untouched.

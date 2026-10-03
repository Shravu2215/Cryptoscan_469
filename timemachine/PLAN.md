# Crypto Time Machine (Feature 5) Implementation Plan

## Overview
The **Crypto Time Machine** analyzes Git repository history to track the introduction, exposure duration, burndown, and resolution of cryptographic findings and leaked secrets across commits.

---

## What Exists (Existing Components & Paths)

1. **Member 1 Static Scanner**:
   - [`scanner/cli.py`](file:///c:/Users/devka/OneDrive/Desktop/Craftverse/Cryptoscan_469/scanner/cli.py) — Entry point with `scan(root, extensions)` function.
   - [`scanner/models.py`](file:///c:/Users/devka/OneDrive/Desktop/Craftverse/Cryptoscan_469/scanner/models.py) — Core `Finding` dataclass (contains `algorithm`, `rule_id`, `severity`, `quantum_risk`, `code_snippet`, `call_site`, `fingerprint`).

2. **Backend Services & Persistence**:
   - [`backend-core/prisma/schema.prisma`](file:///c:/Users/devka/OneDrive/Desktop/Craftverse/Cryptoscan_469/backend-core/prisma/schema.prisma) — Prisma schema (`provider = "postgresql"`).
   - [`backend-core/src/server.js`](file:///c:/Users/devka/OneDrive/Desktop/Craftverse/Cryptoscan_469/backend-core/src/server.js) — Express API server.

3. **Frontend Shell & Navigation**:
   - [`frontend/assets/js/shell.js`](file:///c:/Users/devka/OneDrive/Desktop/Craftverse/Cryptoscan_469/frontend/assets/js/shell.js) — Global navigation shell injecting sidebar and topbar.

---

## Files to Add & Modify

### Python `timemachine/` Module:
- `timemachine/__init__.py`: Package initialization.
- `timemachine/PLAN.md`: Step 1 planning document.
- `timemachine/demo/make_demo_repo.py`: Step 2 script to generate the 7-commit synthetic Git repository.
- `timemachine/demo/expected.json`: Hand-written ground truth for evaluation.
- `timemachine/history.py`: Step 3 read-only Git plumbing reader (`git log`, `git cat-file`, `git show`, hooks disabled).
- `timemachine/scan_history.py`: Step 4 per-commit AST scanning with blob SHA file-content caching.
- `timemachine/lifecycle.py`: Step 5 finding lifecycle & exposure tracking (`introduced_commit`, `removed_commit`, `exposure_days`).
- `timemachine/secrets.py`: Step 6 leaked private key detection with zero key/secret retention (redacted fingerprinting).
- `timemachine/timeline.py`: Step 7 risk debt timeline & burndown series calculation.
- `timemachine/cli.py`: Step 9 CLI interface (`cryptoscan history scan|report|demo`).
- `timemachine/eval/evaluate.py`: Step 10 evaluation harness.
- `timemachine/tests/`: Step 13 unit & safety test suite.
- `timemachine/README.md`: Module documentation and contract specifications.

### Backend Additions (`backend-core/`):
- Update [`backend-core/prisma/schema.prisma`](file:///c:/Users/devka/OneDrive/Desktop/Craftverse/Cryptoscan_469/backend-core/prisma/schema.prisma): Add `HistoryScan`, `HistoryFinding`, `HistorySecret`, `HistoryTimelinePoint` models.
- `backend-core/src/services/historyStorage.js`: Storage service with database operations & in-memory fallback.
- `backend-core/src/routes/history.js`: REST API routes (`POST /api/history/scans`, `GET /api/history/scans/:id`, etc.).

### Frontend Additions (`frontend/`):
- `frontend/timemachine.html`: Step 12 Crypto Time Machine interactive UI.
- Update [`frontend/assets/js/shell.js`](file:///c:/Users/devka/OneDrive/Desktop/Craftverse/Cryptoscan_469/frontend/assets/js/shell.js): Add nav item under `ANALYSIS` group.

---

## Key Assumptions & Hard Rules

1. **Read-Only Git Operations**: Never execute repository code. All Git inspection uses plumbing commands (`git log`, `git diff-tree`, `git cat-file`) with hooks disabled (`core.hooksPath=NUL`).
2. **Zero Secret Leakage**: No private key contents or PEM blocks will ever be stored, logged, or sent in API responses. Only secret types, file locations, dates, and SHA-256 redacted fingerprints are retained.
3. **Additive Database Extensions**: All Prisma models added are strictly additive. Teammates' existing models and PostgreSQL provider settings will remain untouched.
4. **Member 1 Scanner Reuse**: Reuses Member 1's real scanner (`scanner/cli.py`) for per-commit content scanning.

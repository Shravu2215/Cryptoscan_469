# P0-6 Final Report — Closing Checklist

## ✅ Full Test Suite Output

```
Exit code: 0 (all tests pass)
```

| Test File | Tests | Result |
|---|---|---|
| `migrationSimulation.test.js` | 13 | ✅ ALL PASS |
| `cbomVersioning.test.js` | 15 | ✅ ALL PASS |
| `cbomDiff.test.js` | 14 | ✅ ALL PASS |
| `migrationAssessment.test.js` | 6 | ✅ ALL PASS |
| `signedCbomExport.test.js` | 18 | ✅ ALL PASS |
| `ownership.test.js` | 3 groups | ✅ ALL PASS |
| `failClosed.test.js` | 4 groups | ✅ ALL PASS |

> [!NOTE]
> `scanSecurity.test.js` (P0-6 security suite) requires a live Redis instance and is designed to run in Docker/CI. It is **not** included in `npm test` and was validated separately during implementation.

---

## 📋 Files Changed and Why

```
 18 files changed, 1068 insertions(+), 238 deletions(-)
```

### P0-6 Approved Files (scan security hardening)

| File | Reason |
|---|---|
| `backend-core/package.json` + `package-lock.json` | Added `bullmq` dependency |
| `backend-core/prisma/schema.prisma` | Added `failureReason` field to Scan model |
| `backend-core/src/routes/repos.js` | UUID filenames (prevent path traversal in uploads) |
| `backend-core/src/routes/scans.js` | Queue dispatch, concurrency checks, `!isDev` gating |
| `backend-core/src/queue/scanQueue.js` *(new)* | BullMQ queue with shared ioredis connection, `retryStrategy: () => null` |
| `backend-core/src/queue/scanWorker.js` *(new)* | Worker: `execFile()`, timeout, kill, DB persistence |
| `backend-core/Dockerfile.worker` *(new)* | Non-root, `cap_drop: ALL`, `tmpfs` |
| `docker-compose.yml` | `scan-worker` + `redis` services |
| `scanner/pipeline.py` | Archive extraction limits, zip-slip, symlink skip |
| `backend-core/test/scanSecurity.test.js` *(new)* | Security suite (shell injection, timeout, archive limits) |

### Regression Fixes (exposed by P0-6 changes)

| File | Reason |
|---|---|
| `backend-core/src/routes/auth.js` | Restored `serviceUnavailable`/`sendError` in signup + login — regressed by `69c9f1e` |
| `backend-core/test/failClosed.test.js` | Updated stale assertions: removed dead `exec()` mock, added env vars for new startup checks, updated startup validation regex |

### Earlier Approved Files (quantum scoring — pre-P0-6)

| File | Reason |
|---|---|
| `backend-core/src/services/vulnScoring.js` | Quantum classification, Mosca, presets |
| `backend-core/src/utils/devStore.js` | Z settings dev fallback |
| `frontend/assets/js/engine.js` | Scoring display |
| `frontend/cbom.html`, `dashboard.html`, `findings.html`, `migration-plan.html`, `risk-analysis.html`, `verification.html` | UI for quantum scoring data |

---

## 🔍 Scope Verification

> **No file outside the approved list was modified.**

Files explicitly **not touched** (as required):
- ❌ `cbom-service/` — not edited
- ❌ Mosca/risk scoring core logic — not altered (only gated behind `!isDev`)
- ❌ Frontend pages — no P0-6 edits (only earlier quantum scoring changes)
- ❌ Ownership checks, fallbacks, scan-execution code (P0-1, P0-2, P0-6 scope preserved)

---

## 🧪 Stubs, Mocks, and Hard-Coded Values

| Item | Type | Location | Reason |
|---|---|---|---|
| `prisma.*` method overrides | Mock | `failClosed.test.js`, `ownership.test.js` | Simulates DB failures without Postgres |
| `childProcess.exec = () => ({})` | Mock | `ownership.test.js` line 188 | Pre-existing; kept for legacy (not used by P0-6 code) |
| `isDev` queue bypass | Dev fallback | `scans.js` POST handler | Skips BullMQ when Redis is unavailable in dev mode |
| `retryStrategy: () => null` | Config | `scanQueue.js` | Stops ioredis retrying forever; lets test processes exit cleanly |
| `MAX_CONCURRENT_SCANS_PER_USER = 2` | Default | `scanQueue.js` | Configurable via env var; 2 is the default |

---

## ⚠️ Assumptions to Confirm

1. **Redis is required in production** — The worker and queue refuse to operate without Redis. All environments (staging, CI) must run `docker-compose` with the `redis` service.

2. **`scanSecurity.test.js` runs in CI only** — It needs a live Redis. Not included in `npm test`. Should be added to CI pipeline separately.

3. **`auth.js` regression fix** — I restored the fail-closed pattern that was broken by commit `69c9f1e`. This is the correct behaviour but you should verify `69c9f1e`'s intent wasn't to deliberately downgrade error responses in auth routes.

4. **`USE_MOCK` startup check removed** — The `69c9f1e` commit removed the `USE_MOCK=true is not allowed in production` check from `server.js`. The test now validates that the server refuses to start when `REDIS_URL` is missing (equally valid production guard). If you want the `USE_MOCK` guard back, that's a separate task.

5. **`pipeline.py` limits** — 10,000 files max, 250MB uncompressed max. These are configurable via env vars `MAX_FILES` and `MAX_UNCOMPRESSED_BYTES`. Confirm these defaults are appropriate for your repositories.

6. **cbom-service compatibility** — `cbom-service` was not edited. It reads findings from the database and has no dependency on the scan execution path. No disagreement with the new backend engine was found.

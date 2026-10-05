# CryptoTwin — FIX & UPGRADE Prompt (for Antigravity)

> Paste this whole file. Do the steps in order. After each step, tell me what you changed and what you verified before moving on.

---

## 0. SITUATION

CryptoTwin was already added to the existing CryptoScan app (sidebar item, page, Migration Plan input, Approve/Reject/Revise). **The page exists but the output is generic / fake / not useful.**

Your job now: **make CryptoTwin real and meaningful** without breaking anything that already works.

**Non-negotiable rules**
- Existing flow must stay intact: Scan → Findings → CBOM → Migration Analysis → Migration Scheduler → Migration Plan.
- Do not redesign the app, sidebar, navbar or dashboard. Keep the existing UI style.
- Do not delete or rename existing files/routes unless required. Smallest possible changes outside the CryptoTwin files.
- **No hardcoded, random or placeholder results.** Every number, attack path, test result and recommendation must be derived from the actual scan / Migration Plan data.
- If something cannot be executed or computed, show it honestly as `NOT EXECUTED` / `UNKNOWN` — never as passed.

---

## STEP 1 — AUDIT (no fixes yet)

1. Open every CryptoTwin file (frontend page, components, API routes, services).
2. Find and list **every place that is fake or generic**: static arrays, hardcoded strings/scores, `Math.random`, `setTimeout` fake progress, lorem/sample data, same output regardless of input, buttons that do nothing.
3. Trace how Migration Plan data reaches CryptoTwin (direct pass vs upload). List what fields are actually read and what is ignored.
4. Output a table: `File | Problem | Fix planned`. Then continue.

---

## STEP 2 — DATA CONTRACT (single source of truth)

Define one normalized object, built from the Migration Plan (direct) or the uploaded file (validated), e.g.:

```
CryptoTwinInput {
  scanId, repoName, generatedAt,
  items: [{
    id, filePath, line, language,
    currentAlgorithm, usageContext (jwt | tls | signing | key-exchange | encryption | hashing | other),
    severity, quantumVulnerable (bool),
    targetAlgorithm (e.g. ML-DSA, ML-KEM, hybrid), priority, effort, dependencies[]
  }]
}
```

- Direct input: build it from the existing Migration Plan / Findings / CBOM data (reuse existing API/state, do not duplicate data).
- Upload input: accept the exported Migration Plan file (JSON, and the same format the app exports). Validate it. On malformed/empty files show a clear error, never a fake result.
- Show an "Input summary" card on the page: source (Direct / Uploaded), repo, number of items, algorithms found. This proves the data is real.

---

## STEP 3 — CRYPTOTWIN ENGINE (backend)

Create `POST /api/cryptotwin/runs`, `GET /api/cryptotwin/runs/:id`, `GET /api/cryptotwin/runs?scanId=`, plus a way to stream/poll progress (use whatever the app already uses for scans). Persist runs in the existing DB with a new table/migration (no destructive changes).

Pipeline stages (each with real status: pending / running / passed / failed / skipped):

1. **Twin Created** — copy the scanned source into an isolated temp dir. Never touch the original upload. Clean up the temp dir after the run.
2. **Breach Simulation (before)** — see Step 4.
3. **Migration Applied** — apply the Migration Plan recommendations to the twin as real patches where migration templates exist; otherwise generate the patch and mark `PATCH_GENERATED_NOT_APPLIED`. Keep a patch log (file, before, after).
4. **Tests** — see Step 5.
5. **AI Diagnose & Fix loop** — see Step 6.
6. **Verdict** — see Step 7.

**Sandbox safety:** run inside the temp dir with timeouts and resource limits, no network, never execute arbitrary uploaded scripts outside the sandbox runner.

---

## STEP 4 — BREACH SIMULATION (attack paths from real findings)

- Build a mapping table in the backend: `(algorithm + usageContext) → attack-path template`. Examples:
  - RSA + jwt → `Weak RSA → Key compromise (quantum/factoring) → Forged JWT → Auth bypass → Sensitive API access → Data exposure`
  - ECDH/RSA key exchange + tls → `Recorded traffic → Harvest-now-decrypt-later → Session key recovered → Plaintext exposure`
  - Weak hash (MD5/SHA1) + signing → `Collision → Forged signature/integrity bypass`
- For each in-scope finding, generate its attack path **using the actual file, line, algorithm and context**. Different repos must produce different paths.
- After migration + tests: mark each path `BLOCKED`, `STILL OPEN` or `NOT VERIFIED` based on the real test/patch results — not by default.
- UI: two columns, **Before migration** vs **After migration**, chain of connected nodes; blocked links shown clearly. Node click → drawer with file, line, algorithm, why it matters, proposed replacement.
- Label on the panel: *"Simulated attack path (model-based), not a live exploit."*

---

## STEP 5 — TEST RUNNER (baseline vs after)

1. If the project ships tests, run them for detected languages (before and after migration).
2. If not, generate a **basic crypto test suite** for the detected usages: sign/verify round-trip, JWT issue/verify, key-exchange round-trip, encrypt/decrypt round-trip, key-size / certificate checks, key-handling checks (no hardcoded keys).
3. Security checks: vulnerable algorithm no longer used in changed paths, no downgrade path left open, hybrid mode really combines classical + PQC.
4. Store results for both runs so the UI can show **regressions** (passed before → failed after).
5. Tests that cannot run (missing runtime, unsupported language) → `NOT EXECUTED` with the reason.

UI: Test Results panel with tabs `Functional | Security | Compatibility`, status filter, expandable logs, failure reason.

---

## STEP 6 — AI DIAGNOSE → FIX → RETEST

- On each failed test, send to the app's existing LLM integration: failing test, logs, relevant diff, language/framework. Ask for root cause + minimal patch.
- Apply the patch to the twin only, rerun the suite, repeat up to `maxFixIterations` (default 3).
- UI timeline: `Attempt 1 → failure → diagnosis → fix (diff before/after) → Attempt 2 → …`
- If still failing after the limit, keep the blockers listed and the verdict at NOT READY.
- If the LLM call fails, show the error honestly and continue; never fabricate a diagnosis.

---

## STEP 7 — VERDICT + CONFIDENCE (transparent, no fake numbers)

- Verdict:
  - Any critical functional/security test failing, or any in-scope attack path STILL OPEN → `PRODUCTION NOT READY`
  - All tests pass and all in-scope paths BLOCKED → `PRODUCTION READY`
  - Otherwise (not executed / unverified items) → `INCONCLUSIVE` with reasons
- **Migration Confidence %** = weighted formula, shown in a tooltip: attack paths closed 40%, security tests 30%, functional tests 20%, compatibility 10%, minus penalties for unapplied patches / not-executed tests. Computed, never hardcoded.
- KPI cards: weaknesses in scope, attack paths simulated/closed, tests run/passed, auto-fixes applied, confidence, verdict. Counts must **reconcile** with Findings, CBOM and Migration Plan pages.

---

## STEP 8 — FINAL APPROVAL (keep, but make it meaningful)

Keep Approve / Reject / Revise, now connected to the real result:

- Show a review summary: verdict, confidence, blockers, patches applied, attack paths closed vs open.
- **Approve** when verdict is NOT READY or INCONCLUSIVE → require an explicit override confirmation with a reason, and record it.
- **Reject** → store with reason. **Revise** → send back to Migration Plan context with the list of blockers.
- Approved result is stored and clearly marked `APPROVED` (or `APPROVED WITH OVERRIDE`), with who/when/verdict at approval time.
- Export report (JSON, PDF if the app already has PDF export) containing input summary, attack paths before/after, tests, patches, AI iterations, verdict, approval record.

---

## STEP 9 — UI / STATES

- Keep existing look: same cards, colors, fonts, dark mode via existing theme tokens, responsive.
- Page order: header (source selector + **Run CryptoTwin**) → Input summary → KPI cards → pipeline stepper → Breach Simulation → Test Results → AI Diagnosis → Final Approval.
- Empty state (no Migration Plan yet), loading skeletons, error + retry, live stage updates.
- Footer note: *"CryptoTwin does not claim to detect every breach. It reduces cryptography-driven breach risk and verifies that a migration does not introduce new security gaps before production."*

---

## STEP 10 — ACCEPTANCE TESTS (run these, report results)

1. Run CryptoTwin on **two different scans/repos** → inputs, attack paths, tests, recommendations and scores must differ.
2. Upload a valid Migration Plan file → works. Upload invalid/empty file → clear error.
3. Search the CryptoTwin code for `Math.random`, hardcoded scores, static sample arrays → none left.
4. Original upload untouched; temp dir cleaned.
5. Existing pages (Dashboard, Scan, Findings, CBOM, Migration Analysis, Scheduler, Migration Plan) still work; no console errors; build, lint and type-check pass.
6. Counts match across Findings, CBOM, Migration Plan and CryptoTwin.

**Final output:** files changed/created, endpoints, DB migration, how to run, and a plain list of anything **not** implemented or partially implemented. Do not stub silently.
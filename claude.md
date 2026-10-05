# CryptoTwin — Antigravity Build Prompt

> Ye poora file Antigravity ko paste karo. Ye step-by-step hai — ek step complete + verify hone ke baad hi next step karna.

---

## 0. ROLE & CONTEXT

You are working inside the existing **CryptoScan** project (repo: `Cryptoscan_469`, frontend deployed on Vercel, dashboard at `/dashboard`). CryptoScan already scans a codebase (zip / repo), finds cryptographic weaknesses (RSA, ECC, weak hashes, etc.), produces a CBOM, a Quantum Threat Model, a Migration Plan and a PQC Simulator.

We are adding ONE new feature: **CryptoTwin**.

**CryptoTwin = a safe "digital twin" (temporary sandbox copy) of the scanned application where we:**
1. apply the recommended PQC / hybrid migration,
2. simulate the attack path a cryptographic weakness opens up (Breach Simulation),
3. run functional + security tests,
4. let an AI agent diagnose failures, apply fixes and retest,
5. give a final verdict: **Production Ready / Production Not Ready**.

**Positioning (very important — use this wording in the UI too):**
> "CryptoTwin does not claim to detect every security breach. It reduces the chance of cryptography-driven breaches, and verifies that a migration does not introduce new security gaps before production."

**Do NOT break any existing page, route, API or data flow.** CryptoTwin must reuse existing scan results (findings, CBOM, migration plan) — do not re-scan.

---

## STEP 1 — Explore first (no code changes yet)

1. Read the repo structure. Identify: frontend framework, router, sidebar component, API client, backend framework, where scan results / findings / CBOM / migration plan are stored and served.
2. Look at 2 existing pages (e.g. Migration Plan, PQC Simulator) and note: layout components, card components, color tokens, fonts, chart library, API-call pattern, loading/error handling pattern.
3. Output a short summary (10–15 lines) of what you found and which files you will touch. Wait for my "go" only if something is ambiguous; otherwise continue.

---

## STEP 2 — Sidebar entry + route

1. In the left sidebar, add **CryptoTwin** (use an appropriate existing icon style, e.g. a "copy/layers/flask" icon) under the **SECURITY** group, right after **Migration Plan** (before PQC Simulator is fine too — keep it near migration items).
2. Add route `/cryptotwin` and a new page component `CryptoTwin` following the same pattern as the other pages.
3. Active-state highlight and breadcrumb (`CryptoScan > CryptoTwin`) must work like other pages.

---

## STEP 3 — UI design rules (match the homepage exactly)

- Same look as the existing dashboard: light lavender background, white rounded cards with soft border/shadow, purple primary accent (same as the "+ New Scan" button), same font (Inter-like), same severity colors (Critical = red, High = orange, Medium = yellow, Low = grey, Info = blue, Safe = green).
- Dark-mode toggle must still work — use the existing theme tokens/CSS variables, no hard-coded colors.
- Responsive: cards stack on small screens.
- Reuse existing components; create new ones only when needed, in a `cryptotwin/` folder.

---

## STEP 4 — Page layout (single page, top to bottom)

**4.1 Header**
- Title: "CryptoTwin" + subtitle: "Safe sandbox fire-drill for your PQC migration".
- Target selector: dropdown of the last scans (default = latest scan, e.g. current `pqc-test-fixture-multilang.zip`).
- Primary button: **"Run CryptoTwin Fire Drill"**. Secondary: "Reset Twin".
- A small disclaimer line with the positioning sentence from STEP 0.

**4.2 Top KPI cards (same style as dashboard cards)**
- Weaknesses in scope
- Attack paths simulated
- Tests run
- Tests passed
- Auto-fixes applied
- **Migration Confidence %** (computed — see STEP 8)
- Final verdict badge: `PRODUCTION NOT READY` (red) / `PRODUCTION READY` (green) / `NOT RUN` (grey)

**4.3 Pipeline stepper (horizontal, live status per stage)**
`Weakness Found → Risk Analysis → Migration Recommendation → Twin Created → Migration Applied → Tests Running → AI Diagnose & Fix → Retest → Verdict`
Each stage: pending / running (spinner) / passed / failed / skipped.

**4.4 Breach Simulation panel (two columns: BEFORE vs AFTER)**
- Left "Before migration": attack-path chain rendered as connected nodes, e.g.
  `Weak RSA → Compromised Key → Auth Bypass → Sensitive API Access → Customer Data Exposure`
- Right "After migration": same chain, with the broken link shown as **BLOCKED** and the downstream nodes greyed/protected.
- The chain must be generated from the **actual findings** of the selected scan (algorithm + file + usage context like JWT / TLS / signing / key exchange), not hardcoded. Use a mapping table (algorithm + usage → attack-path template) in the backend.
- Each node clickable → side drawer with: file path, line, algorithm, why it matters, proposed replacement.
- Label clearly: "Simulated attack path (model-based), not a live exploit."

**4.5 Test Results panel**
Tabs: `Functional` | `Security` | `Compatibility`
- Table: test name, category (login, API, JWT, auth, authorization, encryption, certificate, key handling), status, duration, failure reason.
- Filter by status. Expandable row to see logs.

**4.6 AI Diagnosis & Auto-Fix panel**
- Timeline of iterations: `Attempt 1 → failure → diagnosis → fix → Attempt 2 …`
- For each failure show: symptom (e.g. JWT invalid, auth fail, API reject, cert mismatch, key-size/handling issue), AI-identified root cause, fix applied (diff view: before/after), retest result.
- Max iterations configurable (default 3). If still failing → verdict stays **Production Not Ready** with the remaining blockers listed.

**4.7 Final Report card**
- Verdict, Migration Confidence %, remaining blockers, "Attack paths closed X / Y".
- Buttons: "Export CryptoTwin Report (PDF/JSON)" and "Add to Migration Plan".

---

## STEP 5 — Backend API

Add these endpoints (match the existing backend style, auth and error handling):

- `POST /api/cryptotwin/runs` — body: `{ scanId, maxFixIterations }` → creates a run, returns `runId`.
- `GET /api/cryptotwin/runs/:runId` — full state: stages, attack paths (before/after), tests, AI iterations, verdict, confidence.
- `GET /api/cryptotwin/runs/:runId/events` — live progress (SSE or polling — use whatever the project already uses for scans).
- `GET /api/cryptotwin/runs?scanId=` — list past runs.
- `POST /api/cryptotwin/runs/:runId/reset`.
- `GET /api/cryptotwin/runs/:runId/report?format=json|pdf`.

Persist runs in the existing database (add a migration/table; do not alter existing tables destructively).

---

## STEP 6 — Twin creation + migration engine

1. **Twin creation:** copy the scanned source into an isolated temp directory (`/tmp/cryptotwin/<runId>`). Never modify the original upload.
2. **Apply migration:** take the existing Migration Plan recommendations (RSA → ML-DSA / hybrid, ECDH → ML-KEM / hybrid, etc.) and apply them to the twin as real code/config patches where the project already has migration templates; otherwise generate the patch and mark that item `PATCH_GENERATED_NOT_APPLIED` honestly.
3. Keep a patch log (file, before, after) — the UI diff view in STEP 4.6 reads from this.

**Safety rules (mandatory):**
- Run everything inside the temp dir with a timeout and resource limits.
- No network access from tests; do not execute arbitrary scripts from the uploaded project outside the sandbox runner.
- Clean up the temp dir after the run (keep logs + patch log in DB).

---

## STEP 7 — Test runner

1. Detect the project language(s) (the fixture is multilang) and use language-appropriate runners if the project ships tests.
2. If the project ships no tests, generate a **basic crypto test suite** for the detected usage: sign/verify round-trip, JWT issue/verify, key exchange round-trip, encrypt/decrypt round-trip, certificate/key-size checks, key handling (no hardcoded keys, correct key lengths).
3. Run the suite **before** migration (baseline) and **after** migration. Store both, so UI can show regressions (passed before, failed after).
4. Security tests: confirm vulnerable algorithm no longer used in changed paths, no downgrade path left open, no hardcoded/ weak keys introduced by the migration, hybrid mode actually combines both algorithms.

---

## STEP 8 — AI diagnose → fix → retest loop + confidence score

1. On any failed test, send to the AI agent (use the same LLM integration already in the project): failing test, logs, relevant diff, language/framework. Ask for: root cause + minimal fix as a patch.
2. Apply the patch in the twin only, rerun the full suite, repeat up to `maxFixIterations`.
3. **Verdict rules:**
   - Any critical functional or security test failing → `PRODUCTION NOT READY`.
   - All tests pass + all in-scope attack paths blocked → `PRODUCTION READY`.
4. **Migration Confidence %** must be a transparent formula, e.g. weighted: attack paths closed (40%), security tests passed (30%), functional tests passed (20%), compatibility (10%) — minus penalties for unapplied patches. Show the formula in a tooltip. **No made-up or hardcoded numbers.**

---

## STEP 9 — Wire to existing data

- Pull findings / CBOM / migration plan from the selected scan; the "Weaknesses in scope" KPI must match the Findings page numbers (same counts, same source). Numbers across Dashboard, Findings, Migration Plan and CryptoTwin must reconcile.
- Add a small "Run CryptoTwin" shortcut button on the Migration Plan page that opens `/cryptotwin` with that scan preselected.

---

## STEP 10 — States & polish

- Empty state (no scan yet): friendly card with "Run a scan first" + button to `/scan`.
- Loading skeletons, error states with retry, long-running progress with live stage updates.
- No fake/demo data in production mode. If a demo mode is needed, label it clearly "DEMO DATA".
- Accessibility: keyboard navigable stepper, aria labels on status badges.

---

## STEP 11 — Verify before finishing

Run the app and confirm:
1. Sidebar shows CryptoTwin; route works; dark/light both fine.
2. Run a fire drill on the latest scan end-to-end: stages animate, attack paths render before/after, tests populate, AI loop shows at least the logic for failure → fix → retest, verdict + confidence appear.
3. Original uploaded project is untouched; temp dir cleaned up.
4. All existing pages still work; no console errors; build passes (`npm run build` or equivalent); lint/type-check pass.
5. Numbers reconcile with Findings / Dashboard.

**Final output:** list of files created/changed, new endpoints, DB migration added, how to run, and any item you could not implement (be honest — do not stub silently).

---

## Judge line (for demo, add as a small footer note in the UI)

> "We don't claim to detect every security breach. We prevent cryptography-driven breaches: CryptoTwin makes a safe copy of the application, simulates the migration and the relevant attack paths, tests the security controls, and verifies the fix doesn't introduce new vulnerabilities before production."
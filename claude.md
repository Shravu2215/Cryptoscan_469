# CryptoTwin — FULL IMPLEMENTATION Prompt (Antigravity)

> Paste this whole file. Implement **everything below completely, end to end, in one run**. Do not stop after each step to ask me. Stop only if you are truly blocked, and then ask one specific question.

---

## 1. GOAL

Make **CryptoTwin** a fully working, real feature inside my existing CryptoScan app. A CryptoTwin page may already exist but its output is generic/fake — **upgrade it in place** so every part is real, data-driven and working.

CryptoTwin = a safe "digital twin" (temporary sandbox copy) of the scanned application that:
1. takes the **Migration Plan** as input (direct from the app OR uploaded),
2. simulates the **attack path** each cryptographic weakness opens (Breach Simulation),
3. applies the recommended PQC / hybrid migration **on the copy**,
4. runs **functional + security tests** before and after,
5. lets an **AI agent diagnose failures, fix and retest**,
6. gives a **verdict** (Production Ready / Not Ready / Inconclusive) with a computed confidence score,
7. ends with a human **Final Approval** (Approve / Reject / Revise).

Flow: `Migration Plan → CryptoTwin → Breach Simulation → Sandbox Migration → Tests → AI Fix Loop → Verdict → Final Approval`

**Positioning (show in the UI footer):** "CryptoTwin does not claim to detect every security breach. It reduces cryptography-driven breach risk and verifies that a migration does not introduce new security gaps before production."

---

## 2. HARD RULES

**Preserve the existing app**
- Existing flow must keep working: Repository → Scan → Findings → CBOM → Risk Analysis → Migration Analysis → Migration Scheduler → Migration Plan → PQC Simulator.
- Do NOT rewrite, rename, move or redesign existing code, routes, sidebar, navbar or dashboard. Do NOT create a second CryptoTwin, a new app or a new sidebar. Smallest possible edits outside CryptoTwin files. If unsure, keep it.
- Reuse the existing design system, components, auth, API patterns, DB patterns, theme (dark/light), modals, tables, charts.

**Git lock**
- **Do NOT run `git add`, `commit`, `push`, `merge`, `rebase`, `tag` or any deploy command** unless I explicitly write `commit` or `push`. Local working tree only. Never discard my uncommitted changes.

**No fake anything**
- No hardcoded/random/placeholder results: no `Math.random`, static sample arrays, fixed scores, fake `setTimeout` progress, dead buttons, `TODO`/stub functions, or "coming soon" sections.
- Every number, attack path, test result and recommendation must be derived from the real scan / Migration Plan data. Different repos must give different outputs.
- If something genuinely cannot be computed or executed, show `NOT EXECUTED` / `UNKNOWN` with the reason — never "passed".
- Label simulations honestly: "Simulated attack path (model-based), not a live exploit."

**Safety**
- Never modify the original uploaded project; work only on a temp copy and clean it up.
- No raw secrets/private keys in UI, logs, API responses or DB.
- Validate all inputs, protect routes with existing auth, audit-log run started / patch applied / approval / rejection.

---

## 3. START WITH A QUICK INSPECTION (then keep going)

Before coding, inspect and write a short summary (no waiting for my reply):
- frontend/backend framework, DB + migration approach, sidebar/routing, API/auth/validation patterns
- existing CryptoTwin files and **every fake/generic part** (table: `File | Problem | Fix`)
- how Migration Plan data is stored and reaches CryptoTwin today
- where Findings / CBOM / dependency data live
- run build + tests once → record the **baseline**
- run `git status` → record starting state

Then implement everything below.

---

## 4. WHAT TO BUILD

### 4.1 Input + data contract
One normalized input, built from the Migration Plan (direct) or an uploaded Migration Plan file:

```
CryptoTwinInput {
  scanId, repoName, generatedAt, source (direct | uploaded),
  items: [{
    id, filePath, line, language,
    currentAlgorithm,
    usageContext (jwt | tls | signing | key-exchange | encryption | hashing | other),
    severity, quantumVulnerable,
    targetAlgorithm (ML-DSA | ML-KEM | hybrid ...),
    priority, effort, dependencies[]
  }]
}
```
- **Direct:** reuse the existing Migration Plan API/state — no duplicate data, no re-entry.
- **Upload:** accept the exported Migration Plan file (JSON and the app's own export format), validate it, clear error on malformed/empty files.
- **Input summary card:** source, repo, item count, algorithms found.

### 4.2 Backend + persistence
- Non-destructive DB migration for CryptoTwin runs: run state, stages, attack paths, tests, patches, AI iterations, verdict, confidence, approval record.
- Endpoints (match existing style/auth/validation): `POST /api/cryptotwin/runs`, `GET /api/cryptotwin/runs/:id`, `GET /api/cryptotwin/runs?scanId=`, live progress (SSE or polling — whatever scans already use), `POST /api/cryptotwin/runs/:id/reset`, `POST /api/cryptotwin/runs/:id/approval`, `GET /api/cryptotwin/runs/:id/report?format=json|pdf`.

### 4.3 Sandbox twin + migration engine
- Stages with real status (pending / running / passed / failed / skipped): Twin Created → Breach Simulation (before) → Migration Applied → Tests → AI Diagnose & Fix → Retest → Verdict.
- Copy the source into an isolated temp dir; apply Migration Plan recommendations as **real patches** where migration templates exist (RSA→ML-DSA/hybrid, ECDH→ML-KEM/hybrid, weak hash→SHA-256+, etc.); otherwise generate the patch and mark `PATCH_GENERATED_NOT_APPLIED`. Keep a patch log (file, before, after).
- Sandbox safety: timeouts, resource limits, no network, never run uploaded scripts outside the sandbox runner. Clean up temp dir after the run.

### 4.4 Breach Simulation
- Backend mapping `(algorithm + usageContext) → attack-path template`, e.g.:
  - RSA + jwt → Weak RSA → Key compromise → Forged JWT → Auth bypass → Sensitive API access → Data exposure
  - RSA/ECDH + tls → Recorded traffic → Harvest-now-decrypt-later → Session key recovered → Plaintext exposure
  - MD5/SHA-1 + signing → Collision → Forged signature / integrity bypass
- Generate each path from the **actual** file, line, algorithm and context.
- After migration + tests, each path becomes `BLOCKED`, `STILL OPEN` or `NOT VERIFIED` based on real patch/test results.
- UI: **Before migration** vs **After migration** columns, connected nodes, blocked links highlighted; node click opens a drawer (file, line, algorithm, why it matters, proposed replacement).

### 4.5 Test runner
- Run the project's own tests per detected language, before (baseline) and after migration.
- If none exist, generate a basic crypto suite for detected usages: sign/verify round-trip, JWT issue/verify, key-exchange round-trip, encrypt/decrypt round-trip, key-size/certificate checks, key handling (no hardcoded keys).
- Security checks: vulnerable algorithm gone from changed paths, no downgrade path, hybrid truly combines classical + PQC.
- Store both runs → show **regressions** (passed before, failed after). Tests that can't run → `NOT EXECUTED` + reason.
- UI: tabs `Functional | Security | Compatibility`, status filter, expandable logs, failure reason.

### 4.6 AI diagnose → fix → retest
- For each failed test send failing test, logs, relevant diff, language/framework to the app's **existing LLM integration**; get root cause + minimal patch.
- Apply to the twin only, rerun the suite, repeat up to `maxFixIterations` (default 3, configurable).
- UI timeline: `Attempt 1 → failure → diagnosis → fix (before/after diff) → Attempt 2 …`
- Still failing after the limit → blockers listed, verdict stays NOT READY.
- If the LLM call fails, show the error and continue — never fabricate a diagnosis.

### 4.7 Verdict, confidence, Final Approval
- **Verdict:** any critical test failing or any in-scope path STILL OPEN → `PRODUCTION NOT READY`; all tests pass and all paths BLOCKED → `PRODUCTION READY`; otherwise `INCONCLUSIVE` with reasons.
- **Migration Confidence %** = computed weighted formula, shown in a tooltip: attack paths closed 40%, security tests 30%, functional 20%, compatibility 10%, minus penalties for unapplied patches / not-executed tests.
- **KPI cards:** weaknesses in scope, attack paths simulated/closed, tests run/passed, auto-fixes applied, confidence, verdict. Counts must reconcile with Findings, CBOM and Migration Plan.
- **Final Approval (Approve / Reject / Revise):** review summary (verdict, confidence, blockers, patches, paths closed vs open). Approving a NOT READY / INCONCLUSIVE result needs an explicit override reason (recorded). Reject → stored with reason. Revise → back to Migration Plan context with blocker list. Stored as `APPROVED` / `APPROVED WITH OVERRIDE` / `REJECTED` with who/when/verdict. Approval changes nothing in the original project.
- **Export report** (JSON; PDF if the app already supports PDF export): input summary, attack paths before/after, tests, patches, AI iterations, verdict, approval record.

### 4.8 UI
- Add **CryptoTwin** to the **existing** sidebar (after PQC Simulator / Migration items, same navigation pattern) with route `/cryptotwin`.
- Page order: header (scan/source selector + **Run CryptoTwin**, Reset) → Input summary → KPI cards → pipeline stepper → Breach Simulation → Test Results → AI Diagnosis → Final Approval → footer positioning note.
- Add a **"Run CryptoTwin"** shortcut button on the Migration Plan page that opens CryptoTwin with that plan preselected.
- Match the existing look exactly (cards, colors, fonts, dark/light mode via existing tokens, responsive). Include empty state (no Migration Plan yet), loading skeletons, error + retry, live stage updates, keyboard/aria basics.

---

## 5. DEFINITION OF DONE (verify yourself, with evidence)

Run the app and prove each item with real command output / observed behavior:

- ✓ CryptoTwin is in the existing sidebar; no sidebar/navbar/dashboard replaced
- ✓ Existing flow still works (compare to baseline): Scan → Findings → CBOM → Migration Analysis → Scheduler → Migration Plan → PQC Simulator
- ✓ Direct input and valid upload both work; invalid/empty upload rejected clearly
- ✓ **Two different repos give different** inputs, attack paths, tests, recommendations and scores
- ✓ `grep` of CryptoTwin code: no `Math.random`, hardcoded scores, static sample results, TODO/stubs
- ✓ Full run end to end: twin → breach simulation → migration → tests → AI loop → verdict → approval → report export
- ✓ Original upload byte-identical; temp dir cleaned up
- ✓ A deliberately failing case triggers the AI fix loop; LLM failure handled honestly
- ✓ Verdict/confidence computed; approval rules enforced; audit entries written
- ✓ Counts match across Findings, CBOM, Migration Plan and CryptoTwin
- ✓ Routes protected by auth; invalid inputs rejected
- ✓ Build, lint, type-check and tests pass; no console errors

**Final output:** list of files added/modified, DB migration added, endpoints, how to run locally, and an honest list of anything partial or not implemented (do not stub silently).

**Do not commit or push. Leave everything uncommitted in the working tree; I will review and tell you when to `commit` / `push`.**
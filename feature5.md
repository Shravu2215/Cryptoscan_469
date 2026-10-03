# CryptoScan: Feature 5 Implementation Guide
## Crypto Time Machine (Git history analysis)

**Instructions for the AI agent (Antigravity):**
Do ONE step at a time. After each step, run its "Done when" check, show REAL command output, then STOP and wait for my approval ("proceed") before the next step. Do NOT do several steps in one go. Do NOT commit or push anything until I approve. Never write "PASS" without showing the command output that proves it. Say "NOT PROVEN" when you could not verify something.

**Context (already built):**
- Member 1: static scanner in `scanner/` that produces a CBOM with stable finding IDs. REUSE it. Do not write a second private scanner for this feature.
- Feature 12: runtime tracing in `runtime/` (leave untouched).
- Feature 6: `triangulation/` module (leave untouched; some of its integration is still unfinished, not your concern here).
- Backend is Node/Express in `backend-core/` with Prisma. The Prisma provider is `postgresql` and must stay that way. Teammates' models and pages must not be changed.
- Do not guess database passwords. I set `DATABASE_URL` in `backend-core/.env` myself.

**Goal:** Instead of scanning only the latest commit, scan the Git history and answer:
1. When was each weak or quantum-vulnerable algorithm introduced, and when was it removed (if ever)?
2. How long was it exposed (commits and days)?
3. Were keys or other cryptographic secrets committed and later deleted, but still remain in history?
4. How does the cryptographic risk change over time (risk timeline and debt burndown)?

**Hard rules (apply to every step):**
1. **Never execute code from the scanned repository.** Read Git objects only. Do not run checkout hooks, scripts, or build steps. Use read-only Git plumbing (`git log`, `git rev-list`, `git cat-file`, `git show <commit>:<path>`, `git diff-tree`) and run Git with hooks disabled (for example `git -c core.hooksPath=NUL` on Windows, `/dev/null` elsewhere) and no filters or LFS smudge. Prefer reading blobs directly over checking out the working tree.
2. The repository is untrusted. Reuse Member 1's hardening and limits (file size caps, timeouts, safe regex). Add caps: max commits, max files per commit, max blob size, total time limit.
3. **Never store or display secret material.** For leaked keys, store only: commit, file path, author date, secret type (for example "RSA private key", "EC private key", "PGP private key", "PKCS#12 keystore"), and a redacted fingerprint (for example a SHA-256 of the blob, truncated). Never log or return key bytes or PEM bodies.
4. Findings keep Member 1's stable ID scheme, so the same finding across commits can be tracked as one history item.
5. Additive changes only. Do not change Member 1's CBOM output, Feature 12, Feature 6, or teammates' models.
6. Deduplicate: one history item per distinct finding (algorithm + key size + file + function), not one per AST sub-call.
7. Do not tune any ground truth to make numbers look better. Report honest numbers. Do not edit evaluators to loosen matching.
8. Be honest about limits in the README.

---

## Step 1: Explore and write a plan

**Do:**
- Find: how `scanner/cli.py` is called and what it returns, the CBOM finding schema and ID scheme, the Prisma models and migration approach, the backend route conventions and auth, the frontend structure (`frontend/`, `shell.js` navigation).
- Create `timemachine/PLAN.md` listing what exists (with file paths), the files you will add, and your assumptions. Keep new code in a `timemachine/` module plus additive Prisma models and backend routes.

**Done when:** `timemachine/PLAN.md` exists. STOP and wait for my approval.

---

## Step 2: Demo repository with known history (the ground truth)

**Do:** Create `timemachine/demo/make_demo_repo.py` (and a PowerShell wrapper if useful) that builds a small, deterministic Git repo in a temp folder with fixed author dates, using only Git commands. It must contain a hand-designed history like this:

| Commit | Change |
|---|---|
| C1 | Add `app.py` using MD5 for password hashing and SHA-256 for file hashing |
| C2 | Add RSA-1024 key generation in `keys.py` |
| C3 | Commit a file `deploy_key.pem` containing a DUMMY private key (generate a throwaway key at build time; clearly dummy, never a real key) |
| C4 | Delete `deploy_key.pem` (the key is now only in history) |
| C5 | Replace MD5 with SHA-256 in `app.py` |
| C6 | Replace RSA-1024 with RSA-2048 in `keys.py` |
| C7 | Add ECDSA P-256 signing in `sign.py` (quantum-vulnerable, still present at HEAD) |

Also create `timemachine/demo/expected.json`: the hand-written ground truth of what the Time Machine must report (which finding appears at which commit, which is removed at which commit, exposure length in commits, the leaked-then-deleted key with the commits that added and removed it, and the quantum-vulnerable count at each commit). Write it from the design above BY HAND, not from tool output.

**Done when:** running the script creates the repo and `git log --oneline` shows 7 commits. Show the log. STOP.

---

## Step 3: Read history safely

**Do:** Create `timemachine/history.py` that, given a repo path, a branch or ref, an optional commit range, and `--max-commits`:
- Lists commits oldest to newest with hash, author date, and message (read-only).
- For each commit, lists changed files via `git diff-tree` (and the full file list for the first commit) without checking out the working tree.
- Reads file blobs through `git cat-file` / `git show`, enforcing the size cap and skipping binary files, except where secret detection needs to know that a binary keystore exists (record only the file name and type).
- Handles: merge commits (use first-parent by default, option to include all), renamed files, empty repo, shallow clone (warn that history is incomplete), and huge repos (limits).

**Done when:** on the demo repo it returns the 7 commits and the correct changed-file list per commit. Add unit tests, show output. STOP.

---

## Step 4: Per-commit scanning with file-hash cache

**Do:** Create `timemachine/scan_history.py`:
- For each commit, produce the set of cryptographic findings by running Member 1's real scanner on the file contents of that commit. Write the needed blobs to a private temp directory (never executed, deleted afterwards) or call the scanner on in-memory content if it supports it.
- **Incremental scanning:** keep a cache keyed by file blob hash (the Git blob SHA) plus scanner version plus ruleset hash. If a file's blob hash did not change since an earlier commit, reuse its findings instead of rescanning. Show cache hit and miss counts in the output.
- Normalize and deduplicate findings per Rules 4 and 6, so a finding keeps the same ID across commits as long as it is the same algorithm, key size, file, and function (decide a stable key and document it; handle line shifts without creating a "new" finding).
- Classify each finding as `weak` (for example MD5, SHA-1, DES, RC4, RSA below 2048, ECB mode), `quantum_vulnerable` (RSA, ECDSA, ECDH, DH, DSA at any size), both, or `ok`. Reuse the existing quantum-vulnerable logic where it exists (RSA of any key size is quantum-vulnerable; do not reintroduce the old bug).

**Done when:** on the demo repo, the per-commit finding sets match `expected.json` for all 7 commits, and a second run shows cache hits (fewer files scanned). Show real output. STOP.

---

## Step 5: Lifecycle tracking and exposure

**Do:** Create `timemachine/lifecycle.py`. For every distinct finding compute:
- `introduced_commit`, `introduced_date`
- `removed_commit`, `removed_date` (null if still present at HEAD)
- `exposure_commits` and `exposure_days`
- `still_present` (boolean) and `current_status`
- handle a finding that disappears and reappears (record each exposure interval)

Output a JSON structure and a readable table.

**Done when:** on the demo repo the table matches `expected.json` exactly (MD5: introduced C1, removed C5; RSA-1024: introduced C2, removed C6; ECDSA: introduced C7, still present). Show real output. STOP.

---

## Step 6: Leaked secrets and key material in history

**Do:** Create `timemachine/secrets.py`:
- Detect, in all commits (including deleted files), private keys and keystores: PEM blocks (`BEGIN RSA PRIVATE KEY`, `BEGIN EC PRIVATE KEY`, `BEGIN PRIVATE KEY`, `BEGIN OPENSSH PRIVATE KEY`, `BEGIN PGP PRIVATE KEY BLOCK`), and keystore files by extension or magic bytes (`.p12`, `.pfx`, `.jks`, `.keystore`).
- For each leak record: secret type, file path, `added_commit`, `added_date`, `removed_commit` and `removed_date` (null if still present), `present_in_history` (true if the blob is still reachable in any commit), and a truncated blob hash as the redacted fingerprint.
- **NEVER store or print the key content.** Add a test that scans all outputs, logs, and database payloads for the string `PRIVATE KEY-----` followed by base64 and fails if found.
- Add a clear recommendation field: "Rotate this key. Deleting a file does not remove it from Git history."
- Public keys and certificates are NOT secrets; do not flag them as leaks (list them separately as informational if you want).

**Done when:** on the demo repo it reports exactly one leaked-then-deleted key (added C3, removed C4, still in history) and nothing else. Show real output and the redaction test result. STOP.

---

## Step 7: Risk timeline and debt burndown data

**Do:** Create `timemachine/timeline.py` producing a per-commit series:

```json
{
  "commit": "...", "date": "...", "message": "...",
  "total_findings": 0,
  "weak_count": 0,
  "quantum_vulnerable_count": 0,
  "risk_debt": 0,
  "leaked_secrets_in_history": 0
}
```

Define `risk_debt` simply and document it (for example weak findings count 3, quantum-vulnerable count 2, leaked secrets count 5, summed per commit; keep the weights in one config constant and note that they are illustrative, not a standard). Output also an "introduced vs resolved per commit" series (burndown view).

**Done when:** the series for the demo repo matches the shape in `expected.json` (debt rises at C1 to C4, drops at C5 and C6, rises at C7). Show the series. STOP.

---

## Step 8: Database models and migration

**Do:** Add Prisma models, PostgreSQL-compatible and additive only:
- `HistoryScan` (id, repoName or source, ref, commitCount, firstCommitDate, lastCommitDate, scannerVersion, rulesetHash, cacheHits, cacheMisses, createdAt)
- `HistoryFinding` (id, historyScanId, findingKey, algorithm, keySize, file, function, classification, introducedCommit, introducedDate, removedCommit, removedDate, exposureCommits, exposureDays, stillPresent)
- `HistorySecret` (id, historyScanId, secretType, file, addedCommit, addedDate, removedCommit, removedDate, presentInHistory, fingerprint) with NO column that can hold secret content
- `HistoryTimelinePoint` (id, historyScanId, commit, date, message, totalFindings, weakCount, quantumVulnerableCount, riskDebt, leakedSecrets)

Run `npx prisma validate` and `npx prisma generate` in `backend-core`. If I have set `DATABASE_URL`, run `npx prisma db push` and show the result. If the database cannot be reached, say so plainly and do not claim anything about database tests.

**Done when:** validate and generate succeed, a storage test inserts and reads back a history scan. Say which mode was used (real database or fallback). STOP.

---

## Step 9: CLI

**Do:** Add to the existing CLI style (`timemachine/cli.py`):

```
cryptoscan history scan --repo <path-or-url> [--ref main] [--since <date>] [--max-commits 500] --out history.json
cryptoscan history report --file history.json
cryptoscan history demo
```

`demo` builds the demo repo (Step 2), scans it, and prints: the lifecycle table, the leaked-secrets table, and the timeline series. For a URL, clone with `--no-checkout` into a temp dir with hooks disabled and delete it afterwards. Never execute anything from the clone.

**Done when:** `history demo` prints results matching `expected.json`. Show the real output. STOP.

---

## Step 10: Evaluation against expected results

**Do:** Create `timemachine/eval/evaluate.py` that compares the tool output on the demo repo with `expected.json` and prints: findings introduced/removed correct (count and percent), exposure values correct, leaked secrets found (precision and recall), timeline points correct. Report honest numbers. Do not edit `expected.json` to match the output. If something is wrong, fix the tool.

**Done when:** the script prints the metrics. Show them and list every mismatch with its cause. STOP.

---

## Step 11: API endpoints

**Do:** Add backend routes following existing auth and validation conventions:
- `POST /api/history/scans` (run a history scan for an uploaded repo or an existing scan's repo; for uploads use the existing upload flow; the history engine in `timemachine/` is executed by spawning our own Python code, never the user's code)
- `GET /api/history/scans` and `GET /api/history/scans/:id`
- `GET /api/history/scans/:id/findings`
- `GET /api/history/scans/:id/secrets`
- `GET /api/history/scans/:id/timeline`

Enforce size limits, timeouts and limits on commit count. Invalid input gives 400; unknown id gives 404. Prove each route with real requests (valid and invalid) and show status codes and response shapes. Confirm that no response ever contains key material.

**Done when:** route tests pass, and an end-to-end call (upload demo repo, run history scan, fetch findings, secrets, timeline) works. Show which storage mode ran. STOP.

---

## Step 12: Frontend page "Crypto Time Machine"

**Do:** Add `frontend/timemachine.html` in the same style as the other pages, linked from the navigation with one link in `shell.js`. It must use real API data (no hardcoded data). Show:
- Summary cards: commits scanned, findings introduced, findings resolved, still-present weak or quantum-vulnerable, leaked secrets in history.
- **Risk timeline chart:** risk_debt (and weak and quantum-vulnerable counts) per commit. Use a lightweight chart that works without extra build steps (inline SVG or an already-used chart library).
- **Debt burndown chart:** introduced vs resolved over time.
- **Findings table:** algorithm, key size, file, introduced (commit and date), removed (commit and date or "still present"), exposure (days and commits), status badge.
- **Leaked secrets panel:** type, file, added and removed commits, "still in history" badge, and the recommendation "Rotate this key. Deleting a file does not remove it from Git history." Never show key content.
- A note on limits: "History results depend on the commits available (shallow clones are incomplete)."
- Loading, empty and error states.

Give me exact demo steps and then show me the page text or a screenshot of each state.

**Done when:** the page displays the demo repo's timeline, lifecycle and leaked key correctly from the real API. STOP.

---

## Step 13: Tests and documentation

**Do:**
- Unit tests: history reading (merges, renames, empty repo, shallow clone), cache hits and misses, finding identity across line shifts, lifecycle (including reappearing findings), secret detection (and no-leak test), timeline series.
- Safety tests: huge blob skipped, commit cap enforced, malicious filenames (path traversal such as `../`, very long names, names starting with `-`), a repo with a Git hook file does NOT execute it.
- Run `python -m pytest runtime/tests/ triangulation/tests/ timemachine/tests/ -v` (all folders) and `npx prisma validate` and `npx prisma generate`.
- Write `timemachine/README.md`: what it does, how to run the demo, the JSON contract Member 3 will consume (risk timeline and historical findings), the risk_debt definition and that its weights are illustrative, and the limits (shallow clones, binary files, renamed or heavily refactored code, only languages Member 1's scanner supports, secret detection covers common key formats only).
- Show `git status`.

**Done when:** all tests pass and the README exists. Give an honest PASS/FAIL table with real output. STOP and wait for my approval. Do not commit or push.

---

## Final checklist
- [ ] Demo repo with 7 commits and a hand-written `expected.json`
- [ ] Per-commit findings match expected, incremental cache works
- [ ] Lifecycle: MD5 (C1 to C5), RSA-1024 (C2 to C6), ECDSA (C7, still present)
- [ ] Leaked-then-deleted key detected (C3 to C4), nothing secret stored or shown
- [ ] Risk timeline and burndown series, plus charts in the UI
- [ ] No repository code ever executed; hooks disabled; limits enforced
- [ ] Real scanner from Member 1 reused, findings deduplicated
- [ ] Prisma validate and generate pass on PostgreSQL; teammates' models untouched
- [ ] Honest evaluation numbers, expected.json not tuned
- [ ] All tests pass (including Feature 12 and Feature 6 tests)
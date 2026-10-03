# CryptoScan: Feature 12 Implementation Guide
## Runtime Cryptographic Intelligence & Execution Tracing

**Instructions for the AI agent (Antigravity):**
Follow the steps below IN ORDER. After each step, run its "Done when" check, then pause and report what you did before starting the next step. Do not skip ahead. Do not change Member 1's CBOM output; only extend additively.

**Context:** Member 1's work (secure, reproducible, multi-language static scanner producing a CycloneDX CBOM with stable finding IDs) is already complete. This feature records which cryptographic operations actually run, so a later feature (Triangulated Truth) can compare static vs runtime evidence.

**Hard rules (apply to every step):**
1. NEVER log key material, plaintext, ciphertext, passwords, or secrets. Metadata only.
2. Instrumentation must NEVER crash or alter the behavior of the target app. Wrap every hook in try/except (Python) or try/catch (Node); on error, swallow and continue.
3. Runtime tracing is for test/staging only. Document this.
4. Reuse the existing finding schema and finding-ID scheme. Do not invent a second one.
5. Be honest in docs about what is not captured.

---

## Step 1: Explore the repo and write a plan

**Do:**
- Locate: the CBOM generator, the finding schema, how finding IDs are built, the PostgreSQL models and migration tool, the API framework and routes, the CLI entry point, the test setup, the frontend.
- Create `runtime/PLAN.md` containing: what exists (with file paths), the list of files you will add or change, and any assumptions.

**Done when:** `runtime/PLAN.md` exists and I have approved it.

---

## Step 2: Define the runtime event schema

**Do:** Create `runtime/schema.py` (or the repo's equivalent) with one event model.

Fields:
| Field | Notes |
|---|---|
| event_id | unique id |
| run_id | links to a run |
| timestamp | UTC ISO-8601 |
| language | `python` or `node` |
| library | e.g. `hashlib`, `cryptography`, `node:crypto` |
| operation | one of: `hash`, `encrypt`, `decrypt`, `sign`, `verify`, `keygen`, `kdf`, `hmac`, `tls`, `other` |
| algorithm | normalized name, e.g. `AES`, `RSA`, `SHA-256`, `ECDSA` |
| key_size | int or null |
| mode | e.g. `GCM`, `CBC`, or null |
| padding | e.g. `OAEP`, `PKCS1v15`, or null |
| curve | e.g. `secp256r1` or null |
| call_file | relative path of caller |
| call_line | int |
| call_function | function name |
| matched_finding_id | nullable, filled in Step 8 |

Also create `runtime/normalize.py` with a function that maps raw library names to canonical algorithm names (e.g. `sha256`, `SHA256`, `sha-256` all become `SHA-256`).

**Done when:** schema validates a sample event, and unit tests for `normalize` pass.

---

## Step 3: Python instrumentation

**Do:** Create `runtime/python_agent/` with a `tracer.py` and a `sitecustomize`-style or import-hook loader.

Hook these (only those installed):
- `hashlib` (`new`, `md5`, `sha1`, `sha256`, etc.), `hmac`
- `cryptography` (hazmat ciphers, hashes, RSA/EC keygen, sign/verify, encrypt/decrypt)
- `Crypto` (PyCryptodome): AES, RSA, hashes
- `jwt` (PyJWT): encode/decode with the algorithm used
- `ssl`: record negotiated TLS version and cipher after handshake

For each hooked call: extract algorithm, key size, mode, padding, and curve from arguments or objects WITHOUT storing the key or data. Use `inspect` or `sys._getframe` to find the first caller frame outside the hook and the library. Emit an event to a thread-safe collector.

Collector: buffer events in memory, write to a JSONL file (path from env var `CRYPTOSCAN_RUNTIME_OUT`) on each event or at exit via `atexit`.

**Done when:** running a small script with `python -c "import hashlib; hashlib.sha256(b'x')"` under the tracer produces one correct `SHA-256` event with the correct call site, and no data bytes appear in the output.

---

## Step 4: Node.js instrumentation

**Do:** Create `runtime/node_agent/preload.js`, loaded via `node --require`.

Hook these:
- Built-in `crypto`: `createHash`, `createHmac`, `createCipheriv`, `createDecipheriv`, `generateKeyPair(Sync)`, `createSign`, `createVerify`, `publicEncrypt`, `privateDecrypt`, `pbkdf2(Sync)`, `scrypt(Sync)`
- `jsonwebtoken` (sign/verify), `node-forge` if installed
- `tls`: record negotiated protocol and cipher on `secureConnect`

Same rules as Step 3: metadata only, never crash, find caller via `new Error().stack` parsing, write JSONL to `CRYPTOSCAN_RUNTIME_OUT`.

**Done when:** `node --require ./runtime/node_agent/preload.js -e "require('crypto').createHash('sha256')"` produces one correct event, with no data content logged.

---

## Step 5: Demo apps

**Do:** Create `runtime/demo/python_app.py` and `runtime/demo/node_app.js`. Each must:
- Use AES-256-GCM, RSA-2048 (keygen + sign/verify), SHA-256, and ECDSA P-256
- Contain ONE crypto path that is never executed at runtime (for example a function using RSA-1024 or MD5 behind an `if False`-style branch that is never called), so we can later demonstrate "Static Only"
- Be small, deterministic, and run without network access

**Done when:** both apps run on their own, and a static scan of them lists the unexecuted path.

---

## Step 6: Database migration and storage

**Do:** Add a migration (using the repo's existing tool) creating:

`runtime_runs`: run_id (pk), scan_id (fk, nullable), language, command, environment (`test`/`staging`), started_at, finished_at, event_count.

`runtime_events`: all schema fields from Step 2, with run_id as a foreign key and an index on (run_id, algorithm).

Add a repository/DAO module to insert runs and bulk-insert events and to query them.

**Done when:** the migration applies and rolls back cleanly, and a test inserts and reads back a run with events.

---

## Step 7: Evidence report generator

**Do:** Create `runtime/report.py`. Given a run_id, produce a JSON report:

```json
{
  "run_id": "...",
  "scan_id": "...",
  "language": "python",
  "environment": "test",
  "summary": {
    "total_events": 0,
    "unique_algorithms": [],
    "quantum_vulnerable_algorithms": [],
    "unmatched_events": 0
  },
  "events": []
}
```

Aggregate repeated identical events (same algorithm, operation, call site) into one entry with a `count`, keeping first and last timestamps. Mark RSA, ECDSA, ECDH, DH, and DSA as quantum-vulnerable.

**Done when:** the report for the demo app run matches the expected summary in a test.

---

## Step 8: Match runtime events to static findings

**Do:** Create `runtime/matcher.py`.

Given a scan's CBOM findings and a run's events, set `matched_finding_id` when ALL of these agree:
1. normalized algorithm matches
2. call file matches the finding's source file (path-normalized)
3. call line falls within the finding's function range, or is within a small configurable line tolerance

Otherwise leave it null. Do not guess. Record the match reason (`exact_line`, `same_function`, `same_file_algorithm`) and a confidence value (`high`, `medium`, `low`).

**Done when:** on the demo app, executed paths are matched to the right finding IDs and the never-executed path has no matching runtime event.

---

## Step 9: CLI

**Do:** Add to the existing CLI:

```
cryptoscan runtime run --lang python --scan-id <id> -- python app.py
cryptoscan runtime run --lang node   --scan-id <id> -- node app.js
cryptoscan runtime report --run-id <id> --out report.json
```

`run` sets `CRYPTOSCAN_RUNTIME_OUT`, injects the agent (`PYTHONPATH`/sitecustomize for Python, `--require` for Node), runs the command, ingests the JSONL into the database, runs the matcher, and prints a short summary. The target app's exit code must be passed through.

**Done when:** both commands work end to end on the demo apps.

---

## Step 10: API endpoints

**Do:** Add routes following the existing API conventions:

- `POST /api/runtime/runs` : ingest a run with events (validate against the schema, cap payload size)
- `GET /api/runtime/runs` : list runs (filter by scan_id)
- `GET /api/runtime/runs/{run_id}` : run details and summary
- `GET /api/runtime/runs/{run_id}/events` : paginated events
- `GET /api/runtime/runs/{run_id}/report` : the Step 7 report

Apply the same authentication and validation used by existing routes.

**Done when:** route tests pass, and an invalid payload is rejected with a clear error.

---

## Step 11: Tests

**Do:**
- Unit: normalizer, schema validation, matcher, report aggregation
- Hook tests: each hooked function emits a correct event, and a test confirming NO key or data bytes appear in any event
- Fail-safe test: force a hook to raise an exception and confirm the target app still runs correctly
- Integration: run each demo app under instrumentation, ingest, match, and assert the expected algorithms and the absence of the unexecuted path

**Done when:** the full test suite passes.

---

## Step 12: Documentation

**Do:** Add a `runtime/README.md` covering:
- What the feature does and the test/staging-only warning
- How to run it (CLI and API examples)
- What is captured, and what is NOT captured (for example: native or C-extension calls that bypass the hooked libraries, other languages, code paths that do not run, anything the hooks do not cover)
- The JSON contract (event schema and report format) that Triangulated Truth will consume

**Done when:** a new teammate could run the demo from the README alone.

---

## Final checklist
- [ ] Demo apps produce correct runtime events
- [ ] No secrets or data content logged anywhere
- [ ] Hook failure never crashes the target app
- [ ] Events stored in PostgreSQL and exposed via API and CLI
- [ ] Executed paths match static finding IDs; unexecuted path has no runtime event
- [ ] Member 1's CBOM output is unchanged
- [ ] Tests and docs complete

**When all steps are done, give me a summary and wait. The next feature is Triangulated Truth.**
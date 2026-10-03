# Crypto Ratchet Gate with Expiring Waivers (Feature 8)

The **Crypto Ratchet Gate** is an automated CI/CD policy enforcement mechanism for CryptoScan. It prevents regressions in cryptographic posture by blocking pull requests that increase quantum-vulnerable cryptography or introduce prohibited legacy algorithms, while supporting auditable, time-bounded waivers with cryptographic ownership.

---

## 1. Stable Asset Fingerprint Specification

To compare cryptographic assets across commits without false-positive diffs caused by shifted line numbers, each asset occurrence is hashed into a stable SHA-256 fingerprint:

$$\text{Fingerprint} = \text{SHA-256}(\text{norm\_algo} \parallel \text{norm\_type} \parallel \text{norm\_keysize} \parallel \text{norm\_path} \parallel \text{norm\_purpose})$$

### Normalization Rules
1. **Algorithm:** Uppercase, trimmed, whitespace collapsed (`RSA`, `AES-256-GCM`, `ECDSA`).
2. **Primitive / Asset Type:** Lowercase (`algorithm`, `signature`, `key-exchange`, `encryption`, `hash`, `protocol`).
3. **Key Size:** Integer string or empty if not applicable (`2048`, `256`, `""`).
4. **File Path:** Repo-relative, forward slashes `/`, stripped leading `./` or `/`.
5. **Purpose / Symbol:** Lowercase trimmed purpose (`signature`, `encryption`, `key-exchange`, `token-auth`).
6. **Line Numbers:** **EXPLICITLY EXCLUDED.** Adding lines above or below an asset does not alter its fingerprint.

### File Move / Rename Heuristic
When a file is renamed or code is moved, the gate computes a **path-independent fingerprint** ($\text{norm\_algo} \parallel \text{norm\_type} \parallel \text{norm\_keysize} \parallel \text{norm\_purpose}$). If an added asset matches a removed asset's path-independent signature, it is categorized as **MOVED / RENAMED** rather than penalized as a newly introduced violation.

---

## 2. Policy File (`.cryptoscan/policy.yaml`)

Sensible defaults are applied automatically if this file is missing:

```yaml
# Maximum newly introduced quantum-vulnerable assets allowed in a PR (default: 0)
max_new_quantum_vulnerable: 0

# Maximum total quantum-vulnerable assets allowed (cannot exceed base branch count)
max_total_quantum_vulnerable: "baseline"

# Legacy / broken algorithms prohibited in new code
prohibited_algorithms:
  - "MD5"
  - "SHA-1"
  - "DES"
  - "3DES"
  - "RC4"
  - "RSA<2048"
  - "DH<2048"

# Enforce hard failure on prohibited algorithms in new code
fail_on_prohibited_in_new_code: true

# Maximum permitted duration for any single waiver (days from today)
waiver_max_days: 90

# Days before waiver expiration when warning is emitted
waiver_warn_days: 14

# Reductions in cryptographic debt pass and are celebrated
allow_decrease: true
```

---

## 3. Waivers (`.cryptoscan/waivers.yaml`)

Waivers allow teams to merge necessary code with temporary technical debt under strict security governance:

```yaml
waivers:
  - id: waiver-rsa-token-migration
    match:
      fingerprint: "a2f90ac444b0f50d6cfa5ba04fe00ae390d0497432b39f274e1afd0b8c0dc22f"
      # OR match by algorithm AND path glob:
      # algorithm: "RSA"
      # path: "src/auth/*.py"
    owner: "@security-lead"
    reason: "Approved transition plan to ML-DSA scheduled for Q4 release."
    expires: "2026-12-15"
    ticket: "https://github.com/org/repo/issues/123"
```

### Validation & Enforcement Rules
| Condition | Result | Behavior |
| :--- | :--- | :--- |
| Missing `owner`, `reason` (<15 chars), or `expires` | **INVALID** | Waiver rejected; logged as error; violation remains active. |
| `expires` in the past | **EXPIRED** | Waiver automatically invalidated; finding counts as blocking violation. |
| `expires` > `waiver_max_days` (90d) | **INVALID** | Duration too long; must break down into shorter milestones. |
| `expires` $\le$ `waiver_warn_days` (14d) | **WARNING** | Still valid; surfaces warning banner prompting renewal or migration. |
| Blanket wildcard without path | **INVALID** | Blanket waivers (`algorithm: "*"` without path) are prohibited. |
| Matches 0 assets in PR branch | **STALE** | Emits cleanup suggestion to remove unused waiver. |

---

## 4. CLI Usage

### 1. Scan and Output CycloneDX 1.6 CBOM
```bash
python cryptoscan scan <path-to-repo> --out cbom.json
```

### 2. Run Policy Gate
```bash
python cryptoscan gate \
  --base base.cbom.json \
  --head head.cbom.json \
  --policy .cryptoscan/policy.yaml \
  --waivers .cryptoscan/waivers.yaml \
  --format md,json \
  --out-md gate-report.md \
  --out-json gate-report.json
```

### Exit Codes
- `0`: **PASS** (Cryptographic posture preserved or improved).
- `1`: **FAIL** (Policy violation: new unapproved quantum-vulnerable cryptography or prohibited algorithm).
- `2`: **ERROR** (Usage or parse error, missing file. Never silently passes on parse failure).

---

## 5. GitHub Actions Integration

The workflow `.github/workflows/crypto-gate.yml` executes on every pull request:
1. Scans head branch $\to$ `head.cbom.json`.
2. Checks out base branch in a temporary worktree and scans $\to$ `base.cbom.json`.
3. Evaluates `cryptoscan gate`.
4. Writes Markdown summary to `$GITHUB_STEP_SUMMARY`.
5. Posts or updates a single sticky PR comment (identified by `<!-- cryptoscan-gate -->`).
6. Uploads CBOMs and reports as workflow artifacts.
7. Fails build if gate exit code is non-zero.

### Branch Protection & CODEOWNERS
1. **Required Status Check:** Set `crypto-gate` as a required status check in GitHub Branch Protection rules.
2. **CODEOWNERS:** Add to `.github/CODEOWNERS`:
   ```text
   .cryptoscan/waivers.yaml @security-team
   .cryptoscan/policy.yaml  @security-team
   ```
   This ensures developers cannot approve their own cryptographic waivers.

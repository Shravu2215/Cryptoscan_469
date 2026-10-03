# HNDL Detection — Engineering Reference

> Internal implementation notes for `backend-core/src/services/quantumRisk/hndl/`.
> Pure-function layer only; no DB, no routes, no UI.

---

## Detection Signals

| Signal | Source | How it works |
|--------|--------|--------------|
| **value** | `detector.js / detectValues` | Regex match + checksum validation (Verhoeff for Aadhaar, Luhn + IIN prefix for payment cards, PAN pattern for PAN). Evidence is masked to `****XXXX` before storage. |
| **name** | `detector.js / detectNames` | Identifier/column name matched against `SENSITIVE_NAME_SYNONYMS` vocabulary across SQL DDL, Prisma, TypeORM, Django, SQLAlchemy, JSON Schema, and plain variable declarations. |
| **type** | `detector.js / detectNames` | Column type text corroborates the name match (e.g. `VARCHAR(12)` → AADHAAR, `CHAR(10)` → PAN). |

`combineSignals` merges value and name findings for the same field; combined confidence = 1 − (1 − p_value)(1 − p_name).

---

## Confidence Rules

| Signal combination | Confidence range |
|--------------------|-----------------|
| value + name (both) | boosted by combination formula ≥ max(p_v, p_n) |
| value alone, confidence ≥ 0.85 | `strongValue` — second priority in sort |
| name + type hint | 0.90 |
| name only | 0.68 |
| boolean/enum type | 0.35 (weak) |

---

## Retention Resolution (Priority Order)

1. **override** (`options.overrides[fieldId]`) — caller-supplied, wins unconditionally; reported as `retentionSource: 'stated'`.
2. **stated** — longest retention duration parsed from source files (comments, config values, SQL `DELETE … WHERE … interval`, TTL constants). When multiple values conflict, the longest is taken and the `note` field records the conflict.
3. **inferred** — a config file key that clearly names the same field followed by a retention/TTL suffix (e.g. `aadhaar_number_retention_days: 1825`). Only triggers on config-like file extensions (`.json`, `.yaml`, `.toml`, etc.).
4. **default** — per-class policy table (editable; **verify with legal/compliance before use**).

### Default Retention Policy

| Class | Default years | Rationale (assumption only) |
|-------|:---:|-------------|
| `AADHAAR` | **5** | Duration of customer relationship plus a short post-closure buffer. |
| `PAN` | **8** | Multi-year tax audit and dispute resolution cycles. |
| `PAYMENT_CARD` | **5** | Dispute window plus buffer period. |
| `HEALTH` | **7** | Continuity of care and medico-legal obligations. |
| `PII_OTHER` | **3** | Minimum period to fulfil the original collection purpose. |

> **Every entry is marked `ASSUMPTION - verify with legal/compliance`.  
> No law, section number, or regulation is cited.**

---

## `detectSensitiveData` Output Shape

```
{
  fields: SensitiveDataField[],          // sorted: filePath → line → dataClass
  stats: {
    filesScanned: number,
    filesSkipped: [{ filePath, reason }], // dep dirs, lockfiles, oversized files
    byClass: { [dataClass]: count },
    truncated: boolean                   // true when input > 20,000 files
  },
  meta: { engineVersion: string }
}
```

Each `SensitiveDataField`:
- `fieldId` — SHA-256-derived stable ID (`field-<24 hex chars>`)
- `retentionSource` — `'stated' | 'inferred' | 'default'`
- `protectedBy: []` — lineage not yet implemented
- `lineageConfidence: 0` — not yet implemented
- `evidence` — array of masked strings (e.g. `["****1234"]`); never raw values

---

## Known Limitations

- **Stated scan is context-windowed** (±5 lines around the field name) for generic `N unit` patterns; explicit retention keywords (TTL, `retain for`, etc.) are matched file-wide.
- **Inferred scan** only checks files with config-like extensions. Application code with embedded maps is not covered.
- **No cross-file lineage** — if a field is defined in one file and its TTL set in another with a different name, the link is not made automatically.
- **Value detection covers AADHAAR, PAN, and major payment card BINs only.** Health and PII_OTHER rely solely on name/type signals.
- **All regexes are linear-time** (no nested quantifiers); pathological inputs are tested in `hndl.test.js`.
- **File cap:** 20,000 files per call; 200 findings per file; 1 MiB per file.

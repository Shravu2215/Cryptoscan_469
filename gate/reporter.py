"""
reporter.py - Generates PR-friendly Markdown and machine-readable JSON reports.

Guarantees:
- Output is deterministic.
- Markdown is GitHub-comment friendly (<65KB), truncating long tables gracefully.
- Clear PASS / FAIL banner, breakdown table, violations, waivers, improvements, and how-to-fix guide.
"""

import json
from typing import Dict, Any, List
from gate.engine import GateEvaluationResult


MAX_TABLE_ROWS = 15  # Avoid exceeding GitHub comment size limit


def generate_markdown_report(result: GateEvaluationResult) -> str:
    """Generates a GitHub-flavored Markdown report suitable for PR comments and job summaries."""
    lines = []

    # Hidden comment identifier for GitHub Script to find & update existing comment
    lines.append("<!-- cryptoscan-gate -->")

    # 1. Verdict Banner
    if result.verdict == "PASS":
        lines.append("## 🟢 Crypto Ratchet Gate: PASSED\n")
        lines.append("> **Cryptographic posture maintained or improved.** No unapproved quantum-vulnerable cryptography was introduced.\n")
    else:
        lines.append("## 🔴 Crypto Ratchet Gate: FAILED\n")
        lines.append("> **Policy Violation Detected.** This pull request introduces unapproved quantum-vulnerable or prohibited cryptographic assets.\n")

    # Failure details
    if result.failure_reasons:
        lines.append("### ⚠️ Blocking Violations\n")
        for fr in result.failure_reasons:
            lines.append(f"- ❌ **{fr}**")
        lines.append("")

    # 2. Base vs Head vs Delta Table
    metrics = result.metrics
    cats = metrics.get("categories", {})
    delta_total = metrics.get("delta_quantum_vulnerable", 0)
    delta_sign = f"+{delta_total}" if delta_total > 0 else str(delta_total)

    lines.append("### 📊 Quantum Cryptography Metric Delta\n")
    lines.append("| Metric / Category | Base Branch | Head (PR) | Delta |")
    lines.append("| :--- | :---: | :---: | :---: |")
    lines.append(f"| **Total Quantum-Vulnerable Assets** | **{metrics.get('base_quantum_vulnerable', 0)}** | **{metrics.get('head_quantum_vulnerable', 0)}** | **`{delta_sign}`** |")

    cat_labels = {
        "signature": "Digital Signatures",
        "key_exchange": "Key Exchange / KEM",
        "encryption": "Encryption / Ciphers",
        "hash": "Cryptographic Hashes",
        "protocol": "Protocols (TLS/SSH/VPN)",
    }
    for c_key, c_label in cat_labels.items():
        c_data = cats.get(c_key, {"base": 0, "head": 0, "delta": 0})
        d = c_data["delta"]
        ds = f"+{d}" if d > 0 else str(d)
        lines.append(f"| {c_label} | {c_data['base']} | {c_data['head']} | `{ds}` |")
    lines.append("")

    # 3. New Violations Table
    unwaived = result.unwaived_violations
    if unwaived:
        lines.append(f"### 🚨 New Unwaived Violations ({len(unwaived)})\n")
        lines.append("| Algorithm | Location | Language | Risk | Suggested PQC Replacement |")
        lines.append("| :--- | :--- | :--- | :--- | :--- |")

        display_rows = unwaived[:MAX_TABLE_ROWS]
        for v in display_rows:
            loc = f"`{v.get('file', 'unknown')}:{v.get('line', 0)}`"
            algo = v.get("algorithm", "UNKNOWN")
            lang = v.get("language", "Unknown")
            risk = v.get("quantum_status") or v.get("severity") or "Quantum Vulnerable"
            rec = v.get("recommendation", "NIST PQC algorithm")
            lines.append(f"| **{algo}** | {loc} | {lang} | {risk} | {rec} |")

        if len(unwaived) > MAX_TABLE_ROWS:
            lines.append(f"| *... and {len(unwaived) - MAX_TABLE_ROWS} more* | | | | |")
        lines.append("")

    # 4. Prohibited Algorithms Table
    prohibited = result.prohibited_violations
    if prohibited:
        lines.append(f"### 🚫 Prohibited Algorithms Introduced ({len(prohibited)})\n")
        lines.append("| Algorithm | Location | Rule Violated |")
        lines.append("| :--- | :--- | :--- |")
        for p in prohibited[:MAX_TABLE_ROWS]:
            lines.append(f"| `{p.get('algorithm')}` | `{p.get('file')}:{p.get('line')}` | Prohibited: `{p.get('prohibited_spec')}` |")
        lines.append("")

    # 5. Waived Assets Table
    waived = result.waived_violations
    if waived:
        lines.append(f"### 🛡️ Active Waivers Applied ({len(waived)})\n")
        lines.append("| Waiver ID | Owner | Reason | Expires | Days Left |")
        lines.append("| :--- | :--- | :--- | :--- | :---: |")
        for w in waived[:MAX_TABLE_ROWS]:
            lines.append(f"| `{w.get('waiver_id')}` | {w.get('waiver_owner')} | {w.get('waiver_reason')} | {w.get('waiver_expires')} | {w.get('waiver_days_left')}d |")
        if len(waived) > MAX_TABLE_ROWS:
            lines.append(f"| *... and {len(waived) - MAX_TABLE_ROWS} more* | | | | |")
        lines.append("")

    # 6. Expired / Invalid / Stale Warnings
    if result.rejected_waivers or result.warning_messages:
        lines.append("### ⚠️ Waiver Warnings & Errors\n")
        for rw in result.rejected_waivers:
            lines.append(f"- ❌ **Waiver `{rw.id}` ({rw.status}):** {rw.error_reason}")
        for sw in result.stale_waivers:
            lines.append(f"- ℹ️ **Waiver `{sw.id}` (STALE):** Matches 0 assets in target branch. Consider removing from `.cryptoscan/waivers.yaml`.")
        for ew in result.expiring_soon_waivers:
            lines.append(f"- ⏳ **Waiver `{ew.id}` (EXPIRING SOON):** {ew.warning_reason}")
        lines.append("")

    # 7. Improvements Section (Reductions celebrated!)
    removed = result.removed_assets
    if removed:
        qv_removed = [r for r in removed if r.get("is_quantum_vulnerable")]
        if qv_removed:
            lines.append(f"### 🎉 Cryptographic Debt Reductions ({len(qv_removed)})\n")
            lines.append(f"Great work! This PR eliminated **{len(qv_removed)}** quantum-vulnerable cryptographic asset(s):\n")
            for r in qv_removed[:5]:
                lines.append(f"- Removed `{r.get('algorithm')}` in `{r.get('file')}:{r.get('line')}`")
            if len(qv_removed) > 5:
                lines.append(f"- *... and {len(qv_removed) - 5} more eliminated*")
            lines.append("")

    # 8. How to fix or request a waiver
    lines.append("### 📖 How to Fix or Request a Waiver\n")
    if result.verdict == "FAIL":
        lines.append(
            "To resolve this failure, either:\n"
            "1. **Migrate the asset:** Replace the classical algorithm with a post-quantum standard (e.g. ML-KEM for key encapsulation, ML-DSA / SLH-DSA for signatures).\n"
            "2. **Add an expiring waiver:** If migration cannot happen in this PR, request a time-bounded waiver approved by security in `.cryptoscan/waivers.yaml`:\n"
        )
        sample_fp = unwaived[0].get("fingerprint") if unwaived else "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        sample_algo = unwaived[0].get("algorithm") if unwaived else "RSA-2048"
        sample_path = unwaived[0].get("file") if unwaived else "src/legacy/*.py"
        today_iso = result.evaluation_date or "2026-10-03"

        lines.append("```yaml")
        lines.append("# Add to .cryptoscan/waivers.yaml:")
        lines.append(f"- id: waiver-{sample_algo.lower().replace('/', '-')}-migration")
        lines.append("  match:")
        lines.append(f"    fingerprint: \"{sample_fp}\"")
        lines.append("    # OR match by algorithm and file path glob:")
        lines.append(f"    # algorithm: \"{sample_algo}\"")
        lines.append(f"    # path: \"{sample_path}\"")
        lines.append("  owner: \"@your-github-handle\"")
        lines.append("  reason: \"Migrating to ML-KEM in Q4 planned sprint; ticket created.\"")
        lines.append("  expires: \"2026-12-15\"  # Max 90 days from today")
        lines.append("  ticket: \"https://github.com/org/repo/issues/123\"")
        lines.append("```\n")
    else:
        lines.append(
            "All cryptographic checks passed according to `.cryptoscan/policy.yaml`. "
            "Continue following quantum-safe cryptographic design principles.\n"
        )

    lines.append("---\n*Generated automatically by [CryptoScan Ratchet Gate](https://cryptoscan.io)*")
    return "\n".join(lines)


def generate_json_report(result: GateEvaluationResult) -> Dict[str, Any]:
    """Generates a structured JSON object representing the gate evaluation."""
    return {
        "verdict": result.verdict,
        "exit_code": result.exit_code,
        "evaluation_date": result.evaluation_date,
        "policy": result.policy,
        "failure_reasons": result.failure_reasons,
        "warnings": result.warning_messages,
        "metrics": result.metrics,
        "new_violations_count": len(result.unwaived_violations),
        "waived_violations_count": len(result.waived_violations),
        "unwaived_violations": result.unwaived_violations,
        "waived_violations": result.waived_violations,
        "prohibited_violations": result.prohibited_violations,
        "active_waivers": [
            {
                "id": w.id,
                "owner": w.owner,
                "reason": w.reason,
                "expires": w.expires_str,
                "days_left": w.days_left,
                "matched_count": len(w.matched_assets),
            }
            for w in result.active_waivers
        ],
        "rejected_waivers": [
            {
                "id": w.id,
                "status": w.status,
                "error": w.error_reason,
            }
            for w in result.rejected_waivers
        ],
        "stale_waivers": [w.id for w in result.stale_waivers],
        "removed_assets_count": len(result.removed_assets),
        "moved_assets_count": len(result.moved_assets),
    }

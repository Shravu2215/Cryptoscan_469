"""
engine.py - Core evaluation engine for Crypto Ratchet Gate.

Performs:
1. CBOM asset extraction & fingerprint comparison.
2. Asset diffing (added, removed, unchanged, renamed/moved).
3. Quantum vulnerability delta calculation overall and by category.
4. Waiver application to new violations.
5. Strict policy evaluation and verdict determination.
"""

from typing import Dict, Any, List, Tuple, Optional, Set
import datetime

from gate.cbom_parser import parse_cbom
from gate.policy import load_policy, check_prohibited_algorithms
from gate.waivers import process_waivers, get_today, WaiverRecord, WaiverStatus


class GateEvaluationResult:
    def __init__(self):
        self.verdict: str = "PASS"  # PASS or FAIL
        self.exit_code: int = 0      # 0 = pass, 1 = policy violation, 2 = parse error
        self.failure_reasons: List[str] = []
        self.warning_messages: List[str] = []

        # Asset sets
        self.base_assets: List[Dict[str, Any]] = []
        self.head_assets: List[Dict[str, Any]] = []
        self.added_assets: List[Dict[str, Any]] = []
        self.removed_assets: List[Dict[str, Any]] = []
        self.unchanged_assets: List[Dict[str, Any]] = []
        self.moved_assets: List[Dict[str, Any]] = []

        # Violations & Waivers
        self.new_quantum_violations: List[Dict[str, Any]] = []
        self.waived_violations: List[Dict[str, Any]] = []
        self.unwaived_violations: List[Dict[str, Any]] = []
        self.prohibited_violations: List[Dict[str, Any]] = []

        # Waiver lists
        self.active_waivers: List[WaiverRecord] = []
        self.rejected_waivers: List[WaiverRecord] = []
        self.stale_waivers: List[WaiverRecord] = []
        self.expiring_soon_waivers: List[WaiverRecord] = []

        # Metrics & Summary
        self.metrics: Dict[str, Any] = {}
        self.policy: Dict[str, Any] = {}
        self.evaluation_date: str = ""


def evaluate_gate(
    base_cbom: Dict[str, Any],
    head_cbom: Dict[str, Any],
    policy_dict: Optional[Dict[str, Any]] = None,
    raw_waivers: Optional[List[Dict[str, Any]]] = None,
    custom_today: Optional[str] = None,
) -> GateEvaluationResult:
    """
    Main entry point for evaluating the Crypto Ratchet Gate against base and head CBOMs.
    """
    res = GateEvaluationResult()
    today = get_today(custom_today)
    res.evaluation_date = today.isoformat()

    policy = policy_dict or load_policy()
    res.policy = policy

    # 1. Parse CBOMs
    base_assets = parse_cbom(base_cbom)
    head_assets = parse_cbom(head_cbom)

    res.base_assets = base_assets
    res.head_assets = head_assets

    # 2. Build fingerprint lookup maps
    base_by_fp = {a["fingerprint"]: a for a in base_assets}
    head_by_fp = {a["fingerprint"]: a for a in head_assets}

    # Added = in head, not in base
    raw_added = [a for a in head_assets if a["fingerprint"] not in base_by_fp]
    # Removed = in base, not in head
    raw_removed = [a for a in base_assets if a["fingerprint"] not in head_by_fp]
    # Unchanged = in both
    res.unchanged_assets = [a for a in head_assets if a["fingerprint"] in base_by_fp]

    # Heuristic for moved/renamed files:
    # If an added asset has the exact same path-independent fingerprint as a removed asset,
    # it is treated as a code move/file rename rather than a newly introduced asset.
    removed_path_indep: Dict[str, List[Dict[str, Any]]] = {}
    for r in raw_removed:
        pfp = r["path_independent_fingerprint"]
        removed_path_indep.setdefault(pfp, []).append(r)

    added_final: List[Dict[str, Any]] = []
    for a in raw_added:
        pfp = a["path_independent_fingerprint"]
        if pfp in removed_path_indep and len(removed_path_indep[pfp]) > 0:
            matched_r = removed_path_indep[pfp].pop(0)
            a["moved_from"] = matched_r.get("file")
            res.moved_assets.append(a)
        else:
            added_final.append(a)

    res.added_assets = added_final
    res.removed_assets = raw_removed

    # 3. Categorize & count quantum vulnerability
    categories = ["signature", "key_exchange", "encryption", "hash", "protocol"]

    base_qv = [a for a in base_assets if a["is_quantum_vulnerable"]]
    head_qv = [a for a in head_assets if a["is_quantum_vulnerable"]]

    # Count by category
    def count_by_cat(asset_list):
        counts = {c: 0 for c in categories}
        for a in asset_list:
            cat = a.get("category", "encryption")
            if cat in counts:
                counts[cat] += 1
            else:
                counts["encryption"] += 1
        return counts

    base_cat_counts = count_by_cat(base_qv)
    head_cat_counts = count_by_cat(head_qv)
    delta_cat_counts = {c: head_cat_counts[c] - base_cat_counts[c] for c in categories}

    total_base_qv = len(base_qv)
    total_head_qv = len(head_qv)
    total_delta_qv = total_head_qv - total_base_qv

    res.metrics = {
        "base_total_assets": len(base_assets),
        "head_total_assets": len(head_assets),
        "base_quantum_vulnerable": total_base_qv,
        "head_quantum_vulnerable": total_head_qv,
        "delta_quantum_vulnerable": total_delta_qv,
        "added_count": len(added_final),
        "removed_count": len(raw_removed),
        "moved_count": len(res.moved_assets),
        "categories": {
            c: {
                "base": base_cat_counts[c],
                "head": head_cat_counts[c],
                "delta": delta_cat_counts[c],
            }
            for c in categories
        },
    }

    # 4. Identify new quantum-vulnerable violations (from added assets)
    new_qv = [a for a in added_final if a["is_quantum_vulnerable"]]
    res.new_quantum_violations = new_qv

    # 5. Check prohibited algorithms in new code
    prohibited_list = policy.get("prohibited_algorithms", [])
    if policy.get("fail_on_prohibited_in_new_code", True):
        for a in added_final:
            matched_spec = check_prohibited_algorithms(prohibited_list, a)
            if matched_spec:
                a_copy = dict(a)
                a_copy["prohibited_spec"] = matched_spec
                res.prohibited_violations.append(a_copy)

    # 6. Process waivers
    valid_waivers, rejected_waivers = process_waivers(
        raw_waivers=raw_waivers or [],
        today=today,
        max_days=policy.get("waiver_max_days", 90),
        warn_days=policy.get("waiver_warn_days", 14),
    )
    res.active_waivers = valid_waivers
    res.rejected_waivers = rejected_waivers

    # Expiring soon warnings
    res.expiring_soon_waivers = [w for w in valid_waivers if w.warning_reason]

    # Apply valid waivers to NEW violations only
    unwaived: List[Dict[str, Any]] = []
    waived: List[Dict[str, Any]] = []

    for violation in new_qv:
        matched_waiver = None
        for w in valid_waivers:
            if w.matches_asset(violation):
                matched_waiver = w
                w.matched_assets.append(violation)
                break

        if matched_waiver:
            v_copy = dict(violation)
            v_copy["waiver_id"] = matched_waiver.id
            v_copy["waiver_owner"] = matched_waiver.owner
            v_copy["waiver_reason"] = matched_waiver.reason
            v_copy["waiver_expires"] = matched_waiver.expires_str
            v_copy["waiver_days_left"] = matched_waiver.days_left
            waived.append(v_copy)
        else:
            unwaived.append(violation)

    res.waived_violations = waived
    res.unwaived_violations = unwaived

    # Check for stale waivers (valid waivers that matched 0 assets in head)
    for w in valid_waivers:
        # Check against head assets
        matches_any_head = any(w.matches_asset(a) for a in head_assets)
        if not matches_any_head:
            res.stale_waivers.append(w)

    # 7. Policy evaluation
    # Rule 1: Max new quantum vulnerable (ratchet gate)
    max_new_allowed = policy.get("max_new_quantum_vulnerable", 0)
    if len(unwaived) > max_new_allowed:
        res.verdict = "FAIL"
        res.exit_code = 1
        res.failure_reasons.append(
            f"Quantum Ratchet Violation: PR introduces {len(unwaived)} new quantum-vulnerable "
            f"cryptographic asset(s) (allowed: {max_new_allowed})."
        )

    # Rule 2: Max total quantum vulnerable cannot exceed baseline
    max_total = policy.get("max_total_quantum_vulnerable", "baseline")
    if max_total == "baseline":
        if total_delta_qv > 0 and len(waived) == 0:
            # If total increased and no waiver covers the increase
            if res.verdict != "FAIL":
                res.verdict = "FAIL"
                res.exit_code = 1
            if not any("Quantum Ratchet Violation" in r for r in res.failure_reasons):
                res.failure_reasons.append(
                    f"Baseline Exceeded: Total quantum-vulnerable assets increased from "
                    f"{total_base_qv} to {total_head_qv} (delta: +{total_delta_qv})."
                )

    # Rule 3: Prohibited algorithms in new code
    if res.prohibited_violations:
        res.verdict = "FAIL"
        res.exit_code = 1
        prohibited_names = ", ".join(sorted(set(v.get("prohibited_spec", "") for v in res.prohibited_violations)))
        res.failure_reasons.append(
            f"Prohibited Algorithm Violation: PR introduces {len(res.prohibited_violations)} "
            f"instance(s) of prohibited algorithms ({prohibited_names}) in new code."
        )

    # Rule 4: Invalid or expired waivers referenced
    # Note: if a waiver is expired, it is recorded in rejected_waivers
    for rw in rejected_waivers:
        if rw.status == WaiverStatus.EXPIRED:
            res.warning_messages.append(f"Waiver '{rw.id}' is EXPIRED ({rw.error_reason}).")
        elif rw.status == WaiverStatus.INVALID:
            res.warning_messages.append(f"Waiver '{rw.id}' is INVALID ({rw.error_reason}).")

    for sw in res.stale_waivers:
        res.warning_messages.append(
            f"Waiver '{sw.id}' is STALE: Matches 0 assets in the target branch. Suggest removing from .cryptoscan/waivers.yaml."
        )

    for ew in res.expiring_soon_waivers:
        res.warning_messages.append(f"Waiver '{ew.id}' will expire soon: {ew.warning_reason}")

    return res

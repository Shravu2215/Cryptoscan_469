"""
Static-to-Runtime Evidence Matcher for CryptoScan.
Correlates runtime execution events with static CBOM findings.
"""

import os
from typing import Dict, Any, List, Tuple
from runtime.normalize import normalize_algorithm


def _normalize_filepath(filepath: str) -> str:
    """Normalizes relative file paths for cross-platform matching."""
    if not filepath:
        return ""
    cleaned = filepath.replace("\\", "/").strip("./")
    return os.path.basename(cleaned)


def match_events_to_findings(
    cbom_findings: List[Dict[str, Any]],
    runtime_events: List[Dict[str, Any]],
    line_tolerance: int = 15,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """
    Correlates runtime events with static CBOM findings.
    Sets matched_finding_id, match_reason, and match_confidence on events when algorithm, file, and line criteria match.
    """
    matched_count = 0
    unmatched_count = 0

    # Index static findings by normalized filename and algorithm
    finding_index: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}
    finding_ids_matched = set()

    for f in cbom_findings:
        fname = _normalize_filepath(f.get("file") or f.get("filePath") or "")
        algo = normalize_algorithm(f.get("algorithm") or "")
        key = (fname, algo)
        if key not in finding_index:
            finding_index[key] = []
        finding_index[key].append(f)

    updated_events = []

    for evt in runtime_events:
        evt_copy = dict(evt)
        evt_file = _normalize_filepath(evt_copy.get("call_file") or evt_copy.get("callFile") or "")
        evt_algo = normalize_algorithm(evt_copy.get("algorithm") or "")
        evt_line = evt_copy.get("call_line") if evt_copy.get("call_line") is not None else evt_copy.get("callLine", 0)

        lookup_key = (evt_file, evt_algo)
        candidates = finding_index.get(lookup_key, [])

        best_match = None
        best_reason = None
        best_confidence = None
        smallest_dist = float("inf")

        for f in candidates:
            f_id = f.get("id") or f.get("fingerprint") or f.get("rule_id")
            f_line = f.get("line") if f.get("line") is not None else f.get("lineNumber", 0)

            dist = abs(evt_line - f_line) if (evt_line > 0 and f_line > 0) else 9999

            if dist == 0:
                best_match = f_id
                best_reason = "exact_line"
                best_confidence = "high"
                smallest_dist = 0
                break
            elif dist <= line_tolerance and dist < smallest_dist:
                best_match = f_id
                best_reason = "same_function"
                best_confidence = "medium"
                smallest_dist = dist
            elif not best_match:
                best_match = f_id
                best_reason = "same_file_algorithm"
                best_confidence = "low"

        if best_match:
            evt_copy["matched_finding_id"] = best_match
            evt_copy["match_reason"] = best_reason
            evt_copy["match_confidence"] = best_confidence
            finding_ids_matched.add(best_match)
            matched_count += 1
        else:
            evt_copy["matched_finding_id"] = None
            evt_copy["match_reason"] = "unmatched"
            evt_copy["match_confidence"] = "none"
            unmatched_count += 1

        updated_events.append(evt_copy)

    summary = {
        "total_events": len(runtime_events),
        "events_matched": matched_count,
        "events_unmatched": unmatched_count,
        "unique_findings_matched": len(finding_ids_matched),
    }

    return updated_events, summary

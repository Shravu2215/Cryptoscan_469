"""
Runtime Evidence Report Generator for CryptoScan.
Aggregates raw execution events by algorithm, call-site, and quantum vulnerability flags.
"""

import json
from typing import Dict, Any, List, Optional

QUANTUM_VULNERABLE_ALGORITHMS = {
    "RSA", "ECDSA", "ECDH", "DH", "DSA", "ED25519", "ED448"
}


def generate_report_from_events(
    run_id: str,
    raw_events: List[Dict[str, Any]],
    scan_id: Optional[str] = None,
    language: str = "python",
    environment: str = "test",
) -> Dict[str, Any]:
    """
    Generates a structured, aggregated runtime evidence report from a list of raw event objects/dicts.
    Identical events (same algorithm, operation, call_file, call_line, call_function) are aggregated into a single entry with a `count`.
    """
    total_events = len(raw_events)
    unique_algos_set = set()
    quantum_vuln_set = set()
    unmatched_count = 0

    aggregated_map: Dict[str, Dict[str, Any]] = {}

    for evt in raw_events:
        algo = evt.get("algorithm", "UNKNOWN")
        unique_algos_set.add(algo)

        if algo in QUANTUM_VULNERABLE_ALGORITHMS:
            quantum_vuln_set.add(algo)

        matched_id = evt.get("matched_finding_id") or evt.get("matchedFindingId")
        if not matched_id:
            unmatched_count += 1

        op = evt.get("operation", "other")
        lib = evt.get("library", "unknown")
        c_file = evt.get("call_file") or evt.get("callFile") or ""
        c_line = evt.get("call_line") if evt.get("call_line") is not None else evt.get("callLine", 0)
        c_func = evt.get("call_function") or evt.get("callFunction") or ""
        ts = evt.get("timestamp", "")

        group_key = f"{algo}|{op}|{lib}|{c_file}|{c_line}|{c_func}"

        if group_key not in aggregated_map:
            aggregated_map[group_key] = {
                "algorithm": algo,
                "operation": op,
                "library": lib,
                "key_size": evt.get("key_size") or evt.get("keySize"),
                "mode": evt.get("mode"),
                "padding": evt.get("padding"),
                "curve": evt.get("curve"),
                "call_file": c_file,
                "call_line": c_line,
                "call_function": c_func,
                "matched_finding_id": matched_id,
                "count": 1,
                "first_seen": ts,
                "last_seen": ts,
                "is_quantum_vulnerable": algo in QUANTUM_VULNERABLE_ALGORITHMS,
            }
        else:
            entry = aggregated_map[group_key]
            entry["count"] += 1
            entry["last_seen"] = ts
            if not entry["matched_finding_id"] and matched_id:
                entry["matched_finding_id"] = matched_id

    aggregated_events = list(aggregated_map.values())

    return {
        "run_id": run_id,
        "scan_id": scan_id,
        "language": language,
        "environment": environment,
        "summary": {
            "total_events": total_events,
            "unique_algorithms": sorted(list(unique_algos_set)),
            "quantum_vulnerable_algorithms": sorted(list(quantum_vuln_set)),
            "unmatched_events": unmatched_count,
        },
        "events": aggregated_events,
    }


def generate_report_from_jsonl(jsonl_path: str, run_id: str = "run-default") -> Dict[str, Any]:
    """Reads events from a JSONL file and generates a report."""
    events = []
    try:
        with open(jsonl_path, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    events.append(json.loads(line.strip()))
    except Exception:
        pass
    return generate_report_from_events(run_id=run_id, raw_events=events)

"""
CLI Entry Point for Crypto Time Machine (Feature 5).
Usage:
    python -m timemachine <repo_path> [--ref HEAD] [--json] [--out <file>]
"""

import argparse
import json
import os
import sys
from typing import Dict, Any

from timemachine.history import read_repository_history
from timemachine.scan_history import HistoryScanner
from timemachine.lifecycle import compute_findings_lifecycle, format_lifecycle_table
from timemachine.secrets import find_history_secrets
from timemachine.timeline import compute_repository_timeline, RISK_DEBT_WEIGHTS


def generate_remediation_priority_list(lifecycles, secrets) -> list:
    """Generates ordered, practical remediation priority recommendations."""
    remediations = []

    # 1. Critical: Leaked Secrets in Git History
    for sec in secrets:
        if sec.present_in_history:
            remediations.append(
                f"[CRITICAL] Leaked Key in History ({sec.file}): {sec.recommendation} Use 'git filter-repo --invert-paths --path {sec.file}' or BFG Repo-Cleaner to purge key blobs from Git object store."
            )

    # 2. High/Medium: Active weak findings
    for lc in lifecycles:
        if lc.still_present and lc.classification in ("weak", "both"):
            remediations.append(
                f"[HIGH] Remediate {lc.algorithm} in {lc.file} ({lc.function}): Upgrade to a secure quantum-safe or classically safe algorithm (e.g. SHA-256 / AES-256 / ML-KEM)."
            )

    # 3. Quantum-vulnerable active findings
    for lc in lifecycles:
        if lc.still_present and lc.classification == "quantum_vulnerable":
            remediations.append(
                f"[MEDIUM] Post-Quantum Migration Needed for {lc.algorithm} in {lc.file} ({lc.function}): Plan migration to NIST PQC standards (ML-KEM / ML-DSA)."
            )

    # 4. Remediated findings historical notes
    for lc in lifecycles:
        if not lc.still_present and lc.classification in ("weak", "both"):
            remediations.append(
                f"[INFO] Previously Remediated: {lc.algorithm} in {lc.file} was removed in C{lc.removed_commit_index}. Verify no regression in current codebase."
            )

    return remediations


def main():
    parser = argparse.ArgumentParser(
        description="Crypto Time Machine - Git History Cryptographic Vulnerability & Risk Exposure Scanner"
    )
    parser.add_argument("repo_path", help="Path to local Git repository")
    parser.add_argument("--ref", default="HEAD", help="Git ref to analyze up to (default: HEAD)")
    parser.add_argument("--json", action="store_true", help="Output raw JSON results")
    parser.add_argument("--out", help="Save output to specified JSON file")
    args = parser.parse_args()

    repo_path = os.path.abspath(args.repo_path)
    if not os.path.exists(repo_path):
        print(f"Error: Repository path '{repo_path}' does not exist.", file=sys.stderr)
        sys.exit(1)

    try:
        commits, repo_metrics = read_repository_history(repo_path, ref=args.ref)
    except Exception as e:
        print(f"Error reading repository history: {e}", file=sys.stderr)
        sys.exit(1)

    scanner = HistoryScanner()
    commit_map, scan_metrics = scanner.scan_commit_trajectory(repo_path, commits)
    lifecycles = compute_findings_lifecycle(commits, commit_map)
    secrets = find_history_secrets(repo_path, commits)
    timeline = compute_repository_timeline(commits, commit_map, secrets)
    remediations = generate_remediation_priority_list(lifecycles, secrets)

    result_dict = {
        "repository_summary": {
            "repo_path": repo_path,
            "ref": args.ref,
            "total_commits": len(commits),
            "first_commit_date": commits[0].author_date if commits else None,
            "last_commit_date": commits[-1].author_date if commits else None,
            "cache_hits": scan_metrics["cache_hits"],
            "cache_misses": scan_metrics["cache_misses"],
        },
        "findings_lifecycle": [lc.to_dict() for lc in lifecycles],
        "leaked_secrets": [s.to_dict() for s in secrets],
        "timeline": [pt.to_dict() for pt in timeline],
        "remediation_priorities": remediations,
    }

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(result_dict, f, indent=2)
        print(f"Results successfully saved to {args.out}")

    if args.json:
        sys.stdout.write(json.dumps(result_dict, indent=2))
        sys.stdout.write('\n')
        sys.exit(0)

    # Human-Readable CLI Output
    print("\n" + "=" * 80)
    print(" CRYPTO TIME MACHINE - GIT HISTORY RISK & LEAK ANALYSIS")
    print("=" * 80)
    print(f"Repository Path   : {repo_path}")
    print(f"Git Ref Analyzed  : {args.ref}")
    print(f"Total Commits     : {len(commits)}")
    print(f"Date Trajectory   : {commits[0].author_date} to {commits[-1].author_date}")
    print(f"Blob SHA Cache    : {scan_metrics['cache_hits']} hits, {scan_metrics['cache_misses']} misses")
    print("=" * 80)

    # 1. Risk Timeline Table
    print("\n[1] RISK TIMELINE & TECHNICAL DEBT BURNDOWN")
    print("-" * 80)
    tl_headers = ["Commit", "Date", "Weak", "Quantum", "Active Secret", "History Secret", "Debt Score"]
    tl_rows = [
        [
            f"C{pt.commit_index} ({pt.commit_hash[:7]})",
            pt.date[:10],
            str(pt.weak_count),
            str(pt.quantum_vulnerable_count),
            str(pt.active_leaked_secrets),
            str(pt.leaked_secrets_in_history),
            f"{pt.risk_debt:.1f}",
        ]
        for pt in timeline
    ]
    widths = [max(len(h), max(len(r[i]) for r in tl_rows)) for i, h in enumerate(tl_headers)]
    print(" | ".join(h.ljust(widths[i]) for i, h in enumerate(tl_headers)))
    print("-+-".join("-" * widths[i] for i in range(len(tl_headers))))
    for r in tl_rows:
        print(" | ".join(r[i].ljust(widths[i]) for i in range(len(tl_headers))))

    # 2. Findings Lifecycle Table
    print("\n[2] FINDINGS LIFECYCLE TABLE")
    print("-" * 80)
    print(format_lifecycle_table(lifecycles))

    # 3. Leaked Secrets Warning Section
    print("\n[3] LEAKED SECRETS & KEY MATERIAL IN HISTORY")
    print("-" * 80)
    if not secrets:
        print("No private keys or keystores detected in repository history.")
    else:
        for s in secrets:
            rem_idx_str = f"C{s.removed_commit_index}" if s.removed_commit_index else "Active (HEAD)"
            print(f"[!] LEAK DETECTED : {s.secret_type}")
            print(f"   File Path     : {s.file}")
            print(f"   Introduced    : C{s.added_commit_index} ({s.added_date})")
            print(f"   Removed       : {rem_idx_str}")
            print(f"   In History    : {s.present_in_history} (Reachable in Git blobs)")
            print(f"   Fingerprint   : {s.fingerprint} (Redacted SHA-256)")
            print(f"   Recommendation: {s.recommendation}")
            print()

    # 4. Remediation Priority List
    print("[4] PRACTICAL REMEDIATION PRIORITY LIST")
    print("-" * 80)
    for idx, rem in enumerate(remediations, 1):
        print(f" {idx}. {rem}")

    print("=" * 80 + "\n")
    sys.exit(0)


if __name__ == "__main__":
    main()

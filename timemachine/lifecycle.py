"""
Lifecycle Tracking and Exposure Analysis for Crypto Time Machine.
Computes introduction, removal, exposure counts, and days exposed for findings across Git commits.
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import List, Dict, Any, Optional
from timemachine.scan_history import NormalizedHistoryFinding
from timemachine.history import CommitInfo


@dataclass
class FindingLifecycle:
    finding_key: str
    algorithm: str
    file: str
    function: str
    classification: str
    introduced_commit: str
    introduced_commit_index: int
    introduced_date: str
    removed_commit: Optional[str]
    removed_commit_index: Optional[int]
    removed_date: Optional[str]
    exposure_commits: int
    exposure_days: int
    still_present: bool
    current_status: str  # "Active" | "Remediated" | "Reintroduced"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def parse_date(date_str: str) -> datetime:
    """Parses ISO date string, handling Z suffix."""
    ds = date_str.replace("Z", "+00:00")
    return datetime.fromisoformat(ds)


def compute_findings_lifecycle(
    commits: List[CommitInfo],
    commit_map: Dict[str, List[NormalizedHistoryFinding]]
) -> List[FindingLifecycle]:
    """
    Computes lifecycle exposure metrics across ordered commit trajectory.
    """
    finding_occurrences: Dict[str, List[NormalizedHistoryFinding]] = {}
    finding_metadata: Dict[str, NormalizedHistoryFinding] = {}

    for commit in commits:
        findings = commit_map.get(commit.commit_hash, [])
        for f in findings:
            if f.finding_key not in finding_occurrences:
                finding_occurrences[f.finding_key] = []
                finding_metadata[f.finding_key] = f
            finding_occurrences[f.finding_key].append(f)

    lifecycles: List[FindingLifecycle] = []

    # Process in order of introduction
    sorted_keys = sorted(
        finding_metadata.keys(),
        key=lambda k: (finding_occurrences[k][0].commit_index, k)
    )

    for fkey in sorted_keys:
        occurrences = finding_occurrences[fkey]
        first_finding = occurrences[0]
        last_finding = occurrences[-1]

        introduced_commit_hash = first_finding.commit_hash
        introduced_commit_idx = first_finding.commit_index
        introduced_date = first_finding.author_date

        head_commit = commits[-1]
        still_present = (last_finding.commit_hash == head_commit.commit_hash)

        if still_present:
            removed_commit_hash = None
            removed_commit_idx = None
            removed_date = None
            current_status = "Active"
            last_exposed_date = head_commit.author_date
        else:
            last_app_idx = last_finding.commit_index
            if last_app_idx < len(commits):
                removal_commit = commits[last_app_idx]  # 1-based index maps to next commit index
                removed_commit_hash = removal_commit.commit_hash
                removed_commit_idx = removal_commit.commit_index
                removed_date = removal_commit.author_date
                last_exposed_date = removal_commit.author_date
            else:
                removed_commit_hash = None
                removed_commit_idx = None
                removed_date = None
                last_exposed_date = head_commit.author_date
            current_status = "Remediated"

        exposure_commits = len(occurrences)

        d_intro = parse_date(introduced_date)
        d_last = parse_date(last_exposed_date)
        exposure_days = max(0, (d_last - d_intro).days)

        lc = FindingLifecycle(
            finding_key=fkey,
            algorithm=first_finding.algorithm,
            file=first_finding.file,
            function=first_finding.function,
            classification=first_finding.classification,
            introduced_commit=introduced_commit_hash,
            introduced_commit_index=introduced_commit_idx,
            introduced_date=introduced_date,
            removed_commit=removed_commit_hash,
            removed_commit_index=removed_commit_idx,
            removed_date=removed_date,
            exposure_commits=exposure_commits,
            exposure_days=exposure_days,
            still_present=still_present,
            current_status=current_status,
        )
        lifecycles.append(lc)

    return lifecycles


def format_lifecycle_table(lifecycles: List[FindingLifecycle]) -> str:
    """Formats findings lifecycle list into a human-readable ASCII table."""
    headers = ["Finding Key", "Algorithm", "File", "Introduced", "Removed", "Commits", "Days", "Status"]
    rows = []
    for lc in lifecycles:
        intro_str = f"C{lc.introduced_commit_index}"
        rem_str = f"C{lc.removed_commit_index}" if lc.removed_commit_index else "-"
        rows.append([
            lc.finding_key,
            lc.algorithm,
            lc.file,
            intro_str,
            rem_str,
            str(lc.exposure_commits),
            str(lc.exposure_days),
            lc.current_status
        ])

    if not rows:
        return "No findings found."

    col_widths = [max(len(h), max(len(r[i]) for r in rows)) for i, h in enumerate(headers)]
    header_line = " | ".join(h.ljust(col_widths[i]) for i, h in enumerate(headers))
    sep_line = "-+-".join("-" * col_widths[i] for i in range(len(headers)))
    row_lines = [" | ".join(r[i].ljust(col_widths[i]) for i in range(len(headers))) for r in rows]

    return "\n".join([header_line, sep_line] + row_lines)

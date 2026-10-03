"""
Risk Timeline and Technical Debt Burndown Analysis for Crypto Time Machine.
Calculates per-commit security metrics, risk debt scores, and burndown trajectory across repository history.
"""

from dataclasses import dataclass, asdict
from typing import List, Dict, Any
from timemachine.history import CommitInfo
from timemachine.scan_history import NormalizedHistoryFinding
from timemachine.secrets import LeakedSecret

# Illustrative Risk Debt Weights (configurable constants)
# Note: These weights are illustrative to quantify security debt over time, not an international standard.
RISK_DEBT_WEIGHTS = {
    "weak_finding": 3.0,
    "quantum_vulnerable": 2.0,
    "active_secret_leak": 10.0,
    "historical_secret_leak": 5.0,
}


@dataclass
class CommitTimelinePoint:
    commit_hash: str
    commit_index: int
    date: str
    author: str
    message: str
    total_findings: int
    weak_count: int
    quantum_vulnerable_count: int
    active_leaked_secrets: int
    leaked_secrets_in_history: int
    risk_debt: float
    findings_introduced: int
    findings_resolved: int

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def calculate_risk_debt(
    weak_count: int, qv_count: int, active_secrets: int, history_secrets: int
) -> float:
    """Computes risk debt score for a commit point based on configured weights."""
    return (
        weak_count * RISK_DEBT_WEIGHTS["weak_finding"]
        + qv_count * RISK_DEBT_WEIGHTS["quantum_vulnerable"]
        + active_secrets * RISK_DEBT_WEIGHTS["active_secret_leak"]
        + history_secrets * RISK_DEBT_WEIGHTS["historical_secret_leak"]
    )


def compute_repository_timeline(
    commits: List[CommitInfo],
    commit_map: Dict[str, List[NormalizedHistoryFinding]],
    leaked_secrets: List[LeakedSecret],
) -> List[CommitTimelinePoint]:
    """
    Computes per-commit risk metrics, risk debt, and introduced vs resolved burndown series.
    """
    timeline: List[CommitTimelinePoint] = []
    prev_finding_keys: set = set()

    for commit in commits:
        findings = commit_map.get(commit.commit_hash, [])
        finding_keys = {f.finding_key for f in findings}

        weak_count = sum(1 for f in findings if f.is_weak)
        qv_count = sum(1 for f in findings if f.is_quantum_vulnerable)
        total_findings = len({(f.file, f.algorithm) for f in findings})

        introduced = len(finding_keys - prev_finding_keys)
        resolved = len(prev_finding_keys - finding_keys)
        prev_finding_keys = finding_keys

        active_secrets = 0
        history_secrets = 0

        for sec in leaked_secrets:
            add_idx = sec.added_commit_index
            rem_idx = sec.removed_commit_index

            if rem_idx is None:
                if commit.commit_index >= add_idx:
                    active_secrets += 1
            else:
                if add_idx <= commit.commit_index < rem_idx:
                    active_secrets += 1
                elif commit.commit_index >= rem_idx and sec.present_in_history:
                    history_secrets += 1

        debt = calculate_risk_debt(weak_count, qv_count, active_secrets, history_secrets)

        pt = CommitTimelinePoint(
            commit_hash=commit.commit_hash,
            commit_index=commit.commit_index,
            date=commit.author_date,
            author=commit.author_name,
            message=commit.message,
            total_findings=total_findings,
            weak_count=weak_count,
            quantum_vulnerable_count=qv_count,
            active_leaked_secrets=active_secrets,
            leaked_secrets_in_history=history_secrets,
            risk_debt=debt,
            findings_introduced=introduced,
            findings_resolved=resolved,
        )
        timeline.append(pt)

    return timeline

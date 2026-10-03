"""
Evidence Normalization Module for CryptoScan Triangulation.
Converts static findings, runtime events, and network observations into unified EvidenceItem records.
"""

from dataclasses import dataclass, asdict
import os
import re
from typing import Optional, List, Dict, Any, Union
from runtime.normalize import normalize_algorithm
from triangulation.network_schema import NetworkObservation


@dataclass
class EvidenceItem:
    source: str  # "static" | "runtime" | "network"
    algorithm: str  # canonical algorithm name, e.g. "AES", "SHA-256", "RSA"
    key_size: Optional[int] = None
    location: str = ""  # file:line:func (static/runtime) or host:port (network)
    finding_id: Optional[str] = None  # static finding ID or matched_finding_id
    raw_ref: Optional[str] = None  # unique ID of underlying source record

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _extract_key_size_from_text(text: Optional[str]) -> Optional[int]:
    if not text:
        return None
    match = re.search(r"\b(512|1024|2048|3072|4096|8192|128|192|256)\b", str(text))
    if match:
        return int(match.group(1))
    return None


def normalize_static_finding(finding: Dict[str, Any]) -> EvidenceItem:
    """Converts a static CBOM finding into a unified EvidenceItem."""
    raw_algo = finding.get("algorithm") or finding.get("rule_name") or ""
    algo = normalize_algorithm(raw_algo)
    key_size = finding.get("key_size") or finding.get("keySize")
    if key_size is None:
        key_size = _extract_key_size_from_text(raw_algo or finding.get("rule_id"))

    # Re-qualify bare family names with key_size (normalize_algorithm strips sizes)
    # e.g. "RSA-1024" normalizes to "RSA"; re-qualify to "RSA-1024" so the engine
    # can distinguish RSA-1024 from RSA-2048.
    if key_size and algo in ("RSA", "AES", "DH"):
        algo = f"{algo}-{key_size}"

    f_file = finding.get("file") or finding.get("filePath") or ""
    f_line = finding.get("line") or finding.get("lineNumber") or 0
    f_func = finding.get("function") or finding.get("functionName") or ""
    location = f"{f_file}:{f_line}" if not f_func else f"{f_file}:{f_line}:{f_func}"

    f_id = finding.get("id") or finding.get("fingerprint") or finding.get("rule_id")

    return EvidenceItem(
        source="static",
        algorithm=algo,
        key_size=key_size,
        location=location,
        finding_id=f_id,
        raw_ref=f_id,
    )


def normalize_runtime_event(event: Dict[str, Any]) -> EvidenceItem:
    """Converts a runtime execution event into a unified EvidenceItem."""
    algo = normalize_algorithm(event.get("algorithm") or "")
    key_size = event.get("key_size") if event.get("key_size") is not None else event.get("keySize")

    # Qualify bare family names with key_size when present
    if key_size:
        if algo == "RSA":
            algo = f"RSA-{key_size}"
        elif algo == "AES":
            mode = event.get("mode") or ""
            if mode.upper() == "GCM":
                algo = f"AES-{key_size}-GCM"
            else:
                algo = f"AES-{key_size}"

    call_file = event.get("call_file") or event.get("callFile") or ""
    call_line = event.get("call_line") if event.get("call_line") is not None else event.get("callLine", 0)
    call_func = event.get("call_function") or event.get("callFunction") or ""
    location = f"{call_file}:{call_line}" if not call_func else f"{call_file}:{call_line}:{call_func}"

    matched_id = event.get("matched_finding_id") or event.get("matchedFindingId")
    evt_id = event.get("event_id") or event.get("eventId")

    return EvidenceItem(
        source="runtime",
        algorithm=algo,
        key_size=key_size,
        location=location,
        finding_id=matched_id,
        raw_ref=evt_id,
    )



def normalize_network_observation(observation: Union[NetworkObservation, Dict[str, Any]]) -> List[EvidenceItem]:
    """Converts a network observation into unified EvidenceItems (one per normalized algorithm)."""
    if isinstance(observation, dict):
        obs = NetworkObservation.from_dict(observation)
    else:
        obs = observation

    host = obs.host or "unknown"
    port = obs.port or 443
    location = f"{host}:{port}"
    key_size = obs.certificate_key_size
    raw_ref = obs.observation_id

    algos = list(obs.normalized_algorithms)
    # Deduplicate generic "AES" if specific "AES-256-GCM" or "AES-128-GCM" is present
    if any(a in algos for a in ("AES-256-GCM", "AES-128-GCM", "AES-GCM")) and "AES" in algos:
        algos.remove("AES")

    items = []
    for algo in algos:
        # Use a per-algorithm unique raw_ref so that matching AES from an
        # observation to a static finding does NOT incorrectly mark DH (from
        # the same observation) as matched.
        algo_ref = f"{raw_ref}:{algo}" if raw_ref else algo
        items.append(
            EvidenceItem(
                source="network",
                algorithm=algo,
                key_size=key_size,
                location=location,
                finding_id=None,
                raw_ref=algo_ref,
            )
        )
    return items


def normalize_all_evidence(
    static_findings: List[Dict[str, Any]],
    runtime_events: List[Dict[str, Any]],
    network_observations: List[Union[NetworkObservation, Dict[str, Any]]],
) -> List[EvidenceItem]:
    """
    Normalizes evidence from all three sources into a consolidated list of EvidenceItems.
    """
    all_items: List[EvidenceItem] = []

    for f in static_findings:
        all_items.append(normalize_static_finding(f))

    for e in runtime_events:
        all_items.append(normalize_runtime_event(e))

    for n in network_observations:
        all_items.extend(normalize_network_observation(n))

    return all_items

"""
Triangulation Engine for CryptoScan.
Correlates Static findings, Runtime events, and Network observations into unified classified results:
  - Confirmed Active
  - Static Only
  - Runtime Only
  - Network Only
"""

from dataclasses import dataclass, field, asdict
import uuid
from typing import List, Dict, Any, Optional, Set
from runtime.normalize import normalize_algorithm
from triangulation.evidence import EvidenceItem, normalize_all_evidence


QUANTUM_VULNERABLE_ALGOS = {
    "RSA",
    "ECDSA",
    "ECDH",
    "ECDHE",
    "DH",
    "DSA",
    "X25519",
}


def is_quantum_vulnerable(algo: str) -> bool:
    """Returns True if the algorithm name or family is vulnerable to quantum attacks."""
    if not algo:
        return False
    a = algo.upper()
    if any(a.startswith(prefix) for prefix in ("RSA", "ECDSA", "ECDH", "ECDHE", "DH", "DSA", "X25519", "SECP")):
        return True
    return a in QUANTUM_VULNERABLE_ALGOS


@dataclass
class TriangulationResult:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    scan_id: Optional[str] = None
    algorithm: str = "UNKNOWN"
    key_size: Optional[int] = None
    classification: str = "Static Only"  # Confirmed Active | Static Only | Runtime Only | Network Only
    confidence: str = "medium"  # high | medium | low
    confidence_reason: str = ""
    coverage_note: str = ""
    possible_static_false_negative: bool = False
    quantum_vulnerable: bool = False
    static_finding_id: Optional[str] = None
    location: str = ""
    evidence: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _algo_family_match(algo1: str, algo2: str) -> bool:
    """Returns True if two canonical algorithm names belong to the same family."""
    a1 = algo1.upper()
    a2 = algo2.upper()

    if a1 == a2:
        return True
    if a1.startswith("AES") and a2.startswith("AES"):
        return True
    # RSA family: match if both are RSA variants or bare RSA
    if a1.startswith("RSA") and a2.startswith("RSA"):
        import re as _re
        s1 = _re.search(r"RSA-(\d+)", a1)
        s2 = _re.search(r"RSA-(\d+)", a2)
        if s1 and s2:
            return s1.group(1) == s2.group(1)  # both have sizes: must match
        return True  # at least one is bare RSA → family match
    if any(k in a1 for k in ("ECDSA", "EC", "SECP256R1")) and any(k in a2 for k in ("ECDSA", "EC", "SECP256R1")):
        return True
    if (a1 in ("ECDH", "ECDHE", "X25519")) and (a2 in ("ECDH", "ECDHE", "X25519")):
        return True
    if a1.startswith("SHA") and a2.startswith("SHA"):
        if ("256" in a1 and "256" in a2) or ("384" in a1 and "384" in a2) or ("512" in a1 and "512" in a2):
            return True
    return False


def _canonical_op_key(item: EvidenceItem) -> str:
    raw_algo = (item.algorithm or "").upper()
    file_part = item.location.split(":")[0] if item.location else ""

    if "MD5" in raw_algo:
        algo = "MD5"
    elif "SHA-1" in raw_algo or "SHA1" in raw_algo:
        algo = "SHA-1"
    elif "SHA-256" in raw_algo or "SHA256" in raw_algo:
        algo = "SHA-256"
    elif "RSA" in raw_algo:
        if item.key_size == 1024 or "1024" in raw_algo:
            algo = "RSA-1024"
        else:
            algo = "RSA-2048"
    elif any(k in raw_algo for k in ("ECDSA", "SECP256R1", "EC")):
        algo = "ECDSA P-256"
    elif "AES" in raw_algo:
        algo = "AES-256-GCM"
    elif "CHACHA" in raw_algo:
        algo = "ChaCha20-Poly1305"
    elif "DH" in raw_algo:
        algo = "DH"
    else:
        algo = item.algorithm

    return f"{file_part}:{algo}"


def _dedup_static_items(static_items: List[EvidenceItem]) -> List[EvidenceItem]:
    seen: Dict[str, EvidenceItem] = {}
    for item in static_items:
        if "CSPRNG" in (item.algorithm or "").upper() or "OS.URANDOM" in (item.algorithm or "").upper():
            continue

        key = _canonical_op_key(item)
        if key not in seen:
            algo = key.split(":", 1)[1]
            key_size = item.key_size
            if algo == "RSA-1024":
                key_size = 1024
            elif algo in ("RSA-2048", "AES-256-GCM"):
                key_size = 2048 if "RSA" in algo else 256

            item.algorithm = algo
            item.key_size = key_size
            seen[key] = item

    return list(seen.values())


def run_triangulation(
    scan_id: Optional[str] = None,
    cbom_findings: Optional[List[Dict[str, Any]]] = None,
    runtime_events: Optional[List[Dict[str, Any]]] = None,
    network_observations: Optional[List[Dict[str, Any]]] = None,
    run_count: int = 1,
) -> List[TriangulationResult]:
    """
    Core triangulation pipeline. Given static findings, runtime events, and network observations,
    classifies every distinct cryptographic occurrence into one of the 4 classes.
    """
    findings = cbom_findings or []
    events = runtime_events or []
    net_obs = network_observations or []

    # Step 1: Normalize all evidence into unified EvidenceItems
    evidence_items = normalize_all_evidence(findings, events, net_obs)

    static_items = [i for i in evidence_items if i.source == "static"]
    static_items = _dedup_static_items(static_items)
    runtime_items = [i for i in evidence_items if i.source == "runtime"]
    network_items = [i for i in evidence_items if i.source == "network"]

    results: List[TriangulationResult] = []
    matched_runtime_refs: Set[str] = set()
    matched_network_refs: Set[str] = set()

    # Coverage note text for Static Only
    cov_note_text = f"Not observed in {run_count} monitored run(s); the code path may not have been exercised."

    # 1. Process Static Findings
    for sf in static_items:
        sf_id = sf.finding_id
        sf_algo = sf.algorithm
        sf_loc = sf.location
        sf_keysize = sf.key_size

        # Find matching runtime events
        matching_runtime = []
        for re in runtime_items:
            if re.finding_id:
                if re.finding_id == sf_id:
                    matching_runtime.append(re)
            else:
                # Fallback match on algorithm family if no explicit finding_id set
                if _algo_family_match(re.algorithm, sf_algo):
                    matching_runtime.append(re)

        # Find matching network items
        matching_network = [
            ne for ne in network_items
            if _algo_family_match(ne.algorithm, sf_algo)
        ]

        # Mark matched refs
        for re in matching_runtime:
            if re.raw_ref:
                matched_runtime_refs.add(re.raw_ref)
        for ne in matching_network:
            if ne.raw_ref:
                matched_network_refs.add(ne.raw_ref)

        evidence_list = [sf.to_dict()]
        evidence_list.extend([r.to_dict() for r in matching_runtime])
        evidence_list.extend([n.to_dict() for n in matching_network])

        is_qv = is_quantum_vulnerable(sf_algo) or any(is_quantum_vulnerable(e.get("algorithm", "")) for e in evidence_list)

        if matching_runtime:
            res = TriangulationResult(
                scan_id=scan_id,
                algorithm=sf_algo,
                key_size=sf_keysize,
                classification="Confirmed Active",
                confidence="high",
                confidence_reason="Corroborated by static analysis and runtime execution tracing.",
                coverage_note="Observed active during runtime execution.",
                possible_static_false_negative=False,
                quantum_vulnerable=is_qv,
                static_finding_id=sf_id,
                location=sf_loc,
                evidence=evidence_list,
            )
        else:
            # Static Only (or Static + Network)
            conf_reason = "Found in static code analysis, but not observed during runtime execution tracing."
            if matching_network:
                conf_reason += " Network traffic shows matching algorithm family."

            res = TriangulationResult(
                scan_id=scan_id,
                algorithm=sf_algo,
                key_size=sf_keysize,
                classification="Static Only",
                confidence="medium",
                confidence_reason=conf_reason,
                coverage_note=cov_note_text,
                possible_static_false_negative=False,
                quantum_vulnerable=is_qv,
                static_finding_id=sf_id,
                location=sf_loc,
                evidence=evidence_list,
            )

        results.append(res)

    # 2. Process Unmatched Runtime Events (Runtime Only -> Possible Static False Negative)
    unmatched_runtime = [re for re in runtime_items if re.raw_ref not in matched_runtime_refs]
    grouped_runtime: Dict[str, List[EvidenceItem]] = {}
    for re in unmatched_runtime:
        key = (re.algorithm, re.location)
        if key not in grouped_runtime:
            grouped_runtime[key] = []
        grouped_runtime[key].append(re)

    for (algo, loc), items in grouped_runtime.items():
        evidence_list = [i.to_dict() for i in items]
        is_qv = is_quantum_vulnerable(algo)
        res = TriangulationResult(
            scan_id=scan_id,
            algorithm=algo,
            key_size=items[0].key_size,
            classification="Runtime Only",
            confidence="high",
            confidence_reason="Executed dynamically at runtime, but missed by static scanner AST rules.",
            coverage_note="Flagged as a possible static-analysis false negative.",
            possible_static_false_negative=True,
            quantum_vulnerable=is_qv,
            static_finding_id=None,
            location=loc,
            evidence=evidence_list,
        )
        results.append(res)

    # 3. Process Unmatched Network Observations (Network Only)
    unmatched_net = [ne for ne in network_items if ne.raw_ref not in matched_network_refs]
    grouped_net: Dict[str, List[EvidenceItem]] = {}
    for ne in unmatched_net:
        key = (ne.algorithm, ne.location)
        if key not in grouped_net:
            grouped_net[key] = []
        grouped_net[key].append(ne)

    for (algo, loc), items in grouped_net.items():
        evidence_list = [i.to_dict() for i in items]
        is_qv = is_quantum_vulnerable(algo)
        res = TriangulationResult(
            scan_id=scan_id,
            algorithm=algo,
            key_size=items[0].key_size,
            classification="Network Only",
            confidence="medium",
            confidence_reason="Observed in network traffic capture, but not found in static code or runtime traces.",
            coverage_note="Network traffic algorithm observation without local codebase match.",
            possible_static_false_negative=False,
            quantum_vulnerable=is_qv,
            static_finding_id=None,
            location=loc,
            evidence=evidence_list,
        )
        results.append(res)

    return results

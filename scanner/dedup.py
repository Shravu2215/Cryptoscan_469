"""
Dedup engine.

Two distinct bugs this exists to fix:

1. Exact duplicates: the same (file, line, rule_id) emitted twice (e.g. a
   generic catch-all rule re-firing on a call site a specific rule already
   covered, or any accidental double-emission in an analyzer). Collapsed to one.

2. Generic-vs-specific overlap: a specific rule ("aes-hardcoded-key",
   "md5-weak-password-hash", "insecure-rng", ...) and a generic catch-all rule
   ("aes-encryption", "md5-hashing") both fire on the same call site. The
   generic one is suppressed - most-specific-rule-wins, one finding per
   (file, line, call-site) unless the findings represent genuinely distinct
   vulnerability classes on the same line (e.g. hardcoded-key AND
   missing-aead on one call - both are kept, since both are real, different,
   independently-fixable issues; only the *generic* AES-encryption note is
   redundant once either fires).

3. Cross-layer duplicate: AST and regex layers independently detect the SAME
   algorithm at the SAME location. The canonical (file, line, algo_norm) key
   collapses these to the highest-specificity finding, and if 2+ layers agree,
   confidence is promoted to CONFIRMED.
"""
import re as _re
from typing import List
from .models import Finding, Confidence


def _normalize_algo(algorithm: str) -> str:
    """Produce a stable canonical algorithm name used for cross-layer dedup.

    Strips key-size suffixes and mode-qualifiers so that e.g.
    'AES-256-CBC missing-aead' and 'AES-CBC' both map to 'AES'.
    This is intentionally lossy — we only use it as a dedup key, not display.
    """
    if not algorithm:
        return "unknown"
    # Remove trailing descriptive suffixes like " missing-aead", " hardcoded-key"
    algo = algorithm.split(" ")[0]
    # Strip key sizes and modes: AES-256-GCM → AES, RSA-2048 → RSA
    algo = _re.sub(r"[-_]?\d{2,4}([-_].*)?$", "", algo, flags=_re.IGNORECASE)
    # Normalize separators
    algo = _re.sub(r"[-_/]", "-", algo.strip()).upper()
    return algo or "unknown"


def dedup(findings: List[Finding]) -> List[Finding]:
    # Pass 1: collapse exact duplicates (same file + line + rule_id).
    seen = {}
    for f in findings:
        key = (f.file, f.line, f.rule_id)
        if key not in seen:
            seen[key] = f
    deduped = list(seen.values())

    # Pass 1b: collapse duplicate findings from the SAME detection layer on the same line
    # with same algorithm family and category. Keep the highest-specificity / most specific name.
    seen_algo = {}
    for f in deduped:
        algo_norm = _normalize_algo(f.algorithm)
        key = (f.file, f.line, f.detection_method, algo_norm, f.category)
        if key not in seen_algo:
            seen_algo[key] = f
        else:
            existing = seen_algo[key]
            # Prefer higher specificity, or longer/more specific algorithm name if specificity tied
            is_better = (f.specificity > existing.specificity) or (
                f.specificity == existing.specificity and len(f.algorithm) > len(existing.algorithm)
            )
            winner = f if is_better else existing
            loser = existing if is_better else f

            if not getattr(winner, "mode", None) and getattr(loser, "mode", None):
                winner.mode = loser.mode
            if not getattr(winner, "exposure_signals", None) and getattr(loser, "exposure_signals", None):
                winner.exposure_signals = loser.exposure_signals
            if not getattr(winner, "exposure_rationale", None) and getattr(loser, "exposure_rationale", None):
                winner.exposure_rationale = loser.exposure_rationale
            seen_algo[key] = winner
    deduped = list(seen_algo.values())

    # Pass 1c: Cross-layer dedup — collapse findings where AST, regex, and entropy
    # independently detected the SAME algorithm family at the SAME (file, line).
    # Keep the highest-specificity / most specific finding name and promote confidence.
    cross_layer: dict = {}
    for f in deduped:
        algo_norm = _normalize_algo(f.algorithm)
        if f.generic:
            continue  # handled in Pass 2
        key = (f.file, f.line, algo_norm)
        if key not in cross_layer:
            cross_layer[key] = {"winner": f, "layer_count": 1}
        else:
            existing = cross_layer[key]["winner"]
            cross_layer[key]["layer_count"] += 1
            is_better = (f.specificity > existing.specificity) or (
                f.specificity == existing.specificity and len(f.algorithm) > len(existing.algorithm)
            )
            winner = f if is_better else existing
            loser = existing if is_better else f

            if not getattr(winner, "mode", None) and getattr(loser, "mode", None):
                winner.mode = loser.mode
            if not getattr(winner, "exposure_signals", None) and getattr(loser, "exposure_signals", None):
                winner.exposure_signals = loser.exposure_signals
            if not getattr(winner, "exposure_rationale", None) and getattr(loser, "exposure_rationale", None):
                winner.exposure_rationale = loser.exposure_rationale
            cross_layer[key]["winner"] = winner

    # Re-assemble: keep all generic findings and non-cross-layer-conflicting findings,
    # then add the winners (with promoted confidence where warranted).
    generic_findings = [f for f in deduped if f.generic]
    non_generic = [f for f in deduped if not f.generic]

    # Determine which non-generic findings were NOT part of a cross-layer merge
    cross_layer_files_lines_algos = set(cross_layer.keys())
    surviving_non_generic = []
    for f in non_generic:
        algo_norm = _normalize_algo(f.algorithm)
        key = (f.file, f.line, algo_norm)
        if key in cross_layer:
            winner = cross_layer[key]["winner"]
            layer_count = cross_layer[key]["layer_count"]
            if f is winner:
                # Promote confidence if multiple layers agreed
                if layer_count >= 2 and winner.confidence != Confidence.CONFIRMED:
                    winner.confidence = Confidence.CONFIRMED
                surviving_non_generic.append(winner)
        else:
            surviving_non_generic.append(f)

    deduped = surviving_non_generic + generic_findings

    # Pass 2: group by (file, line); drop generic findings if a specific one
    # exists for the same call site / line.
    by_site = {}
    for f in deduped:
        by_site.setdefault((f.file, f.line), []).append(f)

    out: List[Finding] = []
    for site, group in by_site.items():
        has_specific = any(not g.generic for g in group)
        has_kms = any(g.category in {"Cloud KMS / HSM", "Cloud KMS", "Hardware Module"} for g in group)
        max_spec_by_cat = {}
        for g in group:
            max_spec_by_cat[g.category] = max(max_spec_by_cat.get(g.category, 0), g.specificity)

        for g in group:
            if g.generic and has_specific:
                continue
            if g.generic and g.specificity < max_spec_by_cat.get(g.category, 0):
                continue
            # Drop hardcoded-secret if we found a KMS/HSM reference on the same line
            if has_kms and g.category in {"hardcoded-secret", "secret"} and g.category not in {"Cloud KMS / HSM", "Cloud KMS", "Hardware Module"}:
                continue
            out.append(g)

    out.sort(key=lambda f: (f.file, f.line, -f.severity.rank, -f.specificity))
    return out

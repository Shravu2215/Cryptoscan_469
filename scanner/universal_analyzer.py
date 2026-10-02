import os
import re
import json
from typing import List, Dict, Any, Optional

from .models import Finding, Severity, QuantumRisk, Confidence
from .plugins.detector import LanguageDetector
from .plugins.registry import PluginRegistry

class UniversalAnalyzer:
    """
    Universal Multi-Language Engine.
    Coordinates language detection, parser adapters, and declarative rules across:
    TypeScript, Java, Go, C/C++, C#, Rust, PHP, Ruby, Kotlin.
    """
    def __init__(self):
        self.rules = self._load_rules()
        self.coverage_stats = {
            "scanned": 0,
            "skipped": 0,
            "unsupported": 0,
            "unparsed": 0,
            "by_language": {}
        }

    def _load_rules(self) -> Dict[str, List[Dict[str, Any]]]:
        rules_dir = os.path.join(os.path.dirname(__file__), "rules")
        loaded = {}
        if os.path.exists(rules_dir):
            for fn in os.listdir(rules_dir):
                if fn.endswith(".json"):
                    lang = fn[:-5]
                    with open(os.path.join(rules_dir, fn), "r", encoding="utf-8") as f:
                        try:
                            loaded[lang] = json.load(f)
                        except Exception:
                            loaded[lang] = []
        return loaded

    def analyze(self, filepath: str, source: str) -> List[Finding]:
        findings: List[Finding] = []
        lang = LanguageDetector.detect(filepath, source)

        if not lang:
            self.coverage_stats["unsupported"] += 1
            return findings

        # Track language coverage
        if lang not in self.coverage_stats["by_language"]:
            self.coverage_stats["by_language"][lang] = {"files": 0, "findings": 0}
        self.coverage_stats["by_language"][lang]["files"] += 1
        self.coverage_stats["scanned"] += 1

        adapter = PluginRegistry.get_adapter(lang)
        try:
            nodes = adapter.parse_nodes(filepath, source)
        except Exception:
            self.coverage_stats["unparsed"] += 1
            return findings

        # Apply declarative rules for language + common rules
        lang_rules = self.rules.get(lang, [])
        lines = source.split("\n")

        for rule in lang_rules:
            pat_str = rule.get("pattern")
            if not pat_str:
                continue
            try:
                regex = re.compile(pat_str, re.IGNORECASE)
            except Exception:
                continue

            for idx, line in enumerate(lines, start=1):
                if line.strip().startswith(("//", "#", "/*", "*")):
                    continue
                match = regex.search(line)
                if match:
                    # Map severity & quantum risk
                    sev_str = rule.get("severity", "Medium")
                    sev = getattr(Severity, sev_str.upper(), Severity.MEDIUM)
                    
                    qrisk_str = rule.get("quantum_risk", "Classical Risk")
                    if qrisk_str == "Quantum-Broken":
                        qrisk = QuantumRisk.QUANTUM_BROKEN
                    elif qrisk_str == "Quantum-Weakened":
                        qrisk = QuantumRisk.QUANTUM_WEAKENED
                    elif qrisk_str == "Safe":
                        qrisk = QuantumRisk.SAFE
                    else:
                        qrisk = QuantumRisk.CLASSICAL_RISK

                    f = Finding(
                        file=filepath,
                        line=idx,
                        column=match.start() + 1,
                        language=lang,
                        rule_id=rule.get("id", f"{lang}-crypto-finding"),
                        rule_name=rule.get("name", rule.get("id", "Crypto Rule")),
                        category=rule.get("category", "hash"),
                        algorithm=rule.get("algorithm", "UNKNOWN"),
                        severity=sev,
                        quantum_risk=qrisk,
                        message=rule.get("message", "Cryptographic issue detected."),
                        recommendation=rule.get("recommendation", "Review cryptography usage."),
                        code_snippet=line.strip()[:160],
                        specificity=rule.get("specificity", 2),
                        confidence=Confidence.LIKELY,
                        mode=rule.get("mode"),
                        library=rule.get("library", "")
                    )
                    findings.append(f)
                    self.coverage_stats["by_language"][lang]["findings"] += 1

        return findings

    def get_coverage_stats(self) -> Dict[str, Any]:
        return self.coverage_stats

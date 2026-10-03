"""
policy.py - Policy configuration loader and evaluator for Crypto Ratchet Gate.

Defaults:
  max_new_quantum_vulnerable: 0
  max_total_quantum_vulnerable: "baseline"
  prohibited_algorithms: ["MD5", "SHA-1", "DES", "3DES", "RC4", "RSA<2048", "DH<2048"]
  fail_on_prohibited_in_new_code: true
  waiver_max_days: 90
  waiver_warn_days: 14
  allow_decrease: true
"""

import os
import re
from typing import Dict, Any, List, Optional

try:
    import yaml
except ImportError:
    yaml = None


DEFAULT_POLICY = {
    "max_new_quantum_vulnerable": 0,
    "max_total_quantum_vulnerable": "baseline",
    "prohibited_algorithms": ["MD5", "SHA-1", "DES", "3DES", "RC4", "RSA<2048", "DH<2048"],
    "fail_on_prohibited_in_new_code": True,
    "waiver_max_days": 90,
    "waiver_warn_days": 14,
    "allow_decrease": True,
}


def simple_yaml_fallback(text: str) -> Dict[str, Any]:
    """Lightweight fallback parser for basic YAML if PyYAML is not available."""
    res = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" in line:
            k, v = line.split(":", 1)
            k = k.strip()
            v = v.strip()
            if v.startswith("[") and v.endswith("]"):
                items = [x.strip().strip("'\"") for x in v[1:-1].split(",") if x.strip()]
                res[k] = items
            elif v.lower() in ("true", "yes"):
                res[k] = True
            elif v.lower() in ("false", "no"):
                res[k] = False
            elif v.isdigit():
                res[k] = int(v)
            else:
                res[k] = v.strip("'\"")
    return res


def load_policy(policy_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Loads policy from the given path (or .cryptoscan/policy.yaml),
    filling in sensible defaults for any missing configuration keys.
    """
    policy = dict(DEFAULT_POLICY)

    if not policy_path:
        candidates = [
            ".cryptoscan/policy.yaml",
            ".cryptoscan/policy.yml",
            ".cryptoscan/policy.json",
        ]
        for c in candidates:
            if os.path.exists(c):
                policy_path = c
                break

    if policy_path and os.path.exists(policy_path):
        try:
            with open(policy_path, "r", encoding="utf-8") as f:
                content = f.read()
            if yaml:
                data = yaml.safe_load(content) or {}
            else:
                data = simple_yaml_fallback(content)

            if isinstance(data, dict):
                for k, v in data.items():
                    if k in DEFAULT_POLICY:
                        policy[k] = v
        except Exception as e:
            raise ValueError(f"Error parsing policy file '{policy_path}': {e}")

    # Validate types
    try:
        policy["max_new_quantum_vulnerable"] = int(policy["max_new_quantum_vulnerable"])
    except (ValueError, TypeError):
        policy["max_new_quantum_vulnerable"] = 0

    try:
        policy["waiver_max_days"] = int(policy["waiver_max_days"])
    except (ValueError, TypeError):
        policy["waiver_max_days"] = 90

    try:
        policy["waiver_warn_days"] = int(policy["waiver_warn_days"])
    except (ValueError, TypeError):
        policy["waiver_warn_days"] = 14

    policy["fail_on_prohibited_in_new_code"] = bool(policy.get("fail_on_prohibited_in_new_code", True))
    policy["allow_decrease"] = bool(policy.get("allow_decrease", True))

    if not isinstance(policy.get("prohibited_algorithms"), list):
        policy["prohibited_algorithms"] = DEFAULT_POLICY["prohibited_algorithms"]

    return policy


def matches_prohibited(algo_spec: str, asset_algo: str, asset_key_size: Any) -> bool:
    """
    Checks if an asset matches a prohibited algorithm rule.
    Rules can be exact/prefix names like 'MD5', 'SHA-1', 'DES' or with key size like 'RSA<2048'.
    """
    spec = algo_spec.strip().upper()
    algo = (asset_algo or "").strip().upper()

    # Case 1: Key size comparison like "RSA<2048" or "DH<2048"
    m = re.match(r"^([A-Z0-9_-]+)\s*<\s*(\d+)$", spec)
    if m:
        target_name, min_size_str = m.group(1), m.group(2)
        min_size = int(min_size_str)
        if target_name in algo:
            # Check key size
            if asset_key_size is not None and str(asset_key_size).isdigit():
                return int(asset_key_size) < min_size
            # If algo string contains a key size e.g. "RSA-1024"
            size_m = re.search(r"(\d+)", algo)
            if size_m:
                return int(size_m.group(1)) < min_size
            # If no key size is specified but it's RSA/DH, conservative check
            return False
        return False

    # Case 2: Direct name matching
    # Normalize comparison: "SHA-1" matches "SHA1" or "SHA-1"
    spec_clean = re.sub(r"[^A-Z0-9]", "", spec)
    algo_clean = re.sub(r"[^A-Z0-9]", "", algo)

    # Prohibited matches if whole token or exact match
    if spec_clean == algo_clean:
        return True
    if spec in algo.split("-") or spec in algo.split("_") or spec in algo.split():
        return True
    return False


def check_prohibited_algorithms(prohibited_list: List[str], asset: Dict[str, Any]) -> Optional[str]:
    """
    Returns the matching prohibited algorithm specification if the asset violates it, else None.
    """
    algo = asset.get("algorithm") or ""
    key_size = asset.get("key_size")
    for spec in prohibited_list:
        if matches_prohibited(spec, algo, key_size):
            return spec
    return None

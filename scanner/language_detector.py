"""
language_detector.py – Per-file language detection for CryptoScan.

Detection order (deterministic, read-only, never executes anything):
  1. Path-pattern overrides (e.g. .github/workflows/ → GitHub Actions)
  2. Exact filename match (Dockerfile, Makefile, .env, nginx.conf, ...)
  3. Filename-prefix match (Dockerfile., requirements, .env.)
  4. File-extension match (.py → Python, .crt → Certificate, ...)
  5. Shebang on first line (#!/usr/bin/env python3 → Python)
  6. Content heuristics (PEM header, YAML/JSON structure, ...)
  7. Fallback: "Unknown"

All rules come from scanner/languages.json — no language logic is
hardcoded here.  Adding a new language is a one-line change in the JSON.

Determinism guarantee: given the same (filepath, source) the function
always returns the same string.
"""

from __future__ import annotations

import json
import os
import re
from functools import lru_cache
from typing import Optional

_REGISTRY_PATH = os.path.join(os.path.dirname(__file__), "languages.json")


@lru_cache(maxsize=1)
def _load_registry() -> dict:
    with open(_REGISTRY_PATH, "r", encoding="utf-8") as fh:
        return json.load(fh)


def detect_language(filepath: str, source: Optional[str] = None) -> str:
    """
    Return the human-readable display name for the language/file-type
    of the file at *filepath*.

    Args:
        filepath: Absolute or relative path to the file being scanned.
        source:   Optional text content of the file (used for shebang and
                  content-heuristic checks).  Pass None to skip those steps.

    Returns:
        A display name such as "Python", "Dotenv", "Certificate",
        "GitHub Actions", or "Unknown".  Never returns None or "".
    """
    reg = _load_registry()
    norm_path = filepath.replace("\\", "/")
    basename   = os.path.basename(norm_path)
    _, ext     = os.path.splitext(basename)
    ext_lower  = ext.lower()
    bn_lower   = basename.lower()

    # ── 1. Path-pattern overrides ─────────────────────────────────────────────
    for rule in reg.get("path_patterns", []):
        if rule["path_contains"] in norm_path:
            return rule["language"]

    # Special: .yml/.yaml files inside .github/workflows/ → GitHub Actions
    # (already handled above via path_patterns but kept explicit for clarity)

    # ── 2. Exact filename match ───────────────────────────────────────────────
    if basename in reg["exact_filenames"]:
        return reg["exact_filenames"][basename]
    if bn_lower in reg["exact_filenames"]:
        return reg["exact_filenames"][bn_lower]

    # ── 3. Filename-prefix match ──────────────────────────────────────────────
    for prefix, lang in reg.get("exact_filename_prefix_patterns", {}).items():
        if basename.startswith(prefix) or bn_lower.startswith(prefix.lower()):
            return lang

    # ── 4. File-extension match ───────────────────────────────────────────────
    if ext and ext in reg["extensions"]:
        return reg["extensions"][ext]
    if ext_lower and ext_lower in reg["extensions"]:
        return reg["extensions"][ext_lower]

    # From here we need source text
    if not source:
        return "Unknown"

    # ── 5. Shebang ────────────────────────────────────────────────────────────
    first_line = source.split("\n", 1)[0].strip()
    if first_line.startswith("#!"):
        shebang = first_line[2:].strip()
        # Strip env-style: #!/usr/bin/env python3
        parts = shebang.replace("/usr/bin/env", "").split()
        interpreter = os.path.basename(parts[0]).split()[0] if parts else ""
        # Strip version suffix: python3 → python3, python3.11 → python3
        interp_clean = re.sub(r"[\d.]+$", "", interpreter)
        for key, lang in reg.get("shebang_patterns", {}).items():
            if interp_clean == key or interpreter == key:
                return lang
        # Final fallback on raw basename
        for key, lang in reg.get("shebang_patterns", {}).items():
            if key in shebang:
                return lang

    # ── 6. Content heuristics ─────────────────────────────────────────────────
    sample = source[:2000]  # only inspect first 2 KB — fast & safe
    for rule in reg.get("content_heuristics", []):
        try:
            if re.search(rule["pattern"], sample, re.MULTILINE):
                return rule["language"]
        except re.error:
            pass

    return "Unknown"

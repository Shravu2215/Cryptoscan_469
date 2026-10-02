"""
security.py – Scanner-side resource limits and safety checks
─────────────────────────────────────────────────────────────
Hostile-Repository Hardening, Requirements 1, 3, 8.

All limits are configurable via environment variables.
Skipped / oversized / binary / minified / timed-out files are reported with
a reason in the file manifest rather than silently dropped.
"""

from __future__ import annotations

import os
import re
import signal
import time
import threading
from typing import Optional

# ── Configurable limits (env overrides, sane defaults) ───────────────────────
class Limits:
    # Per-file max size to read (bytes); default 10 MB
    MAX_FILE_SIZE_BYTES: int = int(os.environ.get("SCANNER_MAX_FILE_SIZE_MB", "10")) * 1024 * 1024

    # Max total bytes read across the whole scan; default 512 MB
    MAX_TOTAL_SIZE_BYTES: int = int(os.environ.get("SCANNER_MAX_TOTAL_SIZE_MB", "512")) * 1024 * 1024

    # Max number of files scanned; default 50 000
    MAX_FILE_COUNT: int = int(os.environ.get("SCANNER_MAX_FILES", "50000"))

    # Max AST depth (Python/JS) to avoid stack overflow attacks
    MAX_AST_DEPTH: int = int(os.environ.get("SCANNER_MAX_AST_DEPTH", "50"))

    # Max AST node count per file
    MAX_AST_NODES: int = int(os.environ.get("SCANNER_MAX_AST_NODES", "100000"))

    # Per-file analysis timeout (seconds); default 30 s
    PER_FILE_TIMEOUT_SEC: float = float(os.environ.get("SCANNER_PER_FILE_TIMEOUT_SEC", "30"))

    # Whole-scan timeout (seconds); default 600 s (10 min)
    SCAN_TIMEOUT_SEC: float = float(os.environ.get("SCANNER_SCAN_TIMEOUT_SEC", "600"))

    # Maximum line length for minification detection
    MAX_LINE_LEN_MINIFIED: int = int(os.environ.get("SCANNER_MAX_LINE_LEN", "2000"))

    # Maximum snippet length returned in findings
    MAX_SNIPPET_LENGTH: int = int(os.environ.get("SCANNER_MAX_SNIPPET_LENGTH", "500"))


# ── Minified / binary file detection ─────────────────────────────────────────

def is_binary_content(content: bytes, sample: int = 8192) -> bool:
    """True if the first `sample` bytes look like binary data."""
    chunk = content[:sample]
    if b"\x00" in chunk:
        return True
    # Heuristic: > 30 % non-text bytes → binary
    non_text = sum(1 for b in chunk if b < 0x09 or (0x0e <= b < 0x20) or b >= 0x80)
    return len(chunk) > 0 and (non_text / len(chunk)) > 0.30


def is_minified_source(text: str) -> bool:
    """
    Returns True if the file looks like minified code.
    We check:
      1. Any line is excessively long
      2. < 5 % of content is newlines (very low line count relative to size)
    """
    if not text:
        return False
    lines = text.split("\n")
    if any(len(line) > Limits.MAX_LINE_LEN_MINIFIED for line in lines):
        return True
    if len(text) > 10_000 and len(lines) < max(5, len(text) // 1000):
        return True
    return False


def is_safe_path(path: str, scan_root: str) -> bool:
    """
    Returns True only if `path` is safely inside `scan_root`.
    Blocks path traversal via realpath resolution.
    """
    try:
        real_root = os.path.realpath(scan_root)
        real_path = os.path.realpath(path)
        return real_path.startswith(real_root + os.sep) or real_path == real_root
    except OSError:
        return False


# ── Per-file timeout context manager ─────────────────────────────────────────

class _TimeoutError(Exception):
    pass


class FileTimeout:
    """
    Cross-platform per-file timeout.

    Uses SIGALRM on Unix (signal-based, zero overhead).
    Falls back to a threading.Timer on Windows.
    """

    def __init__(self, seconds: float):
        self.seconds = seconds
        self._use_signal = hasattr(signal, "SIGALRM")
        self._timer: Optional[threading.Timer] = None
        self._timed_out = False

    def _raise(self, *_):
        self._timed_out = True
        raise _TimeoutError(f"File analysis timed out after {self.seconds}s")

    def __enter__(self):
        if self._use_signal:
            signal.signal(signal.SIGALRM, self._raise)
            signal.setitimer(signal.ITIMER_REAL, self.seconds)
        else:
            # Windows: fire from background thread
            self._timer = threading.Timer(self.seconds, self._raise)
            self._timer.daemon = True
            self._timer.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._use_signal:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, signal.SIG_DFL)
        elif self._timer:
            self._timer.cancel()
        # Do not suppress the timeout exception — propagate it
        return False


# ── Scan-level time budget tracker ────────────────────────────────────────────

class ScanBudget:
    """Tracks elapsed time for the whole scan so we can abort if it runs long."""

    def __init__(self, timeout_sec: float = Limits.SCAN_TIMEOUT_SEC):
        self.timeout_sec = timeout_sec
        self._start = time.monotonic()

    def elapsed(self) -> float:
        return time.monotonic() - self._start

    def expired(self) -> bool:
        return self.elapsed() >= self.timeout_sec

    def remaining(self) -> float:
        return max(0.0, self.timeout_sec - self.elapsed())


# ── File-level safety gate ────────────────────────────────────────────────────

SKIP_RESULT_TEMPLATE = {
    "status": "SKIPPED",
    "findings": [],
}


def check_file_safe(
    filepath: str,
    scan_root: str,
    total_bytes_so_far: int,
) -> tuple[bool, str, Optional[bytes]]:
    """
    Performs all safety checks before a file is analysed.

    Returns:
        (safe, reason, raw_bytes)

        safe       – True if the file may be analysed
        reason     – human-readable reason (empty string if safe)
        raw_bytes  – file bytes if safe, None if the file should be skipped
    """
    # 1. Path traversal guard (belt-and-suspenders; archive extractor also checks)
    if not is_safe_path(filepath, scan_root):
        return False, "SKIP-PATH-TRAVERSAL: path escapes scan root", None

    # 2. Stat the file (catches dangling symlinks, device nodes, etc.)
    try:
        stat = os.lstat(filepath)
    except OSError as exc:
        return False, f"SKIP-STAT-ERROR: {exc}", None

    import stat as stat_module

    # 3. Block symlinks and special files
    if stat_module.S_ISLNK(stat.st_mode):
        # Resolve and verify it stays inside scan root
        try:
            real = os.path.realpath(filepath)
            if not real.startswith(os.path.realpath(scan_root) + os.sep):
                return False, "SKIP-SYMLINK-ESCAPE: symlink points outside scan root", None
        except OSError:
            return False, "SKIP-SYMLINK-UNRESOLVABLE", None

    if not stat_module.S_ISREG(stat.st_mode):
        return False, f"SKIP-SPECIAL-FILE: not a regular file (mode={oct(stat.st_mode)})", None

    # 4. Per-file size guard
    size = stat.st_size
    if size > Limits.MAX_FILE_SIZE_BYTES:
        return (
            False,
            f"SKIP-OVERSIZED: file is {size} bytes (limit {Limits.MAX_FILE_SIZE_BYTES})",
            None,
        )

    # 5. Total-size guard
    if total_bytes_so_far + size > Limits.MAX_TOTAL_SIZE_BYTES:
        return (
            False,
            f"SKIP-TOTAL-SIZE: adding this file would exceed total scan limit "
            f"({Limits.MAX_TOTAL_SIZE_BYTES} bytes)",
            None,
        )

    # 6. Read the file content
    try:
        with open(filepath, "rb") as fh:
            raw = fh.read(size + 1)  # +1 to detect size change
    except OSError as exc:
        return False, f"SKIP-READ-ERROR: {exc}", None

    # 7. Structured data / crypto files allow-list (never skipped as binary)
    fn = os.path.basename(filepath).lower()
    ext = os.path.splitext(fn)[1].lower()
    ALLOWED_DATA_EXTS = {".pem", ".crt", ".cer", ".cert", ".key", ".pfx", ".p12", ".env", ".yml", ".yaml", ".conf", ".ini", ".json", ".xml", ".txt", ".tf", ".properties"}
    is_allowed_data = ext in ALLOWED_DATA_EXTS or fn in {".env", "dockerfile"} or fn.startswith(".env.") or fn.startswith("requirements") or b"-----BEGIN " in raw[:500]

    # 8. Binary content guard
    if not is_allowed_data and is_binary_content(raw):
        return False, "SKIP-BINARY: file appears to be binary", None

    return True, "", raw


def cap_snippet(text: str) -> str:
    """Caps a code snippet to the configured max length (Req 6)."""
    if not text:
        return ""
    return text[: Limits.MAX_SNIPPET_LENGTH]


# ── Exports ───────────────────────────────────────────────────────────────────

__all__ = [
    "Limits",
    "FileTimeout",
    "ScanBudget",
    "check_file_safe",
    "is_binary_content",
    "is_minified_source",
    "is_safe_path",
    "cap_snippet",
    "_TimeoutError",
]

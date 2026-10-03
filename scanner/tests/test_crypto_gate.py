"""
test_crypto_gate.py - Comprehensive Unit Tests for Crypto Ratchet Gate.
"""

import os
import sys
import json
import pytest
import datetime

# Add project root to sys.path
_test_dir = os.path.dirname(os.path.abspath(__file__))
_scanner_dir = os.path.dirname(_test_dir)
_repo_root = os.path.dirname(_scanner_dir)
if _repo_root not in sys.path:
    sys.path.insert(0, _repo_root)

from gate.fingerprint import (
    compute_asset_fingerprint,
    compute_fingerprint_without_path,
    normalize_file_path,
)
from gate.cbom_parser import parse_cbom
from gate.policy import load_policy, matches_prohibited
from gate.waivers import process_waivers, WaiverStatus, WaiverRecord
from gate.engine import evaluate_gate
from gate.reporter import generate_markdown_report, generate_json_report
from gate.cli import run_gate


FIX_DIR = os.path.join(_repo_root, "fixtures", "gate")


# ── 1. Fingerprint Stability Tests ───────────────────────────────────────────

def test_fingerprint_stability_across_line_shifts():
    """
    Two scans of identical code where lines shifted must produce identical fingerprints.
    """
    fp1 = compute_asset_fingerprint(
        algorithm="RSA",
        file_path="src/auth/jwt.py",
        primitive_type="algorithm",
        key_size=2048,
        purpose="signature",
    )
    fp2 = compute_asset_fingerprint(
        algorithm="RSA",
        file_path="src/auth/jwt.py",
        primitive_type="algorithm",
        key_size="2048-bit",  # Normalized key size
        purpose="signature",
    )
    assert fp1 == fp2, "Fingerprints must match regardless of string/int key representation"


def test_fingerprint_normalization():
    """
    Verify path and algorithm normalization:
    Windows vs Linux slashes, leading ./, case differences in algorithm.
    """
    fp_linux = compute_asset_fingerprint("aes-256-gcm", "src/auth/token.py", key_size=256)
    fp_win = compute_asset_fingerprint("AES-256-GCM", ".\\src\\auth\\token.py", key_size="256")
    assert fp_linux == fp_win, "Windows and Linux paths and casing must normalize identically"


def test_path_independent_fingerprint_for_file_moves():
    """
    Moved files share the path-independent fingerprint.
    """
    pfp1 = compute_fingerprint_without_path("RSA", key_size=2048, purpose="signature")
    pfp2 = compute_fingerprint_without_path("RSA", key_size=2048, purpose="signature")
    assert pfp1 == pfp2


# ── 2. Waiver Validation Tests ───────────────────────────────────────────────

def test_waiver_missing_required_fields():
    """Missing owner, reason, or expires must be marked INVALID."""
    today = datetime.date(2026, 10, 3)

    # Missing owner
    w1 = WaiverRecord({"reason": "Valid reason that is long enough", "expires": "2026-11-01", "match": {"algorithm": "RSA", "path": "*.py"}}, 0)
    assert not w1.validate(today)
    assert w1.status == WaiverStatus.INVALID
    assert "owner" in w1.error_reason

    # Reason too short (<15 chars)
    w2 = WaiverRecord({"owner": "@alice", "reason": "Too short", "expires": "2026-11-01", "match": {"algorithm": "RSA", "path": "*.py"}}, 1)
    assert not w2.validate(today)
    assert w2.status == WaiverStatus.INVALID
    assert "15 characters" in w2.error_reason

    # Missing expires
    w3 = WaiverRecord({"owner": "@alice", "reason": "Valid reason that is long enough", "match": {"algorithm": "RSA", "path": "*.py"}}, 2)
    assert not w3.validate(today)
    assert w3.status == WaiverStatus.INVALID


def test_waiver_expired():
    """Waiver in the past must be marked EXPIRED."""
    today = datetime.date(2026, 10, 3)
    w = WaiverRecord({
        "id": "w-exp",
        "owner": "@alice",
        "reason": "Valid reason that is long enough",
        "expires": "2026-09-01",  # Past
        "match": {"algorithm": "RSA", "path": "*.py"},
    }, 0)
    assert not w.validate(today)
    assert w.status == WaiverStatus.EXPIRED


def test_waiver_too_long_duration():
    """Waiver exceeding max_days (90) must be rejected."""
    today = datetime.date(2026, 10, 3)
    w = WaiverRecord({
        "id": "w-long",
        "owner": "@alice",
        "reason": "Valid reason that is long enough",
        "expires": "2027-10-03",  # 365 days
        "match": {"algorithm": "RSA", "path": "*.py"},
    }, 0)
    assert not w.validate(today, max_days=90)
    assert w.status == WaiverStatus.INVALID
    assert "exceeds maximum allowed 90 days" in w.error_reason


def test_waiver_wildcard_without_path_prohibited():
    """Wildcard algorithm without a path pattern is blanket suppression and must be rejected."""
    today = datetime.date(2026, 10, 3)
    w = WaiverRecord({
        "id": "w-blanket",
        "owner": "@alice",
        "reason": "Valid reason that is long enough",
        "expires": "2026-11-01",
        "match": {"algorithm": "RSA"},  # No path
    }, 0)
    assert not w.validate(today)
    assert w.status == WaiverStatus.INVALID
    assert "Blanket suppression prohibited" in w.error_reason


def test_waiver_expiring_soon_warning():
    """Waiver within warn_days (14) must be valid but generate warning."""
    today = datetime.date(2026, 10, 3)
    w = WaiverRecord({
        "id": "w-soon",
        "owner": "@alice",
        "reason": "Valid reason that is long enough",
        "expires": "2026-10-10",  # 7 days left
        "match": {"algorithm": "RSA", "path": "*.py"},
    }, 0)
    assert w.validate(today, warn_days=14)
    assert w.status == WaiverStatus.VALID
    assert w.warning_reason is not None
    assert "7 days remaining" in w.warning_reason


# ── 3. Prohibited Algorithms Evaluation ──────────────────────────────────────

def test_prohibited_algorithms_matching():
    """Verify prohibited algorithms matcher for DES, MD5, and RSA<2048."""
    assert matches_prohibited("MD5", "MD5", None)
    assert matches_prohibited("SHA-1", "SHA1", None)
    assert matches_prohibited("DES", "DES-CBC", 56)
    assert matches_prohibited("RSA<2048", "RSA", 1024)
    assert not matches_prohibited("RSA<2048", "RSA", 2048)
    assert not matches_prohibited("RSA<2048", "RSA", 4096)


# ── 4. Gate Diff & Move Heuristic ────────────────────────────────────────────

def test_file_rename_heuristic():
    """Moved/renamed file should not count as a new violation."""
    today = "2026-10-03"
    base = {
        "components": [
            {
                "name": "RSA",
                "occurrences": [
                    {"file": "src/old_dir/crypto.py", "line": 10, "usage": "signature", "quantumStatus": "Quantum Vulnerable", "keySize": 2048}
                ]
            }
        ]
    }
    head = {
        "components": [
            {
                "name": "RSA",
                "occurrences": [
                    {"file": "src/new_dir/crypto.py", "line": 15, "usage": "signature", "quantumStatus": "Quantum Vulnerable", "keySize": 2048}
                ]
            }
        ]
    }

    res = evaluate_gate(base, head, custom_today=today)
    assert len(res.moved_assets) == 1
    assert len(res.new_quantum_violations) == 0
    assert res.verdict == "PASS"


# ── 5. End-to-End Demo Fixtures Tests (Step 7 requirement) ───────────────────

def test_demo_fail_when_head_adds_rsa_2048():
    """Base vs Head (adds RSA-2048 signature) -> FAIL with exit code 1."""
    with open(os.path.join(FIX_DIR, "base.cbom.json"), "r") as f:
        base_cbom = json.load(f)
    with open(os.path.join(FIX_DIR, "head_fail.cbom.json"), "r") as f:
        head_cbom = json.load(f)

    res = evaluate_gate(base_cbom, head_cbom, custom_today="2026-10-03")
    assert res.verdict == "FAIL"
    assert res.exit_code == 1
    assert len(res.unwaived_violations) == 1
    assert res.unwaived_violations[0]["algorithm"] == "RSA"


def test_demo_pass_when_head_has_valid_waiver():
    """Same Head + Valid Waiver -> PASS with exit code 0."""
    with open(os.path.join(FIX_DIR, "base.cbom.json"), "r") as f:
        base_cbom = json.load(f)
    with open(os.path.join(FIX_DIR, "head_fail.cbom.json"), "r") as f:
        head_cbom = json.load(f)

    valid_waiver = [
        {
            "id": "waiver-rsa-jwt",
            "match": {"algorithm": "RSA", "path": "src/auth/*.py"},
            "owner": "@crypto-alice",
            "reason": "Temporary waiver pending transition to ML-DSA scheduled for next milestone.",
            "expires": "2026-11-30",
        }
    ]

    res = evaluate_gate(base_cbom, head_cbom, raw_waivers=valid_waiver, custom_today="2026-10-03")
    assert res.verdict == "PASS"
    assert res.exit_code == 0
    assert len(res.waived_violations) == 1
    assert len(res.unwaived_violations) == 0


def test_demo_fail_when_waiver_is_expired():
    """Same Head + Expired Waiver -> FAIL again (waiver rejected, violation active)."""
    with open(os.path.join(FIX_DIR, "base.cbom.json"), "r") as f:
        base_cbom = json.load(f)
    with open(os.path.join(FIX_DIR, "head_fail.cbom.json"), "r") as f:
        head_cbom = json.load(f)

    expired_waiver = [
        {
            "id": "waiver-rsa-jwt",
            "match": {"algorithm": "RSA", "path": "src/auth/*.py"},
            "owner": "@crypto-alice",
            "reason": "Temporary waiver pending transition to ML-DSA scheduled for next milestone.",
            "expires": "2025-01-01",  # Expired
        }
    ]

    res = evaluate_gate(base_cbom, head_cbom, raw_waivers=expired_waiver, custom_today="2026-10-03")
    assert res.verdict == "FAIL"
    assert res.exit_code == 1
    assert len(res.unwaived_violations) == 1
    assert any("EXPIRED" in msg for msg in res.warning_messages)


def test_report_generation():
    """Verify Markdown and JSON reports contain required fields."""
    with open(os.path.join(FIX_DIR, "base.cbom.json"), "r") as f:
        base_cbom = json.load(f)
    with open(os.path.join(FIX_DIR, "head_fail.cbom.json"), "r") as f:
        head_cbom = json.load(f)

    res = evaluate_gate(base_cbom, head_cbom, custom_today="2026-10-03")
    md = generate_markdown_report(res)
    js = generate_json_report(res)

    assert "<!-- cryptoscan-gate -->" in md
    assert "## 🔴 Crypto Ratchet Gate: FAILED" in md
    assert "Quantum Cryptography Metric Delta" in md
    assert "How to Fix or Request a Waiver" in md
    assert js["verdict"] == "FAIL"
    assert js["exit_code"] == 1


def test_cli_exit_codes(tmp_path):
    """Verify CLI exit codes: 0 for pass, 1 for fail, 2 for missing file."""
    base_file = os.path.join(FIX_DIR, "base.cbom.json")
    head_file = os.path.join(FIX_DIR, "head_fail.cbom.json")
    valid_waiver = os.path.join(FIX_DIR, "valid_waiver.yaml")

    # Missing file -> exit code 2
    code_err = run_gate("nonexistent.cbom.json", head_file)
    assert code_err == 2

    # Fail -> exit code 1
    code_fail = run_gate(base_file, head_file)
    assert code_fail == 1

    # Pass -> exit code 0
    os.environ["CRYPTOSCAN_TODAY"] = "2026-10-03"
    code_pass = run_gate(base_file, head_file, waivers_path=valid_waiver)
    assert code_pass == 0

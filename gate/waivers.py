"""
waivers.py - Waiver loader, validator, and matcher for Crypto Ratchet Gate.

Each waiver has:
  id: string
  match:
    fingerprint: <sha256>  OR
    algorithm: <name>
    path: <glob-pattern>
  owner: <github-handle-or-email> (required)
  reason: <string> (required, min 15 characters)
  expires: <YYYY-MM-DD> (required, UTC)
  ticket: <url> (optional)

Rules:
- Missing owner / reason (<15 chars) / expires -> INVALID.
- expires in the past -> EXPIRED (finding counts as violation again).
- expires > waiver_max_days from today -> INVALID (too long).
- expires <= waiver_warn_days from today -> VALID, but triggers WARNING.
- Waivers matching nothing in head -> STALE warning.
- Wildcard algorithm without path -> INVALID (no blanket suppression).
"""

import datetime
import fnmatch
import os
import re
from typing import Dict, Any, List, Tuple, Optional

try:
    import yaml
except ImportError:
    yaml = None

from gate.fingerprint import normalize_file_path


def get_today(custom_today: Optional[str] = None) -> datetime.date:
    """Returns today's date in UTC. Injectable via CRYPTOSCAN_TODAY or argument."""
    date_str = custom_today or os.environ.get("CRYPTOSCAN_TODAY")
    if date_str:
        return datetime.date.fromisoformat(date_str.strip())
    return datetime.datetime.now(datetime.timezone.utc).date()


class WaiverStatus:
    VALID = "VALID"
    EXPIRED = "EXPIRED"
    INVALID = "INVALID"
    WARN_EXPIRING_SOON = "EXPIRING_SOON"


class WaiverRecord:
    def __init__(self, raw: Dict[str, Any], index: int):
        self.raw = raw
        self.index = index
        self.id = str(raw.get("id") or f"waiver-{index + 1}").strip()
        self.owner = str(raw.get("owner") or "").strip()
        self.reason = str(raw.get("reason") or "").strip()
        self.expires_str = str(raw.get("expires") or "").strip()
        self.ticket = str(raw.get("ticket") or "").strip()
        self.match = raw.get("match") or {}

        self.status = WaiverStatus.VALID
        self.error_reason: Optional[str] = None
        self.warning_reason: Optional[str] = None
        self.expires_date: Optional[datetime.date] = None
        self.days_left: Optional[int] = None
        self.matched_assets: List[Dict[str, Any]] = []

    def validate(self, today: datetime.date, max_days: int = 90, warn_days: int = 14) -> bool:
        """Validates waiver against all policy rules."""
        # 1. Required fields: owner
        if not self.owner:
            self.status = WaiverStatus.INVALID
            self.error_reason = "Missing required 'owner' field (GitHub handle or email required)."
            return False

        # 2. Required fields: reason (min 15 chars)
        if not self.reason or len(self.reason) < 15:
            self.status = WaiverStatus.INVALID
            self.error_reason = f"Waiver reason must be at least 15 characters (currently: {len(self.reason)} chars)."
            return False

        # 3. Required fields: expires (YYYY-MM-DD)
        if not self.expires_str:
            self.status = WaiverStatus.INVALID
            self.error_reason = "Missing required 'expires' date field (ISO format YYYY-MM-DD)."
            return False

        try:
            self.expires_date = datetime.date.fromisoformat(self.expires_str)
        except ValueError:
            self.status = WaiverStatus.INVALID
            self.error_reason = f"Invalid date format for 'expires': '{self.expires_str}'. Expected YYYY-MM-DD."
            return False

        # 4. Check match specification
        if not isinstance(self.match, dict) or not self.match:
            self.status = WaiverStatus.INVALID
            self.error_reason = "Missing or invalid 'match' block in waiver."
            return False

        fp = self.match.get("fingerprint")
        algo = self.match.get("algorithm")
        path_pattern = self.match.get("path")

        if not fp and not (algo and path_pattern):
            if algo and not path_pattern:
                self.status = WaiverStatus.INVALID
                self.error_reason = f"Blanket suppression prohibited: algorithm '{algo}' specified without a path pattern."
                return False
            self.status = WaiverStatus.INVALID
            self.error_reason = "Waiver match must provide either 'fingerprint' or both 'algorithm' and 'path'."
            return False

        # 5. Check expiration vs today
        self.days_left = (self.expires_date - today).days

        if self.days_left < 0:
            self.status = WaiverStatus.EXPIRED
            self.error_reason = f"Waiver expired on {self.expires_str} ({abs(self.days_left)} days ago)."
            return False

        # 6. Check max duration
        if self.days_left > max_days:
            self.status = WaiverStatus.INVALID
            self.error_reason = f"Waiver expiry duration ({self.days_left} days) exceeds maximum allowed {max_days} days."
            return False

        # 7. Check if expiring soon
        if self.days_left <= warn_days:
            self.warning_reason = f"Expiring soon: {self.days_left} days remaining until {self.expires_str}."

        self.status = WaiverStatus.VALID
        return True

    def matches_asset(self, asset: Dict[str, Any]) -> bool:
        """Evaluates whether this waiver matches a given asset."""
        if not isinstance(self.match, dict):
            return False

        fp = self.match.get("fingerprint")
        if fp and str(fp).strip().lower() == str(asset.get("fingerprint", "")).strip().lower():
            return True

        algo = self.match.get("algorithm")
        path_pattern = self.match.get("path")
        if algo and path_pattern:
            asset_algo = (asset.get("algorithm") or "").upper()
            target_algo = str(algo).strip().upper()
            # If target algorithm matches (e.g. RSA or RSA-2048)
            if target_algo in asset_algo or asset_algo in target_algo:
                asset_path = normalize_file_path(asset.get("file"))
                norm_pat = normalize_file_path(path_pattern)
                # Test fnmatch with globbing
                if fnmatch.fnmatch(asset_path, norm_pat) or fnmatch.fnmatch(asset_path, f"*/{norm_pat}"):
                    return True
                # Support ** recursive globbing
                if "**" in norm_pat:
                    regex_pat = "^" + re.escape(norm_pat).replace(r"\*\*", ".*").replace(r"\*", "[^/]*") + "$"
                    if re.match(regex_pat, asset_path):
                        return True
        return False


def load_waivers(waivers_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """Loads raw waiver objects from .cryptoscan/waivers.yaml or given path."""
    if not waivers_path:
        candidates = [
            ".cryptoscan/waivers.yaml",
            ".cryptoscan/waivers.yml",
            ".cryptoscan/waivers.json",
        ]
        for c in candidates:
            if os.path.exists(c):
                waivers_path = c
                break

    if not waivers_path or not os.path.exists(waivers_path):
        return []

    try:
        with open(waivers_path, "r", encoding="utf-8") as f:
            content = f.read()
        if yaml:
            data = yaml.safe_load(content) or []
        else:
            data = []
        if isinstance(data, list):
            return data
        elif isinstance(data, dict) and "waivers" in data and isinstance(data["waivers"], list):
            return data["waivers"]
        return []
    except Exception as e:
        raise ValueError(f"Error parsing waivers file '{waivers_path}': {e}")


def process_waivers(
    raw_waivers: List[Dict[str, Any]],
    today: datetime.date,
    max_days: int = 90,
    warn_days: int = 14,
) -> Tuple[List[WaiverRecord], List[WaiverRecord]]:
    """
    Validates all waivers and splits them into (active_valid_waivers, rejected_or_expired_waivers).
    """
    valid: List[WaiverRecord] = []
    rejected: List[WaiverRecord] = []

    for idx, raw in enumerate(raw_waivers):
        if not isinstance(raw, dict):
            continue
        record = WaiverRecord(raw, idx)
        is_ok = record.validate(today=today, max_days=max_days, warn_days=warn_days)
        if is_ok:
            valid.append(record)
        else:
            rejected.append(record)

    return valid, rejected

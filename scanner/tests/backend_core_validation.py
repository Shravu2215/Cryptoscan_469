# backend_core_validation.py - Python mirror of repoSecurity.js
from __future__ import annotations
import ipaddress
import re
from urllib.parse import urlparse, unquote

ALLOWED_GIT_HOSTS = {"github.com", "gitlab.com", "bitbucket.org"}

_PRIVATE_CIDRS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),
]

def is_private_ipv4(ip):
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in _PRIVATE_CIDRS)
    except ValueError:
        return False

def validate_git_url_sync(raw_url):
    if not raw_url or not isinstance(raw_url, str):
        raise ValueError("Repository URL is required")
    parsed = urlparse(raw_url.strip())
    if parsed.scheme != "https":
        raise ValueError("Only HTTPS repository URLs are allowed")
    host = (parsed.hostname or "").lower()
    if host not in ALLOWED_GIT_HOSTS:
        raise ValueError(f"Host {host!r} is not in the allowlist")
    parts = [p for p in parsed.path.split("/") if p]
    if len(parts) < 2:
        raise ValueError("URL must contain owner/repo")
    # Decode percent-encoding before validation to catch %2e%2e -> ..
    decoded_parts = [unquote(p) for p in parts]
    if any(p in (".", "..") for p in decoded_parts):
        raise ValueError("URL path contains path traversal sequences")
    owner = decoded_parts[0]
    repo = re.sub(r"\.git$", "", decoded_parts[1])
    SAFE = re.compile(r"^[A-Za-z0-9_.\-]{1,100}$")
    if not SAFE.match(owner) or not SAFE.match(repo):
        raise ValueError("Owner or repo name contains disallowed characters")
    # Extra: reject if decoded owner or repo is literally ".."
    if owner == ".." or repo == "..":
        raise ValueError("URL path contains path traversal sequences")
    return {"owner": owner, "repo": repo, "host": host}

def sanitize_repo_name(name):
    if not name:
        return "unnamed-repo"
    cleaned = re.sub(r"[\x00-\x1f\x7f<>\"'`]", "", name).strip()[:200]
    return cleaned or "unnamed-repo"

def sanitize_file_path(path):
    if not path:
        return ""
    cleaned = path.replace("\x00", "")
    cleaned = re.sub(r"\.\.[/\\]", "", cleaned)
    cleaned = cleaned.lstrip("/\\")
    cleaned = re.sub(r"[\x00-\x1f\x7f]", "", cleaned).strip()[:500]
    return cleaned
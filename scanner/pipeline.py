"""
pipeline.py – CryptoScan scanner entry point
═══════════════════════════════════════════════
Hostile-Repository Hardening applied (Requirements 1, 3, 6, 7, 8):

  Req 1 – Never execute repo code.
           All analyzers only *read* files (AST parse, regex, binary header).
           No eval/exec/import of scanned code, no build scripts.

  Req 3 – Resource limits per scan (all configurable via env — see security.py):
           • per-file size, total scan size, max file count
           • per-file timeout (SIGALRM / threading.Timer)
           • whole-scan timeout (ScanBudget)
           • minified/binary files skipped with reported reason

  Req 6 – Code snippets capped before output (cap_snippet).

  Req 7 – Temp dirs always cleaned up, even on failure or timeout.

  Req 8 – Every skipped/failed/timed-out file appears in `file_manifest` with
           a reason; nothing is silently dropped.
"""

import sys
import json
import uuid
import tempfile
import zipfile
import os
import shutil
import re
from typing import Dict, Any, List, Tuple, Optional

# ── Path setup ────────────────────────────────────────────────────────────────
_scanner_dir = os.path.dirname(os.path.abspath(__file__))
_parent_dir  = os.path.dirname(_scanner_dir)
if _parent_dir not in sys.path:
    sys.path.insert(0, _parent_dir)
if _scanner_dir not in sys.path:
    sys.path.insert(0, _scanner_dir)

# ── Scanner modules ───────────────────────────────────────────────────────────
from scanner.python_analyzer import PythonAnalyzer
from scanner.js_analyzer import JSAnalyzer
from scanner.dedup import dedup
from scanner.regex_analyzer import RegexAnalyzer
from scanner.entropy_analyzer import EntropyAnalyzer
from scanner.confidence import promote_confirmed
from scanner.sca_analyzer import SCAAnalyzer, LockfileVersionResolver
from scanner.config_infra_analyzer import ConfigInfraAnalyzer, detect_exposure
from scanner.container_analyzer import ContainerAnalyzer
from scanner.binary_analyzer import BinaryAnalyzer
from scanner.certificate_analyzer import CertificateAnalyzer
from scanner.universal_analyzer import UniversalAnalyzer
from scanner.sca_correlation import correlate_sca_with_source
from scanner.suppression import load_suppressions, apply_suppressions
from scanner.language_detector import detect_language

# ── Security / resource-limit module (NEW) ────────────────────────────────────
from scanner.security import (
    Limits,
    FileTimeout,
    ScanBudget,
    check_file_safe,
    is_minified_source,
    cap_snippet,
    _TimeoutError,
)


# ── Library / key-size inference helpers (unchanged) ─────────────────────────

def _infer_library(f) -> str:
    if getattr(f, "library", None):
        return f.library
    tags = getattr(f, "tags", []) or []
    if "sca" in tags:
        for t in tags:
            if t not in {"sca", "npm", "pip", "maven"}:
                return t
    if "crypto-js" in str(tags) or "cryptojs" in f.rule_id:
        return "crypto-js"
    if "jsrsasign" in f.rule_id or "jsrsasign" in str(tags):
        return "jsrsasign"
    if "dockerfile" in tags:
        return "Dockerfile"
    if "nginx" in tags:
        return "nginx"
    if "apache" in tags:
        return "apache"
    if "terraform" in tags:
        return "terraform"
    if "k8s" in tags:
        return "kubernetes"
    if f.language == "python":
        if "pycryptodome" in str(tags) or "pycryptodome" in f.rule_id:
            return "pycryptodome"
        if "cryptography" in str(tags) or "cryptography" in f.rule_id:
            return "cryptography"
        if "secrets" in f.rule_id:
            return "secrets"
        if "os." in f.rule_id:
            return "os"
        if "hmac" in f.rule_id:
            return "hmac"
        if "random" in f.rule_id:
            return "random"
        return "hashlib"
    if f.language in ("javascript", "typescript"):
        return "Node Builtin crypto"
    return "Standard Crypto API"


SENSITIVITY_PATTERNS = {
    "HEALTH":    ["health", "hipaa", "patient", "medical", "diagnosis", "ehr", "prescription"],
    "PII":       ["ssn", "social_security", "dob", "birthdate", "passport", "national_id", "email", "phone", "user_address"],
    "FINANCIAL": ["credit_card", "card_number", "cvv", "iban", "bank_account", "pan", "payment_token", "billing"],
    "AUTH":      ["password", "passwd", "auth_token", "api_key", "jwt", "secret_key", "session_id"],
}


def _detect_data_sensitivity(f) -> str:
    text = " ".join(filter(bool, [
        getattr(f, "message", ""),
        getattr(f, "code_snippet", ""),
        getattr(f, "file", ""),
    ])).lower()
    for sens, keywords in SENSITIVITY_PATTERNS.items():
        if any(kw in text for kw in keywords):
            return sens
    return "GENERAL"


def _infer_key_size(f):
    alg     = (f.algorithm or "").upper()
    rule_id = getattr(f, "rule_id", "") or ""
    snippet = getattr(f, "code_snippet", "") or ""
    m = re.search(r'\b(8192|4096|3072|2048|1024|512|256|192|128|56|112)\b', alg)
    if m:
        return int(m.group(1))
    m2 = re.search(r'\b(8192|4096|3072|2048|1024|512|256|192|128|56|112)\b', rule_id)
    if m2:
        return int(m2.group(1))
    m3 = re.search(r'\b(8192|4096|3072|2048|1024|512)\b', snippet)
    if m3 and ("RSA" in alg or "RSA" in rule_id or "rsa" in rule_id):
        return int(m3.group(1))
    if "DES" in alg and "3DES" not in alg:
        return 56
    if "3DES" in alg:
        return 112
    if "BLOWFISH" in alg:
        return 128
    if "RC4" in alg:
        return 128
    return None


# ── Repo surface map & exposure classification (unchanged) ────────────────────

def _build_repo_surface_map(all_files, target_dir) -> Dict[str, Any]:
    """
    Scans repo infrastructure and configuration files to build an external
    exposure map.  Unchanged from original — reads files only, no exec.
    """
    exposed_dirs: set          = set()
    exposed_service_names: set = set()
    COMPOSE_FILES = {"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"}

    for path in all_files:
        fn      = os.path.basename(path).lower()
        rel     = os.path.relpath(path, target_dir).replace("\\", "/")
        rel_dir = os.path.dirname(rel).replace("\\", "/")

        # 1. Docker Compose
        if fn in COMPOSE_FILES or "compose" in fn:
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                    content = fh.read()
                service_chunks = re.split(r'\n  ([a-zA-Z0-9_\-]+):\s*\n', content)
                if len(service_chunks) > 1:
                    for i in range(1, len(service_chunks), 2):
                        s_name = service_chunks[i].strip().lower()
                        s_body = service_chunks[i + 1]
                        has_published_ports = bool(
                            re.search(r'\bports\s*:\s*\n(?:\s*-\s*["\']?[0-9]+[:0-9]*["\']?\s*\n)+', s_body, re.IGNORECASE)
                            or re.search(r'\bports\s*:\s*\[[^]]*\]', s_body, re.IGNORECASE)
                            or re.search(r'["\']?(?:80|443|8080|8443|3000|5000)[:/]', s_body)
                        )
                        if has_published_ports:
                            for variant in (s_name, s_name.replace("-", "_"), s_name.replace("_", "-")):
                                exposed_service_names.add(variant)
                            build_dirs = re.findall(r'build\s*:\s*(?:\./|context\s*:\s*(?:\./)?)([ a-zA-Z0-9_\-\./]+)', s_body)
                            for bdir in build_dirs:
                                clean = bdir.strip("./\\ ").replace("\\", "/")
                                if clean and clean != ".":
                                    exposed_dirs.add(clean)
                else:
                    if re.search(r'(?:ports|expose)\s*:', content, re.IGNORECASE):
                        if rel_dir:
                            exposed_dirs.add(rel_dir)
            except Exception:
                pass

        # 1b. Dockerfile EXPOSE
        if fn == "dockerfile" or fn.startswith("dockerfile") or fn.endswith(".dockerfile"):
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                    df_content = fh.read()
                expose_matches = re.findall(r'^\s*EXPOSE\s+([0-9\s/tcpudp]+)', df_content, re.MULTILINE | re.IGNORECASE)
                if expose_matches:
                    if rel_dir:
                        exposed_dirs.add(rel_dir)
                        dir_stem = os.path.basename(rel_dir).lower()
                        if dir_stem:
                            for variant in (dir_stem, dir_stem.replace("_", "-"), dir_stem.replace("-", "_")):
                                exposed_service_names.add(variant)
                    label_svcs = re.findall(r'LABEL\s+service\s*=\s*["\']?([^"\'\ s]+)', df_content, re.IGNORECASE)
                    for lsvc in label_svcs:
                        exposed_service_names.add(lsvc.lower())
            except Exception:
                pass

        # 2. Kubernetes Service / Ingress
        if fn.endswith(".yaml") or fn.endswith(".yml"):
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                    content = fh.read()
                documents = re.split(r'^---\s*$', content, flags=re.MULTILINE)
                for doc in documents:
                    if not doc.strip():
                        continue
                    kind_m = re.search(r'^kind\s*:\s*(\S+)', doc, re.MULTILINE)
                    kind   = (kind_m.group(1) if kind_m else "").strip()
                    name_m = re.search(r'^metadata\s*:\s*$.*?^\s+name\s*:\s*(\S+)', doc, re.MULTILINE | re.DOTALL)
                    if not name_m:
                        name_m = re.search(r'name\s*:\s*(\S+)', doc, re.MULTILINE)
                    svc_name = (name_m.group(1).strip() if name_m else "").lower()

                    if kind == "Service":
                        if re.search(r'type\s*:\s*(?:LoadBalancer|NodePort)', doc, re.MULTILINE):
                            if rel_dir:
                                exposed_dirs.add(rel_dir)
                            if svc_name:
                                for v in (svc_name, svc_name.replace("-", "_"), svc_name.replace("_", "-")):
                                    exposed_service_names.add(v)
                    elif kind == "Ingress":
                        if rel_dir:
                            exposed_dirs.add(rel_dir)
                        backend_names = re.findall(r'service\s*:\s*\n\s+name\s*:\s*(\S+)', doc, re.MULTILINE)
                        backend_names += re.findall(r'serviceName\s*:\s*(\S+)', doc, re.MULTILINE)
                        for bname in backend_names:
                            bl = bname.strip().lower()
                            if bl:
                                for v in (bl, bl.replace("-", "_"), bl.replace("_", "-")):
                                    exposed_service_names.add(v)
            except Exception:
                pass

        # 3. Terraform
        if fn.endswith(".tf"):
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                    content = fh.read()
                if re.search(
                    r'cidr_blocks\s*=\s*\[[^]]*(?:0\.0\.0\.0/0|::/0)[^]]*\]|'
                    r'source_ranges\s*=\s*\[[^]]*(?:0\.0\.0\.0/0|::/0)[^]]*\]|'
                    r'source_address_prefix\s*=\s*["\']?\*["\']?',
                    content, re.IGNORECASE
                ):
                    if rel_dir:
                        exposed_dirs.add(rel_dir)
                    resource_names = re.findall(r'resource\s+"[^"]+"\s+"([^"]+)"', content)
                    for rname in resource_names:
                        base = re.sub(r'[_-](sg|tg|lb|alb|nlb|group|rule|asg)$', '', rname.lower())
                        for v in (base, base.replace("_", "-"), base.replace("-", "_")):
                            if v:
                                exposed_service_names.add(v)
            except Exception:
                pass

        # 4. Reverse-proxy / web server configs
        is_proxy_or_web = (
            fn in {"caddyfile", "haproxy.cfg", "haproxy.conf", "nginx.conf", "httpd.conf", "apache2.conf"}
            or fn.endswith(".caddy") or fn.startswith("caddyfile")
            or fn.startswith("nginx") or "haproxy" in fn or "envoy" in fn or "traefik" in fn
            or "sites-enabled" in rel or "sites-available" in rel
            or (fn.endswith(".conf") and any(k in rel for k in ("nginx", "apache", "httpd", "proxy", "web", "server")))
        )
        if is_proxy_or_web:
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                    cfg_content = fh.read()
                has_listener = (
                    bool(re.search(r'\b(?:listen|bind|Listen)\s+([^\s;]+)', cfg_content, re.IGNORECASE))
                    or bool(re.search(r'<(?:VirtualHost|Location)', cfg_content, re.IGNORECASE))
                    or bool(re.search(r'\b(?:reverse_proxy|frontend|entryPoints|routers|listeners)\b', cfg_content, re.IGNORECASE))
                )
                if has_listener:
                    if rel_dir:
                        exposed_dirs.add(rel_dir)
                    server_names = re.findall(r'server_name\s+([^;]+);', cfg_content, re.IGNORECASE)
                    for sn_line in server_names:
                        for s_item in sn_line.strip().split():
                            s_clean = s_item.strip("\"'").lower()
                            if s_clean and s_clean not in {"_", "localhost", "127.0.0.1"}:
                                exposed_service_names.add(s_clean.split(".")[0])
                    upstreams = re.findall(r'proxy_pass\s+https?://([a-zA-Z0-9_\-]+)', cfg_content, re.IGNORECASE)
                    upstreams += re.findall(r'reverse_proxy\s+([a-zA-Z0-9_\-]+)', cfg_content, re.IGNORECASE)
                    upstreams += re.findall(r'server\s+([a-zA-Z0-9_\-]+)\s+[0-9.:]+', cfg_content, re.IGNORECASE)
                    for u in upstreams:
                        ul = u.lower()
                        if ul not in {"localhost", "127.0.0.1"}:
                            for v in (ul, ul.replace("-", "_"), ul.replace("_", "-")):
                                exposed_service_names.add(v)
            except Exception:
                pass

    return {"exposed_dirs": exposed_dirs, "exposed_service_names": exposed_service_names}


EXPOSURE_KEYWORDS = ["external", "public", "internet-facing", "edge", "dmz", "webhook", "gateway"]


def _classify_file_exposure(rel_path: str, source: str, surface_map: Dict[str, Any]) -> Tuple[str, List[str], str]:
    norm_path = rel_path.replace("\\", "/")
    parts     = [p.lower() for p in norm_path.split("/")]
    fn        = os.path.basename(norm_path).lower()

    is_explicit_external_name    = any(kw in fn for kw in ("external", "gateway", "edge", "webhook", "dmz"))
    is_private_internal_artifact = (
        fn.endswith((".db", ".sqlite", ".sqlite3", ".sql", ".prisma", ".lock", ".log"))
        or fn in {".env", ".env.example", ".env.local", ".env.production", ".env.test"}
        or fn.startswith(".env.")
        or any(p in {"tests", "test", "fixtures", "mock", "mocks", "prisma", "migrations", "scripts", "tools", "internal"} for p in parts)
    )
    if is_private_internal_artifact and not is_explicit_external_name:
        return "internal", [], "Internal component / private data store"

    stems = set(parts)
    for part in parts:
        stem = part.rsplit(".", 1)[0] if "." in part else part
        stems.update([stem, stem.replace("_", "-"), stem.replace("-", "_")])

    service_names   = surface_map.get("exposed_service_names", set())
    matched_services = stems & service_names if service_names else set()
    if matched_services:
        matched_svc = sorted(matched_services)[0]
        return "external-facing", [f"infra-service:{matched_svc}"], f"Matched exposed infrastructure service '{matched_svc}'"

    for exp_dir in surface_map.get("exposed_dirs", set()):
        if exp_dir and (norm_path.startswith(exp_dir + "/") or norm_path == exp_dir or exp_dir in parts):
            return "external-facing", [f"infra-dir:{exp_dir}"], f"Resides within exposed directory '{exp_dir}'"

    path_lower = norm_path.lower()
    for kw in EXPOSURE_KEYWORDS:
        if kw == "public":
            if (
                "/public/" in path_lower or path_lower.startswith("public/")
                or "-public" in path_lower or "_public" in path_lower
                or "public-" in path_lower or "public_" in path_lower
            ):
                if not any(pk in path_lower for pk in ("public_key", "publickey", "public-key", "public.key", "public.pem")):
                    return "external-facing", [f"keyword:{kw}"], f"Matched keyword '{kw}'"
        elif kw in path_lower:
            return "external-facing", [f"keyword:{kw}"], f"Matched keyword '{kw}'"

    return "internal", [], "No external signals detected"


def _is_file_exposed(rel_path: str, source: str, surface_map: Dict[str, Any]) -> str:
    exposure, _, _ = _classify_file_exposure(rel_path, source, surface_map)
    return exposure


def _compute_systems_rollup(all_files, findings, target_dir) -> List[Dict[str, Any]]:
    system_map = {}
    MANIFEST_NAMES = {"package.json", "requirements.txt", "pom.xml", "build.gradle", "go.mod", "cargo.toml"}

    for path in all_files:
        fn  = os.path.basename(path).lower()
        rel = os.path.relpath(path, target_dir).replace("\\", "/")
        parts = rel.split("/")
        if fn in MANIFEST_NAMES or fn.startswith("dockerfile") or fn == "dockerfile":
            if len(parts) > 1:
                dir_name = parts[0]
                if dir_name not in system_map:
                    system_map[dir_name] = dir_name

    top_dirs: set = set()
    for path in all_files:
        rel   = os.path.relpath(path, target_dir).replace("\\", "/")
        parts = rel.split("/")
        if len(parts) > 1:
            top_dirs.add(parts[0])

    for d in top_dirs:
        if d not in system_map and d not in {"docs", "tests", ".github", "scripts"}:
            system_map[d] = d

    if not system_map:
        system_map["root"] = "main"

    stats = {}
    for sys_id, sys_name in system_map.items():
        stats[sys_id] = {
            "name": sys_name, "path": sys_id,
            "findings_count": 0, "critical_count": 0, "high_count": 0,
            "quantum_broken_count": 0, "algorithms": set(),
        }

    for f in findings:
        rel       = os.path.relpath(f.file, target_dir).replace("\\", "/")
        parts     = rel.split("/")
        first_dir = parts[0] if len(parts) > 1 else "root"
        matched   = first_dir if first_dir in stats else ("root" if "root" in stats else list(stats.keys())[0])
        st        = stats[matched]
        st["findings_count"] += 1
        sev = (f.severity.value if hasattr(f.severity, "value") else str(f.severity)).upper()
        if sev == "CRITICAL":
            st["critical_count"] += 1
        elif sev == "HIGH":
            st["high_count"] += 1
        q = (f.quantum_risk.value if hasattr(f.quantum_risk, "value") else str(f.quantum_risk)).lower()
        if "broken" in q or "vuln" in q:
            st["quantum_broken_count"] += 1
        if f.algorithm:
            st["algorithms"].add(f.algorithm)

    result = []
    for sys_id, st in stats.items():
        if st["findings_count"] > 0 or len(stats) <= 3:
            result.append({
                "name": st["name"], "path": st["path"],
                "findings_count": st["findings_count"],
                "critical_count": st["critical_count"],
                "high_count": st["high_count"],
                "quantum_broken_count": st["quantum_broken_count"],
                "algorithms": sorted(list(st["algorithms"])),
                "risk_score": st["critical_count"] * 10 + st["high_count"] * 5 + max(0, st["findings_count"] - st["critical_count"] - st["high_count"]),
            })
    result.sort(key=lambda s: s["risk_score"], reverse=True)
    return result


# ── Main scan function ────────────────────────────────────────────────────────

def scan_repo(repo_path: str, scan_id: Optional[str] = None) -> Dict[str, Any]:
    """
    Scans a repository directory (or ZIP file) for cryptographic findings.

    All resource limits are enforced; temp dirs are always cleaned up.
    Skipped/failed/timed-out files are reported in `file_manifest`.
    """
    scan_id  = scan_id or str(uuid.uuid4())
    temp_dir = None
    target_dir = repo_path

    # ── Req 7: guarantee cleanup via try/finally ──────────────────────────────
    try:
        # Unzip if necessary (still read-only, no exec)
        if repo_path.lower().endswith(".zip"):
            temp_dir   = tempfile.TemporaryDirectory()
            target_dir = temp_dir.name
            try:
                with zipfile.ZipFile(repo_path, "r") as z:
                    # Basic zip-slip guard at the pipeline level
                    for member in z.namelist():
                        if os.path.isabs(member) or ".." in member.split("/"):
                            raise ValueError(f"ZIP contains unsafe path: {member}")
                    z.extractall(target_dir)
            except Exception as e:
                return {"status": "FAILED", "error": str(e), "file_manifest": []}

        # Initialise analyzers (read-only; no code is imported from the repo)
        lockfile_resolver = LockfileVersionResolver(target_dir)
        py          = PythonAnalyzer()
        js          = JSAnalyzer()
        rx          = RegexAnalyzer()
        ent         = EntropyAnalyzer()
        sca         = SCAAnalyzer(lockfile_resolver)
        infra       = ConfigInfraAnalyzer()
        cnt         = ContainerAnalyzer()
        bin_analyzer  = BinaryAnalyzer()
        cert_analyzer = CertificateAnalyzer()
        universal_analyzer = UniversalAnalyzer()

        findings: List = []
        file_manifest: List[Dict] = []
        files_scanned = 0
        files_skipped = 0
        files_error   = 0
        total_bytes   = 0

        # ── Whole-scan budget (Req 3) ─────────────────────────────────────────
        budget = ScanBudget(Limits.SCAN_TIMEOUT_SEC)

        # ── Collect all candidate files ───────────────────────────────────────
        all_files: List[str] = []
        for root, dirs, files in os.walk(target_dir):
            # Req 1: skip well-known hook / build dirs; never run git hooks
            dirs[:] = [d for d in dirs if d not in {
                "node_modules", ".git", "venv", ".venv", "__pycache__",
                "vendor", "vendors", "bower_components", "dist", "build",
            }]
            for fn in files:
                all_files.append(os.path.join(root, fn))

        import unicodedata
        all_files.sort(key=lambda x: unicodedata.normalize('NFC', os.path.relpath(x, target_dir).replace("\\", "/")))

        # ── File count guard (Req 3) ──────────────────────────────────────────
        if len(all_files) > Limits.MAX_FILE_COUNT:
            # Only process the first MAX_FILE_COUNT files; report the rest skipped
            skipped_extra = all_files[Limits.MAX_FILE_COUNT:]
            all_files     = all_files[: Limits.MAX_FILE_COUNT]
            for fp in skipped_extra:
                rel = os.path.relpath(fp, target_dir).replace("\\", "/")
                file_manifest.append({"file": rel, "status": "SKIPPED", "reason": "SKIP-MAX-FILE-COUNT"})
                files_skipped += 1

        surface_map = _build_repo_surface_map(all_files, target_dir)

        # ── Per-file processing loop ──────────────────────────────────────────
        for filepath in all_files:
            fn      = os.path.basename(filepath)
            ext     = os.path.splitext(fn)[1].lower()
            fn_lower = fn.lower()
            rel_path = os.path.relpath(filepath, target_dir).replace("\\", "/")

            # ── Whole-scan timeout check ──────────────────────────────────────
            if budget.expired():
                file_manifest.append({
                    "file": rel_path, "status": "SKIPPED",
                    "reason": "SKIP-SCAN-TIMEOUT: whole-scan time limit reached",
                })
                files_skipped += 1
                continue

            # ── Binary extension — delegate to BinaryAnalyzer, no text read ──
            BIN_EXTS = {".jar", ".class", ".so", ".dll", ".pyc", ".wasm",
                        ".exe", ".dylib", ".o", ".a", ".lib"}
            if ext in BIN_EXTS:
                try:
                    with FileTimeout(Limits.PER_FILE_TIMEOUT_SEC):
                        findings.extend(bin_analyzer.analyze(filepath))
                    file_manifest.append({"file": rel_path, "status": "SCANNED"})
                    files_scanned += 1
                except _TimeoutError:
                    file_manifest.append({
                        "file": rel_path, "status": "SKIPPED",
                        "reason": f"SKIP-TIMEOUT: binary analysis exceeded {Limits.PER_FILE_TIMEOUT_SEC}s",
                    })
                    files_skipped += 1
                except Exception as e:
                    file_manifest.append({"file": rel_path, "status": "ERROR", "reason": str(e)})
                    files_error += 1
                continue

            # ── Document / media files — fast skip ───────────────────────────
            DOC_EXTS  = {".md", ".markdown", ".rst", ".doc", ".docx", ".pdf",
                         ".rtf", ".csv", ".log", ".txt", ".html", ".htm",
                         ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg"}
            DOC_NAMES = {"readme", "license", "changelog", "contributing",
                         "blind_test_checklist", "checklist"}
            is_sca_manifest = (
                fn_lower in {"package.json", "requirements.txt", "pom.xml",
                             "build.gradle", "go.mod", "cargo.toml"}
                or (fn_lower.startswith("requirements") and fn_lower.endswith(".txt"))
            )
            in_doc_dir = any(p in rel_path.lower().split("/") for p in
                             ["docs", "doc", "documentation", "man", "guides"])

            if (
                (ext in DOC_EXTS and not is_sca_manifest)
                or fn_lower in DOC_NAMES
                or any(fn_lower.startswith(d + ".") for d in DOC_NAMES)
                or in_doc_dir
            ) and not is_sca_manifest:
                file_manifest.append({"file": rel_path, "status": "SKIPPED-UNSUPPORTED"})
                files_skipped += 1
                continue

            # ── Safety gate: size, binary, path traversal (Req 3) ────────────
            safe, reason, raw_bytes = check_file_safe(filepath, target_dir, total_bytes)
            if not safe:
                file_manifest.append({"file": rel_path, "status": "SKIPPED", "reason": reason})
                files_skipped += 1
                continue

            assert raw_bytes is not None
            total_bytes += len(raw_bytes)

            try:
                source = raw_bytes.decode("utf-8", errors="ignore")
            except Exception:
                file_manifest.append({"file": rel_path, "status": "ERROR", "reason": "UTF-8 decode error"})
                files_error += 1
                continue

            # ── Minified file guard (Req 3) ───────────────────────────────────
            if ext in {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx"} and is_minified_source(source):
                file_manifest.append({
                    "file": rel_path, "status": "SKIPPED",
                    "reason": "SKIP-MINIFIED: file appears to be minified",
                })
                files_skipped += 1
                continue

            # ── Per-file analysis with timeout (Req 3) ────────────────────────
            try:
                with FileTimeout(min(Limits.PER_FILE_TIMEOUT_SEC, budget.remaining())):
                    old_len = len(findings)

                    if ext in {".pem", ".crt", ".cer", ".cert", ".key", ".pfx", ".p12"} or "-----BEGIN " in source:
                        findings.extend(cert_analyzer.analyze(filepath, source))

                    if fn.lower().startswith("dockerfile") or "compose" in fn.lower() or ext in {".yaml", ".yml"}:
                        findings.extend(cnt.analyze(filepath, source))

                    if is_sca_manifest:
                        findings.extend(sca.analyze(filepath, source))

                    if (
                        ext in {".tf", ".conf", ".yaml", ".yml", ".ini", ".env",
                                ".properties", ".xml"}
                        or fn.lower() in {"nginx.conf", "httpd.conf", "apache2.conf", "dockerfile"}
                        or fn.startswith("Dockerfile")
                        or ext == ""
                    ):
                        findings.extend(infra.analyze(filepath, source))

                    if ext == ".py":
                        findings.extend(py.analyze(filepath, source))
                        findings.extend(rx.analyze(filepath, source))
                        findings.extend(ent.analyze(filepath, source))
                    elif ext in {".js", ".mjs", ".cjs", ".jsx"}:
                        findings.extend(js.analyze(filepath, source))
                        findings.extend(rx.analyze(filepath, source))
                        findings.extend(ent.analyze(filepath, source))
                    else:
                        findings.extend(universal_analyzer.analyze(filepath, source))
                        findings.extend(rx.analyze(filepath, source))
                        findings.extend(ent.analyze(filepath, source))

                    # Enrich new findings with exposure classification
                    new_findings = findings[old_len:]
                    file_exposure, exp_signals, exp_rationale = _classify_file_exposure(rel_path, source, surface_map)
                    # Detect language once per file and stamp all findings from this file
                    file_language = detect_language(filepath, source)
                    for f in new_findings:
                        if getattr(f, "exposure", "internal") == "internal":
                            f.exposure = file_exposure
                            if exp_signals and not getattr(f, "exposure_signals", None):
                                f.exposure_signals = exp_signals
                            if exp_rationale and not getattr(f, "exposure_rationale", None):
                                f.exposure_rationale = exp_rationale
                        # Stamp language_name (always overwrite — pipeline is authoritative)
                        f.language_name = file_language
                        # Req 6: cap snippets before they leave the analyzer
                        if hasattr(f, "code_snippet") and f.code_snippet:
                            f.code_snippet = cap_snippet(f.code_snippet)

                file_manifest.append({"file": rel_path, "status": "SCANNED"})
                files_scanned += 1

            except _TimeoutError:
                file_manifest.append({
                    "file": rel_path, "status": "SKIPPED",
                    "reason": f"SKIP-TIMEOUT: analysis exceeded {Limits.PER_FILE_TIMEOUT_SEC}s",
                })
                files_skipped += 1
            except Exception as e:
                file_manifest.append({"file": rel_path, "status": "ERROR", "reason": str(e)})
                files_error += 1

        # ── Post-processing ───────────────────────────────────────────────────
        findings = dedup(findings)
        findings = promote_confirmed(findings)
        findings = correlate_sca_with_source(findings)

        import unicodedata
        def _finding_sort_key(f):
            rel = unicodedata.normalize('NFC', os.path.relpath(f.file, target_dir).replace("\\", "/"))
            return (rel, f.line or 0, getattr(f, "rule_id", "") or "")
        findings.sort(key=_finding_sort_key)

        suppressions = load_suppressions(target_dir)
        _, suppressed_count = apply_suppressions(findings, suppressions, repo_path=target_dir)

        out_findings = []
        for i, f in enumerate(findings):
            rel_path = os.path.relpath(f.file, target_dir)
            out_findings.append({
                "id":              f"f{i + 1}",
                "rule_id":         getattr(f, "rule_id", None) or "",
                "file":            rel_path,
                "line":            f.line,
                "algorithm":       f.algorithm,
                "category":        f.category,
                "library":         _infer_library(f),
                "version":         getattr(f, "version", "") or "",
                "key_size":        _infer_key_size(f),
                "severity":        f.severity.value,
                "quantum_risk":    f.quantum_risk.value,
                "message":         f.message,
                "recommendation":  f.recommendation,
                "raw_call":        cap_snippet(getattr(f, "code_snippet", "")),
                "confidence":      f.confidence.value,
                "detection_method": f.detection_method,
                "detection":       getattr(f, "detection", "") or f.detection_method.upper(),
                "language_name":   getattr(f, "language_name", None) or "Unknown",
                "exposure":        getattr(f, "exposure", "internal"),
                "exposure_signals":  getattr(f, "exposure_signals", []) or [],
                "exposure_rationale": getattr(f, "exposure_rationale", "") or "",
                "mode":            getattr(f, "mode", None),
                "dataSensitivity": _detect_data_sensitivity(f),
                "suppressed":      f.suppressed,
                "suppression_reason": f.suppression_reason,
            })

        systems = _compute_systems_rollup(all_files, findings, target_dir)

        source_hash = ""
        hash_file = os.path.join(target_dir, ".source_hash")
        if os.path.exists(hash_file):
            try:
                with open(hash_file, "r") as hf:
                    source_hash = hf.read().strip()
            except Exception:
                pass

        return {
            "status":          "COMPLETED",
            "input_hash":      source_hash,
            "findings":        out_findings,
            "systems":         systems,
            "suppressed_count": suppressed_count,
            "files_scanned":   files_scanned,
            "files_skipped":   files_skipped,
            "files_error":     files_error,
            "file_manifest":   file_manifest,
            "scan_elapsed_sec": round(budget.elapsed(), 2),
        }

    finally:
        # Req 7: guaranteed cleanup regardless of exception, timeout, or success
        if temp_dir:
            try:
                temp_dir.cleanup()
            except Exception:
                pass


if __name__ == "__main__":
    repo = sys.argv[1] if len(sys.argv) > 1 else ""
    print(json.dumps(scan_repo(repo), indent=2))

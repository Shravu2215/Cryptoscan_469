import sys
import json
import uuid
import tempfile
import zipfile
import os
import shutil
import re
from typing import Dict, Any, List, Tuple, Optional

# Make sure we can import from scanner
_scanner_dir = os.path.dirname(os.path.abspath(__file__))
_parent_dir = os.path.dirname(_scanner_dir)
if _parent_dir not in sys.path:
    sys.path.insert(0, _parent_dir)
if _scanner_dir not in sys.path:
    sys.path.insert(0, _scanner_dir)

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
from scanner.sca_correlation import correlate_sca_with_source
from scanner.suppression import load_suppressions, apply_suppressions

DEFAULT_MAX_SCAN_FILES = 10000
DEFAULT_MAX_SCAN_BYTES = 250 * 1024 * 1024  # 250 MB

try:
    MAX_SCAN_FILES = int(os.environ.get("MAX_SCAN_FILES", DEFAULT_MAX_SCAN_FILES))
except ValueError:
    MAX_SCAN_FILES = DEFAULT_MAX_SCAN_FILES

try:
    MAX_SCAN_BYTES = int(os.environ.get("MAX_SCAN_BYTES", DEFAULT_MAX_SCAN_BYTES))
except ValueError:
    MAX_SCAN_BYTES = DEFAULT_MAX_SCAN_BYTES

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
    "HEALTH": ["health", "hipaa", "patient", "medical", "diagnosis", "ehr", "prescription"],
    "PII": ["ssn", "social_security", "dob", "birthdate", "passport", "national_id", "email", "phone", "user_address"],
    "FINANCIAL": ["credit_card", "card_number", "cvv", "iban", "bank_account", "pan", "payment_token", "billing"],
    "AUTH": ["password", "passwd", "auth_token", "api_key", "jwt", "secret_key", "session_id"]
}

def _detect_data_sensitivity(f) -> str:
    text = " ".join(filter(bool, [
        getattr(f, "message", ""),
        getattr(f, "code_snippet", ""),
        getattr(f, "file", "")
    ])).lower()
    
    for sens, keywords in SENSITIVITY_PATTERNS.items():
        if any(kw in text for kw in keywords):
            return sens
    return "GENERAL"

def _infer_key_size(f):
    alg = (f.algorithm or "").upper()
    rule_id = getattr(f, "rule_id", "") or ""
    snippet = getattr(f, "code_snippet", "") or ""
    import re
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


def _build_repo_surface_map(all_files, target_dir) -> Dict[str, Any]:
    """
    Scans repo infrastructure and configuration files to build an external exposure map.
    Identifies exposed services, port mappings, ingresses, and public modules.

    Returns:
        {
          "exposed_dirs": set of relative directory paths confirmed externally reachable,
          "exposed_service_names": set of service identifier strings (lowercase) from
                                    K8s Service metadata.name, Ingress backend service names,
                                    Terraform target names, or docker-compose service names.
        }
    """
    exposed_dirs = set()
    exposed_service_names: set = set()
    COMPOSE_FILES = {"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"}

    for path in all_files:
        fn = os.path.basename(path).lower()
        rel = os.path.relpath(path, target_dir).replace("\\", "/")
        rel_dir = os.path.dirname(rel).replace("\\", "/")

        # 1. Docker Compose port exposures
        if fn in COMPOSE_FILES or "compose" in fn:
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                    content = fh.read()
                # Parse per-service blocks under services: to only extract services with published ports
                service_chunks = re.split(r'\n  ([a-zA-Z0-9_\-]+):\s*\n', content)
                if len(service_chunks) > 1:
                    for i in range(1, len(service_chunks), 2):
                        s_name = service_chunks[i].strip().lower()
                        s_body = service_chunks[i+1]
                        has_published_ports = bool(
                            re.search(r'\bports\s*:\s*\n(?:\s*-\s*["\']?[0-9]+[:0-9]*["\']?\s*\n)+', s_body, re.IGNORECASE)
                            or re.search(r'\bports\s*:\s*\[[^]]*\]', s_body, re.IGNORECASE)
                            or re.search(r'["\']?(?:80|443|8080|8443|3000|5000)[:/]', s_body)
                        )
                        if has_published_ports:
                            exposed_service_names.add(s_name)
                            exposed_service_names.add(s_name.replace("-", "_"))
                            exposed_service_names.add(s_name.replace("_", "-"))
                            build_dirs = re.findall(r'build\s*:\s*(?:\./|context\s*:\s*(?:\./)?)([a-zA-Z0-9_\-\./]+)', s_body)
                            for bdir in build_dirs:
                                clean_bdir = bdir.strip("./\\ ").replace("\\", "/")
                                if clean_bdir and clean_bdir != ".":
                                    exposed_dirs.add(clean_bdir)
                else:
                    if re.search(r'(?:ports|expose)\s*:', content, re.IGNORECASE):
                        if rel_dir:
                            exposed_dirs.add(rel_dir)
            except Exception:
                pass

        # 1b. Dockerfile EXPOSE port exposures
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
                            exposed_service_names.add(dir_stem)
                            exposed_service_names.add(dir_stem.replace("_", "-"))
                            exposed_service_names.add(dir_stem.replace("-", "_"))
                    label_svcs = re.findall(r'LABEL\s+service\s*=\s*["\']?([^"\'\s]+)', df_content, re.IGNORECASE)
                    for lsvc in label_svcs:
                        exposed_service_names.add(lsvc.lower())
            except Exception:
                pass

        # 2. Kubernetes Service / Ingress — content-based, no path filter
        # Parse ANY yaml/yml that contains K8s resources regardless of where it lives.
        if fn.endswith(".yaml") or fn.endswith(".yml"):
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                    content = fh.read()

                # Split multi-document YAML on --- separators
                documents = re.split(r'^---\s*$', content, flags=re.MULTILINE)
                for doc in documents:
                    if not doc.strip():
                        continue

                    # Extract kind
                    kind_m = re.search(r'^kind\s*:\s*(\S+)', doc, re.MULTILINE)
                    kind = (kind_m.group(1) if kind_m else "").strip()

                    # Extract metadata.name
                    name_m = re.search(r'^metadata\s*:\s*$.*?^\s+name\s*:\s*(\S+)', doc, re.MULTILINE | re.DOTALL)
                    if not name_m:
                        name_m = re.search(r'name\s*:\s*(\S+)', doc, re.MULTILINE)
                    svc_name = (name_m.group(1).strip() if name_m else "").lower()

                    if kind == "Service":
                        # Only LoadBalancer / NodePort are externally reachable
                        if re.search(r'type\s*:\s*(?:LoadBalancer|NodePort)', doc, re.MULTILINE):
                            if rel_dir:
                                exposed_dirs.add(rel_dir)
                            if svc_name:
                                exposed_service_names.add(svc_name)
                                # Also add hyphenated <-> underscore variants
                                exposed_service_names.add(svc_name.replace("-", "_"))
                                exposed_service_names.add(svc_name.replace("_", "-"))

                    elif kind == "Ingress":
                        if rel_dir:
                            exposed_dirs.add(rel_dir)
                        # Extract backend service names from Ingress rules
                        backend_names = re.findall(
                            r'service\s*:\s*\n\s+name\s*:\s*(\S+)',
                            doc, re.MULTILINE
                        )
                        # Also match inline: backend.serviceName (v1beta1 style)
                        backend_names += re.findall(
                            r'serviceName\s*:\s*(\S+)',
                            doc, re.MULTILINE
                        )
                        for bname in backend_names:
                            bname_lower = bname.strip().lower()
                            if bname_lower:
                                exposed_service_names.add(bname_lower)
                                exposed_service_names.add(bname_lower.replace("-", "_"))
                                exposed_service_names.add(bname_lower.replace("_", "-"))
            except Exception:
                pass

        # 3. Terraform Ingress / Security Groups open to the internet
        if fn.endswith(".tf"):
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                    content = fh.read()
                # Any resource that permits inbound 0.0.0.0/0 or ::/0
                if re.search(
                    r'cidr_blocks\s*=\s*\[[^]]*(?:0\.0\.0\.0/0|::/0)[^]]*\]|'
                    r'source_ranges\s*=\s*\[[^]]*(?:0\.0\.0\.0/0|::/0)[^]]*\]|'
                    r'source_address_prefix\s*=\s*["\']\*["\']',
                    content, re.IGNORECASE
                ):
                    if rel_dir:
                        exposed_dirs.add(rel_dir)
                    # Extract named resources that are publicly exposed
                    resource_names = re.findall(
                        r'resource\s+"[^"]+"\s+"([^"]+)"', content
                    )
                    for rname in resource_names:
                        # Normalise: public_gateway_sg -> public-gateway, public_gateway
                        base = re.sub(r'[_-](sg|tg|lb|alb|nlb|group|rule|asg)$', '', rname.lower())
                        for variant in (base, base.replace("_", "-"), base.replace("-", "_")):
                            if variant:
                                exposed_service_names.add(variant)
            except Exception:
                pass

        # 4. Reverse-proxy & web server configs (Nginx, Apache, HAProxy, Caddy, Envoy, Traefik)
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

                has_listener = False
                if re.search(r'\b(?:listen|bind|Listen)\s+([^\s;]+)', cfg_content, re.IGNORECASE):
                    has_listener = True
                elif re.search(r'<(?:VirtualHost|Location)', cfg_content, re.IGNORECASE):
                    has_listener = True
                elif re.search(r'\b(?:reverse_proxy|frontend|entryPoints|routers|listeners)\b', cfg_content, re.IGNORECASE):
                    has_listener = True

                if has_listener:
                    if rel_dir:
                        exposed_dirs.add(rel_dir)
                    # Extract server names / domains
                    server_names = re.findall(r'server_name\s+([^;]+);', cfg_content, re.IGNORECASE)
                    for sn_line in server_names:
                        for s_item in sn_line.strip().split():
                            s_clean = s_item.strip("\"'").lower()
                            if s_clean and s_clean not in {"_", "localhost", "127.0.0.1"}:
                                base_s = s_clean.split(".")[0]
                                exposed_service_names.add(base_s)
                    # Extract proxy_pass / upstream backends
                    upstreams = re.findall(r'proxy_pass\s+https?://([a-zA-Z0-9_\-]+)', cfg_content, re.IGNORECASE)
                    upstreams += re.findall(r'reverse_proxy\s+([a-zA-Z0-9_\-]+)', cfg_content, re.IGNORECASE)
                    upstreams += re.findall(r'server\s+([a-zA-Z0-9_\-]+)\s+[0-9.:]+', cfg_content, re.IGNORECASE)
                    for u in upstreams:
                        u_lower = u.lower()
                        if u_lower not in {"localhost", "127.0.0.1"}:
                            exposed_service_names.add(u_lower)
                            exposed_service_names.add(u_lower.replace("-", "_"))
                            exposed_service_names.add(u_lower.replace("_", "-"))
            except Exception:
                pass

    return {"exposed_dirs": exposed_dirs, "exposed_service_names": exposed_service_names}


EXPOSURE_KEYWORDS = ["external", "public", "internet-facing", "edge", "dmz", "webhook", "gateway"]


def _classify_file_exposure(rel_path: str, source: str, surface_map: Dict[str, Any]) -> Tuple[str, List[str], str]:
    norm_path = rel_path.replace("\\", "/")
    parts = [p.lower() for p in norm_path.split("/")]
    fn = os.path.basename(norm_path).lower()

    # Rule 0: Internal file types & locations are Internal by default unless explicitly an edge/gateway/webhook file
    is_explicit_external_name = any(kw in fn for kw in ("external", "gateway", "edge", "webhook", "dmz"))
    is_private_internal_artifact = (
        fn.endswith((".db", ".sqlite", ".sqlite3", ".sql", ".prisma", ".lock", ".log"))
        or fn in {".env", ".env.example", ".env.local", ".env.production", ".env.test"}
        or fn.startswith(".env.")
        or any(part in {"tests", "test", "fixtures", "mock", "mocks", "prisma", "migrations", "scripts", "tools", "internal"} for part in parts)
    )
    if is_private_internal_artifact and not is_explicit_external_name:
        return "internal", [], "Internal component / private data store (database, environment config, test, or migration artifact)"

    stems = set(parts)
    for part in parts:
        stem = part.rsplit(".", 1)[0] if "." in part else part
        stems.add(stem)
        stems.add(stem.replace("_", "-"))
        stems.add(stem.replace("-", "_"))

    # Strategy 1: explicit service name match from infra signals
    service_names = surface_map.get("exposed_service_names", set())
    matched_services = stems & service_names if service_names else set()
    if matched_services:
        matched_svc = sorted(matched_services)[0]
        return "external-facing", [f"infra-service:{matched_svc}"], f"Matched exposed infrastructure service name '{matched_svc}'"

    # Strategy 2: directory prefix match
    for exp_dir in surface_map.get("exposed_dirs", set()):
        if exp_dir and (norm_path.startswith(exp_dir + "/") or norm_path == exp_dir or exp_dir in parts):
            return "external-facing", [f"infra-dir:{exp_dir}"], f"Path resides within exposed infrastructure directory '{exp_dir}'"

    # Strategy 3: Substring keyword fallback on path components and filename
    path_lower = norm_path.lower()
    for kw in EXPOSURE_KEYWORDS:
        if kw == "public":
            # For 'public', avoid matching public_key.pem, public.key, get_public_key, etc.
            if "/public/" in path_lower or path_lower.startswith("public/") or "-public" in path_lower or "_public" in path_lower or "public-" in path_lower or "public_" in path_lower:
                if not any(pk in path_lower for pk in ("public_key", "publickey", "public-key", "public.key", "public.pem")):
                    return "external-facing", [f"keyword:{kw}"], f"Path matched external-facing keyword '{kw}'"
        elif kw in path_lower:
            return "external-facing", [f"keyword:{kw}"], f"Path matched external-facing keyword '{kw}'"

    return "internal", [], "No external infrastructure signals or gateway keywords detected"


def _is_file_exposed(rel_path: str, source: str, surface_map: Dict[str, Any]) -> str:
    exposure, _, _ = _classify_file_exposure(rel_path, source, surface_map)
    return exposure


def _compute_systems_rollup(all_files, findings, target_dir) -> List[Dict[str, Any]]:
    """
    Detects distinct system/service boundaries based on manifests and directory structure,
    and rolls up findings per system.
    """
    system_map = {}
    MANIFEST_NAMES = {"package.json", "requirements.txt", "pom.xml", "build.gradle", "go.mod", "cargo.toml"}

    for path in all_files:
        fn = os.path.basename(path).lower()
        rel = os.path.relpath(path, target_dir).replace("\\", "/")
        parts = rel.split("/")

        if fn in MANIFEST_NAMES or fn.startswith("dockerfile") or fn == "dockerfile":
            if len(parts) > 1:
                dir_name = parts[0]
                if dir_name not in system_map:
                    system_map[dir_name] = dir_name

    top_dirs = set()
    for path in all_files:
        rel = os.path.relpath(path, target_dir).replace("\\", "/")
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
            "name": sys_name,
            "path": sys_id,
            "findings_count": 0,
            "critical_count": 0,
            "high_count": 0,
            "quantum_broken_count": 0,
            "algorithms": set(),
        }

    for f in findings:
        rel = os.path.relpath(f.file, target_dir).replace("\\", "/")
        parts = rel.split("/")
        first_dir = parts[0] if len(parts) > 1 else "root"

        matched_sys = first_dir if first_dir in stats else ("root" if "root" in stats else list(stats.keys())[0])
        st = stats[matched_sys]
        st["findings_count"] += 1
        sev = (f.severity.value if hasattr(f.severity, 'value') else str(f.severity)).upper()
        if sev == "CRITICAL":
            st["critical_count"] += 1
        elif sev == "HIGH":
            st["high_count"] += 1

        q = (f.quantum_risk.value if hasattr(f.quantum_risk, 'value') else str(f.quantum_risk)).lower()
        if "broken" in q or "vuln" in q:
            st["quantum_broken_count"] += 1
        if f.algorithm:
            st["algorithms"].add(f.algorithm)

    result = []
    for sys_id, st in stats.items():
        if st["findings_count"] > 0 or len(stats) <= 3:
            result.append({
                "name": st["name"],
                "path": st["path"],
                "findings_count": st["findings_count"],
                "critical_count": st["critical_count"],
                "high_count": st["high_count"],
                "quantum_broken_count": st["quantum_broken_count"],
                "algorithms": sorted(list(st["algorithms"])),
                "risk_score": (st["critical_count"] * 10) + (st["high_count"] * 5) + max(0, st["findings_count"] - st["critical_count"] - st["high_count"]),
            })

    result.sort(key=lambda s: s["risk_score"], reverse=True)
    return result


def scan_repo(repo_path, scan_id=None):
    scan_id = scan_id or str(uuid.uuid4())
    temp_dir = None
    target_dir = repo_path

    if not repo_path or not os.path.exists(repo_path):
        return {
            "status": "FAILED",
            "error": f"Repository path does not exist: {repo_path}",
            "failure_reason": f"Repository path does not exist: {repo_path}",
        }

    if repo_path.lower().endswith(".zip"):
        temp_dir = tempfile.TemporaryDirectory()
        target_dir = temp_dir.name
        try:
            with zipfile.ZipFile(repo_path, 'r') as z:
                total_extracted_bytes = 0
                extracted_file_count = 0
                real_target = os.path.realpath(target_dir)

                for member in z.infolist():
                    # Skip symlinks
                    if (member.external_attr >> 16) & 0o120000 == 0o120000:
                        continue

                    target_member_path = os.path.realpath(os.path.join(target_dir, member.filename))
                    if not (target_member_path == real_target or target_member_path.startswith(real_target + os.sep)):
                        raise ValueError(f"Unsafe path in archive: {member.filename}")

                    if member.is_dir():
                        os.makedirs(target_member_path, exist_ok=True)
                        continue

                    extracted_file_count += 1
                    if extracted_file_count > MAX_SCAN_FILES:
                        raise ValueError(f"Archive exceeds maximum file count limit ({MAX_SCAN_FILES})")

                    os.makedirs(os.path.dirname(target_member_path), exist_ok=True)
                    with z.open(member, 'r') as src, open(target_member_path, 'wb') as dst:
                        while True:
                            chunk = src.read(65536)
                            if not chunk:
                                break
                            total_extracted_bytes += len(chunk)
                            if total_extracted_bytes > MAX_SCAN_BYTES:
                                raise ValueError(f"Archive exceeds maximum extracted size limit ({MAX_SCAN_BYTES} bytes)")
                            dst.write(chunk)
        except Exception as e:
            if temp_dir:
                try:
                    temp_dir.cleanup()
                except Exception:
                    pass
            return {"status": "FAILED", "error": str(e), "failure_reason": str(e)}

    lockfile_resolver = LockfileVersionResolver(target_dir)
    py = PythonAnalyzer()
    js = JSAnalyzer()
    rx = RegexAnalyzer()
    ent = EntropyAnalyzer()
    sca = SCAAnalyzer(lockfile_resolver)
    infra = ConfigInfraAnalyzer()
    cnt = ContainerAnalyzer()
    bin_analyzer = BinaryAnalyzer()
    cert_analyzer = CertificateAnalyzer()
    findings = []
    
    file_manifest = []
    files_scanned = 0
    files_skipped = 0
    files_error = 0

    all_files = []
    total_scanned_bytes = 0
    for root, dirs, files in os.walk(target_dir):
        dirs[:] = [d for d in dirs if d not in {"node_modules", ".git", "venv", ".venv", "__pycache__", "vendor", "vendors", "bower_components", "dist", "build"}]
        for fn in files:
            full_path = os.path.join(root, fn)
            if os.path.islink(full_path):
                continue
            all_files.append(full_path)
            if len(all_files) > MAX_SCAN_FILES:
                if temp_dir:
                    try:
                        temp_dir.cleanup()
                    except Exception:
                        pass
                return {
                    "status": "FAILED",
                    "error": f"Repository exceeds maximum file count limit ({MAX_SCAN_FILES})",
                    "failure_reason": f"Repository exceeds maximum file count limit ({MAX_SCAN_FILES})"
                }
            try:
                total_scanned_bytes += os.path.getsize(full_path)
                if total_scanned_bytes > MAX_SCAN_BYTES:
                    if temp_dir:
                        try:
                            temp_dir.cleanup()
                        except Exception:
                            pass
                    return {
                        "status": "FAILED",
                        "error": f"Repository exceeds maximum scan size limit ({MAX_SCAN_BYTES} bytes)",
                        "failure_reason": f"Repository exceeds maximum scan size limit ({MAX_SCAN_BYTES} bytes)"
                    }
            except OSError:
                pass

    surface_map = _build_repo_surface_map(all_files, target_dir)

    for path in all_files:
        fn = os.path.basename(path)
        ext = os.path.splitext(fn)[1].lower()
        fn_lower = fn.lower()
        rel_path = os.path.relpath(path, target_dir).replace("\\", "/")

        is_sca_manifest = (
            fn_lower in {"package.json", "requirements.txt", "pom.xml", "build.gradle", "go.mod", "cargo.toml"}
            or (fn_lower.startswith("requirements") and fn_lower.endswith(".txt"))
        )

        DOC_EXTS = {".md", ".markdown", ".rst", ".doc", ".docx", ".pdf", ".rtf", ".csv", ".log", ".txt", ".html", ".htm", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg"}
        DOC_NAMES = {"readme", "license", "changelog", "contributing", "blind_test_checklist", "checklist"}
        in_doc_dir = any(part in rel_path.lower().split("/") for part in ["docs", "doc", "documentation", "man", "guides"])

        if (ext in DOC_EXTS and not is_sca_manifest) or fn_lower in DOC_NAMES or any(fn_lower.startswith(d + ".") for d in DOC_NAMES) or in_doc_dir:
            if not is_sca_manifest:
                file_manifest.append({"file": rel_path, "status": "SKIPPED-UNSUPPORTED"})
                files_skipped += 1
                continue

        if ext in {".jar", ".class", ".so", ".dll", ".pyc", ".wasm", ".exe", ".dylib", ".o", ".a", ".lib"}:
            try:
                findings.extend(bin_analyzer.analyze(path))
                file_manifest.append({"file": rel_path, "status": "SCANNED"})
                files_scanned += 1
            except Exception as e:
                file_manifest.append({"file": rel_path, "status": "ERROR", "error_msg": str(e)})
                files_error += 1
            continue

        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                source = fh.read()
        except OSError as e:
            file_manifest.append({"file": rel_path, "status": "ERROR", "error_msg": str(e)})
            files_error += 1
            continue

        try:
            old_len = len(findings)

            if ext in {".pem", ".crt", ".cer", ".cert", ".key", ".pfx", ".p12"} or "-----BEGIN " in source:
                findings.extend(cert_analyzer.analyze(path, source))
            
            if fn.lower().startswith("dockerfile") or "compose" in fn.lower() or ext in {".yaml", ".yml"}:
                findings.extend(cnt.analyze(path, source))

            if is_sca_manifest:
                findings.extend(sca.analyze(path, source))

            # Infra/config analyzer — triggered for known config extensions AND for
            # extensionless files (e.g. sshd_config, ipsec.conf without extension).
            # The ConfigInfraAnalyzer gates itself by content, so false-positive risk
            # from calling it on arbitrary extensionless files is negligible.
            if ext in {".tf", ".conf", ".yaml", ".yml", ".ini", ".env", ".properties", ".xml"} \
                    or fn.lower() in {"nginx.conf", "httpd.conf", "apache2.conf", "dockerfile"} \
                    or fn.startswith("Dockerfile") \
                    or ext == "":  # extensionless: sshd_config, ipsec.conf, etc.
                findings.extend(infra.analyze(path, source))

            if ext == ".py":
                findings.extend(py.analyze(path, source))
                findings.extend(rx.analyze(path, source))
                findings.extend(ent.analyze(path, source))
            elif ext in {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx"}:
                findings.extend(js.analyze(path, source))
                findings.extend(rx.analyze(path, source))
                findings.extend(ent.analyze(path, source))
            else:
                findings.extend(rx.analyze(path, source))
                findings.extend(ent.analyze(path, source))

            new_findings = findings[old_len:]
            file_exposure, exp_signals, exp_rationale = _classify_file_exposure(rel_path, source, surface_map)
            for f in new_findings:
                if getattr(f, "exposure", "internal") == "internal":
                    f.exposure = file_exposure
                    if exp_signals and not getattr(f, "exposure_signals", None):
                        f.exposure_signals = exp_signals
                    if exp_rationale and not getattr(f, "exposure_rationale", None):
                        f.exposure_rationale = exp_rationale

            file_manifest.append({"file": rel_path, "status": "SCANNED"})
            files_scanned += 1
        except Exception as e:
            file_manifest.append({"file": rel_path, "status": "ERROR", "error_msg": str(e)})
            files_error += 1
                
    findings = dedup(findings)
    findings = promote_confirmed(findings)
    findings = correlate_sca_with_source(findings)

    suppressions = load_suppressions(target_dir)
    _, suppressed_count = apply_suppressions(findings, suppressions, repo_path=target_dir)
    
    out_findings = []
    for i, f in enumerate(findings):
        rel_path = os.path.relpath(f.file, target_dir)

        out_findings.append({
            "id": f"f{i+1}",
            "rule_id": getattr(f, 'rule_id', None) or "",
            "file": rel_path,
            "line": f.line,
            "algorithm": f.algorithm,
            "category": f.category,
            "library": _infer_library(f),
            "version": getattr(f, 'version', '') or '',
            "key_size": _infer_key_size(f),
            "severity": f.severity.value,
            "quantum_risk": f.quantum_risk.value,
            "message": f.message,
            "recommendation": f.recommendation,
            "raw_call": getattr(f, 'code_snippet', ''),
            "confidence": f.confidence.value,
            "detection_method": f.detection_method,
            "exposure": getattr(f, 'exposure', 'internal'),
            "exposure_signals": getattr(f, 'exposure_signals', []) or [],
            "exposure_rationale": getattr(f, 'exposure_rationale', '') or '',
            "mode": getattr(f, 'mode', None),
            "dataSensitivity": _detect_data_sensitivity(f),
            "suppressed": f.suppressed,
            "suppression_reason": f.suppression_reason,
        })

    systems = _compute_systems_rollup(all_files, findings, target_dir)

    if temp_dir:
        temp_dir.cleanup()
        
    return {
        "status": "COMPLETED",
        "findings": out_findings,
        "systems": systems,
        "suppressed_count": suppressed_count,
        "files_scanned": files_scanned,
        "files_skipped": files_skipped,
        "files_error": files_error,
        "file_manifest": file_manifest,
    }

if __name__ == "__main__":
    repo = sys.argv[1] if len(sys.argv) > 1 else ""
    print(json.dumps(scan_repo(repo), indent=2))

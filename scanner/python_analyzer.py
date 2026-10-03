"""
AST-based analyzer for Python source. Uses the stdlib `ast` module (real parse
tree, not regex) to find hashlib/pycryptodome/`cryptography`/random/hmac usage
and flag crypto weaknesses.

Supports: hashlib (md5/sha1/...), pycryptodome (Crypto.Cipher.AES/DES/DES3,
Crypto.PublicKey.RSA), the `cryptography` package (rsa.generate_private_key,
ec.generate_private_key), `random` used for security-sensitive values, and
`==`/`!=` secret comparisons that should use hmac.compare_digest.
"""
import ast
import os
from typing import List, Optional

from .models import Finding, Severity, QuantumRisk
from . import rules


def _name_of(node) -> str:
    """Best-effort dotted name for a Call's func, e.g. 'Crypto.Cipher.AES.new'."""
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


class _Imports(ast.NodeVisitor):
    def __init__(self):
        self.aliases = {}  # local name -> canonical name

    def visit_Import(self, node):
        for alias in node.names:
            last = alias.name.split(".")[-1]
            local = alias.asname or last
            self.aliases[local] = last
            self.aliases[alias.name] = last
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        mod = node.module or ""
        for alias in node.names:
            local = alias.asname or alias.name
            target = alias.name
            full = f"{mod}.{target}" if mod else target
            self.aliases[local] = full
            if mod:
                self.aliases[f"{mod}.{alias.name}"] = full
        self.generic_visit(node)


def _resolve_alias(fname: str, aliases: dict) -> str:
    if not fname:
        return fname
    if fname in aliases:
        return aliases[fname]
    parts = fname.split(".")
    if parts[0] in aliases:
        parts[0] = aliases[parts[0]]
        return ".".join(parts)
    return fname


def _annotate_parents(tree):
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            child._csparent = node


def _enclosing_func_name(node):
    """Walk up parent pointers (set by _annotate_parents) to the nearest
    enclosing function definition's name, or None if at module scope."""
    n = getattr(node, "_csparent", None)
    while n is not None:
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return n.name
        n = getattr(n, "_csparent", None)
    return None


def _literal_bytes_len(node) -> Optional[int]:
    if isinstance(node, ast.Constant) and isinstance(node.value, (bytes, str)):
        return len(node.value)
    return None


def _resolve_bytes_len(node) -> Optional[int]:
    if node is None:
        return None
    lit_len = _literal_bytes_len(node)
    if lit_len is not None:
        return lit_len
    if _is_dynamic_random_source(node):
        if node.args:
            arg = node.args[0]
            if isinstance(arg, ast.Constant) and isinstance(arg.value, int):
                return arg.value
    return None


def _is_secret_name(name: str) -> bool:
    """Delegates to the shared word-boundary matcher in rules."""
    return rules.matches_secret_hint(name)


def _line_src(source_lines, lineno):
    try:
        return source_lines[lineno - 1].strip()
    except IndexError:
        return ""


class _Assigns(ast.NodeVisitor):
    """One-pass, whole-file, last-write-wins variable table. Heuristic by
    design - good enough for flagging obvious hardcoded/static values in a
    single-file static scan, same tradeoff every lightweight SAST tool makes."""

    def __init__(self):
        self.table = {}  # name -> ast node (the assigned value)

    def visit_Assign(self, node):
        for t in node.targets:
            if isinstance(t, ast.Name):
                self.table[t.id] = node.value
        self.generic_visit(node)

    def visit_AnnAssign(self, node):
        if isinstance(node.target, ast.Name) and node.value is not None:
            self.table[node.target.id] = node.value
        self.generic_visit(node)


def _resolve(node, table, depth=0):
    """Follow simple Name -> Assign chains to reach a literal or a Call."""
    if depth > 5 or node is None:
        return node
    if isinstance(node, ast.Name) and node.id in table:
        return _resolve(table[node.id], table, depth + 1)
    return node


def _is_dynamic_random_source(node) -> bool:
    """True if `node` is a call that produces cryptographically random bytes."""
    if isinstance(node, ast.Call):
        n = _name_of(node.func)
        return n in ("os.urandom", "urandom", "secrets.token_bytes", "secrets.token_hex",
                     "get_random_bytes", "Random.get_random_bytes")
    return False


def _is_confirmed_static(node) -> bool:
    """True only when the IV/nonce provably resolves to a fixed literal. An
    *unresolved* Name (e.g. a function parameter we can't trace back through
    this file) is unknown, not static - flagging it would be a false
    positive, not a genuine finding."""
    return isinstance(node, ast.Constant) and isinstance(node.value, (bytes, str))


class PythonAnalyzer:
    rule_source = "python-ast"

    def analyze(self, file_path: str, source: str) -> List[Finding]:
        findings: List[Finding] = []
        ext = os.path.splitext(file_path)[1].lower()
        fn = os.path.basename(file_path).lower()
        if ext in {".md", ".markdown", ".rst", ".doc", ".docx", ".txt", ".pdf", ".rtf", ".csv", ".log", ".html", ".htm"} or fn in {"readme", "license", "changelog"} or "docs" in file_path.replace("\\", "/").split("/"):
            return findings

        try:
            tree = ast.parse(source, filename=file_path)
        except SyntaxError:
            return findings

        assigns = _Assigns()
        assigns.visit(tree)
        table = assigns.table
        source_lines = source.splitlines()

        imports = _Imports()
        imports.visit(tree)
        aliases = imports.aliases

        _annotate_parents(tree)

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                findings.extend(self._check_call(node, file_path, table, source_lines, aliases))
            elif isinstance(node, ast.Compare):
                f = self._check_compare(node, file_path, source_lines)
                if f:
                    findings.append(f)

        return findings

    # -- Call-expression checks --------------------------------------------------
    def _check_call(self, node: ast.Call, file_path, table, source_lines, aliases) -> List[Finding]:
        out: List[Finding] = []
        fname = _resolve_alias(_name_of(node.func), aliases)
        line = node.lineno
        col = node.col_offset
        snippet = _line_src(source_lines, line)

        # -- Hashlib / Cryptography hashes -------------------------------------
        hash_algo = None
        is_crypto_lib = False
        fname_lower = fname.lower()
        if fname in ("hashlib.md5", "md5", "hashlib.sha1", "sha1", "hashlib.sha256", "sha256", "hashlib.sha3_256", "sha3_256", "hashlib.sha512", "sha512", "hashlib.sha384", "sha384"):
            hash_algo = fname.split(".")[-1].replace("sha3_256", "sha3")
            is_crypto_lib = False
        elif (fname_lower in ("hashes.md5", "hashes.sha1", "hashes.sha256", "hashes.sha3_256", "hashes.sha512", "hashes.sha384")
              or fname_lower.startswith("cryptography.hazmat.primitives.hashes.")
              or fname in ("MD5", "SHA1", "SHA256", "SHA512", "SHA3_256", "SHA384")):
            last_part = fname.split(".")[-1].lower().replace("sha3_256", "sha3")
            if last_part in rules.HASH_ALGOS:
                hash_algo = last_part
                is_crypto_lib = True
        elif fname in ("hashlib.new", "new") and node.args:
            lit = _resolve(node.args[0], table)
            if isinstance(lit, ast.Constant) and isinstance(lit.value, str):
                hash_algo = lit.value.lower()

        if hash_algo and hash_algo in rules.HASH_ALGOS:
            profile = dict(rules.HASH_ALGOS[hash_algo])
            is_password_ctx = _is_secret_name(snippet) and ("password" in snippet.lower() or "pwd" in snippet.lower() or "passwd" in snippet.lower())
            lib = "cryptography" if is_crypto_lib else "hashlib"
            
            if hash_algo in ("sha256", "sha3", "sha512", "sha384") and not is_password_ctx:
                out.append(self._mk_finding(
                    file_path, line, col, "python", f"{hash_algo}-hash-safe",
                    f"{profile['algorithm']} Hash", "hash", profile, snippet,
                    specificity=1, generic=False, library=lib
                ))
            else:
                rule_id = f"{hash_algo}-weak-password-hash" if is_password_ctx else f"{hash_algo}-hashing"
                out.append(self._mk_finding(
                    file_path, line, col, "python", rule_id,
                    f"{profile['algorithm']} {'weak-password-hash' if is_password_ctx else 'hashing'}",
                    "hash", profile, snippet, specificity=3 if is_password_ctx else 2, generic=False, library=lib
                ))
            return out

        # -- PyCryptodome Crypto.Cipher.<ALGO>.new(...) ------------------------
        first_p = fname.split(".")[0]
        last_p = fname.split(".")[-1]
        SYMMETRIC_ALGOS = {"AES", "DES", "DES3", "TDES", "3DES", "RC2", "RC4", "ARC4", "BLOWFISH"}
        first_p_upper = first_p.upper()
        last_p_upper = last_p.upper()
        is_symmetric_call = (
            any(p in SYMMETRIC_ALGOS for p in fname.upper().split("."))
            or (fname.endswith(".new") and not (fname.startswith("hmac") or fname.startswith("random") or fname.startswith("secrets") or first_p_upper in {"RSA", "DSA", "EC", "FERNET"}))
        )
        if is_symmetric_call and first_p_upper not in {"RSA", "DSA", "EC", "ECDSA", "ECDH", "HMAC", "FERNET"}:
            out.extend(self._check_cipher_new(node, fname, file_path, table, source_lines))

        # -- Cryptography hazmat: Cipher(algorithms.X(key), modes.Y()) ---------
        if fname in ("Cipher", "ciphers.Cipher") or fname.endswith(".Cipher") or "ciphers.Cipher" in fname:
            out.extend(self._check_hazmat_cipher(node, file_path, table, source_lines))

        # -- Cryptography Fernet -----------------------------------------------
        if fname in ("Fernet", "fernet.Fernet") or fname.endswith(".Fernet"):
            out.append(self._mk_finding(file_path, line, col, "python", "fernet-aes128-cbc-hmac",
                                          "Fernet symmetric encryption", "symmetric-cipher",
                                          rules.FERNET_PROFILE, snippet, specificity=2, library="cryptography", mode="CBC"))

        # -- CSPRNG (secrets, os.urandom) --------------------------------------
        if fname in ("secrets.token_hex", "token_hex") or fname.endswith(".token_hex"):
            profile = dict(rules.SECRETS_TOKEN_HEX_PROFILE)
            out.append(self._mk_finding(file_path, line, col, "python", "secrets-token-hex-csprng",
                                          "CSPRNG (secrets.token_hex)", "rng", profile, snippet, specificity=1, generic=False, library="secrets"))
        elif (fname in ("secrets.token_urlsafe", "secrets.randbelow", "secrets.token_bytes", "secrets.choice", "secrets.SystemRandom", "token_urlsafe", "randbelow", "token_bytes")
              or (fname.startswith("secrets.") and fname not in ("secrets.token_hex", "token_hex"))):
            if not ("random." in fname or fname == "choice"):
                profile = dict(rules.SAFE_CSPRNG_PROFILE)
                profile["algorithm"] = f"CSPRNG ({fname})"
                out.append(self._mk_finding(file_path, line, col, "python", "csprng-safe",
                                              f"CSPRNG usage ({fname})", "rng", profile, snippet, specificity=1, generic=False, library="secrets"))

        if fname in ("os.urandom", "urandom") or fname.endswith(".urandom"):
            profile = dict(rules.SAFE_CSPRNG_PROFILE)
            profile["algorithm"] = "CSPRNG (os.urandom)"
            out.append(self._mk_finding(file_path, line, col, "python", "csprng-safe",
                                          "CSPRNG usage (os.urandom)", "rng", profile, snippet, specificity=1, generic=False, library="os"))

        # -- Constant-time comparison ------------------------------------------
        if fname in ("hmac.compare_digest", "compare_digest") or fname.endswith(".compare_digest"):
            profile = dict(rules.SAFE_COMPARE_PROFILE)
            out.append(self._mk_finding(file_path, line, col, "python", "constant-time-compare-safe",
                                          "Constant-Time Comparison (hmac.compare_digest)", "comparison", profile, snippet, specificity=1, generic=False, library="hmac"))

        # -- Cryptography AEAD ciphers: AESGCM, AESCCM, ChaCha20Poly1305 ------
        fname_upper = fname.upper()
        is_aesgcm = (
            fname in ("AESGCM", "AESGCM.generate_key", "aead.AESGCM")
            or fname.endswith(".AESGCM")
            or fname.endswith(".AESGCM.generate_key")
            or "AESGCM" in fname_upper
        )
        is_aesccm = (
            fname in ("AESCCM", "AESCCM.generate_key", "aead.AESCCM")
            or fname.endswith(".AESCCM")
            or "AESCCM" in fname_upper
        )
        if is_aesgcm or is_aesccm:
            mode = "GCM" if is_aesgcm else "CCM"
            # Try to extract bit_length from AESGCM.generate_key(bit_length=256)
            bits = None
            for kw in node.keywords:
                if kw.arg in ("bit_length", "key_size", "bits"):
                    lit = _resolve(kw.value, table)
                    if isinstance(lit, ast.Constant) and isinstance(lit.value, int):
                        bits = lit.value
                        break
            if bits is None and node.args:
                lit = _resolve(node.args[0], table)
                if isinstance(lit, ast.Constant) and isinstance(lit.value, int):
                    bits = lit.value
            key_size_str = f"-{bits}" if bits else ""
            profile = {
                "algorithm": f"AES{key_size_str}-{mode}",
                "severity": Severity.INFO,
                "quantum_risk": QuantumRisk.SAFE,
                "recommendation": (
                    f"AES-{mode} is an AEAD cipher providing authenticated encryption. "
                    "AES is quantum-safe against Grover's algorithm when key length >= 256 bits."
                ),
                "tags": ["aes", "aead", mode.lower()],
            }
            out.append(self._mk_finding(
                file_path, line, col, "python", f"aes-{mode.lower()}-aead",
                f"AES-{mode} AEAD encryption", "symmetric-cipher",
                profile, snippet, specificity=2, generic=False,
                library="cryptography", mode=mode,
            ))

        # -- ChaCha20-Poly1305 -------------------------------------------------
        if "chacha20" in fname.lower():

            profile = dict(rules.CHACHA20_POLY1305_PROFILE)
            lib = "cryptography" if ("cryptography" in fname or "hazmat" in fname) else "pycryptodome"
            out.append(self._mk_finding(file_path, line, col, "python", "chacha20-poly1305-aead",
                                          "ChaCha20-Poly1305 AEAD", "symmetric-cipher", profile, snippet, specificity=1, generic=False, library=lib, mode="Poly1305"))

        # -- Argon2id ----------------------------------------------------------
        if "argon2" in fname.lower() or fname in ("PasswordHasher", "hash_password", "hash_secret", "ph.hash"):
            profile = dict(rules.ARGON2ID_PROFILE)
            out.append(self._mk_finding(file_path, line, col, "python", "argon2id-kdf",
                                          "Argon2id Password KDF", "kdf", profile, snippet, specificity=2, generic=False, library="argon2-cffi"))

        # -- AWS KMS / Cloud KMS -----------------------------------------------
        if fname in ("boto3.client", "client", "Session.client") or fname.endswith(".client"):
            service_name = None
            if node.args:
                lit = _resolve(node.args[0], table)
                if isinstance(lit, ast.Constant) and isinstance(lit.value, str):
                    service_name = lit.value.lower()
            if not service_name:
                for kw in node.keywords:
                    if kw.arg == "service_name":
                        lit = _resolve(kw.value, table)
                        if isinstance(lit, ast.Constant) and isinstance(lit.value, str):
                            service_name = lit.value.lower()
            if service_name == "kms":
                profile = {
                    "algorithm": "AWS KMS",
                    "severity": Severity.INFO,
                    "quantum_risk": QuantumRisk.SAFE,
                    "recommendation": "Hardware-backed / Cloud KMS key custody verified. Ensure key rotation policies and PQC migration readiness are enabled on KMS keys.",
                    "tags": ["kms", "hsm", "hardware-custody", "aws"],
                }
                out.append(self._mk_finding(file_path, line, col, "python", "kms-hsm-aws-kms",
                                              "AWS KMS Hardware/Cloud Custody", "Cloud KMS / HSM",
                                              profile, snippet, specificity=2, generic=False,
                                              tags=profile.get("tags", []), library="boto3"))

        # -- HMAC digest checking ----------------------------------------------
        if fname in ("hmac.new", "new") and ("hmac" in fname or aliases.get("new", "").startswith("hmac")):
            out.extend(self._check_hmac_digest(node, file_path, table, source_lines, aliases))

        # -- Asymmetric Key Generation: ECDSA vs RSA vs DSA --------------------
        is_ecdsa_gen = (
            fname in ("ec.generate_private_key", "asymmetric.ec.generate_private_key")
            or fname.endswith("ec.generate_private_key")
            or ("ec." in fname and "generate_private_key" in fname)
            or ("generate_private_key" in fname and any(k in snippet for k in ("ec.", "SECP", "SECT", "Brainpool", "Curve", "elliptic_curve")))
        )
        is_dsa_gen = (
            fname in ("dsa.generate_private_key", "DSA.generate")
            or fname.endswith("dsa.generate_private_key")
            or fname.endswith("DSA.generate")
        )
        is_rsa_gen = (
            fname in ("RSA.generate", "rsa.newkeys", "newkeys", "rsa.generate_private_key")
            or fname.endswith("RSA.generate") or fname.endswith("PublicKey.RSA.generate")
            or (fname.endswith("rsa.generate_private_key") and not is_ecdsa_gen)
            or ("generate_private_key" in fname and not is_ecdsa_gen and not is_dsa_gen and ("key_size" in snippet or "rsa" in snippet.lower() or "RSA" in snippet))
        )

        if is_ecdsa_gen:
            curve = "unknown-curve"
            if node.args and isinstance(node.args[0], ast.Call):
                curve = _name_of(node.args[0].func).split(".")[-1]
            elif node.args and isinstance(node.args[0], ast.Attribute):
                curve = node.args[0].attr
            elif "SECP256R1" in snippet:
                curve = "SECP256R1"
            profile = rules.ecc_profile(curve, purpose="signature")
            out.append(self._mk_finding(file_path, line, col, "python", "ecdsa-key-generation",
                                          f"ECDSA key_generation ({curve})", "asymmetric", profile, snippet,
                                          specificity=2, library="cryptography"))
        elif is_rsa_gen:
            bits = None
            for arg in node.args:
                lit = _resolve(arg, table)
                if isinstance(lit, ast.Constant) and isinstance(lit.value, int) and lit.value in (512, 1024, 2048, 3072, 4096, 8192):
                    bits = lit.value
                    break
            if bits is None:
                for kw in node.keywords:
                    if kw.arg in ("key_size", "bits", "size", "keybits", "length"):
                        lit = _resolve(kw.value, table)
                        if isinstance(lit, ast.Constant) and isinstance(lit.value, int):
                            bits = lit.value
                            break
            if bits is None:
                import re
                m_bits = re.search(r'\b(8192|4096|3072|2048|1024|512)\b', snippet)
                if m_bits:
                    bits = int(m_bits.group(1))

            profile = rules.rsa_profile(bits)
            lib = "pycryptodome" if ("RSA.generate" in fname or "newkeys" in fname) else "cryptography"
            out.append(self._mk_finding(file_path, line, col, "python", "rsa-key-generation",
                                          "RSA key_generation", "asymmetric", profile, snippet,
                                          specificity=2, tags=profile.get("tags", []), library=lib))
        elif is_dsa_gen:
            bits = None
            for arg in node.args:
                lit = _resolve(arg, table)
                if isinstance(lit, ast.Constant) and isinstance(lit.value, int) and lit.value in (512, 1024, 2048, 3072, 4096, 8192):
                    bits = lit.value
                    break
            if bits is None:
                for kw in node.keywords:
                    if kw.arg in ("key_size", "bits", "size", "keybits", "length"):
                        lit = _resolve(kw.value, table)
                        if isinstance(lit, ast.Constant) and isinstance(lit.value, int):
                            bits = lit.value
                            break
            profile = dict(
                algorithm=f"DSA-{bits}" if bits else "DSA",
                severity=Severity.HIGH if (bits and bits < 2048) else Severity.MEDIUM,
                quantum_risk=QuantumRisk.QUANTUM_BROKEN,
                recommendation="DSA is broken by Shor's algorithm and weak when key size < 2048. Migrate to ML-DSA (FIPS 204).",
            )
            lib = "pycryptodome" if "DSA.generate" in fname else "cryptography"
            out.append(self._mk_finding(file_path, line, col, "python", "dsa-key-generation",
                                          "DSA key_generation", "asymmetric", profile, snippet,
                                          specificity=2, library=lib))

        # -- Sign / Verify operations ------------------------------------------
        if fname.endswith(".sign") or fname.endswith(".verify") or fname in ("sign", "verify"):
            if "PSS" in snippet or "padding.PSS" in snippet or "PKCS1v15" in snippet:
                profile = rules.rsa_profile(None)
                out.append(self._mk_finding(file_path, line, col, "python", "rsa-signature-operation",
                                              "RSA Signature Operation", "asymmetric", profile, snippet,
                                              specificity=3, library="cryptography"))
            elif "ECDSA" in snippet or "ec.ECDSA" in snippet:
                profile = rules.ecc_profile("generic", purpose="signature")
                out.append(self._mk_finding(file_path, line, col, "python", "ecdsa-signature-operation",
                                              "ECDSA Signature Operation", "asymmetric", profile, snippet,
                                              specificity=3, library="cryptography"))

        # -- Insecure RNG feeding security-sensitive value ---------------------
        if fname in ("random.random", "random.randint", "random.choice", "random.getrandbits",
                       "random.randrange", "random.sample", "random.seed",
                       "randint", "choice", "getrandbits", "randrange", "sample", "seed", "random"):
            out.extend(self._check_rng_context(node, file_path, source_lines, fname))

        return [f for f in out if f is not None]

    def _check_hazmat_cipher(self, node, file_path, table, source_lines) -> List[Finding]:
        """cryptography lib: Cipher(algorithms.AES(key), modes.ECB()) etc."""
        out = []
        line, col = node.lineno, node.col_offset
        snippet = _line_src(source_lines, line)
        if len(node.args) < 1:
            return out

        algo_call = node.args[0]
        mode_call = node.args[1] if len(node.args) >= 2 else None
        for kw in node.keywords:
            if kw.arg == "mode":
                mode_call = kw.value

        if not (isinstance(algo_call, ast.Call)):
            return out
        algo = _name_of(algo_call.func).split(".")[-1]  # e.g. "AES", "TripleDES"
        mode = None
        if isinstance(mode_call, ast.Call):
            mode = _name_of(mode_call.func).split(".")[-1].upper()  # e.g. "ECB", "GCM"

        key_bits = None
        if algo_call.args:
            key_val = _resolve(algo_call.args[0], table)
            blen = _resolve_bytes_len(key_val)
            if blen:
                key_bits = blen * 8

        if algo.upper() not in ("AES",):
            if algo.upper() in ("TRIPLEDES", "3DES", "DES", "BLOWFISH", "ARC4", "RC4"):
                profile = rules.symmetric_profile(algo, mode or "")
                out.append(self._mk_finding(file_path, line, col, "python", f"{algo.lower()}-deprecated-cipher",
                                              f"{algo} deprecated-cipher", "symmetric-cipher", profile, snippet,
                                              specificity=3, library="cryptography", mode=mode))
            return out

        profile = rules.symmetric_profile("AES", mode or "", key_bits)
        if mode == "ECB":
            out.append(self._mk_finding(file_path, line, col, "python", "aes-ecb-mode",
                                          f"AES-{key_bits or '?'}-ECB", "symmetric-cipher", profile, snippet,
                                          specificity=3, library="cryptography", mode="ECB"))
        elif mode in ("CBC", "CTR", "CFB", "OFB"):
            out.append(self._mk_finding(file_path, line, col, "python", "aes-missing-aead",
                                          f"AES-{key_bits or '?'}-{mode} missing-aead", "symmetric-cipher",
                                          profile, snippet, specificity=2, generic=True, library="cryptography", mode=mode))
        elif mode in ("GCM", "CCM"):
            out.append(self._mk_finding(file_path, line, col, "python", "aes-aead-mode",
                                          f"AES-{key_bits or '?'}-{mode}", "symmetric-cipher", profile, snippet,
                                          specificity=1, generic=True, library="cryptography", mode=mode))
        return out

    def _check_hmac_digest(self, node, file_path, table, source_lines, aliases) -> List[Finding]:
        out = []
        line, col = node.lineno, node.col_offset
        snippet = _line_src(source_lines, line)

        digest_node = node.args[2] if len(node.args) >= 3 else None
        for kw in node.keywords:
            if kw.arg == "digestmod":
                digest_node = kw.value
        resolved = _resolve(digest_node, table)

        digest_name = None
        if isinstance(resolved, ast.Attribute):
            digest_name = _resolve_alias(_name_of(resolved), aliases)
        elif isinstance(resolved, ast.Constant) and isinstance(resolved.value, str):
            digest_name = f"hashlib.{resolved.value.lower()}"

        if not digest_name or not digest_name.startswith("hashlib."):
            return out
        algo_key = digest_name.split(".")[-1].lower()
        if algo_key in ("md5", "sha1"):
            profile = dict(rules.HASH_ALGOS[algo_key])
            out.append(self._mk_finding(file_path, line, col, "python", f"{algo_key}-hmac-weak-digest",
                                          f"HMAC-{profile['algorithm']} weak-digest", "hash", profile, snippet,
                                          specificity=3, library="hmac"))
        elif algo_key in ("sha256", "sha512", "sha3_256", "sha3", "sha384"):
            raw_prof = rules.HASH_ALGOS.get(algo_key, rules.HASH_ALGOS["sha256"])
            hmac_profile = dict(
                algorithm=f"HMAC-{raw_prof['algorithm']}",
                severity=Severity.INFO,
                quantum_risk=QuantumRisk.SAFE,
                recommendation=f"HMAC-{raw_prof['algorithm']} is a secure authenticated hash function."
            )
            out.append(self._mk_finding(file_path, line, col, "python", f"hmac-{algo_key}-safe",
                                          f"HMAC-{raw_prof['algorithm']}", "hash", hmac_profile, snippet,
                                          specificity=2, generic=False, library="hmac"))
        return out

    def _check_cipher_new(self, node, fname, file_path, table, source_lines) -> List[Finding]:
        out = []
        line, col = node.lineno, node.col_offset
        snippet = _line_src(source_lines, line)

        CIPHER_NAMES = {"DES", "DES3", "TDES", "3DES", "RC2", "RC4", "ARC4", "BLOWFISH", "AES"}
        parts = [p.upper() for p in fname.split(".")]
        algo = None
        for p in reversed(parts):
            if p in CIPHER_NAMES:
                algo = p
                break
        if not algo:
            return out
        if algo == "3DES":
            algo = "DES3"

        lib = "cryptography" if any(k in fname.lower() for k in ("hazmat", "cryptography", "algorithms", "ciphers")) else "pycryptodome"
        if algo in ("DES", "DES3", "TDES", "RC2", "RC4", "ARC4", "BLOWFISH"):
            mode = None
            mode_node = node.args[1] if len(node.args) >= 2 else None
            for kw in node.keywords:
                if kw.arg == "mode":
                    mode_node = kw.value
            if isinstance(mode_node, ast.Attribute) and mode_node.attr.startswith("MODE_"):
                mode = mode_node.attr.replace("MODE_", "")
            profile = rules.symmetric_profile(algo, mode or "")
            out.append(self._mk_finding(file_path, line, col, "python", f"{algo.lower()}-deprecated-cipher",
                                          f"{algo} deprecated-cipher", "symmetric-cipher", profile, snippet,
                                          specificity=3, library=lib, mode=mode))
            return out

        if algo != "AES":
            return out

        mode = None
        mode_node = None
        if len(node.args) >= 2:
            mode_node = node.args[1]
        for kw in node.keywords:
            if kw.arg == "mode":
                mode_node = kw.value
        if isinstance(mode_node, ast.Attribute) and mode_node.attr.startswith("MODE_"):
            mode = mode_node.attr.replace("MODE_", "")

        key_bits = None
        key_hardcoded = False
        if node.args:
            key_val = _resolve(node.args[0], table)
            blen = _resolve_bytes_len(key_val)
            if blen:
                key_bits = blen * 8
                if isinstance(key_val, ast.Constant):
                    key_hardcoded = True

        iv_node = node.args[2] if len(node.args) >= 3 else None
        for kw in node.keywords:
            if kw.arg in ("iv", "nonce"):
                iv_node = kw.value
        iv_static = False
        resolved_iv = None
        if iv_node is not None:
            resolved_iv = _resolve(iv_node, table)
            iv_static = _is_confirmed_static(resolved_iv)

        profile = rules.symmetric_profile("AES", mode or "", key_bits)
        red_flags = []
        if key_hardcoded:
            red_flags.append("hardcoded-key")
        if iv_node is not None and iv_static:
            red_flags.append("static-iv")

        if key_hardcoded:
            hp = dict(rules.HARDCODED_KEY)
            out.append(self._mk_finding(file_path, line, col, "python", "aes-hardcoded-key",
                                          f"AES-{key_bits}-{mode or '?'} hardcoded-key", "hardcoded-secret",
                                          hp, snippet, specificity=4, library=lib, mode=mode))

        if iv_node is not None and iv_static and mode in ("CBC", "CTR", "CFB", "OFB", "GCM"):
            ivp = dict(rules.STATIC_IV)
            out.append(self._mk_finding(file_path, line, col, "python", "aes-static-iv-reuse",
                                          f"AES-{key_bits}-{mode} static-iv-reuse", "symmetric-cipher",
                                          ivp, snippet, specificity=4, library=lib, mode=mode))

        if mode == "ECB":
            out.append(self._mk_finding(file_path, line, col, "python", "aes-ecb-mode",
                                          f"AES-{key_bits}-ECB", "symmetric-cipher", profile, snippet,
                                          specificity=3, library=lib, mode="ECB"))
        elif mode in ("CBC", "CTR", "CFB", "OFB"):
            missing_aead = dict(profile)
            if red_flags:
                missing_aead["severity"] = Severity.CRITICAL
                missing_aead["recommendation"] = (
                    f"Combined with {', '.join(red_flags)}, lack of authenticated encryption makes "
                    "this call exploitable. " + profile["recommendation"]
                )
            out.append(self._mk_finding(file_path, line, col, "python", "aes-missing-aead",
                                          f"AES-{key_bits}-{mode} missing-aead", "symmetric-cipher",
                                          missing_aead, snippet, specificity=2, generic=(not red_flags), library=lib, mode=mode))
        elif mode in ("GCM", "CCM"):
            out.append(self._mk_finding(file_path, line, col, "python", "aes-aead-mode",
                                          f"AES-{key_bits}-{mode}", "symmetric-cipher", profile, snippet,
                                          specificity=1, generic=True, library=lib, mode=mode))
        else:
            out.append(self._mk_finding(file_path, line, col, "python", "aes-encryption",
                                          f"AES encryption", "symmetric-cipher", profile, snippet,
                                          specificity=1, generic=True, library=lib, mode=mode))
        return out

    def _check_rng_context(self, node, file_path, source_lines, fname: str = "") -> List[Finding]:
        line, col = node.lineno, node.col_offset
        snippet = _line_src(source_lines, line)
        parent_target = None
        if "=" in snippet and not snippet.strip().startswith("if"):
            target = snippet.split("=", 1)[0].strip()
            target = target.split(":")[0].strip()
            if target.isidentifier():
                parent_target = target

        is_secret_context = bool(parent_target and _is_secret_name(parent_target))

        if not is_secret_context:
            func_name = _enclosing_func_name(node)
            if func_name and _is_secret_name(func_name):
                is_secret_context = True

        if not is_secret_context and node.args:
            for arg in node.args:
                arg_name = ""
                if isinstance(arg, ast.Name):
                    arg_name = arg.id
                elif isinstance(arg, ast.Attribute):
                    arg_name = arg.attr
                if arg_name and _is_secret_name(arg_name):
                    is_secret_context = True
                    break

        if not is_secret_context and fname in ("random.seed", "seed", "random.getrandbits", "getrandbits", "random.choice", "choice", "random.randint", "randint", "random.random", "random"):
            is_secret_context = True

        if is_secret_context:
            profile = dict(rules.INSECURE_RNG)
            return [self._mk_finding(file_path, line, col, "python", "insecure-rng",
                                       "random module insecure-rng", "rng", profile, snippet, specificity=3, generic=False, library="random")]
        return []

    def _check_compare(self, node: ast.Compare, file_path, source_lines) -> Optional[Finding]:
        if len(node.ops) != 1 or not isinstance(node.ops[0], (ast.Eq, ast.NotEq)):
            return None
        left, right = node.left, node.comparators[0]

        def name_of(n):
            if isinstance(n, ast.Name):
                return n.id
            if isinstance(n, ast.Attribute):
                return n.attr
            return ""

        def is_trivial(n):
            return isinstance(n, ast.Constant) and n.value in ("", None, 0)

        NON_SECRET_PROPS = {"length", "len", "size", "count", "index"}
        if name_of(left).lower() in NON_SECRET_PROPS or name_of(right).lower() in NON_SECRET_PROPS:
            return None

        candidate = None
        for side in (left, right):
            nm = name_of(side)
            if nm and _is_secret_name(nm):
                candidate = nm
                break
        if not candidate:
            return None
        if is_trivial(left) or is_trivial(right):
            return None

        line, col = node.lineno, node.col_offset
        snippet = _line_src(source_lines, line)
        profile = dict(rules.TIMING_UNSAFE_COMPARE)
        return self._mk_finding(file_path, line, col, "python", "timing-unsafe-compare",
                                  "Non-constant-time secret comparison", "comparison", profile, snippet,
                                  specificity=3, library="stdlib")

    @staticmethod
    def _mk_finding(file_path, line, col, language, rule_id, rule_name, category, profile,
                     snippet, specificity=1, generic=False, tags=None, library="", mode=None) -> Optional[Finding]:
        s_strip = (snippet or "").strip()
        if s_strip.startswith('"""') or s_strip.startswith("'''") or s_strip.startswith("#"):
            return None
        return Finding(
            file=file_path, line=line, column=col, language=language, rule_id=rule_id,
            rule_name=rule_name, category=category, algorithm=profile["algorithm"],
            severity=profile["severity"], quantum_risk=profile["quantum_risk"],
            message=f"{rule_name} at line {line}.", recommendation=profile["recommendation"],
            code_snippet=snippet, specificity=specificity, generic=generic,
            tags=tags or profile.get("tags", []) or [],
            library=library,
            mode=mode,
        )

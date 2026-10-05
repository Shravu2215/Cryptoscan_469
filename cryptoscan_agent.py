"""Metadata-only Python runtime observation for CryptoScan sessions."""

import hashlib
import hmac
import inspect
import json
import os
import random
import re
import secrets
import ssl
import threading
import time
import urllib.error
import urllib.request
import uuid

_LOCK = threading.RLock()
_QUEUE = {}
_STARTED = False
_STOP = threading.Event()
_LOCAL = threading.local()
_INGEST_URL = None
_INGEST_TOKEN = None
_SESSION_ID = None
_THIS_FILE = os.path.abspath(__file__)


def _caller():
    try:
        for frame in inspect.stack()[2:]:
            filename = os.path.abspath(frame.filename)
            if filename == _THIS_FILE:
                continue
            if "site-packages" in filename or "importlib" in filename:
                continue
            relative = os.path.relpath(filename)
            return f"{relative}:{frame.lineno}"[:700]
    except Exception:
        pass
    return "unknown:0"


def _record(source, algorithm, operation, key_info=None, host_origin="", scheme="", port=0):
    try:
        if getattr(_LOCAL, "suppressed", False):
            return
        event = {
            "source": source,
            "algorithm": str(algorithm)[:100],
            "operation": operation,
            "keyInfo": key_info or {},
            "callerScript": _caller(),
            "hostOrigin": host_origin,
            "scheme": scheme,
            "port": int(port or 0),
            "crossOrigin": False,
            "count": 1,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        identity = json.dumps(
            [source, event["algorithm"], operation, event["keyInfo"], event["callerScript"], host_origin],
            sort_keys=True,
            separators=(",", ":"),
        )
        with _LOCK:
            existing = _QUEUE.get(identity)
            if existing:
                existing["count"] += 1
            else:
                _QUEUE[identity] = event
    except Exception:
        pass


def _wrap(target, name, algorithm, operation, metadata=None):
    try:
        original = getattr(target, name)
        if not callable(original) or getattr(original, "_cryptoscan_wrapped", False):
            return False

        def observed(*args, **kwargs):
            depth = getattr(_LOCAL, "depth", 0)
            _LOCAL.depth = depth + 1
            try:
                result = original(*args, **kwargs)
            finally:
                _LOCAL.depth = depth
            if depth == 0 and not getattr(_LOCAL, "suppressed", False):
                try:
                    label = algorithm(args, kwargs) if callable(algorithm) else algorithm
                    details = metadata(args, kwargs) if metadata else {}
                    _record("crypto", label, operation, details)
                except Exception:
                    pass
            return result

        observed._cryptoscan_wrapped = True
        observed.__name__ = getattr(original, "__name__", name)
        observed.__qualname__ = getattr(original, "__qualname__", name)
        setattr(target, name, observed)
        return True
    except Exception:
        return False


def _hashlib_new_name(args, kwargs):
    name = args[0] if args else kwargs.get("name", "")
    normalized = str(name).lower().replace("_", "-")
    aliases = {
        "md5": "MD5", "sha1": "SHA-1", "sha-1": "SHA-1", "sha256": "SHA-256",
        "sha-256": "SHA-256", "sha384": "SHA-384", "sha-384": "SHA-384",
        "sha512": "SHA-512", "sha-512": "SHA-512", "sha3-256": "SHA3-256",
        "sha3-512": "SHA3-512",
    }
    return aliases.get(normalized, str(name)[:100])


def _hashlib_method_name(name):
    names = {"md5": "MD5", "sha1": "SHA-1", "sha256": "SHA-256", "sha384": "SHA-384", "sha512": "SHA-512"}
    return names.get(name, name.upper())


def _hmac_name(args, kwargs):
    digest = kwargs.get("digestmod")
    if digest is None and len(args) > 2:
        digest = args[2]
    if isinstance(digest, str):
        raw = digest
    elif digest is not None:
        raw = getattr(digest, "name", None) or getattr(digest, "__name__", "")
    else:
        raw = ""
    normalized = str(raw).lower().replace("openssl_", "").replace("_", "-")
    return "HMAC-" + _hashlib_new_name((normalized,), {}) if normalized else "HMAC"


def _tls_observed(sock, server_hostname=None):
    try:
        protocol = sock.version()
        cipher = sock.cipher()
        if not protocol or not cipher:
            return
        hostname = server_hostname or getattr(sock, "server_hostname", None)
        peer = sock.getpeername()
        port = int(peer[1]) if len(peer) > 1 else 443
        host = str(hostname or peer[0])
        host_name = f"[{host}]" if ":" in host and not host.startswith("[") else host
        host_origin = f"https://{host_name}:{port}"
        _record("tls", "TLS", "handshake", {
            "version": str(protocol),
            "cipherSuite": str(cipher[0]),
            "bits": int(cipher[2] or 0),
        }, host_origin, "https", port)
    except Exception:
        pass


def _wrap_ssl_context():
    try:
        context_class = ssl.SSLContext
        original = context_class.wrap_socket
        if getattr(original, "_cryptoscan_wrapped", False):
            return

        def observed(context, sock, *args, **kwargs):
            server_hostname = kwargs.get("server_hostname")
            if server_hostname is None and len(args) >= 5:
                server_hostname = args[4]
            wrapped = original(context, sock, *args, **kwargs)
            _tls_observed(wrapped, server_hostname)
            try:
                original_handshake = wrapped.do_handshake
                if not getattr(original_handshake, "_cryptoscan_wrapped", False):
                    def handshake(*handshake_args, **handshake_kwargs):
                        result = original_handshake(*handshake_args, **handshake_kwargs)
                        _tls_observed(wrapped, server_hostname)
                        return result
                    handshake._cryptoscan_wrapped = True
                    wrapped.do_handshake = handshake
            except Exception:
                pass
            return wrapped

        observed._cryptoscan_wrapped = True
        context_class.wrap_socket = observed
    except Exception:
        pass


def _wrap_jwt():
    try:
        import jwt
    except Exception:
        return
    try:
        original_encode = jwt.encode
        if not getattr(original_encode, "_cryptoscan_wrapped", False):
            def encode(*args, **kwargs):
                result = original_encode(*args, **kwargs)
                algorithm = kwargs.get("algorithm", args[2] if len(args) > 2 else "HS256")
                _record("crypto", f"JWT {algorithm}", "sign")
                return result
            encode._cryptoscan_wrapped = True
            jwt.encode = encode
    except Exception:
        pass
    try:
        original_decode = jwt.decode
        if not getattr(original_decode, "_cryptoscan_wrapped", False):
            def decode(*args, **kwargs):
                result = original_decode(*args, **kwargs)
                algorithms = kwargs.get("algorithms", args[2] if len(args) > 2 else [])
                algorithm = algorithms[0] if isinstance(algorithms, (list, tuple)) and algorithms else "JWT"
                _record("crypto", f"JWT {algorithm}", "verify")
                return result
            decode._cryptoscan_wrapped = True
            jwt.decode = decode
    except Exception:
        pass


def _flush_loop():
    while not _STOP.wait(1):
        batch = []
        try:
            with _LOCK:
                keys = list(_QUEUE)[:50]
                batch = [_QUEUE.pop(key) for key in keys]
            if not batch or not _INGEST_URL or not _INGEST_TOKEN:
                continue
            request = urllib.request.Request(
                _INGEST_URL,
                data=json.dumps({"events": batch}, separators=(",", ":")).encode("utf-8"),
                headers={"Content-Type": "application/json", "X-CryptoScan-Token": _INGEST_TOKEN},
                method="POST",
            )
            _LOCAL.suppressed = True
            try:
                with urllib.request.urlopen(request, timeout=5) as response:
                    response.read(1024)
            finally:
                _LOCAL.suppressed = False
        except Exception:
            _LOCAL.suppressed = False
            try:
                with _LOCK:
                    for event in batch:
                        identity = json.dumps(
                            [event["source"], event["algorithm"], event["operation"], event["keyInfo"], event["callerScript"], event["hostOrigin"]],
                            sort_keys=True,
                            separators=(",", ":"),
                        )
                        if identity in _QUEUE:
                            _QUEUE[identity]["count"] += event["count"]
                        else:
                            _QUEUE[identity] = event
            except Exception:
                pass


def start(session_id=None, ingest_url=None, token=None):
    """Install hooks and send metadata; missing session configuration is a no-op."""
    global _STARTED, _SESSION_ID, _INGEST_URL, _INGEST_TOKEN
    session_id = session_id or os.environ.get("CRYPTOSCAN_SESSION")
    ingest_url = ingest_url or os.environ.get("CRYPTOSCAN_INGEST")
    token = token or os.environ.get("CRYPTOSCAN_TOKEN")
    if not session_id or not ingest_url or not token or _STARTED:
        return
    if not re.fullmatch(r"[A-Za-z0-9_-]{32,100}", str(token)):
        return
    _SESSION_ID = str(session_id)
    _INGEST_URL = str(ingest_url)
    _INGEST_TOKEN = str(token)
    _STARTED = True

    for name in ("md5", "sha1", "sha256", "sha384", "sha512", "new"):
        _wrap(hashlib, name, _hashlib_new_name if name == "new" else _hashlib_method_name(name), "digest")
    _wrap(hmac, "new", _hmac_name, "hmac")
    for name in (
        "random", "randint", "randrange", "choice", "choices", "uniform", "getrandbits", "randbytes",
        "shuffle", "sample", "triangular", "normalvariate", "gauss", "lognormvariate", "expovariate",
        "vonmisesvariate", "gammavariate", "betavariate", "paretovariate", "weibullvariate",
    ):
        _wrap(random, name, "Python random." + name, "random")
    for name in ("token_bytes", "token_hex", "token_urlsafe", "choice", "randbelow"):
        _wrap(secrets, name, "secrets", "random")
    _wrap(os, "urandom", "os.urandom", "random")
    _wrap(uuid, "uuid4", "uuid.uuid4", "random")
    _wrap_ssl_context()
    _wrap_jwt()
    _STOP.clear()
    threading.Thread(target=_flush_loop, daemon=True, name="cryptoscan-agent-flush").start()


def stop():
    """Stop the optional agent's background flusher."""
    _STOP.set()

"""Metadata-only runtime crypto observation for Python applications."""

import hashlib
import hmac
import json
import os
import random
import re
import secrets
import ssl
import threading
import time
import traceback
import urllib.error
import urllib.request
import uuid

_lock = threading.Lock()
_queue = {}
_started = False
_stop_event = threading.Event()
_local = threading.local()
_agent_path = os.path.abspath(__file__)
_allowed_algorithm = re.compile(
    r"^(?:Python random\.(?:random|randint|randrange|choice|choices|uniform|getrandbits|randbytes|shuffle|sample|"
    r"triangular|normalvariate|gauss|lognormvariate|expovariate|vonmisesvariate|gammavariate|betavariate|paretovariate|weibullvariate)|"
    r"secrets|os\.urandom|uuid\.uuid4|SSLContext|MD5|SHA-1|SHA-256|SHA-384|SHA-512|SHA3-(?:256|384|512)|"
    r"HMAC-(?:MD5|SHA-1|SHA-256|SHA-384|SHA-512))$"
)


def _site():
    try:
        frames = traceback.extract_stack()[:-2]
        for frame in reversed(frames):
            if os.path.abspath(frame.filename) != _agent_path:
                if frame.filename.startswith("<") and frame.filename.endswith(">"):
                    return f"unknown:{frame.lineno}"
                return f"{frame.filename}:{frame.lineno}"[:500]
    except Exception:
        pass
    return "unknown:0"


def _record(algorithm, operation, key_info=None, call_site=None):
    try:
        if not _allowed_algorithm.fullmatch(str(algorithm)):
            return
        event = {
            "algorithm": str(algorithm)[:100],
            "operation": operation,
            "keyInfo": key_info or {},
            "callSite": call_site or _site(),
            "language": "Python",
            "count": 1,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        key = json.dumps(
            [event["algorithm"], event["operation"], event["keyInfo"], event["callSite"]],
            sort_keys=True,
            separators=(",", ":"),
        )
        with _lock:
            if key in _queue:
                _queue[key]["count"] += 1
            else:
                _queue[key] = event
    except Exception:
        pass


def _wrap(target, name, algorithm, operation):
    try:
        original = getattr(target, name)
        if not callable(original) or getattr(original, "_cryptoscan_wrapped", False):
            return

        def observed(*args, **kwargs):
            depth = getattr(_local, "depth", 0)
            _local.depth = depth + 1
            try:
                result = original(*args, **kwargs)
            finally:
                _local.depth = depth
            if depth == 0 and not getattr(_local, "suppress", False):
                try:
                    resolved = algorithm(args, kwargs) if callable(algorithm) else algorithm
                    _record(resolved, operation)
                except Exception:
                    pass
            return result

        observed._cryptoscan_wrapped = True
        observed.__name__ = getattr(original, "__name__", name)
        observed.__qualname__ = getattr(original, "__qualname__", name)
        setattr(target, name, observed)
    except Exception:
        pass


def _algorithm_from_hash_args(args, kwargs):
    name = args[0] if args and isinstance(args[0], str) else kwargs.get("name", "hashlib.new")
    normalized = str(name).lower().replace("_", "-")
    aliases = {
        "sha1": "SHA-1", "sha-1": "SHA-1",
        "sha256": "SHA-256", "sha-256": "SHA-256",
        "sha384": "SHA-384", "sha-384": "SHA-384",
        "sha512": "SHA-512", "sha-512": "SHA-512",
        "sha3-256": "SHA3-256", "sha3-384": "SHA3-384", "sha3-512": "SHA3-512",
        "md5": "MD5",
    }
    return aliases.get(normalized, str(name)[:100])


def _hmac_algorithm(args, kwargs):
    digest = kwargs.get("digestmod")
    if digest is None and len(args) > 2:
        digest = args[2]
    if digest is None:
        return "HMAC-unknown"
    raw_name = digest if isinstance(digest, str) else getattr(digest, "__name__", "unknown")
    raw_name = str(raw_name).lower().replace("openssl_", "").replace("_", "-")
    normalized = _algorithm_from_hash_args((raw_name,), {})
    return "HMAC-" + normalized


def _ssl_context_algorithm(args, kwargs):
    return "SSLContext"


def _flush_loop(ingest_url, token):
    while not _stop_event.wait(1):
        batch = []
        try:
            with _lock:
                keys = list(_queue)[:50]
                batch = [_queue.pop(key) for key in keys]
            if not batch:
                continue
            payload = json.dumps({"events": batch}, separators=(",", ":")).encode("utf-8")
            request = urllib.request.Request(
                ingest_url,
                data=payload,
                headers={"Content-Type": "application/json", "X-CryptoScan-Token": token},
                method="POST",
            )
            _local.suppress = True
            try:
                with urllib.request.urlopen(request, timeout=5) as response:
                    response.read(1024)
            finally:
                _local.suppress = False
        except Exception:
            try:
                with _lock:
                    for event in batch:
                        key = json.dumps(
                            [event["algorithm"], event["operation"], event["keyInfo"], event["callSite"]],
                            sort_keys=True,
                            separators=(",", ":"),
                        )
                        if key in _queue:
                            _queue[key]["count"] += event["count"]
                        else:
                            _queue[key] = event
            except Exception:
                pass


def start(session_id=None, ingest_url=None, token=None):
    """Install hooks and flush metadata; missing configuration makes this a no-op."""
    global _started
    session_id = session_id or os.environ.get("CRYPTOSCAN_SESSION")
    ingest_url = ingest_url or os.environ.get("CRYPTOSCAN_INGEST")
    token = token or os.environ.get("CRYPTOSCAN_TOKEN")
    if not session_id or not ingest_url or not token or _started:
        return
    _started = True

    for name in (
        "random", "randint", "randrange", "choice", "choices", "uniform", "getrandbits", "randbytes", "shuffle", "sample",
        "triangular", "normalvariate", "gauss", "lognormvariate", "expovariate", "vonmisesvariate", "gammavariate",
        "betavariate", "paretovariate", "weibullvariate",
    ):
        _wrap(random, name, "Python random." + name, "random")
    for name in ("token_bytes", "token_hex", "token_urlsafe", "choice", "randbelow"):
        _wrap(secrets, name, "secrets", "random")
    _wrap(os, "urandom", "os.urandom", "random")
    _wrap(uuid, "uuid4", "uuid.uuid4", "random")

    for name in ("md5", "sha1", "sha256", "sha512"):
        _wrap(hashlib, name, "SHA-" + name[3:] if name.startswith("sha") else name.upper(), "hash")
    _wrap(hashlib, "new", _algorithm_from_hash_args, "hash")
    _wrap(hmac, "new", _hmac_algorithm, "hmac")
    _wrap(ssl, "create_default_context", _ssl_context_algorithm, "tls")
    try:
        _wrap(ssl.SSLContext, "__init__", _ssl_context_algorithm, "tls")
    except Exception:
        pass

    threading.Thread(target=_flush_loop, args=(ingest_url, token), daemon=True, name="cryptoscan-runtime-flush").start()


def stop():
    """Stop the background flusher; server-side Stop remains the source of truth."""
    _stop_event.set()

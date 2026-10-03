"""
Python Runtime Cryptographic Instrumentation Tracer for CryptoScan.
Hooks crypto libraries (hashlib, hmac, cryptography, PyCryptodome, PyJWT, ssl)
and records metadata-only execution events to JSONL.
"""

import atexit
import json
import os
import sys
import threading
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional, List

from runtime.normalize import normalize_algorithm
from runtime.schema import RuntimeEvent, validate_event_dict

_LOCK = threading.Lock()
_EVENT_BUFFER: List[Dict[str, Any]] = []
_RUN_ID: str = os.getenv("CRYPTOSCAN_RUN_ID", str(uuid.uuid4()))
_OUT_PATH: str = os.getenv("CRYPTOSCAN_RUNTIME_OUT", "runtime_events.jsonl")
_HOOKS_INSTALLED = False


def _get_caller_info() -> Dict[str, Any]:
    """Finds the first stack frame outside runtime/python_agent and standard wrapper code."""
    try:
        frame = sys._getframe(2)
        while frame:
            filename = frame.f_code.co_filename
            # Skip python internal tracer/hooks
            if "runtime" in filename and "python_agent" in filename:
                frame = frame.f_back
                continue
            if "importlib" in filename or "sitecustomize" in filename:
                frame = frame.f_back
                continue
            
            # Format relative path if possible
            rel_path = filename
            try:
                rel_path = os.path.relpath(filename)
            except Exception:
                pass

            return {
                "call_file": rel_path,
                "call_line": frame.f_lineno,
                "call_function": frame.f_code.co_name,
            }
    except Exception:
        pass
    return {"call_file": "unknown", "call_line": 0, "call_function": "unknown"}


def emit_event(
    library: str,
    operation: str,
    algorithm: str,
    key_size: Optional[int] = None,
    mode: Optional[str] = None,
    padding: Optional[str] = None,
    curve: Optional[str] = None,
):
    """Thread-safe event collector that writes metadata-only records to output file."""
    try:
        caller = _get_caller_info()
        norm_algo = normalize_algorithm(algorithm)
        
        event_obj = RuntimeEvent(
            event_id=str(uuid.uuid4()),
            run_id=_RUN_ID,
            timestamp=datetime.now(timezone.utc).isoformat(),
            language="python",
            library=library,
            operation=operation,
            algorithm=norm_algo,
            key_size=key_size,
            mode=mode,
            padding=padding,
            curve=curve,
            call_file=caller["call_file"],
            call_line=caller["call_line"],
            call_function=caller["call_function"],
        )
        
        event_dict = event_obj.to_dict()

        with _LOCK:
            _EVENT_BUFFER.append(event_dict)
            _flush_events_to_file()
    except Exception:
        pass  # Never crash the target app


def _flush_events_to_file():
    global _EVENT_BUFFER
    if not _EVENT_BUFFER:
        return
    try:
        out_dir = os.path.dirname(_OUT_PATH)
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
        with open(_OUT_PATH, "a", encoding="utf-8") as f:
            for evt in _EVENT_BUFFER:
                f.write(json.dumps(evt) + "\n")
        _EVENT_BUFFER = []
    except Exception:
        pass


def install_hooks():
    global _HOOKS_INSTALLED
    if _HOOKS_INSTALLED:
        return
    _HOOKS_INSTALLED = True

    _hook_hashlib()
    _hook_hmac()
    _hook_cryptography()
    _hook_pycryptodome()
    _hook_pyjwt()
    _hook_ssl()

    atexit.register(_flush_events_to_file)


# ── Hook Implementations ──────────────────────────────────────────────────

def _hook_hashlib():
    try:
        import hashlib

        # Hook hashlib.new
        orig_new = hashlib.new

        def hooked_new(name, *args, **kwargs):
            try:
                emit_event(library="hashlib", operation="hash", algorithm=str(name))
            except Exception:
                pass
            return orig_new(name, *args, **kwargs)

        hashlib.new = hooked_new

        # Hook specific constructors like hashlib.sha256, md5, etc.
        hash_funcs = ["md5", "sha1", "sha224", "sha256", "sha384", "sha512", "blake2b", "blake2s"]
        for func_name in hash_funcs:
            if hasattr(hashlib, func_name):
                orig_func = getattr(hashlib, func_name)

                def make_wrapper(fn_name, orig_fn):
                    def wrapper(*args, **kwargs):
                        try:
                            emit_event(library="hashlib", operation="hash", algorithm=fn_name)
                        except Exception:
                            pass
                        return orig_fn(*args, **kwargs)
                    return wrapper

                setattr(hashlib, func_name, make_wrapper(func_name, orig_func))
    except Exception:
        pass


def _hook_hmac():
    try:
        import hmac

        orig_new = hmac.new

        def hooked_new(key, msg=None, digestmod=None, *args, **kwargs):
            try:
                algo_name = "HMAC"
                if digestmod:
                    if isinstance(digestmod, str):
                        algo_name = f"HMAC-{digestmod}"
                    elif hasattr(digestmod, "name"):
                        algo_name = f"HMAC-{digestmod.name}"
                    elif callable(digestmod):
                        algo_name = f"HMAC-{getattr(digestmod, '__name__', 'custom')}"
                emit_event(library="hmac", operation="hmac", algorithm=algo_name)
            except Exception:
                pass
            return orig_new(key, msg=msg, digestmod=digestmod, *args, **kwargs)

        hmac.new = hooked_new
    except Exception:
        pass


def _hook_cryptography():
    try:
        import cryptography  # noqa: F401

        # Hook symmetric ciphers (Cipher class — CBC, CTR, etc.)
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher
            orig_cipher_init = Cipher.__init__

            def hooked_cipher_init(self, algorithm, mode, backend=None):
                try:
                    algo_name = getattr(algorithm, "name", str(type(algorithm).__name__))
                    key_size = getattr(algorithm, "key_size", None)
                    mode_name = getattr(mode, "name", str(type(mode).__name__)) if mode else None
                    emit_event(
                        library="cryptography",
                        operation="encrypt",
                        algorithm=algo_name,
                        key_size=key_size,
                        mode=mode_name,
                    )
                except Exception:
                    pass
                return orig_cipher_init(self, algorithm, mode, backend=backend)

            Cipher.__init__ = hooked_cipher_init
        except Exception:
            pass

        # Hook AEAD ciphers (AESGCM, AESCCM, ChaCha20Poly1305)
        try:
            from cryptography.hazmat.primitives.ciphers import aead as _aead

            def _make_aead_hook(cls_name, algo_label, mode_label):
                """Patches encrypt/decrypt on an AEAD class to emit events."""
                try:
                    cls = getattr(_aead, cls_name)
                except AttributeError:
                    return

                orig_encrypt = cls.encrypt
                orig_decrypt = cls.decrypt

                def hooked_encrypt(self, nonce, data, aad=None):
                    try:
                        key_size = len(self._key) * 8 if hasattr(self, "_key") else None
                        emit_event(
                            library="cryptography",
                            operation="encrypt",
                            algorithm=algo_label,
                            key_size=key_size,
                            mode=mode_label,
                        )
                    except Exception:
                        pass
                    return orig_encrypt(self, nonce, data, aad)

                def hooked_decrypt(self, nonce, data, aad=None):
                    try:
                        key_size = len(self._key) * 8 if hasattr(self, "_key") else None
                        emit_event(
                            library="cryptography",
                            operation="decrypt",
                            algorithm=algo_label,
                            key_size=key_size,
                            mode=mode_label,
                        )
                    except Exception:
                        pass
                    return orig_decrypt(self, nonce, data, aad)

                cls.encrypt = hooked_encrypt
                cls.decrypt = hooked_decrypt

            _make_aead_hook("AESGCM", "AES", "GCM")
            _make_aead_hook("AESCCM", "AES", "CCM")
            _make_aead_hook("ChaCha20Poly1305", "ChaCha20", "Poly1305")
        except Exception:
            pass

        # Hook RSA keygen
        try:
            from cryptography.hazmat.primitives.asymmetric import rsa
            orig_generate_rsa = rsa.generate_private_key

            def hooked_gen_rsa(public_exponent, key_size, backend=None):
                try:
                    emit_event(
                        library="cryptography",
                        operation="keygen",
                        algorithm="RSA",
                        key_size=key_size,
                    )
                except Exception:
                    pass
                return orig_generate_rsa(public_exponent, key_size, backend=backend)

            rsa.generate_private_key = hooked_gen_rsa
        except Exception:
            pass

        # Hook RSA sign/verify
        try:
            from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
            orig_rsa_sign = RSAPrivateKey.sign

            def hooked_rsa_sign(self, data, padding, algorithm):
                try:
                    key_size = self.key_size if hasattr(self, "key_size") else None
                    pad_name = type(padding).__name__ if padding is not None else None
                    emit_event(
                        library="cryptography",
                        operation="sign",
                        algorithm="RSA",
                        key_size=key_size,
                        padding=pad_name,
                    )
                except Exception:
                    pass
                return orig_rsa_sign(self, data, padding, algorithm)

            RSAPrivateKey.sign = hooked_rsa_sign
        except Exception:
            pass

        # Hook EC keygen
        try:
            from cryptography.hazmat.primitives.asymmetric import ec
            orig_generate_ec = ec.generate_private_key

            def hooked_gen_ec(curve, backend=None):
                try:
                    curve_name = getattr(curve, "name", str(type(curve).__name__))
                    emit_event(
                        library="cryptography",
                        operation="keygen",
                        algorithm="ECDSA",
                        curve=curve_name,
                    )
                except Exception:
                    pass
                return orig_generate_ec(curve, backend=backend)

            ec.generate_private_key = hooked_gen_ec
        except Exception:
            pass

        # Hook EC sign
        try:
            from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
            orig_ec_sign = EllipticCurvePrivateKey.sign

            def hooked_ec_sign(self, data, signature_algorithm):
                try:
                    curve_name = getattr(self.curve, "name", None) if hasattr(self, "curve") else None
                    emit_event(
                        library="cryptography",
                        operation="sign",
                        algorithm="ECDSA",
                        curve=curve_name,
                    )
                except Exception:
                    pass
                return orig_ec_sign(self, data, signature_algorithm)

            EllipticCurvePrivateKey.sign = hooked_ec_sign
        except Exception:
            pass

    except Exception:
        pass


def _hook_pycryptodome():
    try:
        import Crypto.Cipher.AES as AES
        orig_aes_new = AES.new

        def hooked_aes_new(key, mode, *args, **kwargs):
            try:
                key_size = len(key) * 8 if hasattr(key, "__len__") else None
                mode_str = str(mode)
                emit_event(
                    library="PyCryptodome",
                    operation="encrypt",
                    algorithm="AES",
                    key_size=key_size,
                    mode=mode_str,
                )
            except Exception:
                pass
            return orig_aes_new(key, mode, *args, **kwargs)

        AES.new = hooked_aes_new
    except Exception:
        pass


def _hook_pyjwt():
    try:
        import jwt
        orig_encode = jwt.encode
        orig_decode = jwt.decode

        def hooked_encode(payload, key, algorithm="HS256", *args, **kwargs):
            try:
                emit_event(library="PyJWT", operation="sign", algorithm=str(algorithm))
            except Exception:
                pass
            return orig_encode(payload, key, algorithm=algorithm, *args, **kwargs)

        def hooked_decode(jwt_str, key="", algorithms=None, *args, **kwargs):
            try:
                algo = str(algorithms[0]) if algorithms and isinstance(algorithms, list) else "JWT"
                emit_event(library="PyJWT", operation="verify", algorithm=algo)
            except Exception:
                pass
            return orig_decode(jwt_str, key=key, algorithms=algorithms, *args, **kwargs)

        jwt.encode = hooked_encode
        jwt.decode = hooked_decode
    except Exception:
        pass


def _hook_ssl():
    try:
        import ssl
        orig_wrap = ssl.SSLContext.wrap_socket

        def hooked_wrap(self, sock, *args, **kwargs):
            res = orig_wrap(self, sock, *args, **kwargs)
            try:
                cipher = res.cipher()
                cipher_name = cipher[0] if cipher else "TLS"
                version = res.version() if hasattr(res, "version") else "TLS"
                emit_event(library="ssl", operation="tls", algorithm=f"{version}:{cipher_name}")
            except Exception:
                pass
            return res

        ssl.SSLContext.wrap_socket = hooked_wrap
    except Exception:
        pass


# Automatically install hooks when imported
install_hooks()

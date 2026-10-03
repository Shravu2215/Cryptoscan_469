"""
Deterministic Git Repository Builder for Crypto Time Machine (Feature 5).
Creates a 7-commit synthetic Git repository in a specified target directory.
Usage:
    python timemachine/demo/make_demo_repo.py [--target-dir scratch/demo_repo]
"""

import argparse
import os
import shutil
import subprocess
import sys


def run_git(cmd_args, cwd, env_vars=None):
    """Run a git command safely with hooks disabled."""
    full_env = os.environ.copy()
    if sys.platform == "win32":
        full_env["GIT_CONFIG_PARAMETERS"] = "'core.hooksPath=NUL'"
    else:
        full_env["GIT_CONFIG_PARAMETERS"] = "'core.hooksPath=/dev/null'"
    if env_vars:
        full_env.update(env_vars)

    cmd = ["git"] + cmd_args
    res = subprocess.run(cmd, cwd=cwd, env=full_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if res.returncode != 0:
        raise RuntimeError(f"Git command failed ({' '.join(cmd)}): {res.stderr.strip()}")
    return res.stdout.strip()


def create_demo_repo(target_dir: str) -> str:
    abs_target = os.path.abspath(target_dir)

    if os.path.exists(abs_target):
        shutil.rmtree(abs_target, ignore_errors=True)

    os.makedirs(abs_target, exist_ok=True)

    # 1. Initialize git repository
    run_git(["init"], cwd=abs_target)
    run_git(["config", "user.name", "CryptoScan Demo Author"], cwd=abs_target)
    run_git(["config", "user.email", "demo@cryptoscan.internal"], cwd=abs_target)

    dates = [
        "2026-01-01T10:00:00Z",
        "2026-01-02T10:00:00Z",
        "2026-01-03T10:00:00Z",
        "2026-01-04T10:00:00Z",
        "2026-01-05T10:00:00Z",
        "2026-01-06T10:00:00Z",
        "2026-01-07T10:00:00Z",
    ]

    # --- Commit 1 (C1): Add app.py with MD5 and SHA-256 ---
    app_py_c1 = '''import hashlib

def hash_password(password: str) -> str:
    """Weak MD5 password hashing."""
    return hashlib.md5(password.encode()).hexdigest()

def hash_file(data: bytes) -> str:
    """SHA-256 file hashing."""
    return hashlib.sha256(data).hexdigest()
'''
    with open(os.path.join(abs_target, "app.py"), "w", encoding="utf-8") as f:
        f.write(app_py_c1)
    run_git(["add", "app.py"], cwd=abs_target)
    env_c1 = {"GIT_AUTHOR_DATE": dates[0], "GIT_COMMITTER_DATE": dates[0]}
    run_git(["commit", "-m", "C1: Add app.py using MD5 and SHA-256"], cwd=abs_target, env_vars=env_c1)

    # --- Commit 2 (C2): Add RSA-1024 key generation in keys.py ---
    keys_py_c2 = '''from cryptography.hazmat.primitives.asymmetric import rsa

def generate_key():
    """Weak RSA-1024 key generation."""
    return rsa.generate_private_key(public_exponent=65537, key_size=1024)
'''
    with open(os.path.join(abs_target, "keys.py"), "w", encoding="utf-8") as f:
        f.write(keys_py_c2)
    run_git(["add", "keys.py"], cwd=abs_target)
    env_c2 = {"GIT_AUTHOR_DATE": dates[1], "GIT_COMMITTER_DATE": dates[1]}
    run_git(["commit", "-m", "C2: Add RSA-1024 key generation in keys.py"], cwd=abs_target, env_vars=env_c2)

    # --- Commit 3 (C3): Commit deploy_key.pem containing a DUMMY private key ---
    dummy_key = '''-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAzDUMMYR5UEEtVl6K+5V0d8J8n0+0DUMMYKEY000000000000
DUMMY DUMMY DUMMY DUMMY DUMMY DUMMY DUMMY DUMMY DUMMY DUMMY DUMMY
-----END RSA PRIVATE KEY-----
'''
    with open(os.path.join(abs_target, "deploy_key.pem"), "w", encoding="utf-8") as f:
        f.write(dummy_key)
    run_git(["add", "deploy_key.pem"], cwd=abs_target)
    env_c3 = {"GIT_AUTHOR_DATE": dates[2], "GIT_COMMITTER_DATE": dates[2]}
    run_git(["commit", "-m", "C3: Commit deploy_key.pem dummy key"], cwd=abs_target, env_vars=env_c3)

    # --- Commit 4 (C4): Delete deploy_key.pem ---
    os.remove(os.path.join(abs_target, "deploy_key.pem"))
    run_git(["rm", "deploy_key.pem"], cwd=abs_target)
    env_c4 = {"GIT_AUTHOR_DATE": dates[3], "GIT_COMMITTER_DATE": dates[3]}
    run_git(["commit", "-m", "C4: Delete deploy_key.pem"], cwd=abs_target, env_vars=env_c4)

    # --- Commit 5 (C5): Replace MD5 with SHA-256 in app.py ---
    app_py_c5 = '''import hashlib

def hash_password(password: str) -> str:
    """Upgraded to SHA-256 password hashing."""
    return hashlib.sha256(password.encode()).hexdigest()

def hash_file(data: bytes) -> str:
    """SHA-256 file hashing."""
    return hashlib.sha256(data).hexdigest()
'''
    with open(os.path.join(abs_target, "app.py"), "w", encoding="utf-8") as f:
        f.write(app_py_c5)
    run_git(["add", "app.py"], cwd=abs_target)
    env_c5 = {"GIT_AUTHOR_DATE": dates[4], "GIT_COMMITTER_DATE": dates[4]}
    run_git(["commit", "-m", "C5: Replace MD5 with SHA-256 in app.py"], cwd=abs_target, env_vars=env_c5)

    # --- Commit 6 (C6): Replace RSA-1024 with RSA-2048 in keys.py ---
    keys_py_c6 = '''from cryptography.hazmat.primitives.asymmetric import rsa

def generate_key():
    """Upgraded RSA-2048 key generation."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)
'''
    with open(os.path.join(abs_target, "keys.py"), "w", encoding="utf-8") as f:
        f.write(keys_py_c6)
    run_git(["add", "keys.py"], cwd=abs_target)
    env_c6 = {"GIT_AUTHOR_DATE": dates[5], "GIT_COMMITTER_DATE": dates[5]}
    run_git(["commit", "-m", "C6: Replace RSA-1024 with RSA-2048 in keys.py"], cwd=abs_target, env_vars=env_c6)

    # --- Commit 7 (C7): Add ECDSA P-256 signing in sign.py ---
    sign_py_c7 = '''from cryptography.hazmat.primitives.asymmetric import ec

def sign_data():
    """ECDSA P-256 key generation."""
    return ec.generate_private_key(ec.SECP256R1())
'''
    with open(os.path.join(abs_target, "sign.py"), "w", encoding="utf-8") as f:
        f.write(sign_py_c7)
    run_git(["add", "sign.py"], cwd=abs_target)
    env_c7 = {"GIT_AUTHOR_DATE": dates[6], "GIT_COMMITTER_DATE": dates[6]}
    run_git(["commit", "-m", "C7: Add ECDSA P-256 signing in sign.py"], cwd=abs_target, env_vars=env_c7)

    print(f"[Demo Repo] Successfully created 7-commit repository at {abs_target}")
    return abs_target


def main():
    parser = argparse.ArgumentParser(description="Create synthetic 7-commit demo Git repository")
    parser.add_argument("--target-dir", default="scratch/demo_repo", help="Target directory for demo git repository")
    args = parser.parse_args()

    create_demo_repo(args.target_dir)


if __name__ == "__main__":
    main()

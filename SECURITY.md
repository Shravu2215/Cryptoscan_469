# SECURITY.md – Hostile-Repository Hardening

## Overview

CryptoScan scans untrusted, third-party repositories.  This document
lists every threat covered by the **Hostile-Repository Hardening** feature,
the corresponding mitigations, and all configurable limits.

---

## Threats Covered

| # | Threat | Mitigation | Location |
|---|--------|-----------|----------|
| T-01 | **Malicious git hooks** (`pre-receive`, `post-checkout`, etc.) executed during clone | Repos are imported as ZIP archives via the GitHub REST API (`/zipball`) — no `git clone` is ever executed, so hooks never run | `repos.js` |
| T-02 | **Zip-slip / path traversal** in uploaded archives (`../../etc/passwd`, `/abs/path`) | Every entry's resolved path is checked against the extraction root; absolute paths and `../` entries are rejected before any extraction | `archiveSafety.js` |
| T-03 | **Symlinks / hardlinks escaping the scan root** | Unix file-type bit checked per entry; entries with symlink mode are written as `*.symlink_blocked` plain text; post-write `realpath` check removes any that escape | `archiveSafety.js` |
| T-04 | **Zip bomb** — extreme compression ratios, huge file counts, deep nesting | Four independent guards: max uncompressed bytes, per-entry compression ratio, max file count, max nesting depth — all configurable via env | `archiveSafety.js`, `security.py` |
| T-05 | **Oversized files** crashing the scanner (OOM / timeout) | Each file is `lstat`-ed before reading; files exceeding `MAX_FILE_SIZE_BYTES` are skipped with a `SKIP-OVERSIZED` reason in the manifest | `security.py`, `pipeline.py` |
| T-06 | **Total scan size** exceeding available memory | Rolling `total_bytes` counter; once it exceeds `MAX_TOTAL_SIZE_BYTES` all remaining files are skipped | `security.py`, `pipeline.py` |
| T-07 | **Too many files** (DoS via directory depth / inode exhaustion) | File walk capped at `MAX_FILE_COUNT`; excess entries reported as `SKIP-MAX-FILE-COUNT` | `pipeline.py` |
| T-08 | **Per-file analysis hang** (pathological AST, regex catastrophic backtracking) | `FileTimeout` context manager raises `_TimeoutError` after `PER_FILE_TIMEOUT_SEC`; file is skipped | `security.py`, `pipeline.py` |
| T-09 | **Whole-scan hang** | `ScanBudget` tracks elapsed time; once `SCAN_TIMEOUT_SEC` is exceeded all remaining files are skipped | `security.py`, `pipeline.py` |
| T-10 | **Minified / obfuscated files** causing slow regex / extreme output | Files with any line > `MAX_LINE_LEN_MINIFIED` chars or very low line density are skipped | `security.py`, `pipeline.py` |
| T-11 | **Binary files** causing text decoder OOM / parse errors | `is_binary_content()` checks the first 8 KB for null bytes / non-text ratio; binary files are passed to `BinaryAnalyzer` only | `security.py`, `pipeline.py` |
| T-12 | **SSRF via repository URL** — scanning internal services, cloud-metadata endpoints (`169.254.169.254`) | URL validated against an HTTPS-only, host-allowlisted, DNS-resolved SSRF-safe validator; private IPv4/IPv6 ranges blocked | `repoSecurity.js` |
| T-13 | **Shell injection via repo path** in scanner invocation | `exec()` replaced with `execFile()` (no shell); repo path passed as a separate argument array, never interpolated into a shell string | `scans.js` |
| T-14 | **Untrusted scanner output** (poisoned JSON, XSS in filenames / snippets) | `filePath` from scanner output sanitized via `sanitizeFilePath()`; text fields capped via `sanitizeSnippet()`; frontend must use `textContent` not `innerHTML` | `scans.js`, `repoSecurity.js` |
| T-15 | **Leaked data via DB** — malicious repo name / path injected into logs or DB | `sanitizeRepoName()` strips control chars, HTML chars, limits length; file paths sanitized before DB write | `repos.js`, `repoSecurity.js` |
| T-16 | **Scanner process running as root** with full filesystem access | Scanner container runs as UID 10001 (non-root), `cap_drop: ALL`, `read_only: true`, writable only to `/tmp/scan` tmpfs | `scanner/Dockerfile`, `docker-compose.yml` |
| T-17 | **Scanner exfiltrating data via network** | Scanner container uses an `internal: true` Docker bridge network; `no-new-privileges` security opt; only backend-core can reach port 5001 | `docker-compose.yml` |
| T-18 | **Fork bomb / CPU starvation from scanned code** | `pids_limit` on scanner container; CPU/memory limits via `deploy.resources.limits` | `docker-compose.yml` |
| T-19 | **Temp directory leak** on failure / timeout / crash | `try/finally` in `scan_repo()` always calls `temp_dir.cleanup()`; Node-side `execFile` error path also cleans up | `pipeline.py`, `scans.js` |
| T-20 | **Silent file drops** hiding skipped hostile files from the report | Every file visited by `os.walk` appears in `file_manifest` with `SCANNED`, `SKIPPED`, or `ERROR` status and a `reason` | `pipeline.py` |

---

## Configurable Limits

All limits are read from environment variables at startup with safe defaults.

### Archive (Upload / GitHub Import)

| Env Var | Default | Description |
|---------|---------|-------------|
| `MAX_UPLOAD_SIZE_MB` | `50` | Maximum compressed archive size accepted for upload or GitHub download |
| `MAX_EXTRACTED_SIZE_MB` | `512` | Maximum total uncompressed bytes across all entries in an archive |
| `MAX_COMPRESSION_RATIO` | `100` | Maximum per-entry compression ratio (uncompressed / compressed) |
| `MAX_ARCHIVE_FILES` | `50000` | Maximum number of entries in a single archive |
| `MAX_ARCHIVE_DEPTH` | `20` | Maximum directory nesting depth inside an archive |
| `MAX_SINGLE_FILE_MB` | `50` | Maximum single-entry uncompressed size |

### Scanner (per-scan, all in `security.py`)

| Env Var | Default | Description |
|---------|---------|-------------|
| `SCANNER_MAX_FILE_SIZE_MB` | `10` | Maximum size of a single file the scanner will read (text decode) |
| `SCANNER_MAX_TOTAL_SIZE_MB` | `512` | Maximum total bytes read across all files in one scan |
| `SCANNER_MAX_FILES` | `50000` | Maximum files visited in one scan |
| `SCANNER_MAX_AST_DEPTH` | `50` | Maximum AST tree depth (future: passed to tree-sitter parsers) |
| `SCANNER_MAX_AST_NODES` | `100000` | Maximum AST node count per file |
| `SCANNER_PER_FILE_TIMEOUT_SEC` | `30` | Per-file analysis timeout |
| `SCANNER_SCAN_TIMEOUT_SEC` | `600` | Whole-scan timeout (10 minutes) |
| `SCANNER_MAX_LINE_LEN` | `2000` | Lines longer than this → file treated as minified and skipped |
| `SCANNER_MAX_SNIPPET_LENGTH` | `500` | Maximum code-snippet length in any finding output |

### Docker Sandbox (scanner container)

| Env Var | Default | Description |
|---------|---------|-------------|
| `SCANNER_CPU_LIMIT` | `1.0` | Docker CPU limit for the scanner container |
| `SCANNER_MEMORY_LIMIT` | `1G` | Docker memory limit for the scanner container |
| `SCANNER_PIDS_LIMIT` | `128` | Maximum PIDs in the scanner container (fork-bomb protection) |

### Input Validation

| Env Var | Default | Description |
|---------|---------|-------------|
| `ALLOWED_GIT_HOSTS` | `github.com,gitlab.com,bitbucket.org` | Comma-separated HTTPS hosts allowed for repository import |
| `SSRF_BLOCK_METADATA` | `true` | Set to `false` to skip cloud-metadata IP block (dev only) |

---

## Frontend Safety Note

All scanner output (filenames, code snippets, finding messages) must be
escaped before rendering.  **Never use `innerHTML` with any text that
originates from scanner output.**  Use `element.textContent = value` or
a sanitizer library.  Snippet length is already capped server-side at
`SCANNER_MAX_SNIPPET_LENGTH` bytes.

---

## Test Coverage

Hostile fixture samples are in `scanner/tests/fixtures/hostile/`:

| Fixture | Threat |
|---------|--------|
| `zip_slip.zip` | T-02 (path traversal) |
| `absolute_path.zip` | T-02 (absolute path in archive) |
| `zip_bomb.zip` | T-04 (~1016× compression ratio) |
| `too_many_files.zip` | T-04 (51 000 entries) |
| `deep_nesting.zip` | T-04 (30 directory levels) |
| `malicious_git_repo/.git/hooks/` | T-01 (git hooks never run) |
| `xss_filename.zip` | T-14, T-02 (XSS + traversal in filename) |
| `huge_file_repo/huge.py` | T-05 (60 MB single file) |
| `deep_nesting/deeply_nested.json` | T-08 (1000-level nesting) |
| `xss_filenames/minified.min.js` | T-10 (minified file detection) |

Run with:

```bash
python -m pytest scanner/tests/test_hostile_repo_hardening.py -v
```

Generate/regenerate fixtures:

```bash
python scanner/tests/create_hostile_fixtures.py
```

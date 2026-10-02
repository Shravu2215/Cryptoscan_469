# scanner/Dockerfile – Isolated, low-privilege scanner container
# (Hostile-Repository Hardening, Req 4)
#
# Security properties:
#   • Non-root user (scanner, UID 10001)
#   • Read-only root filesystem (enforced in docker-compose via read_only: true)
#   • Network disabled at compose level (network_mode: none)
#   • CPU/memory/pids limits set in docker-compose
#   • Only a /tmp/scan tmpfs is writable
#   • No SUID binaries, no capabilities beyond what Python needs to read files

FROM python:3.11-slim-bookworm

# Install minimal runtime deps; no build tools, no compilers
RUN apt-get update && apt-get install -y --no-install-recommends \
      libmagic1 \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r scanner && useradd -r -g scanner -u 10001 scanner

WORKDIR /app

# Copy only the scanner directory (not the whole repo)
COPY scanner/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY scanner/ ./scanner/

# Temp dir for scan extractions (tmpfs in compose; fallback here for local dev)
RUN mkdir -p /tmp/scan && chown scanner:scanner /tmp/scan

# Drop to non-root
USER scanner

# The scanner is invoked by backend-core via execFile(python, [pipeline.py, path])
# In Docker mode, backend-core calls the scanner via the internal API below.
EXPOSE 5001

# Simple JSON-over-HTTP shim so backend-core can call the scanner
# without spawning a subprocess across containers.
# Entrypoint: scanner_api.py (see sibling file)
ENTRYPOINT ["python", "-m", "scanner.scanner_api"]

"""JSON CLI wrapper for the existing metadata-only runtime TLS probe."""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scanner.live_tls_analyzer import LiveTLSAnalyzer


def probe(payload):
    host = payload.get("host")
    port = payload.get("port")
    address = payload.get("address")
    if not isinstance(host, str) or not isinstance(address, str) or not isinstance(port, int):
        raise ValueError("host, address, and integer port are required")
    return LiveTLSAnalyzer(timeout=3.0).probe_runtime_endpoint(host, port, address)


if __name__ == "__main__":
    try:
        result = probe(json.load(sys.stdin))
        json.dump(result, sys.stdout, separators=(",", ":"))
    except Exception as error:
        json.dump({"probeSucceeded": False, "error": type(error).__name__}, sys.stdout)
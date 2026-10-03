"""
Runtime Event Uploader Helper Script.
Reads line-delimited JSONL runtime events and posts them to POST /api/runtime/runs.
Usage:
  python runtime/upload.py --file runtime_events.jsonl --scan-id <id> [--api-url http://localhost:3000] [--token <jwt_token>]
"""

import argparse
import json
import os
import sys
import urllib.request
import urllib.error


def upload_runtime_events(
    file_path: str,
    scan_id: str = None,
    api_url: str = "http://localhost:3000",
    token: str = None,
    language: str = "python",
    environment: str = "test",
) -> dict:
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Runtime events file not found: {file_path}")

    events = []
    run_id = None
    with open(file_path, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                evt = json.loads(line)
                events.append(evt)
                if not run_id and evt.get("run_id"):
                    run_id = evt["run_id"]
                if evt.get("language"):
                    language = evt["language"]
            except Exception as e:
                print(f"[Warning] Skipping malformed line {line_num}: {e}")

    payload = {
        "run_id": run_id,
        "scan_id": scan_id,
        "language": language,
        "command": "demo_crypto_app.py",
        "environment": environment,
        "events": events,
    }

    url = f"{api_url.rstrip('/')}/api/runtime/runs"
    data_bytes = json.dumps(payload).encode("utf-8")

    req = urllib.request.Request(url, data=data_bytes, headers={"Content-Type": "application/json"})
    if token:
        req.add_header("Authorization", f"Bearer {token}")

    try:
        with urllib.request.urlopen(req) as resp:
            resp_bytes = resp.read()
            return json.loads(resp_bytes.decode("utf-8"))
    except urllib.error.HTTPError as err:
        err_body = err.read().decode("utf-8")
        raise RuntimeError(f"HTTP Error {err.code}: {err_body}")
    except Exception as err:
        raise RuntimeError(f"Failed to post runtime events to {url}: {err}")


def main():
    parser = argparse.ArgumentParser(description="Upload runtime events JSONL to backend API")
    parser.add_argument("--file", required=True, help="Path to runtime events JSONL file")
    parser.add_argument("--scan-id", help="Scan ID to link this run with")
    parser.add_argument("--api-url", default="http://localhost:3000", help="Base API URL")
    parser.add_argument("--token", help="Optional Bearer token for authentication")

    args = parser.parse_args()

    try:
        res = upload_runtime_events(
            file_path=args.file,
            scan_id=args.scan_id,
            api_url=args.api_url,
            token=args.token,
        )
        print(f"[CryptoScan Upload] Successfully uploaded {res.get('event_count', 0)} events. Run ID: {res.get('run_id')}")
    except Exception as err:
        print(f"[CryptoScan Upload Error] {err}")
        sys.exit(1)


if __name__ == "__main__":
    main()

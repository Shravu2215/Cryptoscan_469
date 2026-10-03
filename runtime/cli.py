"""
CryptoScan Runtime CLI Extension Module.
Handles `cryptoscan runtime run` and `cryptoscan runtime report`.
"""

import sys
import os

_runtime_dir = os.path.dirname(os.path.abspath(__file__))
_repo_root = os.path.dirname(_runtime_dir)
if _repo_root not in sys.path:
    sys.path.insert(0, _repo_root)

import argparse
import json
import subprocess
import tempfile
import uuid
from typing import List, Optional

from runtime.report import generate_report_from_events, generate_report_from_jsonl
from runtime.matcher import match_events_to_findings


def run_command_with_tracer(
    lang: str,
    target_cmd: List[str],
    scan_id: Optional[str] = None,
    out_path: Optional[str] = None,
) -> int:
    """
    Executes a target application command under runtime cryptographic instrumentation.
    Captures JSONL events, runs evidence matcher, prints execution summary, and returns the target process exit code.
    """
    run_id = str(uuid.uuid4())
    temp_jsonl = None

    if not out_path:
        temp_file = tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False)
        out_path = temp_file.name
        temp_file.close()
        temp_jsonl = out_path

    env = os.environ.copy()
    env["CRYPTOSCAN_RUNTIME_OUT"] = out_path
    env["CRYPTOSCAN_RUN_ID"] = run_id

    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

    if lang == "python":
        py_agent_path = os.path.join(repo_root, "runtime", "python_agent")
        existing_pypath = env.get("PYTHONPATH", "")
        env["PYTHONPATH"] = f"{py_agent_path}{os.pathsep}{repo_root}{os.pathsep}{existing_pypath}"
    elif lang == "node":
        preload_path = os.path.join(repo_root, "runtime", "node_agent", "preload.js").replace("\\", "/")
        existing_node_opts = env.get("NODE_OPTIONS", "")
        env["NODE_OPTIONS"] = f"--require \"{preload_path}\" {existing_node_opts}".strip()

    print(f"[CryptoScan Runtime] Starting instrumented execution (Language: {lang}, Run ID: {run_id})...")
    print(f"[CryptoScan Runtime] Executing command: {' '.join(target_cmd)}")

    try:
        res = subprocess.run(target_cmd, env=env)
        exit_code = res.returncode
    except Exception as err:
        print(f"[CryptoScan Runtime] Failed to execute target command: {err}", file=sys.stderr)
        return 1

    print(f"\n[CryptoScan Runtime] Target command finished with exit code {exit_code}.")

    # Parse recorded runtime events
    events = []
    if os.path.exists(out_path):
        try:
            with open(out_path, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        events.append(json.loads(line.strip()))
        except Exception:
            pass

    report_data = generate_report_from_events(
        run_id=run_id,
        raw_events=events,
        scan_id=scan_id,
        language=lang,
        environment="test",
    )

    summary = report_data["summary"]
    print("\n" + "=" * 60)
    print(" CRYPTOSCAN RUNTIME EXECUTION SUMMARY")
    print("=" * 60)
    print(f" Run ID                          : {run_id}")
    print(f" Total Captured Crypto Events    : {summary['total_events']}")
    print(f" Unique Algorithms Executed     : {', '.join(summary['unique_algorithms']) if summary['unique_algorithms'] else 'None'}")
    print(f" Quantum Vulnerable Algorithms   : {', '.join(summary['quantum_vulnerable_algorithms']) if summary['quantum_vulnerable_algorithms'] else 'None'}")

    if temp_jsonl and os.path.exists(temp_jsonl):
        try:
            os.remove(temp_jsonl)
        except Exception:
            pass

    return exit_code


def generate_report_cli(run_id: str, out_path: Optional[str] = None, events_path: Optional[str] = None) -> int:
    """Generates and prints/saves the runtime evidence report."""
    events_file = events_path or "runtime_events.jsonl"
    report_data = generate_report_from_jsonl(events_file, run_id=run_id)

    report_json = json.dumps(report_data, indent=2)

    if out_path:
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(report_json)
        print(f"[CryptoScan Runtime] Report saved to {out_path}")
    else:
        print(report_json)

    return 0


def main(args_list: Optional[List[str]] = None):
    parser = argparse.ArgumentParser(prog="cryptoscan-runtime", description="CryptoScan Runtime Execution Tracing CLI")
    subparsers = parser.add_subparsers(dest="subcommand")

    # `runtime run` subcommand
    run_parser = subparsers.add_parser("run", help="Run application under runtime cryptographic instrumentation")
    run_parser.add_argument("--lang", choices=["python", "node"], required=True, help="Target application language")
    run_parser.add_argument("--scan-id", help="Optional static scan ID for evidence matching")
    run_parser.add_argument("--out", help="Output JSONL events path")
    run_parser.add_argument("command", nargs=argparse.REMAINDER, help="Target command to execute (prefix with --)")

    # `runtime report` subcommand
    report_parser = subparsers.add_parser("report", help="Generate runtime evidence report")
    report_parser.add_argument("--run-id", required=True, help="Run ID")
    report_parser.add_argument("--out", help="Output JSON file path")
    report_parser.add_argument("--events-file", help="Input JSONL events path")

    parsed = parser.parse_args(args_list)

    if parsed.subcommand == "run":
        cmd = parsed.command
        if cmd and cmd[0] == "--":
            cmd = cmd[1:]
        if not cmd:
            print("Error: No target command specified. Usage: cryptoscan runtime run --lang python -- python app.py", file=sys.stderr)
            sys.exit(1)
        code = run_command_with_tracer(lang=parsed.lang, target_cmd=cmd, scan_id=parsed.scan_id, out_path=parsed.out)
        sys.exit(code)
    elif parsed.subcommand == "report":
        code = generate_report_cli(run_id=parsed.run_id, out_path=parsed.out, events_path=parsed.events_file)
        sys.exit(code)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
CryptoScan CLI & Policy Gate Entrypoint.

Usage:
  cryptoscan scan <path> [--out cbom.json]
  cryptoscan gate --base base.cbom.json --head head.cbom.json [--policy .cryptoscan/policy.yaml] [--waivers .cryptoscan/waivers.yaml] [--format md,json] [--out-md report.md] [--out-json report.json]
"""

import argparse
import json
import os
import sys
from typing import Dict, Any

# Ensure project root is in sys.path
_current_dir = os.path.dirname(os.path.abspath(__file__))
_repo_root = os.path.dirname(_current_dir)
if _repo_root not in sys.path:
    sys.path.insert(0, _repo_root)

# Ensure UTF-8 output on all terminals (prevents UnicodeEncodeError on Windows cp1252)
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from gate.cbom_generator import build_cyclonedx_cbom
from gate.engine import evaluate_gate
from gate.policy import load_policy
from gate.waivers import load_waivers
from gate.reporter import generate_markdown_report, generate_json_report


def run_scan(path_to_scan: str, output_path: str = None) -> int:
    """Invokes scanner pipeline and outputs CycloneDX 1.6 CBOM."""
    if not os.path.exists(path_to_scan):
        sys.stderr.write(f"Error: Target path does not exist: {path_to_scan}\n")
        return 2

    try:
        from scanner.pipeline import scan_repo
        print(f"Scanning target: {path_to_scan} ...", file=sys.stderr)
        scan_result = scan_repo(path_to_scan)
        findings = scan_result.get("findings", [])

        repo_name = os.path.basename(os.path.abspath(path_to_scan)) or "scanned-repo"
        cbom = build_cyclonedx_cbom(findings, repo_name=repo_name)

        cbom_json = json.dumps(cbom, indent=2)

        if output_path:
            out_dir = os.path.dirname(output_path)
            if out_dir:
                os.makedirs(out_dir, exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(cbom_json)
            print(f"CBOM written to: {output_path} ({len(cbom.get('components', []))} components)", file=sys.stderr)
        else:
            print(cbom_json)

        return 0
    except Exception as e:
        sys.stderr.write(f"Scan error: {e}\n")
        return 2


def run_gate(
    base_path: str,
    head_path: str,
    policy_path: str = None,
    waivers_path: str = None,
    output_formats: str = "md,json",
    out_md: str = None,
    out_json: str = None,
) -> int:
    """Evaluates the Crypto Ratchet Gate against base and head CBOMs."""
    # Validate base CBOM file
    if not base_path or not os.path.exists(base_path):
        sys.stderr.write(f"Error: Base CBOM file not found: {base_path}\n")
        return 2

    # Validate head CBOM file
    if not head_path or not os.path.exists(head_path):
        sys.stderr.write(f"Error: Head CBOM file not found: {head_path}\n")
        return 2

    # 1. Parse JSON files
    try:
        with open(base_path, "r", encoding="utf-8") as f:
            base_cbom = json.load(f)
    except Exception as e:
        sys.stderr.write(f"Error: Failed to parse base CBOM JSON: {e}\n")
        return 2

    try:
        with open(head_path, "r", encoding="utf-8") as f:
            head_cbom = json.load(f)
    except Exception as e:
        sys.stderr.write(f"Error: Failed to parse head CBOM JSON: {e}\n")
        return 2

    # 2. Load policy and waivers
    try:
        policy = load_policy(policy_path)
    except Exception as e:
        sys.stderr.write(f"Error: Policy loading failed: {e}\n")
        return 2

    try:
        raw_waivers = load_waivers(waivers_path)
    except Exception as e:
        sys.stderr.write(f"Error: Waivers loading failed: {e}\n")
        return 2

    # 3. Evaluate Gate
    result = evaluate_gate(
        base_cbom=base_cbom,
        head_cbom=head_cbom,
        policy_dict=policy,
        raw_waivers=raw_waivers,
    )

    # 4. Generate Reports
    md_report = generate_markdown_report(result)
    json_report = generate_json_report(result)

    formats = [f.strip().lower() for f in (output_formats or "md").split(",")]

    # Write Markdown
    if "md" in formats or out_md:
        if out_md:
            out_dir = os.path.dirname(out_md)
            if out_dir:
                os.makedirs(out_dir, exist_ok=True)
            with open(out_md, "w", encoding="utf-8") as f:
                f.write(md_report)
        else:
            print(md_report)

    # Write JSON
    if "json" in formats or out_json:
        json_str = json.dumps(json_report, indent=2)
        if out_json:
            out_dir = os.path.dirname(out_json)
            if out_dir:
                os.makedirs(out_dir, exist_ok=True)
            with open(out_json, "w", encoding="utf-8") as f:
                f.write(json_str)
        elif "md" not in formats:
            print(json_str)

    # Print summary status to stderr
    if result.verdict == "PASS":
        print(f"\n[Crypto Ratchet Gate] PASS: No quantum ratchet violations.", file=sys.stderr)
    else:
        print(f"\n[Crypto Ratchet Gate] FAIL: {len(result.failure_reasons)} violation(s).", file=sys.stderr)
        for r in result.failure_reasons:
            print(f"  - {r}", file=sys.stderr)

    return result.exit_code


def main():
    parser = argparse.ArgumentParser(
        prog="cryptoscan",
        description="CryptoScan: Cryptographic Security Scanner & CI/CD Policy Gate",
    )
    subparsers = parser.add_subparsers(dest="command", help="Subcommand to execute")

    # 'scan' subcommand
    scan_parser = subparsers.add_parser("scan", help="Scan a directory and generate a CycloneDX 1.6 CBOM")
    scan_parser.add_argument("path", help="Directory or file path to scan")
    scan_parser.add_argument("--out", "-o", help="Output path for CBOM JSON (defaults to stdout)")

    # 'gate' subcommand
    gate_parser = subparsers.add_parser("gate", help="Evaluate CI/CD Crypto Ratchet Gate between base and head CBOMs")
    gate_parser.add_argument("--base", "-b", required=True, help="Base branch CBOM JSON file")
    gate_parser.add_argument("--head", "-H", required=True, help="Head/PR branch CBOM JSON file")
    gate_parser.add_argument("--policy", "-p", help="Path to .cryptoscan/policy.yaml")
    gate_parser.add_argument("--waivers", "-w", help="Path to .cryptoscan/waivers.yaml")
    gate_parser.add_argument("--format", "-f", default="md,json", help="Output formats: md, json, or md,json")
    gate_parser.add_argument("--out-md", help="Output file path for Markdown report")
    gate_parser.add_argument("--out-json", help="Output file path for JSON report")

    args = parser.parse_args()

    if args.command == "scan":
        code = run_scan(path_to_scan=args.path, output_path=args.out)
        sys.exit(code)
    elif args.command == "gate":
        code = run_gate(
            base_path=args.base,
            head_path=args.head,
            policy_path=args.policy,
            waivers_path=args.waivers,
            output_formats=args.format,
            out_md=args.out_md,
            out_json=args.out_json,
        )
        sys.exit(code)
    else:
        parser.print_help()
        sys.exit(2)


if __name__ == "__main__":
    main()

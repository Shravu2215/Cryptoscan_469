"""
CLI Interface for CryptoScan Triangulation & Network Importer.

Usage:
  python -m triangulation.cli scan --static <py-file> [--runtime <jsonl-or-json>] [--network <json>] [--out result.json]
  python -m triangulation.cli network import --file capture.json [--scan-id <id>]
  python -m triangulation.cli triangulate --scan-id <id> [--run-id <id>] [--capture-id <id>] [--out result.json]
  python -m triangulation.cli triangulate eval
"""

import argparse
import ast
import json
import os
import sys
from typing import List, Dict, Any, Optional

from triangulation.network_import import import_network_json, import_openssl_sclient_output, import_network_pcap
from triangulation.engine import run_triangulation
from triangulation.eval.evaluate import evaluate_triangulation, print_evaluation_summary


# ---------------------------------------------------------------------------
# Lightweight AST-based static scanner (self-contained, no external deps)
# ---------------------------------------------------------------------------

_CALL_ALGO_MAP: List[tuple] = [
    # (module_attr_chain, algorithm, key_size_arg_index_or_kwarg)
    ("hashlib.sha256", "SHA-256", None, None),
    ("hashlib.sha384", "SHA-384", None, None),
    ("hashlib.sha512", "SHA-512", None, None),
    ("hashlib.md5", "MD5", None, None),
    ("hashlib.sha1", "SHA-1", None, None),
    ("hashlib.new", None, None, 0),   # first arg is algo name
    ("AESGCM.generate_key", "AES-256-GCM", "bit_length", 0),
    ("AESGCM", "AES-256-GCM", None, None),
    ("rsa.generate_private_key", "RSA", "key_size", 1),
    ("ec.generate_private_key", "ECDSA P-256", None, None),
    ("ChaCha20Poly1305", "ChaCha20-Poly1305", None, None),
    ("AES.new", "AES", None, None),
]

_HASHLIB_NEW_ALGOS = {
    "sha256": "SHA-256", "sha384": "SHA-384", "sha512": "SHA-512",
    "md5": "MD5", "sha1": "SHA-1", "sha224": "SHA-224",
}


def _node_full_name(node) -> str:
    """Reconstruct dotted name from an AST Attribute or Name node."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return _node_full_name(node.value) + "." + node.attr
    return ""


def _extract_int_arg(call: ast.Call, kwarg_name: Optional[str], pos: Optional[int]) -> Optional[int]:
    """Try to extract an integer argument by keyword name or positional index."""
    if kwarg_name:
        for kw in call.keywords:
            if kw.arg == kwarg_name and isinstance(kw.value, ast.Constant):
                return int(kw.value.value)
    if pos is not None and pos < len(call.args):
        node = call.args[pos]
        if isinstance(node, ast.Constant):
            return int(node.value)
    return None


def _get_algo_family(algo: str) -> str:
    """Helper to group algorithms into operation families for AST deduplication."""
    a = algo.upper()
    if a.startswith("AES"):
        return "AES"
    if a.startswith("RSA"):
        return a  # keep RSA-1024 vs RSA-2048 distinct
    if any(k in a for k in ("ECDSA", "EC", "SECP256R1")):
        return "ECDSA"
    return a


def _scan_python_file(filepath: str) -> List[Dict[str, Any]]:
    """
    Lightweight AST scanner for Python crypto calls.
    Returns a list of static finding dicts (1 per distinct operation instance).
    """
    with open(filepath, "r", encoding="utf-8") as f:
        source = f.read()

    try:
        tree = ast.parse(source, filename=filepath)
    except SyntaxError as e:
        print(f"[Scan] SyntaxError parsing {filepath}: {e}", file=sys.stderr)
        return []

    findings = []
    seen_operation_keys = set()

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        full_name = _node_full_name(node.func)
        lineno = node.lineno

        # Determine enclosing function
        func_name = ""
        for parent in ast.walk(tree):
            if isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if any(
                    getattr(child, "lineno", 0) == lineno
                    for child in ast.walk(parent)
                ):
                    func_name = parent.name
                    break

        for (pattern, algo, kw_name, pos_idx) in _CALL_ALGO_MAP:
            if not full_name.endswith(pattern.split(".")[-1]):
                continue
            if not full_name.endswith(pattern) and "." in pattern:
                continue

            resolved_algo = algo
            key_size = None

            if resolved_algo is None and pattern == "hashlib.new":
                if node.args and isinstance(node.args[0], ast.Constant):
                    resolved_algo = _HASHLIB_NEW_ALGOS.get(
                        str(node.args[0].value).lower(), str(node.args[0].value).upper()
                    )
                else:
                    continue

            if pattern in ("AESGCM.generate_key", "rsa.generate_private_key"):
                key_size = _extract_int_arg(node, kw_name, pos_idx)

            if resolved_algo == "RSA" and key_size:
                resolved_algo = f"RSA-{key_size}"

            if resolved_algo == "AES-256-GCM" and key_size and key_size != 256:
                resolved_algo = f"AES-{key_size}-GCM"

            if resolved_algo is None:
                continue

            family = _get_algo_family(resolved_algo)
            op_key = (func_name, family)
            if op_key in seen_operation_keys:
                continue
            seen_operation_keys.add(op_key)

            finding_id = f"static-{os.path.basename(filepath)}-L{lineno}-{resolved_algo.replace(' ', '_')}"
            findings.append({
                "id": finding_id,
                "file": filepath,
                "line": lineno,
                "function": func_name,
                "algorithm": resolved_algo,
                "key_size": key_size,
            })

    return findings


def _load_runtime_events(filepath: str) -> List[Dict[str, Any]]:
    """Load runtime events from a .jsonl file or a JSON file with an 'events' array."""
    if not os.path.exists(filepath):
        print(f"[Error] Runtime file not found: {filepath}", file=sys.stderr)
        sys.exit(1)

    with open(filepath, "r", encoding="utf-8-sig") as f:  # utf-8-sig strips BOM
        content = f.read().strip()

    # Detect format: if it looks like a JSON object/array, parse as JSON first
    if content.startswith("{") or content.startswith("["):
        try:
            obj = json.loads(content)
            if isinstance(obj, list):
                return obj
            elif isinstance(obj, dict):
                return obj.get("events", [obj])
        except json.JSONDecodeError:
            pass  # fall through to JSONL

    # Try JSONL (one JSON object per line)
    events = []
    for i, line in enumerate(content.splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError as e:
            print(f"[Warning] Skipping malformed JSONL line {i}: {e}", file=sys.stderr)
    return events



def _print_scan_table(results) -> None:
    """Print the triangulation result table."""
    header = f"{'Algorithm':<18} {'Classification':<18} {'Location':<40} {'Conf':<8} {'QV'}"
    sep = "-" * len(header)
    print()
    print("=" * 80)
    print("  CRYPTOSCAN TRIANGULATION RESULTS")
    print("=" * 80)
    print(f"  {header}")
    print(f"  {sep}")
    for r in results:
        qv = "YES" if r.quantum_vulnerable else "no"
        loc = r.location[:38] + ".." if len(r.location) > 40 else r.location
        print(f"  {r.algorithm:<18} {r.classification:<18} {loc:<40} {r.confidence:<8} {qv}")
    print(f"  {sep}")

    counts: Dict[str, int] = {}
    for r in results:
        counts[r.classification] = counts.get(r.classification, 0) + 1

    print(f"  Total: {len(results)} findings  |  " +
          "  ".join(f"{k}: {v}" for k, v in sorted(counts.items())))
    print("=" * 80)
    print()


def main():
    parser = argparse.ArgumentParser(description="CryptoScan Triangulation & Network Evidence CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # --- scan subcommand ---
    scan_parser = subparsers.add_parser("scan", help="Scan a Python file and triangulate with runtime/network evidence")
    scan_parser.add_argument("--static", dest="static_file", required=True, help="Path to Python source file to scan statically")
    scan_parser.add_argument("--runtime", dest="runtime_file", help="Path to runtime events file (.jsonl or .json)")
    scan_parser.add_argument("--network", dest="network_file", help="Path to network capture JSON file")
    scan_parser.add_argument("--out", default="triangulation_result.json", help="Output JSON path")
    scan_parser.add_argument("--scan-id", default="cli-scan", help="Scan ID label")

    # --- network subcommand ---
    network_parser = subparsers.add_parser("network", help="Network evidence operations")
    net_sub = network_parser.add_subparsers(dest="subcommand", required=True)

    import_parser = net_sub.add_parser("import", help="Import network capture evidence (JSON, PCAP, OpenSSL)")
    import_parser.add_argument("--file", required=True, help="Path to network capture file (.json, .pcap, .txt)")
    import_parser.add_argument("--scan-id", help="Scan ID to associate with capture")
    import_parser.add_argument("--out", help="Output JSON destination path")

    # --- triangulate subcommand ---
    triangulate_parser = subparsers.add_parser("triangulate", help="Triangulation engine operations")
    triangulate_parser.add_argument("--scan-id", help="Scan ID to triangulate")
    triangulate_parser.add_argument("--run-id", help="Runtime run ID")
    triangulate_parser.add_argument("--capture-id", help="Network capture ID")
    triangulate_parser.add_argument("--out", default="triangulation_result.json", help="Output file path")
    triangulate_parser.add_argument("action", nargs="?", default="run", choices=["run", "eval"], help="Action: 'run' or 'eval'")

    args = parser.parse_args()

    # -------------------------------------------------------------------------
    if args.command == "scan":
        static_file = args.static_file
        if not os.path.exists(static_file):
            print(f"[Error] Static file not found: {static_file}", file=sys.stderr)
            sys.exit(1)

        print(f"[CryptoScan] Scanning {static_file} ...")
        findings = _scan_python_file(static_file)
        print(f"[CryptoScan] Static scan: {len(findings)} finding(s) found.")

        runtime_events: List[Dict[str, Any]] = []
        if args.runtime_file:
            print(f"[CryptoScan] Loading runtime events from {args.runtime_file} ...")
            runtime_events = _load_runtime_events(args.runtime_file)
            print(f"[CryptoScan] Runtime events: {len(runtime_events)} event(s) loaded.")

        network_observations: List[Dict[str, Any]] = []
        if args.network_file:
            if not os.path.exists(args.network_file):
                print(f"[Error] Network file not found: {args.network_file}", file=sys.stderr)
                sys.exit(1)
            print(f"[CryptoScan] Loading network observations from {args.network_file} ...")
            obs_items = import_network_json(args.network_file, capture_id=args.scan_id)
            network_observations = [o.to_dict() for o in obs_items]
            print(f"[CryptoScan] Network observations: {len(network_observations)} item(s) loaded.")

        results = run_triangulation(
            scan_id=args.scan_id,
            cbom_findings=findings,
            runtime_events=runtime_events,
            network_observations=network_observations,
        )

        out_data = [r.to_dict() for r in results]
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(out_data, f, indent=2)
        print(f"[CryptoScan] Detailed results saved to {args.out}")

        _print_scan_table(results)

    # -------------------------------------------------------------------------
    elif args.command == "network":
        if args.subcommand == "import":
            filepath = args.file
            if not os.path.exists(filepath):
                print(f"[Error] File not found: {filepath}")
                sys.exit(1)

            if filepath.endswith(".pcap") or filepath.endswith(".pcapng"):
                res = import_network_pcap(filepath, capture_id=args.scan_id)
                observations = res.get("observations", [])
                print(f"[CryptoScan Network] PCAP processing: {res.get('message')}")
            elif filepath.endswith(".txt"):
                with open(filepath, "r", encoding="utf-8") as f:
                    content = f.read()
                observations = [o.to_dict() for o in import_openssl_sclient_output(content, capture_id=args.scan_id)]
                print(f"[CryptoScan Network] Parsed {len(observations)} observation(s) from OpenSSL s_client text.")
            else:
                observations = [o.to_dict() for o in import_network_json(filepath, capture_id=args.scan_id)]
                print(f"[CryptoScan Network] Successfully imported {len(observations)} observation(s) from JSON.")

            if args.out:
                with open(args.out, "w", encoding="utf-8") as f:
                    json.dump(observations, f, indent=2)
                print(f"[CryptoScan Network] Saved output to {args.out}")

    elif args.command == "triangulate":
        if args.action == "eval" or (hasattr(args, "action") and args.action == "eval"):
            report = evaluate_triangulation()
            print_evaluation_summary(report)
        else:
            # Run triangulation over scan/demo findings
            print(f"[CryptoScan Triangulation] Running triangulation engine for scan: {args.scan_id or 'demo'}...")

            # Load demo findings and events if available
            demo_findings = [
                {"id": "f-sha256", "file": "demo_crypto_app.py", "line": 33, "function": "hash_data", "algorithm": "SHA-256"},
                {"id": "f-aes", "file": "demo_crypto_app.py", "line": 40, "function": "aes_encrypt", "algorithm": "AES-256-GCM"},
                {"id": "f-rsa2048", "file": "demo_crypto_app.py", "line": 45, "function": "rsa_sign_verify", "algorithm": "RSA-2048"},
                {"id": "f-ecdsa", "file": "demo_crypto_app.py", "line": 57, "function": "ecdsa_sign", "algorithm": "ECDSA"},
                {"id": "f-md5", "file": "demo_crypto_app.py", "line": 65, "function": "legacy_weak_crypto", "algorithm": "MD5"},
                {"id": "f-sha1", "file": "demo_crypto_app.py", "line": 66, "function": "legacy_weak_crypto", "algorithm": "SHA-1"},
                {"id": "f-rsa1024", "file": "demo_crypto_app.py", "line": 67, "function": "legacy_weak_crypto", "algorithm": "RSA-1024"},
            ]

            demo_events = [
                {"event_id": "e-sha256", "algorithm": "SHA-256", "call_file": "demo_crypto_app.py", "call_line": 33, "call_function": "hash_data", "matched_finding_id": "f-sha256"},
                {"event_id": "e-aes", "algorithm": "AES", "key_size": 256, "call_file": "demo_crypto_app.py", "call_line": 40, "call_function": "aes_encrypt", "matched_finding_id": "f-aes"},
                {"event_id": "e-rsa2048", "algorithm": "RSA", "key_size": 2048, "call_file": "demo_crypto_app.py", "call_line": 45, "call_function": "rsa_sign_verify", "matched_finding_id": "f-rsa2048"},
                {"event_id": "e-ecdsa", "algorithm": "ECDSA", "call_file": "demo_crypto_app.py", "call_line": 57, "call_function": "ecdsa_sign", "matched_finding_id": "f-ecdsa"},
            ]

            results = run_triangulation(args.scan_id or "demo-scan", demo_findings, demo_events, [])

            out_data = [r.to_dict() for r in results]
            with open(args.out, "w", encoding="utf-8") as f:
                json.dump(out_data, f, indent=2)

            print("==========================================================================")
            print(" TRIANGULATED TRUTH RESULTS SUMMARY")
            print("==========================================================================")
            counts = {"Confirmed Active": 0, "Static Only": 0, "Runtime Only": 0, "Network Only": 0}
            for r in results:
                counts[r.classification] = counts.get(r.classification, 0) + 1
                print(f" [{r.classification:<16}] {r.algorithm:<12} | Loc: {r.location:<30} | Conf: {r.confidence}")

            print("--------------------------------------------------------------------------")
            print(f" Total Findings: {len(results)} | Confirmed Active: {counts['Confirmed Active']} | Static Only: {counts['Static Only']} | Runtime Only: {counts['Runtime Only']} | Network Only: {counts['Network Only']}")
            print(f" Saved detailed results to {args.out}")
            print("==========================================================================")


if __name__ == "__main__":
    main()

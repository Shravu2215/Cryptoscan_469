#!/usr/bin/env python3
"""
cli.py — CryptoScan Attestation CLI

Subcommands:
  attest   Generate a signed in-toto attestation for a CBOM file.
  verify   Independently verify an attestation bundle.

Usage:
  cryptoscan-attest attest \\
    --cbom cbom.json \\
    --out-statement attestation.intoto.json \\
    --out-bundle    attestation.bundle.json \\
    --out-hybrid    attestation.hybrid.json \\
    --repo my-org/my-repo \\
    --commit abc123 \\
    --branch main \\
    --with-pqc \\
    --with-sepolia

  cryptoscan-attest verify \\
    --cbom cbom.json \\
    --statement attestation.intoto.json \\
    --bundle    attestation.bundle.json \\
    --hybrid    attestation.hybrid.json \\
    --identity  "https://github.com/my-org/my-repo/.github/workflows/attest.yml@refs/heads/main" \\
    --issuer    "https://token.actions.githubusercontent.com"

Exit codes:
  0  — success / verification passed
  1  — verification failed
  2  — usage / file-not-found error
"""

import argparse
import json
import logging
import os
import sys
from pathlib import Path

# Ensure UTF-8 output on all terminals (Windows cp1252 fix)
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Ensure repo root is on sys.path
_repo_root = str(Path(__file__).parent.parent)
if _repo_root not in sys.path:
    sys.path.insert(0, _repo_root)

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)


# ── attest subcommand ──────────────────────────────────────────────────────────

def cmd_attest(args) -> int:
    """Generate a signed in-toto attestation for a CBOM file."""
    from attestation.statement import build_statement, statement_to_json, sha256_file
    from attestation.signer import sign_statement
    from attestation.rekor import rekor_search_by_hash

    cbom_path = args.cbom
    if not os.path.isfile(cbom_path):
        sys.stderr.write(f"Error: CBOM file not found: {cbom_path}\n")
        return 2

    # Build metadata from CLI args + environment
    metadata = {
        "repository": args.repo or os.getenv("GITHUB_REPOSITORY", ""),
        "commit": args.commit or os.getenv("GITHUB_SHA", ""),
        "branch": args.branch or os.getenv("GITHUB_REF_NAME", ""),
        "scanner_version": "cryptoscan/1.0.0",
        "scanned_at": None,  # auto-set to now
        "policy_threshold": args.policy_threshold or "CRITICAL",
    }

    print(f"[attest] Computing CBOM SHA-256...", file=sys.stderr)
    cbom_sha256 = sha256_file(cbom_path)
    print(f"[attest] CBOM SHA-256: {cbom_sha256}", file=sys.stderr)

    # 1. Build in-toto Statement
    print(f"[attest] Building in-toto Statement v1...", file=sys.stderr)
    statement = build_statement(
        cbom_path=cbom_path,
        cbom_sha256=cbom_sha256,
        metadata=metadata,
    )

    # Write statement
    stmt_path = args.out_statement or "attestation.intoto.json"
    Path(stmt_path).parent.mkdir(parents=True, exist_ok=True)
    Path(stmt_path).write_text(statement_to_json(statement), encoding="utf-8")
    print(f"[attest] Statement written: {stmt_path}", file=sys.stderr)

    # 2. Sigstore keyless signing
    print(f"[attest] Signing with Sigstore keyless...", file=sys.stderr)
    bundle_path = args.out_bundle or "attestation.bundle.json"
    sign_result = sign_statement(
        statement=statement,
        output_bundle_path=bundle_path,
    )

    if sign_result.get("signed"):
        print(f"[attest] Sigstore signature obtained.", file=sys.stderr)
        rekor_id = sign_result.get("rekor_log_id")
        if rekor_id:
            print(f"[attest] Rekor log entry: {rekor_id}", file=sys.stderr)
            rekor_url = os.getenv("SIGSTORE_REKOR_URL", "https://rekor.sigstore.dev")
            print(f"[attest] Rekor URL: {rekor_url}/api/v1/log/entries/{rekor_id}", file=sys.stderr)
    else:
        print(
            f"[attest] WARNING: Sigstore signing unavailable. Offline bundle written.\n"
            f"         Install: pip install sigstore>=3.0.0",
            file=sys.stderr,
        )

    # 3. Optional: Hybrid ML-DSA-65 outer signature
    hybrid_path = None
    if args.with_pqc:
        print(f"[attest] Wrapping with ML-DSA-65 (FIPS 204) hybrid envelope...", file=sys.stderr)
        from attestation.pqc_wrap import wrap_bundle_with_pqc, _ML_DSA_MODE
        bundle_dict = sign_result.get("bundle", {})
        envelope = wrap_bundle_with_pqc(bundle_dict)
        hybrid_path = args.out_hybrid or "attestation.hybrid.json"
        Path(hybrid_path).parent.mkdir(parents=True, exist_ok=True)
        Path(hybrid_path).write_text(
            json.dumps(envelope, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        print(
            f"[attest] Hybrid envelope written: {hybrid_path} (mode={_ML_DSA_MODE})",
            file=sys.stderr,
        )
        if _ML_DSA_MODE == "stub":
            print(
                "[attest] NOTE: ML-DSA-65 in STUB mode — no real PQC signature was produced.\n"
                "         Install: pip install dilithium-py   (pure Python reference)\n"
                "         Or: pip install cryptography>=44    (with liboqs native library)",
                file=sys.stderr,
            )

    # 4. Optional: Sepolia anchoring
    if args.with_sepolia:
        print(f"[attest] Anchoring attestation hash to Sepolia...", file=sys.stderr)
        from attestation.sepolia_anchor import anchor_attestation_hash
        import uuid
        scan_id = args.scan_id or str(uuid.uuid4())
        anchor_result = anchor_attestation_hash(
            scan_id=scan_id,
            attestation_sha256=sign_result.get("artifact_sha256", cbom_sha256),
        )
        if anchor_result.get("skipped"):
            print(f"[attest] Sepolia anchor skipped: {anchor_result.get('reason', '')}", file=sys.stderr)
        elif anchor_result.get("anchored"):
            print(f"[attest] Sepolia anchor tx: {anchor_result.get('tx_hash')}", file=sys.stderr)
        else:
            print(f"[attest] Sepolia anchor failed: {anchor_result.get('error')}", file=sys.stderr)

    # 5. Print summary JSON to stdout
    summary = {
        "cbom": cbom_path,
        "cbomSha256": cbom_sha256,
        "statement": stmt_path,
        "bundle": bundle_path,
        "bundleDigest": sign_result.get("artifact_sha256"),
        "rekorLogId": sign_result.get("rekor_log_id"),
        "signerIdentity": sign_result.get("signer_identity"),
        "signed": sign_result.get("signed", False),
        "hybridEnvelope": hybrid_path,
        "experimental": {
            "pqcAlgorithm": "ML-DSA-65 (FIPS 204)" if args.with_pqc else None,
        },
    }
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0


# ── verify subcommand ──────────────────────────────────────────────────────────

def cmd_verify(args) -> int:
    """Independently verify an attestation bundle."""
    from attestation.verifier import verify_attestation

    result = verify_attestation(
        cbom_path=args.cbom,
        statement_path=args.statement,
        bundle_path=args.bundle,
        hybrid_envelope_path=args.hybrid,
        expected_identity=args.identity,
        expected_issuer=args.issuer,
        check_rekor=not args.no_rekor,
    )

    print(json.dumps(result, indent=2, ensure_ascii=False))

    if result["valid"]:
        print("\n✅ Attestation VALID", file=sys.stderr)
        return 0
    else:
        print("\n❌ Attestation INVALID", file=sys.stderr)
        for err in result.get("errors", []):
            print(f"   - {err}", file=sys.stderr)
        return 1


# ── Argument parser ────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="cryptoscan-attest",
        description="CryptoScan Attestation: sign and verify CBOM in-toto attestations",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # attest
    a = sub.add_parser("attest", help="Generate a signed in-toto attestation")
    a.add_argument("--cbom", required=True, help="Path to CBOM JSON file")
    a.add_argument("--out-statement", help="Output path for in-toto Statement (default: attestation.intoto.json)")
    a.add_argument("--out-bundle", help="Output path for Sigstore bundle (default: attestation.bundle.json)")
    a.add_argument("--out-hybrid", help="Output path for hybrid ML-DSA envelope (default: attestation.hybrid.json)")
    a.add_argument("--repo", help="Repository name (e.g. my-org/my-repo)")
    a.add_argument("--commit", help="Git commit SHA")
    a.add_argument("--branch", help="Git branch / ref name")
    a.add_argument("--scan-id", help="Scan UUID (auto-generated if omitted; used for Sepolia anchor)")
    a.add_argument("--policy-threshold", default="CRITICAL", help="Policy threshold label in predicate")
    a.add_argument("--with-pqc", action="store_true", help="Add experimental ML-DSA-65 hybrid outer signature")
    a.add_argument("--with-sepolia", action="store_true", help="Anchor attestation hash to Sepolia (requires env vars)")

    # verify
    v = sub.add_parser("verify", help="Independently verify an attestation")
    v.add_argument("--cbom", required=True, help="Path to CBOM JSON file")
    v.add_argument("--statement", required=True, help="Path to in-toto Statement JSON")
    v.add_argument("--bundle", required=True, help="Path to Sigstore bundle JSON")
    v.add_argument("--hybrid", help="Path to hybrid ML-DSA envelope JSON (optional)")
    v.add_argument("--identity", help="Expected OIDC identity SAN in Sigstore certificate")
    v.add_argument("--issuer", help="Expected OIDC issuer (e.g. https://token.actions.githubusercontent.com)")
    v.add_argument("--no-rekor", action="store_true", help="Skip Rekor inclusion check")

    args = parser.parse_args()

    if args.command == "attest":
        sys.exit(cmd_attest(args))
    elif args.command == "verify":
        sys.exit(cmd_verify(args))
    else:
        parser.print_help()
        sys.exit(2)


if __name__ == "__main__":
    main()

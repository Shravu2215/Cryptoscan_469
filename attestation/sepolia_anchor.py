"""
sepolia_anchor.py — Optional Sepolia blockchain anchor for CryptoScan attestations.

When CRYPTOSCAN_SEPOLIA_ANCHOR=1 is set and a valid RPC URL + wallet key are
available, this module records the attestation SHA-256 hash on-chain by calling
the existing CryptoAnchor.anchorScan() contract method via the blockchain-module.

This is an optional, fire-and-forget step. Failure does not block attestation.

Environment variables:
  CRYPTOSCAN_SEPOLIA_ANCHOR=1         — opt-in to blockchain anchoring
  SEPOLIA_RPC_URL                     — Alchemy/Infura Sepolia RPC URL
  WALLET_PRIVATE_KEY                  — deployer wallet private key (hex, 0x-prefixed)
  CRYPTO_ANCHOR_CONTRACT_ADDRESS      — deployed CryptoAnchor contract address

Usage:
    from attestation.sepolia_anchor import anchor_attestation_hash
    result = anchor_attestation_hash(scan_id="<uuid>", attestation_sha256="<hex>")
"""

import json
import logging
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

_BLOCKCHAIN_MODULE_PATH = Path(__file__).parent.parent / "blockchain-module"


def anchor_attestation_hash(
    scan_id: str,
    attestation_sha256: str,
    contract_address: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Anchor an attestation SHA-256 hash on Sepolia via CryptoAnchor.anchorScan().

    Args:
        scan_id:            Scan UUID (used as the on-chain scanId key).
        attestation_sha256: Hex SHA-256 of the attestation bundle / statement.
        contract_address:   Override contract address (reads env if None).

    Returns:
        dict with:
          "anchored"    — True if successfully anchored
          "tx_hash"     — Ethereum transaction hash (or None)
          "error"       — error string (or None on success)
          "skipped"     — True if anchoring is disabled
    """
    if not os.getenv("CRYPTOSCAN_SEPOLIA_ANCHOR"):
        return {"anchored": False, "tx_hash": None, "error": None, "skipped": True,
                "reason": "CRYPTOSCAN_SEPOLIA_ANCHOR not set"}

    rpc_url = os.getenv("SEPOLIA_RPC_URL", "")
    wallet_key = os.getenv("WALLET_PRIVATE_KEY", "")
    addr = contract_address or os.getenv("CRYPTO_ANCHOR_CONTRACT_ADDRESS", "")

    if not rpc_url or not wallet_key or not addr:
        missing = []
        if not rpc_url: missing.append("SEPOLIA_RPC_URL")
        if not wallet_key: missing.append("WALLET_PRIVATE_KEY")
        if not addr: missing.append("CRYPTO_ANCHOR_CONTRACT_ADDRESS")
        msg = f"Sepolia anchor skipped — missing env vars: {', '.join(missing)}"
        logger.warning(msg)
        return {"anchored": False, "tx_hash": None, "error": msg, "skipped": True}

    # Delegate to the existing blockchain-module anchor.js script
    # We write a minimal JSON content file containing the attestation hash
    # as the "component" so anchorScan() records it.
    content = {"attestationSha256": attestation_sha256, "scanId": scan_id}

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", delete=False, encoding="utf-8"
    ) as tmp:
        json.dump(content, tmp)
        tmp_path = tmp.name

    try:
        result = subprocess.run(
            [sys.executable or "node", str(_BLOCKCHAIN_MODULE_PATH / "scripts" / "anchor.js"),
             scan_id, tmp_path],
            capture_output=True,
            text=True,
            timeout=60,
            env={**os.environ, "SEPOLIA_RPC_URL": rpc_url, "WALLET_PRIVATE_KEY": wallet_key,
                 "CRYPTO_ANCHOR_CONTRACT_ADDRESS": addr},
            cwd=str(_BLOCKCHAIN_MODULE_PATH),
        )
        # Note: anchor.js is a Node.js script; use node instead
        pass
    finally:
        os.unlink(tmp_path)

    # Re-run with node
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", delete=False, encoding="utf-8"
    ) as tmp:
        json.dump(content, tmp)
        tmp_path = tmp.name

    try:
        node_result = subprocess.run(
            ["node", str(_BLOCKCHAIN_MODULE_PATH / "scripts" / "anchor.js"),
             scan_id, tmp_path],
            capture_output=True,
            text=True,
            timeout=60,
            env={**os.environ, "SEPOLIA_RPC_URL": rpc_url, "WALLET_PRIVATE_KEY": wallet_key,
                 "CRYPTO_ANCHOR_CONTRACT_ADDRESS": addr},
            cwd=str(_BLOCKCHAIN_MODULE_PATH),
        )

        if node_result.returncode == 0:
            # Try to parse txHash from stdout
            tx_hash = None
            try:
                out = json.loads(node_result.stdout)
                tx_hash = out.get("txHash") or out.get("tx_hash")
            except Exception:
                # Try to extract from plain text
                for line in node_result.stdout.splitlines():
                    if "0x" in line and len(line.strip()) >= 66:
                        tx_hash = line.strip().split()[-1]
                        break

            logger.info("Sepolia anchor success: txHash=%s", tx_hash)
            return {"anchored": True, "tx_hash": tx_hash, "error": None, "skipped": False}
        else:
            err = node_result.stderr[:500] or node_result.stdout[:500]
            logger.error("Sepolia anchor failed: %s", err)
            return {"anchored": False, "tx_hash": None, "error": err, "skipped": False}

    except subprocess.TimeoutExpired:
        err = "Sepolia anchor timed out after 60 seconds"
        logger.error(err)
        return {"anchored": False, "tx_hash": None, "error": err, "skipped": False}
    except Exception as e:
        logger.error("Sepolia anchor error: %s", e)
        return {"anchored": False, "tx_hash": None, "error": str(e), "skipped": False}
    finally:
        try:
            os.unlink(tmp_path)
        except Exception:
            pass

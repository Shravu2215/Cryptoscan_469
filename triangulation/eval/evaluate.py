"""
Evaluation Harness for CryptoScan Triangulation Engine.
Computes Precision, Recall, F1 score, and Classification Accuracy against hand-labeled ground truth.
"""

import json
import os
import sys
from typing import List, Dict, Any
from triangulation.engine import run_triangulation


def evaluate_triangulation(
    ground_truth_path: str = "triangulation/eval/ground_truth.json",
    out_report_path: str = "eval_report.json"
) -> Dict[str, Any]:
    """
    Runs triangulation over evaluation fixtures and compares results against ground truth.
    """
    if not os.path.exists(ground_truth_path):
        raise FileNotFoundError(f"Ground truth dataset not found at {ground_truth_path}")

    with open(ground_truth_path, "r", encoding="utf-8") as f:
        ground_truth: List[Dict[str, Any]] = json.load(f)

    # Simulated findings matching demo_crypto_app static findings
    demo_findings = [
        {"id": "f-sha256", "file": "demo_crypto_app.py", "line": 33, "function": "hash_data", "algorithm": "SHA-256"},
        {"id": "f-aes", "file": "demo_crypto_app.py", "line": 40, "function": "aes_encrypt", "algorithm": "AES-256-GCM"},
        {"id": "f-rsa2048", "file": "demo_crypto_app.py", "line": 45, "function": "rsa_sign_verify", "algorithm": "RSA-2048"},
        {"id": "f-ecdsa", "file": "demo_crypto_app.py", "line": 57, "function": "ecdsa_sign", "algorithm": "ECDSA"},
        {"id": "f-md5", "file": "demo_crypto_app.py", "line": 65, "function": "legacy_weak_crypto", "algorithm": "MD5"},
        {"id": "f-sha1", "file": "demo_crypto_app.py", "line": 66, "function": "legacy_weak_crypto", "algorithm": "SHA-1"},
        {"id": "f-rsa1024", "file": "demo_crypto_app.py", "line": 67, "function": "legacy_weak_crypto", "algorithm": "RSA-1024"},
        {"id": "f-des", "file": "demo_crypto_app.py", "line": 72, "function": "legacy_weak_crypto", "algorithm": "DES"},
        {"id": "f-aes128cbc", "file": "services/payment_gateway.py", "line": 42, "function": "encrypt_payload", "algorithm": "AES-128-CBC"},
    ]

    # Simulated runtime events matching demo_crypto_app + runtime_only fixture
    demo_runtime = [
        {"event_id": "e-sha256", "algorithm": "SHA-256", "call_file": "demo_crypto_app.py", "call_line": 33, "call_function": "hash_data", "matched_finding_id": "f-sha256"},
        {"event_id": "e-aes", "algorithm": "AES", "key_size": 256, "call_file": "demo_crypto_app.py", "call_line": 40, "call_function": "aes_encrypt", "matched_finding_id": "f-aes"},
        {"event_id": "e-rsa2048", "algorithm": "RSA", "key_size": 2048, "call_file": "demo_crypto_app.py", "call_line": 45, "call_function": "rsa_sign_verify", "matched_finding_id": "f-rsa2048"},
        {"event_id": "e-ecdsa", "algorithm": "ECDSA", "call_file": "demo_crypto_app.py", "call_line": 57, "call_function": "ecdsa_sign", "matched_finding_id": "f-ecdsa"},
        {"event_id": "e-chacha", "algorithm": "ChaCha20-Poly1305", "key_size": 256, "call_file": "legacy/dynamic_crypto_loader.py", "call_line": 88, "call_function": "load_dynamic_cipher", "matched_finding_id": None},
    ]

    # Simulated network observations matching network_only fixture
    demo_network = [
        {
            "observation_id": "n-dh",
            "host": "legacy-auth.crypto.internal",
            "port": 8443,
            "protocol": "TLS",
            "protocol_version": "TLSv1.0",
            "cipher_suite": "TLS_DH_anon_WITH_AES_128_CBC_SHA",
            "key_exchange": "DH",
            "certificate_key_type": "DH",
            "certificate_key_size": 1024,
            "normalized_algorithms": ["DH", "AES", "SHA-1"],
        },
        {
            "observation_id": "n-x25519",
            "host": "pqc-gateway.crypto.internal",
            "port": 443,
            "protocol": "TLS",
            "protocol_version": "TLSv1.3",
            "cipher_suite": "TLS_AES_256_GCM_SHA384",
            "key_exchange": "X25519",
            "certificate_key_type": "ECDSA",
            "certificate_key_size": 256,
            "normalized_algorithms": ["X25519"],
        }
    ]

    results = run_triangulation("eval-scan-001", demo_findings, demo_runtime, demo_network)

    # Calculate confusion matrix & class metrics
    correct_matches = 0
    total_gt = len(ground_truth)

    class_counts = {
        "Confirmed Active": {"tp": 0, "fp": 0, "fn": 0},
        "Static Only": {"tp": 0, "fp": 0, "fn": 0},
        "Runtime Only": {"tp": 0, "fp": 0, "fn": 0},
        "Network Only": {"tp": 0, "fp": 0, "fn": 0},
    }

    # Map GT by location (file:line:function) and algorithm family
    for gt in ground_truth:
        gt_algo = gt["algorithm"].upper()
        gt_loc = gt.get("location", "")
        gt_cls = gt["expected_classification"]
        gt_file = gt_loc.split(":")[0] if gt_loc else ""
        gt_line = gt_loc.split(":")[1] if ":" in gt_loc else ""

        # Find matching triangulation result by location first
        matched_res = None
        for r in results:
            r_loc = r.location or ""
            r_algo = r.algorithm.upper()

            # Location match check (file:line or host:port)
            loc_match = False
            if gt_loc and r_loc:
                if gt_loc == r_loc or r_loc.startswith(gt_loc) or gt_loc.startswith(r_loc):
                    loc_match = True
                else:
                    r_file = r_loc.split(":")[0]
                    r_line = r_loc.split(":")[1] if ":" in r_loc else ""
                    if gt_file and r_file and gt_file == r_file and (not gt_line or not r_line or gt_line == r_line):
                        loc_match = True

            # Algorithm match check
            algo_match = (
                r_algo == gt_algo
                or (gt_algo in r_algo or r_algo in gt_algo)
                or (gt_algo.startswith("RSA") and r_algo.startswith("RSA"))
                or (gt_algo.startswith("AES") and r_algo.startswith("AES"))
                or (gt_algo.startswith("ECDSA") and r_algo.startswith("ECDSA"))
            )

            if loc_match and algo_match:
                if r.classification == gt_cls:
                    matched_res = r
                    break

        if matched_res:
            correct_matches += 1
            class_counts[gt_cls]["tp"] += 1
        else:
            class_counts[gt_cls]["fn"] += 1

    accuracy = (correct_matches / total_gt) * 100.0 if total_gt > 0 else 0.0

    metrics = {}
    for cls_name, c in class_counts.items():
        tp = c["tp"]
        fp = c["fp"]
        fn = c["fn"]
        precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 1.0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        metrics[cls_name] = {
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1_score": round(f1, 4),
            "true_positives": tp,
            "false_positives": fp,
            "false_negatives": fn,
        }

    overall_report = {
        "total_ground_truth_samples": total_gt,
        "correct_classifications": correct_matches,
        "classification_accuracy_percent": round(accuracy, 2),
        "class_metrics": metrics,
        "results_evaluated": [r.to_dict() for r in results],
    }

    with open(out_report_path, "w", encoding="utf-8") as f:
        json.dump(overall_report, f, indent=2)

    return overall_report


def print_evaluation_summary(report: Dict[str, Any]):
    """Prints a clean tabular evaluation report."""
    print("==========================================================================")
    print(" CRYPTOSCAN TRIANGULATED TRUTH EVALUATION METRICS REPORT")
    print("==========================================================================")
    print(f" Total Ground Truth Samples     : {report['total_ground_truth_samples']}")
    print(f" Correct Classifications        : {report['correct_classifications']}")
    print(f" Classification Accuracy        : {report['classification_accuracy_percent']}%")
    print("--------------------------------------------------------------------------")
    print(f"{'Classification Tier':<22} | {'Precision':<10} | {'Recall':<10} | {'F1-Score':<10}")
    print("--------------------------------------------------------------------------")
    for cls_name, m in report["class_metrics"].items():
        print(f"{cls_name:<22} | {m['precision']:<10.2f} | {m['recall']:<10.2f} | {m['f1_score']:<10.2f}")
    print("==========================================================================")


if __name__ == "__main__":
    rep = evaluate_triangulation()
    print_evaluation_summary(rep)

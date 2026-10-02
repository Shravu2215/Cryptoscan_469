import os
import json
import pytest
from collections import Counter
from scanner.pipeline import scan_repo
from scanner.models import QuantumRisk

FIXTURE_PATH = "C:/Users/ACER/Downloads/pqc-test-fixture.zip"

def test_pqc_fixture_findings_and_coverage():
    if not os.path.exists(FIXTURE_PATH):
        pytest.skip("pqc-test-fixture.zip not present in Downloads")

    result = scan_repo(FIXTURE_PATH)
    findings = result.get("findings", [])
    
    # 1. Total findings should be 46
    assert len(findings) == 46, f"Expected 46 findings, got {len(findings)}"

    # 2. Check coverage breakdown
    counts = Counter(f.get("detection_method") for f in findings)
    assert counts.get("regex") == 13, f"Expected 13 regex, got {counts.get('regex')}"
    assert counts.get("ast") == 13, f"Expected 13 ast, got {counts.get('ast')}"
    assert counts.get("manifest") == 8, f"Expected 8 manifest, got {counts.get('manifest')}"
    assert counts.get("certificate") == 6, f"Expected 6 certificate, got {counts.get('certificate')}"
    assert counts.get("config") == 4, f"Expected 4 config, got {counts.get('config')}"
    assert counts.get("infra") == 2, f"Expected 2 infra, got {counts.get('infra')}"

def test_pqc_fixture_reproducibility():
    if not os.path.exists(FIXTURE_PATH):
        pytest.skip("pqc-test-fixture.zip not present in Downloads")

    # Run 3 scans and ensure identical output
    results = [scan_repo(FIXTURE_PATH) for _ in range(3)]
    f0 = results[0]["findings"]
    f1 = results[1]["findings"]
    f2 = results[2]["findings"]

    assert len(f0) == len(f1) == len(f2) == 46
    for i in range(46):
        assert f0[i]["file"] == f1[i]["file"] == f2[i]["file"]
        assert f0[i]["line"] == f1[i]["line"] == f2[i]["line"]
        assert f0[i]["algorithm"] == f1[i]["algorithm"] == f2[i]["algorithm"]
        assert f0[i]["detection"] == f1[i]["detection"] == f2[i]["detection"]

def test_secrets_certs_and_kms_presence():
    if not os.path.exists(FIXTURE_PATH):
        pytest.skip("pqc-test-fixture.zip not present in Downloads")

    result = scan_repo(FIXTURE_PATH)
    findings = result.get("findings", [])
    
    # 4 secrets in .env
    env_findings = [f for f in findings if ".env" in f["file"]]
    assert len(env_findings) == 4

    # 6 certs in certs/
    cert_findings = [f for f in findings if "certs" in f["file"]]
    assert len(cert_findings) == 6

    # 4 KMS/HSM files
    kms_hsm_files = set(f["file"] for f in findings if "kms" in f["file"] or "hsm" in f["file"])
    assert any("aws_kms_client" in fn for fn in kms_hsm_files)
    assert any("azure_keyvault_client" in fn for fn in kms_hsm_files)
    assert any("gcp_kms_client" in fn for fn in kms_hsm_files)
    assert any("pkcs11_hsm" in fn for fn in kms_hsm_files)

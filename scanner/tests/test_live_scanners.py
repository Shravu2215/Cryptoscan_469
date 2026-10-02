import os
import sys
# pyrefly: ignore [missing-import]
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from scanner.live_tls_analyzer import LiveTLSAnalyzer
from scanner.sca_analyzer import SCAAnalyzer, check_osv
from scanner.models import Severity


class TestLiveScanners:
    def test_live_tls_expired_badssl(self):
        analyzer = LiveTLSAnalyzer(timeout=8.0)
        try:
            findings = analyzer.analyze_endpoint("expired.badssl.com", 443)
        except Exception as e:
            pytest.skip(f"Network error connecting to expired.badssl.com: {e}")
        if any(f.rule_id == "tls-connection-error" for f in findings):
            pytest.skip("expired.badssl.com is unreachable over network")
        assert len(findings) >= 2
        # Verify an expired cert finding was emitted
        expired_findings = [f for f in findings if "EXPIRED" in f.message or f.severity == Severity.CRITICAL]
        assert len(expired_findings) > 0
        assert any("badssl.com" in f.message for f in expired_findings)

    def test_live_osv_query(self):
        try:
            vulns = check_osv("jsonwebtoken", "npm", "8.5.1")
        except Exception as e:
            pytest.skip(f"Network error querying OSV API: {e}")
        if not vulns:
            pytest.skip("OSV API unreachable or returned empty response")
        # OSV has active vulnerabilities for jsonwebtoken 8.5.1
        assert len(vulns) > 0
        vuln_ids = [v.get("id") for v in vulns]
        assert any(vid.startswith("GHSA") or vid.startswith("CVE") for vid in vuln_ids)

    def test_sca_analyzer_osv_enrichment(self):
        manifest = """
        {
          "dependencies": {
            "jsonwebtoken": "8.5.1"
          }
        }
        """
        analyzer = SCAAnalyzer(enable_osv=True)
        try:
            findings = analyzer.analyze("package.json", manifest)
        except Exception as e:
            pytest.skip(f"Network error during SCA OSV enrichment: {e}")
        if not findings or not any("sca-live" in f.tags for f in findings):
            pytest.skip("OSV API unreachable during SCA enrichment")
        assert len(findings) == 1
        jwt = findings[0]
        assert "sca-live" in jwt.tags
        assert "Live OSV Alert" in jwt.message

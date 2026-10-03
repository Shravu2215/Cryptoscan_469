"""
Unit and integration tests for Step 7: Evidence report generator.
"""

import unittest
from runtime.report import generate_report_from_events


class TestStep7ReportGenerator(unittest.TestCase):
    def test_report_generation_and_aggregation(self):
        sample_events = [
            {
                "event_id": "evt-1",
                "run_id": "run-report-1",
                "timestamp": "2026-10-03T12:00:00Z",
                "language": "python",
                "library": "hashlib",
                "operation": "hash",
                "algorithm": "SHA-256",
                "call_file": "app.py",
                "call_line": 10,
                "call_function": "run",
            },
            {
                "event_id": "evt-2",
                "run_id": "run-report-1",
                "timestamp": "2026-10-03T12:00:01Z",
                "language": "python",
                "library": "hashlib",
                "operation": "hash",
                "algorithm": "SHA-256",
                "call_file": "app.py",
                "call_line": 10,
                "call_function": "run",
            },
            {
                "event_id": "evt-3",
                "run_id": "run-report-1",
                "timestamp": "2026-10-03T12:00:02Z",
                "language": "python",
                "library": "cryptography",
                "operation": "keygen",
                "algorithm": "RSA",
                "key_size": 2048,
                "call_file": "app.py",
                "call_line": 20,
                "call_function": "gen_keys",
            },
        ]

        report = generate_report_from_events(
            run_id="run-report-1",
            raw_events=sample_events,
            language="python",
            environment="test",
        )

        self.assertEqual(report["run_id"], "run-report-1")
        self.assertEqual(report["summary"]["total_events"], 3)
        self.assertIn("SHA-256", report["summary"]["unique_algorithms"])
        self.assertIn("RSA", report["summary"]["unique_algorithms"])
        self.assertIn("RSA", report["summary"]["quantum_vulnerable_algorithms"])
        self.assertEqual(report["summary"]["unmatched_events"], 3)

        # Verify aggregation: SHA-256 repeated twice -> 1 aggregated event entry with count 2
        events_list = report["events"]
        self.assertEqual(len(events_list), 2)

        sha_entry = next(e for e in events_list if e["algorithm"] == "SHA-256")
        self.assertEqual(sha_entry["count"], 2)
        self.assertEqual(sha_entry["first_seen"], "2026-10-03T12:00:00Z")
        self.assertEqual(sha_entry["last_seen"], "2026-10-03T12:00:01Z")

        rsa_entry = next(e for e in events_list if e["algorithm"] == "RSA")
        self.assertEqual(rsa_entry["count"], 1)
        self.assertTrue(rsa_entry["is_quantum_vulnerable"])


if __name__ == "__main__":
    unittest.main()

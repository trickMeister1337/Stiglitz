#!/usr/bin/env python3
"""Unit tests for email_spoof_poc.py and the refactored email_security classifiers."""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))


class TestEmailSecurityClassifiers(unittest.TestCase):
    def test_classify_spf_missing(self):
        from email_security import classify_spf
        r = classify_spf([])
        self.assertEqual(r["status"], "MISSING")
        self.assertEqual(r["severity"], "high")

    def test_classify_spf_permissive(self):
        from email_security import classify_spf
        r = classify_spf(["v=spf1 +all"])
        self.assertEqual(r["status"], "PERMISSIVE")

    def test_classify_spf_ok(self):
        from email_security import classify_spf
        r = classify_spf(["v=spf1 include:_spf.google.com -all"])
        self.assertEqual(r["status"], "OK")

    def test_classify_dmarc_missing(self):
        from email_security import classify_dmarc
        r = classify_dmarc([], "example.com")
        self.assertEqual(r["status"], "MISSING")

    def test_classify_dmarc_none_exposes_policy(self):
        from email_security import classify_dmarc
        r = classify_dmarc(['v=DMARC1; p=none; rua=mailto:x@example.com'], "example.com")
        self.assertEqual(r["status"], "MONITOR_ONLY")
        self.assertEqual(r["policy"], "none")

    def test_classify_dmarc_reject_exposes_policy(self):
        from email_security import classify_dmarc
        r = classify_dmarc(['v=DMARC1; p=reject'], "example.com")
        self.assertEqual(r["status"], "OK")
        self.assertEqual(r["policy"], "reject")

    def test_classify_dkim_found(self):
        from email_security import classify_dkim
        self.assertEqual(classify_dkim(["google"])["status"], "OK")

    def test_classify_dkim_not_found(self):
        from email_security import classify_dkim
        self.assertEqual(classify_dkim([])["status"], "NOT_FOUND")


class TestVerdict(unittest.TestCase):
    def _records(self, spf_status="MISSING", dmarc_status="MISSING", dmarc_policy=None):
        return {
            "spf": {"status": spf_status, "severity": "high"},
            "dmarc": {"status": dmarc_status, "severity": "high", **({"policy": dmarc_policy} if dmarc_policy else {})},
            "dkim": {"status": "NOT_FOUND", "severity": "low"},
        }

    def test_verdict_missing_dmarc_is_inbox(self):
        import email_spoof_poc as esp
        v = esp.compute_verdict(self._records(dmarc_status="MISSING"), "x@example.com")
        self.assertEqual(v["status"], "SPOOFABLE_INBOX")

    def test_verdict_p_none_is_inbox(self):
        import email_spoof_poc as esp
        v = esp.compute_verdict(self._records(dmarc_status="MONITOR_ONLY", dmarc_policy="none"), "x@example.com")
        self.assertEqual(v["status"], "SPOOFABLE_INBOX")

    def test_verdict_quarantine_is_spam(self):
        import email_spoof_poc as esp
        v = esp.compute_verdict(self._records(dmarc_status="OK", dmarc_policy="quarantine"), "x@example.com")
        self.assertEqual(v["status"], "SPOOFABLE_SPAM")

    def test_verdict_reject_is_blocked(self):
        import email_spoof_poc as esp
        v = esp.compute_verdict(self._records(dmarc_status="OK", dmarc_policy="reject"), "x@example.com")
        self.assertEqual(v["status"], "BLOCKED_EXACT")

    def test_verdict_spf_note_present_when_weak(self):
        import email_spoof_poc as esp
        v = esp.compute_verdict(self._records(spf_status="MISSING", dmarc_status="MISSING"), "x@example.com")
        self.assertIsNotNone(v["spf_note_en"])

    def test_verdict_carries_forged_envelope(self):
        import email_spoof_poc as esp
        v = esp.compute_verdict(self._records(), "spoof@example.com")
        self.assertEqual(v["forged_envelope"]["header_from"], "spoof@example.com")


if __name__ == "__main__":
    unittest.main()

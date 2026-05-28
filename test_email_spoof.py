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

    def test_verdict_invalid_dmarc_is_indeterminate(self):
        import email_spoof_poc as esp
        v = esp.compute_verdict(self._records(dmarc_status="INVALID", dmarc_policy="unknown"), "x@example.com")
        self.assertEqual(v["status"], "INDETERMINATE")


class TestMessage(unittest.TestCase):
    def test_build_message_sets_forged_from(self):
        import email_spoof_poc as esp
        msg, msg_id = esp.build_message("ceo@target.com", "victim@corp.com", "Subj", "Body")
        self.assertEqual(msg["From"], "ceo@target.com")
        self.assertEqual(msg["To"], "victim@corp.com")
        self.assertEqual(msg["Subject"], "Subj")

    def test_build_message_returns_captured_message_id(self):
        import email_spoof_poc as esp
        msg, msg_id = esp.build_message("ceo@target.com", "victim@corp.com", "Subj", "Body")
        self.assertTrue(msg_id.startswith("<"))
        self.assertEqual(msg["Message-ID"], msg_id)

    def test_build_message_body_present(self):
        import email_spoof_poc as esp
        msg, _ = esp.build_message("a@b.com", "c@d.com", "S", "HELLO-BODY")
        self.assertIn("HELLO-BODY", msg.get_content())


class FakeSMTP:
    """SMTP falso para testar a entrega sem rede. Registra comandos."""
    instances = []

    def __init__(self, host, port, timeout=15):
        self.host = host
        self.port = port
        self.commands = []
        FakeSMTP.instances.append(self)

    def ehlo(self, name=""):
        self.commands.append(("ehlo", name))
        return (250, b"ok")

    def mail(self, addr):
        self.commands.append(("mail", addr))
        return (250, b"sender ok")

    def rcpt(self, addr):
        self.commands.append(("rcpt", addr))
        return (250, b"recipient ok")

    def data(self, msg_bytes):
        self.commands.append(("data", len(msg_bytes)))
        return (250, b"queued as ABC123")

    def starttls(self):
        self.commands.append(("starttls", None))

    def login(self, user, password):
        self.commands.append(("login", user))

    def quit(self):
        self.commands.append(("quit", None))

    def close(self):
        self.commands.append(("close", None))


class TestDelivery(unittest.TestCase):
    def setUp(self):
        FakeSMTP.instances = []

    def test_parse_mx_sorts_by_preference(self):
        import email_spoof_poc as esp
        hosts = esp.parse_mx("20 mx2.example.com.\n10 mx1.example.com.")
        self.assertEqual(hosts, ["mx1.example.com", "mx2.example.com"])

    def test_deliver_direct_accepts_on_250(self):
        import email_spoof_poc as esp
        result = esp.deliver_direct(["mx1.example.com"], "attacker.test",
                                    "ceo@target.com", "victim@corp.com", b"RAW",
                                    smtp_factory=FakeSMTP)
        self.assertTrue(result["accepted"])
        self.assertEqual(result["mx_used"], "mx1.example.com")
        self.assertEqual(result["method"], "direct")
        self.assertTrue(any("DATA" in line for line in result["transcript"]))

    def test_deliver_direct_tries_next_mx_on_failure(self):
        import email_spoof_poc as esp

        class FailFirst(FakeSMTP):
            def __init__(self, host, port, timeout=15):
                if host == "mx1.example.com":
                    raise OSError("connection refused")
                super().__init__(host, port, timeout)

        result = esp.deliver_direct(["mx1.example.com", "mx2.example.com"], "h",
                                    "a@b.com", "c@d.com", b"RAW", smtp_factory=FailFirst)
        self.assertTrue(result["accepted"])
        self.assertEqual(result["mx_used"], "mx2.example.com")

    def test_deliver_relay_authenticates_when_user_given(self):
        import email_spoof_poc as esp
        result = esp.deliver_relay("relay.test", 587, "user", "pass", "h",
                                   "a@b.com", "c@d.com", b"RAW", smtp_factory=FakeSMTP)
        self.assertTrue(result["accepted"])
        self.assertEqual(result["method"], "relay")
        inst = FakeSMTP.instances[-1]
        self.assertIn(("starttls", None), inst.commands)
        self.assertIn(("login", "user"), inst.commands)

    def test_deliver_direct_closes_socket_on_midconversation_failure(self):
        import email_spoof_poc as esp

        class FailOnMail(FakeSMTP):
            def mail(self, addr):
                raise OSError("boom")

        result = esp.deliver_direct(["mx1.example.com"], "h",
                                    "a@b.com", "c@d.com", b"RAW", smtp_factory=FailOnMail)
        self.assertFalse(result["accepted"])
        inst = FakeSMTP.instances[-1]
        self.assertIn(("close", None), inst.commands)

    def test_deliver_relay_reports_host_on_error(self):
        import email_spoof_poc as esp

        class FailConnect(FakeSMTP):
            def __init__(self, host, port, timeout=15):
                raise OSError("refused")

        result = esp.deliver_relay("relay.test", 587, None, None, "h",
                                   "a@b.com", "c@d.com", b"RAW", smtp_factory=FailConnect)
        self.assertFalse(result["accepted"])
        self.assertEqual(result["mx_used"], "relay.test")


class TestGateAndOutput(unittest.TestCase):
    def test_roe_gate_passes_with_assume_yes(self):
        import email_spoof_poc as esp
        self.assertTrue(esp.roe_gate("a@b.com", "c@d.com", "direct", assume_yes=True))

    def test_roe_gate_blocks_non_interactive_without_consent(self):
        import email_spoof_poc as esp
        # sem assume_yes e sem TTY → falha segura (não envia)
        self.assertFalse(esp.roe_gate("a@b.com", "c@d.com", "direct",
                                      assume_yes=False, interactive=False))

    def test_write_evidence_creates_json_and_transcript(self):
        import json
        import tempfile
        import email_spoof_poc as esp
        with tempfile.TemporaryDirectory() as d:
            records = {"spf": {"status": "MISSING", "severity": "high"},
                       "dmarc": {"status": "MISSING", "severity": "high"},
                       "dkim": {"status": "NOT_FOUND", "severity": "low"}}
            verdict = {"status": "SPOOFABLE_INBOX", "impact_en": "x",
                       "spf_note_en": None,
                       "forged_envelope": {"mail_from": "a@b.com", "header_from": "a@b.com"}}
            send = {"recipient": "c@d.com", "forged_from": "a@b.com", "mx_used": "mx1",
                    "delivery_method": "direct", "message_id": "<id>", "accepted": True,
                    "transcript": ["CONNECT mx1:25", "DATA -> 250 ok"]}
            esp.write_evidence(d, "example.com", records, verdict, send)
            with open(os.path.join(d, "spoof_evidence.json")) as f:
                data = json.load(f)
            self.assertEqual(data["verdict"]["status"], "SPOOFABLE_INBOX")
            self.assertEqual(data["send"]["accepted"], True)
            self.assertTrue(os.path.exists(os.path.join(d, "smtp_transcript.txt")))

    def test_write_evidence_without_send_omits_send_block(self):
        import json
        import tempfile
        import email_spoof_poc as esp
        with tempfile.TemporaryDirectory() as d:
            records = {"spf": {"status": "OK"}, "dmarc": {"status": "OK"}, "dkim": {"status": "OK"}}
            verdict = {"status": "BLOCKED_EXACT", "impact_en": "x", "spf_note_en": None,
                       "forged_envelope": {"mail_from": "a@b.com", "header_from": "a@b.com"}}
            esp.write_evidence(d, "example.com", records, verdict, None)
            with open(os.path.join(d, "spoof_evidence.json")) as f:
                data = json.load(f)
            self.assertNotIn("send", data)
            self.assertFalse(os.path.exists(os.path.join(d, "smtp_transcript.txt")))

    def test_roe_gate_interactive_accepts_on_sim(self):
        import builtins
        from unittest import mock
        import email_spoof_poc as esp
        with mock.patch.object(builtins, "input", return_value="SIM"):
            self.assertTrue(esp.roe_gate("a@b.com", "c@d.com", "direct",
                                         assume_yes=False, interactive=True))

    def test_roe_gate_interactive_rejects_other_input(self):
        import builtins
        from unittest import mock
        import email_spoof_poc as esp
        with mock.patch.object(builtins, "input", return_value="nao"):
            self.assertFalse(esp.roe_gate("a@b.com", "c@d.com", "direct",
                                          assume_yes=False, interactive=True))

    def test_main_dry_run_writes_analytical_evidence(self):
        import json
        import tempfile
        from unittest import mock
        import email_spoof_poc as esp
        fake_records = {"spf": {"status": "MISSING", "severity": "high"},
                        "dmarc": {"status": "MISSING", "severity": "high"},
                        "dkim": {"status": "NOT_FOUND", "severity": "low"}}
        with tempfile.TemporaryDirectory() as d:
            with mock.patch("email_security.analyze", return_value=fake_records):
                rc = esp.main(["example.com", "--dry-run", "--to", "x@test.com", "--outdir", d])
            self.assertEqual(rc, 0)
            with open(os.path.join(d, "spoof_evidence.json")) as f:
                data = json.load(f)
            self.assertEqual(data["verdict"]["status"], "SPOOFABLE_INBOX")
            self.assertNotIn("send", data)


if __name__ == "__main__":
    unittest.main()

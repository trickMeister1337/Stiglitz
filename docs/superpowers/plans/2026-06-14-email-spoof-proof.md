# Email Spoof — Prova de Loop Fechado — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Transformar `email_spoof_poc.py` de "envia e para no 250" em uma prova de loop fechado: envio via relay autenticado, classificação honesta do estágio SMTP, e verdito empírico final via confirmação manual do `Authentication-Results`.

**Architecture:** Tudo em `email_spoof_poc.py` (script standalone single-file, padrão do suite). Funções puras novas (`parse_auth_results`, `compute_empirical_verdict`) + reclassificação dos `deliver_*` + novo modo `--finalize`. Sem rede nos testes (`smtp_factory`/mock injetáveis, padrão já existente).

**Tech Stack:** Python 3 stdlib (`smtplib`, `email`, `re`, `json`, `argparse`), `unittest` + `FakeSMTP` (já em `tests/test_email_spoof.py`).

**Higiene CDE:** todos os testes usam placeholders genéricos (`example.com`, `target.com`). Nenhum domínio/caixa de cliente em código ou fixture.

---

### Task 1: Parser puro de `Authentication-Results`

**Files:**
- Modify: `email_spoof_poc.py` (adiciona `import re` e a função `parse_auth_results`)
- Test: `tests/test_email_spoof.py`

- [ ] **Step 1: Write the failing test**

Adicione ao final de `tests/test_email_spoof.py`, antes do `if __name__`:

```python
class TestParseAuthResults(unittest.TestCase):
    def test_extracts_dmarc_spf_dkim(self):
        import email_spoof_poc as esp
        h = ("Authentication-Results: mx.google.com; "
             "dmarc=fail (p=NONE sp=NONE) header.from=target.com; "
             "spf=softfail smtp.mailfrom=target.com; dkim=none")
        r = esp.parse_auth_results(h)
        self.assertEqual(r["dmarc"], "fail")
        self.assertEqual(r["spf"], "softfail")
        self.assertEqual(r["dkim"], "none")

    def test_handles_multiline_header(self):
        import email_spoof_poc as esp
        h = "Authentication-Results: mx.test;\n  dmarc=pass\n  spf=pass\n  dkim=pass"
        r = esp.parse_auth_results(h)
        self.assertEqual(r["dmarc"], "pass")

    def test_missing_fields_are_none(self):
        import email_spoof_poc as esp
        r = esp.parse_auth_results("Authentication-Results: mx.test; spf=pass")
        self.assertEqual(r["spf"], "pass")
        self.assertIsNone(r["dmarc"])
        self.assertIsNone(r["dkim"])

    def test_empty_input_all_none(self):
        import email_spoof_poc as esp
        r = esp.parse_auth_results("")
        self.assertIsNone(r["dmarc"])
        self.assertIsNone(r["spf"])
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_email_spoof.py::TestParseAuthResults -q`
Expected: FAIL com `AttributeError: module 'email_spoof_poc' has no attribute 'parse_auth_results'`

- [ ] **Step 3: Write minimal implementation**

Em `email_spoof_poc.py`, adicione `import re` junto aos outros imports do topo (após `import os`). Depois adicione a função (sugestão: logo após `compute_verdict`):

```python
def parse_auth_results(header):
    """Extrai os veredictos de um header Authentication-Results.

    Tolerante a múltiplas linhas e à ausência de campos. Retorna dict com
    dmarc/spf/dkim/compauth → valor minúsculo ('pass'|'fail'|'none'|...) ou None.
    """
    keys = ("dmarc", "spf", "dkim", "compauth")
    out = {k: None for k in keys}
    if not header:
        return out
    flat = " ".join(str(header).splitlines())
    for key in keys:
        m = re.search(r'\b' + key + r'=([a-zA-Z]+)', flat, re.IGNORECASE)
        if m:
            out[key] = m.group(1).lower()
    return out
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_email_spoof.py::TestParseAuthResults -q`
Expected: PASS (4 passed)

- [ ] **Step 5: Commit**

```bash
git add email_spoof_poc.py tests/test_email_spoof.py
git commit -m "feat(spoof): parser puro de Authentication-Results

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 2: Classificação de estágio SMTP (`smtp_stage`)

**Files:**
- Modify: `email_spoof_poc.py` (`deliver_direct` e `deliver_relay` passam a retornar `smtp_stage`)
- Test: `tests/test_email_spoof.py`

`smtp_stage` ∈ `{"TRANSPORT_FAILED", "BLOCKED_BY_RELAY", "QUEUED"}`. `accepted` permanece (derivado de `smtp_stage == "QUEUED"`) para não quebrar os testes existentes.

- [ ] **Step 1: Write the failing test**

Adicione à classe `TestDelivery` em `tests/test_email_spoof.py`:

```python
    def test_stage_queued_on_250(self):
        import email_spoof_poc as esp
        result = esp.deliver_direct(["mx1.example.com"], "h", "a@b.com",
                                    "c@d.com", b"RAW", smtp_factory=FakeSMTP)
        self.assertEqual(result["smtp_stage"], "QUEUED")
        self.assertTrue(result["accepted"])

    def test_stage_blocked_when_rcpt_refused(self):
        import email_spoof_poc as esp

        class RcptRefused(FakeSMTP):
            def rcpt(self, addr):
                self.commands.append(("rcpt", addr))
                return (550, b"relaying denied")

        result = esp.deliver_direct(["mx1.example.com"], "h", "a@b.com",
                                    "c@d.com", b"RAW", smtp_factory=RcptRefused)
        self.assertEqual(result["smtp_stage"], "BLOCKED_BY_RELAY")
        self.assertFalse(result["accepted"])

    def test_stage_transport_failed_on_connect_error(self):
        import email_spoof_poc as esp

        class FailConnect(FakeSMTP):
            def __init__(self, host, port, timeout=15):
                raise OSError("refused")

        result = esp.deliver_direct(["mx1.example.com"], "h", "a@b.com",
                                    "c@d.com", b"RAW", smtp_factory=FailConnect)
        self.assertEqual(result["smtp_stage"], "TRANSPORT_FAILED")

    def test_relay_stage_queued(self):
        import email_spoof_poc as esp
        result = esp.deliver_relay("relay.test", 587, "user", "pass", "h",
                                   "a@b.com", "c@d.com", b"RAW", smtp_factory=FakeSMTP)
        self.assertEqual(result["smtp_stage"], "QUEUED")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_email_spoof.py::TestDelivery -q`
Expected: FAIL com `KeyError: 'smtp_stage'`

- [ ] **Step 3: Write minimal implementation**

Substitua a função `deliver_direct` inteira por:

```python
def deliver_direct(mx_hosts, helo, mail_from, rcpt_to, msg_bytes,
                   timeout=15, smtp_factory=smtplib.SMTP):
    """Entrega direta na porta 25, tentando cada MX. Classifica o estágio."""
    transcript = []
    last_err = None
    stage = "TRANSPORT_FAILED"  # default: nem conectou
    for host in mx_hosts:
        s = None
        try:
            transcript.append(f"CONNECTING {host}:25")
            s = smtp_factory(host, 25, timeout=timeout)
            transcript.append(f"CONNECTED {host}:25")
            code, resp = s.ehlo(helo)
            transcript.append(f"EHLO {helo} -> {code} {_decode(resp)}")
            code, resp = s.mail(mail_from)
            transcript.append(f"MAIL FROM:<{mail_from}> -> {code} {_decode(resp)}")
            if code != 250:
                stage = "BLOCKED_BY_RELAY"
                raise smtplib.SMTPException(f"MAIL FROM rejeitado: {code} {_decode(resp)}")
            code, resp = s.rcpt(rcpt_to)
            transcript.append(f"RCPT TO:<{rcpt_to}> -> {code} {_decode(resp)}")
            if code not in (250, 251):
                stage = "BLOCKED_BY_RELAY"
                raise smtplib.SMTPException(f"RCPT TO rejeitado: {code} {_decode(resp)}")
            code, resp = s.data(msg_bytes)
            transcript.append(f"DATA -> {code} {_decode(resp)}")
            stage = "QUEUED" if code == 250 else "BLOCKED_BY_RELAY"
            accepted = stage == "QUEUED"
            try:
                s.quit()
            except Exception:
                _quiet_close(s)
            return {"method": "direct", "mx_used": host, "accepted": accepted,
                    "smtp_stage": stage, "transcript": transcript}
        except Exception as e:
            transcript.append(f"ERROR {host}: {e}")
            last_err = e
            _quiet_close(s)
            continue
    return {"method": "direct", "mx_used": None, "accepted": False,
            "smtp_stage": stage, "transcript": transcript,
            "error": str(last_err) if last_err else None}
```

Substitua a função `deliver_relay` inteira por:

```python
def deliver_relay(host, port, user, password, helo, mail_from, rcpt_to, msg_bytes,
                  timeout=15, smtp_factory=smtplib.SMTP):
    """Entrega via relay configurado (STARTTLS+login se user fornecido)."""
    transcript = []
    s = None
    stage = "TRANSPORT_FAILED"
    try:
        transcript.append(f"CONNECTING relay {host}:{port}")
        s = smtp_factory(host, port, timeout=timeout)
        transcript.append(f"CONNECTED relay {host}:{port}")
        code, resp = s.ehlo(helo)
        transcript.append(f"EHLO {helo} -> {code} {_decode(resp)}")
        if user:
            s.starttls()
            code, resp = s.ehlo(helo)
            transcript.append(f"EHLO (post-STARTTLS) {helo} -> {code} {_decode(resp)}")
            s.login(user, password)
            transcript.append("STARTTLS + AUTH")
        code, resp = s.mail(mail_from)
        transcript.append(f"MAIL FROM:<{mail_from}> -> {code} {_decode(resp)}")
        if code != 250:
            stage = "BLOCKED_BY_RELAY"
            raise smtplib.SMTPException(f"MAIL FROM rejeitado: {code} {_decode(resp)}")
        code, resp = s.rcpt(rcpt_to)
        transcript.append(f"RCPT TO:<{rcpt_to}> -> {code} {_decode(resp)}")
        if code not in (250, 251):
            stage = "BLOCKED_BY_RELAY"
            raise smtplib.SMTPException(f"RCPT TO rejeitado: {code} {_decode(resp)}")
        code, resp = s.data(msg_bytes)
        transcript.append(f"DATA -> {code} {_decode(resp)}")
        stage = "QUEUED" if code == 250 else "BLOCKED_BY_RELAY"
        accepted = stage == "QUEUED"
        try:
            s.quit()
        except Exception:
            _quiet_close(s)
        return {"method": "relay", "mx_used": host, "accepted": accepted,
                "smtp_stage": stage, "transcript": transcript}
    except Exception as e:
        transcript.append(f"ERROR relay {host}: {e}")
        _quiet_close(s)
        return {"method": "relay", "mx_used": host, "accepted": False,
                "smtp_stage": stage, "transcript": transcript, "error": str(e)}
```

Nota: a função `_require_ok` deixa de ser usada — pode ser removida, mas não é obrigatório (deixá-la não quebra nada). Se removê-la, rode a suíte inteira no Step 4 para confirmar que nada mais a referencia.

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_email_spoof.py -q`
Expected: PASS (toda a suíte, incluindo os testes antigos de `accepted`)

- [ ] **Step 5: Commit**

```bash
git add email_spoof_poc.py tests/test_email_spoof.py
git commit -m "feat(spoof): classifica estagio SMTP (transport/blocked/queued)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 3: Verdito empírico (`compute_empirical_verdict`)

**Files:**
- Modify: `email_spoof_poc.py` (nova função pura)
- Test: `tests/test_email_spoof.py`

- [ ] **Step 1: Write the failing test**

Adicione ao final de `tests/test_email_spoof.py`:

```python
class TestEmpiricalVerdict(unittest.TestCase):
    def _analytic(self):
        return {"status": "SPOOFABLE_INBOX", "impact_en": "x"}

    def test_transport_failed_is_inconclusive(self):
        import email_spoof_poc as esp
        v = esp.compute_empirical_verdict(self._analytic(), "TRANSPORT_FAILED")
        self.assertEqual(v["status"], "INCONCLUSIVE_TRANSPORT")
        self.assertEqual(v["severity"], "info")

    def test_blocked_by_relay(self):
        import email_spoof_poc as esp
        v = esp.compute_empirical_verdict(self._analytic(), "BLOCKED_BY_RELAY")
        self.assertEqual(v["status"], "BLOCKED_BY_RELAY")

    def test_queued_without_confirmation_is_pending(self):
        import email_spoof_poc as esp
        v = esp.compute_empirical_verdict(self._analytic(), "QUEUED")
        self.assertEqual(v["status"], "QUEUED_PENDING_CONFIRMATION")

    def test_inbox_dmarc_fail_is_proven_critical(self):
        import email_spoof_poc as esp
        v = esp.compute_empirical_verdict(self._analytic(), "QUEUED",
                                          landed="inbox", auth={"dmarc": "fail"})
        self.assertEqual(v["status"], "SPOOF_PROVEN_INBOX")
        self.assertEqual(v["severity"], "critical")

    def test_spam_dmarc_fail_is_proven_spam(self):
        import email_spoof_poc as esp
        v = esp.compute_empirical_verdict(self._analytic(), "QUEUED",
                                          landed="spam", auth={"dmarc": "fail"})
        self.assertEqual(v["status"], "SPOOF_PROVEN_SPAM")

    def test_dmarc_pass_is_not_spoofable(self):
        import email_spoof_poc as esp
        v = esp.compute_empirical_verdict(self._analytic(), "QUEUED",
                                          landed="inbox", auth={"dmarc": "pass"})
        self.assertEqual(v["status"], "NOT_SPOOFABLE")

    def test_not_delivered(self):
        import email_spoof_poc as esp
        v = esp.compute_empirical_verdict(self._analytic(), "QUEUED",
                                          landed="not_delivered", auth={"dmarc": "fail"})
        self.assertEqual(v["status"], "NOT_DELIVERED")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_email_spoof.py::TestEmpiricalVerdict -q`
Expected: FAIL com `AttributeError: ... has no attribute 'compute_empirical_verdict'`

- [ ] **Step 3: Write minimal implementation**

Em `email_spoof_poc.py`, adicione após `compute_verdict`:

```python
def compute_empirical_verdict(analytic, smtp_stage, landed=None, auth=None):
    """Combina o verdito analítico (DNS) com a confirmação empírica.

    smtp_stage: 'TRANSPORT_FAILED' | 'BLOCKED_BY_RELAY' | 'QUEUED'
    landed:     'inbox' | 'spam' | 'not_delivered' | None (sem confirmação)
    auth:       dict de parse_auth_results (ou None)
    """
    auth = auth or {}
    dmarc = (auth.get("dmarc") or "").lower()
    if smtp_stage == "TRANSPORT_FAILED":
        return {"status": "INCONCLUSIVE_TRANSPORT", "severity": "info",
                "impact_en": "Delivery transport failed (port 25 blocked or sending-IP "
                             "reputation) — NOT a proof the domain is protected."}
    if smtp_stage == "BLOCKED_BY_RELAY":
        return {"status": "BLOCKED_BY_RELAY", "severity": "info",
                "impact_en": "The sending path refused the forged envelope (MAIL/RCPT/DATA) "
                             "before delivery."}
    # smtp_stage == QUEUED
    if landed is None:
        return {"status": "QUEUED_PENDING_CONFIRMATION", "severity": "pending",
                "impact_en": "Message queued for delivery; awaiting manual inbox confirmation "
                             "(Authentication-Results)."}
    if landed == "not_delivered":
        return {"status": "NOT_DELIVERED", "severity": "info",
                "impact_en": "Message was queued but never reached the mailbox "
                             "(silently dropped/discarded)."}
    if dmarc == "pass":
        return {"status": "NOT_SPOOFABLE", "severity": "info",
                "impact_en": "Receiver authenticated the message (dmarc=pass) — the forged "
                             "From: did not bypass DMARC."}
    if landed == "spam":
        return {"status": "SPOOF_PROVEN_SPAM", "severity": "medium",
                "impact_en": f"Forged From: delivered but quarantined/spam-foldered "
                             f"(dmarc={dmarc or 'n/a'})."}
    return {"status": "SPOOF_PROVEN_INBOX", "severity": "critical",
            "impact_en": f"Forged From: of the exact domain delivered to the inbox with "
                         f"dmarc={dmarc or 'n/a'} — spoofing proven."}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_email_spoof.py::TestEmpiricalVerdict -q`
Expected: PASS (7 passed)

- [ ] **Step 5: Commit**

```bash
git add email_spoof_poc.py tests/test_email_spoof.py
git commit -m "feat(spoof): verdito empirico (proven/not-spoofable/inconclusive)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 4: Relay como caminho primário + `--allow-direct`

**Files:**
- Modify: `email_spoof_poc.py` (`parse_args` + bloco de envio em `main`)
- Test: `tests/test_email_spoof.py`

- [ ] **Step 1: Write the failing test**

Adicione ao final de `tests/test_email_spoof.py`:

```python
class TestSendRouting(unittest.TestCase):
    def _spoofable(self):
        return {"spf": {"status": "MISSING", "severity": "high"},
                "dmarc": {"status": "MISSING", "severity": "high"},
                "dkim": {"status": "NOT_FOUND", "severity": "low"}}

    def test_relay_is_primary_when_smtp_given(self):
        import tempfile
        from unittest import mock
        import email_spoof_poc as esp
        relay_result = {"method": "relay", "mx_used": "relay.test", "accepted": True,
                        "smtp_stage": "QUEUED", "transcript": ["DATA -> 250 ok"]}
        with tempfile.TemporaryDirectory() as d:
            with mock.patch("email_security.analyze", return_value=self._spoofable()), \
                 mock.patch.object(esp, "deliver_relay", return_value=relay_result) as mrelay, \
                 mock.patch.object(esp, "deliver_direct") as mdirect:
                rc = esp.main(["example.com", "--send", "--to", "x@test.com",
                               "--smtp", "relay.test:587", "--roe-accept", "--outdir", d])
            self.assertEqual(rc, 0)
            mrelay.assert_called_once()
            mdirect.assert_not_called()

    def test_no_direct_fallback_without_allow_direct(self):
        import tempfile
        from unittest import mock
        import email_spoof_poc as esp
        blocked = {"method": "relay", "mx_used": "relay.test", "accepted": False,
                   "smtp_stage": "BLOCKED_BY_RELAY", "transcript": ["MAIL -> 553"]}
        with tempfile.TemporaryDirectory() as d:
            with mock.patch("email_security.analyze", return_value=self._spoofable()), \
                 mock.patch.object(esp, "deliver_relay", return_value=blocked), \
                 mock.patch.object(esp, "deliver_direct") as mdirect:
                esp.main(["example.com", "--send", "--to", "x@test.com",
                          "--smtp", "relay.test:587", "--roe-accept", "--outdir", d])
            mdirect.assert_not_called()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_email_spoof.py::TestSendRouting -q`
Expected: FAIL — sem `--allow-direct` no parser e/ou `deliver_direct` ainda é chamado como primário.

- [ ] **Step 3: Write minimal implementation**

Em `parse_args`, adicione junto às outras flags (antes do `return`):

```python
    p.add_argument("--allow-direct", action="store_true",
                   help="Permite fallback de entrega direta na porta 25 quando o relay não enfileira.")
```

Em `main`, substitua o bloco de envio atual (de `recipient_domain = args.to.split("@", 1)[1]` até o fim da montagem de `result`, antes de `send = {`) por:

```python
        msg_bytes = msg.as_bytes()
        if args.smtp:
            print("  [!] Relay autenticado: a prova de spoof só vale se o relay PRESERVAR o "
                  "From: forjado. Relays gerenciados (Gmail/SES/etc) reescrevem/rejeitam.")
            host, _, port = args.smtp.partition(":")
            smtp_pass = args.smtp_pass or os.environ.get("STIGLITZ_SMTP_PASS")
            result = deliver_relay(host, int(port) if port else 587,
                                   args.smtp_user, smtp_pass, helo,
                                   forged_from, args.to, msg_bytes)
            if result.get("smtp_stage") != "QUEUED" and args.allow_direct:
                print("  [→] Relay não enfileirou — fallback de entrega direta (--allow-direct) ...")
                mx_hosts = parse_mx(dig("MX", args.to.split("@", 1)[1]))
                if mx_hosts:
                    result = deliver_direct(mx_hosts, helo, forged_from, args.to, msg_bytes)
        else:
            mx_hosts = parse_mx(dig("MX", args.to.split("@", 1)[1]))
            result = {"method": "direct", "mx_used": None, "accepted": False,
                      "smtp_stage": "TRANSPORT_FAILED", "transcript": ["sem MX resolvido"]}
            if mx_hosts:
                result = deliver_direct(mx_hosts, helo, forged_from, args.to, msg_bytes)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_email_spoof.py -q`
Expected: PASS (suíte inteira)

- [ ] **Step 5: Commit**

```bash
git add email_spoof_poc.py tests/test_email_spoof.py
git commit -m "feat(spoof): relay autenticado como caminho primario (--allow-direct)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 5: Evidência com verdito empírico + confirmação manual pendente

**Files:**
- Modify: `email_spoof_poc.py` (`write_evidence` aceita `empirical`/`manual`; `main` os monta no envio)
- Test: `tests/test_email_spoof.py`

- [ ] **Step 1: Write the failing test**

Adicione à classe `TestSendRouting` em `tests/test_email_spoof.py`:

```python
    def test_queued_writes_pending_manual_confirmation(self):
        import json, tempfile
        from unittest import mock
        import email_spoof_poc as esp
        relay_result = {"method": "relay", "mx_used": "relay.test", "accepted": True,
                        "smtp_stage": "QUEUED", "transcript": ["DATA -> 250 ok"]}
        with tempfile.TemporaryDirectory() as d:
            with mock.patch("email_security.analyze", return_value=self._spoofable()), \
                 mock.patch.object(esp, "deliver_relay", return_value=relay_result):
                esp.main(["example.com", "--send", "--to", "x@test.com",
                          "--smtp", "relay.test:587", "--roe-accept", "--outdir", d])
            with open(os.path.join(d, "spoof_evidence.json")) as f:
                data = json.load(f)
        self.assertEqual(data["empirical_verdict"]["status"], "QUEUED_PENDING_CONFIRMATION")
        self.assertIsNone(data["manual_confirmation"]["landed"])
        self.assertIn("message_id", data["manual_confirmation"])
        self.assertEqual(data["send"]["smtp_stage"], "QUEUED")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest "tests/test_email_spoof.py::TestSendRouting::test_queued_writes_pending_manual_confirmation" -q`
Expected: FAIL com `KeyError: 'empirical_verdict'`

- [ ] **Step 3: Write minimal implementation**

Em `write_evidence`, mude a assinatura e adicione os blocos opcionais:

```python
def write_evidence(outdir, domain, records, verdict, send, empirical=None, manual=None):
    """Grava spoof_evidence.json e (se houve envio) smtp_transcript.txt."""
    os.makedirs(outdir, exist_ok=True)
    evidence = {
        "domain": domain,
        "timestamp": datetime.datetime.now().isoformat(timespec="seconds"),
        "dns_records": records,
        "verdict": verdict,
    }
    if empirical is not None:
        evidence["empirical_verdict"] = empirical
    if manual is not None:
        evidence["manual_confirmation"] = manual
    if send is not None:
        transcript = send.get("transcript", [])
        evidence["send"] = {k: v for k, v in send.items() if k != "transcript"}
        evidence["send"]["smtp_transcript"] = transcript
        with open(os.path.join(outdir, "smtp_transcript.txt"), "w") as f:
            f.write("\n".join(transcript) + "\n")
    with open(os.path.join(outdir, "spoof_evidence.json"), "w") as f:
        json.dump(evidence, f, ensure_ascii=False, indent=2)
    return evidence
```

Em `main`, no bloco de envio, substitua a montagem de `send` e a chamada final de `write_evidence`. Localize o trecho que monta `send = {...}` e imprime `[SMTP] ...`, e troque por:

```python
        send = {
            "recipient": args.to,
            "forged_from": forged_from,
            "mx_used": result.get("mx_used"),
            "delivery_method": result.get("method", "direct"),
            "message_id": msg_id,
            "smtp_stage": result.get("smtp_stage"),
            "accepted": result.get("accepted", False),
            "transcript": result["transcript"],
        }
        stage = result.get("smtp_stage", "TRANSPORT_FAILED")
        print(f"  [SMTP] stage={stage} via {send['delivery_method']} (mx={send['mx_used']})")

        empirical = compute_empirical_verdict(verdict, stage, landed=None, auth=None)
        manual = None
        if stage == "QUEUED":
            manual = {
                "message_id": msg_id,
                "forged_from": forged_from,
                "recipient": args.to,
                "landed": None,
                "authentication_results": None,
                "instructions_en": (
                    f"Open mailbox {args.to}, find the message with Message-ID {msg_id}, "
                    f"copy its Authentication-Results header, then run: "
                    f"python3 email_spoof_poc.py --finalize {outdir} "
                    f"--auth-results \"<header>\" --landed inbox|spam|not_delivered"),
            }
            print("\n  [CONFIRMAÇÃO MANUAL] Email enfileirado. Para fechar a prova:")
            print(f"      1) Abra a caixa {args.to} e localize Message-ID {msg_id}")
            print(f"      2) Copie o header Authentication-Results")
            print(f"      3) python3 email_spoof_poc.py --finalize {outdir} "
                  f"--auth-results \"<header>\" --landed inbox|spam")
        print(f"  [VERDITO EMPÍRICO] {empirical['status']} — {empirical['impact_en']}")

        write_evidence(outdir, domain, records, verdict, send, empirical=empirical, manual=manual)
        print(f"  [✓] Evidência em {outdir}/spoof_evidence.json")
        return 0
```

Nota: este `return 0` encerra o fluxo de envio. Garanta que a chamada `write_evidence(outdir, domain, records, verdict, send)` **original** no fim de `main` (a que rodava após o bloco de envio) não seja mais alcançada nesse caminho — ela permanece apenas para o caminho sem `--send` (que já retorna antes, no dry-run, ou cai no `write_evidence` final só-analítico). Verifique que o caminho "sem `--send`" ainda grava a evidência analítica.

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_email_spoof.py -q`
Expected: PASS (suíte inteira, incluindo `test_main_dry_run_writes_analytical_evidence` e os de `write_evidence`)

- [ ] **Step 5: Commit**

```bash
git add email_spoof_poc.py tests/test_email_spoof.py
git commit -m "feat(spoof): evidencia com verdito empirico + confirmacao manual pendente

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 6: Modo `--finalize`

**Files:**
- Modify: `email_spoof_poc.py` (`parse_args` torna `domain` opcional + flags de finalize; `finalize_evidence`; dispatch em `main`)
- Test: `tests/test_email_spoof.py`

- [ ] **Step 1: Write the failing test**

Adicione ao final de `tests/test_email_spoof.py`:

```python
class TestFinalize(unittest.TestCase):
    def _pending(self, d):
        """Grava uma evidência pendente (QUEUED) em d e retorna o path."""
        import email_spoof_poc as esp
        records = {"spf": {"status": "MISSING"}, "dmarc": {"status": "MISSING"},
                   "dkim": {"status": "NOT_FOUND"}}
        verdict = {"status": "SPOOFABLE_INBOX", "impact_en": "x"}
        send = {"recipient": "x@test.com", "forged_from": "a@example.com",
                "mx_used": "relay.test", "delivery_method": "relay",
                "message_id": "<id-1>", "smtp_stage": "QUEUED", "accepted": True,
                "transcript": ["DATA -> 250"]}
        empirical = esp.compute_empirical_verdict(verdict, "QUEUED")
        manual = {"message_id": "<id-1>", "forged_from": "a@example.com",
                  "recipient": "x@test.com", "landed": None,
                  "authentication_results": None}
        esp.write_evidence(d, "example.com", records, verdict, send,
                           empirical=empirical, manual=manual)

    def test_finalize_inbox_dmarc_fail_is_proven(self):
        import json, tempfile
        import email_spoof_poc as esp
        with tempfile.TemporaryDirectory() as d:
            self._pending(d)
            rc = esp.main(["--finalize", d, "--landed", "inbox",
                           "--auth-results", "dmarc=fail spf=softfail dkim=none"])
            self.assertEqual(rc, 0)
            with open(os.path.join(d, "spoof_evidence.json")) as f:
                data = json.load(f)
        self.assertEqual(data["empirical_verdict"]["status"], "SPOOF_PROVEN_INBOX")
        self.assertEqual(data["manual_confirmation"]["landed"], "inbox")
        self.assertEqual(data["manual_confirmation"]["parsed_auth"]["dmarc"], "fail")

    def test_finalize_dmarc_pass_is_not_spoofable(self):
        import json, tempfile
        import email_spoof_poc as esp
        with tempfile.TemporaryDirectory() as d:
            self._pending(d)
            esp.main(["--finalize", d, "--landed", "inbox",
                      "--auth-results", "dmarc=pass spf=pass dkim=pass"])
            with open(os.path.join(d, "spoof_evidence.json")) as f:
                data = json.load(f)
        self.assertEqual(data["empirical_verdict"]["status"], "NOT_SPOOFABLE")

    def test_finalize_requires_auth_and_landed(self):
        import tempfile
        import email_spoof_poc as esp
        with tempfile.TemporaryDirectory() as d:
            self._pending(d)
            rc = esp.main(["--finalize", d, "--landed", "inbox"])
            self.assertEqual(rc, 2)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_email_spoof.py::TestFinalize -q`
Expected: FAIL — `domain` posicional obrigatório faz `parse_args` abortar (SystemExit) ou `--finalize` desconhecido.

- [ ] **Step 3: Write minimal implementation**

Em `parse_args`, torne `domain` opcional e adicione as flags de finalize. Troque a linha do posicional:

```python
    p.add_argument("domain", nargs="?", help="Domínio alvo (domínio forjado em From:/MAIL FROM)")
```

e adicione (antes do `return`):

```python
    p.add_argument("--finalize", metavar="DIR",
                   help="Modo finalização: aplica a confirmação manual a uma evidência pendente.")
    p.add_argument("--auth-results", help="Header Authentication-Results colado da caixa (com --finalize).")
    p.add_argument("--auth-results-file", help="Lê o Authentication-Results de um arquivo (com --finalize).")
    p.add_argument("--landed", choices=("inbox", "spam", "not_delivered"),
                   help="Onde a mensagem chegou (com --finalize).")
```

Adicione a função `finalize_evidence` (após `write_evidence`):

```python
def finalize_evidence(outdir, auth_results, landed):
    """Aplica a confirmação manual a uma evidência pendente e grava o verdito empírico final."""
    path = os.path.join(outdir, "spoof_evidence.json")
    with open(path) as f:
        evidence = json.load(f)
    auth = parse_auth_results(auth_results)
    analytic = evidence.get("verdict", {})
    stage = (evidence.get("send") or {}).get("smtp_stage", "QUEUED")
    empirical = compute_empirical_verdict(analytic, stage, landed=landed, auth=auth)
    evidence["empirical_verdict"] = empirical
    mc = evidence.get("manual_confirmation") or {}
    mc["landed"] = landed
    mc["authentication_results"] = auth_results
    mc["parsed_auth"] = auth
    evidence["manual_confirmation"] = mc
    with open(path, "w") as f:
        json.dump(evidence, f, ensure_ascii=False, indent=2)
    return empirical
```

Em `main`, logo após `args = parse_args(argv)` (antes de qualquer uso de `domain`), adicione o dispatch:

```python
    if args.finalize:
        auth_results = args.auth_results
        if args.auth_results_file:
            try:
                with open(args.auth_results_file) as f:
                    auth_results = f.read()
            except OSError as e:
                print(f"  [!] Não foi possível ler --auth-results-file: {e}")
                return 2
        if not auth_results or not args.landed:
            print("  [!] --finalize requer --auth-results/--auth-results-file e --landed.")
            return 2
        empirical = finalize_evidence(args.finalize, auth_results, args.landed)
        print(f"  [VERDITO EMPÍRICO] {empirical['status']} — {empirical['impact_en']}")
        return 0

    if not args.domain:
        print("  [!] Informe o domínio alvo (ou use --finalize DIR).")
        return 2
```

Como `main` faz `domain = args.domain` logo depois, e agora `args.domain` pode ser `None`, o guard acima garante o retorno antes disso no caminho não-finalize.

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_email_spoof.py -q`
Expected: PASS (suíte inteira)

- [ ] **Step 5: Commit**

```bash
git add email_spoof_poc.py tests/test_email_spoof.py
git commit -m "feat(spoof): modo --finalize fecha a prova com Authentication-Results

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 7: Validação final (suíte + compile + smoke dry-run)

**Files:** nenhuma alteração — verificação.

- [ ] **Step 1: Suíte completa de spoof**

Run: `python3 -m pytest tests/test_email_spoof.py -q`
Expected: PASS (todas)

- [ ] **Step 2: Compile**

Run: `python3 -m py_compile email_spoof_poc.py`
Expected: sem saída (sucesso)

- [ ] **Step 3: Smoke dry-run (sem rede de envio)**

Run: `python3 email_spoof_poc.py example.com --dry-run --to x@test.com --outdir /tmp/spoof_smoke`
Expected: imprime verdito analítico + `[DRY-RUN]` e grava `/tmp/spoof_smoke/spoof_evidence.json`. (Faz consultas DNS reais a `example.com` via `dig`; não envia email.)

- [ ] **Step 4: Smoke finalize (offline)**

Run:
```bash
python3 email_spoof_poc.py --finalize /tmp/spoof_smoke \
  --auth-results "dmarc=fail spf=softfail dkim=none" --landed inbox
```
Expected: imprime `[VERDITO EMPÍRICO] ...` (o dry-run não cria `send`, então `stage` cai no default `QUEUED` → verdito `SPOOF_PROVEN_INBOX`). Confirma que o modo finalize roda fim-a-fim. Limpe depois: `rm -rf /tmp/spoof_smoke`.

- [ ] **Step 5: Commit (se houver ajuste)**

Se algum ajuste foi necessário nos Steps acima, commite; caso contrário, nada a fazer.

---

## Notas de execução real (pós-implementação)

Para o teste real contra o domínio alvo (fora deste plano, executado pelo operador):
- Use `--smtp <relay>:<porta>` com um relay que **preserve** o `From:` forjado (SMTP próprio com rDNS/boa reputação). Relays gerenciados invalidam a prova.
- Senha do relay via `STIGLITZ_SMTP_PASS` (não em `--smtp-pass`, evita exposição em `ps`/history).
- Outputs em `spoof_poc_*/` são gitignored — nunca versionar.

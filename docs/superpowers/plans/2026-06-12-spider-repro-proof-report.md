# Bloco "How to Reproduce / Proof" — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Adicionar ao relatório do scan um bloco padronizado, por finding confirmado/High/Critical, com passos de reprodução, comando copiável e resultado esperado — sanitizando segredos e PAN/PII por padrão.

**Architecture:** Novo módulo puro `lib/repro.py` (gate, sanitização, captura, templates, montagem do bloco e do HTML, CLI), consumido pelo `stiglitz_report.py`. O HTML do painel vive em `repro.render_panel_html()` (puro/testável) porque `stiglitz_report.py` executa código no import e não é importável em teste; o report apenas embute o resultado. Flag `--repro-raw` (env `STIGLITZ_REPRO_RAW=1`) desliga a sanitização para uso interno. Reusa `pan_scanner` e `pii_detect`.

**Tech Stack:** Python 3 (stdlib: `re`, `json`, `html`), pytest, bash; convenção do repo (módulo puro + CLI em `lib/`, igual a `bola.py`/`dast_prep.py`).

**Refinamento vs spec:** o spec disse "stiglitz_report.py renderiza o painel"; aqui a geração do HTML fica em `repro.render_panel_html()` (testável) e o report apenas a embute. Mesmo resultado visual, melhor testabilidade.

---

### Task 1: Esqueleto de `lib/repro.py` + `passes_gate`

**Files:**
- Create: `lib/repro.py`
- Test: `tests/test_repro.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_repro.py
import os, sys, json
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
import repro as R


def test_gate_high_and_critical_pass():
    assert R.passes_gate({"severity": "high"}) is True
    assert R.passes_gate({"severity": "critical"}) is True


def test_gate_confirmed_category_passes():
    assert R.passes_gate({"severity": "low", "confirmed_category": "exploit"}) is True
    assert R.passes_gate({"severity": "info", "confirmed_category": "verified"}) is True


def test_gate_confirmed_bool_passes():
    assert R.passes_gate({"severity": "low", "confirmed": True}) is True


def test_gate_info_low_without_confirmation_fail():
    assert R.passes_gate({"severity": "info"}) is False
    assert R.passes_gate({"severity": "low"}) is False
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_repro.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'repro'`

- [ ] **Step 3: Write minimal implementation**

```python
#!/usr/bin/env python3
"""
repro.py — gera o bloco "How to Reproduce / Proof" por finding (item 6 fintech).

Núcleo puro (sem rede): decide se o finding entra (passes_gate), extrai/monta o
comando de reprodução (captura real do curl/HTTP request, senão template por classe),
sanitiza segredos vivos e PAN/PII por padrão, descreve o resultado esperado (prova) e
monta o HTML do painel. Texto do bloco em INGLÊS (deliverable); console/comentários PT-BR.

Uso (debug): python3 lib/repro.py <finding.json>
"""
import os
import re
import sys
import json
import html

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pan_scanner
import pii_detect


# ── Gate de alcance ───────────────────────────────────────────────────────────
_HIGH_SEVS = {"critical", "high"}
_CONFIRMED_CATS = {"exploit", "verified"}


def passes_gate(finding):
    """True se o finding deve receber o bloco: High/Critical OU confirmado."""
    sev = str(finding.get("severity", "")).strip().lower()
    if sev in _HIGH_SEVS:
        return True
    if str(finding.get("confirmed_category", "")).strip().lower() in _CONFIRMED_CATS:
        return True
    return bool(finding.get("confirmed"))
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_repro.py -q`
Expected: PASS (4 passed)

- [ ] **Step 5: Commit**

```bash
git add lib/repro.py tests/test_repro.py
git commit -m "feat(repro): módulo lib/repro.py + passes_gate (gate confirmado/High/Critical)"
```

---

### Task 2: Sanitização (`sanitize_text`/`sanitize_command`)

**Files:**
- Modify: `lib/repro.py`
- Test: `tests/test_repro.py`

- [ ] **Step 1: Write the failing test** (append to `tests/test_repro.py`)

```python
def test_sanitize_redacts_bearer():
    out, changed = R.sanitize_text("curl -H 'Authorization: Bearer eyJabc.def-123'")
    assert "eyJabc.def-123" not in out
    assert "<TOKEN_A>" in out
    assert changed is True


def test_sanitize_redacts_cookie():
    out, changed = R.sanitize_text("Cookie: session=deadbeef; other=1")
    assert "deadbeef" not in out
    assert "<SESSION>" in out
    assert changed is True


def test_sanitize_redacts_querystring_token():
    out, _ = R.sanitize_text("https://t/cb?code=SECRETCODE&state=x")
    assert "SECRETCODE" not in out


def test_sanitize_masks_valid_pan():
    out, changed = R.sanitize_text("card 4111111111111111 here")
    assert "4111111111111111" not in out
    assert "411111******1111" in out
    assert changed is True


def test_sanitize_masks_valid_cpf():
    out, changed = R.sanitize_text("cpf 529.982.247-25")
    assert "529.982.247-25" not in out
    assert changed is True


def test_sanitize_masks_email():
    out, changed = R.sanitize_text("contact joao.silva@acme.com now")
    assert "joao.silva@acme.com" not in out
    assert "@acme.com" in out
    assert changed is True


def test_sanitize_noop_returns_unchanged():
    out, changed = R.sanitize_text("nothing sensitive here")
    assert out == "nothing sensitive here"
    assert changed is False
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_repro.py -k sanitize -q`
Expected: FAIL — `AttributeError: module 'repro' has no attribute 'sanitize_text'`

- [ ] **Step 3: Write minimal implementation** (append to `lib/repro.py`)

```python
# ── Sanitização ───────────────────────────────────────────────────────────────
_BEARER_RE = re.compile(r"(?i)(authorization\s*:\s*bearer\s+)([A-Za-z0-9._~+/\-]+=*)")
_COOKIE_RE = re.compile(r"(?i)((?:set-)?cookie\s*:\s*)([^\r\n]+)")
_QS_TOKEN_RE = re.compile(
    r"(?i)\b(access_token|refresh_token|id_token|client_secret|code|token)=([^&\s'\"]+)")
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_CPF_RE = re.compile(r"\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b")
_CNPJ_RE = re.compile(r"\b\d{2}\.?\d{3}\.?\d{3}/?\d{4}-?\d{2}\b")


def _mask_pans(text):
    changed = {"v": False}

    def _repl(m):
        pan = m.group(0)
        if pan_scanner.luhn(pan):
            changed["v"] = True
            return pan_scanner.mask(pan)
        return pan

    return pan_scanner.PAN_RE.sub(_repl, text), changed["v"]


def sanitize_text(text):
    """Redige segredos vivos e mascara PAN/PII. Retorna (texto, alterado?)."""
    if not text:
        return text, False
    changed = False
    for rx, repl in ((_BEARER_RE, r"\1<TOKEN_A>"),
                     (_COOKIE_RE, r"\1<SESSION>"),
                     (_QS_TOKEN_RE, r"\1=<REDACTED>")):
        new = rx.sub(repl, text)
        if new != text:
            changed = True
            text = new
    text, pan_changed = _mask_pans(text)
    changed = changed or pan_changed

    def _cpf_repl(m):
        if pii_detect.valid_cpf(m.group(0)):
            _cpf_repl.hit = True
            return "***.***.***-**"
        return m.group(0)
    _cpf_repl.hit = False
    text = _CPF_RE.sub(_cpf_repl, text)

    def _cnpj_repl(m):
        if pii_detect.valid_cnpj(m.group(0)):
            _cnpj_repl.hit = True
            return "**.***.***/****-**"
        return m.group(0)
    _cnpj_repl.hit = False
    text = _CNPJ_RE.sub(_cnpj_repl, text)

    def _email_repl(m):
        masked = pii_detect.mask_email(m.group(0))
        if masked != m.group(0):
            _email_repl.hit = True
        return masked
    _email_repl.hit = False
    text = _EMAIL_RE.sub(_email_repl, text)

    changed = changed or _cpf_repl.hit or _cnpj_repl.hit or _email_repl.hit
    return text, changed


def sanitize_command(text):
    """Mesma política de sanitize_text (alias semântico para comandos)."""
    return sanitize_text(text)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_repro.py -k sanitize -q`
Expected: PASS (7 passed)

- [ ] **Step 5: Commit**

```bash
git add lib/repro.py tests/test_repro.py
git commit -m "feat(repro): sanitização de Bearer/cookie/token + PAN/PII (reusa pan_scanner/pii_detect)"
```

---

### Task 3: Captura do comando real (`_command_from_curl_field`, `_curl_from_request_block`)

**Files:**
- Modify: `lib/repro.py`
- Test: `tests/test_repro.py`

- [ ] **Step 1: Write the failing test** (append to `tests/test_repro.py`)

```python
def test_command_from_curl_field_priority():
    assert R._command_from_curl_field({"curl_command": "A", "curl": "B"}) == "A"
    assert R._command_from_curl_field({"curl": "B"}) == "B"
    assert R._command_from_curl_field({}) is None


def test_curl_from_request_block_parses():
    ev = "--- HTTP REQUEST ---\nGET /api/v1/users/123 HTTP/1.1\nHost: t.com\nAccept: */*\n\n"
    cmd = R._curl_from_request_block(ev, "")
    assert "curl" in cmd and "-X GET" in cmd
    assert "https://t.com/api/v1/users/123" in cmd
    assert "Accept: */*" in cmd


def test_curl_from_request_block_none_when_absent():
    assert R._curl_from_request_block("no block here", "") is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_repro.py -k curl_from_request -q`
Expected: FAIL — `AttributeError: module 'repro' has no attribute '_curl_from_request_block'`

- [ ] **Step 3: Write minimal implementation** (append to `lib/repro.py`)

```python
# ── Captura do comando real ───────────────────────────────────────────────────
_CURL_FIELDS = ("curl_command", "curl_reproducible", "curl-command", "curl")
_REQ_BLOCK_RE = re.compile(
    r"---\s*HTTP REQUEST\s*---\s*\n(.*?)(?=\n---|\Z)", re.DOTALL | re.IGNORECASE)


def _command_from_curl_field(finding):
    """Primeiro campo de curl não-vazio do finding, ou None."""
    for k in _CURL_FIELDS:
        v = finding.get(k)
        if v and str(v).strip():
            return str(v).strip()
    return None


def _curl_from_request_block(evidence, url=""):
    """Monta um curl a partir do bloco '--- HTTP REQUEST ---' da evidence, ou None."""
    m = _REQ_BLOCK_RE.search(evidence or "")
    if not m:
        return None
    lines = m.group(1).strip().splitlines()
    if not lines:
        return None
    parts = lines[0].split()
    method = parts[0] if parts else "GET"
    path = parts[1] if len(parts) > 1 else "/"
    host = ""
    headers = []
    body_lines = []
    in_body = False
    for ln in lines[1:]:
        if not in_body and ln.strip() == "":
            in_body = True
            continue
        if in_body:
            body_lines.append(ln)
            continue
        if ":" in ln:
            hk, _, hv = ln.partition(":")
            if hk.strip().lower() == "host":
                host = hv.strip()
            else:
                headers.append((hk.strip(), hv.strip()))
    full_url = url or (("https://" + host + path) if host else path)
    cmd = "curl -i -s -X %s '%s'" % (method, full_url)
    for hk, hv in headers:
        cmd += " \\\n  -H '%s: %s'" % (hk, hv)
    body = "\n".join(body_lines).strip()
    if body:
        cmd += " \\\n  --data '%s'" % body.replace("'", "'\\''")
    return cmd
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_repro.py -k curl -q`
Expected: PASS (2 passed)

- [ ] **Step 5: Commit**

```bash
git add lib/repro.py tests/test_repro.py
git commit -m "feat(repro): captura do comando (campos curl + parser do bloco HTTP REQUEST)"
```

---

### Task 4: Classificação + templates de fallback (`_classify`, `CLASS_TEMPLATES`)

**Files:**
- Modify: `lib/repro.py`
- Test: `tests/test_repro.py`

- [ ] **Step 1: Write the failing test** (append to `tests/test_repro.py`)

```python
def test_classify_known_classes():
    assert R._classify({"vuln_type": "sqli"}) == "sqli"
    assert R._classify({"cve": "CWE-639", "name": "IDOR"}) == "bola_idor"
    assert R._classify({"name": "GraphQL introspection enabled"}) == "graphql_introspection"


def test_classify_unknown_is_generic():
    assert R._classify({"vuln_type": "zzz-unmapped"}) == "generic"


def test_class_templates_have_required_keys():
    for cls, tpl in R.CLASS_TEMPLATES.items():
        assert set(tpl) >= {"prerequisites", "steps", "command", "expected"}
        assert tpl["steps"] and tpl["command"] and tpl["expected"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_repro.py -k classify -q`
Expected: FAIL — `AttributeError: module 'repro' has no attribute '_classify'`

- [ ] **Step 3: Write minimal implementation** (append to `lib/repro.py`)

```python
# ── Classificação e templates de fallback ─────────────────────────────────────
def _classify(finding):
    """Deriva a classe de reprodução a partir de cve/vuln_type/name/source/template."""
    blob = " ".join(str(finding.get(k, "")) for k in (
        "cve", "vuln_type", "type", "name", "other", "id", "source",
        "template_id")).lower()
    if "sql" in blob:
        return "sqli"
    if "bola" in blob or "idor" in blob or "cwe-639" in blob:
        return "bola_idor"
    if "bfla" in blob or "function level" in blob:
        return "bfla"
    if "ssrf" in blob or "cwe-918" in blob:
        return "ssrf"
    if "ssti" in blob:
        return "ssti"
    if "xss" in blob or "cwe-79" in blob:
        return "xss"
    if "introspection" in blob or "graphql" in blob:
        return "graphql_introspection"
    if "redirect_uri" in blob or "open redirect" in blob or "cwe-601" in blob:
        return "oauth_redirect_uri"
    if "auth" in blob and ("bypass" in blob or "default" in blob):
        return "auth_bypass"
    if "header" in blob and ("missing" in blob or "security" in blob):
        return "missing_security_header"
    if "tls" in blob or "ssl" in blob or "cipher" in blob or "certificate" in blob:
        return "tls_weak"
    return "generic"


CLASS_TEMPLATES = {
    "bola_idor": {
        "prerequisites": "Two accounts (user A and user B); a valid session token for user A.",
        "steps": [
            "Authenticate as user A and capture a request returning an object you own (note the object id).",
            "Replace the object id in the path/parameter with an id belonging to user B.",
            "Replay the request using user A's token.",
        ],
        "command": "curl -i -s '<TARGET>/<endpoint>/<OTHER_USER_ID>' \\\n  -H 'Authorization: Bearer <TOKEN_A>'",
        "expected": "HTTP 200 returning user B's data with user A's token proves Broken Object Level Authorization (BOLA/IDOR).",
    },
    "bfla": {
        "prerequisites": "A low-privilege account token and the path of a privileged function.",
        "steps": [
            "Identify an administrative/privileged endpoint from the documentation or crawl.",
            "Call it using the low-privilege account token.",
        ],
        "command": "curl -i -s -X POST '<TARGET>/<admin_endpoint>' \\\n  -H 'Authorization: Bearer <LOW_PRIV_TOKEN>'",
        "expected": "The privileged action succeeds with a low-privilege token, proving Broken Function Level Authorization (BFLA).",
    },
    "sqli": {
        "prerequisites": "A parameter reachable by the captured request.",
        "steps": [
            "Send the parameter with a benign boolean payload (e.g. ' OR '1'='1).",
            "Compare the response with a false condition (e.g. ' OR '1'='2).",
        ],
        "command": "curl -i -s \"<TARGET>/<endpoint>?id=1'%20OR%20'1'='1\"",
        "expected": "A measurable, condition-dependent difference (rows, length, timing) between the true and false payloads proves SQL injection.",
    },
    "xss": {
        "prerequisites": "A reflected/stored parameter and a browser to render the response.",
        "steps": [
            "Inject a unique marker payload into the parameter.",
            "Render the response and confirm the marker executes as script.",
        ],
        "command": "curl -i -s \"<TARGET>/<endpoint>?q=<svg/onload=alert(1)>\"",
        "expected": "The payload is reflected unencoded and executes in the browser context, proving Cross-Site Scripting.",
    },
    "ssrf": {
        "prerequisites": "An out-of-band listener (e.g. interactsh/Collaborator URL).",
        "steps": [
            "Set the URL/host parameter to your OOB listener address.",
            "Send the request and watch the listener for an inbound callback.",
        ],
        "command": "curl -i -s '<TARGET>/<endpoint>?url=http://<OOB_LISTENER>/'",
        "expected": "An inbound request from the target to the OOB listener proves Server-Side Request Forgery.",
    },
    "ssti": {
        "prerequisites": "A parameter reflected into a server-side template.",
        "steps": [
            "Inject a template arithmetic payload into the parameter.",
            "Confirm the server evaluates it.",
        ],
        "command": "curl -i -s '<TARGET>/<endpoint>?name={{7*7}}'",
        "expected": "The response contains 49 (evaluated expression), proving Server-Side Template Injection.",
    },
    "oauth_redirect_uri": {
        "prerequisites": "A registered client_id for the authorization endpoint.",
        "steps": [
            "Build an authorization request with redirect_uri pointing to an attacker-controlled host.",
            "Open the URL and observe whether the server redirects there with a code/token.",
        ],
        "command": "curl -i -s '<TARGET>/authorize?client_id=<CLIENT_ID>&response_type=code&redirect_uri=https://attacker.example/cb'",
        "expected": "The server accepts the unregistered redirect_uri and forwards the authorization code, proving an open redirect / token leak (CWE-601).",
    },
    "graphql_introspection": {
        "prerequisites": "Network access to the GraphQL endpoint.",
        "steps": [
            "Send the introspection query to the GraphQL endpoint.",
            "Confirm the full schema (types/mutations) is returned.",
        ],
        "command": "curl -i -s '<TARGET>/graphql' \\\n  -H 'Content-Type: application/json' \\\n  --data '{\"query\":\"{ __schema { types { name } } }\"}'",
        "expected": "The endpoint returns the schema, exposing all types and mutations (introspection should be disabled in production).",
    },
    "auth_bypass": {
        "prerequisites": "The protected endpoint path.",
        "steps": [
            "Request the protected endpoint with no/invalid credentials, or with default credentials.",
            "Confirm access is granted.",
        ],
        "command": "curl -i -s '<TARGET>/<protected_endpoint>'",
        "expected": "The protected resource is served without valid authentication, proving an authentication bypass.",
    },
    "missing_security_header": {
        "prerequisites": "Network access to the target.",
        "steps": [
            "Request the resource and inspect the response headers.",
            "Confirm the security header is absent.",
        ],
        "command": "curl -sI '<TARGET>' | grep -iE 'strict-transport-security|content-security-policy|x-frame-options'",
        "expected": "The expected security header is missing from the response.",
    },
    "tls_weak": {
        "prerequisites": "openssl or testssl.sh available locally.",
        "steps": [
            "Negotiate the weak protocol/cipher against the host.",
            "Confirm the handshake succeeds.",
        ],
        "command": "echo | openssl s_client -connect <HOST>:443 -tls1_1 2>/dev/null | grep -E 'Protocol|Cipher'",
        "expected": "The handshake completes with the weak protocol/cipher, proving an insecure TLS configuration.",
    },
    "generic": {
        "prerequisites": "Network access to the target and the captured request below.",
        "steps": [
            "Send the request shown in the Command field to the target.",
            "Compare the response against the Expected Result to confirm the issue.",
        ],
        "command": "curl -i -s '<TARGET>/<endpoint>'",
        "expected": "The response reproduces the vulnerable behavior described in this finding.",
    },
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_repro.py -k "classify or templates" -q`
Expected: PASS (3 passed)

- [ ] **Step 5: Commit**

```bash
git add lib/repro.py tests/test_repro.py
git commit -m "feat(repro): classificação por classe + templates de fallback (foco fintech)"
```

---

### Task 5: Aviso non-destructive (`safe_note`)

**Files:**
- Modify: `lib/repro.py`
- Test: `tests/test_repro.py`

- [ ] **Step 1: Write the failing test** (append to `tests/test_repro.py`)

```python
def test_safe_note_for_money_url():
    note = R.safe_note({"url": "https://t/api/transfer", "name": "BOLA"}, "")
    assert note != ""


def test_safe_note_for_mutating_method():
    note = R.safe_note({"url": "https://t/api/x"}, "curl -i -s -X POST '<TARGET>'")
    assert note != ""


def test_no_safe_note_for_readonly_get():
    note = R.safe_note({"url": "https://t/api/profile", "name": "Missing header"},
                       "curl -sI '<TARGET>'")
    assert note == ""
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_repro.py -k safe_note -q`
Expected: FAIL — `AttributeError: module 'repro' has no attribute 'safe_note'`

- [ ] **Step 3: Write minimal implementation** (append to `lib/repro.py`)

```python
# ── Aviso non-destructive (movimentação de dinheiro / mutação) ────────────────
_MONEY_RE = re.compile(
    r"transfer|refund|withdraw|payout|payment|charge|deposit|"
    r"delete|create|update|remove", re.I)
_SAFE_NOTE = ("Non-destructive validation: prefer a staging environment, use an "
              "idempotency-key, or a read-only variant before replaying on production.")


def safe_note(finding, command=""):
    """Aviso non-destructive p/ classes de dinheiro/mutação; '' caso contrário."""
    blob = " ".join(str(finding.get(k, "")) for k in
                    ("url", "name", "vuln_type", "type"))
    m = re.search(r"-X\s+([A-Za-z]+)", command or "")
    method = m.group(1).upper() if m else ""
    if _MONEY_RE.search(blob) or method in ("POST", "PUT", "PATCH", "DELETE"):
        return _SAFE_NOTE
    return ""
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_repro.py -k safe_note -q`
Expected: PASS (3 passed)

- [ ] **Step 5: Commit**

```bash
git add lib/repro.py tests/test_repro.py
git commit -m "feat(repro): safe_note non-destructive p/ endpoints de dinheiro/mutação"
```

---

### Task 6: Orquestrador (`build_repro`)

**Files:**
- Modify: `lib/repro.py`
- Test: `tests/test_repro.py`

- [ ] **Step 1: Write the failing test** (append to `tests/test_repro.py`)

```python
def test_build_repro_none_when_gate_fails():
    assert R.build_repro({"severity": "info"}) is None


def test_build_repro_uses_captured_curl():
    f = {"severity": "high", "curl_command": "curl -i 'https://t/api'"}
    d = R.build_repro(f, raw=True)
    assert d["command"] == "curl -i 'https://t/api'"
    assert d["sanitized"] is False


def test_build_repro_builds_curl_from_request_block():
    ev = "--- HTTP REQUEST ---\nGET /api/v1/users/123 HTTP/1.1\nHost: t.com\n\n"
    d = R.build_repro({"severity": "high", "evidence": ev}, raw=True)
    assert "/api/v1/users/123" in d["command"]
    assert "t.com" in d["command"]


def test_build_repro_template_fallback():
    d = R.build_repro({"severity": "high", "vuln_type": "sqli"}, raw=True)
    assert d["command"] == R.CLASS_TEMPLATES["sqli"]["command"]
    assert d["expected"] == R.CLASS_TEMPLATES["sqli"]["expected"]
    assert d["steps"] == R.CLASS_TEMPLATES["sqli"]["steps"]


def test_build_repro_sanitizes_by_default():
    f = {"severity": "high", "curl_command": "curl -H 'Authorization: Bearer eyJsecret'"}
    d = R.build_repro(f)  # raw=False
    assert "eyJsecret" not in d["command"]
    assert d["sanitized"] is True


def test_build_repro_safe_note_on_money_endpoint():
    f = {"severity": "high", "url": "https://t/api/transfer", "vuln_type": "bola_idor"}
    d = R.build_repro(f, raw=True)
    assert d["safe_note"] != ""
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_repro.py -k build_repro -q`
Expected: FAIL — `AttributeError: module 'repro' has no attribute 'build_repro'`

- [ ] **Step 3: Write minimal implementation** (append to `lib/repro.py`)

```python
# ── Orquestrador ──────────────────────────────────────────────────────────────
def build_repro(finding, raw=False):
    """Bloco estruturado de reprodução, ou None se o finding não passa no gate."""
    if not passes_gate(finding):
        return None
    cls = _classify(finding)
    tpl = CLASS_TEMPLATES.get(cls, CLASS_TEMPLATES["generic"])
    captured = (_command_from_curl_field(finding)
                or _curl_from_request_block(finding.get("evidence", ""),
                                            finding.get("url", "")))
    command = captured or tpl["command"]
    sanitized = False
    if not raw:
        command, sanitized = sanitize_command(command)
    return {
        "prerequisites": tpl["prerequisites"],
        "steps": list(tpl["steps"]),
        "command": command,
        "expected": tpl["expected"],
        "sanitized": sanitized,
        "safe_note": safe_note(finding, command),
    }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_repro.py -k build_repro -q`
Expected: PASS (6 passed)

- [ ] **Step 5: Commit**

```bash
git add lib/repro.py tests/test_repro.py
git commit -m "feat(repro): build_repro (captura→template, sanitização por padrão, safe_note)"
```

---

### Task 7: HTML do painel (`render_panel_html`) + CLI

**Files:**
- Modify: `lib/repro.py`
- Test: `tests/test_repro.py`

- [ ] **Step 1: Write the failing test** (append to `tests/test_repro.py`)

```python
def test_render_panel_empty_when_gate_fails():
    assert R.render_panel_html({"severity": "info"}, raw=True) == ""


def test_render_panel_contains_sections():
    out = R.render_panel_html({"severity": "high", "vuln_type": "sqli"}, raw=True)
    assert "How to Reproduce / Proof" in out
    assert "Expected Result" in out
    assert "<pre" in out
    assert "<ol" in out


def test_render_panel_sanitized_badge_and_no_leak():
    f = {"severity": "high", "curl_command": "curl -H 'Authorization: Bearer eyJsecret'"}
    out = R.render_panel_html(f, raw=False)
    assert "values sanitized" in out
    assert "eyJsecret" not in out


def test_cli_outputs_json(tmp_path):
    import subprocess
    p = tmp_path / "f.json"
    p.write_text(json.dumps({"severity": "high", "vuln_type": "sqli"}))
    repro_py = os.path.join(os.path.dirname(__file__), "..", "lib", "repro.py")
    r = subprocess.run([sys.executable, repro_py, str(p)],
                       capture_output=True, text=True)
    assert r.returncode == 0
    data = json.loads(r.stdout)
    assert data["expected"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_repro.py -k "render_panel or cli" -q`
Expected: FAIL — `AttributeError: module 'repro' has no attribute 'render_panel_html'`

- [ ] **Step 3: Write minimal implementation** (append to `lib/repro.py`)

```python
# ── HTML do painel (EN, deliverable) ──────────────────────────────────────────
def render_panel_html(finding, raw=False):
    """HTML do painel 'How to Reproduce / Proof'; '' se o finding não passa no gate."""
    data = build_repro(finding, raw=raw)
    if not data:
        return ""
    esc = html.escape
    steps = "".join("<li>%s</li>" % esc(s) for s in data["steps"])
    out = ['<div class="repro-box" style="margin:10px 0;padding:12px 14px;'
           'border-left:4px solid #2d6cdf;background:#f4f7fc;border-radius:4px">',
           '<strong style="color:#1b3a6b">How to Reproduce / Proof</strong>']
    if data["sanitized"]:
        out.append('<span style="background:#2d6cdf;color:#fff;padding:1px 7px;'
                   'border-radius:3px;font-size:10px;margin-left:8px">values sanitized</span>')
    if data["prerequisites"]:
        out.append('<p style="margin:8px 0 2px"><em>Prerequisites:</em> %s</p>'
                   % esc(data["prerequisites"]))
    out.append('<ol style="margin:6px 0 6px 18px">%s</ol>' % steps)
    out.append('<p style="margin:6px 0 2px"><em>Command:</em></p>')
    out.append('<pre class="evidence-box">%s</pre>' % esc(data["command"]))
    out.append('<p style="margin:6px 0 2px"><em>Expected Result (Proof):</em> %s</p>'
               % esc(data["expected"]))
    if data["safe_note"]:
        out.append('<p style="margin:6px 0 0;color:#8a6d00"><em>&#9888; %s</em></p>'
                   % esc(data["safe_note"]))
    out.append('</div>')
    return "".join(out)


# ── CLI (debug) ───────────────────────────────────────────────────────────────
def main(path):
    with open(path, encoding="utf-8") as fh:
        finding = json.load(fh)
    result = build_repro(finding, raw=os.environ.get("STIGLITZ_REPRO_RAW") == "1")
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("uso: python3 lib/repro.py <finding.json>", file=sys.stderr)
        sys.exit(2)
    main(sys.argv[1])
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_repro.py -q`
Expected: PASS (all tests, ~28 passed)

- [ ] **Step 5: Commit**

```bash
git add lib/repro.py tests/test_repro.py
git commit -m "feat(repro): render_panel_html (HTML EN) + CLI de debug"
```

---

### Task 8: Integração no `stiglitz_report.py`

**Files:**
- Modify: `stiglitz_report.py:31` (imports), `stiglitz_report.py:1304` (injeção), `stiglitz_report.py:1313-1316` (return)

- [ ] **Step 1: Add the import and REPRO_RAW flag**

Após a linha 31 (`from report_helpers import inject_cve_signals  # noqa: E402`), inserir:

```python
try:
    import repro  # noqa: E402
except Exception:
    repro = None
REPRO_RAW = os.environ.get("STIGLITZ_REPRO_RAW") == "1"
```

- [ ] **Step 2: Inject confirmed_category before the repro call**

Em `render_finding`, logo após `_cat = _confirmed_category(f)` (linha 1304), inserir:

```python
    f["confirmed_category"] = _cat
```

- [ ] **Step 3: Embed the panel in the return**

Substituir o `return` de `render_finding` (linhas 1313-1316) por:

```python
    repro_panel = repro.render_panel_html(f, raw=REPRO_RAW) if repro else ""
    return f'''<div class="vuln {f['severity']}">
  <h3>{html.escape(f.get('name',''))} <span class="source-badge {src_cls}">{f.get('source','')}</span> {badge(f['severity'])}{reclassify_badge}{confirmed_badge}</h3>
  <table>{rows}
  </table>{repro_panel}</div>'''
```

- [ ] **Step 4: Verify compile + integration hooks present**

Run:
```bash
python3 -m py_compile stiglitz_report.py
grep -n "import repro" stiglitz_report.py
grep -n 'f\["confirmed_category"\] = _cat' stiglitz_report.py
grep -n "repro.render_panel_html" stiglitz_report.py
```
Expected: `py_compile` sem erro; os três `grep` retornam uma linha cada.

- [ ] **Step 5: Smoke — render against any existing scan dir (se houver)**

Run (substitua `<scan_dir>` por um diretório de scan existente, se disponível; senão pule este passo):
```bash
OUTDIR=<scan_dir> TARGET=https://example.com DOMAIN=example.com python3 stiglitz_report.py && \
  grep -c "How to Reproduce / Proof" <scan_dir>/stiglitz_report.html
```
Expected: relatório gerado; contagem ≥ 0 (≥ 1 se o scan tiver finding confirmado/High/Critical). A cobertura completa do caminho HTML roda no CI via `test_integration.py` (scan real do Juice Shop).

- [ ] **Step 6: Commit**

```bash
git add stiglitz_report.py
git commit -m "feat(report): embute painel How to Reproduce/Proof por finding (confirmado/High/Critical)"
```

---

### Task 9: Flag `--repro-raw` no `stiglitz.sh`

**Files:**
- Modify: `stiglitz.sh:289` (default), `stiglitz.sh:295-307` (parser), `stiglitz.sh:~2522` (export antes da P11)

- [ ] **Step 1: Add the default near OAUTH_ACTIVE**

Após a linha 289 (`OAUTH_ACTIVE=0     # Probes ativos OAuth/OIDC (P9.6) — opt-in via --oauth-active`), inserir:

```bash
REPRO_RAW=0        # Bloco de repro sem sanitização (uso interno) — opt-in via --repro-raw
```

- [ ] **Step 2: Add the case branch in the arg parser**

No bloco `case`, após `--bizlogic-mutate)   BIZLOGIC_MUTATE=1 ;;`, inserir:

```bash
        --repro-raw)         REPRO_RAW=1 ;;
```

- [ ] **Step 3: Export before the P11 report invocation**

Imediatamente antes da linha `if [ -f "$_report_py" ]; then` (≈ linha 2522), inserir:

```bash
export STIGLITZ_REPRO_RAW="$REPRO_RAW"
```

- [ ] **Step 4: Verify syntax, lint and hooks**

Run:
```bash
bash -n stiglitz.sh
shellcheck --severity=warning stiglitz.sh
grep -n "REPRO_RAW=0" stiglitz.sh
grep -n -- "--repro-raw)" stiglitz.sh
grep -n 'export STIGLITZ_REPRO_RAW' stiglitz.sh
```
Expected: `bash -n` sem saída; `shellcheck` sem novos warnings; cada `grep` retorna uma linha.

- [ ] **Step 5: Commit**

```bash
git add stiglitz.sh
git commit -m "feat(scan): flag --repro-raw → STIGLITZ_REPRO_RAW (desliga sanitização do repro)"
```

---

### Task 10: Validação final + documentação

**Files:**
- Modify: `CLAUDE.md` (tabela de módulos `lib/`)

- [ ] **Step 1: Run the full project gates**

Run:
```bash
python3 -m py_compile stiglitz_report.py lib/repro.py
python3 -m pytest tests/test_repro.py -q
bash -n stiglitz.sh
shellcheck --severity=warning stiglitz.sh
```
Expected: tudo passa, sem erros nem novos warnings.

- [ ] **Step 2: Document repro.py in the CLAUDE.md lib table**

Na tabela de módulos `lib/` do `CLAUDE.md`, adicionar a linha (após `takeover.py`):

```markdown
| `repro.py` | Bloco "How to Reproduce / Proof" do relatório (item 6): gate (confirmado/High/Critical), captura do comando real (curl/HTTP request) com fallback de template por classe, sanitização de Bearer/cookie/PAN/PII por padrão (`--repro-raw` desliga), `safe_note` non-destructive p/ endpoints de dinheiro, e `render_panel_html` (EN). Lógica pura + CLI; reusa `pan_scanner`/`pii_detect` |
```

- [ ] **Step 3: Commit**

```bash
git add CLAUDE.md
git commit -m "docs: registra lib/repro.py na tabela de módulos (item 6 fintech)"
```

---

## Self-Review

**Spec coverage:**
- Fonte híbrida (captura→template) → Tasks 3, 4, 6. ✓
- Sanitização por padrão + `--repro-raw` → Tasks 2, 6, 9. ✓
- Alcance confirmados+High/Critical → Task 1 (`passes_gate`) + Task 8 (injeção de `confirmed_category`). ✓
- `safe_note` non-destructive → Task 5. ✓
- Campos do bloco (Prerequisites/Steps/Command/Expected/safe_note/sanitized) → Tasks 6, 7. ✓
- Integração no report + flag no scan → Tasks 8, 9. ✓
- Testes TDD + gates → todas as tasks + Task 10. ✓
- Idioma EN no bloco → Task 4 (templates) e Task 7 (HTML). ✓

**Type consistency:** `build_repro` retorna dict com chaves `prerequisites/steps/command/expected/sanitized/safe_note`; `render_panel_html`, os testes e a CLI usam exatamente essas chaves. `passes_gate`, `sanitize_text/sanitize_command`, `_classify`, `CLASS_TEMPLATES`, `safe_note`, `_command_from_curl_field`, `_curl_from_request_block` mantêm a mesma assinatura entre definição, testes e uso. ✓

**Placeholders:** nenhum `<TARGET>`/`<id>` é placeholder de plano — são placeholders **de conteúdo** dos templates (intencionais, exibidos ao validador). Nenhum `TBD`/`TODO` no plano. ✓

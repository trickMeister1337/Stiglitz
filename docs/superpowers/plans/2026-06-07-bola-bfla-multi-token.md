# BOLA/BFLA multi-token (OWASP API #1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Detectar BOLA/IDOR e BFLA (OWASP API #1) no `stiglitz.sh` reproduzindo requisições reais gravadas pelo ZAP com dois tokens (`--token-a`/`--token-b`), confirmando acesso indevido por tripla A/B/unauth + canário de corpo.

**Architecture:** Lógica pura e testável em `lib/bola.py` (parse do ZAP → filtro de candidatos com object-ref → canário → máquina de estados `verdict` → `build_findings`), com orquestração de rede fina (`replay`/`run`) injetável para teste. O `stiglitz.sh` ganha a fase **P9.5 Access Control**: a P9 crawla como A, a P9.5 faz spider-only como B, exporta os dois message histories e invoca o módulo. Reusa `response_diff`/`normalize` (`poc_validator.py`), classes do `vuln_catalog.py` e `fingerprint.py`.

**Tech Stack:** Python 3 (stdlib: `json`, `re`, `urllib`, `subprocess`), pytest, bash. Ferramentas externas: ZAP (já na P9), `curl`. Tokens via env `BOLA_TOKEN_A`/`BOLA_TOKEN_B`.

---

## Referências de assinaturas reais (do código atual)

- `lib/fingerprint.py`: `fingerprint(finding)` → 16 hex de `(vuln_class, host, path-template, param)`. `vuln_class` lê `cwe`/`cve` (regex CWE), senão `type`/`name`. `normalize_path(url)` templatiza `/user/1 → /user/{id}`. Usa `finding["url"]`, `finding.get("cwe")`, `finding.get("type")`, `finding.get("param")`.
- `lib/poc_validator.py`: `normalize(text)` (colapsa whitespace/normaliza); `response_diff(base_norm, payload_norm)` → `(changed: bool, score: int, note: str)`. **`changed=True` significa DIFERENTE**; corpos ≈ iguais → `changed=False`. `build_safe_baseline` retorna baseline sem auth (referência de implementação do replay unauth).
- `lib/vuln_catalog.py`: `CATALOG` dict classe→`{cwe, vector, title}`. Já tem `bola` (CWE-639), `idor_read_pii` (CWE-639), `idor_write` (CWE-639). **Não tem `bfla`** — Task 1 adiciona.
- `stiglitz.sh`: `AUTH_TOKEN` (linha ~247), parse de args (`--token|-t` linha ~258), injeção de Authorization no ZAP via `replacer/action/addRule` (linha ~1500), `core/action/accessUrl`, helper `zap_api_call`. `SCRIPT_DIR` já existe. Fase 9 = ZAP. Cores/log: `${GREEN}[✓]`, `${YELLOW}`, `${BLUE}[…]`.
- Convenção de testes: `tests/test_*.py`, `sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))`.
- Artefatos do scan vão no `OUTDIR` (gitignored) — nunca versionados. Testes usam `target.com` sintético.

---

## File Structure

- **Create `lib/bola.py`** — motor BOLA/BFLA: funções puras + orquestração de rede fina + CLI. Responsabilidade única: detectar autorização quebrada a partir de dois corpora ZAP.
- **Create `tests/test_bola.py`** — testes unitários das funções puras (sem rede; `run` testado com `replay_fn` injetado).
- **Modify `lib/vuln_catalog.py`** — adicionar entrada `bfla` (CWE-285).
- **Modify `stiglitz.sh`** — args `--token-a`/`--token-b` (+ `--token` apelido de A); fase P9.5 (spider-B, export de messages, chamada do módulo).
- **Modify `CLAUDE.md`** — registrar a fase P9.5 e `lib/bola.py`.

---

## Task 1: `vuln_catalog.py` — entrada `bfla` (CWE-285)

**Files:**
- Modify: `lib/vuln_catalog.py`
- Test: `tests/test_bola.py` (Create)

- [ ] **Step 1: Write the failing test**

```python
# tests/test_bola.py
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
import vuln_catalog


def test_catalog_has_bfla_entry():
    e = vuln_catalog.CATALOG["bfla"]
    assert e["cwe"] == "CWE-285"
    assert "AV:N" in e["vector"]
    assert e["title"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_bola.py -q`
Expected: FAIL — `KeyError: 'bfla'`

- [ ] **Step 3: Add the entry**

Em `lib/vuln_catalog.py`, dentro do dict `CATALOG`, logo após a entrada `"bola":` (linha ~16), adicionar:

```python
    "bfla":               {"cwe": "CWE-285", "title": "Broken Function Level Authorization",
                           "vector": "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"},
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_bola.py -q`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add lib/vuln_catalog.py tests/test_bola.py
git commit -m "feat(catalog): classe bfla — Broken Function Level Authorization (CWE-285) (P1)"
```

---

## Task 2: `lib/bola.py` — `parse_zap_messages`

**Files:**
- Create: `lib/bola.py`
- Test: `tests/test_bola.py`

- [ ] **Step 1: Write the failing test**

Adicionar a `tests/test_bola.py`:

```python
import bola as B


def test_parse_zap_messages_extracts_requests():
    dump = {
        "messages": [
            {"requestHeader": "GET /users/123 HTTP/1.1\r\nHost: t.com\r\nAuthorization: Bearer X\r\n\r\n",
             "requestBody": "",
             "responseHeader": "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n",
             "responseBody": '{"id":123,"email":"a@t.com"}'},
            {"requestHeader": "POST /login HTTP/1.1\r\nHost: t.com\r\n\r\n",
             "requestBody": "u=1", "responseHeader": "HTTP/1.1 302 Found\r\n\r\n",
             "responseBody": ""},
        ]
    }
    import json
    reqs = B.parse_zap_messages(json.dumps(dump))
    assert len(reqs) == 2
    r0 = reqs[0]
    assert r0["method"] == "GET"
    assert r0["url"].endswith("/users/123")
    assert r0["status"] == 200
    assert "email" in r0["resp_body"]
    assert reqs[1]["method"] == "POST"


def test_parse_zap_messages_ignores_garbage():
    assert B.parse_zap_messages("not json") == []
    assert B.parse_zap_messages('{"messages": "x"}') == []
    assert B.parse_zap_messages("") == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_bola.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'bola'`

- [ ] **Step 3: Write minimal implementation**

```python
# lib/bola.py
#!/usr/bin/env python3
"""
bola.py — detecção de BOLA/IDOR e BFLA (OWASP API #1) via replay multi-token (P1).

Reproduz requisições reais (gravadas pelo ZAP como token A/B) com a identidade do
outro usuário e confirma acesso indevido por tripla A/B/unauth + canário de corpo.
Lógica pura + CLI fina (replay de rede injetável p/ teste). Sem domínio hardcoded.
"""
import sys
import os
import re
import json
import urllib.parse

# Limiares ajustáveis (defaults conservadores — preferir FN a FP).
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
PRIVILEGED_PATH = re.compile(r"/(admin|internal|manage|console|root|sudo)\b", re.I)
_NUM_SEG = re.compile(r"/\d+(?=/|$)")
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)
_ID_PARAM = re.compile(r"(^|[?&])(id|user_id|account|uid|order|customer)=", re.I)
_EMAIL = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
_CPF = re.compile(r"\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b")


def _first_line(header):
    return (header or "").split("\r\n", 1)[0].split("\n", 1)[0]


def _status_of(resp_header):
    m = re.search(r"HTTP/\S+\s+(\d{3})", resp_header or "")
    return int(m.group(1)) if m else 0


def parse_zap_messages(json_text):
    """Lê o dump do core/view/messages do ZAP. Retorna lista de dicts
    {method, url, req_headers, req_body, status, resp_body}. Itens inválidos ignorados."""
    try:
        obj = json.loads(json_text or "")
    except Exception:
        return []
    msgs = obj.get("messages") if isinstance(obj, dict) else None
    if not isinstance(msgs, list):
        return []
    out = []
    for m in msgs:
        if not isinstance(m, dict):
            continue
        line = _first_line(m.get("requestHeader"))
        parts = line.split()
        if len(parts) < 2:
            continue
        method, target = parts[0].upper(), parts[1]
        out.append({
            "method": method,
            "url": target,
            "req_headers": m.get("requestHeader") or "",
            "req_body": m.get("requestBody") or "",
            "status": _status_of(m.get("responseHeader")),
            "resp_body": m.get("responseBody") or "",
        })
    return out
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_bola.py -q`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add lib/bola.py tests/test_bola.py
git commit -m "feat(bola): parse_zap_messages — extrai requests do dump do ZAP (P1)"
```

---

## Task 3: `is_object_ref_request` + `is_safe_method`

**Files:**
- Modify: `lib/bola.py`
- Test: `tests/test_bola.py`

- [ ] **Step 1: Write the failing test**

Adicionar a `tests/test_bola.py`:

```python
def test_is_object_ref_request_detects_object_handles():
    assert B.is_object_ref_request({"url": "/users/123"}) is True
    assert B.is_object_ref_request({"url": "/api/orders/42/items"}) is True
    assert B.is_object_ref_request(
        {"url": "/x?account=550e8400-e29b-41d4-a716-446655440000"}) is True
    assert B.is_object_ref_request({"url": "/profile?id=7"}) is True
    assert B.is_object_ref_request({"url": "/about"}) is False
    assert B.is_object_ref_request({"url": "/login"}) is False
    assert B.is_object_ref_request({"url": ""}) is False


def test_is_safe_method():
    assert B.is_safe_method("GET") is True
    assert B.is_safe_method("head") is True
    assert B.is_safe_method("OPTIONS") is True
    assert B.is_safe_method("POST") is False
    assert B.is_safe_method("DELETE") is False
    assert B.is_safe_method("") is False
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_bola.py -q`
Expected: FAIL — `AttributeError: module 'bola' has no attribute 'is_object_ref_request'`

- [ ] **Step 3: Implement**

Adicionar a `lib/bola.py`:

```python
def is_safe_method(method):
    """Só métodos idempotentes read-only são reproduzidos (segurança/RoE)."""
    return (method or "").strip().upper() in SAFE_METHODS


def is_object_ref_request(req):
    """True se a URL carrega referência a objeto (id numérico em path, UUID,
    ou param id/user_id/account/...). Sem object-ref, replay é ruído."""
    url = req.get("url") or ""
    split = urllib.parse.urlsplit(url)
    path, query = split.path or url, split.query or ""
    if _NUM_SEG.search(path):
        return True
    if _UUID.search(url):
        return True
    if _ID_PARAM.search("?" + query):
        return True
    return False
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_bola.py -q`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add lib/bola.py tests/test_bola.py
git commit -m "feat(bola): is_object_ref_request + is_safe_method — filtro de candidatos (P1)"
```

---

## Task 4: `extract_canary`

**Files:**
- Modify: `lib/bola.py`
- Test: `tests/test_bola.py`

- [ ] **Step 1: Write the failing test**

Adicionar a `tests/test_bola.py`:

```python
def test_extract_canary_pulls_ids_and_pii():
    body = '{"id":123,"email":"alice@target.com","name":"Alice","cpf":"123.456.789-09"}'
    can = B.extract_canary(body, "application/json")
    assert "alice@target.com" in can
    assert "123.456.789-09" in can
    assert "123" in can  # id


def test_extract_canary_empty_when_no_handles():
    assert B.extract_canary("<html><body>welcome</body></html>", "text/html") == set()
    assert B.extract_canary("", "application/json") == set()


def test_canary_is_pii_flags_email_cpf():
    assert B.canary_is_pii({"alice@target.com"}) is True
    assert B.canary_is_pii({"123.456.789-09"}) is True
    assert B.canary_is_pii({"123"}) is False
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_bola.py -q`
Expected: FAIL — `AttributeError: ... 'extract_canary'`

- [ ] **Step 3: Implement**

Adicionar a `lib/bola.py`:

```python
def extract_canary(resp_body, content_type=""):
    """Extrai identificadores do objeto do dono (o que se procura no corpo do
    cross-replay): emails, CPFs, e valores de campos id/uuid em JSON. Retorna set."""
    body = resp_body or ""
    canary = set()
    canary.update(_EMAIL.findall(body))
    canary.update(_CPF.findall(body))
    canary.update(_UUID.findall(body))
    # valores de campos "id"/"..._id" em JSON: "id": 123  ou  "user_id":"abc"
    for m in re.finditer(r'"(?:\w*_)?id"\s*:\s*"?([\w-]{1,64})"?', body, re.I):
        canary.add(m.group(1))
    return {c for c in canary if c}


def canary_is_pii(canary):
    """True se algum item do canário é PII (email/CPF) — vira idor_read_pii."""
    return any(_EMAIL.fullmatch(c) or _CPF.fullmatch(c) for c in canary)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_bola.py -q`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add lib/bola.py tests/test_bola.py
git commit -m "feat(bola): extract_canary + canary_is_pii — identificadores do objeto do dono (P1)"
```

---

## Task 5: `verdict` — máquina de estados de confirmação

**Files:**
- Modify: `lib/bola.py`
- Test: `tests/test_bola.py`

- [ ] **Step 1: Write the failing test**

Adicionar a `tests/test_bola.py`. Cada resposta é um dict `{status, body}`:

```python
OWNER = {"status": 200, "body": '{"id":123,"email":"alice@target.com"}'}


def test_verdict_protected_when_cross_denied():
    cross = {"status": 403, "body": "forbidden"}
    unauth = {"status": 401, "body": "no"}
    v = B.verdict(OWNER, cross, unauth, {"alice@target.com", "123"})
    assert v["state"] == "PROTECTED"


def test_verdict_public_when_unauth_sees_same_body():
    cross = {"status": 200, "body": OWNER["body"]}
    unauth = {"status": 200, "body": OWNER["body"]}   # qualquer um acessa
    v = B.verdict(OWNER, cross, unauth, {"alice@target.com", "123"})
    assert v["state"] == "PUBLIC"


def test_verdict_confirmed_when_cross_sees_owner_object():
    cross = {"status": 200, "body": OWNER["body"]}     # idêntico ao dono
    unauth = {"status": 401, "body": "no"}             # anônimo negado
    v = B.verdict(OWNER, cross, unauth, {"alice@target.com", "123"})
    assert v["state"] == "CONFIRMED"
    assert v["canary_hit"] is True
    assert v["confidence"] >= 85


def test_verdict_inconclusive_when_canary_absent():
    # cross vê 200 com MESMO template mas dados próprios (sem canário do dono)
    cross = {"status": 200, "body": '{"id":999,"email":"bob@target.com"}'}
    unauth = {"status": 401, "body": "no"}
    v = B.verdict(OWNER, cross, unauth, {"alice@target.com", "123"})
    assert v["state"] == "INCONCLUSIVE"
    assert v["canary_hit"] is False
    assert v["confidence"] < 60
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_bola.py -q`
Expected: FAIL — `AttributeError: ... 'verdict'`

- [ ] **Step 3: Implement**

Adicionar a `lib/bola.py` (importa helpers do `poc_validator`):

```python
try:
    from poc_validator import normalize as _normalize, response_diff as _response_diff
except Exception:  # fallback se importado fora do pacote lib/
    def _normalize(t):
        return re.sub(r"\s+", " ", (t or "")).strip()

    def _response_diff(a, b):
        return (a != b, 0, "")


def _is_2xx(status):
    return 200 <= int(status or 0) < 300


def _bodies_match(a, b):
    """True se os dois corpos são ≈ iguais (response_diff.changed == False)."""
    changed, _score, _note = _response_diff(_normalize(a), _normalize(b))
    return not changed


def _canary_hit(canary, body):
    body = body or ""
    return any(c and c in body for c in canary)


def verdict(baseline, cross, unauth, canary):
    """Máquina de estados de confirmação. baseline/cross/unauth: {status, body}.
    Retorna {state, canary_hit, confidence}.
      PROTECTED   — cross negado (401/403): autorização funciona.
      PUBLIC      — unauth 2xx com corpo ≈ baseline: recurso público (não é achado).
      CONFIRMED   — cross 2xx + corpo ≈ baseline + canário bate + unauth negado.
      INCONCLUSIVE— cross 2xx mas corpo difere ou canário não bate (baixa confiança).
    """
    c_status = int(cross.get("status") or 0)
    if c_status in (401, 403):
        return {"state": "PROTECTED", "canary_hit": False, "confidence": 0}

    unauth_open = _is_2xx(unauth.get("status")) and _bodies_match(
        baseline.get("body"), unauth.get("body"))
    if unauth_open:
        return {"state": "PUBLIC", "canary_hit": False, "confidence": 0}

    if not _is_2xx(c_status):
        return {"state": "INCONCLUSIVE", "canary_hit": False, "confidence": 20}

    hit = _canary_hit(canary, cross.get("body"))
    same = _bodies_match(baseline.get("body"), cross.get("body"))
    if hit and same:
        return {"state": "CONFIRMED", "canary_hit": True, "confidence": 90}
    return {"state": "INCONCLUSIVE", "canary_hit": hit, "confidence": 50 if same else 30}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_bola.py -q`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add lib/bola.py tests/test_bola.py
git commit -m "feat(bola): verdict — confirmação tripla A/B/unauth + canário (P1)"
```

---

## Task 6: `classify` + `build_findings`

**Files:**
- Modify: `lib/bola.py`
- Test: `tests/test_bola.py`

- [ ] **Step 1: Write the failing test**

Adicionar a `tests/test_bola.py`:

```python
def test_classify_picks_bfla_idor_bola():
    # path privilegiado → bfla
    assert B.classify({"url": "https://t.com/admin/users/1"}, {"x"}) == "bfla"
    # PII no canário → idor_read_pii
    assert B.classify({"url": "https://t.com/users/1"}, {"alice@target.com"}) == "idor_read_pii"
    # objeto sem PII → bola
    assert B.classify({"url": "https://t.com/orders/9"}, {"9"}) == "bola"


def test_build_findings_schema_and_fingerprint():
    results = [{
        "req": {"url": "https://t.com/users/123", "method": "GET"},
        "verdict": {"state": "CONFIRMED", "canary_hit": True, "confidence": 90},
        "canary": {"alice@target.com", "123"},
        "direction": "B->A",
    }]
    out = B.build_findings(results)
    assert len(out) == 1
    f = out[0]
    assert f["type"] == "idor_read_pii"
    assert f["cwe"] == "CWE-639"
    assert f["url"] == "https://t.com/users/123"
    assert f["confirmed"] is True
    assert f["severity"] == "high"
    assert f["direction"] == "B->A"
    assert len(f["fingerprint"]) == 16


def test_build_findings_skips_non_actionable():
    results = [
        {"req": {"url": "https://t.com/a/1"}, "verdict": {"state": "PROTECTED", "confidence": 0},
         "canary": set(), "direction": "B->A"},
        {"req": {"url": "https://t.com/a/2"}, "verdict": {"state": "PUBLIC", "confidence": 0},
         "canary": set(), "direction": "B->A"},
    ]
    assert B.build_findings(results) == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_bola.py -q`
Expected: FAIL — `AttributeError: ... 'classify'`

- [ ] **Step 3: Implement**

Adicionar a `lib/bola.py` (importa `fingerprint` e `vuln_catalog`):

```python
try:
    from fingerprint import fingerprint as _fingerprint
    from vuln_catalog import CATALOG as _CATALOG
except Exception:
    def _fingerprint(f):
        return "0" * 16
    _CATALOG = {}


def classify(req, canary):
    """Classe do finding: bfla (path privilegiado) > idor_read_pii (PII) > bola."""
    if PRIVILEGED_PATH.search(req.get("url") or ""):
        return "bfla"
    if canary_is_pii(canary):
        return "idor_read_pii"
    return "bola"


def build_findings(results):
    """Converte resultados CONFIRMED/INCONCLUSIVE em findings (schema findings.json).
    PROTECTED/PUBLIC são descartados. CONFIRMED → confirmed=True/severity high;
    INCONCLUSIVE → confirmed=False/severity info (triagem)."""
    findings = []
    for r in results:
        state = r["verdict"]["state"]
        if state not in ("CONFIRMED", "INCONCLUSIVE"):
            continue
        klass = classify(r["req"], r.get("canary") or set())
        cwe = _CATALOG.get(klass, {}).get("cwe", "")
        confirmed = state == "CONFIRMED"
        finding = {
            "type": klass,
            "cwe": cwe,
            "url": r["req"].get("url", ""),
            "param": "",
            "severity": "high" if confirmed else "info",
            "confirmed": confirmed,
            "confidence": r["verdict"].get("confidence", 0),
            "direction": r.get("direction", ""),
            "canary_hit": r["verdict"].get("canary_hit", False),
            "source": "bola",
            "poc_note": f"Access-control {state} via replay {r.get('direction','')}",
        }
        finding["fingerprint"] = _fingerprint(finding)
        findings.append(finding)
    return findings
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_bola.py -q`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add lib/bola.py tests/test_bola.py
git commit -m "feat(bola): classify + build_findings — classe/severidade/fingerprint (P1)"
```

---

## Task 7: `replay` + `run` (orquestração injetável) + CLI

**Files:**
- Modify: `lib/bola.py`
- Test: `tests/test_bola.py`

- [ ] **Step 1: Write the failing test**

Adicionar a `tests/test_bola.py`. `run` recebe um `replay_fn` injetável `(req, token) -> {status, body}` (token `None` = unauth), evitando rede:

```python
import json as _json


def _fake_replay_factory():
    # Simula: cross com token "B" vê o objeto do dono em /users/123 (BOLA);
    # unauth sempre negado; /about é público.
    def replay_fn(req, token):
        url = req["url"]
        if "/users/123" in url:
            if token is None:
                return {"status": 401, "body": "no"}
            return {"status": 200, "body": '{"id":123,"email":"alice@target.com"}'}
        return {"status": 404, "body": ""}
    return replay_fn


def test_run_confirms_bola_bidirectional(tmp_path):
    msgs_a = _json.dumps({"messages": [
        {"requestHeader": "GET /users/123 HTTP/1.1\r\nHost: t.com\r\n\r\n", "requestBody": "",
         "responseHeader": "HTTP/1.1 200 OK\r\n\r\n",
         "responseBody": '{"id":123,"email":"alice@target.com"}'},
    ]})
    msgs_b = _json.dumps({"messages": []})
    out = str(tmp_path)
    res = B.run(msgs_a, msgs_b, "tokA", "tokB", out, replay_fn=_fake_replay_factory())
    assert any(f["type"] == "idor_read_pii" and f["confirmed"] for f in res["findings"])
    assert os.path.exists(os.path.join(out, "access_control.json"))


def test_cli_run_returns_zero(tmp_path, monkeypatch, capsys):
    msgs_a = tmp_path / "a.json"
    msgs_a.write_text('{"messages": []}')
    msgs_b = tmp_path / "b.json"
    msgs_b.write_text('{"messages": []}')
    monkeypatch.setenv("BOLA_TOKEN_A", "x")
    monkeypatch.setenv("BOLA_TOKEN_B", "y")
    rc = B.main(["bola.py", "run", str(msgs_a), str(msgs_b), str(tmp_path)])
    assert rc == 0


def test_cli_unknown_command_returns_2():
    assert B.main(["bola.py", "bogus"]) == 2
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_bola.py -q`
Expected: FAIL — `AttributeError: ... 'run'`

- [ ] **Step 3: Implement**

Adicionar a `lib/bola.py`:

```python
def replay(req, token):
    """Reemite a requisição (só método seguro) trocando o header Authorization.
    token=None → sem auth. Retorna {status, body}. Usa curl (timeout/retry)."""
    import subprocess
    url = req.get("url") or ""
    method = (req.get("method") or "GET").upper()
    cmd = ["curl", "-s", "-S", "--max-time", "15", "-X", method,
           "-o", "-", "-w", "\n__HTTP_STATUS__:%{http_code}", url]
    if token:
        cmd += ["-H", f"Authorization: Bearer {token}"]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        raw = p.stdout or ""
    except Exception:
        return {"status": 0, "body": ""}
    status = 0
    body = raw
    marker = raw.rfind("__HTTP_STATUS__:")
    if marker != -1:
        body = raw[:marker].rstrip("\n")
        try:
            status = int(raw[marker + len("__HTTP_STATUS__:"):].strip())
        except ValueError:
            status = 0
    return {"status": status, "body": body}


def _scan_direction(corpus_owner, token_cross, direction, replay_fn):
    """Para cada candidato (object-ref + método seguro) do corpus do dono,
    reproduz com o token oposto e sem auth, e gera o verdict."""
    results = []
    for req in corpus_owner:
        if not is_safe_method(req.get("method")) or not is_object_ref_request(req):
            continue
        baseline = {"status": req.get("status"), "body": req.get("resp_body")}
        canary = extract_canary(req.get("resp_body"), "")
        cross = replay_fn(req, token_cross)
        unauth = replay_fn(req, None)
        v = verdict(baseline, cross, unauth, canary)
        results.append({"req": req, "verdict": v, "canary": canary, "direction": direction})
    return results


def run(messages_a, messages_b, token_a, token_b, outdir, replay_fn=replay):
    """Loop bidirecional: B→objetos de A e A→objetos de B. Grava access_control.json."""
    corpus_a = parse_zap_messages(messages_a)
    corpus_b = parse_zap_messages(messages_b)
    results = []
    results += _scan_direction(corpus_a, token_b, "B->A", replay_fn)
    results += _scan_direction(corpus_b, token_a, "A->B", replay_fn)
    findings = build_findings(results)
    payload = {"findings": findings,
               "summary": {"candidates": len(results),
                           "confirmed": sum(1 for f in findings if f["confirmed"])}}
    try:
        os.makedirs(outdir, exist_ok=True)
        with open(os.path.join(outdir, "access_control.json"), "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, ensure_ascii=False)
    except Exception:
        pass
    return payload


def main(argv):
    if len(argv) >= 5 and argv[1] == "run":
        msgs_a = open(argv[2], encoding="utf-8").read()
        msgs_b = open(argv[3], encoding="utf-8").read()
        outdir = argv[4]
        tok_a = os.environ.get("BOLA_TOKEN_A", "")
        tok_b = os.environ.get("BOLA_TOKEN_B", "")
        res = run(msgs_a, msgs_b, tok_a, tok_b, outdir)
        print(f"access-control: {res['summary']['confirmed']} confirmado(s) "
              f"de {res['summary']['candidates']} candidato(s)")
        return 0
    print("uso: bola.py run <messages_a.json> <messages_b.json> <outdir>", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_bola.py -q`
Expected: PASS

- [ ] **Step 5: Verify module compiles**

Run: `python3 -m py_compile lib/bola.py`
Expected: sem saída (ok)

- [ ] **Step 6: Commit**

```bash
git add lib/bola.py tests/test_bola.py
git commit -m "feat(bola): replay + run bidirecional + CLI (P1)"
```

---

## Task 8: Wire no `stiglitz.sh` — args `--token-a`/`--token-b` (+ apelido)

**Files:**
- Modify: `stiglitz.sh` (declaração de vars ~247; parser de args ~258)

- [ ] **Step 1: Declarar as vars dos dois tokens**

Localizar `AUTH_TOKEN=""` (linha ~247) e inserir logo abaixo:

```bash
TOKEN_A=""         # token primário (BOLA/BFLA) — também alimenta AUTH_TOKEN
TOKEN_B=""         # token secundário (BOLA/BFLA)
```

- [ ] **Step 2: Acrescentar o parse dos novos args**

Localizar a linha `--token|-t)          AUTH_TOKEN="${_args[$((${_i}+1))]}" ;;` (~258) e inserir logo abaixo:

```bash
        --token-a)           TOKEN_A="${_args[$((${_i}+1))]}" ;;
        --token-b)           TOKEN_B="${_args[$((${_i}+1))]}" ;;
```

- [ ] **Step 3: Resolver apelido (`--token` = `--token-a`) após o parser**

Localizar o fim do loop de parse de args (o `done` que fecha o `for`/`while` do parser, logo após o `case`). Imediatamente após esse `done`, inserir:

```bash
# --token/-t é apelido de --token-a; AUTH_TOKEN (usado pela P9/nuclei) reflete o token A
[ -z "$TOKEN_A" ] && [ -n "$AUTH_TOKEN" ] && TOKEN_A="$AUTH_TOKEN"
[ -n "$TOKEN_A" ] && AUTH_TOKEN="$TOKEN_A"
```

- [ ] **Step 4: Validar sintaxe**

Run:
```bash
bash -n stiglitz.sh
grep -n 'TOKEN_A=\|TOKEN_B=\|--token-a)\|--token-b)' stiglitz.sh
```
Expected: sem erro de sintaxe; mostra as 2 vars e os 2 cases.

- [ ] **Step 5: Commit**

```bash
git add stiglitz.sh
git commit -m "feat(scan): args --token-a/--token-b (--token vira apelido de A) (P1)"
```

---

## Task 9: Wire no `stiglitz.sh` — fase P9.5 Access Control

**Files:**
- Modify: `stiglitz.sh` (após o bloco da Fase 9 / ZAP)

- [ ] **Step 1: Localizar o fim da Fase 9 (ZAP)**

Run:
```bash
grep -n 'Fase 9\|FASE 9\|phase_zap\|Active Scan\|zap_api_call "core/view' stiglitz.sh | head
```
Expected: identifica onde a P9 termina (após o active scan e antes da Fase 10 / JS Analysis). A P9.5 é inserida nesse ponto.

- [ ] **Step 2: Inserir o bloco da fase P9.5**

Imediatamente após o término do bloco da Fase 9 (antes do início da Fase 10), inserir:

```bash
    # ── Fase 9.5 — Access Control (BOLA/BFLA) — só com dois tokens ──
    if [ -n "$TOKEN_A" ] && [ -n "$TOKEN_B" ]; then
        echo -e "\n${BLUE}═══ FASE 9.5 — Access Control (BOLA/BFLA) ═══${NC}"
        # sem `local`: o bloco pode estar em escopo top-level do script
        _zap_msgs_a="$OUTDIR/raw/zap_messages_a.json"
        _zap_msgs_b="$OUTDIR/raw/zap_messages_b.json"

        # corpus de A: histórico já gravado pelo crawl autenticado da P9 (token A)
        zap_api_call "core/view/messages" "" > "$_zap_msgs_a" 2>/dev/null || true

        # corpus de B: spider-only leve como token B (sem active scan)
        if [ -n "$ZAP_RUNNING" ]; then
            _tb_enc=$(python3 -c \
                "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1],safe=''))" \
                "Bearer ${TOKEN_B}" 2>/dev/null)
            # troca a replacer rule do Authorization para o token B
            zap_api_call "replacer/action/removeRule" "description=AuthToken" >/dev/null 2>&1 || true
            zap_api_call "replacer/action/addRule" \
                "description=AuthToken&enabled=true&matchType=REQ_HEADER&matchString=Authorization&replacement=${_tb_enc}" \
                >/dev/null 2>&1
            zap_api_call "spider/action/scan" "url=${TARGET}&maxChildren=10" >/dev/null 2>&1
            sleep 20
            zap_api_call "core/view/messages" "" > "$_zap_msgs_b" 2>/dev/null || true
        else
            echo '{"messages":[]}' > "$_zap_msgs_b"
            echo -e "  ${YELLOW}[!] ZAP indisponível — corpus de B vazio (só direção B→A)${NC}"
        fi

        if [ ! -s "$_zap_msgs_a" ]; then
            echo -e "  ${YELLOW}[!] access-control: sem corpus do ZAP (P9 não rodou?) — BOLA/BFLA pulado${NC}"
        else
            BOLA_TOKEN_A="$TOKEN_A" BOLA_TOKEN_B="$TOKEN_B" \
                python3 "$SCRIPT_DIR/lib/bola.py" run \
                "$_zap_msgs_a" "$_zap_msgs_b" "$OUTDIR" \
                && echo -e "  ${GREEN}[✓] Access Control concluído → raw/access_control.json${NC}" \
                || echo -e "  ${YELLOW}[!] access-control: motor BOLA retornou erro${NC}"
        fi
    fi
```

> Nota: `ZAP_RUNNING` é a flag de estado do ZAP no script — se o nome real diferir (ex.: `ZAP_OK`/`ZAP_PID`), use o existente. O `grep` da Task 9 Step 1 revela o nome. Se não houver flag, troque `[ -n "$ZAP_RUNNING" ]` por um teste de porta: `curl -s "http://localhost:8080" >/dev/null 2>&1`.

- [ ] **Step 3: Validar sintaxe e lint**

Run:
```bash
bash -n stiglitz.sh
shellcheck --severity=warning stiglitz.sh 2>&1 | head -20
```
Expected: sem erro de sintaxe; sem novos warnings de shellcheck introduzidos pelo bloco.

- [ ] **Step 4: Confirmar o wiring**

Run:
```bash
grep -n 'FASE 9.5\|bola.py run\|zap_messages_a\|BOLA_TOKEN_A=' stiglitz.sh
```
Expected: bloco P9.5 presente, chamada do módulo com env de tokens, export dos dois corpora.

- [ ] **Step 5: Commit**

```bash
git add stiglitz.sh
git commit -m "feat(scan): fase P9.5 Access Control (BOLA/BFLA) via lib/bola.py (P1)"
```

---

## Task 10: Validação final + docs

**Files:**
- Modify: `CLAUDE.md`

- [ ] **Step 1: Suite completa verde**

Run: `python3 -m pytest tests/ -q`
Expected: PASS (inclui `tests/test_bola.py`; sem regressões).

- [ ] **Step 2: Compilar módulos e validar bash**

Run:
```bash
python3 -m py_compile lib/bola.py lib/vuln_catalog.py
bash -n stiglitz.sh && shellcheck --severity=warning stiglitz.sh
```
Expected: sem saída do py_compile; bash/shellcheck limpos.

- [ ] **Step 3: Atualizar CLAUDE.md**

- Na lista de fases do `stiglitz.sh` (seção `### stiglitz.sh`), acrescentar após a Fase 9:
  `9.5. **Fase 9.5** — Access Control (BOLA/BFLA) — opt-in com --token-a + --token-b: replay multi-token de requests do ZAP, confirma por tripla A/B/unauth + canário`
- Na tabela de módulos `lib/`, adicionar:
  `| \`bola.py\` | Detecção de BOLA/IDOR e BFLA (OWASP API #1, fase P9.5) — reproduz requests do ZAP com dois tokens (--token-a/-b), confirma acesso indevido por tripla A/B/unauth + canário de corpo → \`access_control.json\`. Só GET/HEAD/OPTIONS; tokens via env. Lógica pura + CLI |`
- Registrar que `--token`/`-t` virou apelido de `--token-a`.

- [ ] **Step 4: Commit**

```bash
git add CLAUDE.md
git commit -m "docs: fase P9.5 Access Control (BOLA/BFLA) + lib/bola.py + --token-a/-b (P1)"
```

---

## Self-review (preenchido pelo autor do plano)

- **Cobertura do spec:** CLI `--token-a/-b` + apelido (T8); fase P9.5 com captura dos dois corpora + spider-B + degradação (T9); `lib/bola.py` — parse (T2), filtros object-ref/safe-method (T3), canário (T4), verdict tripla A/B/unauth (T5), classify+build_findings com classes/fingerprint (T6), replay+run bidirecional+CLI (T7); classe `bfla` nova no catálogo (T1); docs+suite (T10). Tripla A/B/unauth + canário no T5; só GET/HEAD/OPTIONS no T3/T7; bidirecional no T7 (`_scan_direction` nas duas direções); tokens via env no T7/T9; nada versionado (artefatos no OUTDIR). ✓ todos os itens do spec mapeados.
- **Placeholders:** nenhum "TODO/TBD"; todo passo de código mostra o código real. A única nota condicional (nome da flag `ZAP_RUNNING`) traz fallback concreto (teste de porta via curl).
- **Consistência de tipos:** `parse_zap_messages(text)->[{method,url,req_headers,req_body,status,resp_body}]`; `is_safe_method(str)->bool`; `is_object_ref_request(req)->bool`; `extract_canary(body,ct)->set`; `canary_is_pii(set)->bool`; `verdict(baseline,cross,unauth,canary)->{state,canary_hit,confidence}` com `{status,body}`; `classify(req,canary)->str`; `build_findings([{req,verdict,canary,direction}])->[finding]`; `replay(req,token)->{status,body}`; `run(msgs_a,msgs_b,tok_a,tok_b,outdir,replay_fn)->{findings,summary}`; `main(argv)->int`. Usadas com as mesmas assinaturas em T1–T9. `fingerprint(finding)` recebe dict com `url`/`cwe`/`type`/`param` (T6 monta esses campos antes de chamar). `response_diff` retorna `(changed,score,note)` e `changed=True`=diferente — `_bodies_match` inverte corretamente. ✓

## Pendência operacional (pré-push)

Trabalho **local** até autorização explícita. Antes de qualquer `git push`, permanece pendente o shred seguro de `scan_pos.bee2pay.com_20260606_144522/` + `scan_pos_full.log` (dados CDE). Nenhum artefato deste plano é versionado — `raw/zap_messages_*.json` e `access_control.json` ficam no `OUTDIR` gitignored; testes usam `target.com` sintético.

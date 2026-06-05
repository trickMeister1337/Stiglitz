# Detecções de Lógica de Negócio/Authz (Fase 1) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Módulo spec-driven que testa IDOR/BOLA (read/write), privilege escalation, amount tampering e race/idempotency em apps fintech, emitindo findings confirmados com `vuln_class` que alimentam o motor de criticidade (Fase 0).

**Architecture:** Núcleo Python `lib/bizlogic.py` (config JSON/YAML, auth multi-conta via urllib, 4 famílias de teste, funções puras de verdito) + wrapper `lib/bizlogic.sh` (profile/RoE/escopo) como nova fase do `stiglitz_red.sh`. Sem dependência de runtime (urllib + threading da stdlib; YAML opcional). Testado contra um app HTTP falso (http.server da stdlib) com endpoints vulnerável e seguro por família.

**Tech Stack:** Python 3 stdlib (urllib, threading, http.server, json); PyYAML opcional (config yaml); pytest; convenções de `lib/` e `lib/profiles.conf`.

**Spec:** `docs/superpowers/specs/2026-06-01-bizlogic-authz-design.md`

---

## File Structure

- **Create** `lib/bizlogic.py` — núcleo: config, auth, HTTP, 4 famílias, verdito, emissão de findings, CLI.
- **Create** `lib/bizlogic.sh` — wrapper: profile → flags, gate RoE, escopo, audit.
- **Create** `tests/test_bizlogic.py` — funções puras + app falso + gating.
- **Modify** `lib/profiles.conf` — entradas de profile para bizlogic.
- **Modify** `lib/ingest.py` — ler `raw/bizlogic.json`.
- **Modify** `stiglitz_red.sh` — nova fase chamando `lib/bizlogic.sh`.
- **Modify** `requirements-dev.txt` — `PyYAML` (para testar o caminho yaml).
- **Modify** `.github/workflows/ci.yml` — incluir `tests/test_bizlogic.py`.

---

## PARTE 1 — Config, auth e HTTP

### Task 1: Carregar e validar config (JSON nativo; YAML opcional)

**Files:** Create `lib/bizlogic.py`, `tests/test_bizlogic.py`

- [ ] **Step 1: Teste que falha**

```python
#!/usr/bin/env python3
"""Testes do módulo de lógica de negócio/authz (bizlogic)."""
import json
import os
import sys
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
sys.path[:0] = [_ROOT, os.path.join(_ROOT, "lib")]

VALID_CFG = {
    "base_url": "http://localhost:0",
    "accounts": {
        "A": {"auth": {"type": "bearer", "token": "ta"}, "id": "1"},
        "B": {"auth": {"type": "bearer", "token": "tb"}, "id": "2"},
    },
    "sentinel": {"amount": "0.01", "recipient": "test-rcpt"},
    "endpoints": [
        {"name": "get_acct", "method": "GET", "path": "/api/accounts/{id}",
         "owner_param": "id", "object_of": "A", "tests": ["idor_read"]},
    ],
}


class TestConfig(unittest.TestCase):
    def test_load_json(self):
        import bizlogic
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(VALID_CFG, f)
            path = f.name
        cfg = bizlogic.load_config(path)
        self.assertEqual(cfg["base_url"], "http://localhost:0")
        os.unlink(path)

    def test_missing_required_raises(self):
        import bizlogic
        with self.assertRaises(ValueError):
            bizlogic.validate_config({"base_url": "x"})  # sem accounts/endpoints

    def test_validate_ok(self):
        import bizlogic
        bizlogic.validate_config(VALID_CFG)  # não levanta
```

- [ ] **Step 2: Rodar — falha**

Run: `python3 -m pytest tests/test_bizlogic.py::TestConfig -v`
Expected: FAIL (`No module named 'bizlogic'`)

- [ ] **Step 3: Implementar**

```python
#!/usr/bin/env python3
"""
bizlogic.py — Detecções de lógica de negócio/authz (red team autorizado).

Spec-driven: lê um config (JSON nativo ou YAML opcional) com contas de teste e
endpoints-alvo, executa testes estruturados e seguros (IDOR read/write, privesc,
amount tampering, race/idempotency), e emite findings com vuln_class p/ o motor
de criticidade. Mutações são gated por profile + sentinela + RoE.

Console PT-BR; campos de evidência em EN (padrão deliverable do suite).
"""
import argparse
import json
import os
import sys
import threading
import urllib.error
import urllib.request

REQUIRED_TOP = ("base_url", "accounts", "endpoints")


def load_config(path):
    """Carrega config de .json (stdlib) ou .yaml/.yml (PyYAML, se instalado)."""
    with open(path, encoding="utf-8") as f:
        text = f.read()
    if path.endswith((".yaml", ".yml")):
        try:
            import yaml
        except ImportError:
            raise ValueError("Config YAML requer PyYAML; use .json ou instale PyYAML.")
        cfg = yaml.safe_load(text)
    else:
        cfg = json.loads(text)
    validate_config(cfg)
    return cfg


def validate_config(cfg):
    """Valida campos obrigatórios; levanta ValueError com mensagem clara."""
    if not isinstance(cfg, dict):
        raise ValueError("Config deve ser um objeto.")
    for k in REQUIRED_TOP:
        if k not in cfg:
            raise ValueError(f"Config sem campo obrigatório: {k}")
    if not cfg["accounts"]:
        raise ValueError("Config precisa de ao menos uma conta em 'accounts'.")
    if not isinstance(cfg["endpoints"], list) or not cfg["endpoints"]:
        raise ValueError("Config precisa de 'endpoints' (lista não vazia).")
    for ep in cfg["endpoints"]:
        for k in ("name", "method", "path", "tests"):
            if k not in ep:
                raise ValueError(f"Endpoint sem campo '{k}': {ep!r}")
```

- [ ] **Step 4: Rodar — passa**

Run: `python3 -m pytest tests/test_bizlogic.py::TestConfig -v`
Expected: PASS (3 passed)

- [ ] **Step 5: Commit**

```bash
git add lib/bizlogic.py tests/test_bizlogic.py
git commit -m "feat(bizlogic): carga e validação de config (json/yaml)"
```

---

### Task 2: Headers de autenticação (bearer/cookie/header)

**Files:** Modify `lib/bizlogic.py`, `tests/test_bizlogic.py`

- [ ] **Step 1: Teste que falha**

```python
class TestAuth(unittest.TestCase):
    def test_bearer(self):
        import bizlogic
        h = bizlogic.auth_headers({"auth": {"type": "bearer", "token": "abc"}})
        self.assertEqual(h["Authorization"], "Bearer abc")

    def test_cookie(self):
        import bizlogic
        h = bizlogic.auth_headers({"auth": {"type": "cookie", "cookie": "s=1"}})
        self.assertEqual(h["Cookie"], "s=1")

    def test_header(self):
        import bizlogic
        h = bizlogic.auth_headers({"auth": {"type": "header", "headers": {"X-Auth": "k"}}})
        self.assertEqual(h["X-Auth"], "k")

    def test_unknown_type_raises(self):
        import bizlogic
        with self.assertRaises(ValueError):
            bizlogic.auth_headers({"auth": {"type": "magic"}})
```

- [ ] **Step 2: Rodar — falha**

Run: `python3 -m pytest tests/test_bizlogic.py::TestAuth -v`
Expected: FAIL (`auth_headers` inexistente)

- [ ] **Step 3: Implementar (adicionar a `lib/bizlogic.py`)**

```python
def auth_headers(account):
    """Constrói os headers de autenticação de uma conta."""
    auth = account.get("auth", {})
    t = auth.get("type")
    if t == "bearer":
        return {"Authorization": f"Bearer {auth['token']}"}
    if t == "cookie":
        return {"Cookie": auth["cookie"]}
    if t == "header":
        return dict(auth.get("headers", {}))
    raise ValueError(f"Tipo de auth desconhecido: {t!r}")
```

- [ ] **Step 4: Rodar — passa** · Run: `python3 -m pytest tests/test_bizlogic.py::TestAuth -v` → 4 passed
- [ ] **Step 5: Commit**

```bash
git add lib/bizlogic.py tests/test_bizlogic.py
git commit -m "feat(bizlogic): auth_headers (bearer/cookie/header)"
```

---

### Task 3: Cliente HTTP (urllib) + Response

**Files:** Modify `lib/bizlogic.py`, `tests/test_bizlogic.py`

- [ ] **Step 1: Teste que falha** (usa um http.server local mínimo)

```python
class TestHttp(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from http.server import BaseHTTPRequestHandler, HTTPServer

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass
            def do_GET(self):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'{"ok":true}')
        cls.srv = HTTPServer(("127.0.0.1", 0), H)
        cls.port = cls.srv.server_address[1]
        cls.t = threading.Thread(target=cls.srv.serve_forever, daemon=True)
        cls.t.start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def test_http_request_returns_status_and_body(self):
        import bizlogic
        r = bizlogic.http_request("GET", f"http://127.0.0.1:{self.port}/x", {}, None)
        self.assertEqual(r.status, 200)
        self.assertIn("ok", r.body)
```

- [ ] **Step 2: Rodar — falha** · Run: `python3 -m pytest tests/test_bizlogic.py::TestHttp -v` → FAIL
- [ ] **Step 3: Implementar (adicionar a `lib/bizlogic.py`)**

```python
class Response:
    """Resposta HTTP simplificada."""
    __slots__ = ("status", "body", "headers")

    def __init__(self, status, body, headers):
        self.status = status
        self.body = body
        self.headers = headers


def http_request(method, url, headers, body, timeout=15):
    """Faz uma requisição HTTP via urllib. Nunca levanta por status != 2xx."""
    data = None
    hdrs = dict(headers or {})
    if body is not None:
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        hdrs.setdefault("Content-Type", "application/json")
    req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode(errors="replace")
            return Response(resp.status, raw, dict(resp.headers))
    except urllib.error.HTTPError as e:
        raw = e.read().decode(errors="replace") if e.fp else ""
        return Response(e.code, raw, dict(e.headers or {}))
    except (urllib.error.URLError, OSError) as e:
        return Response(0, f"__error__:{e}", {})
```

- [ ] **Step 4: Rodar — passa** · Run: `python3 -m pytest tests/test_bizlogic.py::TestHttp -v` → PASS
- [ ] **Step 5: Commit**

```bash
git add lib/bizlogic.py tests/test_bizlogic.py
git commit -m "feat(bizlogic): cliente HTTP urllib + Response"
```

---

## PARTE 2 — Funções puras de verdito

### Task 4: Equivalência de respostas (IDOR read)

**Files:** Modify `lib/bizlogic.py`, `tests/test_bizlogic.py`

- [ ] **Step 1: Teste que falha**

```python
class TestEquivalence(unittest.TestCase):
    def test_same_json_equivalent(self):
        import bizlogic
        self.assertTrue(bizlogic.responses_equivalent('{"a":1,"b":2}', '{"a":1,"b":2}'))

    def test_dynamic_tokens_ignored(self):
        import bizlogic
        a = '{"a":1,"ts":"2026-01-01T00:00:00","req_id":"x1"}'
        b = '{"a":1,"ts":"2026-06-06T12:00:00","req_id":"x2"}'
        self.assertTrue(bizlogic.responses_equivalent(a, b))

    def test_different_data_not_equivalent(self):
        import bizlogic
        self.assertFalse(bizlogic.responses_equivalent('{"owner":"A","x":1}',
                                                       '{"owner":"B","x":9}'))
```

- [ ] **Step 2: Rodar — falha** · `python3 -m pytest tests/test_bizlogic.py::TestEquivalence -v` → FAIL
- [ ] **Step 3: Implementar (adicionar a `lib/bizlogic.py`)**

```python
import re

# Campos dinâmicos que variam entre requisições e não indicam dados distintos.
_DYNAMIC_KEYS = re.compile(r"(ts|time|timestamp|date|req_id|request_id|trace|nonce|"
                           r"etag|expires|iat|exp)", re.IGNORECASE)


def _strip_dynamic(obj):
    """Remove recursivamente chaves dinâmicas de um objeto JSON decodificado."""
    if isinstance(obj, dict):
        return {k: _strip_dynamic(v) for k, v in sorted(obj.items())
                if not _DYNAMIC_KEYS.fullmatch(k)}
    if isinstance(obj, list):
        return [_strip_dynamic(v) for v in obj]
    return obj


def responses_equivalent(body_a, body_b):
    """True se dois corpos JSON representam os mesmos dados (ignora campos dinâmicos).

    Usado no IDOR read: se a conta B recebe um corpo equivalente ao baseline da
    conta A, houve exposição cross-user.
    """
    try:
        ja = _strip_dynamic(json.loads(body_a))
        jb = _strip_dynamic(json.loads(body_b))
        return ja == jb
    except (ValueError, TypeError):
        # Fallback não-JSON: comparação literal após strip de espaços.
        return body_a.strip() == body_b.strip()
```

- [ ] **Step 4: Rodar — passa** · `python3 -m pytest tests/test_bizlogic.py::TestEquivalence -v` → 3 passed
- [ ] **Step 5: Commit**

```bash
git add lib/bizlogic.py tests/test_bizlogic.py
git commit -m "feat(bizlogic): responses_equivalent (verdito IDOR read)"
```

---

### Task 5: Variações de adulteração de valor + detecção de double-spend

**Files:** Modify `lib/bizlogic.py`, `tests/test_bizlogic.py`

- [ ] **Step 1: Teste que falha**

```python
class TestTamperAndRace(unittest.TestCase):
    def test_tamper_variations_cover_cases(self):
        import bizlogic
        base = {"amount": "{amount}", "to": "{recipient}"}
        vs = bizlogic.tamper_variations(base, ["amount"], {"amount": "0.01", "recipient": "r"})
        amounts = [v["amount"] for v in vs]
        self.assertIn("-0.01", amounts)       # negativo
        self.assertIn("0", amounts)           # zero
        self.assertIn("0.001", amounts)       # casas extras
        self.assertTrue(any(a == "1e9" or a == "1000000000" for a in amounts))  # overflow
        for v in vs:
            self.assertEqual(v["to"], "r")    # placeholders resolvidos

    def test_detect_double_spend(self):
        import bizlogic
        self.assertTrue(bizlogic.detect_double_spend([200, 200, 409], allowed=1))
        self.assertFalse(bizlogic.detect_double_spend([200, 409, 409], allowed=1))
```

- [ ] **Step 2: Rodar — falha** · `python3 -m pytest tests/test_bizlogic.py::TestTamperAndRace -v` → FAIL
- [ ] **Step 3: Implementar (adicionar a `lib/bizlogic.py`)**

```python
def _resolve(template, values):
    """Resolve placeholders {k} em strings de um dict (1 nível)."""
    out = {}
    for k, v in template.items():
        if isinstance(v, str):
            for ph, val in values.items():
                v = v.replace("{" + ph + "}", str(val))
        out[k] = v
    return out


def tamper_variations(base_body, money_params, sentinel):
    """Gera corpos com valores adulterados nos money_params (placeholders resolvidos)."""
    resolved = _resolve(base_body, sentinel)
    bad_values = ["-0.01", "0", "0.001", "abc", "1e9"]
    variations = []
    for p in money_params:
        for bad in bad_values:
            v = dict(resolved)
            v[p] = bad
            variations.append(v)
    return variations


def detect_double_spend(statuses, allowed=1):
    """True se mais respostas de sucesso (2xx) do que o permitido (double-spend)."""
    ok = sum(1 for s in statuses if 200 <= s < 300)
    return ok > allowed
```

- [ ] **Step 4: Rodar — passa** · `python3 -m pytest tests/test_bizlogic.py::TestTamperAndRace -v` → 2 passed
- [ ] **Step 5: Commit**

```bash
git add lib/bizlogic.py tests/test_bizlogic.py
git commit -m "feat(bizlogic): tamper_variations + detect_double_spend"
```

---

## PARTE 3 — App falso e famílias de detecção

### Task 6: App HTTP falso (vulnerável + seguro) para os testes

**Files:** Modify `tests/test_bizlogic.py`

- [ ] **Step 1: Implementar o harness do app falso** (não há "teste que falha" — é infra de teste; valide carregando)

Adicione a `tests/test_bizlogic.py` uma classe-base que sobe um `http.server` com rotas vulneráveis e seguras. Comportamento:
- `GET /vuln/accounts/<id>` → sempre 200 com `{"owner":"<id>","balance":100}` (não checa dono → IDOR).
- `GET /safe/accounts/<id>` → 200 só se header `X-Acct` == `<id>`; senão 403 (checa dono).
- `POST /vuln/transfer` → 200 sempre (aceita qualquer amount, sem idempotência, sem lock → tampering/race/idempotency).
- `POST /safe/transfer` → rejeita amount <= 0 ou não-numérico (400); honra `Idempotency-Key` (2ª vez → 409); serializa (lock) p/ não permitir double-spend.
- `GET /vuln/admin` → 200 sempre; `GET /safe/admin` → 403 sem header `X-Admin: 1`.

```python
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer


class _App(BaseHTTPRequestHandler):
    seen_keys = set()
    lock = threading.Lock()
    transfers = 0

    def log_message(self, *a):
        pass

    def _send(self, code, obj):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(obj).encode())

    def do_GET(self):
        p = self.path
        if p.startswith("/vuln/accounts/"):
            return self._send(200, {"owner": p.rsplit("/", 1)[1], "balance": 100})
        if p.startswith("/safe/accounts/"):
            acct = p.rsplit("/", 1)[1]
            if self.headers.get("X-Acct") == acct:
                return self._send(200, {"owner": acct, "balance": 100})
            return self._send(403, {"error": "forbidden"})
        if p == "/vuln/admin":
            return self._send(200, {"users": ["u1", "u2"]})
        if p == "/safe/admin":
            if self.headers.get("X-Admin") == "1":
                return self._send(200, {"users": ["u1", "u2"]})
            return self._send(403, {"error": "forbidden"})
        return self._send(404, {})

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length) if length else b"{}"
        try:
            body = json.loads(raw or b"{}")
        except ValueError:
            body = {}
        p = self.path
        if p == "/vuln/transfer":
            type(self).transfers += 1
            return self._send(200, {"status": "done"})
        if p == "/safe/transfer":
            amt = body.get("amount")
            try:
                if float(amt) <= 0:
                    return self._send(400, {"error": "invalid amount"})
            except (TypeError, ValueError):
                return self._send(400, {"error": "invalid amount"})
            key = self.headers.get("Idempotency-Key")
            with type(self).lock:
                if key and key in type(self).seen_keys:
                    return self._send(409, {"error": "duplicate"})
                if key:
                    type(self).seen_keys.add(key)
                type(self).transfers += 1
            return self._send(200, {"status": "done"})
        return self._send(404, {})


class AppTestCase(unittest.TestCase):
    def setUp(self):
        _App.seen_keys = set()
        _App.transfers = 0
        self.srv = HTTPServer(("127.0.0.1", 0), _App)
        self.base = f"http://127.0.0.1:{self.srv.server_address[1]}"
        self.t = threading.Thread(target=self.srv.serve_forever, daemon=True)
        self.t.start()

    def tearDown(self):
        self.srv.shutdown()
```

- [ ] **Step 2: Rodar** · `python3 -m pytest tests/test_bizlogic.py -q` (deve continuar verde; AppTestCase ainda sem testes próprios)
- [ ] **Step 3: Commit**

```bash
git add tests/test_bizlogic.py
git commit -m "test(bizlogic): app HTTP falso (vulnerável + seguro)"
```

---

### Task 7: Família IDOR read

**Files:** Modify `lib/bizlogic.py`, `tests/test_bizlogic.py`

- [ ] **Step 1: Teste que falha** (subclasse de `AppTestCase`)

```python
class TestIdorRead(AppTestCase):
    def _cfg(self, path):
        return {
            "base_url": self.base,
            "accounts": {"A": {"auth": {"type": "header", "headers": {"X-Acct": "A"}}, "id": "A"},
                          "B": {"auth": {"type": "header", "headers": {"X-Acct": "B"}}, "id": "B"}},
            "endpoints": [{"name": "acct", "method": "GET", "path": path,
                           "owner_param": "id", "object_of": "A", "tests": ["idor_read"]}],
        }

    def test_vulnerable_endpoint_confirms(self):
        import bizlogic
        cfg = self._cfg("/vuln/accounts/{id}")
        f = bizlogic.test_idor_read(cfg, cfg["endpoints"][0])
        self.assertIsNotNone(f)
        self.assertTrue(f["confirmed"])
        self.assertEqual(f["vuln_class"], "idor_read_pii")

    def test_safe_endpoint_no_finding(self):
        import bizlogic
        cfg = self._cfg("/safe/accounts/{id}")
        f = bizlogic.test_idor_read(cfg, cfg["endpoints"][0])
        self.assertIsNone(f)
```

- [ ] **Step 2: Rodar — falha** · `python3 -m pytest tests/test_bizlogic.py::TestIdorRead -v` → FAIL
- [ ] **Step 3: Implementar (adicionar a `lib/bizlogic.py`)**

```python
def _account(cfg, name):
    return cfg["accounts"][name]


def _url(cfg, ep, values):
    return cfg["base_url"].rstrip("/") + _resolve({"_": ep["path"]}, values)["_"]


def _finding(name, vuln_class, url, method, confirmed, evidence, severity="high"):
    return {"name": name, "vuln_class": vuln_class, "url": url, "method": method,
            "severity": severity, "confirmed": confirmed, "tool": "bizlogic",
            "evidence": evidence}


def test_idor_read(cfg, ep):
    """A pega o próprio recurso (baseline); B pede o MESMO recurso de A.
    Confirma se B recebe 2xx com corpo equivalente ao baseline."""
    owner = ep["object_of"]
    owner_id = _account(cfg, owner)["id"]
    url = _url(cfg, ep, {"id": owner_id, "owner": owner_id})

    base = http_request("GET", url, auth_headers(_account(cfg, owner)), None)
    if not (200 <= base.status < 300):
        return None  # baseline não acessível — nada a comparar

    other = "B" if owner != "B" else "A"
    victimless = http_request("GET", url, auth_headers(_account(cfg, other)), None)
    confirmed = (200 <= victimless.status < 300
                 and responses_equivalent(base.body, victimless.body))
    if not confirmed:
        return None
    return _finding(f"IDOR read: {ep['name']}", "idor_read_pii", url, "GET", True,
                    {"baseline_account": owner, "cross_account": other,
                     "baseline_status": base.status, "cross_status": victimless.status,
                     "response_excerpt": victimless.body[:400]})
```

- [ ] **Step 4: Rodar — passa** · `python3 -m pytest tests/test_bizlogic.py::TestIdorRead -v` → 2 passed
- [ ] **Step 5: Commit**

```bash
git add lib/bizlogic.py tests/test_bizlogic.py
git commit -m "feat(bizlogic): família IDOR read"
```

---

### Task 8: Famílias IDOR write + privilege escalation

**Files:** Modify `lib/bizlogic.py`, `tests/test_bizlogic.py`

- [ ] **Step 1: Teste que falha**

```python
class TestPrivesc(AppTestCase):
    def _cfg(self, path):
        return {"base_url": self.base,
                "accounts": {"A": {"auth": {"type": "header", "headers": {}}, "id": "A"}},
                "endpoints": [{"name": "admin", "method": "GET", "path": path,
                               "tests": ["privesc"]}]}

    def test_vuln_admin_confirms(self):
        import bizlogic
        cfg = self._cfg("/vuln/admin")
        f = bizlogic.test_privesc(cfg, cfg["endpoints"][0], actor="A")
        self.assertIsNotNone(f)
        self.assertEqual(f["vuln_class"], "priv_escalation")

    def test_safe_admin_no_finding(self):
        import bizlogic
        cfg = self._cfg("/safe/admin")
        self.assertIsNone(bizlogic.test_privesc(cfg, cfg["endpoints"][0], actor="A"))
```

- [ ] **Step 2: Rodar — falha** · `python3 -m pytest tests/test_bizlogic.py::TestPrivesc -v` → FAIL
- [ ] **Step 3: Implementar (adicionar a `lib/bizlogic.py`)**

```python
def test_privesc(cfg, ep, actor="A"):
    """Ator não-privilegiado acessa endpoint privilegiado. 2xx → confirmado."""
    url = _url(cfg, ep, {"id": _account(cfg, actor).get("id", ""), "owner": ""})
    r = http_request(ep["method"], url, auth_headers(_account(cfg, actor)),
                     ep.get("body"))
    if not (200 <= r.status < 300):
        return None
    return _finding(f"Privilege escalation: {ep['name']}", "priv_escalation", url,
                    ep["method"], True,
                    {"actor": actor, "status": r.status, "response_excerpt": r.body[:400]})


def test_idor_write(cfg, ep, mutate_allowed, dry_run):
    """B muta o recurso de A. Mutating → respeita gating.
    Em dry_run: monta a request e marca como potencial (não envia a mutação)."""
    owner = ep["object_of"]
    owner_id = _account(cfg, owner)["id"]
    url = _url(cfg, ep, {"id": owner_id, "owner": owner_id})
    other = "B" if owner != "B" else "A"
    if dry_run or not mutate_allowed:
        return _finding(f"IDOR write (dry-run): {ep['name']}", "idor_write", url,
                        ep["method"], False,
                        {"note": "dry-run — mutação não enviada", "cross_account": other,
                         "would_send": ep.get("body")})
    r = http_request(ep["method"], url, auth_headers(_account(cfg, other)), ep.get("body"))
    if not (200 <= r.status < 300):
        return None
    # Confirmação: re-leitura como A reflete a mudança? (best-effort)
    return _finding(f"IDOR write: {ep['name']}", "idor_write", url, ep["method"], True,
                    {"cross_account": other, "status": r.status,
                     "response_excerpt": r.body[:400]})
```

- [ ] **Step 4: Rodar — passa** · `python3 -m pytest tests/test_bizlogic.py::TestPrivesc -v` → 2 passed
- [ ] **Step 5: Commit**

```bash
git add lib/bizlogic.py tests/test_bizlogic.py
git commit -m "feat(bizlogic): famílias privesc + IDOR write (com dry-run)"
```

---

### Task 9: Família amount tampering

**Files:** Modify `lib/bizlogic.py`, `tests/test_bizlogic.py`

- [ ] **Step 1: Teste que falha**

```python
class TestAmount(AppTestCase):
    def _cfg(self, path):
        return {"base_url": self.base,
                "accounts": {"A": {"auth": {"type": "header", "headers": {}}, "id": "A"}},
                "sentinel": {"amount": "0.01", "recipient": "r"},
                "endpoints": [{"name": "transfer", "method": "POST", "path": path,
                               "body": {"amount": "{amount}", "to": "{recipient}"},
                               "money_params": ["amount"], "tests": ["amount_tampering"]}]}

    def test_vuln_transfer_confirms(self):
        import bizlogic
        cfg = self._cfg("/vuln/transfer")
        f = bizlogic.test_amount_tampering(cfg, cfg["endpoints"][0], actor="A",
                                           mutate_allowed=True, dry_run=False)
        self.assertIsNotNone(f)
        self.assertEqual(f["vuln_class"], "amount_tampering")

    def test_safe_transfer_no_finding(self):
        import bizlogic
        cfg = self._cfg("/safe/transfer")
        self.assertIsNone(bizlogic.test_amount_tampering(cfg, cfg["endpoints"][0],
                          actor="A", mutate_allowed=True, dry_run=False))

    def test_dry_run_does_not_confirm(self):
        import bizlogic
        cfg = self._cfg("/vuln/transfer")
        f = bizlogic.test_amount_tampering(cfg, cfg["endpoints"][0], actor="A",
                                           mutate_allowed=False, dry_run=True)
        self.assertFalse(f["confirmed"])
```

- [ ] **Step 2: Rodar — falha** · `python3 -m pytest tests/test_bizlogic.py::TestAmount -v` → FAIL
- [ ] **Step 3: Implementar (adicionar a `lib/bizlogic.py`)**

```python
def test_amount_tampering(cfg, ep, actor, mutate_allowed, dry_run):
    """Envia variações adulteradas de valor (sentinela). Aceito sem validação → confirma."""
    if "sentinel" not in cfg:
        raise ValueError("amount_tampering exige 'sentinel' no config.")
    url = _url(cfg, ep, {"owner": _account(cfg, actor).get("id", "")})
    variations = tamper_variations(ep.get("body", {}), ep.get("money_params", []),
                                   cfg["sentinel"])
    if dry_run or not mutate_allowed:
        return _finding(f"Amount tampering (dry-run): {ep['name']}", "amount_tampering",
                        url, ep["method"], False,
                        {"note": "dry-run — variações não enviadas",
                         "variations": variations[:5]})
    accepted = []
    for body in variations:
        r = http_request(ep["method"], url, auth_headers(_account(cfg, actor)), body)
        if 200 <= r.status < 300:
            accepted.append({"body": body, "status": r.status})
    if not accepted:
        return None
    return _finding(f"Amount tampering: {ep['name']}", "amount_tampering", url,
                    ep["method"], True,
                    {"accepted_variations": accepted[:5], "total_accepted": len(accepted)})
```

- [ ] **Step 4: Rodar — passa** · `python3 -m pytest tests/test_bizlogic.py::TestAmount -v` → 3 passed
- [ ] **Step 5: Commit**

```bash
git add lib/bizlogic.py tests/test_bizlogic.py
git commit -m "feat(bizlogic): família amount tampering"
```

---

### Task 10: Famílias race condition + idempotency replay

**Files:** Modify `lib/bizlogic.py`, `tests/test_bizlogic.py`

- [ ] **Step 1: Teste que falha**

```python
class TestRaceIdem(AppTestCase):
    def _cfg(self, path):
        return {"base_url": self.base,
                "accounts": {"A": {"auth": {"type": "header", "headers": {}}, "id": "A"}},
                "sentinel": {"amount": "0.01", "recipient": "r"},
                "endpoints": [{"name": "transfer", "method": "POST", "path": path,
                               "body": {"amount": "{amount}", "to": "{recipient}"},
                               "idempotency_header": "Idempotency-Key",
                               "tests": ["race", "idempotency"]}]}

    def test_race_vuln_confirms(self):
        import bizlogic
        cfg = self._cfg("/vuln/transfer")
        f = bizlogic.test_race(cfg, cfg["endpoints"][0], actor="A", workers=5,
                               mutate_allowed=True, dry_run=False)
        self.assertIsNotNone(f)
        self.assertEqual(f["vuln_class"], "race_condition_funds")

    def test_race_safe_no_finding(self):
        import bizlogic
        cfg = self._cfg("/safe/transfer")
        self.assertIsNone(bizlogic.test_race(cfg, cfg["endpoints"][0], actor="A",
                          workers=5, mutate_allowed=True, dry_run=False))

    def test_idempotency_vuln_confirms(self):
        import bizlogic
        cfg = self._cfg("/vuln/transfer")
        f = bizlogic.test_idempotency(cfg, cfg["endpoints"][0], actor="A",
                                      mutate_allowed=True, dry_run=False)
        self.assertIsNotNone(f)

    def test_idempotency_safe_no_finding(self):
        import bizlogic
        cfg = self._cfg("/safe/transfer")
        self.assertIsNone(bizlogic.test_idempotency(cfg, cfg["endpoints"][0],
                          actor="A", mutate_allowed=True, dry_run=False))
```

- [ ] **Step 2: Rodar — falha** · `python3 -m pytest tests/test_bizlogic.py::TestRaceIdem -v` → FAIL
- [ ] **Step 3: Implementar (adicionar a `lib/bizlogic.py`)**

```python
def test_race(cfg, ep, actor, workers, mutate_allowed, dry_run):
    """Dispara N requisições concorrentes da mesma operação sentinela.
    Mais de uma 2xx além do permitido → double-spend."""
    if "sentinel" not in cfg:
        raise ValueError("race exige 'sentinel'.")
    url = _url(cfg, ep, {"owner": _account(cfg, actor).get("id", "")})
    body = _resolve(ep.get("body", {}), cfg["sentinel"])
    if dry_run or not mutate_allowed:
        return _finding(f"Race condition (dry-run): {ep['name']}", "race_condition_funds",
                        url, ep["method"], False, {"note": "dry-run", "workers": workers})
    results = [None] * workers
    hdrs = auth_headers(_account(cfg, actor))

    def worker(i):
        results[i] = http_request(ep["method"], url, hdrs, body).status

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(workers)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    if not detect_double_spend(results, allowed=1):
        return None
    return _finding(f"Race condition: {ep['name']}", "race_condition_funds", url,
                    ep["method"], True,
                    {"workers": workers, "statuses": results,
                     "success_count": sum(1 for s in results if 200 <= s < 300)})


def test_idempotency(cfg, ep, actor, mutate_allowed, dry_run):
    """Reenvia a mesma requisição com a MESMA Idempotency-Key. Processada 2× → falha."""
    if "sentinel" not in cfg:
        raise ValueError("idempotency exige 'sentinel'.")
    hdr_name = ep.get("idempotency_header", "Idempotency-Key")
    url = _url(cfg, ep, {"owner": _account(cfg, actor).get("id", "")})
    body = _resolve(ep.get("body", {}), cfg["sentinel"])
    if dry_run or not mutate_allowed:
        return _finding(f"Idempotency replay (dry-run): {ep['name']}",
                        "race_condition_funds", url, ep["method"], False,
                        {"note": "dry-run"})
    hdrs = dict(auth_headers(_account(cfg, actor)))
    hdrs[hdr_name] = "stiglitz-idem-canary-1"
    r1 = http_request(ep["method"], url, hdrs, body)
    r2 = http_request(ep["method"], url, hdrs, body)
    # Falha de idempotência: ambas processadas (2xx) em vez de a 2ª retornar 409/cacheado.
    if not (200 <= r1.status < 300 and 200 <= r2.status < 300):
        return None
    return _finding(f"Idempotency replay: {ep['name']}", "race_condition_funds", url,
                    ep["method"], True,
                    {"first_status": r1.status, "second_status": r2.status,
                     "idempotency_header": hdr_name})
```

- [ ] **Step 4: Rodar — passa** · `python3 -m pytest tests/test_bizlogic.py::TestRaceIdem -v` → 4 passed
- [ ] **Step 5: Commit**

```bash
git add lib/bizlogic.py tests/test_bizlogic.py
git commit -m "feat(bizlogic): famílias race condition + idempotency"
```

---

## PARTE 4 — Orquestração, segurança e integração

### Task 11: Orquestrador `run()` — gating, escopo, dispatch, emissão

**Files:** Modify `lib/bizlogic.py`, `tests/test_bizlogic.py`

- [ ] **Step 1: Teste que falha**

```python
class TestRun(AppTestCase):
    def _cfg(self):
        return {"base_url": self.base,
                "accounts": {"A": {"auth": {"type": "header", "headers": {"X-Acct": "A"}}, "id": "A"},
                              "B": {"auth": {"type": "header", "headers": {"X-Acct": "B"}}, "id": "B"}},
                "sentinel": {"amount": "0.01", "recipient": "r"},
                "endpoints": [{"name": "acct", "method": "GET", "path": "/vuln/accounts/{id}",
                               "owner_param": "id", "object_of": "A", "tests": ["idor_read"]}]}

    def test_run_emits_findings(self):
        import bizlogic
        host = self.base.split("://", 1)[1].split(":")[0]
        findings = bizlogic.run(self._cfg(), profile="staging", scope=[host])
        self.assertTrue(any(f["vuln_class"] == "idor_read_pii" for f in findings))

    def test_run_blocks_out_of_scope(self):
        import bizlogic
        findings = bizlogic.run(self._cfg(), profile="staging", scope=["other.example.com"])
        self.assertEqual(findings, [])  # host fora de escopo → nada executado

    def test_production_does_not_mutate(self):
        import bizlogic
        cfg = self._cfg()
        cfg["endpoints"] = [{"name": "t", "method": "POST", "path": "/vuln/transfer",
                             "body": {"amount": "{amount}", "to": "{recipient}"},
                             "money_params": ["amount"], "tests": ["amount_tampering"]}]
        host = self.base.split("://", 1)[1].split(":")[0]
        findings = bizlogic.run(cfg, profile="production", scope=[host])
        # production → dry-run: finding presente mas não confirmado
        self.assertTrue(all(not f["confirmed"] for f in findings))
```

- [ ] **Step 2: Rodar — falha** · `python3 -m pytest tests/test_bizlogic.py::TestRun -v` → FAIL
- [ ] **Step 3: Implementar (adicionar a `lib/bizlogic.py`)**

```python
from urllib.parse import urlparse

# Mutação real só nestes profiles; production sempre dry-run.
_MUTATE_PROFILES = {"lab", "staging"}
_RACE_WORKERS = {"lab": 10, "staging": 5, "production": 1}


def _in_scope(url, scope):
    if not scope:
        return True
    host = urlparse(url).hostname or ""
    return any(host == s or host.endswith("." + s) for s in scope)


def run(config, profile="staging", scope=None, outdir=None):
    """Executa os testes declarados, respeitando profile/escopo. Retorna findings.

    profile: lab/staging → mutação real (contra sentinela); production → dry-run.
    scope: lista de domínios permitidos; URLs fora são puladas.
    """
    validate_config(config)
    mutate_allowed = profile in _MUTATE_PROFILES
    dry_run = not mutate_allowed
    workers = _RACE_WORKERS.get(profile, 1)
    findings = []

    if not _in_scope(config["base_url"], scope):
        return findings

    for ep in config["endpoints"]:
        for test in ep.get("tests", []):
            try:
                if test == "idor_read":
                    f = test_idor_read(config, ep)
                elif test == "idor_write":
                    f = test_idor_write(config, ep, mutate_allowed, dry_run)
                elif test == "privesc":
                    f = test_privesc(config, ep)
                elif test == "amount_tampering":
                    f = test_amount_tampering(config, ep, "A", mutate_allowed, dry_run)
                elif test == "race":
                    f = test_race(config, ep, "A", workers, mutate_allowed, dry_run)
                elif test == "idempotency":
                    f = test_idempotency(config, ep, "A", mutate_allowed, dry_run)
                else:
                    continue
            except (ValueError, KeyError) as e:
                print(f"  [!] bizlogic: teste {test} em {ep.get('name')} pulado: {e}")
                continue
            if f:
                findings.append(f)

    if outdir:
        os.makedirs(os.path.join(outdir, "raw"), exist_ok=True)
        with open(os.path.join(outdir, "raw", "bizlogic.json"), "w", encoding="utf-8") as fh:
            json.dump(findings, fh, ensure_ascii=False, indent=2)
    return findings
```

- [ ] **Step 4: Rodar — passa** · `python3 -m pytest tests/test_bizlogic.py::TestRun -v` → 3 passed
- [ ] **Step 5: Commit**

```bash
git add lib/bizlogic.py tests/test_bizlogic.py
git commit -m "feat(bizlogic): orquestrador run() com gating de profile e escopo"
```

---

### Task 12: Gate RoE + CLI `main()`

**Files:** Modify `lib/bizlogic.py`, `tests/test_bizlogic.py`

- [ ] **Step 1: Teste que falha**

```python
class TestGateAndCli(unittest.TestCase):
    def test_roe_gate_blocks_non_interactive(self):
        import bizlogic
        self.assertFalse(bizlogic.roe_gate(assume_yes=False, interactive=False))

    def test_roe_gate_assume_yes(self):
        import bizlogic
        self.assertTrue(bizlogic.roe_gate(assume_yes=True))

    def test_parse_args_defaults(self):
        import bizlogic
        a = bizlogic.parse_args(["--config", "c.json", "--profile", "staging"])
        self.assertEqual(a.profile, "staging")
        self.assertFalse(a.roe_accept)
```

- [ ] **Step 2: Rodar — falha** · `python3 -m pytest tests/test_bizlogic.py::TestGateAndCli -v` → FAIL
- [ ] **Step 3: Implementar (adicionar a `lib/bizlogic.py`)**

```python
def roe_gate(assume_yes=False, interactive=None):
    """Confirma autorização antes de testes mutantes. Fail-safe sem TTY/consentimento."""
    if assume_yes:
        return True
    if interactive is None:
        interactive = sys.stdin.isatty()
    print("\n  [RoE] TESTES DE LÓGICA DE NEGÓCIO MUTANTES — uso autorizado apenas")
    if not interactive:
        print("  [RoE] Sem confirmação e sem terminal — abortando mutação.")
        return False
    try:
        return input("  [RoE] Digite EU AUTORIZO para confirmar: ").strip() == "EU AUTORIZO"
    except EOFError:
        return False


def parse_args(argv=None):
    p = argparse.ArgumentParser(description="Detecções de lógica de negócio/authz (red team autorizado).")
    p.add_argument("--config", required=True, help="bizlogic.yaml ou .json")
    p.add_argument("--profile", default="staging", choices=["lab", "staging", "production"])
    p.add_argument("--scope", default="", help="domínios permitidos (separados por vírgula)")
    p.add_argument("--outdir", default=None)
    p.add_argument("--roe-accept", action="store_true", help="auto-confirma o gate RoE (CI/RoE prévio)")
    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    cfg = load_config(args.config)
    scope = [s.strip() for s in args.scope.split(",") if s.strip()]

    # Gate só é exigido quando o profile permite mutação.
    if args.profile in _MUTATE_PROFILES:
        if not roe_gate(assume_yes=args.roe_accept):
            print("  [!] Autorização negada — abortando.")
            return 1

    findings = run(cfg, profile=args.profile, scope=scope, outdir=args.outdir)
    confirmed = sum(1 for f in findings if f["confirmed"])
    print(f"  [✓] bizlogic: {len(findings)} finding(s), {confirmed} confirmado(s).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 4: Rodar — passa** · `python3 -m pytest tests/test_bizlogic.py::TestGateAndCli -v` → 3 passed
- [ ] **Step 5: Commit**

```bash
git add lib/bizlogic.py tests/test_bizlogic.py
git commit -m "feat(bizlogic): gate RoE + CLI main()"
```

---

### Task 13: Wrapper `lib/bizlogic.sh` + profiles

**Files:** Create `lib/bizlogic.sh`; Modify `lib/profiles.conf`

- [ ] **Step 1: Adicionar entradas em `lib/profiles.conf`**

Após as linhas de profile existentes, acrescente:

```bash
PROFILE_BIZLOGIC_MUTATE[lab]=true;   PROFILE_BIZLOGIC_MUTATE[staging]=true;   PROFILE_BIZLOGIC_MUTATE[production]=false
PROFILE_BIZLOGIC_TIMEOUT[lab]=900;   PROFILE_BIZLOGIC_TIMEOUT[staging]=600;   PROFILE_BIZLOGIC_TIMEOUT[production]=300
```

(Declare os arrays associativos no topo junto aos demais `declare -A PROFILE_*` se o arquivo os declarar explicitamente.)

- [ ] **Step 2: Criar `lib/bizlogic.sh`**

```bash
#!/usr/bin/env bash
# bizlogic.sh — wrapper da fase de lógica de negócio/authz do Stiglitz RED.
# Aplica profile, escopo e timeout, e delega a lib/bizlogic.py.
# Uso: bizlogic.sh <scan_dir> <profile> <config> [scope_csv] [roe_accept]
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

SCAN_DIR="${1:?scan_dir}"; PROFILE="${2:-staging}"; CONFIG="${3:?config}"
SCOPE_CSV="${4:-}"; ROE_ACCEPT="${5:-}"

if [ ! -f "$CONFIG" ]; then
    echo "  [○] bizlogic: config não encontrado ($CONFIG) — fase pulada."
    exit 0
fi

ARGS=(--config "$CONFIG" --profile "$PROFILE" --outdir "$SCAN_DIR")
[ -n "$SCOPE_CSV" ] && ARGS+=(--scope "$SCOPE_CSV")
[ "$ROE_ACCEPT" = "1" ] && ARGS+=(--roe-accept)

python3 "$SCRIPT_DIR/bizlogic.py" "${ARGS[@]}"
RC=$?
command -v audit &>/dev/null && audit "PHASE_END name=bizlogic result=$([ $RC -eq 0 ] && echo ok || echo fail)"
exit $RC
```

- [ ] **Step 3: Validar sintaxe**

Run: `bash -n lib/bizlogic.sh && echo OK`
Expected: OK

- [ ] **Step 4: Commit**

```bash
git add lib/bizlogic.sh lib/profiles.conf
chmod +x lib/bizlogic.sh
git commit -m "feat(bizlogic): wrapper .sh + entradas de profile"
```

---

### Task 14: Ingestão em `lib/ingest.py` + fase no `stiglitz_red.sh`

**Files:** Modify `lib/ingest.py`, `stiglitz_red.sh`, `tests/test_bizlogic.py`

- [ ] **Step 1: Teste que falha (ingestão)**

```python
class TestIngest(unittest.TestCase):
    def test_parse_bizlogic_reads_file(self):
        import ingest
        import tempfile
        d = tempfile.mkdtemp()
        os.makedirs(os.path.join(d, "raw"))
        with open(os.path.join(d, "raw", "bizlogic.json"), "w") as f:
            json.dump([{"name": "x", "vuln_class": "idor_read_pii", "url": "http://h/a",
                        "confirmed": True, "severity": "high"}], f)
        out = ingest.parse_bizlogic(d)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["vuln_class"], "idor_read_pii")
```

- [ ] **Step 2: Rodar — falha** · `python3 -m pytest tests/test_bizlogic.py::TestIngest -v` → FAIL
- [ ] **Step 3: Implementar `parse_bizlogic` em `lib/ingest.py`**

Adicione (seguindo o padrão das outras `parse_*`):

```python
def parse_bizlogic(scan_dir: str) -> list:
    """Lê raw/bizlogic.json (findings de lógica de negócio/authz)."""
    data = _load_json(os.path.join(scan_dir, "raw", "bizlogic.json"))
    return data if isinstance(data, list) else []
```

E garanta que os findings de bizlogic sejam incluídos na lista consolidada que o RED report processa (no ponto onde as outras fontes são reunidas — procure por onde `parse_findings`/`parse_nuclei` são combinados e some `parse_bizlogic(scan_dir)`).

- [ ] **Step 4: Rodar — passa** · `python3 -m pytest tests/test_bizlogic.py::TestIngest -v` → PASS

- [ ] **Step 5: Adicionar a fase no `stiglitz_red.sh`**

Localize a sequência de fases (procure `phase_banner`/`audit "PHASE_START`). Após a fase de ingestão e antes dos exploits, adicione:

```bash
# ── Fase: Lógica de negócio / Authz ───────────────────────────────────────
command -v audit &>/dev/null && audit "PHASE_START name=bizlogic"
BIZLOGIC_CONFIG="${BIZLOGIC_CONFIG:-$SCAN_DIR/bizlogic.yaml}"
[ -f "$BIZLOGIC_CONFIG" ] || BIZLOGIC_CONFIG="${BIZLOGIC_CONFIG%.yaml}.json"
if [ -f "$BIZLOGIC_CONFIG" ]; then
    phase_banner "LÓGICA DE NEGÓCIO / AUTHZ (IDOR/BOLA/privesc/amount/race)"
    bash "$LIB_DIR/bizlogic.sh" "$SCAN_DIR" "$PROFILE" "$BIZLOGIC_CONFIG" \
        "${SCOPE_DOMAINS:-}" "$([ "$ROE_CONFIRMED" = "1" ] && echo 1 || echo 0)" || true
else
    echo -e "  ${YELLOW}[○] bizlogic: sem config (\$BIZLOGIC_CONFIG) — fase pulada${NC}"
fi
```

(Ajuste `LIB_DIR`, `PROFILE`, `SCOPE_DOMAINS`, `ROE_CONFIRMED` aos nomes reais das variáveis em `stiglitz_red.sh` — verifique lendo o cabeçalho do script. Se o RED já mantém uma variável de "RoE aceito", reuse-a para passar o auto-accept.)

- [ ] **Step 6: Validar sintaxe** · Run: `bash -n stiglitz_red.sh && echo OK` → OK
- [ ] **Step 7: Commit**

```bash
git add lib/ingest.py stiglitz_red.sh tests/test_bizlogic.py
git commit -m "feat(bizlogic): ingestão + fase no stiglitz_red.sh"
```

---

### Task 15: Integração com criticidade + dep de teste + CI

**Files:** Modify `requirements-dev.txt`, `.github/workflows/ci.yml`, `tests/test_bizlogic.py`

- [ ] **Step 1: Teste de integração com o motor de criticidade**

```python
class TestCriticalityIntegration(unittest.TestCase):
    def test_confirmed_bizlogic_finding_scored_high_on_funds(self):
        import criticality
        findings = [{"name": "IDOR write", "vuln_class": "idor_write", "severity": "high",
                     "url": "https://app-gateway-cielo.hml2.example.com/api/transfer",
                     "confirmed": True}]
        criticality.enrich_findings(findings)
        f = findings[0]
        self.assertIn("cvss_environmental", f)
        self.assertEqual(f["asset_class"], "funds")
        self.assertIn(f["severity"], ("high", "critical"))
        self.assertEqual(f["score_source"], "catalog")
```

- [ ] **Step 2: Rodar** · `python3 -m pytest tests/test_bizlogic.py::TestCriticalityIntegration -v`
Expected: PASS (o motor da Fase 0 já resolve `idor_write` via catálogo, `funds` via inferência de host, `confirmed`→E:H). Se falhar, investigar o motor — não criar workaround.

- [ ] **Step 3: Adicionar PyYAML como dep de teste**

Acrescente ao final de `requirements-dev.txt`:

```
PyYAML>=6.0
```

E adicione um teste do caminho YAML:

```python
class TestYamlConfig(unittest.TestCase):
    def test_load_yaml(self):
        import bizlogic
        import tempfile
        y = ("base_url: http://localhost:1\n"
             "accounts: {A: {auth: {type: bearer, token: t}, id: '1'}}\n"
             "endpoints: [{name: e, method: GET, path: /x, tests: [idor_read]}]\n")
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
            f.write(y); path = f.name
        cfg = bizlogic.load_config(path)
        self.assertEqual(cfg["base_url"], "http://localhost:1")
        os.unlink(path)
```

- [ ] **Step 4: Incluir no CI** — em `.github/workflows/ci.yml`, na linha do pytest de unit tests, acrescente `tests/test_bizlogic.py`:

```yaml
        run: python3 -m pytest tests/test_lib.py tests/test_stiglitz_modules.py tests/test_pipeline.py tests/test_e2e.py tests/test_email_spoof.py tests/test_criticality.py tests/test_bizlogic.py -v --tb=short
```

- [ ] **Step 5: Rodar a suíte completa**

Run: `python3 -m pytest tests/test_lib.py tests/test_stiglitz_modules.py tests/test_pipeline.py tests/test_e2e.py tests/test_email_spoof.py tests/test_criticality.py tests/test_bizlogic.py -q`
Expected: PASS (tudo)

- [ ] **Step 6: Commit**

```bash
git add requirements-dev.txt .github/workflows/ci.yml tests/test_bizlogic.py
git commit -m "feat(bizlogic): integração com criticidade + YAML + CI"
```

---

### Task 16: Documentação (CLAUDE.md + README + bizlogic.example.yaml)

**Files:** Create `bizlogic.example.yaml`; Modify `README.md`, `CLAUDE.md` (ambos), `.gitignore`/`.dockerignore` se necessário

- [ ] **Step 1: Criar `bizlogic.example.yaml`** com o exemplo da seção 5 do spec (contas fictícias, endpoints ilustrativos), como template para o operador.

- [ ] **Step 2: Documentar** — adicionar `lib/bizlogic.py`/`bizlogic.sh` à tabela de componentes do README e à lista de scripts do CLAUDE.md, com exemplo de uso:

```bash
python3 lib/bizlogic.py --config bizlogic.yaml --scope target.com --profile staging --outdir scan_dir/
```

E uma nota: production = dry-run; mutação exige profile lab/staging + "EU AUTORIZO".

- [ ] **Step 3: Whitelist** — garantir que `bizlogic.example.yaml` e (se versionado) os novos arquivos estejam permitidos no `.gitignore` (whitelist). Adicionar `!/bizlogic.example.yaml` e confirmar que `lib/`/`tests/` já cobrem os novos módulos.

- [ ] **Step 4: Rodar a suíte completa final + bash**

Run: `python3 -m pytest tests/ -q` e `bash tests/test_stiglitz_red.sh`
Expected: tudo verde

- [ ] **Step 5: Commit**

```bash
git add bizlogic.example.yaml README.md .gitignore
git commit -m "docs(bizlogic): exemplo de config + documentação"
```

---

## Self-Review (preenchido)

- **Cobertura do spec:** §4 componentes → Tasks 1-3,11-14; §5 yaml → Tasks 1,15; §6.1 IDOR read → Task 7; §6.2 write/privesc → Task 8; §6.3 amount → Task 9; §6.4 race/idem → Task 10; §7 gating (profile/RoE/escopo/sentinela) → Tasks 11,12; §8 saída/ingestão/criticidade → Tasks 11,14,15; §9 erros → Tasks 3,11 (exceções tipadas, sem except mudo); §10 testes/app falso → Tasks 6-10; §12 critérios de aceite → Tasks 7-15. Todos cobertos.
- **Placeholders:** nenhum passo de código sem código. As Tasks 13-14 começam com localização (grep/leitura) porque tocam scripts existentes (`profiles.conf`, `stiglitz_red.sh`, `ingest.py`) cujos pontos exatos variam; o código a inserir é fornecido na íntegra.
- **Consistência de tipos:** todas as famílias retornam o dict de `_finding(...)`; `run()` despacha por nome de teste consistente com os nomes em `tests`; `vuln_class` (idor_read_pii/idor_write/priv_escalation/amount_tampering/race_condition_funds) batem com o catálogo da Fase 0; assinaturas (`mutate_allowed, dry_run`) consistentes entre as famílias mutantes.

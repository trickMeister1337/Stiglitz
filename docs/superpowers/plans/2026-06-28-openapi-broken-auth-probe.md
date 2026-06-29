# OpenAPI Broken-Auth Probe (P0.1 núcleo) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Detectar *broken authentication* zero-credencial — endpoint documentado no OpenAPI/Swagger como protegido (`security:`) que responde 2xx com dados reais a uma requisição **sem credencial** → finding High (CWE-306).

**Architecture:** Novo módulo `lib/openapi_probe.py` (lógica pura + `fetch_fn` injetável + CLI), no padrão `bola.py`/`openapi_seed.py`. Consome `raw/openapi_spec.json` (já produzido na Fase 4 por `discover_openapi_urls`/`openapi_discover.py`). Reusa `bola.extract_canary`/`bola.is_safe_method` e `openapi_seed._prefix`. Integra na Fase 4 do `stiglitz.sh` (onde o spec está garantidamente disponível, junto ao aviso de coverage-gap) e grava `raw/openapi_authz.json`, ingerido pelo `stiglitz_report.py` como mais um `*_findings.json`.

**Tech Stack:** Python 3 (stdlib `urllib` + `netproxy` p/ proxy/mTLS), bash (`stiglitz.sh`), pytest.

## Global Constraints

- Módulos novos = **lógica pura + CLI primeiro**, integração depois (padrão `bola.py`/`takeover.py`).
- **Só métodos seguros** (GET/HEAD/OPTIONS) por padrão — não-destrutivo (RoE). Reusar `bola.is_safe_method`.
- HTTP ao alvo **sempre** via `netproxy.urlopen` (herda `--proxy` + mTLS). Nunca `urllib.urlopen` direto.
- **Texto dos findings em inglês** (deliverable); mensagens de console em **PT-BR**.
- Fail-safe: spec ausente/inválido, fetch que estoura → degrada para 0 findings, nunca aborta.
- Commits pequenos; cada commit com `python3 -m py_compile` limpo. Footer do commit:
  `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`
- Convenção de teste: `sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))`.

---

### Task 1: Parsing do spec — operações documentadas + requisito de auth

**Files:**
- Create: `lib/openapi_probe.py`
- Test: `tests/test_openapi_probe.py`

**Interfaces:**
- Consumes: `openapi_seed._prefix(spec) -> str` (prefixo basePath/servers).
- Produces:
  - `documented_operations(spec) -> list[dict]` — cada item `{"path": str, "method": str (UPPER), "requires_auth": bool}`. Aceita `spec` dict ou texto JSON.
  - `op_url(spec, base_url, path, sample="1") -> str` — URL absoluta com prefixo aplicado e `{param}` resolvido.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_openapi_probe.py
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
import openapi_probe as P


def test_documented_operations_marks_global_security():
    spec = {
        "security": [{"oauth2": []}],
        "paths": {
            "/accounts/{id}": {"get": {}, "post": {}},
            "/public/health": {"get": {"security": []}},
        },
    }
    ops = P.documented_operations(spec)
    by = {(o["path"], o["method"]): o["requires_auth"] for o in ops}
    assert by[("/accounts/{id}", "GET")] is True
    assert by[("/accounts/{id}", "POST")] is True
    # security: [] na operação remove a exigência global -> público
    assert by[("/public/health", "GET")] is False


def test_documented_operations_operation_level_security():
    spec = {"paths": {"/x": {"get": {"security": [{"bearer": []}]}}}}
    ops = P.documented_operations(spec)
    assert ops[0]["requires_auth"] is True


def test_documented_operations_no_security_anywhere_is_false():
    spec = {"paths": {"/x": {"get": {}}}}
    assert P.documented_operations(spec)[0]["requires_auth"] is False


def test_op_url_applies_prefix_and_resolves_param():
    spec = {"basePath": "/api/v1", "paths": {}}
    assert P.op_url(spec, "https://t.example", "/accounts/{id}") == \
        "https://t.example/api/v1/accounts/1"


def test_documented_operations_accepts_json_text_and_bad_input():
    assert P.documented_operations("not json") == []
    assert P.documented_operations({"paths": "nope"}) == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_openapi_probe.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'openapi_probe'`

- [ ] **Step 3: Write minimal implementation**

```python
# lib/openapi_probe.py
#!/usr/bin/env python3
"""openapi_probe.py — P0.1 (núcleo): OpenAPI/Swagger como motor de detecção de
broken-auth ZERO-credencial. Para cada operação documentada como protegida
(`security:`), faz uma requisição SEM credencial e confirma 'Missing Authentication'
(CWE-306) quando o endpoint responde 2xx com dados reais.

Lógica pura + fetch injetável + CLI. Reusa bola.extract_canary/is_safe_method e
openapi_seed._prefix. Só métodos seguros (GET/HEAD/OPTIONS) por padrão.
"""
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from openapi_seed import _prefix as _spec_prefix

_PARAM = re.compile(r"\{[^}]+\}")
_HTTP_METHODS = ("get", "put", "post", "delete", "options", "head", "patch", "trace")


def _as_dict(spec):
    if isinstance(spec, str):
        try:
            spec = json.loads(spec)
        except (ValueError, TypeError):
            return None
    return spec if isinstance(spec, dict) else None


def _op_requires_auth(spec, operation):
    """True se a operação exige auth. security:[] na operação remove a global."""
    op_sec = operation.get("security")
    if op_sec is not None:
        return bool(op_sec)
    return bool(spec.get("security"))


def documented_operations(spec):
    """Lista de {path, method(UPPER), requires_auth} para cada operação do spec."""
    spec = _as_dict(spec)
    if spec is None:
        return []
    paths = spec.get("paths")
    if not isinstance(paths, dict):
        return []
    out = []
    for raw, item in paths.items():
        if not isinstance(raw, str) or not raw.startswith("/") or not isinstance(item, dict):
            continue
        for method, operation in item.items():
            if method.lower() not in _HTTP_METHODS or not isinstance(operation, dict):
                continue
            out.append({
                "path": raw,
                "method": method.upper(),
                "requires_auth": _op_requires_auth(spec, operation),
            })
    return out


def op_url(spec, base_url, path, sample="1"):
    """URL absoluta: prefixo (basePath/servers) aplicado + {param} resolvido."""
    spec = _as_dict(spec) or {}
    prefix = _spec_prefix(spec)
    root = base_url.rstrip("/")
    full = path if (not prefix or path.startswith(prefix)) else prefix + path
    return _PARAM.sub(sample, root + full)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_openapi_probe.py -v`
Expected: PASS (5 testes)

- [ ] **Step 5: Commit**

```bash
git add lib/openapi_probe.py tests/test_openapi_probe.py
git commit -m "feat(openapi-probe): parse spec — operações documentadas + requisito de auth

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 2: Veredito da resposta sem credencial (`unauth_verdict`)

**Files:**
- Modify: `lib/openapi_probe.py`
- Test: `tests/test_openapi_probe.py`

**Interfaces:**
- Consumes: `bola.extract_canary(body, content_type) -> set` (sinal de "dados reais": emails/CPFs/UUIDs/ids).
- Produces: `unauth_verdict(status, body, content_type="") -> dict` com chaves `{"state", "severity", "confidence"}`.
  - `state ∈ {"PROTECTED", "BROKEN_AUTH", "INCONCLUSIVE"}`.
  - `BROKEN_AUTH` ⇒ `severity="high"`, `confidence>=70`. Demais ⇒ `severity="info"`.

- [ ] **Step 1: Write the failing test**

```python
def test_verdict_denied_is_protected():
    for s in (401, 403, 302, 301):
        assert P.unauth_verdict(s, '{"data":1}', "application/json")["state"] == "PROTECTED"


def test_verdict_2xx_with_pii_is_broken_auth_high():
    body = '{"users":[{"id":7,"email":"alice@bank.example"}]}'
    v = P.unauth_verdict(200, body, "application/json")
    assert v["state"] == "BROKEN_AUTH"
    assert v["severity"] == "high"
    assert v["confidence"] >= 80


def test_verdict_2xx_json_without_pii_is_broken_auth():
    v = P.unauth_verdict(200, '{"balance": 1234, "currency": "BRL"}', "application/json")
    assert v["state"] == "BROKEN_AUTH"
    assert v["severity"] == "high"


def test_verdict_2xx_auth_error_envelope_is_protected():
    # API que devolve 200 + corpo de erro de auth (anti-FP)
    v = P.unauth_verdict(200, '{"error":"Unauthorized: token missing"}', "application/json")
    assert v["state"] == "PROTECTED"


def test_verdict_2xx_empty_or_tiny_is_inconclusive():
    assert P.unauth_verdict(200, "", "application/json")["state"] == "INCONCLUSIVE"
    assert P.unauth_verdict(200, "ok", "text/plain")["state"] == "INCONCLUSIVE"


def test_verdict_404_405_5xx_inconclusive():
    for s in (404, 405, 500):
        assert P.unauth_verdict(s, "x", "")["state"] == "INCONCLUSIVE"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_openapi_probe.py -k verdict -v`
Expected: FAIL with `AttributeError: module 'openapi_probe' has no attribute 'unauth_verdict'`

- [ ] **Step 3: Write minimal implementation**

Adicionar ao topo de `lib/openapi_probe.py` (junto aos outros imports):

```python
from bola import extract_canary, is_safe_method
```

Adicionar a constante (após `_HTTP_METHODS`):

```python
_AUTH_ERR = re.compile(
    r"unauthor|forbidden|access\s+denied|not\s+authenticated|"
    r"missing\s+(?:token|auth)|invalid\s+token|token\s+(?:expired|missing)|"
    r"please\s+log\s*in|login\s+required",
    re.I,
)
```

Adicionar a função:

```python
def unauth_verdict(status, body, content_type=""):
    """Veredito da resposta SEM credencial a um endpoint documentado como protegido.
      PROTECTED    — 401/403/3xx, ou 2xx cujo corpo é envelope de erro de auth.
      BROKEN_AUTH  — 2xx com dados reais (estruturado, canário, ou corpo substancial) → High.
      INCONCLUSIVE — 2xx vazio/curto, 404/405, 5xx.
    """
    s = int(status or 0)
    if s in (401, 403) or 300 <= s < 400:
        return {"state": "PROTECTED", "severity": "info", "confidence": 0}
    if not (200 <= s < 300):
        return {"state": "INCONCLUSIVE", "severity": "info", "confidence": 20}
    text = body or ""
    if not text.strip():
        return {"state": "INCONCLUSIVE", "severity": "info", "confidence": 25}
    if _AUTH_ERR.search(text[:512]):
        return {"state": "PROTECTED", "severity": "info", "confidence": 0}
    canary = extract_canary(text, content_type)
    ct = (content_type or "").lower()
    structured = ("json" in ct or "xml" in ct or text.lstrip()[:1] in ("{", "["))
    if canary:
        return {"state": "BROKEN_AUTH", "severity": "high", "confidence": 90}
    if structured or len(text) >= 64:
        return {"state": "BROKEN_AUTH", "severity": "high", "confidence": 70}
    return {"state": "INCONCLUSIVE", "severity": "info", "confidence": 40}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_openapi_probe.py -v`
Expected: PASS (todos)

- [ ] **Step 5: Commit**

```bash
git add lib/openapi_probe.py tests/test_openapi_probe.py
git commit -m "feat(openapi-probe): veredito unauth (BROKEN_AUTH/PROTECTED/INCONCLUSIVE) anti-FP

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 3: Catálogo CWE-306 + construção do finding

**Files:**
- Modify: `lib/vuln_catalog.py` (adicionar classe `broken_auth_documented`)
- Modify: `lib/openapi_probe.py` (adicionar `build_finding`)
- Test: `tests/test_openapi_probe.py`

**Interfaces:**
- Produces: `build_finding(op, url, verdict_res, status) -> dict` — finding normalizado p/ o report. Campos: `type, name, severity, cwe, url, method, confirmed, confidence, source, tool, description, evidence`.
- Catálogo: `vuln_catalog.CATALOG["broken_auth_documented"]` com `cwe="CWE-306"`.

- [ ] **Step 1: Write the failing test**

```python
import vuln_catalog


def test_catalog_has_broken_auth_documented():
    e = vuln_catalog.CATALOG["broken_auth_documented"]
    assert e["cwe"] == "CWE-306"
    assert "AV:N" in e["vector"]
    assert e["title"]


def test_build_finding_shape():
    op = {"path": "/accounts/{id}", "method": "GET", "requires_auth": True}
    v = {"state": "BROKEN_AUTH", "severity": "high", "confidence": 90}
    f = P.build_finding(op, "https://t.example/accounts/1", v, 200)
    assert f["type"] == "broken_auth_documented"
    assert f["severity"] == "high"
    assert f["cwe"] == "CWE-306"
    assert f["url"] == "https://t.example/accounts/1"
    assert f["method"] == "GET"
    assert f["confirmed"] is True
    assert f["source"] == "openapi_probe"
    # texto do deliverable em inglês
    assert "OpenAPI" in f["description"] or "Swagger" in f["description"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_openapi_probe.py -k "catalog_has_broken_auth_documented or build_finding" -v`
Expected: FAIL (`KeyError: 'broken_auth_documented'` e `AttributeError: build_finding`)

- [ ] **Step 3: Write minimal implementation**

Em `lib/vuln_catalog.py`, dentro do dict `CATALOG`, logo após a entrada `"broken_auth":`:

```python
    "broken_auth_documented": {"cwe": "CWE-306", "title": "Missing authentication on documented-protected endpoint",
                           "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
```

Em `lib/openapi_probe.py`, adicionar:

```python
def build_finding(op, url, verdict_res, status):
    """Finding normalizado (texto EN — deliverable) para o broken-auth documentado."""
    return {
        "type": "broken_auth_documented",
        "name": "Missing Authentication on Documented-Protected Endpoint",
        "severity": verdict_res["severity"],
        "cwe": "CWE-306",
        "url": url,
        "method": op["method"],
        "confirmed": verdict_res["confidence"] >= 80,
        "confidence": verdict_res["confidence"],
        "source": "openapi_probe",
        "tool": "openapi_probe",
        "description": (
            "An endpoint documented in the OpenAPI/Swagger specification as requiring "
            "authentication (a security requirement is declared) returned HTTP %s with a "
            "data-bearing body in response to an UNAUTHENTICATED request. Authentication "
            "is not enforced at runtime, exposing the documented resource without credentials."
            % status
        ),
        "evidence": "Unauthenticated %s %s -> HTTP %s (verdict=%s, confidence=%s%%)" % (
            op["method"], url, status, verdict_res["state"], verdict_res["confidence"]),
    }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_openapi_probe.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add lib/vuln_catalog.py lib/openapi_probe.py tests/test_openapi_probe.py
git commit -m "feat(openapi-probe): catálogo CWE-306 + build_finding (texto EN)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 4: Orquestração — `probe` + `run` + fetch via netproxy + CLI

**Files:**
- Modify: `lib/openapi_probe.py`
- Test: `tests/test_openapi_probe.py`

**Interfaces:**
- Produces:
  - `probe(spec, base_url, fetch_fn, safe_only=True, sample="1") -> list[dict]` — itera operações que exigem auth; `fetch_fn(url, method) -> (status:int, body:str, content_type:str)`. Só emite findings `BROKEN_AUTH`.
  - `run(spec_path, base_url, outdir, fetch_fn=_default_fetch) -> int` — grava `<outdir>/raw/openapi_authz.json`, retorna a contagem.
  - `_default_fetch(url, method, timeout=10) -> (status, body, content_type)` — usa `netproxy.urlopen` (proxy+mTLS).
  - `main(argv=None) -> int` — CLI `openapi_probe.py <spec.json> <base_url> [outdir]`.

- [ ] **Step 1: Write the failing test**

```python
import json, tempfile


def test_probe_only_emits_broken_auth_for_protected_safe_ops():
    spec = {
        "security": [{"oauth2": []}],
        "paths": {
            "/accounts/{id}": {"get": {}},          # protegido + GET -> sondado
            "/accounts/{id}/close": {"post": {}},   # protegido mas POST -> pulado (safe_only)
            "/public": {"get": {"security": []}},   # público -> pulado
        },
    }
    calls = []
    def fake_fetch(url, method):
        calls.append((method, url))
        return (200, '{"id":1,"email":"x@y.example"}', "application/json")
    findings = P.probe(spec, "https://t.example", fake_fetch)
    # só o GET protegido foi para a rede
    assert calls == [("GET", "https://t.example/accounts/1")]
    assert len(findings) == 1
    assert findings[0]["type"] == "broken_auth_documented"


def test_probe_skips_when_protected_endpoint_denies():
    spec = {"security": [{"x": []}], "paths": {"/a": {"get": {}}}}
    findings = P.probe(spec, "https://t.example", lambda u, m: (401, "", ""))
    assert findings == []


def test_run_writes_openapi_authz_json():
    spec = {"security": [{"x": []}], "paths": {"/a": {"get": {}}}}
    with tempfile.TemporaryDirectory() as d:
        sp = os.path.join(d, "spec.json")
        json.dump(spec, open(sp, "w"))
        n = P.run(sp, "https://t.example", d,
                  fetch_fn=lambda u, m: (200, '{"k":"vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv"}', "application/json"))
        assert n == 1
        out = json.load(open(os.path.join(d, "raw", "openapi_authz.json")))
        assert out[0]["cwe"] == "CWE-306"


def test_run_missing_spec_returns_zero():
    with tempfile.TemporaryDirectory() as d:
        assert P.run(os.path.join(d, "nope.json"), "https://t.example", d) == 0
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_openapi_probe.py -k "probe or run" -v`
Expected: FAIL (`AttributeError: 'probe'`)

- [ ] **Step 3: Write minimal implementation**

Adicionar imports no topo de `lib/openapi_probe.py`:

```python
import urllib.request
import urllib.error
import netproxy
```

Adicionar funções:

```python
def probe(spec, base_url, fetch_fn, safe_only=True, sample="1"):
    """Sonda cada operação documentada-protegida SEM credencial. Retorna findings BROKEN_AUTH."""
    findings = []
    for op in documented_operations(spec):
        if not op["requires_auth"]:
            continue
        if safe_only and not is_safe_method(op["method"]):
            continue
        url = op_url(spec, base_url, op["path"], sample=sample)
        try:
            status, body, content_type = fetch_fn(url, op["method"])
        except Exception:
            continue
        v = unauth_verdict(status, body, content_type)
        if v["state"] == "BROKEN_AUTH":
            findings.append(build_finding(op, url, v, status))
    return findings


def _default_fetch(url, method, timeout=10):
    """Fetch real via netproxy (herda --proxy + mTLS). Retorna (status, body, content_type)."""
    req = urllib.request.Request(url, method=method,
                                 headers={"Accept": "application/json, */*"})
    try:
        with netproxy.urlopen(req, timeout=timeout) as resp:
            body = resp.read(65536).decode("utf-8", "replace")
            return resp.status, body, resp.headers.get("content-type", "")
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read(65536).decode("utf-8", "replace")
        except Exception:
            pass
        ct = e.headers.get("content-type", "") if getattr(e, "headers", None) else ""
        return e.code, body, ct


def run(spec_path, base_url, outdir, fetch_fn=_default_fetch):
    """Lê o spec, sonda, grava <outdir>/raw/openapi_authz.json. Retorna a contagem."""
    try:
        with open(spec_path, encoding="utf-8") as f:
            spec = json.load(f)
    except (OSError, ValueError):
        return 0
    findings = probe(spec, base_url, fetch_fn)
    raw = os.path.join(outdir, "raw")
    try:
        os.makedirs(raw, exist_ok=True)
        with open(os.path.join(raw, "openapi_authz.json"), "w", encoding="utf-8") as f:
            json.dump(findings, f, indent=2)
    except OSError:
        pass
    return len(findings)


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) < 2:
        print("uso: openapi_probe.py <spec.json> <base_url> [outdir]", file=sys.stderr)
        return 2
    outdir = argv[2] if len(argv) > 2 else "."
    print(run(argv[0], argv[1], outdir))
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_openapi_probe.py -v`
Expected: PASS (todos)

- [ ] **Step 5: Commit**

```bash
git add lib/openapi_probe.py tests/test_openapi_probe.py
git commit -m "feat(openapi-probe): probe/run + fetch via netproxy + CLI

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 5: Integração no scan (stiglitz.sh Fase 4) + ingestão no relatório

**Files:**
- Modify: `stiglitz.sh` (bloco após `discover_openapi_urls`, ~linha 1264)
- Modify: `stiglitz_report.py` (lista de tuplas `*_findings.json`, ~linha 951)

**Interfaces:**
- Consumes: `lib/openapi_probe.py main` (CLI), `raw/openapi_spec.json`, `$TARGET`, `$OUTDIR`.
- Produces: `raw/openapi_authz.json` ingerido pelo `stiglitz_report.py` em `version_findings`.

- [ ] **Step 1: Adicionar a ingestão no relatório**

Em `stiglitz_report.py`, na lista de tuplas (logo após `('bizlogic_findings.json',   'bizlogic_findings'),`), adicionar:

```python
    ('openapi_authz.json',       'openapi_authz'),
```

- [ ] **Step 2: Adicionar o bloco de sondagem no `stiglitz.sh`**

Localizar o fechamento do bloco `discover_openapi_urls` (a linha `fi` imediatamente após `unset _oa_n`, ~linha 1264) e inserir logo após:

```bash
    # ── P0.1: OpenAPI como motor — broken-auth ZERO-credencial ──────────────
    # O spec documenta quais endpoints exigem auth (security:). Sondamos cada um
    # SEM credencial: 2xx com dados reais = autenticação não aplicada (CWE-306),
    # achado High confirmável que independe de token. Complementa o aviso de
    # coverage-gap acima (em vez de só avisar "não testado", testamos o que dá).
    if [ -s "$OUTDIR/raw/openapi_spec.json" ]; then
        _ba_n=$(timeout 180 python3 "$SCRIPT_DIR/lib/openapi_probe.py" \
                  "$OUTDIR/raw/openapi_spec.json" "$TARGET" "$OUTDIR" 2>/dev/null || echo 0)
        if [ "${_ba_n:-0}" -gt 0 ]; then
            echo -e "  ${RED}[!] OpenAPI broken-auth: ${_ba_n} endpoint(s) documentado(s) como protegido(s) respondem SEM credencial (CWE-306)${NC}"
        else
            echo -e "  ${GREEN}[✓]${NC} OpenAPI broken-auth: nenhum endpoint protegido respondeu sem credencial"
        fi
        unset _ba_n
    fi
```

- [ ] **Step 3: Validar sintaxe e compilação**

Run:
```bash
bash -n stiglitz.sh && python3 -m py_compile stiglitz_report.py lib/openapi_probe.py lib/vuln_catalog.py && echo OK
```
Expected: `OK`

- [ ] **Step 4: Validação ao vivo (Juice Shop ou spec local)**

Criar um spec mínimo e rodar o CLI contra um alvo controlado (`http://localhost:3000` Juice Shop, ou um stub):

Run:
```bash
printf '%s' '{"security":[{"x":[]}],"paths":{"/rest/products":{"get":{}}}}' > /tmp/spec.json
mkdir -p /tmp/oaprobe/raw
python3 lib/openapi_probe.py /tmp/spec.json http://localhost:3000 /tmp/oaprobe
cat /tmp/oaprobe/raw/openapi_authz.json
```
Expected: um inteiro impresso (≥0) e um JSON (lista, possivelmente vazia se o alvo negar/estiver off). Sem stacktrace.

- [ ] **Step 5: Rodar a suíte e o lint**

Run:
```bash
python3 -m pytest tests/test_openapi_probe.py -v && \
shellcheck --severity=warning stiglitz.sh && echo OK
```
Expected: testes PASS; shellcheck sem novos warnings; `OK`

- [ ] **Step 6: Commit**

```bash
git add stiglitz.sh stiglitz_report.py
git commit -m "feat(scan): P0.1 OpenAPI broken-auth probe na Fase 4 + ingestão no relatório

Sonda endpoints documentados como protegidos SEM credencial; 2xx com dados
reais = CWE-306 (Missing Authentication). raw/openapi_authz.json ingerido
pelo stiglitz_report.py. Converte o caso 'Swagger público + 0 High' em
achado real zero-cred.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Self-Review

**1. Spec coverage (roadmap P0.1 núcleo):**
- "broken-auth em endpoint documentado com `security:` que responde 2xx sem token" → Tasks 1 (requires_auth) + 2 (verdict) + 4 (probe). ✓
- "request method-aware" → `documented_operations` preserva o método; `_default_fetch` usa `method=`. ✓ (sondagem ativa limitada a métodos seguros por RoE — métodos mutantes documentados ficam p/ P0.1b).
- "reusa canário do `bola.py`" → `extract_canary` no `unauth_verdict`. ✓
- "consome `raw/openapi_spec.json`; netproxy/mtls" → Tasks 4/5. ✓
- "resolve o ⏳ OpenAPI seeding mutante" → **parcial**: este plano cobre só GET-safe broken-auth; o seeding mutante (POST/PUT via schema → `nuclei -dast`) é o follow-up **P0.1b** (fora de escopo aqui, por desenho — ver Não-objetivos do roadmap). Anotado, não é gap.

**2. Placeholder scan:** nenhum TBD/TODO; todo passo de código tem código completo. ✓

**3. Type consistency:** `documented_operations` retorna `{path, method, requires_auth}` — consumido igual em `probe`/`build_finding`. `unauth_verdict` retorna `{state, severity, confidence}` — consumido em `probe`/`build_finding`. `fetch_fn(url, method) -> (status, body, content_type)` — assinatura idêntica no fake de teste, no `_default_fetch` e na chamada em `probe`. ✓

**4. Ambiguidade:** "dados reais" definido explicitamente no `unauth_verdict` (estruturado OU canário OU len≥64, menos envelope de erro de auth). ✓

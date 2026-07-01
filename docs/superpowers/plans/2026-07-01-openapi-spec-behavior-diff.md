# OpenAPI Spec-vs-Behavior Diff Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Detectar duas divergências spec-vs-comportamento numa API documentada — Excessive Data Exposure (resposta com campos fora do schema) e Shadow Endpoint (path observado ∉ spec) — num módulo novo `lib/openapi_diff.py`.

**Architecture:** Módulo puro + fetch injetável + CLI (padrão `openapi_probe.py`). Reusa `_as_dict`/`documented_operations`/`op_url`/`unauth_verdict` de `openapi_probe`, e `pii_detect`/`pan_scanner`/`bola.extract_canary` para classificar dado sensível. Novo resolver de schema (`$ref` → `components/schemas`/`definitions`). Wired na Fase 4 do `stiglitz.sh` (após o broken-auth) e ingerido no `stiglitz_report.py` (uma linha na lista de ingest genérica).

**Tech Stack:** Python 3 stdlib (json/re/urllib), pytest. Sem dependências novas.

## Global Constraints

- **Idioma:** findings/relatório em **inglês** (deliverable); console/comentários/docstrings em **PT-BR**.
- **Não-destrutivo:** SOMENTE GET (excessive reusa respostas já buscadas; shadow é set-diff; a elevação opcional de shadow faz GET).
- **Fail-safe:** sem spec / sem schema resolvível / sem `katana_urls.txt` → no-op parcial ou total; nunca inventa finding sem baseline.
- **Findings `estimated`:** ingest no report NÃO seta `vuln_class` (o piso preserva a severidade; padrão APM/service_exposure/openapi_authz).
- **Reuso, não reescrita:** importa helpers de `openapi_probe`/`pii_detect`/`pan_scanner`/`bola`; não os altera.
- **Módulo novo:** `lib/openapi_diff.py` (NÃO tocar `lib/openapi_probe.py`).
- **1º nível apenas** de `properties` no resolver de schema (YAGNI); `$ref` direto + `properties` inline (sem `oneOf`/`anyOf`/`allOf`).
- **Validação por commit:** `python3 -m pytest tests/` verde (baseline 1007 passed / 3 skipped); `py_compile` nos arquivos tocados; `bash -n stiglitz.sh` quando tocá-lo.

## File Structure

- `lib/openapi_diff.py` (criar) — resolver de schema + excessive + shadow + findings + orquestração + CLI.
- `tests/test_openapi_diff.py` (criar) — núcleo puro + orquestração com `fetch_fn` fake.
- `stiglitz.sh` (modificar, após o bloco P0.1 broken-auth ~`:1293`) — invocação.
- `stiglitz_report.py` (modificar, lista de ingest ~`:1014`) — uma linha + teste de caracterização.

---

### Task 1: Resolver de schema de resposta (`resolve_response_schema`)

**Files:**
- Create: `lib/openapi_diff.py`
- Test: `tests/test_openapi_diff.py`

**Interfaces:**
- Produces: `resolve_response_schema(spec, path, method) -> set[str]` — nomes de campo declarados na resposta 2xx da operação; `set()` quando não resolvível.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_openapi_diff.py
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
import openapi_diff as od

_OAS3 = {
    "openapi": "3.0.0",
    "paths": {"/cards/{id}": {"get": {"responses": {"200": {"content": {
        "application/json": {"schema": {"$ref": "#/components/schemas/Card"}}}}}}}},
    "components": {"schemas": {"Card": {"type": "object", "properties": {
        "id": {"type": "string"}, "last4": {"type": "string"}}}}},
}
_SW2 = {
    "swagger": "2.0",
    "paths": {"/u": {"get": {"responses": {"200": {"schema": {"$ref": "#/definitions/U"}}}}}},
    "definitions": {"U": {"properties": {"name": {"type": "string"}}}},
}


def test_resolve_oas3_ref():
    assert od.resolve_response_schema(_OAS3, "/cards/{id}", "GET") == {"id", "last4"}


def test_resolve_swagger2_definitions():
    assert od.resolve_response_schema(_SW2, "/u", "GET") == {"name"}


def test_resolve_inline_properties():
    spec = {"openapi": "3.0.0", "paths": {"/x": {"get": {"responses": {"200": {"content": {
        "application/json": {"schema": {"properties": {"a": {}, "b": {}}}}}}}}}}}
    assert od.resolve_response_schema(spec, "/x", "GET") == {"a", "b"}


def test_resolve_cyclic_ref_terminates():
    spec = {"openapi": "3.0.0",
            "paths": {"/x": {"get": {"responses": {"200": {"content": {
                "application/json": {"schema": {"$ref": "#/components/schemas/Node"}}}}}}}},
            "components": {"schemas": {"Node": {"properties": {"self": {"$ref": "#/components/schemas/Node"}}}}}}
    # não deve travar; retorna as chaves de topo
    assert od.resolve_response_schema(spec, "/x", "GET") == {"self"}


def test_resolve_missing_schema_is_empty():
    spec = {"openapi": "3.0.0", "paths": {"/x": {"get": {"responses": {"200": {}}}}}}
    assert od.resolve_response_schema(spec, "/x", "GET") == set()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_openapi_diff.py -v`
Expected: FAIL (`ModuleNotFoundError: No module named 'openapi_diff'`)

- [ ] **Step 3: Write minimal implementation**

```python
#!/usr/bin/env python3
"""openapi_diff.py — item #2 do ROADMAP-analyst-parity: diff spec-vs-comportamento.

Compara o que o spec OpenAPI/Swagger DECLARA com o que a API OBSERVAVELMENTE faz:
  - Excessive Data Exposure: resposta traz campos fora do schema declarado (CWE-213).
  - Shadow Endpoint: path observado (crawl/histórico) que não existe no spec (CWE-1059).
Mass Assignment fica de fora (mutante/gated → bizlogic).

Lógica pura + fetch injetável + CLI (padrão openapi_probe.py). Findings em EN
(deliverable); console/comentários PT-BR. Reusa helpers de openapi_probe e os
detectores de dado sensível (pii_detect/pan_scanner/bola).
"""
import json
import os
import re
import sys
import urllib.request
import urllib.error

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from openapi_probe import _as_dict, documented_operations, op_url, unauth_verdict
import netproxy


def _resolve_ref(spec, node, seen):
    """Resolve um nó de schema, seguindo $ref (guarda anti-ciclo via `seen`)."""
    if not isinstance(node, dict):
        return {}
    ref = node.get("$ref")
    if isinstance(ref, str):
        if ref in seen:
            return {}
        seen.add(ref)
        # #/components/schemas/X  ou  #/definitions/X
        target = spec
        for part in ref.lstrip("#/").split("/"):
            if not isinstance(target, dict):
                return {}
            target = target.get(part, {})
        return _resolve_ref(spec, target, seen)
    return node


def _response_schema_node(operation):
    """Extrai o nó de schema da resposta 2xx (OAS3 content.*.schema ou Swagger2 schema)."""
    responses = operation.get("responses")
    if not isinstance(responses, dict):
        return None
    for code, resp in responses.items():
        if not str(code).startswith("2") or not isinstance(resp, dict):
            continue
        # Swagger 2: resp["schema"]
        if isinstance(resp.get("schema"), dict):
            return resp["schema"]
        # OpenAPI 3: resp["content"][mediatype]["schema"]
        content = resp.get("content")
        if isinstance(content, dict):
            for mt in content.values():
                if isinstance(mt, dict) and isinstance(mt.get("schema"), dict):
                    return mt["schema"]
    return None


def resolve_response_schema(spec, path, method):
    """Conjunto dos nomes de campo declarados na resposta 2xx da operação.

    Resolve $ref contra components/schemas (OAS3) e definitions (Swagger2), lê
    `properties` inline. Só o 1º nível. Não resolvível → set() (não é erro:
    sinaliza "sem baseline para comparar")."""
    spec = _as_dict(spec) or {}
    item = (spec.get("paths") or {}).get(path)
    if not isinstance(item, dict):
        return set()
    operation = item.get(method.lower())
    if not isinstance(operation, dict):
        return set()
    node = _response_schema_node(operation)
    if node is None:
        return set()
    resolved = _resolve_ref(spec, node, set())
    props = resolved.get("properties") if isinstance(resolved, dict) else None
    if not isinstance(props, dict):
        return set()
    return set(props.keys())
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_openapi_diff.py -v`
Expected: PASS (5 testes)

- [ ] **Step 5: Commit**

```bash
git add lib/openapi_diff.py tests/test_openapi_diff.py
git commit -m "feat(openapi-diff): resolver de schema de resposta (\$ref OAS3/Swagger2)"
```

---

### Task 2: Excessive Data Exposure (`excessive_fields`, `classify_excessive`)

**Files:**
- Modify: `lib/openapi_diff.py`
- Test: `tests/test_openapi_diff.py`

**Interfaces:**
- Consumes: `resolve_response_schema`; `pii_detect.extract_pii`/`pan_scanner.scan_text`/`bola.extract_canary`.
- Produces: `observed_fields(body, content_type) -> set[str]`; `excessive_fields(observed_body, declared_fields, content_type="") -> set[str]`; `classify_excessive(extra_fields, observed_body) -> str` (severity).

- [ ] **Step 1: Write the failing test**

```python
def test_observed_fields_top_level_json():
    assert od.observed_fields('{"id":1,"last4":"1234","pan":"x"}', "application/json") == {"id", "last4", "pan"}


def test_observed_fields_non_json_is_empty():
    assert od.observed_fields("<html>hi</html>", "text/html") == set()


def test_excessive_fields_detects_extra():
    assert od.excessive_fields('{"id":1,"last4":"1","full_pan":"x"}', {"id", "last4"}, "application/json") == {"full_pan"}


def test_excessive_fields_no_extra_is_empty():
    assert od.excessive_fields('{"id":1,"last4":"1"}', {"id", "last4"}, "application/json") == set()


def test_excessive_fields_empty_declared_is_empty():
    # sem baseline declarado -> não inventa exposição
    assert od.excessive_fields('{"id":1}', set(), "application/json") == set()


def test_classify_excessive_base_medium():
    assert od.classify_excessive({"nickname"}, '{"nickname":"joe"}') == "medium"


def test_classify_excessive_pii_high():
    assert od.classify_excessive({"email"}, '{"email":"a@b.com"}') == "high"


def test_classify_excessive_pan_critical():
    # PAN Luhn-válido com contexto de cartão
    body = '{"card_number":"4111111111111111"}'
    assert od.classify_excessive({"card_number"}, body) == "critical"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_openapi_diff.py -k "observed or excessive or classify" -v`
Expected: FAIL (`AttributeError: ... 'observed_fields'`)

- [ ] **Step 3: Write minimal implementation**

```python
# imports adicionais (juntar aos do topo do módulo)
try:
    from bola import extract_canary
    from pii_detect import extract_pii
    from pan_scanner import scan_text as _pan_scan
except Exception:  # importado fora de lib/
    def extract_canary(b, ct=""):
        return set()

    def extract_pii(content, corporate_domains):
        return {}

    def _pan_scan(body):
        return []


def observed_fields(body, content_type=""):
    """Chaves de topo de um corpo JSON de objeto. Não-JSON / lista / inválido → set()."""
    ct = (content_type or "").lower()
    text = (body or "").lstrip()
    if not ("json" in ct or text[:1] == "{"):
        return set()
    try:
        obj = json.loads(body)
    except (ValueError, TypeError):
        return set()
    return set(obj.keys()) if isinstance(obj, dict) else set()


def excessive_fields(observed_body, declared_fields, content_type=""):
    """Campos de topo na resposta AUSENTES do schema declarado. Sem baseline
    (declared_fields vazio) → set() (não inventa exposição)."""
    if not declared_fields:
        return set()
    return observed_fields(observed_body, content_type) - set(declared_fields)


def classify_excessive(extra_fields, observed_body):
    """Severidade da exposição: critical se há PAN (Luhn+contexto), high se PII
    (CPF/CNPJ/email), senão medium."""
    if _pan_scan(observed_body or ""):
        return "critical"
    pii = extract_pii(observed_body or "", [])
    has_pii = bool(pii) or any(
        "@" in c or c.replace(".", "").replace("-", "").isdigit()
        for c in extract_canary(observed_body or ""))
    return "high" if has_pii else "medium"
```

> Nota ao implementador: `extract_pii` retorna um dict (ver `lib/pii_detect.py:117`); trate qualquer valor não-vazio como PII presente. `_pan_scan` (=`pan_scanner.scan_text`) devolve lista de PANs mascarados (só Luhn-válidos com contexto de cartão — `lib/pan_scanner.py:40`).

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_openapi_diff.py -k "observed or excessive or classify" -v`
Expected: PASS (8 testes)

- [ ] **Step 5: Commit**

```bash
git add lib/openapi_diff.py tests/test_openapi_diff.py
git commit -m "feat(openapi-diff): excessive data exposure + classificação por PAN/PII"
```

---

### Task 3: Shadow Endpoint (`documented_path_matchers`, `shadow_paths`)

**Files:**
- Modify: `lib/openapi_diff.py`
- Test: `tests/test_openapi_diff.py`

**Interfaces:**
- Consumes: `_as_dict`; `openapi_probe._spec_prefix` via `op_url` (usar `_prefix`).
- Produces: `documented_path_matchers(spec) -> list[re.Pattern]`; `shadow_paths(observed_urls, matchers, scope_host="") -> list[str]`.

- [ ] **Step 1: Write the failing test**

```python
_SPEC_PATHS = {"openapi": "3.0.0", "paths": {
    "/cards/{id}": {"get": {}}, "/users": {"get": {}}}}


def test_matchers_match_templated_path():
    m = od.documented_path_matchers(_SPEC_PATHS)
    # /cards/123 casa (documentado); não é shadow
    assert od.shadow_paths(["https://h/cards/123"], m) == []


def test_shadow_path_not_in_spec():
    m = od.documented_path_matchers(_SPEC_PATHS)
    assert od.shadow_paths(["https://h/admin/debug"], m) == ["/admin/debug"]


def test_shadow_ignores_querystring():
    m = od.documented_path_matchers(_SPEC_PATHS)
    assert od.shadow_paths(["https://h/users?page=2"], m) == []


def test_shadow_dedups_and_filters_scope():
    m = od.documented_path_matchers(_SPEC_PATHS)
    urls = ["https://h/admin", "https://h/admin", "https://evil.com/x"]
    assert od.shadow_paths(urls, m, scope_host="h") == ["/admin"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_openapi_diff.py -k "matcher or shadow" -v`
Expected: FAIL (`AttributeError: ... 'documented_path_matchers'`)

- [ ] **Step 3: Write minimal implementation**

```python
from urllib.parse import urlsplit


def documented_path_matchers(spec):
    """Um regex por path do spec: {param} (segmento inteiro) -> [^/]+ ; resto escapado;
    ancorado. Respeita basePath/servers via openapi_seed._prefix."""
    spec = _as_dict(spec) or {}
    from openapi_seed import _prefix as _spec_prefix
    prefix = _spec_prefix(spec) or ""
    out = []
    for raw in (spec.get("paths") or {}):
        if not isinstance(raw, str) or not raw.startswith("/"):
            continue
        full = raw if (not prefix or raw.startswith(prefix)) else prefix + raw
        # constrói o regex segmento a segmento: {param} vira [^/]+, o resto é literal
        segs = ["[^/]+" if (s.startswith("{") and s.endswith("}")) else re.escape(s)
                for s in full.split("/")]
        out.append(re.compile("^" + "/".join(segs) + "$"))
    return out


def shadow_paths(observed_urls, matchers, scope_host=""):
    """Paths observados que não casam nenhum matcher. Query-string removida;
    fora do scope_host descartado; dedup preservando ordem de 1ª ocorrência."""
    seen, out = set(), []
    for u in observed_urls or []:
        parts = urlsplit(u if "://" in u else "//" + u)
        if scope_host and parts.netloc and parts.netloc != scope_host:
            continue
        path = parts.path or "/"
        if path in seen:
            continue
        if any(m.match(path) for m in matchers):
            continue
        seen.add(path)
        out.append(path)
    return out
```

> Nota ao implementador: params de segmento-inteiro (`/cards/{id}`) são o caso comum de OpenAPI e o que este 1º corte cobre; templates parciais (`/x/{id}.json`) ficam de fora (YAGNI). Rode `test_matchers_match_templated_path` para confirmar que `/cards/{id}` casa `/cards/123`.

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_openapi_diff.py -k "matcher or shadow" -v`
Expected: PASS (4 testes)

- [ ] **Step 5: Commit**

```bash
git add lib/openapi_diff.py tests/test_openapi_diff.py
git commit -m "feat(openapi-diff): shadow endpoint (path observado fora do spec)"
```

---

### Task 4: Findings (`build_finding`) + montagem

**Files:**
- Modify: `lib/openapi_diff.py`
- Test: `tests/test_openapi_diff.py`

**Interfaces:**
- Produces: `_finding(ftype, name, severity, cwe, url, description, evidence, method="") -> dict` (com `fingerprint`); constantes de descrição.

- [ ] **Step 1: Write the failing test**

```python
def test_build_finding_excessive_shape():
    f = od._finding("openapi_excessive_data",
                    "Excessive Data Exposure vs OpenAPI schema", "high", "CWE-213",
                    "https://h/cards/1", "desc", "ev", method="GET")
    assert f["type"] == "openapi_excessive_data"
    assert f["severity"] == "high"
    assert f["cwe"] == "CWE-213"
    assert f["source"] == "openapi_diff" and f["tool"] == "openapi_diff"
    assert f["fingerprint"] and f["fingerprint"] != "0" * 16


def test_build_finding_distinct_types_distinct_fingerprints():
    a = od._finding("openapi_excessive_data", "n", "medium", "CWE-213", "https://h/x", "d", "e")
    b = od._finding("openapi_shadow_endpoint", "n", "low", "CWE-1059", "https://h/x", "d", "e")
    assert a["fingerprint"] != b["fingerprint"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_openapi_diff.py -k build_finding -v`
Expected: FAIL (`AttributeError: ... '_finding'`)

- [ ] **Step 3: Write minimal implementation**

```python
try:
    from fingerprint import fingerprint as _fingerprint
except Exception:
    def _fingerprint(f):
        return "0" * 16


def _finding(ftype, name, severity, cwe, url, description, evidence, method=""):
    """Finding normalizado (EN). Schema alinhado ao openapi_probe.build_finding."""
    f = {
        "type": ftype, "name": name, "severity": severity, "cwe": cwe,
        "url": url, "method": method, "source": "openapi_diff", "tool": "openapi_diff",
        "description": description, "evidence": evidence,
    }
    f["fingerprint"] = _fingerprint(f)
    return f
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_openapi_diff.py -k build_finding -v`
Expected: PASS (2 testes)

- [ ] **Step 5: Commit**

```bash
git add lib/openapi_diff.py tests/test_openapi_diff.py
git commit -m "feat(openapi-diff): schema de finding (EN + cwe + fingerprint)"
```

---

### Task 5: Orquestração (`probe`, `run`, `_default_fetch`, CLI)

**Files:**
- Modify: `lib/openapi_diff.py`
- Test: `tests/test_openapi_diff.py`

**Interfaces:**
- Consumes: tudo acima; `documented_operations`/`op_url`/`unauth_verdict` de `openapi_probe`.
- Produces: `probe(spec, base_url, observed_urls, fetch_fn, sample="1") -> list[dict]`; `run(spec_path, base_url, outdir, observed_urls_path=None, fetch_fn=_default_fetch) -> int`; `main(argv)`.

- [ ] **Step 1: Write the failing test**

```python
def test_probe_emits_excessive_when_extra_field_returned(tmp_path):
    spec = {"openapi": "3.0.0",
            "paths": {"/cards/{id}": {"get": {"responses": {"200": {"content": {
                "application/json": {"schema": {"$ref": "#/components/schemas/Card"}}}}}}}},
            "components": {"schemas": {"Card": {"properties": {"id": {}, "last4": {}}}}}}

    def fake_fetch(url, method):
        # servidor devolve um campo extra não-documentado (full_pan)
        return 200, '{"id":1,"last4":"1234","full_pan":"4111111111111111"}', "application/json"

    findings = od.probe(spec, "https://h", observed_urls=[], fetch_fn=fake_fetch)
    exc = [f for f in findings if f["type"] == "openapi_excessive_data"]
    assert exc and exc[0]["severity"] == "critical"        # full_pan é PAN Luhn-válido
    assert "full_pan" in exc[0]["evidence"]


def test_probe_emits_shadow_for_undocumented_observed_path():
    spec = {"openapi": "3.0.0", "paths": {"/users": {"get": {}}}}
    findings = od.probe(spec, "https://h", observed_urls=["https://h/admin/secret"],
                        fetch_fn=lambda u, m: (0, "", ""))
    shadow = [f for f in findings if f["type"] == "openapi_shadow_endpoint"]
    assert shadow and "/admin/secret" in shadow[0]["url"]


def test_run_writes_openapi_diff_json(tmp_path):
    spec = {"openapi": "3.0.0", "paths": {"/users": {"get": {}}}}
    sp = tmp_path / "spec.json"
    sp.write_text(__import__("json").dumps(spec))
    obs = tmp_path / "katana.txt"
    obs.write_text("https://h/admin\n")
    n = od.run(str(sp), "https://h", str(tmp_path), str(obs),
               fetch_fn=lambda u, m: (0, "", ""))
    assert n >= 1
    saved = __import__("json").load(open(tmp_path / "raw" / "openapi_diff.json"))
    assert any(f["type"] == "openapi_shadow_endpoint" for f in saved)


def test_run_missing_spec_returns_zero(tmp_path):
    assert od.run(str(tmp_path / "nope.json"), "https://h", str(tmp_path)) == 0
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_openapi_diff.py -k "probe or run" -v`
Expected: FAIL (`AttributeError: ... 'probe'`)

- [ ] **Step 3: Write minimal implementation**

```python
_EXCESSIVE_DESC = (
    "An endpoint returned fields in its response body that are NOT declared in the "
    "OpenAPI/Swagger response schema. Undeclared fields indicate the API exposes more "
    "data than documented; when they carry sensitive values (PAN, PII) this is a "
    "confidentiality exposure that schema review would not catch.")
_SHADOW_DESC = (
    "A path observed during crawling is NOT documented in the OpenAPI/Swagger "
    "specification. Undocumented (shadow) endpoints are outside the security inventory: "
    "they are typically unreviewed, unmonitored, and a frequent source of forgotten "
    "debug/admin surface.")


def probe(spec, base_url, observed_urls, fetch_fn, sample="1"):
    """Roda as duas detecções. Retorna lista de findings (EN)."""
    spec = _as_dict(spec) or {}
    findings = []

    # 1) Excessive data — reusa o GET das operações documentadas (só métodos seguros).
    for op in documented_operations(spec):
        if op["method"] not in ("GET", "HEAD", "OPTIONS"):
            continue
        declared = resolve_response_schema(spec, op["path"], op["method"])
        if not declared:
            continue
        url = op_url(spec, base_url, op["path"], sample=sample)
        try:
            status, body, content_type = fetch_fn(url, op["method"])
        except Exception:
            continue
        if not (200 <= int(status or 0) < 300):
            continue
        extra = excessive_fields(body, declared, content_type)
        if not extra:
            continue
        sev = classify_excessive(extra, body)
        findings.append(_finding(
            "openapi_excessive_data",
            "Excessive Data Exposure vs OpenAPI schema", sev, "CWE-213",
            url, _EXCESSIVE_DESC,
            "Undeclared response field(s): %s (declared schema: %s)" % (
                ", ".join(sorted(extra)), ", ".join(sorted(declared))),
            method=op["method"]))

    # 2) Shadow endpoints — set-diff observed - documented.
    matchers = documented_path_matchers(spec)
    host = urlsplit(base_url).netloc
    for path in shadow_paths(observed_urls, matchers, scope_host=host):
        url = base_url.rstrip("/") + path
        sev = "low"
        try:
            status, body, ct = fetch_fn(url, "GET")
            v = unauth_verdict(status, body, ct)
            if v["state"] == "BROKEN_AUTH":
                sev = "medium"
        except Exception:
            pass
        findings.append(_finding(
            "openapi_shadow_endpoint",
            "Shadow Endpoint (undocumented, observed at runtime)", sev, "CWE-1059",
            url, _SHADOW_DESC, "Observed path %s not present in the OpenAPI spec" % path,
            method="GET"))
    return findings


def _default_fetch(url, method, timeout=10):
    """Fetch real via netproxy (herda --proxy + mTLS). (status, body, content_type)."""
    req = urllib.request.Request(url, method=method,
                                 headers={"Accept": "application/json, */*"})
    try:
        with netproxy.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read(65536).decode("utf-8", "replace"), \
                resp.headers.get("content-type", "")
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read(65536).decode("utf-8", "replace")
        except Exception:
            pass
        ct = e.headers.get("content-type", "") if getattr(e, "headers", None) else ""
        return e.code, body, ct
    except Exception:
        return 0, "", ""


def run(spec_path, base_url, outdir, observed_urls_path=None, fetch_fn=_default_fetch):
    """Lê spec + observed_urls, sonda, grava <outdir>/raw/openapi_diff.json. Retorna a contagem."""
    try:
        with open(spec_path, encoding="utf-8") as f:
            spec = json.load(f)
    except (OSError, ValueError):
        return 0
    observed = []
    if observed_urls_path and os.path.exists(observed_urls_path):
        try:
            with open(observed_urls_path, encoding="utf-8") as f:
                observed = [ln.strip() for ln in f if ln.strip()]
        except OSError:
            observed = []
    findings = probe(spec, base_url, observed, fetch_fn)
    raw = os.path.join(outdir, "raw")
    try:
        os.makedirs(raw, exist_ok=True)
        with open(os.path.join(raw, "openapi_diff.json"), "w", encoding="utf-8") as f:
            json.dump(findings, f, indent=2)
    except OSError:
        pass
    return len(findings)


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) < 2:
        print("uso: openapi_diff.py <spec.json> <base_url> [outdir] [observed_urls.txt]",
              file=sys.stderr)
        return 2
    outdir = argv[2] if len(argv) > 2 else "."
    observed = argv[3] if len(argv) > 3 else None
    print(run(argv[0], argv[1], outdir, observed))
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_openapi_diff.py -v && python3 -m py_compile lib/openapi_diff.py`
Expected: PASS (todos) e compile sem erro

- [ ] **Step 5: Commit**

```bash
git add lib/openapi_diff.py tests/test_openapi_diff.py
git commit -m "feat(openapi-diff): orquestração probe + run + CLI (GET-only, fail-safe)"
```

---

### Task 6: Wiring no `stiglitz.sh`

**Files:**
- Modify: `stiglitz.sh` (após o bloco P0.1 broken-auth, que termina em ~`:1293` com `unset _ba_n; fi`)

**Interfaces:**
- Consumes: `lib/openapi_diff.py` CLI (`<spec> <target> <outdir> <katana_urls.txt>`).
- Produces: `raw/openapi_diff.json`.

- [ ] **Step 1: Localizar o fim do bloco P0.1 e inserir o novo bloco**

Localizar (em `stiglitz.sh`), o fim do bloco de broken-auth:

```bash
        unset _ba_n
    fi
```

Inserir imediatamente depois:

```bash
    # ── Item #2: OpenAPI diff spec-vs-comportamento ─────────────────────────────
    # Excessive Data Exposure (resposta com campos fora do schema) + Shadow Endpoint
    # (path observado ∉ spec). Reusa o spec descoberto e os paths do katana. GET-only,
    # fail-safe (no-op sem spec/schema). → raw/openapi_diff.json
    if [ -s "$OUTDIR/raw/openapi_spec.json" ]; then
        _od_n=$(timeout 180 python3 "$SCRIPT_DIR/lib/openapi_diff.py" \
                  "$OUTDIR/raw/openapi_spec.json" "$TARGET" "$OUTDIR" \
                  "$OUTDIR/raw/katana_urls.txt" 2>/dev/null || echo 0)
        if [ "${_od_n:-0}" -gt 0 ]; then
            echo -e "  ${RED}[!] OpenAPI spec-vs-behavior: ${_od_n} divergência(s) (excessive data / shadow endpoint)${NC}"
        else
            echo -e "  ${GREEN}[✓]${NC} OpenAPI spec-vs-behavior: nenhuma divergência detectada"
        fi
        unset _od_n
    fi
```

- [ ] **Step 2: Validar sintaxe e presença**

Run: `bash -n stiglitz.sh && grep -n "lib/openapi_diff.py" stiglitz.sh`
Expected: sem erro; grep mostra a linha inserida

- [ ] **Step 3: Lint (se disponível)**

Run: `command -v shellcheck && shellcheck --severity=warning stiglitz.sh || echo "shellcheck ausente — gate do CI; inspeção manual do quoting"`
Expected: sem novos warnings, ou nota de ausência (inspecionar aspas de `"$OUTDIR"`/`"$TARGET"`/`"$SCRIPT_DIR"`)

- [ ] **Step 4: Commit**

```bash
git add stiglitz.sh
git commit -m "feat(scan): roda openapi_diff após o broken-auth (Fase 4)"
```

---

### Task 7: Ingest no `stiglitz_report.py`

**Files:**
- Modify: `stiglitz_report.py` (lista de ingest genérica, ~`:1014`, logo após `('openapi_authz.json', 'openapi_authz'),`)
- Test: `tests/test_openapi_diff_report_wiring.py` (criar)

**Interfaces:**
- Consumes: `raw/openapi_diff.json`.
- Produces: findings de `openapi_diff` agregados via o loop de ingest existente (findings `estimated`).

- [ ] **Step 1: Write the failing characterization test**

```python
# tests/test_openapi_diff_report_wiring.py
import os, sys, json, subprocess, pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent


def _run_report(outdir):
    env = dict(os.environ, OUTDIR=str(outdir), DOMAIN="host", TARGET="https://host",
               STIGLITZ_DEDUP="0")
    return subprocess.run([sys.executable, str(ROOT / "stiglitz_report.py")],
                          env=env, capture_output=True, text=True, cwd=str(ROOT))


def test_openapi_diff_finding_reaches_findings_json(tmp_path):
    raw = tmp_path / "raw"
    raw.mkdir(parents=True)
    (raw / "openapi_diff.json").write_text(json.dumps([{
        "type": "openapi_excessive_data",
        "name": "Excessive Data Exposure vs OpenAPI schema",
        "severity": "critical", "cwe": "CWE-213",
        "url": "https://host/cards/1", "method": "GET",
        "source": "openapi_diff", "tool": "openapi_diff",
        "description": "d", "evidence": "e", "fingerprint": "abc123def456ab00",
    }]))
    r = _run_report(tmp_path)
    assert r.returncode == 0, r.stderr
    fj = json.load(open(tmp_path / "findings.json"))
    arr = fj["findings"] if isinstance(fj, dict) else fj
    hit = [f for f in arr if f.get("id", "").endswith("openapi_excessive_data")
           or f.get("name", "").startswith("Excessive Data Exposure")]
    assert hit, "finding do openapi_diff não chegou ao findings.json"
```

> Nota ao implementador: o `findings.json` é um dict com chave `findings` (confirmado no trabalho anterior). A lista de ingest genérica (`stiglitz_report.py` ~`:1000-1026`) já normaliza `severity_orig`/`cve_ids`; o finding entra como `version_findings` e daí para `_all_f_raw`. O teste casa por `name`/`id` porque `type` não é exportado no `findings.json`.

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_openapi_diff_report_wiring.py -v`
Expected: FAIL (finding não aparece — ingest ainda não existe)

- [ ] **Step 3: Add the ingest line**

Em `stiglitz_report.py`, na lista de tuplas de ingest (logo após a linha `('openapi_authz.json', 'openapi_authz'),`), adicionar:

```python
    ('openapi_diff.json',        'openapi_diff'),
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_openapi_diff_report_wiring.py -v && python3 -m py_compile stiglitz_report.py`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add stiglitz_report.py tests/test_openapi_diff_report_wiring.py
git commit -m "feat(report): ingest openapi_diff.json (excessive data / shadow endpoint)"
```

---

### Task 8: Regressão completa + docs

**Files:**
- Modify: `CLAUDE.md` (tabela de módulos `lib/`), `CHANGELOG.md` (Unreleased), `docs/ROADMAP-analyst-parity.md` (marcar item #2).

**Interfaces:** nenhuma nova.

- [ ] **Step 1: Suíte completa + compile + lint**

Run:
```bash
python3 -m pytest tests/ -q
python3 -m py_compile stiglitz_report.py lib/openapi_diff.py
bash -n stiglitz.sh
command -v shellcheck && shellcheck --severity=warning stiglitz.sh || echo "shellcheck: gate do CI"
```
Expected: tudo verde (baseline 1007 + novos testes); compile/sintaxe OK.

- [ ] **Step 2: `CLAUDE.md` — linha na tabela de módulos**

Adicionar após a entrada do `openapi_seed.py` (seguindo o estilo das vizinhas):

```
| `openapi_diff.py` | Diff spec-vs-comportamento (item #2, Fase 4, após o broken-auth do `openapi_probe`): **Excessive Data Exposure** (resposta com campos de topo fora do schema declarado — resolve `$ref` de `components/schemas` OAS3 / `definitions` Swagger2, 1º nível; severidade elevada por PAN/PII via `pan_scanner`/`pii_detect`; CWE-213) + **Shadow Endpoint** (path do `katana_urls.txt` que não casa nenhum `spec.paths`, `{param}`→`[^/]+`; CWE-1059, medium se responde dados). GET-only, fail-safe (no-op sem spec/schema). Reusa `_as_dict`/`documented_operations`/`op_url`/`unauth_verdict` do `openapi_probe`. → `raw/openapi_diff.json`, ingerido como `estimated`. Lógica pura + `fetch_fn` injetável + CLI |
```

- [ ] **Step 3: `CHANGELOG.md` — bullet na Unreleased**

Adicionar na seção `## Unreleased` (estilo das entradas vizinhas), cobrindo `lib/openapi_diff.py` (Excessive Data Exposure + Shadow Endpoint, item #2, GET-only/fail-safe, ingerido no report).

- [ ] **Step 4: `docs/ROADMAP-analyst-parity.md` — marcar item #2**

Na tabela dos 6 itens, mudar o status do item #2 de `⏳ pendente` para `✅ FEITO — Excessive Data Exposure + Shadow Endpoint (Mass Assignment deferido → bizlogic)`. Manter higienizado.

- [ ] **Step 5: Commit**

```bash
git add CLAUDE.md CHANGELOG.md docs/ROADMAP-analyst-parity.md
git commit -m "docs: registra openapi_diff (item #2 — spec-vs-comportamento)"
```

---

## Self-Review

**1. Spec coverage:**
- Resolver de schema (`$ref` OAS3/Swagger2, inline, ciclo, vazio) → Task 1 ✓
- Excessive Data Exposure (campos extras + classificação PAN/PII) → Task 2 ✓
- Shadow Endpoint (matchers `{param}`, set-diff, query/escopo) → Task 3 ✓ (elevação opcional a medium via fetch → Task 5 `probe`) ✓
- Findings schema EN + fingerprint → Task 4 ✓
- Orquestração probe/run/CLI, GET-only, fail-safe → Task 5 ✓
- Wiring Fase 4 → Task 6 ✓; ingest report `estimated` → Task 7 ✓
- Mass Assignment deferido → não há task (correto, fora de escopo) ✓
- Docs (CLAUDE.md/CHANGELOG/ROADMAP) → Task 8 ✓

**2. Placeholder scan:** Todo step de código traz o código real; testes com asserts concretos. As duas "Notas ao implementador" (regex `_PARAM` sobre string escapada; formato do `findings.json`) são instruções de verificação, não lacunas.

**3. Type consistency:** `resolve_response_schema(spec, path, method) -> set` (T1) consumido por `excessive_fields`/`probe` (T2/T5); `excessive_fields(observed_body, declared_fields, content_type)` e `classify_excessive(extra_fields, observed_body)` (T2) usados no `probe` (T5); `documented_path_matchers(spec)` + `shadow_paths(observed_urls, matchers, scope_host)` (T3) usados no `probe` (T5); `_finding(ftype, name, severity, cwe, url, description, evidence, method)` (T4) usado no `probe` (T5); `run(spec_path, base_url, outdir, observed_urls_path, fetch_fn)` (T5) usado no wiring (T6). `source="openapi_diff"` consistente entre T4 e o ingest T7. Nomes de tipo de finding (`openapi_excessive_data`/`openapi_shadow_endpoint`) idênticos em T4/T5/T7.

## Execution Handoff

Ver mensagem ao usuário após salvar.

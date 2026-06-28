# GraphQL além de introspection (DoS + field-level authz) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Estender o GraphQL do scanner além de introspection — detecção de resource-exhaustion (batching/aliasing) e confirmação de field-level authorization (BOLA/BFLA) reusando o núcleo do `bola.py`.

**Architecture:** Três módulos puros + injetáveis: `graphql_audit.py` ganha `is_mutation`; `graphql_dos.py` (probes `__typename` de aliasing/batching, dry-run em production); `graphql_authz.py` (replay das operações GraphQL reais do histórico ZAP com 2 tokens, reusando `bola.verdict`/`extract_canary`). Integração: DoS no bloco GraphQL da Fase 9; authz na nova sub-fase P9.8 gated em 2 tokens.

**Tech Stack:** Python 3 stdlib (`json`, `urllib`, `subprocess`), reuso de `bola.py`/`netproxy`/`mtls`, bash, pytest.

## Global Constraints

- Mensagens de console/operador em **PT-BR com acentuação plena** (nunca substituir acentos). Texto dos **findings em inglês** (deliverable).
- Probes não-destrutivos: DoS usa leituras de `__typename` (request único, N/M limitados); authz replaya só **queries** por padrão (mutations exigem `--graphql-mutate` + `STIGLITZ_PROFILE != production`).
- DoS em `production` → **dry-run** (detecta o endpoint, não envia probes de amplificação).
- Reuso do `bola.py`: `verdict`, `extract_canary`, `parse_zap_messages` (NÃO `build_findings`, que fixa classes REST — o authz tem builder próprio com classes `graphql_bola`/`graphql_bfla`).
- POSTs ao alvo via `curl` com `netproxy.curl_proxy_args()` + `mtls.curl_cert_args()` (herda proxy+mTLS). Tokens via env, nunca em CLI/log.
- Fail-soft: endpoint ausente / erro de rede / JSON inválido → no-op silencioso, nunca aborta a fase.
- Git: commit direto na `main`; mensagem termina com `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.
- Validação antes de cada commit: `python3 -m pytest tests/ -q` verde; para `.sh`/`.py` tocados, `bash -n stiglitz.sh` + `shellcheck --severity=warning stiglitz.sh` + `python3 -m py_compile`.

---

## File Structure

- `lib/graphql_audit.py` — +`is_mutation(operation_body) -> bool` (helper de domínio).
- `lib/graphql_dos.py` — **novo**: probes de aliasing/batching + classificação + `run` (detecção + dry-run) + CLI.
- `lib/graphql_authz.py` — **novo**: seleção de ops GraphQL do dump ZAP + replay + findings (reusa `bola`).
- `stiglitz.sh` — DoS no bloco GraphQL da Fase 9 (~1791); nova sub-fase P9.8; flag `--graphql-mutate`.
- `pipeline.py` — adicionar `P9_8` ao grupo combinado P9.
- `stiglitz_report.py:946` — ingerir `graphql_dos.json` + `graphql_authz.json`.
- `tests/test_graphql_audit.py`, `tests/test_graphql_dos.py`, `tests/test_graphql_authz.py`, `tests/test_graphql_stiglitz_integration.py` — **novos**.

---

### Task 1: `graphql_audit.is_mutation`

**Files:**
- Modify: `lib/graphql_audit.py` (adiciona `is_mutation`; garante `import json` presente — já há `import json`)
- Create: `tests/test_graphql_audit.py`

**Interfaces:**
- Produces: `is_mutation(operation_body: str) -> bool`

- [ ] **Step 1: Escrever os testes que falham**

Criar `tests/test_graphql_audit.py`:
```python
# tests/test_graphql_audit.py
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
import graphql_audit as ga


def test_is_mutation_json_body_true():
    assert ga.is_mutation('{"query":"mutation { deleteUser(id:1){ ok } }"}') is True

def test_is_mutation_named_mutation_true():
    assert ga.is_mutation('mutation Foo($a:Int){ pay(amount:$a){ id } }') is True

def test_is_mutation_anonymous_query_false():
    assert ga.is_mutation('{"query":"{ me { id } }"}') is False

def test_is_mutation_explicit_query_false():
    assert ga.is_mutation('{"query":"query Q { account(id:1){ id } }"}') is False

def test_is_mutation_subscription_false():
    assert ga.is_mutation('subscription { onEvent { id } }') is False

def test_is_mutation_leading_comment_and_space_true():
    assert ga.is_mutation('{"query":"  # comentário\\n  mutation { x }"}') is True

def test_is_mutation_batch_any_mutation_true():
    assert ga.is_mutation('[{"query":"{ a }"},{"query":"mutation { b }"}]') is True

def test_is_mutation_empty_false():
    assert ga.is_mutation("") is False
```

- [ ] **Step 2: Rodar para verificar a falha**

Run: `python3 -m pytest tests/test_graphql_audit.py -q`
Expected: FAIL com `AttributeError: module 'graphql_audit' has no attribute 'is_mutation'`.

- [ ] **Step 3: Implementar**

Em `lib/graphql_audit.py`, adicionar (após `introspection_query()`):
```python
def is_mutation(operation_body):
    """True se a operação GraphQL é uma mutation.

    Aceita o corpo JSON do POST ({"query": "..."}), a string da operação, ou um
    array de batch (mutation se QUALQUER op for mutation). Heurística: o keyword
    de operação top-level é 'mutation'. Queries anônimas ('{ ... }'), 'query' e
    'subscription' → False. Não faz parse completo de AST.
    """
    text = operation_body or ""
    try:
        obj = json.loads(text)
        if isinstance(obj, dict) and "query" in obj:
            text = obj.get("query") or ""
        elif isinstance(obj, list):
            return any(
                is_mutation(o.get("query", "")) if isinstance(o, dict) else False
                for o in obj)
    except (ValueError, TypeError):
        pass
    text = re.sub(r"#[^\n]*", "", text).lstrip()
    return bool(re.match(r"mutation\b", text, re.I))
```

- [ ] **Step 4: Rodar para verificar verde**

Run: `python3 -m pytest tests/test_graphql_audit.py -q`
Expected: PASS (8 testes).

- [ ] **Step 5: Commit**

```bash
git add lib/graphql_audit.py tests/test_graphql_audit.py
git commit -m "$(cat <<'MSG'
feat(graphql): is_mutation — distingue mutation de query/subscription

Helper de domínio (corpo JSON, string ou batch) reusado pelo field-level authz
p/ pular mutations no replay read-only por padrão.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
MSG
)"
```

---

### Task 2: `graphql_dos.py` — probes + classificação

**Files:**
- Create: `lib/graphql_dos.py`
- Create: `tests/test_graphql_dos.py`

**Interfaces:**
- Produces: `build_alias_probe(n) -> dict`; `build_batch_probe(m) -> list`; `_is_graphql_response(status, body) -> bool`; `classify_alias_response(status, body, n) -> dict|None`; `classify_batch_response(status, body, m) -> dict|None`

- [ ] **Step 1: Escrever os testes que falham**

Criar `tests/test_graphql_dos.py`:
```python
# tests/test_graphql_dos.py
import os, sys, json
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
import graphql_dos as gd


def test_build_alias_probe_has_n_aliases():
    p = gd.build_alias_probe(5)
    assert p["query"].count("__typename") == 5
    assert "a0:__typename" in p["query"] and "a4:__typename" in p["query"]

def test_build_batch_probe_len():
    b = gd.build_batch_probe(7)
    assert isinstance(b, list) and len(b) == 7
    assert all(x == {"query": "{__typename}"} for x in b)

def test_is_graphql_response_data_or_errors():
    assert gd._is_graphql_response(200, '{"data":{"__typename":"Query"}}') is True
    assert gd._is_graphql_response(400, '{"errors":[{"message":"x"}]}') is True
    assert gd._is_graphql_response(200, '<html>nope</html>') is False

def test_classify_alias_finds_when_all_resolved():
    data = {"data": {f"a{i}": "Query" for i in range(10)}}
    f = gd.classify_alias_response(200, json.dumps(data), 10)
    assert f and f["type"] == "graphql_no_complexity_limit" and f["severity"] == "medium"

def test_classify_alias_none_when_errors():
    body = '{"errors":[{"message":"max complexity exceeded"}]}'
    assert gd.classify_alias_response(200, body, 10) is None

def test_classify_alias_none_when_partial():
    data = {"data": {f"a{i}": "Query" for i in range(3)}}
    assert gd.classify_alias_response(200, json.dumps(data), 10) is None

def test_classify_batch_finds_array():
    body = json.dumps([{"data": {}}, {"data": {}}, {"data": {}}])
    f = gd.classify_batch_response(200, body, 3)
    assert f and f["type"] == "graphql_batching_enabled" and f["severity"] == "low"

def test_classify_batch_none_single_object():
    assert gd.classify_batch_response(200, '{"data":{}}', 3) is None
```

- [ ] **Step 2: Rodar para verificar a falha**

Run: `python3 -m pytest tests/test_graphql_dos.py -q`
Expected: FAIL com `ModuleNotFoundError: No module named 'graphql_dos'`.

- [ ] **Step 3: Implementar (parte 1 — sem `run`/CLI, que vêm na Task 3)**

Criar `lib/graphql_dos.py`:
```python
#!/usr/bin/env python3
"""graphql_dos.py — detecção de resource-exhaustion em GraphQL (batching/aliasing).

Probes não-destrutivos (leituras de __typename, request único, contagem limitada)
que detectam AUSÊNCIA de limite de complexidade/alias e de batching. Não requer
introspection (usa __typename). Em production, faz dry-run. Lógica pura + send_fn
injetável.
"""
import json
import os
import sys

ALIAS_N_DEFAULT = 100
BATCH_M_DEFAULT = 15


def _alias_n():
    try:
        return max(2, int(os.environ.get("STIGLITZ_GQL_ALIAS_N", ALIAS_N_DEFAULT)))
    except ValueError:
        return ALIAS_N_DEFAULT


def _batch_m():
    try:
        return max(2, int(os.environ.get("STIGLITZ_GQL_BATCH_M", BATCH_M_DEFAULT)))
    except ValueError:
        return BATCH_M_DEFAULT


def build_alias_probe(n):
    """Query com n aliases de __typename (meta-campo universal, sem args)."""
    aliases = " ".join(f"a{i}:__typename" for i in range(n))
    return {"query": "{ " + aliases + " }"}


def build_batch_probe(m):
    """Array JSON de m operações pequenas (batch)."""
    return [{"query": "{__typename}"} for _ in range(m)]


def _is_graphql_response(status, body):
    """True se body parece um envelope GraphQL (data/errors)."""
    try:
        obj = json.loads(body or "")
    except (ValueError, TypeError):
        return False
    if isinstance(obj, dict):
        return "data" in obj or "errors" in obj
    if isinstance(obj, list):
        return any(isinstance(x, dict) and ("data" in x or "errors" in x) for x in obj)
    return False


def classify_alias_response(status, body, n):
    """Finding quando 200 + os n aliases resolveram (sem errors de complexidade)."""
    if int(status or 0) != 200:
        return None
    try:
        obj = json.loads(body or "")
    except (ValueError, TypeError):
        return None
    if not isinstance(obj, dict) or obj.get("errors"):
        return None
    data = obj.get("data") or {}
    resolved = sum(1 for k in data if k.startswith("a"))
    if resolved < n:
        return None
    return {
        "tool": "graphql_dos", "type": "graphql_no_complexity_limit", "source": "GraphQL",
        "name": "GraphQL lacks query complexity/alias limiting",
        "severity": "medium", "cve": "CWE-770",
        "description": (f"The endpoint resolved a query with {n} aliased fields without "
                        "rejection, indicating no query-complexity/alias limiting — a "
                        "resource-exhaustion (DoS) amplification vector."),
        "remediation": "Enforce query complexity/depth/alias limits (e.g., a cost-analysis plugin).",
    }


def classify_batch_response(status, body, m):
    """Finding quando a resposta é um array de >= 2 resultados (batch processado)."""
    try:
        obj = json.loads(body or "")
    except (ValueError, TypeError):
        return None
    if isinstance(obj, list) and len(obj) >= 2:
        return {
            "tool": "graphql_dos", "type": "graphql_batching_enabled", "source": "GraphQL",
            "name": "GraphQL query batching enabled",
            "severity": "low", "cve": "CWE-770",
            "description": (f"The endpoint processed a batched array of {len(obj)} operations, "
                            "enabling request amplification (brute-force/DoS)."),
            "remediation": "Disable array-based query batching or bound the batch size.",
        }
    return None
```

- [ ] **Step 4: Rodar para verificar verde**

Run: `python3 -m pytest tests/test_graphql_dos.py -q`
Expected: PASS (8 testes).

- [ ] **Step 5: Commit**

```bash
git add lib/graphql_dos.py tests/test_graphql_dos.py
git commit -m "$(cat <<'MSG'
feat(graphql): probes de DoS (aliasing/batching) + classificação

build_alias_probe/build_batch_probe (__typename), classify_alias_response
(n aliases resolvidos sem errors → no-complexity-limit) e classify_batch_response
(array >=2 → batching enabled). Lógica pura.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
MSG
)"
```

---

### Task 3: `graphql_dos.run` (detecção + dry-run) + CLI

**Files:**
- Modify: `lib/graphql_dos.py` (adiciona `run`, `_send`, `main`, `import` de subprocess local)
- Modify: `tests/test_graphql_dos.py` (testes de `run`)

**Interfaces:**
- Consumes: `build_alias_probe`, `build_batch_probe`, `classify_*`, `_is_graphql_response` (Task 2)
- Produces: `run(url, profile, send_fn, n=None, m=None) -> list`; `main(argv) -> None`

- [ ] **Step 1: Escrever os testes que falham**

Adicionar a `tests/test_graphql_dos.py`:
```python
def _fake_send_factory(responses):
    """responses: dict mapeando a 1ª query-substring → {status, body}."""
    calls = []
    def send(url, payload):
        calls.append(payload)
        q = json.dumps(payload)
        for key, resp in responses.items():
            if key in q:
                return resp
        return {"status": 200, "body": '{"data":{"__typename":"Query"}}'}
    send.calls = calls
    return send


def test_run_noop_on_non_graphql(monkeypatch):
    send = _fake_send_factory({"__typename": {"status": 200, "body": "<html/>"}})
    out = gd.run("http://t/graphql", "staging", send)
    assert out == []

def test_run_production_is_dry_run(monkeypatch):
    # detecção GraphQL ok, mas probes de amplificação NÃO são enviados
    send = _fake_send_factory({"__typename": {"status": 200, "body": '{"data":{"__typename":"Query"}}'}})
    out = gd.run("http://t/graphql", "production", send, n=10, m=3)
    assert len(send.calls) == 1  # só a detecção
    assert any(f["type"] == "graphql_dos_dryrun" for f in out)

def test_run_staging_sends_and_classifies(monkeypatch):
    def send(url, payload):
        # detecção
        if payload == {"query": "{__typename}"}:
            return {"status": 200, "body": '{"data":{"__typename":"Query"}}'}
        # aliasing: devolve os n aliases resolvidos
        if isinstance(payload, dict) and payload.get("query", "").startswith("{ a0:"):
            data = {"data": {f"a{i}": "Query" for i in range(10)}}
            return {"status": 200, "body": json.dumps(data)}
        # batching
        if isinstance(payload, list):
            return {"status": 200, "body": json.dumps([{"data": {}}] * len(payload))}
        return {"status": 200, "body": "{}"}
    out = gd.run("http://t/graphql", "staging", send, n=10, m=3)
    types = {f["type"] for f in out}
    assert "graphql_no_complexity_limit" in types
    assert "graphql_batching_enabled" in types
```

- [ ] **Step 2: Rodar para verificar a falha**

Run: `python3 -m pytest tests/test_graphql_dos.py -k run -q`
Expected: FAIL com `AttributeError: module 'graphql_dos' has no attribute 'run'`.

- [ ] **Step 3: Implementar**

Adicionar a `lib/graphql_dos.py`:
```python
def run(url, profile, send_fn, n=None, m=None):
    """Detecta o endpoint via {__typename}; roda probes de aliasing/batching.

    production → dry-run (não envia amplificação). Fail-soft. Retorna lista de findings.
    """
    n = n or _alias_n()
    m = m or _batch_m()
    findings = []
    try:
        det = send_fn(url, {"query": "{__typename}"})
    except Exception:
        return []
    if not _is_graphql_response(det.get("status"), det.get("body")):
        return []
    if (profile or "").lower() == "production":
        findings.append({
            "tool": "graphql_dos", "type": "graphql_dos_dryrun", "source": "GraphQL",
            "name": "GraphQL DoS probes skipped (production dry-run)",
            "severity": "info", "cve": "CWE-770", "url": url,
            "description": (f"GraphQL endpoint detected. Aliasing ({n} aliases) and batching "
                            f"({m} ops) probes were NOT sent (production profile). Re-run in a "
                            "staging window to confirm complexity/batch limiting."),
            "remediation": "Confirm query-complexity and batch limits in an approved window.",
        })
        return findings
    try:
        ar = send_fn(url, build_alias_probe(n))
        f = classify_alias_response(ar.get("status"), ar.get("body"), n)
        if f:
            f["url"] = url
            findings.append(f)
    except Exception:
        pass
    try:
        br = send_fn(url, build_batch_probe(m))
        f = classify_batch_response(br.get("status"), br.get("body"), m)
        if f:
            f["url"] = url
            findings.append(f)
    except Exception:
        pass
    return findings


def _send(url, payload):
    """POST default via netproxy/mtls (curl). Retorna {status, body}."""
    import subprocess
    import netproxy
    import mtls
    cmd = ["curl", *netproxy.curl_proxy_args(), *mtls.curl_cert_args(), "-s", "-S",
           "--max-time", "15", "-X", "POST", "-H", "Content-Type: application/json",
           "-o", "-", "-w", "\n__HTTP_STATUS__:%{http_code}",
           "-d", json.dumps(payload), "--", url]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        raw = p.stdout or ""
    except Exception:
        return {"status": 0, "body": ""}
    status, body = 0, raw
    marker = raw.rfind("__HTTP_STATUS__:")
    if marker != -1:
        body = raw[:marker].rstrip("\n")
        try:
            status = int(raw[marker + len("__HTTP_STATUS__:"):].strip())
        except ValueError:
            status = 0
    return {"status": status, "body": body}


def main(argv):
    outdir, url = argv[1], argv[2]
    profile = os.environ.get("STIGLITZ_PROFILE", "staging")
    findings = run(url, profile, _send)
    for i, f in enumerate(findings, 1):
        f["id"] = f"GQLDOS-{i:03d}"
    out = os.path.join(outdir, "raw", "graphql_dos.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(findings, fh, indent=2, ensure_ascii=False)
    print(f"  [{'✓' if findings else '○'}] GraphQL DoS: {len(findings)} finding(s) → graphql_dos.json")


if __name__ == "__main__":
    main(sys.argv)
```

- [ ] **Step 4: Rodar para verificar verde**

Run: `python3 -m pytest tests/test_graphql_dos.py -q`
Expected: PASS (11 testes). Output pristino.

- [ ] **Step 5: Commit**

```bash
git add lib/graphql_dos.py tests/test_graphql_dos.py
git commit -m "$(cat <<'MSG'
feat(graphql): graphql_dos.run (detecção {__typename} + dry-run em prod) + CLI

run detecta o endpoint sem depender de introspection; em production faz dry-run
(não envia amplificação); em staging/lab envia e classifica. _send via curl
(netproxy+mtls). CLI grava raw/graphql_dos.json.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
MSG
)"
```

---

### Task 4: `graphql_authz.py` — seleção + replay + classificação

**Files:**
- Create: `lib/graphql_authz.py`
- Create: `tests/test_graphql_authz.py`

**Interfaces:**
- Consumes: `bola.parse_zap_messages`, `bola.extract_canary`, `bola.verdict`; `graphql_audit.is_mutation`, `graphql_audit._SENSITIVE_RE`
- Produces: `select_graphql_messages(messages, endpoint_substr="graphql") -> list`; `_classify(req) -> str`; `_replay(req, token) -> dict`

- [ ] **Step 1: Escrever os testes que falham**

Criar `tests/test_graphql_authz.py`:
```python
# tests/test_graphql_authz.py
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
import graphql_authz as gz


def _msg(method, url, body, status=200, resp=""):
    return {"method": method, "url": url, "req_body": body,
            "status": status, "resp_body": resp, "req_headers": ""}


def test_select_only_graphql_posts():
    msgs = [
        _msg("POST", "http://t/graphql", '{"query":"{ me { id } }"}'),
        _msg("GET", "http://t/graphql", ""),                       # não-POST
        _msg("POST", "http://t/api/users/1", '{"x":1}'),            # não-graphql path
        _msg("POST", "http://t/v1/graphql", '{"query":"mutation { x }"}'),
    ]
    out = gz.select_graphql_messages(msgs)
    urls = [m["url"] for m in out]
    assert urls == ["http://t/graphql", "http://t/v1/graphql"]


def test_classify_mutation_is_bfla():
    req = _msg("POST", "http://t/graphql", '{"query":"mutation { deleteUser(id:1){ ok } }"}')
    assert gz._classify(req) == "graphql_bfla"

def test_classify_sensitive_name_is_bfla():
    req = _msg("POST", "http://t/graphql", '{"query":"{ adminPanel { secret } }"}')
    assert gz._classify(req) == "graphql_bfla"

def test_classify_plain_query_is_bola():
    req = _msg("POST", "http://t/graphql", '{"query":"{ account(id:1){ balance } }"}')
    assert gz._classify(req) == "graphql_bola"
```

- [ ] **Step 2: Rodar para verificar a falha**

Run: `python3 -m pytest tests/test_graphql_authz.py -q`
Expected: FAIL com `ModuleNotFoundError: No module named 'graphql_authz'`.

- [ ] **Step 3: Implementar (parte 1 — sem `run`/CLI, que vêm na Task 5)**

Criar `lib/graphql_authz.py`:
```python
#!/usr/bin/env python3
"""graphql_authz.py — field-level authorization (BOLA/BFLA) em GraphQL.

Reusa o núcleo de confirmação do bola.py (verdict + extract_canary) sobre as
operações GraphQL reais capturadas no histórico do ZAP. Replaya cada operação
com token-a/token-b/unauth e confirma acesso indevido. Só queries por padrão;
mutations exigem mutate=True + profile != production. Lógica pura + replay_fn injetável.
"""
import json
import os
import sys
import urllib.parse

import bola
import graphql_audit

try:
    from fingerprint import fingerprint as _fingerprint
except Exception:
    def _fingerprint(f):
        return "0" * 16

_SENSITIVE = graphql_audit._SENSITIVE_RE


def select_graphql_messages(messages, endpoint_substr="graphql"):
    """POSTs ao endpoint GraphQL com corpo de operação, a partir do dump ZAP."""
    out = []
    for m in messages:
        if (m.get("method") or "").upper() != "POST":
            continue
        if endpoint_substr not in (m.get("url") or "").lower():
            continue
        body = m.get("req_body") or ""
        if '"query"' in body or '"mutation"' in body or "operationName" in body:
            out.append(m)
    return out


def _classify(req):
    """graphql_bfla se mutation ou nome sensível; senão graphql_bola."""
    body = req.get("req_body") or ""
    if graphql_audit.is_mutation(body) or _SENSITIVE.search(body):
        return "graphql_bfla"
    return "graphql_bola"


def _replay(req, token):
    """POST do corpo GraphQL trocando o Authorization. token=None → unauth.
    Retorna {status, body}. Reusa netproxy/mtls."""
    import subprocess
    import netproxy
    import mtls
    url = req.get("url") or ""
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return {"status": 0, "body": ""}
    cmd = ["curl", *netproxy.curl_proxy_args(), *mtls.curl_cert_args(), "-s", "-S",
           "--max-time", "15", "-X", "POST", "-H", "Content-Type: application/json",
           "-o", "-", "-w", "\n__HTTP_STATUS__:%{http_code}",
           "-d", req.get("req_body") or "", "--", url]
    if token:
        cmd += ["-H", f"Authorization: Bearer {token}"]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        raw = p.stdout or ""
    except Exception:
        return {"status": 0, "body": ""}
    status, body = 0, raw
    marker = raw.rfind("__HTTP_STATUS__:")
    if marker != -1:
        body = raw[:marker].rstrip("\n")
        try:
            status = int(raw[marker + len("__HTTP_STATUS__:"):].strip())
        except ValueError:
            status = 0
    return {"status": status, "body": body}
```

- [ ] **Step 4: Rodar para verificar verde**

Run: `python3 -m pytest tests/test_graphql_authz.py -q`
Expected: PASS (4 testes).

- [ ] **Step 5: Commit**

```bash
git add lib/graphql_authz.py tests/test_graphql_authz.py
git commit -m "$(cat <<'MSG'
feat(graphql): authz — seleção de ops do dump ZAP + replay + classificação

select_graphql_messages filtra POSTs GraphQL do histórico; _classify mapeia
mutation/nome-sensível → graphql_bfla, senão graphql_bola; _replay POSTa o corpo
trocando o Authorization (netproxy+mtls).

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
MSG
)"
```

---

### Task 5: `graphql_authz.run` + findings + dedup + CLI

**Files:**
- Modify: `lib/graphql_authz.py` (adiciona `run`, `main`)
- Modify: `tests/test_graphql_authz.py` (testes de `run`)

**Interfaces:**
- Consumes: `select_graphql_messages`, `_classify`, `_replay` (Task 4); `bola.verdict`, `bola.extract_canary`
- Produces: `run(messages, token_a, token_b, outdir, replay_fn=_replay, mutate=False, profile="staging") -> list`; `main(argv) -> int`

- [ ] **Step 1: Escrever os testes que falham**

Adicionar a `tests/test_graphql_authz.py`:
```python
def _msgs_with_owner_data():
    # baseline (token A) devolveu o email do dono no corpo
    return [_msg("POST", "http://t/graphql", '{"query":"{ me { email } }"}',
                 status=200, resp='{"data":{"me":{"email":"alice@corp.com"}}}')]


def test_run_confirms_bola_when_cross_leaks_owner_data(tmp_path):
    msgs = _msgs_with_owner_data()
    def replay_fn(req, token):
        # token B (cross) recebe o MESMO dado do dono → BOLA confirmado
        if token == "B":
            return {"status": 200, "body": '{"data":{"me":{"email":"alice@corp.com"}}}'}
        return {"status": 401, "body": ""}  # unauth negado
    out = gz.run(msgs, "A", "B", str(tmp_path), replay_fn=replay_fn)
    assert len(out) == 1
    assert out[0]["type"] == "graphql_bola"
    assert out[0]["confirmed"] is True
    assert os.path.exists(os.path.join(str(tmp_path), "raw", "graphql_authz.json"))


def test_run_skips_mutation_without_optin(tmp_path):
    msgs = [_msg("POST", "http://t/graphql", '{"query":"mutation { pay(amount:1){ id } }"}',
                 status=200, resp='{"data":{"pay":{"id":"x"}}}')]
    calls = []
    def replay_fn(req, token):
        calls.append(token)
        return {"status": 200, "body": '{"data":{"pay":{"id":"x"}}}'}
    out = gz.run(msgs, "A", "B", str(tmp_path), replay_fn=replay_fn, mutate=False)
    assert calls == []          # mutation nunca replayada sem opt-in
    assert out == []


def test_run_mutation_optin_blocked_in_production(tmp_path):
    msgs = [_msg("POST", "http://t/graphql", '{"query":"mutation { pay(amount:1){ id } }"}',
                 status=200, resp='{}')]
    calls = []
    def replay_fn(req, token):
        calls.append(token)
        return {"status": 200, "body": "{}"}
    out = gz.run(msgs, "A", "B", str(tmp_path), replay_fn=replay_fn, mutate=True, profile="production")
    assert calls == []          # gating duplo: mutate=True mas production → pulado


def test_run_dedups_same_host_path_class(tmp_path):
    op = '{"query":"{ account(id:1){ balance } }"}'
    msgs = [_msg("POST", "http://t/graphql", op, status=200, resp='{"data":{"account":{"id":"1"}}}'),
            _msg("POST", "http://t/graphql", op, status=200, resp='{"data":{"account":{"id":"1"}}}')]
    def replay_fn(req, token):
        if token == "B":
            return {"status": 200, "body": '{"data":{"account":{"id":"1"}}}'}
        return {"status": 401, "body": ""}
    out = gz.run(msgs, "A", "B", str(tmp_path), replay_fn=replay_fn)
    assert len(out) == 1        # mesma (host, path, class) → 1 finding
```

- [ ] **Step 2: Rodar para verificar a falha**

Run: `python3 -m pytest tests/test_graphql_authz.py -k run -q`
Expected: FAIL com `AttributeError: module 'graphql_authz' has no attribute 'run'`.

- [ ] **Step 3: Implementar**

Adicionar a `lib/graphql_authz.py`:
```python
def run(messages, token_a, token_b, outdir, replay_fn=_replay, mutate=False, profile="staging"):
    """Replaya as operações GraphQL com 2 tokens; grava raw/graphql_authz.json.

    Só queries por padrão; mutations só com mutate=True E profile != production.
    """
    corpus = select_graphql_messages(messages)
    seen = set()
    findings = []
    prod = (profile or "").lower() == "production"
    for req in corpus:
        if graphql_audit.is_mutation(req.get("req_body") or "") and not (mutate and not prod):
            continue
        baseline = {"status": req.get("status"), "body": req.get("resp_body")}
        canary = bola.extract_canary(req.get("resp_body"), "")
        cross = replay_fn(req, token_b)
        unauth = replay_fn(req, None)
        v = bola.verdict(baseline, cross, unauth, canary)
        if v["state"] not in ("CONFIRMED", "INCONCLUSIVE"):
            continue
        klass = _classify(req)
        sp = urllib.parse.urlsplit(req.get("url") or "")
        key = (sp.netloc, sp.path, klass)
        if key in seen:
            continue
        seen.add(key)
        confirmed = v["state"] == "CONFIRMED"
        finding = {
            "type": klass,
            "cwe": "CWE-639" if klass == "graphql_bola" else "CWE-285",
            "url": req.get("url", ""), "param": "",
            "severity": "high" if confirmed else "info",
            "confirmed": confirmed, "confidence": v.get("confidence", 0),
            "canary_hit": v.get("canary_hit", False), "source": "graphql_authz",
            "poc_note": f"GraphQL access-control {v['state']} via token-B replay",
        }
        finding["fingerprint"] = _fingerprint(finding)
        findings.append(finding)
    out = os.path.join(outdir, "raw", "graphql_authz.json")
    try:
        os.makedirs(os.path.dirname(out), exist_ok=True)
        with open(out, "w", encoding="utf-8") as fh:
            json.dump(findings, fh, indent=2, ensure_ascii=False)
    except Exception as exc:
        print(f"aviso: não foi possível gravar graphql_authz.json: {exc}", file=sys.stderr)
    return findings


def main(argv):
    """uso: graphql_authz.py <zap_messages.json> <outdir> (tokens via env)."""
    with open(argv[1], encoding="utf-8") as fh:
        messages = bola.parse_zap_messages(fh.read())
    outdir = argv[2]
    tok_a = os.environ.get("BOLA_TOKEN_A", "")
    tok_b = os.environ.get("BOLA_TOKEN_B", "")
    if not tok_a or not tok_b:
        print("  [○] GraphQL authz: 2 tokens necessários — pulado")
        return 0
    if tok_a == tok_b:
        print("  [○] GraphQL authz: TOKEN_A == TOKEN_B — pulado", file=sys.stderr)
        return 0
    mutate = os.environ.get("STIGLITZ_GQL_MUTATE", "") == "1"
    profile = os.environ.get("STIGLITZ_PROFILE", "staging")
    findings = run(messages, tok_a, tok_b, outdir, mutate=mutate, profile=profile)
    print(f"  [{'✓' if findings else '○'}] GraphQL authz: {len(findings)} finding(s) → graphql_authz.json")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
```

- [ ] **Step 4: Rodar para verificar verde**

Run: `python3 -m pytest tests/test_graphql_authz.py -q`
Expected: PASS (8 testes). Output pristino.

- [ ] **Step 5: Commit**

```bash
git add lib/graphql_authz.py tests/test_graphql_authz.py
git commit -m "$(cat <<'MSG'
feat(graphql): authz.run — replay 2-token + veredito bola + dedup + CLI

run reusa bola.verdict/extract_canary sobre as ops do histórico ZAP; queries-only
default, mutations com gating duplo (mutate + profile != production); findings
graphql_bola/graphql_bfla com fingerprint; dedup por (host, path, class). CLI lê
tokens do env (BOLA_TOKEN_A/_B).

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
MSG
)"
```

---

### Task 6: Integração no `stiglitz.sh` + `pipeline.py` + report

**Files:**
- Modify: `stiglitz.sh` (DoS no bloco GraphQL ~1791; flag `--graphql-mutate` + var `GRAPHQL_MUTATE`; sub-fase P9.8 após P9.7)
- Modify: `pipeline.py` (adicionar `P9_8` ao grupo combinado P9)
- Modify: `stiglitz_report.py` (linha ~946: ingerir `graphql_dos.json` + `graphql_authz.json`)
- Create: `tests/test_graphql_stiglitz_integration.py`

**Interfaces:**
- Consumes: CLI `graphql_dos.py <outdir> <url>` (Task 3); CLI `graphql_authz.py <msgs> <outdir>` (Task 5)

- [ ] **Step 1: Escrever o guard source-level que falha**

Criar `tests/test_graphql_stiglitz_integration.py`:
```python
# tests/test_graphql_stiglitz_integration.py
import os

ROOT = os.path.join(os.path.dirname(__file__), "..")


def _read(p):
    with open(os.path.join(ROOT, p), encoding="utf-8") as fh:
        return fh.read()


def test_dos_invoked_in_graphql_block():
    assert "graphql_dos.py" in _read("stiglitz.sh")

def test_p98_gated_on_two_tokens():
    src = _read("stiglitz.sh")
    assert 'graphql_authz.py' in src
    # a sub-fase P9.8 é gated em TOKEN_A e TOKEN_B
    i = src.index("P9_8")
    window = src[i:i + 400]
    assert '[ -n "$TOKEN_A" ]' in window and '[ -n "$TOKEN_B" ]' in window

def test_graphql_mutate_flag_parsed():
    assert "--graphql-mutate" in _read("stiglitz.sh")

def test_report_ingests_new_json():
    src = _read("stiglitz_report.py")
    assert "graphql_dos.json" in src and "graphql_authz.json" in src

def test_pipeline_includes_p9_8():
    assert "P9_8" in _read("pipeline.py")
```

- [ ] **Step 2: Rodar para verificar a falha**

Run: `python3 -m pytest tests/test_graphql_stiglitz_integration.py -q`
Expected: FAIL (os blocos ainda não existem).

- [ ] **Step 3: DoS no bloco GraphQL do `stiglitz.sh`**

Localizar (em `stiglitz.sh`, ~linha 1797-1802):
```bash
            if echo "$_gql_resp" | grep -q '"__schema"'; then
                echo -e "  ${GREEN}[✓]${NC} GraphQL introspection respondeu em ${_gql}"
                echo "$_gql_resp" > "$OUTDIR/raw/graphql_resp.json"
                python3 "$SCRIPT_DIR/lib/graphql_audit.py" "$OUTDIR" "$_gql" || true
                break
            fi
```
Substituir por:
```bash
            if echo "$_gql_resp" | grep -qE '"__schema"|"errors"|"data"'; then
                # endpoint GraphQL detectado (mesmo com introspection desabilitada → "errors")
                if echo "$_gql_resp" | grep -q '"__schema"'; then
                    echo -e "  ${GREEN}[✓]${NC} GraphQL introspection respondeu em ${_gql}"
                    echo "$_gql_resp" > "$OUTDIR/raw/graphql_resp.json"
                    python3 "$SCRIPT_DIR/lib/graphql_audit.py" "$OUTDIR" "$_gql" || true
                fi
                # DoS (batching/aliasing) — independe de introspection; dry-run em production
                STIGLITZ_PROFILE="${STIGLITZ_PROFILE:-staging}" \
                    python3 "$SCRIPT_DIR/lib/graphql_dos.py" "$OUTDIR" "$_gql" || true
                break
            fi
```

- [ ] **Step 4: Flag `--graphql-mutate` no parse de args**

Localizar o bloco de parse de flags (onde estão `--oauth-active)` etc., ~linha 342). Adicionar o default perto de `OAUTH_ACTIVE=0` (~linha 323):
```bash
GRAPHQL_MUTATE=""   # replay de mutations no P9.8 (opt-in, gated por profile)
```
E o case (junto de `--oauth-active)`):
```bash
        --graphql-mutate)    GRAPHQL_MUTATE=1 ;;
```

- [ ] **Step 5: Sub-fase P9.8 após a P9.7**

**Antes de inserir:** ler a definição de `_phase_enabled` em `stiglitz.sh` e confirmar como ele decide se uma fase roda. Se houver um registro/lista de fases conhecidas (ex.: um array de fases válidas, ou um default que retorna falso para fases não-listadas), **adicionar `P9_8` a esse registro** ao lado de `P9_7`, senão a fase nunca executará num run padrão. Se `_phase_enabled` retorna verdadeiro por padrão para qualquer fase quando não há `--only-phase`, nenhum registro precisa mudar — mas verifique e relate o que encontrou.

Localizar o fim do bloco da Fase 9.7 (após o `fi` que fecha `if _phase_enabled "P9_7" ...`). Inserir logo depois:
```bash

# ====================== FASE 9.8: GRAPHQL FIELD-LEVEL AUTHZ ======================
if _phase_enabled "P9_8" && [ -n "$TOKEN_A" ] && [ -n "$TOKEN_B" ]; then
phase_start "P9_8"
phase_banner "FASE 9.8/11: GRAPHQL FIELD-LEVEL AUTHZ (BOLA/BFLA)"
_zap_msgs_gql="$OUTDIR/raw/zap_messages_a.json"
# Reusa o dump do P9.5; se ausente (P9.5 desligada), dumpa agora
[ -s "$_zap_msgs_gql" ] || zap_api_call "core/view/messages" "" > "$_zap_msgs_gql" 2>/dev/null || true
if [ -s "$_zap_msgs_gql" ]; then
    BOLA_TOKEN_A="$TOKEN_A" BOLA_TOKEN_B="$TOKEN_B" \
        STIGLITZ_GQL_MUTATE="$GRAPHQL_MUTATE" STIGLITZ_PROFILE="${STIGLITZ_PROFILE:-staging}" \
        python3 "$SCRIPT_DIR/lib/graphql_authz.py" "$_zap_msgs_gql" "$OUTDIR" || true
else
    echo -e "  ${YELLOW}[○] sem histórico ZAP — GraphQL authz pulado${NC}"
fi
phase_done "P9_8"
fi
```

- [ ] **Step 6: `pipeline.py` — adicionar P9_8 ao grupo combinado P9**

Localizar a definição do grupo combinado P9 (procurar `"P9_7"` no `pipeline.py`). Acrescentar `"P9_8"` à mesma lista/string onde `P9 P9_5 P9_6 P9_7` é definido (ex.: `"P9 P9_5 P9_6 P9_7 P9_8"`).

- [ ] **Step 7: `stiglitz_report.py` — ingerir os 2 novos JSON**

Localizar (`stiglitz_report.py:946`):
```python
    ('graphql_findings.json',    'graphql_findings'),
```
Adicionar logo após:
```python
    ('graphql_dos.json',         'graphql_dos'),
    ('graphql_authz.json',       'graphql_authz'),
```

- [ ] **Step 8: Rodar guards + sintaxe + lint + suíte**

Run: `python3 -m pytest tests/test_graphql_stiglitz_integration.py -q`
Expected: PASS (5 testes).

Run: `bash -n stiglitz.sh && echo OK`
Expected: `OK`.

Run: `shellcheck --severity=warning stiglitz.sh`
Expected: sem saída (limpo). Se SC2086 aparecer em `STIGLITZ_PROFILE=... python3 ...`, manter como está (atribuição de env inline antes do comando é válida e quotada).

Run: `python3 -m py_compile pipeline.py stiglitz_report.py && echo OK`
Expected: `OK`.

Run: `python3 -m pytest tests/ -q`
Expected: PASS (todos).

- [ ] **Step 9: Commit**

```bash
git add stiglitz.sh pipeline.py stiglitz_report.py tests/test_graphql_stiglitz_integration.py
git commit -m "$(cat <<'MSG'
feat(graphql): integra DoS na Fase 9 + sub-fase P9.8 authz + ingestão no report

DoS roda no bloco GraphQL (detecção por data/errors/__schema, independe de
introspection). P9.8 (gated em 2 tokens) replaya o histórico ZAP via graphql_authz;
flag --graphql-mutate habilita mutations (gated por profile). pipeline.py inclui
P9_8 no grupo P9; o report ingere graphql_dos.json + graphql_authz.json.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
MSG
)"
```

---

### Task 7: Documentação

**Files:**
- Modify: `docs/ROADMAP.md` (marca o item GraphQL como ✅)
- Modify: `CLAUDE.md` (linhas de módulo + nota da Fase 9/P9.8)
- Modify: `CHANGELOG.md` (entrada no topo de Unreleased)

- [ ] **Step 1: `docs/ROADMAP.md`**

Substituir a linha `- ⏳ **GraphQL além de introspection**: ...` (linha ~133) por:
```markdown
- ✅ **GraphQL além de introspection** (`lib/graphql_dos.py` + `lib/graphql_authz.py`):
  DoS batching/aliasing (probes `__typename`, detecção independente de introspection,
  dry-run em `production`) na Fase 9; field-level authz (BOLA/BFLA) na **P9.8** —
  replay das operações reais do histórico ZAP com 2 tokens reusando `bola.verdict`,
  queries-only por padrão (mutations via `--graphql-mutate` + gating de profile)
```

- [ ] **Step 2: `CLAUDE.md`**

Na tabela de módulos `lib/`, após a linha de `oauth_token.py`, adicionar:
```markdown
| `graphql_dos.py` | Resource-exhaustion GraphQL (Fase 9): probes de aliasing/batching com `__typename` (detecção de endpoint independente de introspection), classificação de ausência de limite de complexidade/batch (CWE-770). Dry-run em `production`. Lógica pura + `send_fn` injetável + CLI |
| `graphql_authz.py` | Field-level authz GraphQL (BOLA/BFLA, fase **P9.8**): replaya as operações reais do histórico ZAP com 2 tokens (`--token-a`/`--token-b`), reusa `bola.verdict`/`extract_canary` → `graphql_bola`/`graphql_bfla`. Queries-only default; mutations via `--graphql-mutate` + gating de profile. Dedup por `(host, path, class)`. Lógica pura + `replay_fn` injetável + CLI |
```

Na seção da Fase 9, após o bullet da Fase 9.7, adicionar:
```markdown
   - **Fase 9.8** — GraphQL Field-Level Authz (`lib/graphql_authz.py`) — opt-in com `--token-a`+`--token-b`: replay das operações GraphQL do histórico ZAP com 2 tokens, confirma BOLA/BFLA por campo/mutation reusando o veredito do `bola.py` (queries-only; mutations via `--graphql-mutate` + profile). O probe de **DoS** (batching/aliasing, `lib/graphql_dos.py`) roda no bloco GraphQL da Fase 9, deslogado, com dry-run em `production`.
```

- [ ] **Step 3: `CHANGELOG.md`**

No topo da seção Unreleased:
```markdown
- **GraphQL além de introspection**: `lib/graphql_dos.py` (DoS batching/aliasing
  via probes `__typename`, dry-run em `production`) na Fase 9 e `lib/graphql_authz.py`
  (field-level authz BOLA/BFLA na P9.8, replay 2-token do histórico ZAP reusando
  `bola.py`, queries-only com mutations opt-in via `--graphql-mutate`).
```

- [ ] **Step 4: Validar**

Run: `python3 -m pytest tests/ -q`
Expected: PASS (todos).

Run: `bash -n stiglitz.sh && shellcheck --severity=warning stiglitz.sh && echo CLEAN`
Expected: `CLEAN`.

Run: `python3 -m py_compile lib/graphql_audit.py lib/graphql_dos.py lib/graphql_authz.py && echo OK`
Expected: `OK`.

- [ ] **Step 5: Commit**

```bash
git add docs/ROADMAP.md CLAUDE.md CHANGELOG.md
git commit -m "$(cat <<'MSG'
docs(graphql): ROADMAP (feito) + CLAUDE.md (módulos + P9.8) + CHANGELOG

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
MSG
)"
```

---

## Self-Review (preenchido pelo autor do plano)

**Spec coverage:**
- `is_mutation` helper → Task 1.
- DoS probes/classificação/run/dry-run → Tasks 2-3.
- Field-level authz (seleção, replay, veredito bola, graphql_bola/bfla, dedup, mutations gated) → Tasks 4-5.
- Integração Fase 9 DoS + P9.8 authz + report + pipeline → Task 6.
- Detecção independente de introspection (`{__typename}` + grep data/errors) → Task 3 (run) + Task 6 (bash).
- Gating: DoS dry-run em production (Task 3); mutate duplo-gate (Task 5); P9.8 2-token (Task 6).
- Findings em inglês; PT-BR no console; fail-soft → presente em todos os módulos.
- Docs → Task 7.

**Placeholder scan:** sem TBD/TODO; todo step de código mostra o código.

**Type consistency:** `run(url, profile, send_fn, n=None, m=None)` (dos) e `run(messages, token_a, token_b, outdir, replay_fn=_replay, mutate=False, profile="staging")` (authz) idênticos entre tasks; `send_fn(url, payload) -> {status, body}` e `replay_fn(req, token) -> {status, body}` consistentes; `is_mutation`, `select_graphql_messages`, `_classify`, `classify_alias_response`/`classify_batch_response` com nomes estáveis. **Refinamento do spec:** o authz usa builder próprio (classes `graphql_bola`/`graphql_bfla`) reusando `bola.verdict`/`extract_canary`, NÃO `bola.build_findings` (que fixa classes REST) — registrado aqui para o revisor.

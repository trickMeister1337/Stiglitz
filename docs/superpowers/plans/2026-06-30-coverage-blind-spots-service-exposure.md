# Coverage & Blind Spots + Service Exposure — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fechar a cegueira de descoberta (Modo A) com um probe de exposição de serviços dirigido por catálogo, e declarar lacunas de cobertura (Modo B) numa seção dedicada do relatório.

**Architecture:** Dois módulos puros novos seguindo o padrão `apm_probe.py` (lógica pura + `send_fn` injetável + CLI + fail-safe). `lib/service_exposure.py` sonda um catálogo de serviços HTTP contra `$TARGET` na Fase 3 → `raw/service_exposure.json`, ingerido pelo report como findings `estimated`. `lib/coverage.py` deriva dimensões de lacuna a partir de sinais já computados e renderiza uma seção HTML que **não** entra em `severity_counts`.

**Tech Stack:** Python 3 stdlib (urllib/subprocess/json), pytest. Reusa `netproxy`/`mtls`/`fingerprint`. Sem dependências novas.

## Global Constraints

- **Idioma:** findings/relatório em **inglês** (deliverable); console/comentários/docstrings em **PT-BR**.
- **Não-destrutivo:** probes usam **apenas GET** — nada que altere estado no alvo.
- **Fail-safe:** só emite finding com serviço fingerprintado **E** veredito `CONFIRMED`; caso contrário no-op silencioso (lista vazia).
- **Wiring sem `vuln_class`:** findings ingeridos como `estimated` (NÃO setar `vuln_class` no report) — o piso preserva a severidade do catálogo (igual APM/TLS); forçar o catálogo deixaria o environmental rebaixar High→Medium.
- **Catálogo é dado embutido:** `SERVICE_CATALOG` é um dict Python no módulo (conhecimento da ferramenta, testável puro, sem I/O).
- **Aditivo:** não reescrever `apm_probe.py` nem `monitoring_check.py`; não repetir `/metrics`/`/actuator/prometheus` no catálogo (dedup semântico cobre sobreposição residual).
- **Validação por commit:** `python3 -m pytest tests/` verde (baseline 943+); `python3 -m py_compile` nos arquivos tocados; `bash -n stiglitz.sh` quando tocá-lo.

## File Structure

- `lib/service_exposure.py` (criar) — catálogo + fingerprint + classificadores + orquestração + CLI.
- `lib/coverage.py` (criar) — `blind_spots(signals)` + `render_section_html(dimensions)`.
- `tests/test_service_exposure.py` (criar) — núcleo puro + orquestração com `send_fn` fake.
- `tests/test_coverage.py` (criar) — dimensões + render.
- `stiglitz.sh` (modificar `:1099`) — invocação na Fase 3.
- `stiglitz_report.py` (modificar `:925-950`, `:1106-1119`, `:2510-2514`) — ingest + seção + migração do coverage finding.

---

### Task 1: Catálogo + fingerprint do serviço (`lib/service_exposure.py`)

**Files:**
- Create: `lib/service_exposure.py`
- Test: `tests/test_service_exposure.py`

**Interfaces:**
- Produces: `SERVICE_CATALOG` (dict), `markers_match(body, markers) -> bool`, `is_service(status, body, markers) -> bool`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_service_exposure.py
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
import service_exposure as se


def test_markers_match_all_present_non_html():
    assert se.markers_match('{"tagline":"You Know, for Search","version":{"lucene_version":"9.7"}}',
                            ["you know, for search", "lucene_version"]) is True


def test_markers_match_html_body_disqualifies():
    assert se.markers_match("<html><body>You Know, for Search</body></html>",
                            ["you know, for search"]) is False


def test_markers_match_missing_marker():
    assert se.markers_match('{"tagline":"You Know, for Search"}', ["lucene_version"]) is False


def test_is_service_requires_200():
    assert se.is_service(401, '{"lucene_version":"9.7"}', ["lucene_version"]) is False
    assert se.is_service(200, '{"lucene_version":"9.7"}', ["lucene_version"]) is True


def test_catalog_has_expected_services():
    names = {s["name"] for s in se.SERVICE_CATALOG.values()}
    assert {"Elasticsearch", "Kibana", "Grafana", "Spring Boot Actuator", "Consul",
            "etcd", "Docker Engine API", "Kubernetes API", "RabbitMQ Management",
            "Apache Airflow", "Jenkins"} <= names
    # cada probe traz os campos exigidos pelo finding
    for spec in se.SERVICE_CATALOG.values():
        assert spec["fingerprint"] and spec["probes"]
        for pr in spec["probes"]:
            assert {"path", "finding_class", "severity", "cwe", "name", "exposes", "remediation"} <= set(pr)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_service_exposure.py -v`
Expected: FAIL (`ModuleNotFoundError: No module named 'service_exposure'`)

- [ ] **Step 3: Write minimal implementation**

```python
#!/usr/bin/env python3
"""
service_exposure.py — probe config-driven de serviços com exposição/acesso sem auth.

Generaliza o padrão do apm_probe.py num CATÁLOGO: serviço novo = uma entrada de
dados, não um módulo novo. Fecha a "cegueira de descoberta" (Modo A): serviços de
API pura (ES/Kibana/Grafana/Actuator/Consul/etcd/Docker/K8s/RabbitMQ/Airflow/Jenkins)
que o spider/katana não alcançam por falta de links e o nuclei não cobre por template.

Núcleo puro (catálogo + fingerprint + classificadores, testável sem rede) +
orquestração de rede fina (curl via netproxy/mtls, injetável). Findings em EN
(deliverable); console/comentários PT-BR.

Não-destrutivo: SOMENTE GET. Fail-safe: só emite com serviço fingerprintado E
veredito CONFIRMED. Espelha apm_probe.py / oauth_audit.py.

Uso (CLI): python3 lib/service_exposure.py <scan_dir> <target_url>
"""
import os
import sys
import json
import urllib.parse

import netproxy
import mtls

try:
    from fingerprint import fingerprint as _fingerprint
except Exception:  # importado fora de lib/
    def _fingerprint(f):
        return "0" * 16

_PROBE_TOKEN = "Bearer service-exposure-invalid-probe"

# ── Catálogo de serviços (conhecimento da ferramenta; dado embutido) ───────────
# Cada entrada: fingerprint (confirma o serviço, markers que COEXISTEM no corpo) +
# probes (endpoints sensíveis, só GET). description é gerada por template a partir
# de name/path/exposes; remediation é específica por serviço.
SERVICE_CATALOG = {
    "elasticsearch": {
        "name": "Elasticsearch",
        "fingerprint": [{"path": "/", "markers": ["you know, for search", "lucene_version"]}],
        "probes": [{"path": "/_cat/indices?format=json", "finding_class": "elasticsearch_unauth_data",
                    "severity": "high", "cwe": "CWE-306",
                    "name": "Elasticsearch indices readable without authentication",
                    "exposes": "all index names and document counts",
                    "remediation": "Enable the Elasticsearch security features (xpack.security.enabled: true) "
                                   "and require credentials; never expose the HTTP API to untrusted networks."}],
        "port": 9200,
    },
    "kibana": {
        "name": "Kibana",
        "fingerprint": [{"path": "/api/status", "markers": ["\"version\"", "kibana"]}],
        "probes": [{"path": "/api/status", "finding_class": "kibana_unauth_status",
                    "severity": "medium", "cwe": "CWE-306",
                    "name": "Kibana status API readable without authentication",
                    "exposes": "version, plugin and infrastructure status",
                    "remediation": "Enable Kibana/Elastic security and require login; restrict network exposure."}],
        "port": 5601,
    },
    "grafana": {
        "name": "Grafana",
        "fingerprint": [{"path": "/api/health", "markers": ["\"database\"", "\"version\""]}],
        "probes": [{"path": "/api/org", "finding_class": "grafana_anon_org",
                    "severity": "medium", "cwe": "CWE-306",
                    "name": "Grafana organization API reachable anonymously",
                    "exposes": "organization details with anonymous access enabled",
                    "remediation": "Disable anonymous auth ([auth.anonymous] enabled = false) and require login."}],
        "port": 3000,
    },
    "actuator": {
        "name": "Spring Boot Actuator",
        "fingerprint": [{"path": "/actuator", "markers": ["_links", "self"]}],
        "probes": [{"path": "/actuator/env", "finding_class": "actuator_env_exposed",
                    "severity": "high", "cwe": "CWE-200",
                    "name": "Spring Boot Actuator /env exposed without authentication",
                    "exposes": "environment properties (may include secrets and connection strings)",
                    "remediation": "Restrict actuator endpoints (management.endpoints.web.exposure.include) "
                                   "and require authentication; never expose /env, /heapdump in production."},
                   {"path": "/actuator/heapdump", "finding_class": "actuator_heapdump_exposed",
                    "severity": "high", "cwe": "CWE-200",
                    "name": "Spring Boot Actuator /heapdump downloadable without authentication",
                    "exposes": "a full JVM heap dump (credentials, tokens, in-memory data)",
                    "remediation": "Disable /heapdump exposure and require authentication on actuator endpoints."}],
        "port": 8080,
    },
    "consul": {
        "name": "Consul",
        "fingerprint": [{"path": "/v1/agent/self", "markers": ["\"config\"", "\"member\""]}],
        "probes": [{"path": "/v1/catalog/services", "finding_class": "consul_catalog_exposed",
                    "severity": "high", "cwe": "CWE-306",
                    "name": "Consul service catalog readable without an ACL token",
                    "exposes": "the full service catalog (internal topology)",
                    "remediation": "Enable ACLs with a default-deny policy (acl.default_policy = deny) and require tokens."}],
        "port": 8500,
    },
    "etcd": {
        "name": "etcd",
        "fingerprint": [{"path": "/version", "markers": ["etcdserver", "etcdcluster"]}],
        "probes": [{"path": "/v2/keys/", "finding_class": "etcd_keys_exposed",
                    "severity": "high", "cwe": "CWE-306",
                    "name": "etcd key-value store readable without authentication",
                    "exposes": "cluster keys (often config and secrets)",
                    "remediation": "Enable client cert auth / RBAC and require TLS client certificates."}],
        "port": 2379,
    },
    "docker": {
        "name": "Docker Engine API",
        "fingerprint": [{"path": "/version", "markers": ["apiversion", "components"]}],
        "probes": [{"path": "/containers/json", "finding_class": "docker_api_exposed",
                    "severity": "critical", "cwe": "CWE-306",
                    "name": "Docker Engine API exposed without authentication",
                    "exposes": "container control (equivalent to host root access)",
                    "remediation": "Never expose the Docker socket/API over TCP without mTLS; bind to localhost only."}],
        "port": 2375,
    },
    "kubernetes": {
        "name": "Kubernetes API",
        "fingerprint": [{"path": "/version", "markers": ["gitversion", "\"major\"", "\"minor\""]}],
        "probes": [{"path": "/api", "finding_class": "kubernetes_anon_api",
                    "severity": "high", "cwe": "CWE-306",
                    "name": "Kubernetes API reachable anonymously",
                    "exposes": "API group discovery with anonymous access enabled",
                    "remediation": "Disable anonymous auth (--anonymous-auth=false) and enforce RBAC."}],
        "port": 6443,
    },
    "rabbitmq": {
        "name": "RabbitMQ Management",
        "fingerprint": [{"path": "/api/overview", "markers": ["rabbitmq_version", "management_version"]}],
        "probes": [{"path": "/api/overview", "finding_class": "rabbitmq_mgmt_exposed",
                    "severity": "medium", "cwe": "CWE-306",
                    "name": "RabbitMQ Management API readable without authentication",
                    "exposes": "broker overview, nodes and stats",
                    "remediation": "Require authentication on the management plugin; do not expose default guest access."}],
        "port": 15672,
    },
    "airflow": {
        "name": "Apache Airflow",
        "fingerprint": [{"path": "/api/v1/health", "markers": ["metadatabase", "scheduler"]}],
        "probes": [{"path": "/api/v1/dags", "finding_class": "airflow_dags_exposed",
                    "severity": "high", "cwe": "CWE-306",
                    "name": "Airflow DAGs API readable without authentication",
                    "exposes": "workflow definitions and schedules",
                    "remediation": "Set the API auth backend to require authentication (auth_backends) and disable anonymous access."}],
        "port": 8080,
    },
    "jenkins": {
        "name": "Jenkins",
        "fingerprint": [{"path": "/api/json", "markers": ["hudson.model.hudson"]}],
        "probes": [{"path": "/script", "finding_class": "jenkins_script_console",
                    "severity": "critical", "cwe": "CWE-306",
                    "name": "Jenkins Groovy script console reachable without authentication",
                    "exposes": "arbitrary Groovy execution on the controller (RCE)",
                    "remediation": "Enable security (matrix/role auth), require login, and restrict the /script console to admins."}],
        "port": 8080,
    },
}


# ── Fingerprint (puro) ─────────────────────────────────────────────────────────
def markers_match(body, markers):
    """True se TODOS os markers (case-insensitive) estão no corpo e o corpo não é HTML.

    Corpo HTML desqualifica — uma SPA catch-all devolve index.html 200 p/ qualquer
    path (mesma guarda anti-FP do js_chunks.is_js_payload)."""
    b = (body or "").lower()
    if "<html" in b:
        return False
    return bool(markers) and all(str(m).lower() in b for m in markers)


def is_service(status, body, markers):
    """O serviço está fingerprintado: HTTP 200 + markers presentes em corpo não-HTML."""
    return status == 200 and markers_match(body, markers)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_service_exposure.py -v`
Expected: PASS (5 testes)

- [ ] **Step 5: Commit**

```bash
git add lib/service_exposure.py tests/test_service_exposure.py
git commit -m "feat(service-exposure): catálogo de serviços + fingerprint puro"
```

---

### Task 2: Classificador de exposição (`classify_exposure`)

**Files:**
- Modify: `lib/service_exposure.py`
- Test: `tests/test_service_exposure.py`

**Interfaces:**
- Produces: `classify_exposure(probe_status, probe_body, auth_status=None) -> {"state", "evidence"}` com `state ∈ {CONFIRMED, REJECTED, INCONCLUSIVE}`.

- [ ] **Step 1: Write the failing test**

```python
def test_classify_rejected_when_auth_required():
    v = se.classify_exposure(401, "")
    assert v["state"] == "REJECTED"
    v = se.classify_exposure(403, "")
    assert v["state"] == "REJECTED"


def test_classify_confirmed_on_200():
    v = se.classify_exposure(200, '{"ok":true}')
    assert v["state"] == "CONFIRMED"


def test_classify_confirmed_reinforced_by_auth_contrast():
    v = se.classify_exposure(200, "{}", auth_status=401)
    assert v["state"] == "CONFIRMED"
    assert "invalid token" in v["evidence"]


def test_classify_inconclusive_on_other_status():
    assert se.classify_exposure(404, "")["state"] == "INCONCLUSIVE"
    assert se.classify_exposure(0, "")["state"] == "INCONCLUSIVE"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_service_exposure.py -k classify -v`
Expected: FAIL (`AttributeError: module 'service_exposure' has no attribute 'classify_exposure'`)

- [ ] **Step 3: Write minimal implementation**

```python
# ── Classificador (puro) ───────────────────────────────────────────────────────
def classify_exposure(probe_status, probe_body, auth_status=None):
    """Veredito sobre o endpoint sensível acessado sem credencial.

    REJECTED   — 401/403 (protegido);
    CONFIRMED  — 200 sem auth (reforçado quando a 2ª sonda com token inválido dá 401/403);
    INCONCLUSIVE — qualquer outro status (404, host fora do ar, etc.).
    """
    if probe_status in (401, 403):
        return {"state": "REJECTED",
                "evidence": f"endpoint without auth -> HTTP {probe_status} (authentication required)"}
    if probe_status == 200:
        if auth_status in (401, 403):
            return {"state": "CONFIRMED",
                    "evidence": (f"without auth -> HTTP 200 (processed); "
                                 f"with invalid token -> HTTP {auth_status}")}
        return {"state": "CONFIRMED",
                "evidence": "endpoint without auth -> HTTP 200 (no authentication enforced)"}
    return {"state": "INCONCLUSIVE",
            "evidence": f"endpoint without auth -> HTTP {probe_status}"}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_service_exposure.py -k classify -v`
Expected: PASS (4 testes)

- [ ] **Step 5: Commit**

```bash
git add lib/service_exposure.py tests/test_service_exposure.py
git commit -m "feat(service-exposure): classificador CONFIRMED/REJECTED/INCONCLUSIVE"
```

---

### Task 3: Construção de findings (`build_findings`)

**Files:**
- Modify: `lib/service_exposure.py`
- Test: `tests/test_service_exposure.py`

**Interfaces:**
- Consumes: `SERVICE_CATALOG`, `_fingerprint`.
- Produces: `_finding(probe, base, spec, verdict) -> dict`, `build_findings(service_key, confirmed, target) -> [dict]` onde `confirmed` é uma lista de `(probe_dict, verdict_dict)`.

- [ ] **Step 1: Write the failing test**

```python
def test_build_findings_schema_and_cwe():
    spec = se.SERVICE_CATALOG["elasticsearch"]
    probe = spec["probes"][0]
    verdict = {"state": "CONFIRMED", "evidence": "without auth -> HTTP 200"}
    out = se.build_findings("elasticsearch", [(probe, verdict)], "https://host")
    assert len(out) == 1
    f = out[0]
    assert f["tool"] == "service_exposure"
    assert f["type"] == "elasticsearch_unauth_data"
    assert f["source"] == "Service Exposure"
    assert f["severity"] == "high"
    assert f["cwe"] == "CWE-306"
    assert f["url"] == "https://host/_cat/indices"   # query string removida
    assert "Elasticsearch" in f["name"]
    assert f["fingerprint"] and f["fingerprint"] != "0" * 16
    assert "all index names" in f["description"]


def test_build_findings_distinct_endpoints_distinct_fingerprints():
    spec = se.SERVICE_CATALOG["actuator"]
    v = {"state": "CONFIRMED", "evidence": "x"}
    out = se.build_findings("actuator", [(spec["probes"][0], v), (spec["probes"][1], v)], "https://h")
    assert len({f["fingerprint"] for f in out}) == 2
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_service_exposure.py -k build_findings -v`
Expected: FAIL (`AttributeError: ... 'build_findings'`)

- [ ] **Step 3: Write minimal implementation**

```python
# ── Findings ────────────────────────────────────────────────────────────────────
def _finding(probe, base, spec, verdict):
    """Schema do finding (igual apm_probe._finding). Texto em EN. description gerada
    por template a partir de name/path/exposes; remediation específica do catálogo."""
    url = base + probe["path"].split("?", 1)[0]
    description = (
        f"The {spec['name']} endpoint {probe['path']} responded to an unauthenticated "
        f"request with HTTP 200, exposing {probe['exposes']} without requiring credentials. "
        "An attacker on the network can reach this endpoint directly; the scan did not send "
        "any state-changing request (GET only).")
    f = {
        "tool": "service_exposure", "type": probe["finding_class"], "source": "Service Exposure",
        "name": probe["name"], "url": url, "severity": probe["severity"],
        "description": description, "remediation": probe["remediation"],
        "evidence": verdict.get("evidence", ""), "cwe": probe.get("cwe", ""),
    }
    f["fingerprint"] = _fingerprint(f)
    return f


def build_findings(service_key, confirmed, target):
    """Converte (probe, verdict) CONFIRMED em findings (EN). Não-CONFIRMED é ignorado."""
    spec = SERVICE_CATALOG.get(service_key) or {}
    base = (target or "").rstrip("/")
    out = []
    for probe, verdict in confirmed:
        if (verdict or {}).get("state") == "CONFIRMED":
            out.append(_finding(probe, base, spec, verdict))
    return out
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_service_exposure.py -k build_findings -v`
Expected: PASS (2 testes)

- [ ] **Step 5: Commit**

```bash
git add lib/service_exposure.py tests/test_service_exposure.py
git commit -m "feat(service-exposure): build_findings (schema EN + cwe + fingerprint)"
```

---

### Task 4: Orquestração (`send_request`, `run`) + CLI

**Files:**
- Modify: `lib/service_exposure.py`
- Test: `tests/test_service_exposure.py`

**Interfaces:**
- Consumes: `SERVICE_CATALOG`, `is_service`, `classify_exposure`, `build_findings`.
- Produces: `send_request(method, url, headers, data, timeout) -> (status, body)`, `run(scan_dir, target, send_fn=send_request, timeout=15) -> {"findings", "summary"}`, `main(argv)`.

- [ ] **Step 1: Write the failing test**

```python
import json as _json


class _Recorder:
    """send_fn fake: roteia por (method, path) e registra todas as chamadas."""
    def __init__(self, routes):
        self.routes = routes          # {(method, path): (status, body)}
        self.calls = []

    def __call__(self, method, url, headers, data, timeout=15):
        from urllib.parse import urlsplit
        path = urlsplit(url).path
        if "?" in url:
            path = url.split(url.split("//", 1)[1].split("/", 1)[0], 1)[-1]  # mantém querystring
        self.calls.append((method, url, dict(headers or {})))
        # casa por path (sem querystring) para simplificar
        from urllib.parse import urlsplit as _u
        key = (method, _u(url).path)
        return self.routes.get(key, (404, ""))


def test_run_detects_elasticsearch_and_emits_finding(tmp_path):
    routes = {
        ("GET", "/"): (200, '{"tagline":"You Know, for Search","version":{"lucene_version":"9.7"}}'),
        ("GET", "/_cat/indices"): (200, '[{"index":"users"}]'),
    }
    rec = _Recorder(routes)
    res = se.run(str(tmp_path), "https://host", send_fn=rec, timeout=1)
    assert res["summary"]["service"] == "elasticsearch"
    assert res["summary"]["total"] == 1
    assert res["findings"][0]["type"] == "elasticsearch_unauth_data"
    # gravou o JSON
    saved = _json.load(open(tmp_path / "raw" / "service_exposure.json"))
    assert saved[0]["type"] == "elasticsearch_unauth_data"


def test_run_failsafe_no_service(tmp_path):
    rec = _Recorder({})  # tudo 404
    res = se.run(str(tmp_path), "https://host", send_fn=rec, timeout=1)
    assert res["summary"]["service"] is None
    assert res["findings"] == []


def test_run_only_uses_get(tmp_path):
    routes = {
        ("GET", "/"): (200, '{"tagline":"You Know, for Search","version":{"lucene_version":"9.7"}}'),
        ("GET", "/_cat/indices"): (200, "[]"),
    }
    rec = _Recorder(routes)
    se.run(str(tmp_path), "https://host", send_fn=rec, timeout=1)
    assert all(c[0] == "GET" for c in rec.calls)   # NÃO-DESTRUTIVO


def test_run_rejected_emits_nothing(tmp_path):
    routes = {
        ("GET", "/"): (200, '{"tagline":"You Know, for Search","version":{"lucene_version":"9.7"}}'),
        ("GET", "/_cat/indices"): (401, ""),
    }
    rec = _Recorder(routes)
    res = se.run(str(tmp_path), "https://host", send_fn=rec, timeout=1)
    assert res["summary"]["service"] == "elasticsearch"
    assert res["findings"] == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_service_exposure.py -k run -v`
Expected: FAIL (`AttributeError: ... 'run'`)

- [ ] **Step 3: Write minimal implementation**

```python
# ── Rede (injetável) ────────────────────────────────────────────────────────────
def send_request(method, url, headers, data, timeout=15):
    """GET via curl (herda proxy/mTLS). Retorna (status, body). Não segue redirect; -k."""
    import subprocess
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return (0, "")
    cmd = ["curl", *netproxy.curl_proxy_args(), *mtls.curl_cert_args(),
           "-sk", "-S", "--max-time", str(timeout),
           "-o", "-", "-w", "\n__HTTP_STATUS__:%{http_code}", "-X", method]
    for k, v in (headers or {}).items():
        cmd += ["-H", f"{k}: {v}"]
    if data is not None:
        cmd += ["--data-binary", data]
    cmd += ["--", url]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 5)
        raw = p.stdout or ""
    except Exception:
        return (0, "")
    status, body = 0, raw
    sm = raw.rfind("__HTTP_STATUS__:")
    if sm != -1:
        body = raw[:sm].rstrip("\n")
        try:
            status = int(raw[sm:].split(":", 1)[1].strip())
        except (ValueError, IndexError):
            status = 0
    return (status, body)


# ── Orquestração ──────────────────────────────────────────────────────────────
def run(scan_dir, target, send_fn=send_request, timeout=15):
    """Fingerprinta o catálogo contra o alvo; no 1º serviço confirmado, sonda os
    endpoints sensíveis e emite findings CONFIRMED. Grava raw/service_exposure.json.

    Fail-safe: sem serviço fingerprintado → no-op (lista vazia). SOMENTE GET."""
    base = (target or "").rstrip("/")
    detected = None
    findings = []
    for key, spec in SERVICE_CATALOG.items():
        matched = False
        for fp in spec["fingerprint"]:
            st, bo = send_fn("GET", base + fp["path"], {}, None, timeout)
            if is_service(st, bo, fp["markers"]):
                matched = True
                break
        if not matched:
            continue
        detected = key
        confirmed = []
        for pr in spec["probes"]:
            st, bo = send_fn("GET", base + pr["path"], {}, None, timeout)
            auth_st = None
            if pr.get("auth_contrast"):
                auth_st, _ = send_fn("GET", base + pr["path"],
                                     {"Authorization": _PROBE_TOKEN}, None, timeout)
            verdict = classify_exposure(st, bo, auth_st)
            if verdict["state"] == "CONFIRMED":
                confirmed.append((pr, verdict))
        findings = build_findings(key, confirmed, base)
        break  # um host = um serviço; evita ruído e custo

    summary = {"service": detected, "total": len(findings)}
    raw_dir = os.path.join(scan_dir, "raw")
    try:
        os.makedirs(raw_dir, exist_ok=True)
        with open(os.path.join(raw_dir, "service_exposure.json"), "w", encoding="utf-8") as fh:
            json.dump(findings, fh, indent=2, ensure_ascii=False)
    except Exception as exc:
        print(f"  aviso: não foi possível gravar service_exposure.json: {exc}", file=sys.stderr)
    return {"findings": findings, "summary": summary}


# ── CLI ───────────────────────────────────────────────────────────────────────
def main(argv):
    if len(argv) >= 4 and argv[1] == "run":
        scan_dir, target = argv[2], argv[3]
    elif len(argv) >= 3:
        scan_dir, target = argv[1], argv[2]
    else:
        print("uso: service_exposure.py <scan_dir> <target_url>", file=sys.stderr)
        return 2
    res = run(scan_dir, target)
    s = res["summary"]
    if s["service"]:
        print(f"  service-exposure: {s['service']} detectado → {s['total']} finding(s)")
    else:
        print("  service-exposure: nenhum serviço do catálogo exposto sem auth")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_service_exposure.py -v && python3 -m py_compile lib/service_exposure.py`
Expected: PASS (todos) e py_compile sem erro

- [ ] **Step 5: Commit**

```bash
git add lib/service_exposure.py tests/test_service_exposure.py
git commit -m "feat(service-exposure): orquestração run + send_request + CLI (fail-safe, GET-only)"
```

---

### Task 5: Wiring no `stiglitz.sh` (Fase 3)

**Files:**
- Modify: `stiglitz.sh:1099` (logo após a invocação do `apm_probe`)

**Interfaces:**
- Consumes: `lib/service_exposure.py` CLI (`<scan_dir> <target>`).
- Produces: `raw/service_exposure.json` durante a Fase 3.

- [ ] **Step 1: Adicionar a invocação após o apm_probe**

Localizar (em `stiglitz.sh`, ~`:1099`):

```bash
echo -e "  ${BLUE}[…]${NC} Probe de APM Server (ingestão/config sem auth)..."
python3 "$SCRIPT_DIR/lib/apm_probe.py" "$OUTDIR" "$TARGET" || true
```

Inserir imediatamente depois:

```bash
# ── Service Exposure: serviços de API pura expostos sem auth (catálogo) ──────
# Generaliza o probe do APM: ES/Kibana/Grafana/Actuator/Consul/etcd/Docker/K8s/
# RabbitMQ/Airflow/Jenkins. Só GET, fail-safe (no-op fora do catálogo). → raw/service_exposure.json
echo -e "  ${BLUE}[…]${NC} Probe de exposição de serviços (catálogo, sem auth)..."
python3 "$SCRIPT_DIR/lib/service_exposure.py" "$OUTDIR" "$TARGET" || true
```

- [ ] **Step 2: Validar sintaxe e presença**

Run: `bash -n stiglitz.sh && grep -n "lib/service_exposure.py" stiglitz.sh`
Expected: sem erro de sintaxe; grep mostra a linha inserida

- [ ] **Step 3: Lint**

Run: `shellcheck --severity=warning stiglitz.sh`
Expected: sem novos warnings

- [ ] **Step 4: Commit**

```bash
git add stiglitz.sh
git commit -m "feat(scan): roda service_exposure na Fase 3 (após apm_probe)"
```

---

### Task 6: Ingest no `stiglitz_report.py`

**Files:**
- Modify: `stiglitz_report.py` — adicionar bloco de ingest após o bloco APM (`:950`) e incluir `service_findings` em `_all_f_raw` (`:1119`).
- Test: `tests/test_service_exposure_report_wiring.py` (criar)

**Interfaces:**
- Consumes: `raw/service_exposure.json`.
- Produces: lista `service_findings` agregada em `_all_f_raw`, sem `vuln_class` (estimated).

- [ ] **Step 1: Write the failing characterization test**

```python
# tests/test_service_exposure_report_wiring.py
import os, sys, json, subprocess, tempfile, pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent


def _run_report(outdir):
    env = dict(os.environ, OUTDIR=str(outdir), DOMAIN="host", TARGET="https://host",
               STIGLITZ_DEDUP="0")
    return subprocess.run([sys.executable, str(ROOT / "stiglitz_report.py")],
                          env=env, capture_output=True, text=True, cwd=str(ROOT))


def test_service_exposure_finding_reaches_findings_json(tmp_path):
    raw = tmp_path / "raw"
    raw.mkdir(parents=True)
    (raw / "service_exposure.json").write_text(json.dumps([{
        "tool": "service_exposure", "type": "docker_api_exposed", "source": "Service Exposure",
        "name": "Docker Engine API exposed without authentication",
        "url": "https://host/containers/json", "severity": "critical",
        "description": "x", "remediation": "y", "evidence": "z",
        "cwe": "CWE-306", "fingerprint": "abc123def456",
    }]))
    r = _run_report(tmp_path)
    assert r.returncode == 0, r.stderr
    fj = json.load(open(tmp_path / "findings.json"))
    arr = fj["findings"] if isinstance(fj, dict) else fj
    hit = [f for f in arr if f.get("type") == "docker_api_exposed"]
    assert hit, "service_exposure finding não chegou ao findings.json"
    assert hit[0]["severity"] == "critical"   # estimated preserva a severidade
```

> Nota ao implementador: confirme o formato exato de `findings.json` (dict com chave
> `findings` vs lista) lendo onde `stiglitz_report.py` o grava; ajuste o `arr =` acima
> ao formato real antes de rodar. O teste é a fonte de verdade do comportamento.

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_service_exposure_report_wiring.py -v`
Expected: FAIL (finding não aparece — ingest ainda não existe)

- [ ] **Step 3: Add the ingest block**

Em `stiglitz_report.py`, logo após o bloco APM (termina em `:950` com o `except ... errors.append(f"apm_probe: {e}")`), inserir:

```python
# ── Service Exposure Findings (lib/service_exposure.py — serviços sem auth) ─
# raw/service_exposure.json já traz findings prontos (mesmo schema do apm_probe);
# mantidos como 'estimated' (sem vuln_class) p/ o piso preservar a severity do
# catálogo (igual APM/TLS). Lista vazia = no-op (nenhum serviço do catálogo exposto).
service_findings = []
_se_path = os.path.join(OUTDIR, 'raw', 'service_exposure.json')
if os.path.exists(_se_path) and os.path.getsize(_se_path) > 0:
    try:
        for _sf in json.load(open(_se_path, 'r', encoding='utf-8')):
            _ssev = _sf.get('severity', 'medium')
            service_findings.append({
                "id":   f"svc-{_sf.get('type','issue')}",
                "name": _sf.get('name', 'Service exposure'),
                "severity": _ssev, "severity_orig": _ssev, "severity_reclassified": False,
                "source": _sf.get('source', 'Service Exposure'),
                "url": _sf.get('url', TARGET),
                "type": _sf.get('type', ''),
                "cve": _sf.get('cwe', ''), "cve_ids": [],
                "description": _sf.get('description', ''),
                "remediation": _sf.get('remediation', ''),
                "evidence": _sf.get('evidence', ''),
                "param": "", "attack": "", "other": "",
                "fingerprint": _sf.get('fingerprint', ''),
            })
    except Exception as e:
        errors.append(f"service_exposure: {e}")
```

Depois, em `:1119`, incluir `service_findings` na lista combinada:

```python
_all_f_raw = findings + zap_findings + header_findings + version_findings + tls_findings + email_findings + apm_findings + service_findings + coverage_findings
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_service_exposure_report_wiring.py -v && python3 -m py_compile stiglitz_report.py`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add stiglitz_report.py tests/test_service_exposure_report_wiring.py
git commit -m "feat(report): ingest service_exposure.json como findings estimated"
```

---

### Task 7: `lib/coverage.py` — `blind_spots(signals)`

**Files:**
- Create: `lib/coverage.py`
- Test: `tests/test_coverage.py`

**Interfaces:**
- Produces: `blind_spots(signals: dict) -> list[dict]` onde cada dimensão = `{area, status, not_exercised, how_to_close}`; `_STATUS_LABEL` dict.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_coverage.py
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
import coverage as cov


def test_empty_when_full_coverage():
    sig = {"nmap_ran": True, "fingerprinted_services": [], "probed_services": [],
           "live_hosts_no_surface": 0, "authed_api": {"count": 0, "has_token": False}}
    assert cov.blind_spots(sig) == []


def test_nmap_not_run_dimension():
    dims = cov.blind_spots({"nmap_ran": False})
    assert any(d["area"] == "Network port scan" and d["status"] == "not_run" for d in dims)


def test_fingerprinted_unprobed_dimension():
    dims = cov.blind_spots({"nmap_ran": True,
                            "fingerprinted_services": ["Redis", "Grafana"],
                            "probed_services": ["Grafana"]})
    d = [x for x in dims if x["area"] == "Fingerprinted services not probed"]
    assert d and "Redis" in d[0]["not_exercised"] and "Grafana" not in d[0]["not_exercised"]


def test_live_host_minimal_surface_dimension():
    dims = cov.blind_spots({"nmap_ran": True, "live_hosts_no_surface": 1})
    assert any(d["area"].startswith("Live host") for d in dims)


def test_authed_api_dimension_only_without_token():
    dims = cov.blind_spots({"nmap_ran": True, "authed_api": {"count": 12, "has_token": False}})
    assert any(d["area"] == "Authenticated API surface" for d in dims)
    dims2 = cov.blind_spots({"nmap_ran": True, "authed_api": {"count": 12, "has_token": True}})
    assert not any(d["area"] == "Authenticated API surface" for d in dims2)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_coverage.py -v`
Expected: FAIL (`ModuleNotFoundError: No module named 'coverage'` ou AttributeError)

> Nota: há um pacote `coverage` (cobertura de testes) instalável. O `sys.path.insert`
> coloca `lib/` à frente, então `import coverage` resolve para `lib/coverage.py`. Se
> houver conflito no ambiente, rode com `PYTHONPATH=lib`.

- [ ] **Step 3: Write minimal implementation**

```python
#!/usr/bin/env python3
"""coverage.py — declara lacunas de cobertura do scan ("Coverage & Blind Spots").

Lógica pura: recebe SINAIS já derivados pelo stiglitz_report.py e devolve as
dimensões de lacuna (transforma achado-oculto em lacuna-declarada). NÃO é finding
— não entra em severity_counts; é seção de apresentação (Modo B do roadmap de
cobertura). Findings/relatório em EN; comentários PT-BR.
"""
_STATUS_LABEL = {"not_run": "Not run", "partial": "Partial", "ok": "OK"}


def blind_spots(signals):
    """Retorna a lista de dimensões de lacuna (status != ok) a partir de `signals`.

    signals (todas opcionais, default seguro):
      nmap_ran: bool                      — port scan rodou e produziu saída
      nmap_note: str                      — nota custom (proxy/edge/timeout)
      fingerprinted_services: [str]       — serviços de infra detectados (tech_profile)
      probed_services: [str]              — serviços p/ os quais HÁ sonda ativa
      live_hosts_no_surface: int          — hosts vivos só com '/' e sem spec
      authed_api: {count:int, has_token:bool}
    """
    s = signals or {}
    dims = []

    if not s.get("nmap_ran"):
        dims.append({
            "area": "Network port scan",
            "status": "not_run",
            "not_exercised": s.get("nmap_note") or (
                "TCP port enumeration did not run, so services on non-web ports "
                "(databases, caches, orchestration) were not discovered."),
            "how_to_close": "Run a dedicated port scan (naabu/nmap) without proxy/edge "
                            "constraints, then re-scan the services it reveals.",
        })

    _unprobed = sorted(set(s.get("fingerprinted_services") or [])
                       - set(s.get("probed_services") or []))
    if _unprobed:
        dims.append({
            "area": "Fingerprinted services not probed",
            "status": "partial",
            "not_exercised": ("Detected by fingerprint but not actively probed for "
                              "unauthenticated exposure: " + ", ".join(_unprobed) + "."),
            "how_to_close": "Add a service_exposure catalog entry for each, or review "
                            "their access controls manually.",
        })

    _lh = s.get("live_hosts_no_surface") or 0
    if _lh:
        dims.append({
            "area": "Live host, minimal discovered surface",
            "status": "partial",
            "not_exercised": (f"{_lh} live host(s) exposed only '/' with no crawlable links "
                              "and no OpenAPI spec — pure-API services here are reached only "
                              "via targeted probes, not by the spider."),
            "how_to_close": "Provide an OpenAPI/Swagger spec (--osint-dir or seeding) or a "
                            "list of known endpoints for active probing.",
        })

    _api = s.get("authed_api") or {}
    try:
        _n = int(_api.get("count", 0))
    except (TypeError, ValueError):
        _n = 0
    if _n > 0 and not _api.get("has_token"):
        dims.append({
            "area": "Authenticated API surface",
            "status": "not_run",
            "not_exercised": (f"{_n} documented endpoint(s) require authentication, but no "
                              "token was supplied; access-control (BOLA/IDOR) and "
                              "business-logic risks were not exercised."),
            "how_to_close": "Re-run with --token-a/--token-b (two test accounts) to enable "
                            "the access-control (P9.5) and business-logic (P9.7) phases.",
        })

    return dims
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_coverage.py -v`
Expected: PASS (5 testes)

- [ ] **Step 5: Commit**

```bash
git add lib/coverage.py tests/test_coverage.py
git commit -m "feat(coverage): blind_spots puro (4 dimensões de lacuna)"
```

---

### Task 8: `lib/coverage.py` — `render_section_html(dimensions)`

**Files:**
- Modify: `lib/coverage.py`
- Test: `tests/test_coverage.py`

**Interfaces:**
- Consumes: dimensões de `blind_spots`.
- Produces: `render_section_html(dimensions) -> str` (vazio quando sem dimensões).

- [ ] **Step 1: Write the failing test**

```python
def test_render_empty_when_no_dimensions():
    assert cov.render_section_html([]) == ""


def test_render_contains_section_and_rows():
    html = cov.render_section_html([
        {"area": "Network port scan", "status": "not_run",
         "not_exercised": "x", "how_to_close": "y"}])
    assert "Coverage &amp; Blind Spots" in html
    assert "Network port scan" in html
    assert "Not run" in html   # label legível


def test_render_escapes_html():
    html = cov.render_section_html([
        {"area": "<svg>", "status": "partial", "not_exercised": "<b>", "how_to_close": "z"}])
    assert "<svg>" not in html and "&lt;svg&gt;" in html
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_coverage.py -k render -v`
Expected: FAIL (`AttributeError: ... 'render_section_html'`)

- [ ] **Step 3: Write minimal implementation**

```python
import html as _html


def render_section_html(dimensions):
    """Seção HTML 'Coverage & Blind Spots'. Vazia quando não há lacunas (cobertura
    completa). NÃO entra em severity_counts — é apresentação."""
    if not dimensions:
        return ""
    rows = ""
    for d in dimensions:
        rows += ("<tr>"
                 f"<td>{_html.escape(str(d.get('area', '')))}</td>"
                 f"<td>{_html.escape(_STATUS_LABEL.get(d.get('status', ''), str(d.get('status', ''))))}</td>"
                 f"<td style='font-size:12px'>{_html.escape(str(d.get('not_exercised', '')))}</td>"
                 f"<td style='font-size:12px'>{_html.escape(str(d.get('how_to_close', '')))}</td>"
                 "</tr>")
    return ("<h2>Coverage &amp; Blind Spots</h2>"
            "<p>Areas the automated scan did not fully exercise. Declared so that a low "
            "finding count is read against actual coverage, not as an all-clear.</p>"
            "<table><tr><th>Area</th><th>Status</th><th>Not exercised</th>"
            "<th>How to close</th></tr>" + rows + "</table>")
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_coverage.py -v && python3 -m py_compile lib/coverage.py`
Expected: PASS (8 testes)

- [ ] **Step 5: Commit**

```bash
git add lib/coverage.py tests/test_coverage.py
git commit -m "feat(coverage): render_section_html (seção HTML, escapa, vazio sem lacuna)"
```

---

### Task 9: Wiring da seção no `stiglitz_report.py` + migração do coverage finding

**Files:**
- Modify: `stiglitz_report.py` — derivar sinais e montar `coverage_section_html` (perto de `:2426`); remover `coverage_findings` de `_all_f_raw` (`:1106-1119`); interpolar `{coverage_section_html}` no template (`:2513`).
- Test: `tests/test_coverage_report_wiring.py` (criar)

**Interfaces:**
- Consumes: `lib/coverage.py`, `finding_quality.coverage_gap_finding` (já existe; agora alimenta um sinal, não um finding), `tech_categories`, `nf` (`:452`), `_cg_n` (`:1110`).
- Produces: `coverage_section_html` no relatório; `_all_f_raw` **sem** o coverage finding.

- [ ] **Step 1: Write the failing characterization test**

```python
# tests/test_coverage_report_wiring.py
import os, sys, json, subprocess, pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent


def _run_report(outdir, extra_env=None):
    env = dict(os.environ, OUTDIR=str(outdir), DOMAIN="host", TARGET="https://host",
               STIGLITZ_DEDUP="0")
    if extra_env:
        env.update(extra_env)
    return subprocess.run([sys.executable, str(ROOT / "stiglitz_report.py")],
                          env=env, capture_output=True, text=True, cwd=str(ROOT))


def test_coverage_section_rendered_when_authed_api_untested(tmp_path):
    raw = tmp_path / "raw"
    raw.mkdir(parents=True)
    (raw / ".coverage_gap_authed_api").write_text("15")   # 15 endpoints, sem token
    r = _run_report(tmp_path)
    assert r.returncode == 0, r.stderr
    html = (tmp_path / "stiglitz_report.html").read_text()
    assert "Coverage &amp; Blind Spots" in html
    assert "Authenticated API surface" in html


def test_coverage_gap_not_counted_as_info_finding(tmp_path):
    raw = tmp_path / "raw"
    raw.mkdir(parents=True)
    (raw / ".coverage_gap_authed_api").write_text("15")
    _run_report(tmp_path)
    fj = json.load(open(tmp_path / "findings.json"))
    arr = fj["findings"] if isinstance(fj, dict) else fj
    # migrou: NÃO há mais finding 'Coverage' info inflando a contagem
    assert not any((f.get("source") == "Coverage") for f in arr)
```

> Nota ao implementador: ajuste `arr =` ao formato real de `findings.json` (igual ao
> da Task 6). Confirme o nome do arquivo HTML gerado (`stiglitz_report.html`).

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_coverage_report_wiring.py -v`
Expected: FAIL (`test_coverage_gap_not_counted...` falha: o finding Coverage ainda existe; e a seção não é renderizada)

- [ ] **Step 3a: Remover a emissão do coverage finding (migração)**

Em `stiglitz_report.py:1106-1119`, **substituir** o bloco:

```python
coverage_findings = []
_cg_path = _raw(".coverage_gap_authed_api")
if os.path.exists(_cg_path):
    try:
        _cg_n = int((open(_cg_path).read().strip() or "0"))
    except (ValueError, OSError):
        _cg_n = 0
    _cg = finding_quality.coverage_gap_finding(
        _cg_n, has_token=bool(os.environ.get("AUTH_TOKEN", "")))
    if _cg:
        coverage_findings.append(_cg)

# Montar lista combinada (todos os tipos) antes de enriquecer com criticidade
_all_f_raw = findings + zap_findings + header_findings + version_findings + tls_findings + email_findings + apm_findings + service_findings + coverage_findings
```

por (o `_cg_n` continua sendo lido — agora alimenta a SEÇÃO, não um finding):

```python
# (Cobertura) lê o nº de endpoints autenticados não testados — vira sinal da seção
# "Coverage & Blind Spots" (migrado de finding info p/ não inflar severity_counts).
_cg_path = _raw(".coverage_gap_authed_api")
_cg_n = 0
if os.path.exists(_cg_path):
    try:
        _cg_n = int((open(_cg_path).read().strip() or "0"))
    except (ValueError, OSError):
        _cg_n = 0

# Montar lista combinada (todos os tipos) antes de enriquecer com criticidade
_all_f_raw = findings + zap_findings + header_findings + version_findings + tls_findings + email_findings + apm_findings + service_findings
```

- [ ] **Step 3b: Montar `coverage_section_html`**

Em `stiglitz_report.py`, logo após o bloco `deferred_section_html` (`:2426`), inserir:

```python
# ── Coverage & Blind Spots: declara o que o scan NÃO exercitou (Modo B) ─────────
# Seção de apresentação, NÃO finding — não entra em severity_counts. Deriva sinais
# já computados (nmap rodou? serviços fingerprintados sem sonda? API auth sem token?).
import coverage as _coverage
import service_exposure as _svc_exp

_probe_coverage = ({s["name"] for s in _svc_exp.SERVICE_CATALOG.values()}
                   | {"Prometheus", "Elastic APM"})
_infra_detected = set()
for _cat in ("monitoring", "database", "message-queue", "cache"):
    for _name in (tech_categories.get(_cat) or []):
        _infra_detected.add(_name)

_katana = _raw("katana_urls.txt")
_n_urls = 0
if os.path.exists(_katana):
    try:
        _n_urls = sum(1 for _ in open(_katana, encoding="utf-8", errors="ignore"))
    except OSError:
        _n_urls = 0
_has_openapi = os.path.exists(_raw("openapi_urls.txt")) or _cg_n > 0

_cov_signals = {
    "nmap_ran": os.path.exists(nf) and os.path.getsize(nf) > 0,
    "nmap_note": ("" if (os.path.exists(nf) and os.path.getsize(nf) > 0)
                  else "TCP port scan was skipped (proxy/edge mode) or produced no output."),
    "fingerprinted_services": sorted(_infra_detected),
    "probed_services": sorted(_probe_coverage),
    "live_hosts_no_surface": 1 if (_n_urls <= 1 and not _has_openapi) else 0,
    "authed_api": {"count": _cg_n, "has_token": bool(os.environ.get("AUTH_TOKEN", ""))},
}
coverage_section_html = _coverage.render_section_html(_coverage.blind_spots(_cov_signals))
```

> Nota: `nf` é definido em `:452` (`nf = os.path.join(OUTDIR,"raw","nmap.txt")`) e está
> em escopo aqui. Se não estiver, recompute-o: `nf = os.path.join(OUTDIR, "raw", "nmap.txt")`.

- [ ] **Step 3c: Interpolar a seção no template**

Em `stiglitz_report.py:2513`, trocar:

```python
{deferred_section_html}
```

por:

```python
{deferred_section_html}
{coverage_section_html}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_coverage_report_wiring.py -v && python3 -m py_compile stiglitz_report.py`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add stiglitz_report.py tests/test_coverage_report_wiring.py
git commit -m "feat(report): seção Coverage & Blind Spots + migra coverage finding (fora do stats)"
```

---

### Task 10: Regressão completa + nota de docs

**Files:**
- Modify: `CLAUDE.md` (tabela de módulos `lib/`), `CHANGELOG`/`docs/ROADMAP.md` (marcar P0 de cobertura).

**Interfaces:** nenhuma nova.

- [ ] **Step 1: Suíte completa + compile + lint**

Run:
```bash
python3 -m pytest tests/ -q
python3 -m py_compile stiglitz_report.py lib/service_exposure.py lib/coverage.py
bash -n stiglitz.sh && shellcheck --severity=warning stiglitz.sh
```
Expected: tudo verde (baseline anterior 943 + novos testes); sem erro de compile/sintaxe; sem novos warnings de shellcheck.

- [ ] **Step 2: Atualizar a tabela de módulos do `CLAUDE.md`**

Adicionar duas linhas na tabela `Módulos lib/` (seguindo o estilo das entradas existentes, ex.: a do `apm_probe.py`):

```
| `service_exposure.py` | Probe config-driven de serviços expostos sem auth (Fase 3, após apm_probe). Catálogo embutido (`SERVICE_CATALOG`) de ES/Kibana/Grafana/Actuator/Consul/etcd/Docker/K8s/RabbitMQ/Airflow/Jenkins — serviço novo = uma entrada de dados. Fingerprint por markers (corpo não-HTML, anti-catch-all) → probe GET dos endpoints sensíveis → classifica 200-sem-auth (CWE-306/200). Não-destrutivo (só GET); fail-safe (no-op sem serviço confirmado) → `raw/service_exposure.json`. Lógica pura + `send_fn` injetável + CLI |
| `coverage.py` | Seção "Coverage & Blind Spots" do relatório (Modo B): `blind_spots(signals)` declara o que o scan NÃO exercitou (port scan ausente/truncado; serviço fingerprintado sem sonda; host vivo só com `/`; API autenticada sem token) e `render_section_html` monta a seção. **NÃO é finding** — não entra em `severity_counts`. Absorve o ex-`coverage_gap_finding` (migrado de finding info p/ dimensão da seção). Lógica pura |
```

- [ ] **Step 3: Marcar o P0 no `docs/ROADMAP.md`**

Na seção apropriada (Follow-ups / cobertura), registrar que os dois P0 do roadmap de cobertura (service_exposure config-driven + seção Coverage & Blind Spots) foram entregues. Manter higienizado (sem dados de alvo).

- [ ] **Step 4: Commit**

```bash
git add CLAUDE.md docs/ROADMAP.md
git commit -m "docs: registra service_exposure + Coverage & Blind Spots (P0 de cobertura)"
```

---

## Self-Review

**1. Spec coverage:**
- service_exposure config-driven (catálogo embutido) → Tasks 1-4 ✓
- escopo (A) HTTP-no-target, campo `port` opcional → catálogo (Task 1) ✓
- aditivo (não reescreve apm/monitoring; não repete /metrics) → Global Constraints + catálogo ✓
- fail-safe + GET-only + sem vuln_class → Tasks 4/6 + Global Constraints ✓
- seção Coverage HTML dedicada fora de severity_counts → Tasks 7-9 ✓
- migração do coverage_gap_finding → Task 9 (3a) ✓
- 4 dimensões de blind-spot → Task 7 ✓ (dim "host vivo só com /" cabeada via katana_urls/openapi — heurística honesta)
- wiring Fase 3 + ingest + interpolação → Tasks 5/6/9 ✓
- testes (fingerprint/classify/build/run/fail-safe/não-destrutivo; dimensões/render; caracterização) → Tasks 1-3,4,6,7,8,9 ✓

**2. Placeholder scan:** Catálogo completo (11 serviços) com texto real; todas as funções com corpo completo; testes com asserts concretos. As duas "Notas ao implementador" (formato do `findings.json`, conflito do nome `coverage`) são instruções de verificação pontual, não lacunas de conteúdo.

**3. Type consistency:** `run` retorna `{"findings", "summary"}` com `summary["service"]`/`["total"]` (usado no CLI e no teste); `classify_exposure` → `{"state","evidence"}` (consumido por `run`/`build_findings`); `build_findings(service_key, confirmed=[(probe,verdict)], target)` (assinatura usada nos testes e em `run`); `blind_spots(signals) -> [dim]` e `render_section_html([dim])` casam nas Tasks 7-9. `service_findings` definido na Task 6 e referenciado em `_all_f_raw` (Task 6) e removido do bloco coverage (Task 9) de forma consistente.

## Execution Handoff

Ver mensagem ao usuário após salvar.

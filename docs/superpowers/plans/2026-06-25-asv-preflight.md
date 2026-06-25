# ASV-Preflight Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Adicionar ao Stiglitz um modo que prevê se um alvo passaria num scan ASV PCI, aplicando o critério do *ASV Program Guide* (CVSS base ≥ 4.0 + gatilhos de falha automática) aos findings já coletados, rodando só fases não-intrusivas e deslogadas.

**Architecture:** Núcleo puro `lib/asv_preflight.py` (classificação de categoria + veredito por finding + agregação + inventário + render HTML + CLI), um hook condicional em `stiglitz_report.py` (sob `STIGLITZ_ASV_PREFLIGHT=1`) que grava `asv_verdict.json` e injeta a seção HTML, e um orquestrador fino `asv_preflight.sh` que roda o subconjunto ASV-safe via `pipeline.py`. Camada paralela e aditiva: não altera o scoring `KEV>EPSS>CVSS` nem o fluxo padrão.

**Tech Stack:** Python 3 (stdlib + `defusedxml` já usado no projeto), Bash. Reusa `lib/scope.py`, `lib/finding_quality.py`, `lib/compliance_map.py`.

## Global Constraints

- **Idioma:** mensagens de console/operador em PT-BR; texto de relatório (HTML, strings que vão para o deliverable) em **inglês**.
- **Módulos puros:** `lib/*.py` são arquivos reais, sem rede própria; toda E/S de rede é injetada ou feita pelas fases. `lib/asv_preflight.py` só lê arquivos de `raw/` e o `findings.json`.
- **Aditivo / zero regressão:** sem `STIGLITZ_ASV_PREFLIGHT=1`, o `findings.json` e o `stiglitz_report.html` devem ser byte-idênticos ao comportamento atual.
- **CVSS base, não environmental** no critério ASV (usa `cvss_base`, com fallback `cvss`).
- **Limiar ASV:** CVSS base ≥ 4.0 = FAIL.
- **Fail-safe:** na dúvida (categoria desconhecida, sem score), NÃO fabricar FAIL — classificar como `NOT_COUNTED`.
- **Testes:** `python3 -m pytest tests/` deve passar; novos testes em `tests/test_asv_preflight.py`.
- **Validação bash:** `bash -n asv_preflight.sh` e `shellcheck --severity=warning asv_preflight.sh` limpos.

---

### Task 1: Classificação de categoria e veredito por finding

**Files:**
- Create: `lib/asv_preflight.py`
- Test: `tests/test_asv_preflight.py`

**Interfaces:**
- Consumes (do projeto): `lib/finding_quality.py::is_low_value_zap_alert(name, url) -> bool`.
- Produces:
  - `classify_category(finding: dict) -> str` — retorna uma das categorias: `"sqli"`, `"xss"`, `"rce"`, `"lfi"`, `"ssti"`, `"xxe"`, `"default_creds"`, `"sensitive_data"`, `"tls_insecure"`, `"open_db"`, `"security_header"`, `"low_value"`, `"other"`.
  - `asv_verdict_for(finding: dict) -> tuple[str, str]` — retorna `(verdict, reason)`, `verdict ∈ {"FAIL","PASS","NOT_COUNTED"}`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_asv_preflight.py
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from lib import asv_preflight as ap


def _f(**kw):
    base = {"name": "", "source": "", "url": "", "severity": "info", "other": ""}
    base.update(kw)
    return base


def test_classify_auto_fail_categories():
    assert ap.classify_category(_f(name="SQL Injection", source="Nuclei")) == "sqli"
    assert ap.classify_category(_f(name="Cross-Site Scripting (Reflected)", source="OWASP ZAP")) == "xss"
    assert ap.classify_category(_f(name="Remote Code Execution via mod_cgi")) == "rce"
    assert ap.classify_category(_f(name="Local File Inclusion / Path Traversal")) == "lfi"
    assert ap.classify_category(_f(name="Default Login (admin:admin) accepted")) == "default_creds"
    assert ap.classify_category(_f(name="Exposed PAN / cardholder data")) == "sensitive_data"


def test_classify_tls_and_db_and_headers():
    assert ap.classify_category(_f(name="SSLv3 supported", source="testssl.sh", severity="high")) == "tls_insecure"
    assert ap.classify_category(_f(name="Exposed Service: Redis on 6379/tcp", source="Exposed Service")) == "open_db"
    assert ap.classify_category(_f(name="Missing Anti-clickjacking Header", source="Security Headers")) == "security_header"


def test_classify_low_value_zap_is_low_value():
    # is_low_value_zap_alert: disclosure ruidoso em asset estático
    cat = ap.classify_category(_f(name="Timestamp Disclosure - Unix",
                                  source="OWASP ZAP",
                                  url="https://x.com/app.bundle.js"))
    assert cat == "low_value"


def test_verdict_auto_fail():
    v, why = ap.asv_verdict_for(_f(name="SQL Injection", source="Nuclei", severity="high"))
    assert v == "FAIL"
    assert "automatic" in why.lower()


def test_verdict_cvss_threshold():
    assert ap.asv_verdict_for(_f(name="Some CVE", cvss_base=3.9, severity="low"))[0] == "PASS"
    assert ap.asv_verdict_for(_f(name="Some CVE", cvss_base=4.0, severity="medium"))[0] == "FAIL"
    assert ap.asv_verdict_for(_f(name="Some CVE", cvss_base=9.8, severity="critical"))[0] == "FAIL"


def test_verdict_headers_not_counted():
    v, _ = ap.asv_verdict_for(_f(name="Missing CSP Header", source="Security Headers", severity="high"))
    assert v == "NOT_COUNTED"


def test_verdict_low_value_not_counted():
    v, _ = ap.asv_verdict_for(_f(name="Timestamp Disclosure - Unix",
                                 source="OWASP ZAP",
                                 url="https://x.com/app.bundle.js",
                                 severity="low"))
    assert v == "NOT_COUNTED"


def test_verdict_severity_fallback_without_cvss():
    # sem cvss_base, cai na banda de severidade
    assert ap.asv_verdict_for(_f(name="Some misconfig", source="Nuclei", severity="medium"))[0] == "FAIL"
    assert ap.asv_verdict_for(_f(name="Some info", source="Nuclei", severity="info"))[0] == "PASS"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_asv_preflight.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'lib.asv_preflight'` (ou `AttributeError`).

- [ ] **Step 3: Write minimal implementation**

```python
# lib/asv_preflight.py
"""ASV-Preflight: prevê o resultado de um scan ASV PCI sobre findings já coletados.

Camada pura e paralela ao scoring KEV>EPSS>CVSS. Aplica o critério do ASV Program
Guide: CVSS base >= 4.0 = FAIL, além de gatilhos de falha automática (SQLi/XSS/TLS
fraco/default creds/etc.) independentes de score. Sem rede própria.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from lib import finding_quality as _fq
except Exception:  # execução direta a partir de lib/
    import finding_quality as _fq

ASV_THRESHOLD = 4.0  # CVSS base >= 4.0 reprova (ASV Program Guide)

# Categorias que reprovam independentemente do CVSS (gatilhos de falha automática).
AUTO_FAIL = {"sqli", "xss", "rce", "lfi", "ssti", "xxe",
             "default_creds", "sensitive_data", "tls_insecure", "open_db"}
# Categorias que nunca contam para o veredito (informativas no contexto ASV).
INFORMATIONAL = {"security_header", "low_value"}

# Padrões (substring, lowercase) em finding["name"] -> categoria de auto-fail.
_NAME_PATTERNS = [
    ("sqli", ("sql injection", "sqli")),
    ("xss", ("cross-site scripting", "xss")),
    ("rce", ("remote code execution", "command injection", " rce")),
    ("lfi", ("local file inclusion", "path traversal", "directory traversal", "lfi")),
    ("ssti", ("server-side template", "ssti")),
    ("xxe", ("xml external entity", "xxe")),
    ("default_creds", ("default login", "default credential", "default password")),
    ("sensitive_data", ("pan ", "cardholder", "exposed pii", "private key", "sensitive data expos")),
    ("open_db", ("redis", "mongodb", "mongo on", "elasticsearch", "memcached", "couchdb")),
]


def classify_category(finding):
    """Classifica o finding numa categoria ASV a partir de name/source/url.
    Não depende de CWE (campo nem sempre presente)."""
    name = (finding.get("name") or "").lower()
    source = (finding.get("source") or "").lower()
    url = finding.get("url") or ""

    # Headers de segurança: informativos para ASV.
    if "security headers" in source or "missing" in name and "header" in name:
        return "security_header"

    # FP previsível (disclosure ruidoso em asset estático).
    if _fq.is_low_value_zap_alert(finding.get("name") or "", url):
        return "low_value"

    # TLS: findings do testssl com severidade relevante = TLS inseguro.
    if "testssl" in source and (finding.get("severity") or "").lower() in ("medium", "high", "critical"):
        return "tls_insecure"

    # Serviços de banco expostos (open_db) só quando vêm de detecção de serviço.
    if "service" in source:
        for cat, pats in _NAME_PATTERNS:
            if cat == "open_db" and any(p in name for p in pats):
                return "open_db"

    # Demais padrões de auto-fail por nome.
    for cat, pats in _NAME_PATTERNS:
        if cat == "open_db":
            continue
        if any(p in name for p in pats):
            return cat

    return "other"


def _cvss_base(finding):
    """CVSS base do finding (fallback para `cvss`); 0.0 se ausente/inválido."""
    for key in ("cvss_base", "cvss"):
        val = finding.get(key)
        try:
            if val is not None and float(val) > 0:
                return float(val)
        except (TypeError, ValueError):
            continue
    return 0.0


def asv_verdict_for(finding):
    """Veredito ASV de um finding: (verdict, reason).
    verdict ∈ {'FAIL','PASS','NOT_COUNTED'}. Fail-safe: na dúvida, não fabrica FAIL."""
    cat = classify_category(finding)

    if cat in AUTO_FAIL:
        return "FAIL", "ASV automatic-failure category: %s" % cat
    if cat in INFORMATIONAL:
        return "NOT_COUNTED", "informational under ASV criteria (%s)" % cat

    base = _cvss_base(finding)
    if base >= ASV_THRESHOLD:
        return "FAIL", "CVSS base %.1f >= %.1f" % (base, ASV_THRESHOLD)
    if base > 0:
        return "PASS", "CVSS base %.1f < %.1f" % (base, ASV_THRESHOLD)

    # Sem CVSS: fallback pela banda de severidade já calculada.
    sev = (finding.get("severity") or "info").lower()
    if sev in ("medium", "high", "critical"):
        return "FAIL", "severity %s (no CVSS, band >= 4.0)" % sev
    return "PASS", "severity %s below ASV threshold" % sev
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_asv_preflight.py -v`
Expected: PASS (todos os testes desta task).

- [ ] **Step 5: Commit**

```bash
git add lib/asv_preflight.py tests/test_asv_preflight.py
git commit -m "feat(asv): critério de veredito por finding (auto-fail + CVSS>=4.0)"
```

---

### Task 2: Veredito agregado com escopo e requisito

**Files:**
- Modify: `lib/asv_preflight.py`
- Test: `tests/test_asv_preflight.py`

**Interfaces:**
- Consumes (do projeto): `lib/scope.py::in_scope(url, scope_domains) -> bool`; `lib/compliance_map.py::frameworks_for_cwe(cwe) -> dict` (chave opcional `"pci"`).
- Consumes (Task 1): `asv_verdict_for`, `classify_category`.
- Produces:
  - `requirement_for(finding: dict) -> str` — requisito PCI ("6.2.4", "4.2.1", …) via CWE ou fallback por categoria; `""` se desconhecido.
  - `aggregate(findings: list[dict], scope_domains: list[str] | None = None) -> dict` — `{"would_pass": bool, "counted": int, "fails": list[dict]}`. Cada fail: `{"name","host","port","cvss_base","reason","requirement","remediation","severity"}`.

- [ ] **Step 1: Write the failing test**

```python
# adicionar a tests/test_asv_preflight.py

def test_requirement_via_cwe():
    assert ap.requirement_for(_f(name="XSS", cwe="CWE-79")) == "6.2.4"


def test_requirement_fallback_by_category():
    # sem CWE, deriva da categoria
    assert ap.requirement_for(_f(name="SSLv3 supported", source="testssl.sh", severity="high")) == "4.2.1"
    assert ap.requirement_for(_f(name="SQL Injection")) == "6.2.4"


def test_aggregate_would_not_pass():
    findings = [
        _f(name="SQL Injection", source="Nuclei", severity="high", url="https://a.com/x?id=1"),
        _f(name="Missing CSP Header", source="Security Headers", severity="high", url="https://a.com/"),
    ]
    out = ap.aggregate(findings, ["a.com"])
    assert out["would_pass"] is False
    assert out["counted"] == 1                  # header não conta
    assert out["fails"][0]["name"] == "SQL Injection"
    assert out["fails"][0]["host"] == "a.com"
    assert out["fails"][0]["requirement"] == "6.2.4"


def test_aggregate_would_pass():
    findings = [_f(name="Missing CSP Header", source="Security Headers", severity="high")]
    out = ap.aggregate(findings, ["a.com"])
    assert out["would_pass"] is True
    assert out["fails"] == []


def test_aggregate_respects_scope():
    findings = [_f(name="SQL Injection", source="Nuclei", severity="high", url="https://evil.com/x")]
    out = ap.aggregate(findings, ["a.com"])     # finding fora de escopo
    assert out["would_pass"] is True
    assert out["fails"] == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_asv_preflight.py -k "requirement or aggregate" -v`
Expected: FAIL with `AttributeError: module 'lib.asv_preflight' has no attribute 'requirement_for'`.

- [ ] **Step 3: Write minimal implementation**

```python
# adicionar a lib/asv_preflight.py (após asv_verdict_for)
from urllib.parse import urlparse

try:
    from lib import scope as _scope
    from lib import compliance_map as _cmap
except Exception:
    import scope as _scope
    import compliance_map as _cmap

# Requisito PCI default por categoria, quando o finding não traz CWE.
_CATEGORY_REQ = {
    "sqli": "6.2.4", "xss": "6.2.4", "rce": "6.2.4", "lfi": "6.2.4",
    "ssti": "6.2.4", "xxe": "6.2.4",
    "tls_insecure": "4.2.1",
    "default_creds": "8.3.1",
    "open_db": "2.2.5",
    "sensitive_data": "3.5.1",
}


def requirement_for(finding):
    """Requisito PCI do finding: via CWE (compliance_map) ou fallback por categoria."""
    cwe = finding.get("cwe")
    if cwe:
        pci = _cmap.frameworks_for_cwe(cwe).get("pci")
        if pci:
            return pci
    return _CATEGORY_REQ.get(classify_category(finding), "")


def _host_port(url):
    """(host, port) a partir da URL do finding; port inferida do esquema."""
    try:
        sp = urlparse(url if "://" in (url or "") else "//" + (url or ""))
        host = (sp.hostname or "").lower()
        port = sp.port or (443 if (sp.scheme == "https") else 80 if sp.scheme == "http" else "")
        return host, port
    except Exception:
        return "", ""


def aggregate(findings, scope_domains=None):
    """Veredito ASV agregado. would_pass=False sse houver >=1 FAIL em escopo."""
    scope_domains = scope_domains or []
    fails = []
    counted = 0
    for f in findings or []:
        url = f.get("url") or ""
        if scope_domains and url and not _scope.in_scope(url, scope_domains):
            continue
        verdict, reason = asv_verdict_for(f)
        if verdict == "NOT_COUNTED":
            continue
        counted += 1
        if verdict == "FAIL":
            host, port = _host_port(url)
            fails.append({
                "name": f.get("name", ""),
                "host": host,
                "port": port,
                "cvss_base": _cvss_base(f),
                "reason": reason,
                "requirement": requirement_for(f),
                "remediation": f.get("remediation", ""),
                "severity": (f.get("severity") or "info").lower(),
            })
    return {"would_pass": len(fails) == 0, "counted": counted, "fails": fails}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_asv_preflight.py -v`
Expected: PASS (Task 1 + Task 2).

- [ ] **Step 5: Commit**

```bash
git add lib/asv_preflight.py tests/test_asv_preflight.py
git commit -m "feat(asv): veredito agregado com escopo e requisito PCI"
```

---

### Task 3: Inventário de componentes (nmap.xml + httpx)

**Files:**
- Modify: `lib/asv_preflight.py`
- Test: `tests/test_asv_preflight.py`

**Interfaces:**
- Consumes: `defusedxml.ElementTree` (já dependência do projeto, ver `lib/service_versions.py`).
- Produces:
  - `build_inventory(raw_dir: str) -> list[dict]` — cada linha: `{"host","ip","port","service","version","tls"}`. Lê `raw/nmap.xml` (estruturado) e `raw/httpx_results.txt` (web), dedup por `(host, port)`. Degrada quando um arquivo falta.

- [ ] **Step 1: Write the failing test**

```python
# adicionar a tests/test_asv_preflight.py
import tempfile

_NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="203.0.113.10" addrtype="ipv4"/>
    <hostnames><hostname name="a.com"/></hostnames>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https" product="nginx" version="1.18.0" tunnel="ssl"/>
      </port>
      <port protocol="tcp" portid="6379">
        <state state="open"/>
        <service name="redis" product="Redis key-value store" version="6.0.5"/>
      </port>
      <port protocol="tcp" portid="9">
        <state state="closed"/>
        <service name="discard"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

_HTTPX_TXT = "https://a.com [200] [nginx] [Django]\nhttps://api.a.com:8443 [200] [nginx]\n"


def test_build_inventory_from_nmap_and_httpx():
    with tempfile.TemporaryDirectory() as d:
        raw = os.path.join(d, "raw")
        os.makedirs(raw)
        open(os.path.join(raw, "nmap.xml"), "w").write(_NMAP_XML)
        open(os.path.join(raw, "httpx_results.txt"), "w").write(_HTTPX_TXT)
        inv = ap.build_inventory(raw)

    keyed = {(r["host"], r["port"]): r for r in inv}
    # porta fechada não entra
    assert ("a.com", 9) not in keyed
    # serviço nmap estruturado
    assert keyed[("a.com", 443)]["service"] == "https"
    assert keyed[("a.com", 443)]["version"] == "nginx 1.18.0"
    assert keyed[("a.com", 443)]["tls"] is True
    assert keyed[("a.com", 6379)]["service"] == "redis"
    # host só do httpx (não estava no nmap)
    assert ("api.a.com", 8443) in keyed


def test_build_inventory_missing_files_degrades():
    with tempfile.TemporaryDirectory() as d:
        raw = os.path.join(d, "raw")
        os.makedirs(raw)
        assert ap.build_inventory(raw) == []   # nada para inventariar, sem erro
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_asv_preflight.py -k inventory -v`
Expected: FAIL with `AttributeError: ... has no attribute 'build_inventory'`.

- [ ] **Step 3: Write minimal implementation**

```python
# adicionar a lib/asv_preflight.py
import re as _re

try:
    from defusedxml import ElementTree as _ET
except Exception:  # defusedxml ausente: inventário degrada (sem nmap)
    _ET = None


def _inventory_from_nmap(xml_path):
    rows = []
    if _ET is None or not os.path.exists(xml_path):
        return rows
    try:
        tree = _ET.parse(xml_path)
    except Exception:
        return rows
    root = tree.getroot()
    for host_el in root.findall("host"):
        ip = ""
        for addr in host_el.findall("address"):
            if addr.get("addrtype") in ("ipv4", "ipv6"):
                ip = addr.get("addr", "")
                break
        hostname = ""
        hn = host_el.find("hostnames/hostname")
        if hn is not None:
            hostname = hn.get("name", "")
        host = hostname or ip
        ports_el = host_el.find("ports")
        if ports_el is None:
            continue
        for port_el in ports_el.findall("port"):
            state = port_el.find("state")
            if state is None or state.get("state") != "open":
                continue
            try:
                portid = int(port_el.get("portid"))
            except (TypeError, ValueError):
                continue
            svc = port_el.find("service")
            name = svc.get("name", "") if svc is not None else ""
            product = svc.get("product", "") if svc is not None else ""
            version = svc.get("version", "") if svc is not None else ""
            tunnel = svc.get("tunnel", "") if svc is not None else ""
            ver_str = (product + " " + version).strip()
            tls = (tunnel == "ssl") or name in ("https", "ssl") or portid == 443
            rows.append({"host": host, "ip": ip, "port": portid,
                         "service": name, "version": ver_str, "tls": tls})
    return rows


def _inventory_from_httpx(txt_path):
    rows = []
    if not os.path.exists(txt_path):
        return rows
    try:
        text = open(txt_path, encoding="utf-8", errors="replace").read()
    except Exception:
        return rows
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        url = line.split()[0]
        host, port = _host_port(url)
        if not host:
            continue
        techs = _re.findall(r"\[([^\]]+)\]", line)
        # primeiro token entre colchetes costuma ser status code numérico; ignora
        tech_tokens = [t for t in techs if not t.isdigit()]
        rows.append({"host": host, "ip": "", "port": port,
                     "service": "https" if url.startswith("https") else "http",
                     "version": ", ".join(tech_tokens), "tls": url.startswith("https")})
    return rows


def build_inventory(raw_dir):
    """Inventário agregado host/ip/port/service/version/tls (nmap + httpx), dedup
    por (host, port). nmap (estruturado) tem precedência sobre httpx."""
    nmap_rows = _inventory_from_nmap(os.path.join(raw_dir, "nmap.xml"))
    httpx_rows = _inventory_from_httpx(os.path.join(raw_dir, "httpx_results.txt"))
    keyed = {}
    for r in nmap_rows + httpx_rows:          # nmap primeiro = precedência
        key = (r["host"], r["port"])
        if key not in keyed:
            keyed[key] = r
    return list(keyed.values())
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_asv_preflight.py -v`
Expected: PASS (Tasks 1-3).

- [ ] **Step 5: Commit**

```bash
git add lib/asv_preflight.py tests/test_asv_preflight.py
git commit -m "feat(asv): inventário de componentes (nmap.xml + httpx)"
```

---

### Task 4: Render da seção HTML + CLI

**Files:**
- Modify: `lib/asv_preflight.py`
- Test: `tests/test_asv_preflight.py`

**Interfaces:**
- Consumes (Task 2/3): `aggregate`, `build_inventory`.
- Produces:
  - `render_section_html(verdict: dict, inventory: list[dict]) -> str` — string HTML (EN) com banner PASS/FAIL, tabela de fails, tabela de inventário e disclaimer. Sempre retorna string (vazia nunca; render mínimo se sem dados).
  - `main(argv)` / bloco `__main__`: CLI `verdict <findings.json> [raw_dir]` (imprime JSON do `aggregate` + `inventory`) e `inventory <raw_dir>` (imprime JSON do inventário).

- [ ] **Step 1: Write the failing test**

```python
# adicionar a tests/test_asv_preflight.py
import json
import subprocess


def test_render_section_fail_banner():
    verdict = {"would_pass": False, "counted": 1, "fails": [
        {"name": "SQL Injection", "host": "a.com", "port": 443, "cvss_base": 9.8,
         "reason": "ASV automatic-failure category: sqli", "requirement": "6.2.4",
         "remediation": "Use parameterized queries", "severity": "high"}]}
    inv = [{"host": "a.com", "ip": "203.0.113.10", "port": 443,
            "service": "https", "version": "nginx 1.18.0", "tls": True}]
    html_out = ap.render_section_html(verdict, inv)
    assert "ASV Preflight" in html_out
    assert "WOULD NOT PASS" in html_out
    assert "SQL Injection" in html_out
    assert "203.0.113.10" in html_out
    assert "does not replace" in html_out.lower()   # disclaimer


def test_render_section_pass_banner():
    out = ap.render_section_html({"would_pass": True, "counted": 0, "fails": []}, [])
    assert "WOULD PASS" in out


def test_cli_verdict(tmp_path):
    findings = {"summary": {"findings": [
        {"name": "SQL Injection", "source": "Nuclei", "severity": "high",
         "url": "https://a.com/x?id=1"}]}}
    fj = tmp_path / "findings.json"
    fj.write_text(json.dumps(findings))
    res = subprocess.run(
        ["python3", os.path.join(os.path.dirname(__file__), "..", "lib", "asv_preflight.py"),
         "verdict", str(fj)],
        capture_output=True, text=True)
    assert res.returncode == 0
    payload = json.loads(res.stdout)
    assert payload["verdict"]["would_pass"] is False
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_asv_preflight.py -k "render or cli" -v`
Expected: FAIL with `AttributeError: ... has no attribute 'render_section_html'`.

- [ ] **Step 3: Write minimal implementation**

```python
# adicionar a lib/asv_preflight.py
import html as _html
import json as _json

_DISCLAIMER = ("This ASV Preflight is a prediction to remediate before the official "
               "scan; it does not replace an ASV-certified scan (PCI DSS Req. 11.3.2) "
               "and is not an Attestation of Scan Compliance. Criterion: CVSS v3.1 base "
               ">= 4.0 plus automatic-failure categories.")


def render_section_html(verdict, inventory):
    """Seção HTML 'ASV Preflight Verdict' (EN, deliverable)."""
    would_pass = verdict.get("would_pass", True)
    banner = "WOULD PASS" if would_pass else "WOULD NOT PASS"
    color = "#4a7c8c" if would_pass else "#b34e4e"
    out = ["<h2>ASV Preflight Verdict</h2>"]
    out.append("<p><strong>Predicted result:</strong> "
               "<span style='color:%s;font-weight:bold'>%s</span> "
               "(%d finding(s) assessed against ASV criteria)</p>"
               % (color, banner, verdict.get("counted", 0)))

    fails = verdict.get("fails", [])
    if fails:
        out.append("<table><tr><th>Finding</th><th>Host:Port</th><th>CVSS</th>"
                   "<th>Reason</th><th>PCI Req</th><th>Remediation</th></tr>")
        for f in fails:
            out.append("<tr><td>%s</td><td><code>%s:%s</code></td><td>%s</td>"
                       "<td style='font-size:12px'>%s</td><td>%s</td>"
                       "<td style='font-size:11px'>%s</td></tr>" % (
                           _html.escape(str(f.get("name", ""))),
                           _html.escape(str(f.get("host", ""))),
                           _html.escape(str(f.get("port", ""))),
                           _html.escape("%.1f" % f.get("cvss_base", 0.0)),
                           _html.escape(str(f.get("reason", ""))),
                           _html.escape(str(f.get("requirement", ""))),
                           _html.escape(str(f.get("remediation", "")))))
        out.append("</table>")

    if inventory:
        out.append("<h3>Scanned components</h3>")
        out.append("<table><tr><th>Host</th><th>IP</th><th>Port</th>"
                   "<th>Service</th><th>Version</th><th>TLS</th></tr>")
        for r in inventory:
            out.append("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td>"
                       "<td>%s</td><td>%s</td></tr>" % (
                           _html.escape(str(r.get("host", ""))),
                           _html.escape(str(r.get("ip", ""))),
                           _html.escape(str(r.get("port", ""))),
                           _html.escape(str(r.get("service", ""))),
                           _html.escape(str(r.get("version", ""))),
                           "yes" if r.get("tls") else "no"))
        out.append("</table>")

    out.append("<p style='font-size:11px;color:#888'>%s</p>" % _html.escape(_DISCLAIMER))
    return "".join(out)


def _load_findings(path):
    data = _json.load(open(path, encoding="utf-8"))
    if isinstance(data, dict):
        return data.get("summary", {}).get("findings", []) or data.get("findings", [])
    return data or []


def main(argv):
    if len(argv) < 2:
        sys.stderr.write("usage: asv_preflight.py {verdict <findings.json> [raw_dir]"
                         " | inventory <raw_dir>}\n")
        return 2
    cmd = argv[0]
    if cmd == "verdict":
        findings = _load_findings(argv[1])
        raw_dir = argv[2] if len(argv) > 2 else ""
        inv = build_inventory(raw_dir) if raw_dir else []
        print(_json.dumps({"verdict": aggregate(findings), "inventory": inv},
                          ensure_ascii=False, indent=2))
        return 0
    if cmd == "inventory":
        print(_json.dumps(build_inventory(argv[1]), ensure_ascii=False, indent=2))
        return 0
    sys.stderr.write("unknown command: %s\n" % cmd)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_asv_preflight.py -v`
Expected: PASS (Tasks 1-4).

- [ ] **Step 5: Commit**

```bash
git add lib/asv_preflight.py tests/test_asv_preflight.py
git commit -m "feat(asv): render da seção HTML + CLI verdict/inventory"
```

---

### Task 5: Hook condicional em `stiglitz_report.py`

**Files:**
- Modify: `lib/asv_preflight.py` (adiciona `emit_artifacts`)
- Modify: `stiglitz_report.py` (env read perto da linha 40; chamada a `emit_artifacts` perto da escrita do `findings.json`, ~linha 2614; injeção da seção no corpo HTML perto das seções PCI/OWASP, ~linha 2165-2170)
- Test: `tests/test_report_asv_wiring.py`

**Interfaces:**
- Consumes (Task 1-4): `lib.asv_preflight.aggregate`, `build_inventory`, `render_section_html`.
- Produces:
  - `emit_artifacts(outdir: str, findings: list[dict], scope_domains: list[str] | None = None) -> str` — calcula veredito + inventário, grava `asv_verdict.json` em `outdir`, retorna a seção HTML. É a única lógica nova; o `stiglitz_report.py` apenas a chama (testamos o código real, não uma réplica).
  - No `stiglitz_report.py`: `asv_verdict.json` no OUTDIR + seção `asv_section_html` injetada, ambos só sob `STIGLITZ_ASV_PREFLIGHT=1`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_report_asv_wiring.py
"""Wiring: emit_artifacts grava o JSON e devolve a seção HTML (código real,
chamado pelo stiglitz_report.py sob STIGLITZ_ASV_PREFLIGHT=1)."""
import os, sys, json, tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from lib import asv_preflight as ap


def test_emit_artifacts_writes_json_and_returns_html():
    with tempfile.TemporaryDirectory() as d:
        os.makedirs(os.path.join(d, "raw"))
        findings = [{"name": "SQL Injection", "source": "Nuclei",
                     "severity": "high", "url": "https://a.com/x?id=1"}]
        html_out = ap.emit_artifacts(d, findings, ["a.com"])
        assert "ASV Preflight" in html_out
        assert os.path.exists(os.path.join(d, "asv_verdict.json"))
        data = json.load(open(os.path.join(d, "asv_verdict.json")))
        assert data["verdict"]["would_pass"] is False
        assert "inventory" in data


def test_emit_artifacts_pass_case():
    with tempfile.TemporaryDirectory() as d:
        os.makedirs(os.path.join(d, "raw"))
        findings = [{"name": "Missing CSP Header", "source": "Security Headers",
                     "severity": "high", "url": "https://a.com/"}]
        html_out = ap.emit_artifacts(d, findings, ["a.com"])
        assert "WOULD PASS" in html_out
        data = json.load(open(os.path.join(d, "asv_verdict.json")))
        assert data["verdict"]["would_pass"] is True
```

> O contrato opt-in (`STIGLITZ_ASV_PREFLIGHT=1`) vive no `stiglitz_report.py` (Step 3) — `emit_artifacts` só é chamada quando o env está setado. O teste exercita a função pura diretamente; a presença do guard no report é verificada por `grep` no Step 4.

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_report_asv_wiring.py -v`
Expected: FAIL with `AttributeError: module 'lib.asv_preflight' has no attribute 'emit_artifacts'`.

- [ ] **Step 3a: Add `emit_artifacts` to `lib/asv_preflight.py`**

Adicionar (após `render_section_html`/`main`, antes do bloco `if __name__`):

```python
def emit_artifacts(outdir, findings, scope_domains=None):
    """Calcula veredito + inventário, grava asv_verdict.json em outdir e
    retorna a seção HTML. Toda a lógica do hook vive aqui (testável)."""
    verdict = aggregate(findings, scope_domains)
    inventory = build_inventory(os.path.join(outdir, "raw"))
    with open(os.path.join(outdir, "asv_verdict.json"), "w", encoding="utf-8") as fh:
        _json.dump({"verdict": verdict, "inventory": inventory}, fh,
                   ensure_ascii=False, indent=2, default=str)
    return render_section_html(verdict, inventory)
```

- [ ] **Step 3b: Wire the hook into `stiglitz_report.py`**

Adicionar a leitura do env perto da linha 40 (junto de `REPRO_RAW`):

```python
ASV_PREFLIGHT = os.environ.get("STIGLITZ_ASV_PREFLIGHT") == "1"
```

Importar o módulo no topo, junto dos demais `from lib import ...`:

```python
from lib import asv_preflight as _asv
```

Antes da montagem da string HTML final do relatório (o `aggregate` depende só de
`all_f`, que já existe nesse ponto; `DOMAIN` também), definir a seção:

```python
if ASV_PREFLIGHT:
    asv_section_html = _asv.emit_artifacts(OUTDIR, all_f, [DOMAIN] if DOMAIN else [])
else:
    asv_section_html = ""
```

Na montagem do corpo HTML (onde `pci_section_html`/`owasp_section_html` são
concatenados, ~linha 2165-2170), incluir `asv_section_html` logo após a seção
OWASP, seguindo o padrão existente:

```python
# ... + compliance_section_html + owasp_section_html + asv_section_html + ...
```

> Confirme no arquivo que o bloco `if ASV_PREFLIGHT:` é definido ANTES do f-string
> do relatório que referencia `asv_section_html`. Se a escrita do `findings.json`
> (~linha 2614) acontecer depois desse f-string, não importa: `emit_artifacts`
> grava o `asv_verdict.json` por conta própria, independentemente da ordem.

- [ ] **Step 4: Run tests + regression check**

```bash
python3 -m pytest tests/test_report_asv_wiring.py tests/test_asv_preflight.py -v
python3 -m py_compile stiglitz_report.py lib/asv_preflight.py
grep -n "ASV_PREFLIGHT\|asv_section_html\|emit_artifacts" stiglitz_report.py
```
Expected: testes PASS; `py_compile` sem erro; o `grep` mostra (1) o guard `ASV_PREFLIGHT = os.environ.get(...)`, (2) a definição de `asv_section_html` via `emit_artifacts`, e (3) a concatenação de `asv_section_html` no corpo HTML.

- [ ] **Step 5: Commit**

```bash
git add lib/asv_preflight.py stiglitz_report.py tests/test_report_asv_wiring.py
git commit -m "feat(asv): hook em stiglitz_report (asv_verdict.json + seção, opt-in)"
```

---

### Task 6: Orquestrador `asv_preflight.sh`

**Files:**
- Create: `asv_preflight.sh`
- Test: smoke (`bash -n`, `shellcheck`, `--dry-run`)

**Interfaces:**
- Consumes: `pipeline.py` (`--only` vírgula-separado; `--profile production`; herda env do processo); env `STIGLITZ_ASV_PREFLIGHT` lido por `stiglitz_report.py` (Task 5).
- Produces: um comando único que roda o subconjunto ASV-safe e emite o relatório com a seção ASV + `asv_verdict.json`.

- [ ] **Step 1: Write the script**

```bash
#!/usr/bin/env bash
# asv_preflight.sh — Modo ASV-Preflight: prevê o resultado de um scan ASV PCI.
# Roda só o subconjunto NÃO-intrusivo e deslogado das fases do Stiglitz e aplica
# o critério do ASV Program Guide (lib/asv_preflight.py via stiglitz_report.py).
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; readonly SCRIPT_DIR
trap 'echo; echo "[!] Interrompido pelo usuário — abortando."; exit 130' INT TERM

# Subconjunto ASV-safe (não-intrusivo, deslogado). Exclui P5, P9*, P10_5, P12.
readonly ASV_PHASES="P1,P2,P2_5,P3_P4,P6,P8,P10,P11"

TARGET=""
OUTDIR=""
PROXY=""
DRY_RUN=false

usage() {
    cat <<EOF
Uso: bash asv_preflight.sh <target> [--outdir <dir>] [--proxy <url>] [--dry-run]

Prevê se o alvo passaria num scan ASV PCI (CVSS base >= 4.0 + gatilhos de falha
automática). NÃO substitui um scan ASV certificado (PCI DSS Req. 11.3.2).
Saída: stiglitz_report.html (seção "ASV Preflight Verdict") + asv_verdict.json.
EOF
    exit "${1:-0}"
}

parse_args() {
    [ $# -eq 0 ] && usage 1
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --outdir)  OUTDIR="$2"; shift 2 ;;
            --proxy)   PROXY="$2";  shift 2 ;;
            --dry-run) DRY_RUN=true; shift ;;
            -h|--help) usage 0 ;;
            -*)        echo "[!] Argumento desconhecido: $1" >&2; usage 1 ;;
            *)         TARGET="$1"; shift ;;
        esac
    done
    [ -z "$TARGET" ] && { echo "[!] Informe o alvo." >&2; usage 1; }
}

main() {
    parse_args "$@"
    echo "[*] ASV-Preflight em $TARGET (fases: $ASV_PHASES, perfil: production)"
    echo "[*] AVISO: previsão de remediação — NÃO substitui scan ASV certificado."

    local -a args=("$TARGET" --profile production --only "$ASV_PHASES")
    [ -n "$OUTDIR" ] && args+=(--outdir "$OUTDIR")
    [ -n "$PROXY" ] && args+=(--proxy "$PROXY")
    "$DRY_RUN" && args+=(--dry-run)

    export STIGLITZ_ASV_PREFLIGHT=1
    export STIGLITZ_PROFILE=production
    python3 "$SCRIPT_DIR/pipeline.py" "${args[@]}"
}

main "$@"
```

- [ ] **Step 2: Verify syntax and lint**

```bash
bash -n asv_preflight.sh
shellcheck --severity=warning asv_preflight.sh
```
Expected: ambos sem saída/erro.

- [ ] **Step 3: Confirm pipeline.py accepts the flags (dry-run)**

```bash
python3 pipeline.py --help | grep -E "\-\-only|\-\-profile|\-\-proxy|\-\-dry-run"
bash asv_preflight.sh example.com --dry-run
```
Expected: o `--help` lista `--only`, `--profile`, `--dry-run`; o dry-run imprime o plano com as fases `P1 P2 P2_5 P3_P4 P6 P8 P10 P11` e perfil `production`, sem executar scan.

> Se `--proxy` não existir no `pipeline.py` (ele pode só repassar a `stiglitz.sh`), remova o branch `--proxy` do wrapper ou ajuste para a flag aceita — confirme com o `--help`.

- [ ] **Step 4: Full test suite (no regression)**

```bash
python3 -m pytest tests/ -q
bash -n stiglitz.sh stiglitz_red.sh stiglitz_full.sh stiglitz_batch.sh osint.sh asv_preflight.sh lib/*.sh
```
Expected: suíte verde; sintaxe de todos os scripts OK.

- [ ] **Step 5: Commit**

```bash
git add asv_preflight.sh
git commit -m "feat(asv): orquestrador asv_preflight.sh (subconjunto ASV-safe)"
```

---

## Self-Review (preenchido)

**1. Spec coverage:**
- Re-veredito por critério ASV → Tasks 1-2 ✓
- Mapa de categorias (headers não contam) → Task 1 (`INFORMATIONAL`, `is_low_value_zap_alert`) ✓
- Inventário de componentes → Task 3 ✓
- Seção de relatório dedicada → Task 4 (`render_section_html`) + Task 5 (injeção) ✓
- Restrição a fases ASV-safe → Task 6 (`ASV_PHASES`, exclui P5/P9*/P10_5/P12) ✓
- `asv_verdict.json` → Task 5 ✓
- Aditivo / opt-in → Task 5 (`ASV_PREFLIGHT`), Task 6 (export) ✓
- Disclaimer de não-conformidade → Task 4 (`_DISCLAIMER`) ✓
- Fail-safe / escopo → Tasks 1-2 ✓

**2. Placeholder scan:** Sem TBD/TODO; todo código está presente. As duas notas com `>` são contingências de verificação (ordem de concatenação no report; flag `--proxy` do pipeline), com instrução concreta — não placeholders.

**3. Type consistency:** `aggregate` retorna `{would_pass,counted,fails}` e é consumido assim em Tasks 4/5. `build_inventory` retorna lista de `{host,ip,port,service,version,tls}`, idem nas tabelas HTML. `asv_verdict_for` retorna `(str,str)` em todas as chamadas. `classify_category` retorna as categorias usadas em `AUTO_FAIL`/`INFORMATIONAL`. CLI `verdict` emite `{"verdict":..., "inventory":...}`, casado com o teste da Task 4 e o `asv_verdict.json` da Task 5.

## Notas de execução
- Ordem das tasks é sequencial (cada uma estende `lib/asv_preflight.py`).
- Após Task 5, revalidar que um relatório SEM o env é idêntico ao baseline (diff contra um scan de referência, se disponível).
- Limitação v1 (sem ZAP active scan; SQLi/XSS via nuclei) está documentada no spec; não é gap do plano.

# OAuth/OIDC Audit (redirect_uri & PKCE) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Adicionar auditoria OAuth 2.0/OIDC ao `stiglitz.sh` (fase P9.6) cobrindo redirect_uri (open redirect/ATO), PKCE (ausente/downgrade), state/nonce e implicit flow — descoberta passiva sempre + probes ativos opt-in (`--oauth-active`, dry-run em `production`).

**Architecture:** Módulo único `lib/oauth_audit.py` com núcleo puro testável (parse de well-known/ZAP, análise de params, builders de probe, classifiers de resposta, build_findings) + orquestração de rede fina (fetch well-known + envio de probe via curl, injetável nos testes). Espelha `lib/jwt_audit.py` e `lib/bola.py`. Findings no schema do `jwt_audit` + `fingerprint`, coletados pelo `stiglitz_report.py` e classificados pelo motor de criticidade via 6 classes novas no `vuln_catalog.py`.

**Tech Stack:** Python 3 (stdlib: `json`, `urllib`, `subprocess`, `re`, `os`), bash (`stiglitz.sh`), pytest. Reuso: `bola.parse_zap_messages`, `fingerprint.fingerprint`, `vuln_catalog.CATALOG`.

**Convenções do repo:** módulos `lib/` importam por nome simples (ex.: `from fingerprint import fingerprint`) porque rodam como `python3 "$SCRIPT_DIR/lib/<mod>.py"` (lib/ entra no sys.path). Texto de finding em **EN** (deliverable); console em **PT-BR**. Exemplos usam `target.com` e canary `oauth-probe.invalid` — nunca domínio real.

---

## File Structure

- **Create** `lib/oauth_audit.py` — núcleo puro + orquestração de rede + CLI.
- **Create** `tests/test_oauth_audit.py` — testes por função (sem rede; `send_fn` injetável).
- **Modify** `lib/vuln_catalog.py` — 6 entradas `oauth_*` no `CATALOG`.
- **Modify** `stiglitz.sh` — fase P9.6 + flag `--oauth-active` (parsing de arg).
- **Modify** `stiglitz_report.py` — +1 tupla `('oauth_findings.json','oauth_findings')` na lista de coletores (linha ~872-884).
- **Modify** `CLAUDE.md` — fase P9.6 na lista do `stiglitz.sh` + linha de `oauth_audit.py` na tabela `lib/`.

---

## Task 1: Classes OAuth no catálogo de vulnerabilidades

**Files:**
- Modify: `lib/vuln_catalog.py` (dentro do dict `CATALOG`, após a entrada `open_redirect`)
- Test: `tests/test_oauth_audit.py`

- [ ] **Step 1: Write the failing test**

Criar `tests/test_oauth_audit.py` com:

```python
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))

from vuln_catalog import CATALOG


def test_oauth_classes_registered():
    expected = {
        "oauth_redirect_uri":  "CWE-601",
        "oauth_pkce_missing":  "CWE-287",
        "oauth_pkce_downgrade": "CWE-310",
        "oauth_missing_state": "CWE-352",
        "oauth_missing_nonce": "CWE-294",
        "oauth_implicit_flow": "CWE-522",
    }
    for klass, cwe in expected.items():
        assert klass in CATALOG, f"{klass} ausente do CATALOG"
        assert CATALOG[klass]["cwe"] == cwe
        assert CATALOG[klass]["vector"].startswith("AV:")
        assert CATALOG[klass]["title"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd ~/Stiglitz && python3 -m pytest tests/test_oauth_audit.py::test_oauth_classes_registered -v`
Expected: FAIL (`oauth_redirect_uri ausente do CATALOG`).

- [ ] **Step 3: Add the catalog entries**

Em `lib/vuln_catalog.py`, logo após a entrada `"open_redirect": {...},` adicionar:

```python
    "oauth_redirect_uri":   {"cwe": "CWE-601", "title": "OAuth redirect_uri validation bypass (account takeover)",
                             "vector": "AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N"},
    "oauth_pkce_missing":   {"cwe": "CWE-287", "title": "OAuth authorization code flow without enforced PKCE",
                             "vector": "AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N"},
    "oauth_pkce_downgrade": {"cwe": "CWE-310", "title": "OAuth PKCE downgrade to plain challenge method",
                             "vector": "AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N"},
    "oauth_missing_state":  {"cwe": "CWE-352", "title": "OAuth flow without state parameter (login CSRF)",
                             "vector": "AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"},
    "oauth_missing_nonce":  {"cwe": "CWE-294", "title": "OIDC flow without nonce (id_token replay)",
                             "vector": "AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N"},
    "oauth_implicit_flow":  {"cwe": "CWE-522", "title": "OAuth implicit flow enabled (token exposed in URL fragment)",
                             "vector": "AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N"},
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd ~/Stiglitz && python3 -m pytest tests/test_oauth_audit.py::test_oauth_classes_registered -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cd ~/Stiglitz && git add lib/vuln_catalog.py tests/test_oauth_audit.py
git commit -m "feat(catalog): 6 classes OAuth/OIDC (redirect_uri/PKCE/state/nonce/implicit) (P1)"
```

---

## Task 2: Criar `lib/oauth_audit.py` + `parse_well_known`

**Files:**
- Create: `lib/oauth_audit.py`
- Test: `tests/test_oauth_audit.py`

- [ ] **Step 1: Write the failing test**

Adicionar a `tests/test_oauth_audit.py`:

```python
import oauth_audit


def test_parse_well_known_normalizes():
    doc = """{"authorization_endpoint":"https://target.com/authorize",
              "token_endpoint":"https://target.com/token",
              "response_types_supported":["code","token","id_token"],
              "code_challenge_methods_supported":["S256"],
              "grant_types_supported":["authorization_code"]}"""
    wk = oauth_audit.parse_well_known(doc)
    assert wk["authorization_endpoint"] == "https://target.com/authorize"
    assert wk["response_types_supported"] == ["code", "token", "id_token"]
    assert wk["code_challenge_methods_supported"] == ["S256"]


def test_parse_well_known_invalid_returns_empty():
    assert oauth_audit.parse_well_known("not json") == {}
    assert oauth_audit.parse_well_known("[1,2,3]") == {}
    assert oauth_audit.parse_well_known("") == {}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd ~/Stiglitz && python3 -m pytest tests/test_oauth_audit.py -k parse_well_known -v`
Expected: FAIL (`ModuleNotFoundError: No module named 'oauth_audit'`).

- [ ] **Step 3: Create the module with header + `parse_well_known`**

Criar `lib/oauth_audit.py`:

```python
#!/usr/bin/env python3
"""
oauth_audit.py — auditoria ATIVA de OAuth 2.0 / OIDC (P1, fase P9.6).

Núcleo puro (parse de well-known/ZAP, análise de params, builders de probe,
classifiers de resposta) testável sem rede + orquestração de rede fina
(fetch well-known + envio de probe via curl, injetável). Espelha jwt_audit.py
e bola.py. Findings em EN, schema do jwt_audit + fingerprint.

Descoberta passiva roda sempre; probes ativos exigem flag --oauth-active e,
mesmo assim, viram dry-run sob STIGLITZ_PROFILE=production.
"""
import sys
import os
import re
import json
import urllib.parse

WELL_KNOWN_PATHS = (
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
)

try:
    from bola import parse_zap_messages
except Exception:  # importado fora de lib/
    def parse_zap_messages(_):
        return []

try:
    from fingerprint import fingerprint as _fingerprint
    from vuln_catalog import CATALOG as _CATALOG
except Exception:
    def _fingerprint(f):
        return "0" * 16
    _CATALOG = {}


def parse_well_known(json_text):
    """Normaliza o JSON do .well-known. JSON inválido/não-dict → {}."""
    try:
        d = json.loads(json_text or "")
    except Exception:
        return {}
    if not isinstance(d, dict):
        return {}

    def _list(k):
        v = d.get(k)
        return [str(x) for x in v] if isinstance(v, list) else []

    return {
        "authorization_endpoint": str(d.get("authorization_endpoint") or ""),
        "token_endpoint": str(d.get("token_endpoint") or ""),
        "response_types_supported": _list("response_types_supported"),
        "code_challenge_methods_supported": _list("code_challenge_methods_supported"),
        "grant_types_supported": _list("grant_types_supported"),
        "scopes_supported": _list("scopes_supported"),
    }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd ~/Stiglitz && python3 -m pytest tests/test_oauth_audit.py -k parse_well_known -v`
Expected: PASS (2 testes).

- [ ] **Step 5: Commit**

```bash
cd ~/Stiglitz && git add lib/oauth_audit.py tests/test_oauth_audit.py
git commit -m "feat(oauth): módulo oauth_audit + parse_well_known (P1)"
```

---

## Task 3: `parse_authorize_requests` (params reais do ZAP)

**Files:**
- Modify: `lib/oauth_audit.py`
- Test: `tests/test_oauth_audit.py`

- [ ] **Step 1: Write the failing test**

```python
def test_parse_authorize_requests_extracts_params():
    dump = json.dumps({"messages": [
        {"requestHeader": "GET https://target.com/oauth2/authorize?client_id=abc&"
                          "redirect_uri=https%3A%2F%2Ftarget.com%2Fcb&response_type=code&"
                          "scope=openid%20profile&state=xyz&code_challenge=ch&"
                          "code_challenge_method=S256 HTTP/1.1",
         "responseHeader": "HTTP/1.1 302 Found", "responseBody": ""},
        {"requestHeader": "GET https://target.com/about HTTP/1.1",
         "responseHeader": "HTTP/1.1 200 OK", "responseBody": ""},
    ]})
    flows = oauth_audit.parse_authorize_requests(dump)
    assert len(flows) == 1
    f = flows[0]
    assert f["client_id"] == "abc"
    assert f["redirect_uri"] == "https://target.com/cb"
    assert f["response_type"] == "code"
    assert f["scope"] == "openid profile"
    assert f["state"] == "xyz"
    assert f["code_challenge_method"] == "S256"


def test_parse_authorize_requests_ignores_non_oauth():
    import json as _j
    dump = _j.dumps({"messages": [
        {"requestHeader": "GET https://target.com/home HTTP/1.1",
         "responseHeader": "HTTP/1.1 200 OK", "responseBody": ""}]})
    assert oauth_audit.parse_authorize_requests(dump) == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd ~/Stiglitz && python3 -m pytest tests/test_oauth_audit.py -k authorize_requests -v`
Expected: FAIL (`AttributeError: module 'oauth_audit' has no attribute 'parse_authorize_requests'`).

- [ ] **Step 3: Implement**

Adicionar a `lib/oauth_audit.py`:

```python
_AUTHORIZE_HINT = re.compile(r'/(?:oauth2?/)?(?:authorize|auth)\b|[?&]response_type=', re.I)


def parse_authorize_requests(zap_messages_text):
    """Extrai fluxos /authorize observados no dump do ZAP. Reusa bola.parse_zap_messages."""
    flows = []
    for r in parse_zap_messages(zap_messages_text):
        url = r.get("url") or ""
        if not _AUTHORIZE_HINT.search(url):
            continue
        q = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)

        def g(k):
            v = q.get(k)
            return v[0] if v else ""

        flows.append({
            "authorize_url": url,
            "client_id": g("client_id"),
            "redirect_uri": g("redirect_uri"),
            "response_type": g("response_type"),
            "state": g("state"),
            "nonce": g("nonce"),
            "code_challenge": g("code_challenge"),
            "code_challenge_method": g("code_challenge_method"),
            "scope": g("scope"),
        })
    return flows
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd ~/Stiglitz && python3 -m pytest tests/test_oauth_audit.py -k authorize_requests -v`
Expected: PASS (2 testes).

- [ ] **Step 5: Commit**

```bash
cd ~/Stiglitz && git add lib/oauth_audit.py tests/test_oauth_audit.py
git commit -m "feat(oauth): parse_authorize_requests — params reais do dump ZAP (P1)"
```

---

## Task 4: `_finding` helper + `static_findings` (descoberta passiva)

**Files:**
- Modify: `lib/oauth_audit.py`
- Test: `tests/test_oauth_audit.py`

- [ ] **Step 1: Write the failing test**

```python
def test_finding_schema():
    f = oauth_audit._finding("oauth_implicit_flow", "https://target.com/authorize",
                             "Implicit flow enabled", "medium", "desc", "fix", "ev")
    assert f["tool"] == "oauth_audit"
    assert f["type"] == "oauth_implicit_flow"
    assert f["source"] == "OAuth Audit"
    assert f["cwe"] == "CWE-522"
    assert f["severity"] == "medium"
    assert len(f["fingerprint"]) == 16


def test_static_findings_from_well_known():
    wk = oauth_audit.parse_well_known(json.dumps({
        "authorization_endpoint": "https://target.com/authorize",
        "response_types_supported": ["code", "token"],
        "code_challenge_methods_supported": ["plain"]}))
    types = {f["type"] for f in oauth_audit.static_findings(wk, [], "https://target.com")}
    assert "oauth_implicit_flow" in types      # token em response_types
    assert "oauth_pkce_downgrade" in types     # só plain anunciado


def test_static_findings_pkce_not_advertised():
    wk = oauth_audit.parse_well_known(json.dumps({
        "authorization_endpoint": "https://target.com/authorize",
        "response_types_supported": ["code"]}))
    types = {f["type"] for f in oauth_audit.static_findings(wk, [], "https://target.com")}
    assert "oauth_pkce_missing" in types
    assert "oauth_implicit_flow" not in types


def test_static_findings_from_observed_flow():
    flow = {"authorize_url": "https://target.com/authorize", "client_id": "a",
            "redirect_uri": "http://target.com/cb", "response_type": "code",
            "state": "", "nonce": "", "code_challenge": "",
            "code_challenge_method": "", "scope": "openid"}
    types = {f["type"] for f in oauth_audit.static_findings({}, [flow], "https://target.com")}
    assert "oauth_pkce_missing" in types    # code flow sem code_challenge
    assert "oauth_missing_state" in types   # sem state
    assert "oauth_missing_nonce" in types   # openid sem nonce
    assert "oauth_redirect_uri" in types    # redirect_uri http://


def test_static_findings_clean_flow_no_issues():
    flow = {"authorize_url": "https://target.com/authorize", "client_id": "a",
            "redirect_uri": "https://target.com/cb", "response_type": "code",
            "state": "s", "nonce": "n", "code_challenge": "c",
            "code_challenge_method": "S256", "scope": "openid"}
    wk = {"authorization_endpoint": "https://target.com/authorize",
          "response_types_supported": ["code"],
          "code_challenge_methods_supported": ["S256"]}
    assert oauth_audit.static_findings(wk, [flow], "https://target.com") == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd ~/Stiglitz && python3 -m pytest tests/test_oauth_audit.py -k "finding_schema or static_findings" -v`
Expected: FAIL (`module 'oauth_audit' has no attribute '_finding'`).

- [ ] **Step 3: Implement**

Adicionar a `lib/oauth_audit.py`:

```python
def _finding(klass, url, name, severity, description, remediation, evidence=""):
    """Schema do finding (igual jwt_audit + cwe + fingerprint). Texto em EN."""
    f = {
        "tool": "oauth_audit", "type": klass, "source": "OAuth Audit",
        "name": name, "url": url, "severity": severity,
        "description": description, "remediation": remediation,
        "evidence": evidence, "cwe": _CATALOG.get(klass, {}).get("cwe", ""),
    }
    f["fingerprint"] = _fingerprint(f)
    return f


def _dedup(findings):
    """Remove duplicatas por fingerprint, preservando ordem."""
    seen, out = set(), []
    for f in findings:
        fp = f.get("fingerprint")
        if fp in seen:
            continue
        seen.add(fp)
        out.append(f)
    return out


def static_findings(wellknown, flows, target):
    """Findings derivados sem rede do well-known + fluxos observados."""
    out = []
    wk = wellknown or {}
    rts = [r.lower() for r in wk.get("response_types_supported", [])]
    ccm = [m.lower() for m in wk.get("code_challenge_methods_supported", [])]

    if any("token" in rt.split() for rt in rts):
        out.append(_finding(
            "oauth_implicit_flow", wk.get("authorization_endpoint") or target,
            "Implicit flow enabled (response_type=token advertised)", "medium",
            "The authorization server advertises the implicit grant (response_type=token), "
            "which returns the access_token in the URL fragment where it leaks via browser "
            "history, Referer headers and logs.",
            "Disable the implicit grant; use authorization code flow with PKCE."))

    if wk.get("authorization_endpoint"):
        if not ccm:
            out.append(_finding(
                "oauth_pkce_missing", wk.get("authorization_endpoint"),
                "PKCE not advertised by the authorization server", "high",
                "code_challenge_methods_supported is absent from the discovery document; "
                "the server likely does not enforce PKCE, exposing public clients to "
                "authorization code interception.",
                "Advertise and enforce PKCE with the S256 method for all clients."))
        elif ccm == ["plain"]:
            out.append(_finding(
                "oauth_pkce_downgrade", wk.get("authorization_endpoint"),
                "Only the 'plain' PKCE method is supported", "medium",
                "The server advertises only code_challenge_method=plain, which provides no "
                "protection if the authorization request is observed.",
                "Support and require the S256 PKCE method; reject 'plain'."))

    for f in flows:
        au = f.get("authorize_url") or target
        rt = (f.get("response_type") or "").lower().split()
        if "token" in rt:
            out.append(_finding(
                "oauth_implicit_flow", au,
                "Implicit flow observed in live request (response_type=token)", "medium",
                "An observed /authorize request uses response_type=token; the access_token "
                "is returned in the URL fragment and leaks via history/Referer/logs.",
                "Migrate the client to authorization code flow with PKCE.",
                evidence=f"response_type={f.get('response_type')}"))
        if "code" in rt and not f.get("code_challenge"):
            out.append(_finding(
                "oauth_pkce_missing", au,
                "Authorization code request without PKCE", "high",
                "An observed code-flow /authorize request carries no code_challenge, so the "
                "client is not protected against authorization code interception.",
                "Send and enforce a code_challenge (S256) on every code-flow request.",
                evidence="no code_challenge in request"))
        if (f.get("code_challenge_method") or "").lower() == "plain":
            out.append(_finding(
                "oauth_pkce_downgrade", au,
                "PKCE downgrade observed (code_challenge_method=plain)", "medium",
                "An observed request uses code_challenge_method=plain instead of S256.",
                "Use and require S256.", evidence="code_challenge_method=plain"))
        if rt and not f.get("state"):
            out.append(_finding(
                "oauth_missing_state", au,
                "OAuth request without state parameter", "medium",
                "An observed /authorize request omits the state parameter, exposing the flow "
                "to login CSRF / authorization response fixation.",
                "Send an unguessable state on every request and validate it on callback.",
                evidence="no state parameter"))
        if "openid" in (f.get("scope") or "").lower().split() and not f.get("nonce"):
            out.append(_finding(
                "oauth_missing_nonce", au,
                "OIDC request without nonce", "low",
                "An OpenID Connect request (scope=openid) omits nonce, allowing id_token replay.",
                "Send and validate a nonce for OIDC requests.", evidence="no nonce parameter"))
        if (f.get("redirect_uri") or "").startswith("http://"):
            out.append(_finding(
                "oauth_redirect_uri", au,
                "OAuth redirect_uri uses cleartext HTTP", "high",
                "An observed redirect_uri uses http://, so the authorization code/token can be "
                "intercepted on the network.",
                "Register and require https:// redirect URIs only.",
                evidence=f"redirect_uri={f.get('redirect_uri')}"))
    return _dedup(out)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd ~/Stiglitz && python3 -m pytest tests/test_oauth_audit.py -k "finding_schema or static_findings" -v`
Expected: PASS (6 testes).

- [ ] **Step 5: Commit**

```bash
cd ~/Stiglitz && git add lib/oauth_audit.py tests/test_oauth_audit.py
git commit -m "feat(oauth): static_findings — descoberta passiva (well-known + fluxos) (P1)"
```

---

## Task 5: Probe builders (`_with_query`, `build_redirect_uri_probes`, `build_pkce_*`)

**Files:**
- Modify: `lib/oauth_audit.py`
- Test: `tests/test_oauth_audit.py`

- [ ] **Step 1: Write the failing test**

```python
BASE = {"client_id": "abc", "response_type": "code", "scope": "openid",
        "state": "s", "redirect_uri": "https://target.com/cb"}
CANARY = "https://oauth-probe.invalid/cb"


def test_redirect_uri_probes_point_to_canary():
    probes = oauth_audit.build_redirect_uri_probes(
        "https://target.com/authorize", BASE, CANARY)
    labels = {p["label"] for p in probes}
    assert "redirect_uri:external" in labels
    for p in probes:
        assert p["expected_marker"] == "oauth-probe.invalid"
        assert "oauth-probe.invalid" in p["url"]
        assert p["url"].startswith("https://target.com/authorize?")
        assert "client_id=abc" in p["url"]


def test_pkce_missing_probe_drops_challenge():
    p = oauth_audit.build_pkce_missing_probe("https://target.com/authorize", BASE)
    assert "code_challenge" not in p["url"]
    assert p["label"] == "pkce:missing"


def test_pkce_downgrade_probe_uses_plain():
    p = oauth_audit.build_pkce_downgrade_probe("https://target.com/authorize", BASE)
    assert "code_challenge_method=plain" in p["url"]
    assert p["label"] == "pkce:downgrade"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd ~/Stiglitz && python3 -m pytest tests/test_oauth_audit.py -k "probe" -v`
Expected: FAIL (`has no attribute 'build_redirect_uri_probes'`).

- [ ] **Step 3: Implement**

Adicionar a `lib/oauth_audit.py`:

```python
def _with_query(url, params):
    """Reescreve a query da URL com params (descarta valores vazios)."""
    s = urllib.parse.urlsplit(url)
    q = urllib.parse.urlencode({k: v for k, v in params.items() if v != ""})
    return urllib.parse.urlunsplit((s.scheme, s.netloc, s.path, q, ""))


def build_redirect_uri_probes(authorize_url, params, canary):
    """Variações maliciosas de redirect_uri apontando ao host canary (sentinela)."""
    host = urllib.parse.urlsplit(canary).netloc or canary
    legit = params.get("redirect_uri", "")
    legit_host = urllib.parse.urlsplit(legit).netloc
    variants = {
        "external": canary,
        "subdomain_suffix": f"https://{legit_host}.{host}/cb" if legit_host else canary,
        "userinfo": f"{legit}@{host}" if legit else canary,
        "path_traversal": f"{legit}/../{host}" if legit else canary,
        "open_redirect_param": f"{legit}?next={canary}" if legit else canary,
    }
    probes = []
    for label, evil in variants.items():
        p = dict(params)
        p["redirect_uri"] = evil
        probes.append({"label": f"redirect_uri:{label}",
                       "url": _with_query(authorize_url, p),
                       "expected_marker": host, "kind": "redirect"})
    return probes


def build_pkce_missing_probe(authorize_url, params):
    """Code flow sem code_challenge — testa se o servidor aceita (PKCE não enforçado)."""
    p = dict(params)
    p["response_type"] = "code"
    p.pop("code_challenge", None)
    p.pop("code_challenge_method", None)
    return {"label": "pkce:missing", "url": _with_query(authorize_url, p), "kind": "pkce"}


def build_pkce_downgrade_probe(authorize_url, params):
    """Code flow com code_challenge_method=plain — testa downgrade."""
    p = dict(params)
    p["response_type"] = "code"
    p["code_challenge"] = p.get("code_challenge") or "plainchallenge"
    p["code_challenge_method"] = "plain"
    return {"label": "pkce:downgrade", "url": _with_query(authorize_url, p), "kind": "pkce"}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd ~/Stiglitz && python3 -m pytest tests/test_oauth_audit.py -k "probe" -v`
Expected: PASS (3 testes).

- [ ] **Step 5: Commit**

```bash
cd ~/Stiglitz && git add lib/oauth_audit.py tests/test_oauth_audit.py
git commit -m "feat(oauth): probe builders redirect_uri/PKCE (puros, canary sentinela) (P1)"
```

---

## Task 6: Classifiers de resposta

**Files:**
- Modify: `lib/oauth_audit.py`
- Test: `tests/test_oauth_audit.py`

- [ ] **Step 1: Write the failing test**

```python
def test_classify_redirect_confirmed_when_location_is_canary():
    v = oauth_audit.classify_redirect_response(
        302, "https://oauth-probe.invalid/cb?code=x", "oauth-probe.invalid")
    assert v["state"] == "CONFIRMED"


def test_classify_redirect_rejected():
    v = oauth_audit.classify_redirect_response(
        400, "", "oauth-probe.invalid")
    assert v["state"] == "REJECTED"
    v2 = oauth_audit.classify_redirect_response(
        302, "https://target.com/error?e=invalid_redirect_uri", "oauth-probe.invalid")
    assert v2["state"] == "REJECTED"


def test_classify_redirect_inconclusive():
    v = oauth_audit.classify_redirect_response(
        200, "", "oauth-probe.invalid")
    assert v["state"] == "INCONCLUSIVE"


def test_classify_pkce_confirmed_when_code_issued():
    v = oauth_audit.classify_pkce_response(302, "https://target.com/cb?code=abc", "")
    assert v["state"] == "CONFIRMED"


def test_classify_pkce_rejected():
    v = oauth_audit.classify_pkce_response(400, "", "code_challenge required")
    assert v["state"] == "REJECTED"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd ~/Stiglitz && python3 -m pytest tests/test_oauth_audit.py -k "classify" -v`
Expected: FAIL (`has no attribute 'classify_redirect_response'`).

- [ ] **Step 3: Implement**

Adicionar a `lib/oauth_audit.py`:

```python
def _loc_host(location):
    return urllib.parse.urlsplit(location or "").netloc


def classify_redirect_response(status, location, canary_host):
    """CONFIRMED se o servidor redireciona para o host canary; REJECTED se nega; senão INCONCLUSIVE."""
    loc = location or ""
    host = _loc_host(loc)
    if host and (host == canary_host or host.endswith("." + canary_host)):
        return {"state": "CONFIRMED", "evidence": f"Location -> {loc[:120]}"}
    low = loc.lower()
    if status in (400, 401, 403) or "invalid_redirect" in low or "invalid_request" in low:
        return {"state": "REJECTED", "evidence": f"status={status} {loc[:80]}"}
    return {"state": "INCONCLUSIVE", "evidence": f"status={status} location={loc[:80]}"}


def classify_pkce_response(status, location, body):
    """CONFIRMED se um authorization code é emitido sem PKCE válido; REJECTED se o servidor exige PKCE."""
    loc = location or ""
    b = body or ""
    if "code=" in loc or '"code"' in b or '"access_token"' in b:
        return {"state": "CONFIRMED", "evidence": f"code issued (status={status})"}
    low = (loc + " " + b).lower()
    if status in (400, 401, 403) or "code_challenge" in low or "pkce" in low:
        return {"state": "REJECTED", "evidence": f"status={status}"}
    return {"state": "INCONCLUSIVE", "evidence": f"status={status}"}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd ~/Stiglitz && python3 -m pytest tests/test_oauth_audit.py -k "classify" -v`
Expected: PASS (5 testes).

- [ ] **Step 5: Commit**

```bash
cd ~/Stiglitz && git add lib/oauth_audit.py tests/test_oauth_audit.py
git commit -m "feat(oauth): classifiers redirect/PKCE (CONFIRMED/REJECTED/INCONCLUSIVE) (P1)"
```

---

## Task 7: `active_findings` — verdicts dos probes → findings

**Files:**
- Modify: `lib/oauth_audit.py`
- Test: `tests/test_oauth_audit.py`

- [ ] **Step 1: Write the failing test**

```python
def test_active_findings_redirect_confirmed():
    probe = {"label": "redirect_uri:external",
             "url": "https://target.com/authorize?redirect_uri=https://oauth-probe.invalid/cb",
             "expected_marker": "oauth-probe.invalid", "kind": "redirect"}
    verdict = {"state": "CONFIRMED", "evidence": "Location -> https://oauth-probe.invalid/cb"}
    fs = oauth_audit.active_findings([(probe, verdict)], "https://target.com")
    assert len(fs) == 1
    assert fs[0]["type"] == "oauth_redirect_uri"
    assert fs[0]["severity"] == "high"
    assert "oauth-probe.invalid" in fs[0]["evidence"]


def test_active_findings_pkce_confirmed():
    probe = {"label": "pkce:missing", "url": "https://target.com/authorize?response_type=code",
             "kind": "pkce"}
    verdict = {"state": "CONFIRMED", "evidence": "code issued (status=302)"}
    fs = oauth_audit.active_findings([(probe, verdict)], "https://target.com")
    assert fs[0]["type"] == "oauth_pkce_missing"


def test_active_findings_drops_non_confirmed():
    probe = {"label": "redirect_uri:external", "url": "u",
             "expected_marker": "oauth-probe.invalid", "kind": "redirect"}
    for st in ("REJECTED", "INCONCLUSIVE"):
        assert oauth_audit.active_findings([(probe, {"state": st, "evidence": ""})],
                                           "https://target.com") == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd ~/Stiglitz && python3 -m pytest tests/test_oauth_audit.py -k "active_findings" -v`
Expected: FAIL (`has no attribute 'active_findings'`).

- [ ] **Step 3: Implement**

Adicionar a `lib/oauth_audit.py`:

```python
def active_findings(probe_verdicts, target):
    """Converte (probe, verdict) CONFIRMED em findings. Não-CONFIRMED é descartado."""
    out = []
    for probe, verdict in probe_verdicts:
        if verdict.get("state") != "CONFIRMED":
            continue
        kind = probe.get("kind")
        ev = verdict.get("evidence", "")
        if kind == "redirect":
            out.append(_finding(
                "oauth_redirect_uri", target,
                "redirect_uri validation bypass confirmed (open redirect / code theft)", "high",
                "The authorization server accepted an attacker-controlled redirect_uri and "
                "redirected to it. An attacker can steal the authorization code/token and take "
                "over the victim's account.",
                "Enforce exact-match allow-listing of registered redirect URIs; reject any "
                "unregistered value. No substring/subdomain/path matching.",
                evidence=f"{probe.get('label')} | {ev}"))
        elif kind == "pkce":
            klass = "oauth_pkce_missing" if probe.get("label") == "pkce:missing" else "oauth_pkce_downgrade"
            out.append(_finding(
                klass, target,
                "PKCE not enforced — authorization code issued without valid PKCE", "high",
                "The authorization server issued an authorization code for a request that "
                "lacked a valid S256 code_challenge, leaving public clients open to "
                "authorization code interception.",
                "Require and validate a S256 code_challenge for every authorization code "
                "request; reject 'plain' and missing challenges.",
                evidence=f"{probe.get('label')} | {ev}"))
    return _dedup(out)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd ~/Stiglitz && python3 -m pytest tests/test_oauth_audit.py -k "active_findings" -v`
Expected: PASS (3 testes).

- [ ] **Step 5: Commit**

```bash
cd ~/Stiglitz && git add lib/oauth_audit.py tests/test_oauth_audit.py
git commit -m "feat(oauth): active_findings — verdicts confirmados viram findings (P1)"
```

---

## Task 8: Orquestração de rede (`fetch_well_known`, `send_probe`) + `run` com gating

**Files:**
- Modify: `lib/oauth_audit.py`
- Test: `tests/test_oauth_audit.py`

- [ ] **Step 1: Write the failing test**

```python
def _wk_text():
    return json.dumps({"authorization_endpoint": "https://target.com/authorize",
                       "response_types_supported": ["code"],
                       "code_challenge_methods_supported": []})


def _zap_text():
    return json.dumps({"messages": [
        {"requestHeader": "GET https://target.com/authorize?client_id=a&"
                          "redirect_uri=https%3A%2F%2Ftarget.com%2Fcb&response_type=code&"
                          "state=s HTTP/1.1",
         "responseHeader": "HTTP/1.1 302 Found", "responseBody": ""}]})


def test_run_passive_only_when_not_active(tmp_path):
    sent = []

    def fake_send(probe):
        sent.append(probe)
        return (302, "https://oauth-probe.invalid/cb", "")

    res = oauth_audit.run(str(tmp_path), active=False, profile=None,
                          well_known_text=_wk_text(), zap_text=_zap_text(),
                          client_id="a", authorize_url="https://target.com/authorize",
                          target="https://target.com", send_fn=fake_send)
    assert sent == []                       # nenhum probe enviado (passivo)
    assert res["summary"]["active"] is False
    assert res["summary"]["passive"] >= 1   # achou PKCE-missing no well-known
    out = json.load(open(os.path.join(str(tmp_path), "raw", "oauth_findings.json")))
    assert any(f["type"] == "oauth_pkce_missing" for f in out)


def test_run_production_forces_dry_run(tmp_path):
    sent = []

    def fake_send(probe):
        sent.append(probe)
        return (302, "https://oauth-probe.invalid/cb", "")

    res = oauth_audit.run(str(tmp_path), active=True, profile="production",
                          well_known_text=_wk_text(), zap_text=_zap_text(),
                          client_id="a", authorize_url="https://target.com/authorize",
                          target="https://target.com", send_fn=fake_send)
    assert sent == []                       # production → dry-run
    assert res["summary"]["dry_run"] is True


def test_run_active_sends_probes_and_confirms(tmp_path):
    def fake_send(probe):
        if probe.get("kind") == "redirect":
            return (302, "https://oauth-probe.invalid/cb?code=x", "")
        return (302, "https://target.com/cb?code=x", "")

    res = oauth_audit.run(str(tmp_path), active=True, profile="staging",
                          well_known_text=_wk_text(), zap_text=_zap_text(),
                          client_id="a", authorize_url="https://target.com/authorize",
                          target="https://target.com", send_fn=fake_send)
    out = json.load(open(os.path.join(str(tmp_path), "raw", "oauth_findings.json")))
    types = {f["type"] for f in out}
    assert "oauth_redirect_uri" in types
    assert "oauth_pkce_missing" in types
    assert res["summary"]["active"] is True
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd ~/Stiglitz && python3 -m pytest tests/test_oauth_audit.py -k "run_" -v`
Expected: FAIL (`run() got an unexpected keyword` / `has no attribute 'run'`).

- [ ] **Step 3: Implement**

Adicionar a `lib/oauth_audit.py`:

```python
def fetch_well_known(base_url, timeout=15):
    """GET nos paths .well-known. Retorna o primeiro corpo JSON não-vazio, ou ''."""
    import urllib.request
    base = base_url.rstrip("/")
    for path in WELL_KNOWN_PATHS:
        try:
            req = urllib.request.Request(base + path, headers={"Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read().decode("utf-8", errors="replace")
            if body.strip():
                return body
        except Exception:
            continue
    return ""


def send_probe(probe, timeout=15):
    """Envia o probe via curl SEM seguir redirect (lê o Location cru). Retorna (status, location, body)."""
    import subprocess
    url = probe.get("url") or ""
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return (0, "", "")
    cmd = ["curl", "-s", "-S", "--max-time", str(timeout), "-o", "-",
           "-w", "\n__HTTP_STATUS__:%{http_code}\n__LOCATION__:%{redirect_url}", "--", url]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 5)
        raw = p.stdout or ""
    except Exception:
        return (0, "", "")
    status, location, body = 0, "", raw
    sm = raw.rfind("__HTTP_STATUS__:")
    if sm != -1:
        body = raw[:sm].rstrip("\n")
        tail = raw[sm:]
        for line in tail.splitlines():
            if line.startswith("__HTTP_STATUS__:"):
                try:
                    status = int(line.split(":", 1)[1].strip())
                except ValueError:
                    status = 0
            elif line.startswith("__LOCATION__:"):
                location = line.split(":", 1)[1].strip()
    return (status, location, body)


def run(scan_dir, active=False, profile=None, well_known_text=None, zap_text=None,
        client_id="", authorize_url="", redirect_uri="", canary=None, target="",
        send_fn=send_probe):
    """Orquestra a fase P9.6. Passivo sempre; ativo só com active=True e profile!=production.
    well_known_text/zap_text injetáveis (testes); em produção real são lidos do disco/rede pelo caller."""
    canary = canary or os.environ.get("STIGLITZ_OAUTH_CANARY_URI") or "https://oauth-probe.invalid/cb"
    wk = parse_well_known(well_known_text or "")
    flows = parse_authorize_requests(zap_text or "")

    findings = static_findings(wk, flows, target or authorize_url)
    passive_n = len(findings)

    authorize_url = authorize_url or wk.get("authorization_endpoint") or ""
    if not client_id and flows:
        client_id = flows[0].get("client_id", "")
    if not redirect_uri and flows:
        redirect_uri = flows[0].get("redirect_uri", "")

    dry_run = active and (profile or "").lower() == "production"
    do_active = active and not dry_run and bool(authorize_url) and bool(client_id)

    params = {"client_id": client_id, "response_type": "code",
              "scope": (flows[0].get("scope") if flows else "") or "openid",
              "state": "stiglitz", "redirect_uri": redirect_uri}

    if active and not do_active and not dry_run:
        print("  [!] oauth-audit: probes ativos pulados (sem authorize_url/client_id)")

    if dry_run:
        print("  [i] oauth-audit: probes ativos em dry-run (STIGLITZ_PROFILE=production)")

    if do_active:
        probes = build_redirect_uri_probes(authorize_url, params, canary)
        pkce_missing = build_pkce_missing_probe(authorize_url, params)
        pkce_down = build_pkce_downgrade_probe(authorize_url, params)
        canary_host = urllib.parse.urlsplit(canary).netloc
        verdicts = []
        for pr in probes:
            status, loc, body = send_fn(pr)
            verdicts.append((pr, classify_redirect_response(status, loc, canary_host)))
        for pr in (pkce_missing, pkce_down):
            status, loc, body = send_fn(pr)
            verdicts.append((pr, classify_pkce_response(status, loc, body)))
        findings += active_findings(verdicts, target or authorize_url)
        findings = _dedup(findings)

    summary = {"passive": passive_n, "active": do_active, "dry_run": dry_run,
               "total": len(findings)}
    raw_dir = os.path.join(scan_dir, "raw")
    try:
        os.makedirs(raw_dir, exist_ok=True)
        with open(os.path.join(raw_dir, "oauth_findings.json"), "w", encoding="utf-8") as fh:
            json.dump(findings, fh, indent=2, ensure_ascii=False)
    except Exception as exc:
        print(f"  aviso: não foi possível gravar oauth_findings.json: {exc}", file=sys.stderr)
    return {"findings": findings, "summary": summary}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd ~/Stiglitz && python3 -m pytest tests/test_oauth_audit.py -k "run_" -v`
Expected: PASS (3 testes).

- [ ] **Step 5: Commit**

```bash
cd ~/Stiglitz && git add lib/oauth_audit.py tests/test_oauth_audit.py
git commit -m "feat(oauth): fetch_well_known/send_probe + run() com gating opt-in/production (P1)"
```

---

## Task 9: CLI `main()`

**Files:**
- Modify: `lib/oauth_audit.py`
- Test: `tests/test_oauth_audit.py`

- [ ] **Step 1: Write the failing test**

```python
def test_cli_run_writes_output(tmp_path, monkeypatch, capsys):
    wk = tmp_path / "wk.json"; wk.write_text(_wk_text())
    zap = tmp_path / "zap.json"; zap.write_text(_zap_text())
    rc = oauth_audit.main(["oauth_audit.py", "run", str(tmp_path),
                           "--well-known", str(wk), "--zap", str(zap),
                           "--target", "https://target.com"])
    assert rc == 0
    out = json.load(open(os.path.join(str(tmp_path), "raw", "oauth_findings.json")))
    assert isinstance(out, list)
    assert "oauth-audit" in capsys.readouterr().out


def test_cli_usage_on_bad_args():
    assert oauth_audit.main(["oauth_audit.py"]) == 2
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd ~/Stiglitz && python3 -m pytest tests/test_oauth_audit.py -k "cli" -v`
Expected: FAIL (`has no attribute 'main'`).

- [ ] **Step 3: Implement**

Adicionar a `lib/oauth_audit.py` (no fim do arquivo):

```python
def _read(path):
    try:
        with open(path, encoding="utf-8", errors="ignore") as fh:
            return fh.read()
    except Exception:
        return ""


def main(argv):
    """CLI: oauth_audit.py run <scan_dir> [--well-known F] [--zap F] [--active]
    [--profile P] [--target URL] [--authorize-url URL]. Segredos via env STIGLITZ_OAUTH_*."""
    if len(argv) < 3 or argv[1] != "run":
        print("uso: oauth_audit.py run <scan_dir> [--well-known F] [--zap F] "
              "[--active] [--profile P] [--target URL] [--authorize-url URL]", file=sys.stderr)
        return 2
    scan_dir = argv[2]
    opts = {"--well-known": "", "--zap": "", "--profile": os.environ.get("STIGLITZ_PROFILE", ""),
            "--target": "", "--authorize-url": os.environ.get("STIGLITZ_OAUTH_AUTHORIZE_URL", "")}
    active = "--active" in argv
    i = 3
    while i < len(argv):
        if argv[i] in opts and i + 1 < len(argv):
            opts[argv[i]] = argv[i + 1]
            i += 2
        else:
            i += 1
    wk_text = _read(opts["--well-known"]) if opts["--well-known"] else ""
    if not wk_text and opts["--target"]:
        wk_text = fetch_well_known(opts["--target"])
    zap_text = _read(opts["--zap"]) if opts["--zap"] else ""
    res = run(scan_dir, active=active, profile=opts["--profile"] or None,
              well_known_text=wk_text, zap_text=zap_text,
              client_id=os.environ.get("STIGLITZ_OAUTH_CLIENT_ID", ""),
              authorize_url=opts["--authorize-url"],
              redirect_uri=os.environ.get("STIGLITZ_OAUTH_REDIRECT_URI", ""),
              target=opts["--target"])
    s = res["summary"]
    print(f"  oauth-audit: {s['total']} finding(s) ({s['passive']} passivo, "
          f"ativo={s['active']}, dry_run={s['dry_run']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd ~/Stiglitz && python3 -m pytest tests/test_oauth_audit.py -k "cli" -v`
Expected: PASS (2 testes).

- [ ] **Step 5: Run the full module test suite + compile**

Run: `cd ~/Stiglitz && python3 -m pytest tests/test_oauth_audit.py -v && python3 -m py_compile lib/oauth_audit.py`
Expected: PASS (todos) e compile sem erro.

- [ ] **Step 6: Commit**

```bash
cd ~/Stiglitz && git add lib/oauth_audit.py tests/test_oauth_audit.py
git commit -m "feat(oauth): CLI main() — run com well-known/zap/active/profile (P1)"
```

---

## Task 10: Wiring no `stiglitz.sh` (flag `--oauth-active` + fase P9.6)

**Files:**
- Modify: `stiglitz.sh` (parsing de args; novo bloco após a P9.5, que termina em `fi  # fim P9.5` na linha ~1739)

- [ ] **Step 1: Adicionar o parsing da flag `--oauth-active`**

Localizar o bloco de parsing de argumentos (onde `--token-a`/`--token-b` são tratados; procurar `--token-a)` com `grep -n '\-\-token-a)' stiglitz.sh`). Adicionar um caso novo no mesmo `case`/`while`:

```bash
        --oauth-active)
            OAUTH_ACTIVE=1
            shift
            ;;
```

E inicializar a variável junto às outras defaults (perto de `TOKEN_A=""`), com:

```bash
OAUTH_ACTIVE=0
```

- [ ] **Step 2: Adicionar a fase P9.6 após a P9.5**

Imediatamente após a linha `fi  # fim P9.5` (~1739), inserir:

```bash
# ====================== FASE 9.6: OAUTH/OIDC AUDIT ======================
if _phase_enabled "P9_6"; then
phase_start "P9_6"
phase_banner "FASE 9.6/11: OAUTH/OIDC AUDIT (redirect_uri & PKCE)"

_oauth_wk="$OUTDIR/raw/oauth_well_known.json"
: > "$_oauth_wk"
# Descoberta passiva do well-known (degrada silenciosamente se ausente)
for _wkp in "/.well-known/openid-configuration" "/.well-known/oauth-authorization-server"; do
    if curl -s -S --max-time 15 "https://${TARGET}${_wkp}" -o "$_oauth_wk" 2>/dev/null \
            && [ -s "$_oauth_wk" ] && grep -q "authorization_endpoint" "$_oauth_wk"; then
        break
    fi
    : > "$_oauth_wk"
done

# Corpus do ZAP (reusa o dump da P9.5 se existir)
_oauth_zap="$OUTDIR/raw/zap_messages_a.json"
[ -f "$_oauth_zap" ] || _oauth_zap=""

_oauth_active_arg=""
if [ "${OAUTH_ACTIVE:-0}" = "1" ]; then
    _oauth_active_arg="--active"
fi

python3 "$SCRIPT_DIR/lib/oauth_audit.py" run "$OUTDIR" \
    ${_oauth_wk:+--well-known "$_oauth_wk"} \
    ${_oauth_zap:+--zap "$_oauth_zap"} \
    --target "https://${TARGET}" \
    ${STIGLITZ_PROFILE:+--profile "$STIGLITZ_PROFILE"} \
    $_oauth_active_arg \
    && echo -e "  ${GREEN}[✓] OAuth audit concluído → raw/oauth_findings.json${NC}" \
    || echo -e "  ${YELLOW}[!] oauth-audit: módulo retornou erro${NC}"

phase_end "P9_6"
phase_done "FASE_9_6"
fi  # fim P9.6
```

- [ ] **Step 3: Verify bash syntax + shellcheck + wiring**

Run:
```bash
cd ~/Stiglitz && bash -n stiglitz.sh && \
shellcheck --severity=warning stiglitz.sh | head -20 ; \
grep -n "oauth-active\|FASE 9.6\|oauth_audit.py\|P9_6" stiglitz.sh
```
Expected: `bash -n` sem erro; shellcheck sem **novos** warnings introduzidos pelo bloco; grep mostra a flag, o banner, a invocação e o gate `P9_6`.

- [ ] **Step 4: Commit**

```bash
cd ~/Stiglitz && git add stiglitz.sh
git commit -m "feat(scan): fase P9.6 OAuth audit + flag --oauth-active (P1)"
```

---

## Task 11: Wiring no `stiglitz_report.py` (coletor) + `CLAUDE.md`

**Files:**
- Modify: `stiglitz_report.py` (lista de tuplas de coletores, linha ~872-884)
- Modify: `CLAUDE.md`

- [ ] **Step 1: Adicionar a tupla coletora**

Em `stiglitz_report.py`, na lista que hoje termina com `('access_findings.json', 'access_findings'),`, adicionar a linha:

```python
    ('oauth_findings.json',      'oauth_findings'),
```

- [ ] **Step 2: Verify compile + presença**

Run: `cd ~/Stiglitz && python3 -m py_compile stiglitz_report.py && grep -n "oauth_findings" stiglitz_report.py`
Expected: compile OK; grep mostra a tupla nova.

- [ ] **Step 3: Atualizar a documentação**

Em `CLAUDE.md`, na descrição das fases do `stiglitz.sh`, após a linha da **Fase 9.5**, adicionar:

```markdown
   - **Fase 9.6** — OAuth/OIDC Audit — descoberta passiva (well-known + params do ZAP) de redirect_uri/PKCE/state/nonce/implicit flow; probes ativos opt-in com `--oauth-active` (dry-run sob `STIGLITZ_PROFILE=production`)
```

E na tabela de módulos `lib/`, adicionar a linha:

```markdown
| `oauth_audit.py` | Auditoria OAuth 2.0/OIDC (fase P9.6) — well-known + params do ZAP → findings de `redirect_uri` (CWE-601), PKCE ausente/downgrade, state/nonce, implicit flow. Probes ativos opt-in (`--oauth-active`), dry-run em `production`. Lógica pura + CLI; `send_fn` injetável (testável sem rede) |
```

- [ ] **Step 4: Commit**

```bash
cd ~/Stiglitz && git add stiglitz_report.py CLAUDE.md
git commit -m "feat(report): coleta oauth_findings.json + doc fase P9.6 (P1)"
```

---

## Task 12: Verificação final (suíte completa + lint + smoke dry-run)

**Files:** nenhum (gate de qualidade)

- [ ] **Step 1: Suíte Python completa + compile de tudo**

Run:
```bash
cd ~/Stiglitz && python3 -m pytest tests/test_oauth_audit.py tests/test_bola.py tests/test_criticality.py -v && \
python3 -m py_compile stiglitz_report.py lib/oauth_audit.py lib/vuln_catalog.py
```
Expected: todos PASS; compile sem erro. (Roda os testes vizinhos para garantir que o catálogo não quebrou nada.)

- [ ] **Step 2: Lint bash**

Run: `cd ~/Stiglitz && bash -n stiglitz.sh && shellcheck --severity=warning stiglitz.sh | head -20`
Expected: sem erro de sintaxe; sem novos warnings.

- [ ] **Step 3: Smoke do gating (sanidade manual sem rede)**

Run:
```bash
cd ~/Stiglitz && python3 -c "
import sys; sys.path.insert(0, 'lib'); import oauth_audit, tempfile, os, json
d = tempfile.mkdtemp()
wk = json.dumps({'authorization_endpoint':'https://target.com/authorize','response_types_supported':['code','token'],'code_challenge_methods_supported':[]})
sent=[]
res = oauth_audit.run(d, active=True, profile='production', well_known_text=wk, zap_text='', client_id='a', authorize_url='https://target.com/authorize', target='https://target.com', send_fn=lambda p:(sent.append(p) or (302,'https://oauth-probe.invalid/cb','')))
assert sent==[], 'production deveria ser dry-run'
assert res['summary']['dry_run'] is True
print('OK: production=dry-run, passivo=%d achados' % res['summary']['passive'])
"
```
Expected: `OK: production=dry-run, passivo=2 achados` (implicit flow + pkce_missing).

- [ ] **Step 4: Self-review do plano vs. spec** (manual, sem commit)

Confirmar cobertura: redirect_uri (Task 4 HTTP + Task 7 ativo) · PKCE missing/downgrade (Task 4 + 7) · state/nonce (Task 4) · implicit (Task 4) · gating opt-in/production (Task 8) · 6 classes (Task 1) · report+doc (Task 11). Sem lacunas.

- [ ] **Step 5: Commit final (se houver ajustes pendentes) e resumo**

```bash
cd ~/Stiglitz && git status -sb && git log --oneline -12
```
Expected: working tree limpa; ~11 commits da feature na branch `feat/oauth-redirect-pkce`.

---

## Notas de execução

- **Branch:** já estamos em `feat/oauth-redirect-pkce` (a spec foi commitada nela). Todos os commits desta feature vão para essa branch. **Não** fazer push nem merge sem o usuário pedir.
- **Política do repo:** nenhum domínio real de cliente em código/teste — só `target.com` / `oauth-probe.invalid`. Resultados (`oauth_findings.json`) ficam no `OUTDIR` gitignored.
- **Reuso confirmado:** `bola.parse_zap_messages`, `fingerprint.fingerprint`, `vuln_catalog.CATALOG` — assinaturas verificadas em 2026-06-08.

# Suporte a Proxy HTTP/SOCKS (stiglitz.sh) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rotear por um proxy HTTP/SOCKS configurável (`--proxy`/`STIGLITZ_PROXY`) todo o tráfego do `stiglitz.sh` que toca o alvo, sem nunca deixar uma ferramenta-alvo rodar direto (anti-vazamento de atribuição).

**Architecture:** Um helper Python puro `lib/netproxy.py` provê openers urllib proxiados (HTTP via stdlib, SOCKS via PySocks; sem PySocks → `ProxyUnavailable` que o chamador trata como falha de rede, nunca direto). No `stiglitz.sh`, arrays bash (`_PROXY_GO`/`_PROXY_CURL`/`_PROXY_TESTSSL`/`_ZAP_PROXY_CFG`) injetam o flag certo só nas invocações que tocam o alvo; nmap pula+avisa; subfinder/cve_enrich/notificações/ZAP-API ficam diretos.

**Tech Stack:** Python 3 stdlib (`urllib.request`), PySocks (opcional, p/ SOCKS), bash, pytest, shellcheck.

---

### Task 1: `lib/netproxy.py` + testes

**Files:**
- Create: `lib/netproxy.py`
- Test: `tests/test_netproxy.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_netproxy.py
import os, sys
import urllib.request
import urllib.error
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
import netproxy as N


def test_proxy_url_reads_env(monkeypatch):
    monkeypatch.delenv("STIGLITZ_PROXY", raising=False)
    assert N.proxy_url() == ""
    monkeypatch.setenv("STIGLITZ_PROXY", "http://127.0.0.1:8080")
    assert N.proxy_url() == "http://127.0.0.1:8080"


def test_no_proxy_has_no_proxyhandler(monkeypatch):
    monkeypatch.delenv("STIGLITZ_PROXY", raising=False)
    assert N._proxy_handlers() == []


def test_http_proxy_builds_proxyhandler(monkeypatch):
    monkeypatch.setenv("STIGLITZ_PROXY", "http://127.0.0.1:8080")
    handlers = N._proxy_handlers()
    ph = [h for h in handlers if isinstance(h, urllib.request.ProxyHandler)]
    assert ph, "esperado um ProxyHandler"
    assert ph[0].proxies.get("https") == "http://127.0.0.1:8080"


def test_proxy_unavailable_is_urlerror():
    assert issubclass(N.ProxyUnavailable, urllib.error.URLError)


def test_socks_never_yields_direct_opener(monkeypatch):
    # Propriedade anti-vazamento: SOCKS ou produz um handler de proxy, ou levanta
    # ProxyUnavailable — NUNCA retorna [] (que seria conexão direta).
    monkeypatch.setenv("STIGLITZ_PROXY", "socks5h://127.0.0.1:9050")
    try:
        handlers = N._proxy_handlers()
        assert handlers, "SOCKS não pode resultar em opener direto (lista vazia)"
        assert not isinstance(handlers[0], urllib.request.ProxyHandler)
    except N.ProxyUnavailable:
        pass  # PySocks ausente — aceitável (chamador pula)


def test_make_opener_with_ssl_context_has_https_handler(monkeypatch):
    import ssl
    monkeypatch.delenv("STIGLITZ_PROXY", raising=False)
    ctx = ssl.create_default_context()
    opener = N.make_opener(ssl_context=ctx)
    assert any(isinstance(h, urllib.request.HTTPSHandler) for h in opener.handlers)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_netproxy.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'netproxy'`

- [ ] **Step 3: Write minimal implementation**

```python
#!/usr/bin/env python3
"""
netproxy.py — opener urllib com proxy opt-in (item 2 fintech), só p/ tráfego do alvo.

Lê STIGLITZ_PROXY (http(s):// ou socks5(h)://). Sem proxy → opener default (idêntico
ao comportamento atual). HTTP/HTTPS via ProxyHandler (stdlib). SOCKS via PySocks; se
PySocks ausente, levanta ProxyUnavailable — o chamador pula+avisa (NUNCA cai p/ direto),
preservando a garantia anti-vazamento. Módulos de terceiros (cve_enrich) NÃO usam isto.

Console em PT-BR.
"""
import os
import sys
import socket
import urllib.request
import urllib.error


class ProxyUnavailable(urllib.error.URLError):
    """Proxy configurado mas não pôde ser construído (ex.: SOCKS sem PySocks).

    Subclasse de URLError p/ ser capturada pelo tratamento de rede já existente nos
    módulos (degrada como falha de rede; nunca envia direto)."""


def proxy_url():
    """URL do proxy (STIGLITZ_PROXY) ou '' se não configurado."""
    return os.environ.get("STIGLITZ_PROXY", "").strip()


_WARNED = {"socks": False}


def _warn_once_socks(reason):
    if not _WARNED["socks"]:
        _WARNED["socks"] = True
        print(f"  [!] proxy SOCKS indisponível ({reason}) — sondagem pulada "
              f"(sem fallback direto, p/ não vazar atribuição)", file=sys.stderr)


def _proxy_handlers(ssl_context=None):
    """Handlers de proxy p/ o opener. [] se sem proxy. Levanta ProxyUnavailable se
    SOCKS sem PySocks (o chamador pula; nunca conexão direta)."""
    url = proxy_url()
    if not url:
        return []
    if url.startswith(("http://", "https://")):
        return [urllib.request.ProxyHandler({"http": url, "https": url})]
    if url.startswith(("socks5://", "socks5h://")):
        try:
            import socks  # PySocks
            from sockshandler import SocksiPyHandler
        except ImportError:
            _warn_once_socks("PySocks não instalado")
            raise ProxyUnavailable("SOCKS requer PySocks (pip install PySocks)")
        host, _, port = url.split("://", 1)[1].partition(":")
        kw = {"rdns": url.startswith("socks5h://")}
        if ssl_context is not None:
            kw["context"] = ssl_context
        return [SocksiPyHandler(socks.PROXY_TYPE_SOCKS5, host, int(port or 1080), **kw)]
    return []  # esquema desconhecido — a validação no stiglitz.sh já barra


def make_opener(ssl_context=None):
    """OpenerDirector com proxy (se configurado) + ssl_context p/ HTTPS."""
    handlers = []
    if ssl_context is not None:
        handlers.append(urllib.request.HTTPSHandler(context=ssl_context))
    handlers.extend(_proxy_handlers(ssl_context=ssl_context))
    return urllib.request.build_opener(*handlers)


def build_opener(*extra_handlers, ssl_context=None):
    """build_opener incluindo os handlers de proxy. Para módulos com handlers próprios
    (ex.: bizlogic _ScopedRedirectHandler)."""
    handlers = list(extra_handlers)
    if ssl_context is not None:
        handlers.append(urllib.request.HTTPSHandler(context=ssl_context))
    handlers.extend(_proxy_handlers(ssl_context=ssl_context))
    return urllib.request.build_opener(*handlers)


def urlopen(req, timeout=socket._GLOBAL_DEFAULT_TIMEOUT, context=None):
    """Drop-in p/ urllib.request.urlopen roteado pelo proxy (se configurado).
    `context` = ssl context (mesma semântica do urlopen)."""
    return make_opener(ssl_context=context).open(req, timeout=timeout)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_netproxy.py -q`
Expected: PASS (6 passed)

- [ ] **Step 5: Commit**

```bash
git add lib/netproxy.py tests/test_netproxy.py
git commit -m "feat(netproxy): opener urllib com proxy opt-in (http/socks), anti-vazamento"
```

---

### Task 2: `stiglitz.sh` — flag `--proxy`, validação, export e arrays

**Files:**
- Modify: `stiglitz.sh` (defaults ~L289-291, parser ~L296-307, e bloco novo de proxy após o parse)

- [ ] **Step 1: Add the default**

Encontre (≈ L289-291):

```bash
OAUTH_ACTIVE=0     # Probes ativos OAuth/OIDC (P9.6) — opt-in via --oauth-active
BIZLOGIC_MUTATE=0  # opt-in p/ testes mutantes de lógica de negócio (P9.7)
REPRO_RAW=0        # bloco de repro sem sanitização (uso interno) — opt-in via --repro-raw
```

Insira após a última linha:

```bash
STIGLITZ_PROXY="${STIGLITZ_PROXY:-}"  # proxy HTTP/SOCKS p/ tráfego do alvo — opt-in via --proxy
```

- [ ] **Step 2: Add the parser branch**

Encontre no `case`:

```bash
        --repro-raw)         REPRO_RAW=1 ;;
```

Insira após:

```bash
        --proxy)             STIGLITZ_PROXY="${_args[$((${_i}+1))]}" ;;
```

- [ ] **Step 3: Add validation + export + proxy arrays (new block)**

Encontre a linha (logo após o bloco do parser, onde o token A é resolvido):

```bash
# --token/-t é apelido de --token-a; AUTH_TOKEN (usado pela P9/nuclei) reflete o token A
[ -z "$TOKEN_A" ] && [ -n "$AUTH_TOKEN" ] && TOKEN_A="$AUTH_TOKEN"
```

Insira IMEDIATAMENTE APÓS esse `[ -z "$TOKEN_A" ]...`:

```bash

# ── Proxy (opt-in via --proxy / STIGLITZ_PROXY) ───────────────────────────────
# Aplicado SOMENTE a tráfego que toca o alvo. Controle (ZAP API localhost),
# enriquecimento (NVD/EPSS/KEV), notificações e subfinder (DNS passivo) vão direto.
if [ -n "$STIGLITZ_PROXY" ]; then
    if ! printf '%s' "$STIGLITZ_PROXY" | grep -qE '^(https?|socks5h?)://[^/]+'; then
        echo -e "  ${RED}[✗] --proxy inválido: '${STIGLITZ_PROXY}'. Use http(s)://host:porta ou socks5(h)://host:porta${NC}" >&2
        exit 1
    fi
    echo -e "  ${BLUE}[…] Modo proxy ativo: ${STIGLITZ_PROXY} (só tráfego do alvo; nmap será pulado)${NC}"
fi
export STIGLITZ_PROXY

# Arrays de proxy expandidos só nas invocações que tocam o alvo (vazios = sem proxy).
_PROXY_GO=();      [ -n "$STIGLITZ_PROXY" ] && _PROXY_GO=(-proxy "$STIGLITZ_PROXY")
_PROXY_CURL=();    [ -n "$STIGLITZ_PROXY" ] && _PROXY_CURL=(-x "$STIGLITZ_PROXY")
_PROXY_TESTSSL=(); [ -n "$STIGLITZ_PROXY" ] && _PROXY_TESTSSL=(--proxy "${STIGLITZ_PROXY#*://}")
```

- [ ] **Step 4: Verify syntax, lint and hooks**

Run:
```bash
bash -n stiglitz.sh && echo SYNTAX_OK
shellcheck --severity=warning stiglitz.sh && echo SHELLCHECK_OK
grep -n -- '--proxy)' stiglitz.sh
grep -n 'export STIGLITZ_PROXY' stiglitz.sh
grep -n '_PROXY_GO=(' stiglitz.sh
```
Expected: SYNTAX_OK, SHELLCHECK_OK; cada grep retorna ≥1 linha.

- [ ] **Step 5: Verify validation rejects malformed proxy**

Run:
```bash
bash stiglitz.sh example.com --proxy "not-a-url" --dry-run; echo "exit=$?"
```
Expected: imprime `[✗] --proxy inválido` e `exit=1`.

- [ ] **Step 6: Commit**

```bash
git add stiglitz.sh
git commit -m "feat(scan): flag --proxy + validação + STIGLITZ_PROXY export + arrays de proxy"
```

---

### Task 3: `stiglitz.sh` — proxy nas ferramentas Go + testssl

**Files:**
- Modify: `stiglitz.sh` (httpx ~L722, katana ~L779, nuclei ~L1062/L1089/L1114/L1145, testssl ~L935, ffuf ~L2283)

- [ ] **Step 1: httpx**

Encontre:

```bash
        httpx -silent -status-code -title -tech-detect -timeout 5 \
```

Substitua por:

```bash
        httpx -silent -status-code -title -tech-detect -timeout 5 \
              "${_PROXY_GO[@]}" \
```

- [ ] **Step 2: katana**

Encontre:

```bash
    katana -u "$TARGET" \
```

Substitua por:

```bash
    katana -u "$TARGET" \
        "${_PROXY_GO[@]}" \
```

- [ ] **Step 3: nuclei (4 sites)**

Em cada um dos quatro, adicione a expansão do array como continuação logo após a linha do `nuclei`:

(a) Encontre `            timeout "$NUCLEI_BATCH_TIMEOUT" nuclei -l "$_batch" \` → adicione a linha seguinte `                "${_PROXY_GO[@]}" \`.

(b) Encontre `    [ "${_nuclei_skip:-0}" = "1" ] || timeout "$NUCLEI_TIMEOUT" nuclei "${_nuclei_input[@]}" \` → adicione a linha seguinte `        "${_PROXY_GO[@]}" \`.

(c) Encontre `        timeout "$NUCLEI_TIMEOUT" nuclei -l "$_nuclei_list" \` → adicione a linha seguinte `            "${_PROXY_GO[@]}" \`.

(d) Encontre `            timeout "$NUCLEI_TIMEOUT" nuclei -l "$OUTDIR/raw/dast_urls.txt" -dast -silent \` → adicione a linha seguinte `                "${_PROXY_GO[@]}" \`.

- [ ] **Step 4: testssl**

Encontre:

```bash
    timeout "$TESTSSL_TIMEOUT" testssl --color 0 --warnings off --quiet \
```

Substitua por:

```bash
    timeout "$TESTSSL_TIMEOUT" testssl --color 0 --warnings off --quiet \
            "${_PROXY_TESTSSL[@]}" \
```

- [ ] **Step 5: ffuf**

Encontre:

```bash
        timeout 90 ffuf \
```

Substitua por:

```bash
        timeout 90 ffuf \
            "${_PROXY_GO[@]}" \
```

- [ ] **Step 6: Verify**

Run:
```bash
bash -n stiglitz.sh && echo SYNTAX_OK
shellcheck --severity=warning stiglitz.sh && echo SHELLCHECK_OK
grep -c '"${_PROXY_GO\[@\]}"' stiglitz.sh
grep -c '"${_PROXY_TESTSSL\[@\]}"' stiglitz.sh
```
Expected: SYNTAX_OK, SHELLCHECK_OK; `_PROXY_GO` aparece 7x (httpx + katana + 4×nuclei + ffuf); `_PROXY_TESTSSL` 1x.

- [ ] **Step 7: Commit**

```bash
git add stiglitz.sh
git commit -m "feat(scan): proxy nas ferramentas Go (httpx/nuclei/katana/ffuf) + testssl"
```

---

### Task 4: `stiglitz.sh` — curl ao alvo, nmap skip+warn, ZAP upstream

**Files:**
- Modify: `stiglitz.sh` (curls ~L1410/L1469/L1596/L1837, nmap ~L732-741, ZAP daemon ~L1346)

- [ ] **Step 1: curl ao alvo — OAuth check (L1410)**

Encontre:

```bash
            _oa_resp=$(curl -s --max-time 8 -w "%{http_code}" -o "$OUTDIR/raw/oa_check.tmp" "$_oa_url" 2>/dev/null)
```

Substitua por:

```bash
            _oa_resp=$(curl -s "${_PROXY_CURL[@]}" --max-time 8 -w "%{http_code}" -o "$OUTDIR/raw/oa_check.tmp" "$_oa_url" 2>/dev/null)
```

- [ ] **Step 2: curl ao alvo — GraphQL (L1469)**

Encontre:

```bash
            _gql_resp=$(curl -s -m 10 -X POST -H "Content-Type: application/json" \
```

Substitua por:

```bash
            _gql_resp=$(curl -s "${_PROXY_CURL[@]}" -m 10 -X POST -H "Content-Type: application/json" \
```

- [ ] **Step 3: curl ao alvo — robots (L1596)**

Encontre:

```bash
        _robots=$(curl -sk --max-time 5 "${TARGET%/}/robots.txt" 2>/dev/null)
```

Substitua por:

```bash
        _robots=$(curl -sk "${_PROXY_CURL[@]}" --max-time 5 "${TARGET%/}/robots.txt" 2>/dev/null)
```

- [ ] **Step 4: curl ao alvo — OAuth well-known (L1837)**

Encontre:

```bash
    if curl -s -S --max-time 15 "${TARGET}${_wkp}" -o "$_oauth_wk" 2>/dev/null \
```

Substitua por:

```bash
    if curl -s -S "${_PROXY_CURL[@]}" --max-time 15 "${TARGET}${_wkp}" -o "$_oauth_wk" 2>/dev/null \
```

- [ ] **Step 5: nmap — skip+warn em modo proxy**

Encontre:

```bash
if command -v nmap &>/dev/null; then
```

Substitua por:

```bash
if [ -n "$STIGLITZ_PROXY" ]; then
    echo -e "  ${YELLOW}[○] nmap pulado — sem suporte a proxy; rodá-lo direto vazaria atribuição ao alvo${NC}"
elif command -v nmap &>/dev/null; then
```

(O `else`/`fi` existentes do bloco nmap permanecem; agora há três ramos: proxy → pula; nmap presente → roda; nmap ausente → aviso atual.)

- [ ] **Step 6: ZAP — upstream proxy no daemon**

Encontre o comando do daemon:

```bash
        zaproxy -daemon \
                -host "$ZAP_HOST" \
                -port "$ZAP_PORT" \
                -dir  "$ZAP_HOME" \
                -config api.disablekey=true \
                > "$OUTDIR/raw/zap_daemon.log" 2>&1 &
```

Imediatamente ANTES do `zaproxy -daemon \`, adicione a construção do array de config:

```bash
        _ZAP_PROXY_CFG=()
        if [ -n "$STIGLITZ_PROXY" ]; then
            _zp_hostport="${STIGLITZ_PROXY#*://}"; _zp_host="${_zp_hostport%%:*}"; _zp_port="${_zp_hostport##*:}"
            if printf '%s' "$STIGLITZ_PROXY" | grep -q '^socks'; then
                _ZAP_PROXY_CFG=(-config "network.connection.socksProxy.host=${_zp_host}" \
                                -config "network.connection.socksProxy.port=${_zp_port}" \
                                -config "network.connection.socksProxy.enabled=true")
            else
                _ZAP_PROXY_CFG=(-config "network.connection.httpProxy.host=${_zp_host}" \
                                -config "network.connection.httpProxy.port=${_zp_port}" \
                                -config "network.connection.httpProxy.enabled=true")
            fi
        fi
```

E altere o comando do daemon para incluir o array (antes de `-config api.disablekey=true`):

```bash
        zaproxy -daemon \
                -host "$ZAP_HOST" \
                -port "$ZAP_PORT" \
                -dir  "$ZAP_HOME" \
                "${_ZAP_PROXY_CFG[@]}" \
                -config api.disablekey=true \
                > "$OUTDIR/raw/zap_daemon.log" 2>&1 &
```

- [ ] **Step 7: Verify**

Run:
```bash
bash -n stiglitz.sh && echo SYNTAX_OK
shellcheck --severity=warning stiglitz.sh && echo SHELLCHECK_OK
grep -c '"${_PROXY_CURL\[@\]}"' stiglitz.sh
grep -n 'nmap pulado' stiglitz.sh
grep -n '_ZAP_PROXY_CFG' stiglitz.sh
# Confirma que curls de localhost/notificação NÃO receberam proxy:
sed -n '1731p;1733p' stiglitz.sh | grep -c '_PROXY_CURL' | grep -qx 0 && echo "ZAP_API_LIMPO"
```
Expected: SYNTAX_OK, SHELLCHECK_OK; `_PROXY_CURL` aparece 4x; `nmap pulado` e `_ZAP_PROXY_CFG` presentes; `ZAP_API_LIMPO`.

- [ ] **Step 8: Commit**

```bash
git add stiglitz.sh
git commit -m "feat(scan): proxy em curl ao alvo + nmap pula em modo proxy + ZAP upstream proxy"
```

---

### Task 5: Módulos `lib/` — rotear urlopen pelo netproxy

**Files:**
- Modify: `lib/js_analysis.py`, `lib/secscan.py`, `lib/payment_page_monitor.py`, `lib/oauth_refresh.py`, `lib/pan_scanner.py`, `lib/ratelimit_check.py`, `lib/monitoring_check.py`, `lib/version_fingerprint.py`, `lib/oauth_audit.py`, `lib/parsers.py`

Edição uniforme em cada módulo: (a) adicionar `import netproxy` junto aos imports do topo; (b) trocar a chamada `urllib.request.urlopen(` por `netproxy.urlopen(` na(s) linha(s) indicada(s). `netproxy.urlopen` é drop-in (aceita `timeout=` e `context=`). Sem `STIGLITZ_PROXY` o comportamento é idêntico ao atual.

- [ ] **Step 1: Confirmar que `parsers.py:310` busca o ALVO**

Run: `sed -n '300,312p' lib/parsers.py`
Se o `urlopen` da L310 buscar um recurso do alvo (ex.: sitemap/robots/URL derivada do alvo), prossiga e inclua `parsers.py` na edição. Se for um recurso de terceiros/controle, NÃO edite `parsers.py` e registre isso no commit. (Esperado: é busca derivada do alvo em `extract_all_urls` → incluir.)

- [ ] **Step 2: Add `import netproxy` to each module**

Em cada arquivo da lista, adicione a linha `import netproxy` logo após os imports existentes do topo (os módulos já têm `lib/` no `sys.path` em todos os contextos de execução: rodados como `python3 lib/x.py` ou importados com `lib/` no path).

- [ ] **Step 3: Replace each urlopen call site**

Aplique as substituições exatas (linha → linha):

- `lib/js_analysis.py:26`: `        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:` → `        with netproxy.urlopen(req, timeout=timeout, context=ctx) as r:`
- `lib/js_analysis.py:207`: `        with urllib.request.urlopen(req, timeout=8, context=ctx) as r:` → `        with netproxy.urlopen(req, timeout=8, context=ctx) as r:`
- `lib/secscan.py:17`: `        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:` → `        with netproxy.urlopen(req, timeout=timeout, context=ctx) as r:`
- `lib/payment_page_monitor.py:57`: `    with urllib.request.urlopen(req, timeout=timeout, context=_ssl_ctx()) as r:` → `    with netproxy.urlopen(req, timeout=timeout, context=_ssl_ctx()) as r:`
- `lib/oauth_refresh.py:61`: `        with urllib.request.urlopen(req, timeout=timeout) as resp:` → `        with netproxy.urlopen(req, timeout=timeout) as resp:`
- `lib/pan_scanner.py:60`: `    with urllib.request.urlopen(req, timeout=timeout, context=ctx_ssl) as r:` → `    with netproxy.urlopen(req, timeout=timeout, context=ctx_ssl) as r:`
- `lib/ratelimit_check.py:26`: `            r = urllib.request.urlopen(req, timeout=8, context=ctx)` → `            r = netproxy.urlopen(req, timeout=8, context=ctx)`
- `lib/monitoring_check.py:29`: `            r = urllib.request.urlopen(req, timeout=10, context=ctx)` → `            r = netproxy.urlopen(req, timeout=10, context=ctx)`
- `lib/version_fingerprint.py:22`: `            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:` → `            with netproxy.urlopen(req, timeout=timeout, context=ctx) as r:`
- `lib/oauth_audit.py:321`: `            with urllib.request.urlopen(req, timeout=timeout) as resp:` → `            with netproxy.urlopen(req, timeout=timeout) as resp:`
- `lib/parsers.py:310` (se Step 1 confirmar alvo): `            resp = urllib.request.urlopen(req, timeout=10)` → `            resp = netproxy.urlopen(req, timeout=10)`

- [ ] **Step 4: Verify compile + no leftover bare urlopen in target modules**

Run:
```bash
python3 -m py_compile lib/js_analysis.py lib/secscan.py lib/payment_page_monitor.py \
  lib/oauth_refresh.py lib/pan_scanner.py lib/ratelimit_check.py lib/monitoring_check.py \
  lib/version_fingerprint.py lib/oauth_audit.py lib/parsers.py && echo COMPILE_OK
# cve_enrich permanece DIRETO (terceiros) — não deve usar netproxy:
grep -c "netproxy" lib/cve_enrich.py | grep -qx 0 && echo "CVE_ENRICH_DIRETO_OK"
# nenhum urllib.request.urlopen remanescente nos módulos-alvo:
grep -rn "urllib.request.urlopen" lib/js_analysis.py lib/secscan.py lib/payment_page_monitor.py \
  lib/oauth_refresh.py lib/pan_scanner.py lib/ratelimit_check.py lib/monitoring_check.py \
  lib/version_fingerprint.py lib/oauth_audit.py || echo "SEM_URLOPEN_NU_ALVO"
```
Expected: COMPILE_OK; CVE_ENRICH_DIRETO_OK; SEM_URLOPEN_NU_ALVO (parsers.py pode aparecer só se Step 1 decidiu não editar).

- [ ] **Step 5: Run the existing suite (sem regressão sem proxy)**

Run: `python3 -m pytest tests/ -q 2>&1 | tail -5`
Expected: tudo passa (sem `STIGLITZ_PROXY`, comportamento idêntico ao anterior).

- [ ] **Step 6: Commit**

```bash
git add lib/*.py
git commit -m "feat(lib): rotear urlopen dos módulos-alvo pelo netproxy (cve_enrich fica direto)"
```

---

### Task 6: `lib/bizlogic.py` — `_OPENER` proxiado (lazy, anti-vazamento)

**Files:**
- Modify: `lib/bizlogic.py:42` (`_OPENER`) e `lib/bizlogic.py:119` (uso)

- [ ] **Step 1: Add `import netproxy`**

Adicione `import netproxy` junto aos imports do topo de `lib/bizlogic.py`.

- [ ] **Step 2: Tornar o opener lazy + proxiado**

Encontre (L42):

```python
_OPENER = urllib.request.build_opener(_ScopedRedirectHandler())
```

Substitua por:

```python
_OPENER = None


def _get_opener():
    """Opener com o handler de redirect escopado + proxy (se STIGLITZ_PROXY).
    Lazy: se o proxy não puder ser construído (SOCKS sem PySocks), levanta
    ProxyUnavailable (URLError) — capturado no envio, sem fallback direto."""
    global _OPENER
    if _OPENER is None:
        _OPENER = netproxy.build_opener(_ScopedRedirectHandler())
    return _OPENER
```

- [ ] **Step 3: Usar o getter no envio**

Encontre (L119, agora deslocada):

```python
        with _OPENER.open(req, timeout=timeout) as resp:
```

Substitua por:

```python
        with _get_opener().open(req, timeout=timeout) as resp:
```

(O `try/except (urllib.error.URLError, OSError)` já existente em volta captura `ProxyUnavailable` → `Response(0, "__error__:...")`, ou seja, a requisição NÃO é enviada direto.)

- [ ] **Step 4: Verify**

Run:
```bash
python3 -m py_compile lib/bizlogic.py && echo COMPILE_OK
python3 -m pytest tests/test_bizlogic.py tests/test_bola.py -q 2>&1 | tail -5
```
Expected: COMPILE_OK; testes de bizlogic/bola passam (sem proxy, comportamento idêntico).

- [ ] **Step 5: Commit**

```bash
git add lib/bizlogic.py
git commit -m "feat(bizlogic): _OPENER lazy proxiado via netproxy (SOCKS sem PySocks → skip, não direto)"
```

---

### Task 7: Verificação anti-vazamento, validação final e docs

**Files:**
- Modify: `CLAUDE.md` (tabela de módulos + nota de proxy), `stiglitz.sh` (sem novas edições — só verificação)

- [ ] **Step 1: Anti-leak smoke (dry-run com proxy)**

Run:
```bash
bash stiglitz.sh example.com --proxy http://127.0.0.1:8080 --dry-run 2>&1 | grep -iE "proxy|nmap" | head
```
Expected: imprime a linha "Modo proxy ativo: http://127.0.0.1:8080 (só tráfego do alvo; nmap será pulado)". (O dry-run não executa ferramentas; confirma o gating de config.)

- [ ] **Step 2: Anti-leak grep audit (todas as ferramentas-alvo cobertas, controle limpo)**

Run:
```bash
echo "Go tools com proxy (esperado 7):"; grep -c '"${_PROXY_GO\[@\]}"' stiglitz.sh
echo "curl ao alvo com proxy (esperado 4):"; grep -c '"${_PROXY_CURL\[@\]}"' stiglitz.sh
echo "testssl com proxy (esperado 1):"; grep -c '"${_PROXY_TESTSSL\[@\]}"' stiglitz.sh
echo "ZAP API localhost SEM proxy (esperado 0):"; sed -n '/JSON\/core\/view\/alerts/p;/OTHER\/core\/other\/xmlreport/p' stiglitz.sh | grep -c '_PROXY_CURL'
echo "notificações SEM proxy (esperado 0):"; grep -E 'api.telegram.org|hooks.slack|/sendMessage' stiglitz.sh | grep -c '_PROXY_CURL'
```
Expected: 7, 4, 1, 0, 0.

- [ ] **Step 3: Full gates**

Run:
```bash
python3 -m py_compile lib/netproxy.py lib/*.py stiglitz_report.py && echo COMPILE_OK
python3 -m pytest tests/ -q 2>&1 | tail -5
bash -n stiglitz.sh && shellcheck --severity=warning stiglitz.sh && echo BASH_OK
```
Expected: COMPILE_OK; suíte verde; BASH_OK.

- [ ] **Step 4: Document in CLAUDE.md (lib table + proxy note)**

Na tabela de módulos `lib/`, após a linha `repro.py`, adicione:

```markdown
| `netproxy.py` | Opener urllib com proxy opt-in (item 2 fintech) — lê `STIGLITZ_PROXY` (http(s)/socks5(h)); HTTP via `ProxyHandler` (stdlib), SOCKS via PySocks; sem PySocks → `ProxyUnavailable` (o chamador pula, **nunca** conexão direta). Aplicado só a tráfego do alvo; `cve_enrich`/subfinder/notificações ficam diretos. Lógica pura |
```

E na seção da Fase 2 (ou no topo dos Scripts Principais), adicione uma nota curta:

```markdown
**Proxy (opt-in):** `bash stiglitz.sh <target> --proxy socks5h://127.0.0.1:9050` roteia **só o tráfego do alvo** (Go tools, testssl, curl-ao-alvo, ZAP upstream, módulos lib via `lib/netproxy.py`) pelo proxy. nmap é **pulado** em modo proxy (sem proxy nativo — rodá-lo direto vazaria atribuição). Controle (ZAP API localhost), enriquecimento (NVD/EPSS/KEV), notificações e subfinder (DNS passivo) vão **direto**. SOCKS requer PySocks; sem ele, módulos Python pulam a sondagem.
```

- [ ] **Step 5: Commit**

```bash
git add CLAUDE.md
git commit -m "docs: registra lib/netproxy.py + nota de uso do --proxy (item 2 fintech)"
```

---

## Self-Review

**Spec coverage:**
- Config `--proxy`/`STIGLITZ_PROXY` + validação + schemes → Task 2. ✓
- Classificação alvo/direto/skip → Tasks 3 (alvo Go/testssl), 4 (curl alvo, nmap skip, ZAP), 5 (lib alvo), com cve_enrich/subfinder/notificações intactos. ✓
- nmap pula+avisa → Task 4 Step 5. ✓
- `lib/netproxy.py` (http/socks/ProxyUnavailable/ssl_context) → Task 1. ✓
- Aplicação nos ~9 módulos + bizlogic opener → Tasks 5, 6. ✓
- Garantia anti-vazamento (socks→skip, nunca direto; controle limpo) → Task 1 (test_socks_never_yields_direct_opener), Task 6 (lazy), Task 7 Step 2 (grep audit). ✓
- Testes + gates → Task 1 + Task 7. ✓
- Idioma PT-BR console → strings dos avisos. ✓

**Placeholder scan:** o único item condicional é `parsers.py` (Task 5 Step 1) — é uma verificação explícita de 1 linha com resultado esperado declarado, não vagueza. Sem TBD/TODO.

**Type/consistency:** `netproxy.urlopen(req, timeout=, context=)`, `netproxy.make_opener(ssl_context=)`, `netproxy.build_opener(*handlers)`, `netproxy.ProxyUnavailable`, `netproxy._proxy_handlers()`, `netproxy.proxy_url()` — nomes idênticos entre Task 1 (definição), Tasks 5/6 (uso) e os testes. Arrays bash `_PROXY_GO`/`_PROXY_CURL`/`_PROXY_TESTSSL`/`_ZAP_PROXY_CFG` definidos na Task 2 e usados nas Tasks 3/4. ✓

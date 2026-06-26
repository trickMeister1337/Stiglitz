# mTLS client-cert Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Apresentar um certificado de cliente (mTLS) em todo o tráfego ao alvo do `stiglitz.sh` que suporte client-cert, para escanear alvos fintech (Open Banking BR / ICP-Brasil) que exigem mTLS.

**Architecture:** Novo módulo `lib/mtls.py` (lógica pura + CLI) é o ponto único de verdade: lê `STIGLITZ_MTLS_CERT`/`STIGLITZ_MTLS_KEY` (PEM, chave sem senha) e fornece um `ssl.SSLContext` (que o `netproxy` já aceita — cobre os 16 módulos urllib sem editar os call sites), args de `curl`, e validação fail-closed. O `stiglitz.sh` monta arrays bash por ferramenta (`_MTLS_CURL`/`_MTLS_NUCLEI`/`_MTLS_FFUF`) e injeta um PKCS#12 efêmero no ZAP. Espelha o padrão do `netproxy.py`.

**Tech Stack:** Python 3 stdlib (`ssl`, `os`), `cryptography` (só nos testes, p/ gerar par PEM), bash, ferramentas Go (nuclei/ffuf), ZAP REST API, `openssl` (PEM→P12 do ZAP).

## Global Constraints

- Console/operador em **PT-BR**; relatórios HTML em **EN** (esta feature não toca relatório).
- Opt-in: sem `STIGLITZ_MTLS_*` configurado → comportamento **byte-idêntico** ao atual.
- **Fail-closed**: mTLS configurado mas material inválido → `stiglitz.sh` aborta (`exit 1`).
- Módulos novos = **lógica pura + CLI primeiro** (padrão `bola.py`/`takeover.py`/`netproxy.py`).
- Nunca logar conteúdo do material sensível (só caminhos).
- Validação: `bash -n` + `shellcheck --severity=warning` limpos; `python3 -m py_compile` dos módulos; `python3 -m pytest tests/`.
- Módulos Python no `lib/` são importados nos testes via `sys.path.insert(0, .../lib)`.
- O `stiglitz.sh` chama módulos como `python3 "$SCRIPT_DIR/lib/<mod>.py"`.

---

### Task 1: `lib/mtls.py` — núcleo puro (config, validação, curl args, CLI)

**Files:**
- Create: `lib/mtls.py`
- Test: `tests/test_mtls.py`

**Interfaces:**
- Consumes: env `STIGLITZ_MTLS_CERT`, `STIGLITZ_MTLS_KEY`.
- Produces: `is_enabled() -> bool`, `cert_path() -> str`, `key_path() -> str`, `key_is_encrypted(path: str) -> bool`, `validate() -> None` (raises `MtlsConfigError`), `curl_cert_args() -> list[str]`, exceção `MtlsConfigError`, CLI `mtls.py <check|curl-args>`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_mtls.py
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
import mtls as M
import pytest


@pytest.fixture(autouse=True)
def _clear_env(monkeypatch):
    monkeypatch.delenv("STIGLITZ_MTLS_CERT", raising=False)
    monkeypatch.delenv("STIGLITZ_MTLS_KEY", raising=False)


def _write(p, text):
    p.write_text(text, encoding="utf-8")
    return str(p)


def test_disabled_by_default():
    assert M.is_enabled() is False
    assert M.curl_cert_args() == []
    assert M.validate() is None  # no-op


def test_enabled_when_both_set(monkeypatch, tmp_path):
    c = _write(tmp_path / "c.pem", "cert"); k = _write(tmp_path / "k.pem", "key")
    monkeypatch.setenv("STIGLITZ_MTLS_CERT", c)
    monkeypatch.setenv("STIGLITZ_MTLS_KEY", k)
    assert M.is_enabled() is True
    assert M.curl_cert_args() == ["--cert", c, "--key", k]


def test_partial_config_is_error(monkeypatch, tmp_path):
    monkeypatch.setenv("STIGLITZ_MTLS_CERT", _write(tmp_path / "c.pem", "cert"))
    assert M.is_enabled() is False
    with pytest.raises(M.MtlsConfigError):
        M.validate()


def test_validate_missing_file(monkeypatch, tmp_path):
    monkeypatch.setenv("STIGLITZ_MTLS_CERT", str(tmp_path / "nope.pem"))
    monkeypatch.setenv("STIGLITZ_MTLS_KEY", _write(tmp_path / "k.pem", "key"))
    with pytest.raises(M.MtlsConfigError):
        M.validate()


def test_validate_rejects_encrypted_key(monkeypatch, tmp_path):
    c = _write(tmp_path / "c.pem", "-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----")
    k = _write(tmp_path / "k.pem", "-----BEGIN ENCRYPTED PRIVATE KEY-----\nx\n-----END ENCRYPTED PRIVATE KEY-----")
    monkeypatch.setenv("STIGLITZ_MTLS_CERT", c)
    monkeypatch.setenv("STIGLITZ_MTLS_KEY", k)
    with pytest.raises(M.MtlsConfigError):
        M.validate()


def test_key_is_encrypted_detects_traditional_pem(tmp_path):
    k = _write(tmp_path / "k.pem", "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\n")
    assert M.key_is_encrypted(k) is True
    plain = _write(tmp_path / "p.pem", "-----BEGIN PRIVATE KEY-----\nMIIxxx\n")
    assert M.key_is_encrypted(plain) is False
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_mtls.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'mtls'`

- [ ] **Step 3: Write minimal implementation**

```python
#!/usr/bin/env python3
"""
mtls.py — client-cert mTLS opt-in (especialização fintech), só p/ tráfego do alvo.

Lê STIGLITZ_MTLS_CERT / STIGLITZ_MTLS_KEY (PEM; chave SEM senha). Sem config → no-op
(idêntico ao comportamento atual). Fornece o ssl_context que o netproxy injeta nos
openers urllib, args de curl, e validação fail-closed consumida pelo stiglitz.sh.

Console em PT-BR.
"""
import os
import ssl
import sys


class MtlsConfigError(Exception):
    """mTLS configurado mas material inválido (ausente/ilegível/parcial/chave com senha).
    Erro de configuração — deve ABORTAR o scan, não ser tratado como falha de rede."""


def cert_path():
    return os.environ.get("STIGLITZ_MTLS_CERT", "").strip()


def key_path():
    return os.environ.get("STIGLITZ_MTLS_KEY", "").strip()


def is_enabled():
    """True só quando cert E key estão setados."""
    return bool(cert_path() and key_path())


def key_is_encrypted(path):
    """True se o PEM da chave indica criptografia (chave com senha). Cobre PKCS#8
    ('BEGIN ENCRYPTED PRIVATE KEY') e PEM tradicional ('Proc-Type: 4,ENCRYPTED')."""
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return "ENCRYPTED" in fh.read(4096)
    except OSError:
        return False


def validate():
    """Valida o material mTLS. No-op se nem cert nem key setados. Levanta
    MtlsConfigError (PT-BR, com instrução openssl) se inválido."""
    c, k = cert_path(), key_path()
    if not c and not k:
        return
    if not (c and k):
        raise MtlsConfigError(
            "mTLS parcial: defina STIGLITZ_MTLS_CERT E STIGLITZ_MTLS_KEY (ambos os arquivos PEM)")
    for label, p in (("cert", c), ("key", k)):
        if not os.path.isfile(p):
            raise MtlsConfigError(f"mTLS {label} nao encontrado: {p!r}")
        if not os.access(p, os.R_OK):
            raise MtlsConfigError(f"mTLS {label} sem permissao de leitura: {p!r}")
    if key_is_encrypted(k):
        raise MtlsConfigError(
            f"mTLS key protegida por senha: {k!r}. Decripte antes "
            "(ex.: openssl rsa -in enc.pem -out plain.pem) — senha nao suportada nesta entrega")


def curl_cert_args():
    """Args de client-cert p/ curl via subprocess: [] sem mTLS, senão --cert/--key."""
    if not is_enabled():
        return []
    return ["--cert", cert_path(), "--key", key_path()]


def main(argv):
    if len(argv) < 2:
        print("uso: mtls.py <check|curl-args>", file=sys.stderr)
        return 2
    cmd = argv[1]
    if cmd == "check":
        try:
            validate()
        except MtlsConfigError as e:
            print(str(e), file=sys.stderr)
            return 1
        print(f"mTLS ok: cert={cert_path()} key={key_path()}" if is_enabled()
              else "mTLS desativado")
        return 0
    if cmd == "curl-args":
        print(" ".join(curl_cert_args()))
        return 0
    print(f"comando desconhecido: {cmd}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m pytest tests/test_mtls.py -v && python3 -m py_compile lib/mtls.py`
Expected: PASS (6 testes)

- [ ] **Step 5: Commit**

```bash
git add lib/mtls.py tests/test_mtls.py
git commit -m "feat(mtls): núcleo puro do client-cert (config/validação/curl args + CLI)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 2: `lib/mtls.py` — `client_ssl_context()`

**Files:**
- Modify: `lib/mtls.py` (adicionar `client_ssl_context`)
- Test: `tests/test_mtls.py` (adicionar casos)

**Interfaces:**
- Consumes: `is_enabled()`, `cert_path()`, `key_path()` (Task 1).
- Produces: `client_ssl_context() -> ssl.SSLContext | None`.

- [ ] **Step 1: Write the failing test**

```python
# adicionar ao fim de tests/test_mtls.py
import ssl as _ssl


def _gen_pair(tmp_path):
    """Par cert+key PEM auto-assinado p/ teste (cryptography)."""
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    import datetime
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test")])
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime(2020, 1, 1))
            .not_valid_after(datetime.datetime(2030, 1, 1))
            .sign(key, hashes.SHA256()))
    cpath = tmp_path / "cert.pem"; kpath = tmp_path / "key.pem"
    cpath.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    kpath.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()))
    return str(cpath), str(kpath)


def test_client_ssl_context_none_when_disabled():
    assert M.client_ssl_context() is None


def test_client_ssl_context_loads_pair(monkeypatch, tmp_path):
    c, k = _gen_pair(tmp_path)
    monkeypatch.setenv("STIGLITZ_MTLS_CERT", c)
    monkeypatch.setenv("STIGLITZ_MTLS_KEY", k)
    ctx = M.client_ssl_context()
    assert isinstance(ctx, _ssl.SSLContext)
    assert ctx.verify_mode == _ssl.CERT_NONE  # servidor segue skip-verify (scanner)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_mtls.py::test_client_ssl_context_loads_pair -v`
Expected: FAIL with `AttributeError: module 'mtls' has no attribute 'client_ssl_context'`

- [ ] **Step 3: Write minimal implementation**

```python
# adicionar a lib/mtls.py (após curl_cert_args)
def client_ssl_context():
    """ssl.SSLContext com o client-cert carregado, ou None se não-enabled. Consumido
    pelo netproxy.make_opener(ssl_context=...). Verificação do servidor desligada
    (skip-verify, alinhado ao resto do scanner): mTLS cobre só a identidade do cliente."""
    if not is_enabled():
        return None
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.load_cert_chain(certfile=cert_path(), keyfile=key_path())
    return ctx
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m pytest tests/test_mtls.py -v && python3 -m py_compile lib/mtls.py`
Expected: PASS (8 testes)

- [ ] **Step 5: Commit**

```bash
git add lib/mtls.py tests/test_mtls.py
git commit -m "feat(mtls): client_ssl_context() p/ injeção no netproxy

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 3: Integração `netproxy.py` — gancho do ssl_context

**Files:**
- Modify: `lib/netproxy.py` (`make_opener`, `build_opener`, helper `_mtls_context`)
- Test: `tests/test_netproxy_mtls.py`

**Interfaces:**
- Consumes: `mtls.client_ssl_context()` (Task 2).
- Produces: `make_opener`/`build_opener`/`urlopen` passam a usar o context do mtls quando `ssl_context is None`. Sem mudança de assinatura.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_netproxy_mtls.py
import os, sys, ssl
import urllib.request
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
import netproxy


def _https_handlers(opener):
    return [h for h in opener.handlers if isinstance(h, urllib.request.HTTPSHandler)]


def test_make_opener_uses_mtls_context_when_none(monkeypatch):
    called = []
    ctx = ssl.create_default_context()
    monkeypatch.setattr(netproxy, "_mtls_context", lambda: (called.append(1) or ctx))
    monkeypatch.delenv("STIGLITZ_PROXY", raising=False)
    opener = netproxy.make_opener()
    assert called, "make_opener deve consultar o mtls quando ssl_context é None"
    hs = _https_handlers(opener)
    assert hs and getattr(hs[0], "_context", None) is ctx


def test_make_opener_keeps_explicit_context(monkeypatch):
    called = []
    monkeypatch.setattr(netproxy, "_mtls_context", lambda: called.append(1))
    explicit = ssl.create_default_context()
    monkeypatch.delenv("STIGLITZ_PROXY", raising=False)
    netproxy.make_opener(ssl_context=explicit)
    assert not called, "context explícito não deve ser sobrescrito pelo mtls"


def test_mtls_context_returns_none_without_module(monkeypatch):
    # sem env mTLS, client_ssl_context retorna None → opener sem HTTPSHandler custom
    monkeypatch.delenv("STIGLITZ_MTLS_CERT", raising=False)
    monkeypatch.delenv("STIGLITZ_MTLS_KEY", raising=False)
    monkeypatch.delenv("STIGLITZ_PROXY", raising=False)
    assert netproxy._mtls_context() is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_netproxy_mtls.py -v`
Expected: FAIL with `AttributeError: module 'netproxy' has no attribute '_mtls_context'`

- [ ] **Step 3: Write minimal implementation**

Adicionar o helper a `lib/netproxy.py` (após os imports, antes de `proxy_url`):

```python
def _mtls_context():
    """ssl_context com client-cert do lib/mtls, ou None. Import tardio p/ não criar
    ciclo e manter o netproxy standalone quando o mtls não está presente."""
    try:
        import mtls
    except ImportError:
        return None
    return mtls.client_ssl_context()
```

Em `make_opener`, trocar a primeira linha do corpo:

```python
def make_opener(ssl_context=None):
    """..."""
    if ssl_context is None:
        ssl_context = _mtls_context()
    proxy_handlers = _proxy_handlers(ssl_context=ssl_context)
    handlers = []
    if ssl_context is not None and not _is_socks():
        handlers.append(urllib.request.HTTPSHandler(context=ssl_context))
    handlers.extend(proxy_handlers)
    return urllib.request.build_opener(*handlers)
```

Em `build_opener`, idem — adicionar no topo do corpo:

```python
def build_opener(*extra_handlers, ssl_context=None):
    """..."""
    if ssl_context is None:
        ssl_context = _mtls_context()
    proxy_handlers = _proxy_handlers(ssl_context=ssl_context)
    handlers = list(extra_handlers)
    if ssl_context is not None and not _is_socks():
        handlers.append(urllib.request.HTTPSHandler(context=ssl_context))
    handlers.extend(proxy_handlers)
    return urllib.request.build_opener(*handlers)
```

(`urlopen` chama `make_opener(ssl_context=context)`; quando `context` é None herda o mtls — sem alteração.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m pytest tests/test_netproxy_mtls.py -v && python3 -m py_compile lib/netproxy.py`
Expected: PASS (3 testes)

- [ ] **Step 5: Commit**

```bash
git add lib/netproxy.py tests/test_netproxy_mtls.py
git commit -m "feat(mtls): netproxy injeta o client-cert nos 16 módulos urllib (0 edição nos call sites)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 4: Integração curl subprocess (5 módulos) + guard de paridade

**Files:**
- Modify: `lib/bola.py`, `lib/cors_check.py`, `lib/oauth_audit.py`, `lib/poc_validator.py`, `lib/security_headers.py`
- Test: `tests/test_mtls_curl_parity.py`

**Interfaces:**
- Consumes: `mtls.curl_cert_args()` (Task 1).
- Produces: todo comando curl que já passa `*netproxy.curl_proxy_args()` passa também `*mtls.curl_cert_args()`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_mtls_curl_parity.py
import os, glob
LIBDIR = os.path.join(os.path.dirname(__file__), "..", "lib")


def test_every_curl_proxy_site_also_passes_mtls_args():
    offenders = []
    for f in glob.glob(os.path.join(LIBDIR, "*.py")):
        if os.path.basename(f) in ("netproxy.py", "mtls.py"):
            continue
        src = open(f, encoding="utf-8").read()
        if "curl_proxy_args()" in src and "mtls.curl_cert_args()" not in src:
            offenders.append(os.path.basename(f))
    assert not offenders, f"módulos com curl proxy mas sem mtls: {offenders}"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_mtls_curl_parity.py -v`
Expected: FAIL — `offenders` lista os 5 módulos.

- [ ] **Step 3: Edit the 5 modules**

Em cada um dos 5 arquivos: garantir `import mtls` (ao lado do `import netproxy`) e inserir `*mtls.curl_cert_args(),` imediatamente após `*netproxy.curl_proxy_args(),` na construção do comando curl.

Exemplo (`lib/security_headers.py`, linha ~110):

```python
        r = subprocess.run(
            ["curl", *netproxy.curl_proxy_args(), *mtls.curl_cert_args(), "-sk","-I","--max-time","10","-L",url],
```

Exemplo (`lib/bola.py`, linha ~219):

```python
    cmd = ["curl", *netproxy.curl_proxy_args(), *mtls.curl_cert_args(), "-s", "-S", "--max-time", "15", "-X", method,
```

Para `cors_check.py`, `oauth_audit.py`, `poc_validator.py`: localizar com `grep -n "curl_proxy_args" lib/<mod>.py`, aplicar o mesmo padrão (inserir `*mtls.curl_cert_args(),` após `*netproxy.curl_proxy_args(),`), e adicionar `import mtls` se ausente (`grep -q "import mtls" lib/<mod>.py || ` adicione junto ao `import netproxy`).

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m pytest tests/test_mtls_curl_parity.py -v && python3 -m py_compile lib/bola.py lib/cors_check.py lib/oauth_audit.py lib/poc_validator.py lib/security_headers.py`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add lib/bola.py lib/cors_check.py lib/oauth_audit.py lib/poc_validator.py lib/security_headers.py tests/test_mtls_curl_parity.py
git commit -m "feat(mtls): client-cert nos 5 módulos curl subprocess + guard de paridade

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 5: `stiglitz.sh` — parse CLI, validação fail-closed, arrays

**Files:**
- Modify: `stiglitz.sh` (default de env ~L297; parse de args ~L314; bloco de validação/arrays após o bloco do `--proxy` ~L335)

**Interfaces:**
- Consumes: `python3 "$SCRIPT_DIR/lib/mtls.py" check`.
- Produces: env `STIGLITZ_MTLS_CERT`/`STIGLITZ_MTLS_KEY` exportadas; arrays bash `_MTLS_CURL`, `_MTLS_NUCLEI`, `_MTLS_FFUF` (vazios sem mTLS).

- [ ] **Step 1: Adicionar defaults de env**

Após a linha `STIGLITZ_PROXY="${STIGLITZ_PROXY:-}"  # proxy HTTP/SOCKS...`:

```bash
STIGLITZ_MTLS_CERT="${STIGLITZ_MTLS_CERT:-}"  # client-cert PEM — opt-in via --mtls-cert
STIGLITZ_MTLS_KEY="${STIGLITZ_MTLS_KEY:-}"    # client-key  PEM (sem senha) — via --mtls-key
```

- [ ] **Step 2: Adicionar parse das flags**

Após a linha `--proxy)             STIGLITZ_PROXY="${_args[$((${_i}+1))]}" ;;`:

```bash
        --mtls-cert)         STIGLITZ_MTLS_CERT="${_args[$((${_i}+1))]}" ;;
        --mtls-key)          STIGLITZ_MTLS_KEY="${_args[$((${_i}+1))]}" ;;
```

- [ ] **Step 3: Adicionar bloco de validação + arrays**

Imediatamente após a linha `_PROXY_TESTSSL=(); [ -n "$STIGLITZ_PROXY" ] && _PROXY_TESTSSL=(--proxy "${STIGLITZ_PROXY#*://}")`:

```bash

# ── mTLS client-cert (opt-in via --mtls-cert/--mtls-key) ──────────────────────
# Fail-closed: configurado mas inválido → aborta (≠ proxy, que pula): sem o cert o
# handshake TLS falha e o scan ficaria cego, reportando "0 findings" enganoso.
export STIGLITZ_MTLS_CERT STIGLITZ_MTLS_KEY
_MTLS_CURL=(); _MTLS_NUCLEI=(); _MTLS_FFUF=()
if [ -n "$STIGLITZ_MTLS_CERT" ] || [ -n "$STIGLITZ_MTLS_KEY" ]; then
    if ! _mtls_msg="$(python3 "$SCRIPT_DIR/lib/mtls.py" check 2>&1)"; then
        echo -e "  ${RED}[✗] ${_mtls_msg}${NC}" >&2
        exit 1
    fi
    echo -e "  ${BLUE}[…] mTLS ativo: cert=${STIGLITZ_MTLS_CERT} key=${STIGLITZ_MTLS_KEY} (só tráfego do alvo)${NC}"
    _MTLS_CURL=(--cert "$STIGLITZ_MTLS_CERT" --key "$STIGLITZ_MTLS_KEY")
    _MTLS_NUCLEI=(-client-cert "$STIGLITZ_MTLS_CERT" -client-key "$STIGLITZ_MTLS_KEY")
    _MTLS_FFUF=(-cc "$STIGLITZ_MTLS_CERT" -ck "$STIGLITZ_MTLS_KEY")
fi
```

- [ ] **Step 4: Validar**

Run:
```bash
bash -n stiglitz.sh && shellcheck --severity=warning stiglitz.sh
# fail-closed: só um arg → aborta
STIGLITZ_MTLS_CERT=/x bash stiglitz.sh example.com --dry-run; echo "exit=$?"   # espera exit=1
```
Expected: `bash -n` ok; shellcheck sem warning novo; o run aborta com `exit=1` e mensagem mTLS.

- [ ] **Step 5: Commit**

```bash
git add stiglitz.sh
git commit -m "feat(mtls): --mtls-cert/--mtls-key no stiglitz.sh (parse, fail-closed, arrays)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 6: `stiglitz.sh` — espalhar arrays nas invocações nuclei/ffuf + avisos httpx/katana

**Files:**
- Modify: `stiglitz.sh` (invocações nuclei: âncoras `"${_PROXY_GO[@]}"` que pertencem a `nuclei`; ffuf ~L2554; mensagens httpx ~L788 / katana ~L877)

**Interfaces:**
- Consumes: `_MTLS_NUCLEI`, `_MTLS_FFUF` (Task 5).
- Produces: nuclei e ffuf apresentam client-cert; httpx/katana avisam que não suportam.

- [ ] **Step 1: Adicionar `_MTLS_NUCLEI` a cada invocação nuclei**

Para CADA invocação `nuclei` que contém a linha `"${_PROXY_GO[@]}" \` (cinco ocorrências: Fase 4 batch, single, info, templates, dast), inserir logo abaixo:

```bash
                "${_MTLS_NUCLEI[@]}" \
```

Localizar com: `grep -n '"\${_PROXY_GO\[@\]}"' stiglitz.sh` e, para cada uma cujo bloco acima contém `nuclei`, adicionar a linha `_MTLS_NUCLEI`. **NÃO** adicionar nas ocorrências de `httpx` (L~788) nem `katana` (L~877) — não suportam client-cert. Manter a indentação da linha `_PROXY_GO` vizinha.

Para a invocação nuclei da Fase 10.5 (`nuclei -l "$_info_urls"`, ~L2761), que não tem `_PROXY_GO`, adicionar `"${_MTLS_NUCLEI[@]}" \` logo após a linha do `nuclei -l "$_info_urls" \`.

- [ ] **Step 2: Adicionar `_MTLS_FFUF` ao ffuf**

Na invocação `timeout 90 ffuf \` (~L2554), adicionar logo após a primeira linha:

```bash
        "${_MTLS_FFUF[@]}" \
```

- [ ] **Step 3: Avisos para httpx/katana**

Imediatamente antes da invocação `httpx -silent -json ...` (~L788), adicionar:

```bash
        [ ${#_MTLS_NUCLEI[@]} -gt 0 ] && echo -e "  ${YELLOW}[○] httpx não suporta client-cert — mapeamento de superfície limitado sob mTLS (ZAP/nuclei cobrem a superfície autenticada)${NC}"
```

Imediatamente antes da invocação `katana -u "$TARGET" \` (~L877), adicionar:

```bash
    [ ${#_MTLS_NUCLEI[@]} -gt 0 ] && echo -e "  ${YELLOW}[○] katana não suporta client-cert — crawl limitado sob mTLS${NC}"
```

- [ ] **Step 4: Validar**

Run:
```bash
bash -n stiglitz.sh && shellcheck --severity=warning stiglitz.sh
# paridade: toda invocação nuclei com _PROXY_GO deve ter _MTLS_NUCLEI logo abaixo
grep -n -A1 '"\${_PROXY_GO\[@\]}"' stiglitz.sh | grep -c "_MTLS_NUCLEI"
```
Expected: `bash -n` ok; shellcheck limpo; o contador de paridade ≥ 5.

- [ ] **Step 5: Commit**

```bash
git add stiglitz.sh
git commit -m "feat(mtls): nuclei/ffuf apresentam client-cert; httpx/katana avisam limitação

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 7: `stiglitz.sh` — injeção do client-cert no ZAP (P12 efêmero)

**Files:**
- Modify: `stiglitz.sh` (helper `zap_setup_client_cert` perto de `zap_inject_auth_headers` ~L191; chamada antes do spider ~L1755; cleanup do P12 em `cleanup()` ~L255)

**Interfaces:**
- Consumes: env `STIGLITZ_MTLS_CERT`/`STIGLITZ_MTLS_KEY`, `zap_api_call`, `openssl`.
- Produces: ZAP usa o client-cert via PKCS#12 efêmero; arquivo apagado no cleanup.

- [ ] **Step 1: Adicionar o helper**

Após a função `zap_inject_auth_headers() { ... }` (localizar o `}` que a fecha, ~L230), adicionar:

```bash
# Client-cert mTLS no ZAP: ZAP só aceita PKCS#12. Gera um .p12 efêmero (sem senha) a
# partir do PEM e carrega via network addon. No-op sem mTLS. Não aborta (a validação
# fail-closed já rodou na entrada); aqui só avisa se o ZAP/openssl falhar.
ZAP_MTLS_P12=""
zap_setup_client_cert() {
    [ -n "$STIGLITZ_MTLS_CERT" ] && [ -n "$STIGLITZ_MTLS_KEY" ] || return 0
    command -v openssl >/dev/null 2>&1 || { echo -e "  ${YELLOW}[○] openssl ausente — client-cert no ZAP pulado${NC}"; return 0; }
    ZAP_MTLS_P12="$OUTDIR/raw/.zap_client.p12"
    if ! openssl pkcs12 -export -inkey "$STIGLITZ_MTLS_KEY" -in "$STIGLITZ_MTLS_CERT" \
            -out "$ZAP_MTLS_P12" -passout pass: >/dev/null 2>&1; then
        echo -e "  ${YELLOW}[○] falha ao gerar PKCS#12 p/ o ZAP — client-cert no ZAP pulado${NC}"
        rm -f "$ZAP_MTLS_P12"; ZAP_MTLS_P12=""; return 0
    fi
    chmod 600 "$ZAP_MTLS_P12" 2>/dev/null || true
    zap_api_call "network/action/addPkcs12ClientCertificate" \
        "filePath=${ZAP_MTLS_P12}&password=&index=0" >/dev/null 2>&1
    zap_api_call "network/action/setUseClientCertificate" "use=true" >/dev/null 2>&1
    echo -e "  ${GREEN}[✓] client-cert mTLS carregado no ZAP${NC}"
}
```

- [ ] **Step 2: Chamar antes do spider**

Imediatamente após a linha `zap_inject_auth_headers` (~L1755):

```bash
        # ── Client-cert mTLS no ZAP (antes do spider) ──
        zap_setup_client_cert
```

- [ ] **Step 3: Limpar o P12 no cleanup**

Dentro da função `cleanup()` (~L255), adicionar:

```bash
    [ -n "$ZAP_MTLS_P12" ] && rm -f "$ZAP_MTLS_P12" 2>/dev/null
```

- [ ] **Step 4: Validar**

Run: `bash -n stiglitz.sh && shellcheck --severity=warning stiglitz.sh`
Expected: `bash -n` ok; shellcheck sem warning novo (se `ZAP_MTLS_P12` disparar SC2154/SC2034, confirmar que é declarada no escopo do helper — está).

- [ ] **Step 5: Commit**

```bash
git add stiglitz.sh
git commit -m "feat(mtls): client-cert no ZAP via PKCS#12 efêmero (gerado/usado/limpo)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 8: Documentação (CLAUDE.md, ROADMAP, CHANGELOG)

**Files:**
- Modify: `CLAUDE.md` (Fase 9 + tabela de módulos `lib/` + nota de proxy); `docs/ROADMAP.md` (mover mTLS p/ feito); `CHANGELOG.md` (entrada Unreleased)

**Interfaces:** nenhuma (docs).

- [ ] **Step 1: CLAUDE.md — tabela de módulos**

Na tabela de módulos `lib/`, adicionar uma linha (após `netproxy.py`):

```markdown
| `mtls.py` | Client-cert mTLS opt-in (`STIGLITZ_MTLS_CERT`/`_KEY`, PEM sem senha) p/ alvos Open Banking BR/ICP-Brasil. `client_ssl_context()` (injetado pelo `netproxy` nos 16 módulos urllib, 0 edição nos call sites), `curl_cert_args()`, `validate()` fail-closed. nuclei (`-client-cert`)/ffuf (`-cc`/`-ck`) recebem o par; ZAP via PKCS#12 efêmero; httpx/katana não suportam (limitação). Lógica pura + CLI |
```

- [ ] **Step 2: CLAUDE.md — Fase 9 e nota de proxy**

Na descrição da **Fase 9**, após a frase sobre o replacer/auth, acrescentar:

```markdown
   - **mTLS client-cert (opt-in `--mtls-cert`/`--mtls-key`):** quando o alvo exige mutual TLS (Open Banking BR/ICP-Brasil), o par PEM (chave sem senha) é apresentado por curl/nuclei/ffuf e pelos módulos urllib (via `netproxy`); o ZAP recebe um PKCS#12 efêmero (gerado do PEM, sem senha, apagado no cleanup). Fail-closed: material inválido aborta o scan. httpx/katana não suportam client-cert — superfície coberta por ZAP spider + nuclei.
```

- [ ] **Step 3: docs/ROADMAP.md — mover mTLS para feito**

Na seção "Especialização fintech / API-heavy", trocar a linha `- ⏳ **mTLS client-cert**: ausente...` por:

```markdown
- ✅ **mTLS client-cert** (`lib/mtls.py`, opt-in `--mtls-cert`/`--mtls-key`): par PEM (sem senha) apresentado por curl/nuclei/ffuf + módulos urllib (via `netproxy.client_ssl_context`) + ZAP (PKCS#12 efêmero). Fail-closed; coexiste com `--proxy`. httpx/katana sem suporte (limitação documentada)
```

- [ ] **Step 4: CHANGELOG.md — entrada Unreleased**

No topo da seção `## Unreleased`, adicionar:

```markdown
- **mTLS client-cert (`lib/mtls.py`, opt-in `--mtls-cert`/`--mtls-key`)** — apresenta um certificado de cliente PEM (chave sem senha) no handshake TLS de alvos que exigem mutual TLS (Open Banking BR / ICP-Brasil). Cobertura do `stiglitz.sh` inteiro: o `netproxy` injeta o `ssl_context` nos 16 módulos urllib sem editar os call sites; curl subprocess + nuclei (`-client-cert`/`-client-key`) + ffuf (`-cc`/`-ck`) recebem o par; o ZAP recebe um PKCS#12 efêmero (gerado do PEM, sem senha, em temp `600`, apagado no cleanup). Fail-closed (material inválido/ausente/chave com senha → aborta), coexiste com `--proxy`. httpx/katana não têm flag de client-cert → limitados sob mTLS (superfície coberta por ZAP spider + nuclei). +11 testes (`tests/test_mtls.py`, `tests/test_netproxy_mtls.py`, `tests/test_mtls_curl_parity.py`).
```

- [ ] **Step 5: Validar e commit**

Run: `python3 -m pytest tests/ -q`
Expected: toda a suíte passa (inclui os novos testes).

```bash
git add CLAUDE.md docs/ROADMAP.md CHANGELOG.md
git commit -m "docs(mtls): CLAUDE.md (Fase 9 + módulo) + ROADMAP (feito) + CHANGELOG

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
git push origin main
```

---

## Self-Review

**1. Spec coverage:**
- R1 (apresentar par PEM) → Tasks 1-7. R2 (opt-in env/CLI) → Tasks 1, 5. R3 (cobertura inteira) → Tasks 3 (urllib), 4 (curl), 6 (nuclei/ffuf), 7 (ZAP). R4 (fail-closed) → Tasks 1 (`validate`), 5 (abort). R5 (coexistir com proxy) → Task 3 (gancho só quando `ssl_context is None`; proxy intacto). R6 (não vazar) → Task 5 (loga caminhos). §6 ZAP P12 → Task 7. §7 fail-closed → Task 5. §8 testes → Tasks 1-4. §9 limitações → Tasks 6, 8. Sem gaps.

**2. Placeholder scan:** sem TBD/TODO. As edições do `stiglitz.sh` usam âncoras textuais (números de linha mudam entre tasks) com o código exato a inserir. Task 4 dá o padrão + dois exemplos concretos e instrui localizar os 3 restantes por grep (mesma edição mecânica).

**3. Type consistency:** `is_enabled`/`cert_path`/`key_path`/`key_is_encrypted`/`validate`/`curl_cert_args`/`client_ssl_context`/`MtlsConfigError` consistentes entre Tasks 1-2 e consumo em 3-4. `_mtls_context` (netproxy) e `client_ssl_context` (mtls) batem. Arrays `_MTLS_CURL`/`_MTLS_NUCLEI`/`_MTLS_FFUF` definidos na Task 5 e consumidos na Task 6. `ZAP_MTLS_P12` definido e limpo na Task 7.

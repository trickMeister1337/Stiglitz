# Auto-aquisição de token OAuth2 (client_credentials) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Adquirir automaticamente um `access_token` OAuth2 via grant `client_credentials` no startup do `stiglitz.sh` e injetá-lo no pipeline inteiro (`AUTH_TOKEN`/`TOKEN_A`), sem JWT manual.

**Architecture:** Renomear `lib/oauth_refresh.py` → `lib/oauth_token.py`, unificando aquisição + refresh sobre um helper compartilhado `_request_token`. O bash chama a CLI `acquire` no startup; o token herda `--proxy` e o client-cert mTLS via `netproxy.urlopen`. Falha é fail-closed por padrão.

**Tech Stack:** Python 3 stdlib (`urllib`, `json`, `base64`), `netproxy` (proxy+mTLS), bash, pytest + unittest.

## Global Constraints

- Mensagens de console/operador em **PT-BR com acentuação plena** (nunca substituir caracteres acentuados). Relatórios HTML em inglês (não se aplica aqui).
- Credenciais OAuth são **env-only** (`STIGLITZ_OAUTH_*`) — nenhuma flag CLI nova para credenciais; nunca logar `client_secret` nem o `access_token`.
- Namespace env: `STIGLITZ_OAUTH_TOKEN_URL`, `_CLIENT_ID`, `_CLIENT_SECRET` (existem); `_SCOPE`, `_AUDIENCE`, `_AUTH_STYLE` (`post` default | `basic`), `_REQUIRED` (`1` default fail-closed | `0` fail-open) — novas; `_REFRESH_TOKEN`, `_GRANT_TYPE` (refresh, inalteradas).
- Todo POST ao token endpoint passa por `netproxy.urlopen` (herda proxy + mTLS). Não usar `urllib.request.urlopen` direto.
- Fluxo git: commit direto na `main`, sem PR. Mensagem de commit termina com `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.
- Validação antes de cada commit: `python3 -m pytest tests/ -q` verde + (para mudanças no `.sh`) `bash -n stiglitz.sh` e `shellcheck --severity=warning stiglitz.sh`.

---

## File Structure

- `lib/oauth_token.py` — **renomeado** de `oauth_refresh.py`. Gestão de access_token: `_request_token` (helper), `acquire_access_token` (client_credentials), `refresh_access_token` (refatorado), `is_acquire_enabled`, `is_enabled`, `apply_to_curl`, CLI `acquire`.
- `lib/poc_validator.py` — modificado: import `oauth_refresh` → `oauth_token`; `_refresh_oauth_safe` escolhe refresh ou re-aquisição.
- `stiglitz.sh` — modificado: bloco de aquisição no startup (~linha 385).
- `tests/test_oauth_token.py` — **novo**: unit de `acquire_access_token`/`is_acquire_enabled`/CLI.
- `tests/test_lib.py` — modificado: imports `oauth_refresh` → `oauth_token` (8 ocorrências, classe `TestOAuthRefresh`).
- `tests/test_oauth_acquire_stiglitz.py` — **novo**: guard source-level do bloco bash.
- `tests/test_poc_validator_oauth.py` — **novo**: `_refresh_oauth_safe` escolhe refresh/acquire.
- `docs/ROADMAP.md`, `CLAUDE.md`, `CHANGELOG.md` — modificados (Task 6).

---

### Task 1: Rename + helper compartilhado `_request_token` (refactor protegido por regressão)

Renomeia o módulo e extrai o POST comum, mantendo o comportamento do refresh idêntico. Os testes existentes (`TestOAuthRefresh` em `tests/test_lib.py`) são a rede de regressão.

**Files:**
- Rename: `lib/oauth_refresh.py` → `lib/oauth_token.py` (via `git mv`)
- Modify: `lib/oauth_token.py` (adiciona `_request_token`, refatora `refresh_access_token`, adiciona `import sys`)
- Modify: `lib/poc_validator.py:47` (`import oauth_refresh as _oauth` → `import oauth_token as _oauth`)
- Modify: `tests/test_lib.py` (todas as `import oauth_refresh as oa` → `import oauth_token as oa`)

**Interfaces:**
- Consumes: `netproxy.urlopen` (já usado).
- Produces: `_request_token(data: dict, headers: dict|None = None, timeout: int = 15) -> dict` (dict da resposta JSON; levanta `OAuthError`). `refresh_access_token(timeout=15) -> str` (inalterado externamente).

- [ ] **Step 1: Renomear o arquivo preservando história**

```bash
git mv lib/oauth_refresh.py lib/oauth_token.py
```

- [ ] **Step 2: Atualizar os imports dos consumidores**

Em `lib/poc_validator.py` linha 47, trocar:
```python
    import oauth_refresh as _oauth
```
por:
```python
    import oauth_token as _oauth
```

Em `tests/test_lib.py`, trocar **todas** as ocorrências de `import oauth_refresh as oa` por `import oauth_token as oa` (linhas 772, 776, 786, 791, 799, 806, 812). Atualizar a docstring da classe na linha 761 de `"""oauth_refresh.py — ..."""` para `"""oauth_token.py — refresh + aquisição de access tokens."""`.

- [ ] **Step 3: Rodar a suíte para provar que o rename não quebrou nada**

Run: `python3 -m pytest tests/test_lib.py -k OAuth -q`
Expected: PASS (os testes de refresh continuam verdes após o rename + atualização de imports).

- [ ] **Step 4: Extrair o helper `_request_token` e refatorar `refresh_access_token`**

Adicionar o helper (após a classe `OAuthError`):
```python
def _request_token(data, headers=None, timeout=15):
    """POST x-www-form-urlencoded ao token endpoint via netproxy (herda proxy+mTLS).

    Devolve o dict da resposta JSON. Levanta OAuthError em rede/HTTP/parse.
    """
    token_url = os.environ.get("STIGLITZ_OAUTH_TOKEN_URL", "").strip()
    if not token_url:
        raise OAuthError("STIGLITZ_OAUTH_TOKEN_URL não configurado")
    hdrs = {"Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json"}
    if headers:
        hdrs.update(headers)
    body = urllib.parse.urlencode(data).encode("utf-8")
    req = urllib.request.Request(token_url, data=body, method="POST", headers=hdrs)
    try:
        with netproxy.urlopen(req, timeout=timeout) as resp:
            payload = resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        raise OAuthError(f"HTTP {e.code} do token endpoint: {e.reason}") from None
    except (urllib.error.URLError, OSError) as e:
        raise OAuthError(f"falha de rede: {e}") from None
    try:
        return json.loads(payload)
    except json.JSONDecodeError as e:
        raise OAuthError(f"resposta não-JSON do token endpoint: {e}") from None
```

Substituir o corpo de `refresh_access_token` (da montagem do `req` até o `return token`) para delegar ao helper:
```python
def refresh_access_token(timeout=15):
    """Chama o endpoint de refresh e retorna o novo access_token (str)."""
    token_url = os.environ.get("STIGLITZ_OAUTH_TOKEN_URL", "").strip()
    refresh   = os.environ.get("STIGLITZ_OAUTH_REFRESH_TOKEN", "").strip()
    if not token_url or not refresh:
        raise OAuthError("STIGLITZ_OAUTH_TOKEN_URL / STIGLITZ_OAUTH_REFRESH_TOKEN não configurados")

    grant   = os.environ.get("STIGLITZ_OAUTH_GRANT_TYPE", "refresh_token")
    client  = os.environ.get("STIGLITZ_OAUTH_CLIENT_ID", "").strip()
    secret  = os.environ.get("STIGLITZ_OAUTH_CLIENT_SECRET", "").strip()

    data = {"grant_type": grant, "refresh_token": refresh}
    if client: data["client_id"]     = client
    if secret: data["client_secret"] = secret

    parsed = _request_token(data, timeout=timeout)
    token = parsed.get("access_token")
    if not token or not isinstance(token, str):
        raise OAuthError(f"resposta sem access_token (chaves: {sorted(parsed)})")
    return token
```

- [ ] **Step 5: Rodar a suíte de refresh para confirmar comportamento idêntico**

Run: `python3 -m pytest tests/test_lib.py -k OAuth -q`
Expected: PASS (inclusive `test_refresh_uses_mock_endpoint`, que exercita o caminho de rede agora via `_request_token`).

- [ ] **Step 6: Commit**

```bash
git add lib/oauth_token.py lib/poc_validator.py tests/test_lib.py
git commit -m "$(cat <<'MSG'
refactor(oauth): rename oauth_refresh.py → oauth_token.py + helper _request_token

git mv preserva história. refresh_access_token agora delega a _request_token
(POST compartilhado via netproxy). Atualiza imports em poc_validator e test_lib.
Comportamento do refresh inalterado (TestOAuthRefresh verde).

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
MSG
)"
```

---

### Task 2: `acquire_access_token()` + `is_acquire_enabled()`

Grant `client_credentials`, com auth-style `post` (default) ou `basic`, scope/audience opcionais.

**Files:**
- Create: `tests/test_oauth_token.py`
- Modify: `lib/oauth_token.py` (adiciona `acquire_access_token`, `is_acquire_enabled`)

**Interfaces:**
- Consumes: `_request_token` (Task 1).
- Produces: `acquire_access_token(timeout: int = 15) -> str`; `is_acquire_enabled() -> bool`.

- [ ] **Step 1: Escrever os testes que falham**

Criar `tests/test_oauth_token.py`:
```python
# tests/test_oauth_token.py
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
import oauth_token as oa
import pytest


@pytest.fixture(autouse=True)
def _clear_env(monkeypatch):
    for k in ("STIGLITZ_OAUTH_TOKEN_URL", "STIGLITZ_OAUTH_CLIENT_ID",
              "STIGLITZ_OAUTH_CLIENT_SECRET", "STIGLITZ_OAUTH_SCOPE",
              "STIGLITZ_OAUTH_AUDIENCE", "STIGLITZ_OAUTH_AUTH_STYLE",
              "STIGLITZ_OAUTH_REFRESH_TOKEN"):
        monkeypatch.delenv(k, raising=False)


def _set_creds(monkeypatch):
    monkeypatch.setenv("STIGLITZ_OAUTH_TOKEN_URL", "https://idp/token")
    monkeypatch.setenv("STIGLITZ_OAUTH_CLIENT_ID", "cid")
    monkeypatch.setenv("STIGLITZ_OAUTH_CLIENT_SECRET", "csecret")


def test_is_acquire_enabled_matrix(monkeypatch):
    assert oa.is_acquire_enabled() is False
    _set_creds(monkeypatch)
    assert oa.is_acquire_enabled() is True
    monkeypatch.delenv("STIGLITZ_OAUTH_CLIENT_SECRET")
    assert oa.is_acquire_enabled() is False


def test_acquire_post_style_body(monkeypatch):
    captured = {}
    def fake_request(data, headers=None, timeout=15):
        captured["data"] = data
        captured["headers"] = headers
        return {"access_token": "AT-1"}
    monkeypatch.setattr(oa, "_request_token", fake_request)
    _set_creds(monkeypatch)
    tok = oa.acquire_access_token()
    assert tok == "AT-1"
    assert captured["data"]["grant_type"] == "client_credentials"
    assert captured["data"]["client_id"] == "cid"
    assert captured["data"]["client_secret"] == "csecret"
    assert captured["headers"] is None


def test_acquire_basic_style_header(monkeypatch):
    captured = {}
    def fake_request(data, headers=None, timeout=15):
        captured["data"] = data
        captured["headers"] = headers
        return {"access_token": "AT-2"}
    monkeypatch.setattr(oa, "_request_token", fake_request)
    _set_creds(monkeypatch)
    monkeypatch.setenv("STIGLITZ_OAUTH_AUTH_STYLE", "basic")
    tok = oa.acquire_access_token()
    assert tok == "AT-2"
    # credenciais vão no header Basic, não no corpo
    assert "client_secret" not in captured["data"]
    assert captured["headers"]["Authorization"].startswith("Basic ")
    import base64
    assert base64.b64decode(captured["headers"]["Authorization"].split()[1]).decode() == "cid:csecret"


def test_acquire_includes_scope_and_audience(monkeypatch):
    captured = {}
    monkeypatch.setattr(oa, "_request_token",
                        lambda data, headers=None, timeout=15: captured.update(data) or {"access_token": "AT"})
    _set_creds(monkeypatch)
    monkeypatch.setenv("STIGLITZ_OAUTH_SCOPE", "accounts payments")
    monkeypatch.setenv("STIGLITZ_OAUTH_AUDIENCE", "https://api/aud")
    oa.acquire_access_token()
    assert captured["scope"] == "accounts payments"
    assert captured["audience"] == "https://api/aud"


def test_acquire_raises_without_config(monkeypatch):
    with pytest.raises(oa.OAuthError):
        oa.acquire_access_token()


def test_acquire_raises_without_access_token(monkeypatch):
    monkeypatch.setattr(oa, "_request_token",
                        lambda data, headers=None, timeout=15: {"token_type": "Bearer"})
    _set_creds(monkeypatch)
    with pytest.raises(oa.OAuthError):
        oa.acquire_access_token()
```

- [ ] **Step 2: Rodar para verificar a falha**

Run: `python3 -m pytest tests/test_oauth_token.py -q`
Expected: FAIL com `AttributeError: module 'oauth_token' has no attribute 'acquire_access_token'` (e `is_acquire_enabled`).

- [ ] **Step 3: Implementar**

Em `lib/oauth_token.py`, adicionar após `is_enabled()`:
```python
def is_acquire_enabled():
    """True se TOKEN_URL + CLIENT_ID + CLIENT_SECRET estão no env (grant client_credentials)."""
    return bool(os.environ.get("STIGLITZ_OAUTH_TOKEN_URL")
                and os.environ.get("STIGLITZ_OAUTH_CLIENT_ID")
                and os.environ.get("STIGLITZ_OAUTH_CLIENT_SECRET"))


def acquire_access_token(timeout=15):
    """Adquire um access_token via grant client_credentials. Retorna a str do token.

    Auth style via STIGLITZ_OAUTH_AUTH_STYLE: 'post' (default, id/secret no corpo)
    ou 'basic' (header Authorization: Basic). scope/audience opcionais.
    Raises OAuthError em config ausente ou resposta sem access_token.
    """
    token_url = os.environ.get("STIGLITZ_OAUTH_TOKEN_URL", "").strip()
    client    = os.environ.get("STIGLITZ_OAUTH_CLIENT_ID", "").strip()
    secret    = os.environ.get("STIGLITZ_OAUTH_CLIENT_SECRET", "").strip()
    if not token_url or not client or not secret:
        raise OAuthError(
            "STIGLITZ_OAUTH_TOKEN_URL / STIGLITZ_OAUTH_CLIENT_ID / "
            "STIGLITZ_OAUTH_CLIENT_SECRET não configurados")

    scope    = os.environ.get("STIGLITZ_OAUTH_SCOPE", "").strip()
    audience = os.environ.get("STIGLITZ_OAUTH_AUDIENCE", "").strip()
    style    = os.environ.get("STIGLITZ_OAUTH_AUTH_STYLE", "post").strip().lower()

    data = {"grant_type": "client_credentials"}
    if scope:    data["scope"]    = scope
    if audience: data["audience"] = audience

    headers = None
    if style == "basic":
        import base64
        cred = base64.b64encode(f"{client}:{secret}".encode("utf-8")).decode("ascii")
        headers = {"Authorization": f"Basic {cred}"}
    else:  # 'post' (default)
        data["client_id"]     = client
        data["client_secret"] = secret

    parsed = _request_token(data, headers=headers, timeout=timeout)
    token = parsed.get("access_token")
    if not token or not isinstance(token, str):
        raise OAuthError(f"resposta sem access_token (chaves: {sorted(parsed)})")
    return token
```

- [ ] **Step 4: Rodar para verificar verde**

Run: `python3 -m pytest tests/test_oauth_token.py -q`
Expected: PASS (6 testes), output pristino.

- [ ] **Step 5: Commit**

```bash
git add lib/oauth_token.py tests/test_oauth_token.py
git commit -m "$(cat <<'MSG'
feat(oauth): acquire_access_token (client_credentials) + is_acquire_enabled

Grant client_credentials com auth-style post (default) ou basic; scope/audience
opcionais. POST via _request_token (herda proxy+mTLS). Fail-closed: config
incompleta ou resposta sem access_token → OAuthError.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
MSG
)"
```

---

### Task 3: CLI `acquire`

O bash chama `python3 lib/oauth_token.py acquire` no startup; imprime só o token.

**Files:**
- Modify: `lib/oauth_token.py` (adiciona `main(argv)` + bloco `__main__`)
- Modify: `tests/test_oauth_token.py` (testes da CLI)

**Interfaces:**
- Consumes: `acquire_access_token` (Task 2).
- Produces: `main(argv: list[str]) -> int` (0 sucesso, 1 OAuthError, 2 uso inválido). Subcomando `acquire` imprime o token em stdout.

- [ ] **Step 1: Escrever os testes que falham**

Adicionar ao final de `tests/test_oauth_token.py`:
```python
def test_cli_acquire_prints_only_token(monkeypatch, capsys):
    monkeypatch.setattr(oa, "acquire_access_token", lambda timeout=15: "AT-CLI")
    rc = oa.main(["acquire"])
    out = capsys.readouterr()
    assert rc == 0
    assert out.out.strip() == "AT-CLI"
    assert out.err == ""


def test_cli_acquire_error_to_stderr(monkeypatch, capsys):
    def boom(timeout=15):
        raise oa.OAuthError("HTTP 401 do token endpoint: Unauthorized")
    monkeypatch.setattr(oa, "acquire_access_token", boom)
    rc = oa.main(["acquire"])
    out = capsys.readouterr()
    assert rc == 1
    assert out.out == ""
    assert "401" in out.err


def test_cli_unknown_subcommand(capsys):
    rc = oa.main(["bogus"])
    assert rc == 2
```

- [ ] **Step 2: Rodar para verificar a falha**

Run: `python3 -m pytest tests/test_oauth_token.py -k cli -q`
Expected: FAIL com `AttributeError: module 'oauth_token' has no attribute 'main'`.

- [ ] **Step 3: Implementar**

Adicionar `import sys` ao bloco de imports no topo de `lib/oauth_token.py` (junto de `import json`, `import os`). Adicionar ao final de `lib/oauth_token.py`:
```python
def main(argv):
    """CLI: `acquire` imprime o access_token em stdout (exit 0); erro → stderr (exit 1)."""
    if argv and argv[0] == "acquire":
        try:
            print(acquire_access_token())
            return 0
        except OAuthError as e:
            print(f"erro: {e}", file=sys.stderr)
            return 1
    print("uso: oauth_token.py acquire", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
```

- [ ] **Step 4: Rodar para verificar verde**

Run: `python3 -m pytest tests/test_oauth_token.py -q`
Expected: PASS (9 testes no total), output pristino.

- [ ] **Step 5: Verificar a CLI manualmente (sem config → exit 1, sem stdout)**

Run: `python3 lib/oauth_token.py acquire; echo "rc=$?"`
Expected: linha `erro: STIGLITZ_OAUTH_TOKEN_URL ...` no stderr, nada no stdout, `rc=1`.

- [ ] **Step 6: Commit**

```bash
git add lib/oauth_token.py tests/test_oauth_token.py
git commit -m "$(cat <<'MSG'
feat(oauth): CLI `acquire` — imprime o access_token p/ o bash capturar

main(argv): acquire → token em stdout (exit 0); OAuthError → stderr (exit 1);
subcomando desconhecido → exit 2. Token nunca vai p/ stderr nem log.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
MSG
)"
```

---

### Task 4: Renovação na Fase 5 escolhe refresh OU re-aquisição

`_refresh_oauth_safe` no `poc_validator` passa a renovar via `client_credentials` quando não há refresh token.

**Files:**
- Modify: `lib/poc_validator.py:53-64` (`_refresh_oauth_safe`)
- Create: `tests/test_poc_validator_oauth.py`

**Interfaces:**
- Consumes: `_oauth.is_enabled`, `_oauth.is_acquire_enabled`, `_oauth.refresh_access_token`, `_oauth.acquire_access_token`.
- Produces: comportamento de `_refresh_oauth_safe` (escolhe o caminho disponível).

- [ ] **Step 1: Escrever os testes que falham**

Criar `tests/test_poc_validator_oauth.py`:
```python
# tests/test_poc_validator_oauth.py
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
import poc_validator as pv


def _reset():
    pv._OAUTH_TOKEN = ""


def test_refresh_path_chosen_when_enabled(monkeypatch):
    _reset()
    monkeypatch.setattr(pv, "_OAUTH_AVAILABLE", True)
    monkeypatch.setattr(pv._oauth, "is_enabled", lambda: True)
    monkeypatch.setattr(pv._oauth, "is_acquire_enabled", lambda: True)
    monkeypatch.setattr(pv._oauth, "refresh_access_token", lambda: "R-TOK")
    monkeypatch.setattr(pv._oauth, "acquire_access_token", lambda: "A-TOK")
    assert pv._refresh_oauth_safe() == "R-TOK"


def test_acquire_path_chosen_when_only_acquire(monkeypatch):
    _reset()
    monkeypatch.setattr(pv, "_OAUTH_AVAILABLE", True)
    monkeypatch.setattr(pv._oauth, "is_enabled", lambda: False)
    monkeypatch.setattr(pv._oauth, "is_acquire_enabled", lambda: True)
    monkeypatch.setattr(pv._oauth, "acquire_access_token", lambda: "A-TOK")
    assert pv._refresh_oauth_safe() == "A-TOK"


def test_noop_when_neither(monkeypatch):
    _reset()
    monkeypatch.setattr(pv, "_OAUTH_AVAILABLE", True)
    monkeypatch.setattr(pv._oauth, "is_enabled", lambda: False)
    monkeypatch.setattr(pv._oauth, "is_acquire_enabled", lambda: False)
    assert pv._refresh_oauth_safe() == ""
```

- [ ] **Step 2: Rodar para verificar a falha**

Run: `python3 -m pytest tests/test_poc_validator_oauth.py -q`
Expected: FAIL — `test_acquire_path_chosen_when_only_acquire` falha (hoje `_refresh_oauth_safe` só chama refresh quando `is_enabled()`, retornando "" no caminho só-acquire).

- [ ] **Step 3: Implementar**

Substituir `_refresh_oauth_safe` em `lib/poc_validator.py` (linhas 53-64) por:
```python
def _refresh_oauth_safe():
    """Renova o token; em falha retorna "" e loga (não aborta o scan).

    Escolhe o caminho disponível: refresh_token se configurado, senão
    re-aquisição client_credentials. No-op se nenhum.
    """
    global _OAUTH_TOKEN
    if not _OAUTH_AVAILABLE:
        return ""
    try:
        if _oauth.is_enabled():
            _OAUTH_TOKEN = _oauth.refresh_access_token()
        elif _oauth.is_acquire_enabled():
            _OAUTH_TOKEN = _oauth.acquire_access_token()
        else:
            return ""
        print("  [OAuth] token atualizado")
        return _OAUTH_TOKEN
    except Exception as e:
        print(f"  [OAuth] renovação falhou: {e}")
        return ""
```

- [ ] **Step 4: Rodar para verificar verde**

Run: `python3 -m pytest tests/test_poc_validator_oauth.py -q`
Expected: PASS (3 testes).

- [ ] **Step 5: Commit**

```bash
git add lib/poc_validator.py tests/test_poc_validator_oauth.py
git commit -m "$(cat <<'MSG'
feat(oauth): Fase 5 renova on-401 via refresh OU re-aquisição

_refresh_oauth_safe escolhe refresh_access_token (se REFRESH_TOKEN) senão
acquire_access_token (se client_credentials). Cobre setups só-client_credentials,
que antes não renovavam (is_enabled False → no-op).

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
MSG
)"
```

---

### Task 5: Bloco de aquisição no startup do `stiglitz.sh`

**Files:**
- Modify: `stiglitz.sh` (após `[ -n "$TOKEN_A" ] && AUTH_TOKEN="$TOKEN_A"`, ~linha 385)
- Create: `tests/test_oauth_acquire_stiglitz.py`

**Interfaces:**
- Consumes: CLI `oauth_token.py acquire` (Task 3); env `STIGLITZ_OAUTH_*`.
- Produces: `AUTH_TOKEN`/`TOKEN_A` populados quando a aquisição tem sucesso.

- [ ] **Step 1: Escrever o guard source-level que falha**

Criar `tests/test_oauth_acquire_stiglitz.py`:
```python
# tests/test_oauth_acquire_stiglitz.py
"""Guard: o bloco de auto-aquisição OAuth2 no stiglitz.sh deve (a) só disparar
quando AUTH_TOKEN está vazio (token manual vence), (b) invocar a CLI acquire,
(c) respeitar STIGLITZ_OAUTH_REQUIRED (fail-closed)."""
import os

STIGLITZ_SH = os.path.join(os.path.dirname(__file__), "..", "stiglitz.sh")


def _src():
    with open(STIGLITZ_SH, encoding="utf-8") as fh:
        return fh.read()


def test_acquire_block_invokes_cli():
    assert 'oauth_token.py" acquire' in _src() or 'oauth_token.py acquire' in _src()


def test_acquire_block_guards_on_empty_auth_token():
    src = _src()
    guard = src.index('[ -z "$AUTH_TOKEN" ]')
    invoke = src.index("oauth_token.py")
    # o guard de AUTH_TOKEN vazio aparece antes da invocação da aquisição
    assert guard < invoke


def test_acquire_block_respects_required():
    assert "STIGLITZ_OAUTH_REQUIRED" in _src()
```

- [ ] **Step 2: Rodar para verificar a falha**

Run: `python3 -m pytest tests/test_oauth_acquire_stiglitz.py -q`
Expected: FAIL (o bloco ainda não existe; `oauth_token.py` não aparece no `.sh`).

- [ ] **Step 3: Implementar o bloco no `stiglitz.sh`**

Localizar (~linha 385):
```bash
[ -n "$TOKEN_A" ] && AUTH_TOKEN="$TOKEN_A"
```
Inserir **logo após** essa linha:
```bash

# ── Auto-aquisição de token OAuth2 (client_credentials) ──────────────────────
# Só dispara quando NENHUM token manual foi passado e as 3 credenciais de client
# estão no env. --token manual sempre vence. Falha: fail-closed (default) ou
# best-effort deslogado sob STIGLITZ_OAUTH_REQUIRED=0.
if [ -z "$AUTH_TOKEN" ] && [ -n "${STIGLITZ_OAUTH_TOKEN_URL:-}" ] \
   && [ -n "${STIGLITZ_OAUTH_CLIENT_ID:-}" ] && [ -n "${STIGLITZ_OAUTH_CLIENT_SECRET:-}" ]; then
    _oauth_err=$(mktemp)
    if _oauth_tok=$(python3 "$SCRIPT_DIR/lib/oauth_token.py" acquire 2>"$_oauth_err") \
            && [ -n "$_oauth_tok" ]; then
        AUTH_TOKEN="$_oauth_tok"; TOKEN_A="$_oauth_tok"
        echo -e "  ${GREEN}[✓] token OAuth2 adquirido (client_credentials)${NC}"
    elif [ "${STIGLITZ_OAUTH_REQUIRED:-1}" = "0" ]; then
        echo -e "  ${YELLOW}[!] aquisição OAuth2 falhou ($(cat "$_oauth_err")) — scan seguirá DESLOGADO${NC}"
    else
        echo -e "  ${RED}[✗] aquisição OAuth2 falhou ($(cat "$_oauth_err")) — abortando (STIGLITZ_OAUTH_REQUIRED=0 p/ best-effort)${NC}"
        rm -f "$_oauth_err"; exit 1
    fi
    rm -f "$_oauth_err"
    unset _oauth_tok _oauth_err
fi
```

(Confirmar que `SCRIPT_DIR`, `GREEN`, `YELLOW`, `RED`, `NC` já estão definidos antes desse ponto — estão, são usados nas mensagens anteriores. `_oauth_tok` é capturado em variável e nunca ecoado.)

- [ ] **Step 4: Rodar o guard + sintaxe + lint**

Run: `python3 -m pytest tests/test_oauth_acquire_stiglitz.py -q`
Expected: PASS (3 testes).

Run: `bash -n stiglitz.sh && echo OK`
Expected: `OK`.

Run: `shellcheck --severity=warning stiglitz.sh`
Expected: sem saída (limpo). Se aparecer SC2155 (declare-and-assign) no `_oauth_err=$(mktemp)`, está em statement próprio (não `local`) — não deve disparar; se disparar, separar declaração/atribuição.

- [ ] **Step 5: Smoke — token manual vence (sem rede)**

Run:
```bash
STIGLITZ_OAUTH_TOKEN_URL=x STIGLITZ_OAUTH_CLIENT_ID=x STIGLITZ_OAUTH_CLIENT_SECRET=x \
  bash -c 'AUTH_TOKEN="manual"; [ -z "$AUTH_TOKEN" ] && echo ADQUIRIRIA || echo "manual vence"'
```
Expected: `manual vence` (valida a lógica do guard isoladamente).

- [ ] **Step 6: Commit**

```bash
git add stiglitz.sh tests/test_oauth_acquire_stiglitz.py
git commit -m "$(cat <<'MSG'
feat(oauth): auto-aquisição de token no startup do stiglitz.sh

Quando AUTH_TOKEN vazio e STIGLITZ_OAUTH_TOKEN_URL/_CLIENT_ID/_CLIENT_SECRET
no env, adquire via client_credentials (CLI oauth_token.py acquire) e popula
AUTH_TOKEN/TOKEN_A → ZAP spider + nuclei + Fase 5 autenticados. Fail-closed
default; STIGLITZ_OAUTH_REQUIRED=0 → best-effort deslogado. Token nunca ecoado.
Guard source-level garante que o token manual vence.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
MSG
)"
```

---

### Task 6: Documentação

**Files:**
- Modify: `docs/ROADMAP.md` (linha do auto-token + rename do módulo)
- Modify: `CLAUDE.md` (linha do módulo `oauth_refresh`→`oauth_token` + bullet da Fase 9/startup)
- Modify: `CHANGELOG.md` (entrada no topo de Unreleased)

- [ ] **Step 1: Atualizar `docs/ROADMAP.md`**

Trocar a linha existente do auto-token (que descreve só o refresh) para refletir a aquisição client_credentials. Localizar `Auto-aquisição de token (refresh flow)` e substituir o bloco por:
```markdown
- ✅ **Auto-aquisição de token OAuth2** (`lib/oauth_token.py`, ex-`oauth_refresh.py`):
  grant `client_credentials` no startup do `stiglitz.sh` (opt-in via env
  `STIGLITZ_OAUTH_TOKEN_URL`/`_CLIENT_ID`/`_CLIENT_SECRET`; `_SCOPE`/`_AUDIENCE`/
  `_AUTH_STYLE`/`_REQUIRED` opcionais) → popula `AUTH_TOKEN`/`TOKEN_A` (pipeline
  inteiro autenticado, sem JWT manual). Fail-closed default. `refresh_token` grant
  mantém a renovação on-401 na Fase 5. POST herda proxy+mTLS via `netproxy.urlopen`
```

- [ ] **Step 2: Atualizar `CLAUDE.md`**

Na tabela de módulos `lib/`, substituir a linha do `oauth_refresh.py` (se houver) ou adicionar a do `oauth_token.py`:
```markdown
| `oauth_token.py` | Gestão de access_token OAuth2 (ex-`oauth_refresh.py`): `acquire_access_token` (grant `client_credentials`, auth-style post/basic, scope/audience) usado no **startup do stiglitz.sh** p/ adquirir token sem JWT manual (popula `AUTH_TOKEN`/`TOKEN_A`); `refresh_access_token` (refresh grant, renovação on-401 na Fase 5); helper `_request_token` compartilhado (POST via `netproxy` → herda proxy+mTLS). Fail-closed default (`STIGLITZ_OAUTH_REQUIRED`). Lógica pura + CLI (`acquire`) |
```
Se a tabela já tiver uma linha `oauth_refresh.py`, removê-la (substituída por esta).

Adicionar, na seção da Fase 9 ou no preâmbulo de autenticação, uma nota curta:
```markdown
   - **Auto-token OAuth2 (opt-in via env `STIGLITZ_OAUTH_*`):** quando nenhum `--token` é passado e há credenciais de client no env, o scan adquire um `access_token` via `client_credentials` no startup (`lib/oauth_token.py`) e autentica o pipeline inteiro. Fail-closed por padrão; `STIGLITZ_OAUTH_REQUIRED=0` relaxa p/ best-effort.
```

- [ ] **Step 3: Atualizar `CHANGELOG.md`**

No topo da seção Unreleased:
```markdown
- **Auto-aquisição de token OAuth2 (client_credentials)**: `lib/oauth_token.py`
  (renomeado de `oauth_refresh.py`) adquire o `access_token` no startup do
  `stiglitz.sh` a partir de credenciais de client no env (`STIGLITZ_OAUTH_*`),
  populando `AUTH_TOKEN`/`TOKEN_A` — scan autenticado sem JWT manual. Auth-style
  post/basic, scope/audience, fail-closed default. POST herda proxy+mTLS.
```

- [ ] **Step 4: Validar a suíte completa + sintaxe**

Run: `python3 -m pytest tests/ -q`
Expected: PASS (todos), output pristino.

Run: `bash -n stiglitz.sh && shellcheck --severity=warning stiglitz.sh && echo CLEAN`
Expected: `CLEAN`.

Run: `python3 -m py_compile lib/oauth_token.py lib/poc_validator.py && echo OK`
Expected: `OK`.

- [ ] **Step 5: Commit**

```bash
git add docs/ROADMAP.md CLAUDE.md CHANGELOG.md
git commit -m "$(cat <<'MSG'
docs(oauth): ROADMAP + CLAUDE.md (módulo oauth_token) + CHANGELOG

Auto-aquisição client_credentials no startup; rename oauth_refresh→oauth_token.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
MSG
)"
```

---

## Self-Review (preenchido pelo autor do plano)

**Spec coverage:**
- Módulo `oauth_token.py` + `_request_token`/`acquire`/`is_acquire_enabled`/refresh refactor → Task 1+2.
- CLI `acquire` → Task 3.
- Renovação Fase 5 refresh-ou-acquire → Task 4.
- Bloco startup bash + fail-closed/REQUIRED + manual-vence → Task 5.
- Env `_SCOPE`/`_AUDIENCE`/`_AUTH_STYLE`/`_REQUIRED` → Task 2 (módulo) + Task 5 (bash).
- Sinergia mTLS (netproxy.urlopen) → herdada pelo `_request_token` (Task 1), sem código novo.
- Docs/rename churn → Task 6 + imports em Task 1.
- Testes (acquire body post/basic, scope/audience, OAuthError, is_acquire matrix, CLI, refresh regressão, poc_validator escolha, guard bash) → Tasks 1-5.

**Placeholder scan:** sem TBD/TODO; todo step de código mostra o código.

**Type consistency:** `_request_token(data, headers=None, timeout=15) -> dict` usado consistentemente por `acquire_access_token`/`refresh_access_token`; `acquire_access_token(timeout=15) -> str`, `is_acquire_enabled() -> bool`, `main(argv) -> int` — nomes idênticos entre tasks.

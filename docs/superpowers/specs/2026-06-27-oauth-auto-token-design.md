# Design — Auto-aquisição de token OAuth2 (client_credentials)

**Data:** 2026-06-27
**Status:** aprovado (brainstorming) — pronto para plano de implementação
**Roadmap:** item 3 fintech (`docs/ROADMAP.md`, "mTLS client-cert + aquisição automática de token OAuth2"). mTLS entregue; este spec cobre a aquisição automática.

## Problema

Hoje o scan autenticado do `stiglitz.sh` exige que o operador cole um JWT na mão
(`--token`/`--token-a`). Em fintech/Open Banking BR a credencial real é um par
`client_id`/`client_secret` (grant **client_credentials**, M2M), e o `access_token`
expira em minutos — menor que a janela de um scan completo. O `lib/oauth_refresh.py`
já renova um token via `refresh_token`, mas **apenas dentro do `poc_validator.py`
(Fase 5)** — não adquire token do zero nem autentica o resto do pipeline
(ZAP spider, nuclei, BOLA).

## Objetivo

Quando o operador fornecer credenciais de client OAuth2 por env, o scan **adquire o
`access_token` no startup** (grant `client_credentials`) e o injeta no pipeline inteiro
via `AUTH_TOKEN`/`TOKEN_A`, sem JWT manual. Mantém o `refresh_token` existente para a
renovação mid-scan.

## Decisões fechadas (brainstorming)

1. **Escopo:** aquisição no startup populando o pipeline inteiro (não só o `poc_validator`).
2. **Grant:** `client_credentials` apenas (o `refresh_token` existente cobre a renovação).
   `password`/ROPC descartado (deprecado em OAuth 2.1/FAPI, baixo valor).
3. **Número de tokens:** um (v1) — alimenta `AUTH_TOKEN`/`TOKEN_A`. BOLA/BFLA segue
   opt-in com `--token-a`/`--token-b` manuais.
4. **Falha:** configurável, **default fail-closed** (`STIGLITZ_OAUTH_REQUIRED=1`).
5. **Módulo:** renomear `lib/oauth_refresh.py` → `lib/oauth_token.py`, unificando
   aquisição + refresh sobre um helper compartilhado.

## Arquitetura

### Módulo `lib/oauth_token.py` (renomeado de `oauth_refresh.py`)

Módulo de gestão de access_token OAuth2. Lógica pura + CLI. Importa `netproxy` (já faz),
de modo que todo POST ao token endpoint herda `--proxy` e o client-cert mTLS.

Interface:

- `OAuthError(Exception)` — inalterado.
- `_request_token(data, headers=None, timeout=15) -> dict` — **helper compartilhado novo**.
  POST `application/x-www-form-urlencoded` de `data` ao `STIGLITZ_OAUTH_TOKEN_URL` via
  `netproxy.urlopen`; `Accept: application/json` + quaisquer `headers` extras; parseia o
  corpo como JSON e devolve o dict. Levanta `OAuthError` em:
  - `urllib.error.HTTPError` → `f"HTTP {code} do token endpoint: {reason}"`
  - `URLError`/`OSError` → `f"falha de rede: {e}"`
  - JSON inválido → `f"resposta não-JSON do token endpoint: {e}"`
- `acquire_access_token(timeout=15) -> str` — **novo**. Grant `client_credentials`.
  - Lê `TOKEN_URL`, `CLIENT_ID`, `CLIENT_SECRET` (obrigatórios); `SCOPE`, `AUDIENCE`,
    `AUTH_STYLE` (opcionais).
  - `OAuthError("STIGLITZ_OAUTH_TOKEN_URL / _CLIENT_ID / _CLIENT_SECRET não configurados")`
    se faltar qualquer obrigatório.
  - `data = {"grant_type": "client_credentials"}`; adiciona `scope` e `audience` quando setados.
  - **Auth style** (`STIGLITZ_OAUTH_AUTH_STYLE`, default `post`):
    - `post`: `client_id`/`client_secret` no corpo (`data`).
    - `basic`: header `Authorization: Basic base64(client_id:client_secret)`; **não** os põe no corpo.
  - Chama `_request_token(...)` (devolve o dict da resposta); extrai `access_token`
    (str não-vazia) ou `OAuthError` com um trecho truncado da resposta (sem secret).
  - Devolve o `access_token`.
- `refresh_access_token(timeout=15) -> str` — comportamento atual preservado, reescrito
  para delegar a `_request_token` (refactor DRY; sem mudança observável).
- `is_acquire_enabled() -> bool` — `TOKEN_URL` E `CLIENT_ID` E `CLIENT_SECRET` setados.
- `is_enabled() -> bool` (refresh) — `TOKEN_URL` E `REFRESH_TOKEN` setados (inalterado).
- `apply_to_curl(...)` — inalterado.
- **CLI** `main(argv)`:
  - `acquire` — roda `acquire_access_token()`. Sucesso → imprime **somente o token** em
    stdout (sem prefixo/sufixo), exit 0. `OAuthError` → mensagem em **stderr**, exit 1.
  - (Sem subcomando `refresh` na CLI: o refresh permanece interno ao `poc_validator`. YAGNI.)

### Configuração (env, namespace `STIGLITZ_OAUTH_*`)

| Var | Estado | Papel |
|-----|--------|-------|
| `STIGLITZ_OAUTH_TOKEN_URL` | existe | endpoint do token (POST) |
| `STIGLITZ_OAUTH_CLIENT_ID` | existe | client id |
| `STIGLITZ_OAUTH_CLIENT_SECRET` | existe | client secret |
| `STIGLITZ_OAUTH_SCOPE` | nova | scopes (space-delimited), opcional |
| `STIGLITZ_OAUTH_AUDIENCE` | nova | audience (AS estilo Auth0), opcional |
| `STIGLITZ_OAUTH_AUTH_STYLE` | nova | `post` (default) \| `basic` |
| `STIGLITZ_OAUTH_REQUIRED` | nova | `1` (default, fail-closed) \| `0` (fail-open) |
| `STIGLITZ_OAUTH_REFRESH_TOKEN` | existe | refresh grant (renovação mid-scan, inalterado) |
| `STIGLITZ_OAUTH_GRANT_TYPE` | existe | grant do refresh (default `refresh_token`, inalterado) |

**Credenciais são env-only** — nenhuma flag CLI nova p/ credenciais (evita vazamento na
process-list/audit/log).

### Integração no startup (`stiglitz.sh`)

Bloco novo logo após o parse de token (~linha 385, após
`[ -n "$TOKEN_A" ] && AUTH_TOKEN="$TOKEN_A"`), **antes** de qualquer fase consumir
`AUTH_TOKEN`/`TOKEN_A`:

```bash
# Auto-aquisição OAuth2 (client_credentials): só quando NENHUM token manual foi passado
# e as 3 credenciais de client estão no env. --token manual sempre vence.
if [ -z "$AUTH_TOKEN" ] && [ -n "${STIGLITZ_OAUTH_TOKEN_URL:-}" ] \
   && [ -n "${STIGLITZ_OAUTH_CLIENT_ID:-}" ] && [ -n "${STIGLITZ_OAUTH_CLIENT_SECRET:-}" ]; then
    _oauth_err="$(mktemp)"
    if _tok=$(python3 "$SCRIPT_DIR/lib/oauth_token.py" acquire 2>"$_oauth_err") && [ -n "$_tok" ]; then
        AUTH_TOKEN="$_tok"; TOKEN_A="$_tok"
        echo -e "  ${GREEN}[✓] token OAuth2 adquirido (client_credentials)${NC}"
    else
        if [ "${STIGLITZ_OAUTH_REQUIRED:-1}" = "0" ]; then
            echo -e "  ${YELLOW}[!] aquisição OAuth2 falhou ($(cat "$_oauth_err")) — scan seguirá DESLOGADO${NC}"
        else
            echo -e "  ${RED}[✗] aquisição OAuth2 falhou ($(cat "$_oauth_err")) — abortando (defina STIGLITZ_OAUTH_REQUIRED=0 p/ best-effort)${NC}"
            rm -f "$_oauth_err"; exit 1
        fi
    fi
    rm -f "$_oauth_err"
fi
```

- O token adquirido alimenta `AUTH_TOKEN` **e** `TOKEN_A` → ZAP spider
  (`zap_inject_auth_headers`), nuclei (`-H Authorization: Bearer`), Fase 5 (`poc_validator`).
- Popula **só** `TOKEN_A` (não `TOKEN_B`).
- A mensagem de erro carrega a razão do `OAuthError` (stderr capturado); **nunca o secret**
  (não está no `OAuthError`) e **nunca o token** (capturado em `$_tok`, não ecoado).

### Renovação na Fase 5 (`poc_validator.py`)

O `_refresh_oauth_safe` atual chama `refresh_access_token()`, que exige `REFRESH_TOKEN`.
Num setup só-`client_credentials` (sem refresh token) o `is_enabled()` é falso e a
renovação on-401 não dispararia. Como client_credentials re-adquire livremente, o
`_refresh_oauth_safe` passa a escolher o caminho disponível:

```python
if _oauth.is_enabled():            # refresh_token configurado
    _OAUTH_TOKEN = _oauth.refresh_access_token()
elif _oauth.is_acquire_enabled():  # client_credentials configurado
    _OAUTH_TOKEN = _oauth.acquire_access_token()
else:
    return ""  # nenhum configurado — no-op (inalterado)
```

Assim a Fase 5 renova via refresh **ou** re-aquisição, conforme o que estiver no env.
Mudança mínima e isolada ao `_refresh_oauth_safe` (a função já é fail-safe: em falha
retorna "" e loga, não aborta).

## Tratamento de erro / fail behavior

- `STIGLITZ_OAUTH_REQUIRED` ausente ou `1` → falha aborta (`exit 1`), espelhando o mTLS.
- `=0` → aviso PT-BR proeminente + segue com `AUTH_TOKEN` vazio (best-effort).
- `acquire_access_token` é fail-closed por natureza: config incompleta levanta `OAuthError`
  (o bash só o invoca quando as 3 vars estão setadas, mas o módulo revalida).

## Segurança

- **Sinergia mTLS:** o POST passa por `netproxy.urlopen`, herdando `--proxy` e o client-cert
  mTLS automaticamente. Token endpoints do Open Banking BR exigem mTLS — coberto sem código extra.
- Verificação do servidor segue o `netproxy`: verificada por padrão; relaxada (`CERT_NONE`) só
  quando o modo mTLS client-cert está ativo — consistente com o resto da ferramenta.
- O `access_token` adquirido é tratado como o token manual (sanitização no `repro.py`, nunca
  versionado — ver `cde_scope_never_on_github`). Sem nova superfície de vazamento.
- Credenciais e token nunca aparecem em mensagens de console, audit log ou arquivos do scan.

## Testes (TDD)

Unit em `tests/` (novo `test_oauth_token.py` ou estender o existente), monkeypatch de
`netproxy.urlopen`/`_request_token`, credenciais fake:

- `acquire_access_token` monta o corpo `client_credentials` correto:
  - `grant_type=client_credentials`;
  - `post`: `client_id`/`client_secret` no corpo, sem header Basic;
  - `basic`: header `Authorization: Basic ...`, sem id/secret no corpo;
  - `scope`/`audience` incluídos só quando setados.
- devolve `access_token` da resposta;
- `OAuthError` em: config ausente (cada uma das 3), resposta sem `access_token`,
  HTTPError, resposta não-JSON.
- `is_acquire_enabled()` matriz (3 vars presentes/ausentes).
- **regressão:** `refresh_access_token` ainda funciona após o refactor para `_request_token`
  (os testes existentes em `tests/test_lib.py` devem continuar verdes; atualizar o import
  `oauth_refresh` → `oauth_token`).
- CLI `acquire`: sucesso imprime **só** o token em stdout (exit 0); `OAuthError` → stderr + exit 1.
- `poc_validator._refresh_oauth_safe`: escolhe `refresh_access_token` quando `is_enabled()`,
  `acquire_access_token` quando só `is_acquire_enabled()`, e no-op quando nenhum (monkeypatch
  das três funções do módulo; verificar qual foi chamada).
- Output dos testes pristino (sem warnings).

Bash: `bash -n` + `shellcheck --severity=warning`. Guard source-level (análogo a
`test_mtls_stiglitz_curl_parity.py`): o bloco de aquisição guarda em `-z "$AUTH_TOKEN"`
(token manual vence) e respeita `STIGLITZ_OAUTH_REQUIRED`.

## Migração / churn do rename

- `lib/oauth_refresh.py` → `lib/oauth_token.py` (via `git mv`, preserva história).
- Atualizar import em `lib/poc_validator.py` (`import oauth_refresh as _oauth` → `oauth_token`).
- Atualizar `tests/test_lib.py` (import/refs a `oauth_refresh`).
- Atualizar docs: `docs/ROADMAP.md`, `CLAUDE.md` (linha do módulo), `CHANGELOG.md`.
- Sem compat shim (`oauth_refresh.py` não é interface pública externa; só consumido internamente).

## Não-objetivos (v1)

- `password`/ROPC e `device_code` grants.
- Segundo token p/ BOLA automático (TOKEN_B).
- `private_key_jwt` / `tls_client_auth` como método de autenticação do client (FAPI follow-up).
- Renovação proativa por `expires_in` no pipeline principal. O token adquirido no startup vale
  pela duração do scan; ZAP/nuclei (que rodam antes da Fase 5) **não** renovam on-401 — se o
  token expirar durante a varredura longa do ZAP, esses passos recebem 401 sem renovação (mesma
  limitação do token manual hoje). Só a Fase 5 (`poc_validator`) renova on-401, via refresh ou
  re-aquisição. Renovação pipeline-wide fica para um follow-up.
- PAR/JARM e demais itens FAPI/Open Banking (item 5 do roadmap).

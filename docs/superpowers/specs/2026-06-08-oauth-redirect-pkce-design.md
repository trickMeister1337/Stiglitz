# Auditoria OAuth/OIDC — redirect_uri & PKCE (authn ativo) — Design

> Spec de design. Fonte de verdade para o plano de implementação. Verificar assinaturas contra o código antes de afirmar (este doc é snapshot de 2026-06-08).

## Objetivo

Fechar a **Frente 1 (testes de authn ativos)** do roadmap adicionando auditoria de **OAuth 2.0 / OIDC** ao `stiglitz.sh`: validação fraca de **`redirect_uri`** (open redirect → roubo de authorization code → account takeover) e fraquezas de **PKCE** (ausente/não enforçado, downgrade para `plain`), além de duas classes adjacentes que saem da mesma análise (**state/CSRF + nonce** e **implicit flow exposto**).

Hoje o toolkit só tem JWT ativo (`lib/jwt_audit.py`) e BOLA/BFLA (`lib/bola.py`); o único código OAuth é `lib/oauth_refresh.py`, que **mantém sessão** (refresh-token) e **não audita** nada. Este design preenche a lacuna seguindo o padrão consolidado: **núcleo puro testável + confirmação ativa gated por perfil**.

## Decisões (brainstorming 2026-06-08)

| Tema | Decisão |
|------|---------|
| Modo | **Híbrido gated por perfil**: descoberta passiva sempre gera findings estáticos; probes ativos rodam em `staging`/`lab`, **dry-run em `production`** (padrão BOLA/JWT) |
| Escopo de checks | `redirect_uri` (open redirect + validação fraca) **e** PKCE (ausente + downgrade) — núcleo; **+** state/CSRF + nonce; **+** implicit flow exposto |
| Fontes de entrada | **well-known discovery** + **ZAP dump** (params reais) + **config via env** — combinadas |
| Estrutura | **Módulo único `lib/oauth_audit.py`** (lógica pura + CLI), espelhando `jwt_audit.py`/`bola.py` |
| Posicionamento | Nova fase **P9.6 OAuth Audit** no `stiglitz.sh`, após a P9.5 (BOLA/BFLA) — ambas consomem o ZAP dump e são authn/authz |
| Canary do probe | Host sentinela **configurável** `STIGLITZ_OAUTH_CANARY_URI`, default RFC2606 (`https://oauth-probe.invalid`) — **nunca** domínio de terceiro real |

## Arquitetura

Lógica pura e testável (parse, análise de params, *builders* de probe, *classifiers* de resposta) em `lib/oauth_audit.py`, com orquestração de rede fina no mesmo módulo (fetch do well-known + envio dos probes). O `stiglitz.sh` (nova fase **P9.6**) descobre/coleta as fontes e invoca o módulo, que emite `raw/oauth_findings.json`. Reuso deliberado: `parse_zap_messages` (`bola.py`), `fingerprint.py`, classes do `vuln_catalog.py`, e o `run_cmd`/curl com timeout do `poc_validator.py` para os probes.

### CLI e ativação (`stiglitz.sh`)

- A fase **P9.6 roda em dois níveis**:
  - **Passivo** (sempre que houver well-known **ou** ZAP dump): só `static_findings`, zero tráfego ofensivo. **É o default** — sem nenhuma flag, a fase só descobre e analisa.
  - **Ativo** (probes): exige a **flag opt-in `--oauth-active`** (igual ao BOLA exigir `--token-a/-b`) **e** `client_id` (do env ou capturado). Mesmo com a flag, `STIGLITZ_PROFILE=production` força **dry-run** (probes montados e logados, não enviados). O scan não tem perfil nativo (diferente do `stiglitz_red.sh`); o perfil chega só via env `STIGLITZ_PROFILE` (default ausente ⇒ tratado como permissivo, mas a flag já é o gate primário).
- Config opcional via env: `STIGLITZ_OAUTH_AUTHORIZE_URL`, `STIGLITZ_OAUTH_CLIENT_ID`, `STIGLITZ_OAUTH_REDIRECT_URI` (redirect legítimo registrado, base dos probes), `STIGLITZ_OAUTH_CANARY_URI`, `STIGLITZ_PROFILE`. Sem nenhuma, a fase ainda roda passiva a partir do well-known/ZAP descobertos.
- Invocável isoladamente pelo `pipeline.py` (`--only-phase`), com checkpoint, no padrão das demais fases.

### Gating de perfil / segurança

- Probes ativos **gated por flag opt-in `--oauth-active`** (default off). Quando ligados, `STIGLITZ_PROFILE=production` força dry-run. O `stiglitz.sh` (scan) não tem perfil nativo — os perfis sqlmap/brute são do `stiglitz_red.sh`; por isso o gate primário é a flag, e o perfil é um override opcional via env.
- O probe de open redirect usa **somente** o `STIGLITZ_OAUTH_CANARY_URI` (sentinela), nunca um domínio externo arbitrário — evita SSRF/redirect contra terceiros reais.
- Segredos (`client_id`, redirect) por env, não em argv. `oauth_findings.json` fica no `OUTDIR` (gitignored) — **nunca** versionado.

## Componentes — `lib/oauth_audit.py`

### Funções puras (núcleo testável, sem rede)

- `parse_well_known(doc) -> dict` — normaliza `{authorization_endpoint, token_endpoint, response_types_supported, code_challenge_methods_supported, grant_types_supported, scopes_supported}`. JSON inválido → dict vazio.
- `parse_authorize_requests(zap_messages) -> [Flow]` — extrai fluxos `/authorize` observados: `{authorize_url, client_id, redirect_uri, response_type, state, nonce, code_challenge, code_challenge_method, scope}`. Reusa `parse_zap_messages` do `bola.py` e filtra por URL de autorização.
- `static_findings(wellknown, flows, target) -> [finding]` — findings derivados **sem rede**:
  - **implicit flow**: `token` em `response_types_supported` ou observado em fluxo.
  - **PKCE**: `code_challenge_methods_supported` ausente ou `== ["plain"]`; fluxo observado sem `code_challenge`.
  - **state/nonce**: fluxo observado sem `state`; fluxo OIDC (`scope` contém `openid`) sem `nonce`.
  - **redirect_uri sobre HTTP**: `redirect_uri` observado com esquema `http://`.
- **Probe builders** (puros — montam a request, não enviam):
  - `build_redirect_uri_probes(authorize_url, base_params, canary) -> [probe]` — variações: domínio canary puro, `sub.target.canary` (sufixo), path traversal (`/../`), `@canary` (userinfo), `%0d%0a`/`%2e` (encoding), `target.com.canary` (prefixo). Cada probe carrega o `expected_marker` (host canary).
  - `build_pkce_downgrade_probe(...)` — fluxo com `code_challenge_method=plain`.
  - `build_pkce_missing_probe(...)` — code flow sem `code_challenge`.
- **Classifiers**:
  - `classify_redirect_response(status, location, canary_host) -> verdict` — **CONFIRMED** se o `Location` (ou erro de redirect) aponta para `canary_host`; **REJECTED** se 4xx/erro `invalid_redirect_uri`; **INCONCLUSIVE** caso ambíguo.
  - `classify_pkce_response(status, body) -> verdict` — aceitou troca de code sem `code_verifier` / com `plain` → CONFIRMED.
- `build_findings(verdicts, statics, target) -> [finding]` — schema padronizado (`tool/type/source/name/url/severity/description/remediation/evidence/cve`) **+ fingerprint** (`fingerprint.py`), texto **em EN** (deliverable).

### Orquestração de rede (isolada)

- `fetch_well_known(base_url) -> dict` — GET em `/.well-known/openid-configuration` e `/.well-known/oauth-authorization-server`; degrada para `{}` sem abortar.
- `send_probe(probe) -> (status, location, body)` — via `curl` (padrão `poc_validator.run_cmd`: timeout/retry), **sem seguir redirect** (`-s -o /dev/null -D -`), para ler o `Location` cru.
- `run(scan_dir, profile) -> result` — descobre fontes (well-known + `raw/zap_messages_a.json` se existir + env), roda `static_findings`; se perfil permite e há `client_id`, monta probes e chama `send_probe` → classifiers → `build_findings`. Grava `raw/oauth_findings.json`. Em `production` registra os probes como dry-run (não envia).

### CLI

```
python3 lib/oauth_audit.py run <scan_dir> [--profile staging]
```
Funções puras exercidas direto pelos testes com dados sintéticos (sem rede, domínio `target.com` / canary `oauth-probe.invalid`).

## Fluxo de dados

```
well-known (fetch)  ─┐
ZAP /authorize dump ─┼─►  parse_well_known + parse_authorize_requests
env STIGLITZ_OAUTH_* ┘                 │
                                       ▼
                          static_findings  (passivo, sempre)
                                       │
                  perfil permite + client_id?  ──não──►  só estáticos
                                       │ sim
                                       ▼
        build_*_probes  ──►  send_probe (curl, -D -, sem follow)  [dry-run em production]
                                       │
                                       ▼
        classify_redirect_response / classify_pkce_response
                                       │
                                       ▼
        build_findings (classes oauth_*, com fingerprint)  ──►  raw/oauth_findings.json
                                       │
                                       ▼
        stiglitz_report.py (coletor +1 linha)  ──►  findings.json + SARIF + relatório HTML
                                       │
                                       ▼
                          motor de criticidade (base + environmental do CDE)
```

## Catálogo de vulnerabilidades (`lib/vuln_catalog.py`)

Já existem `open_redirect` (CWE-601) e `csrf_state_changing` (CWE-352) genéricos — usados como **precedente de CWE**, mas o impacto via OAuth (roubo de code → ATO; contexto CDE) difere, então adicionamos **entradas OAuth dedicadas** (como o BOLA adicionou `bfla`), para severidade e relatório corretos. Vetores base propostos (no padrão das entradas authz/jwt; severidade final sai do motor de criticidade):

| Classe | CWE | Vetor base (CVSS 3.1) |
|--------|-----|------------------------|
| `oauth_redirect_uri` | CWE-601 | `AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N` (ATO via roubo de code) |
| `oauth_pkce_missing` | CWE-287 | `AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N` (interceptação de code, public client) |
| `oauth_pkce_downgrade` | CWE-310 | `AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N` |
| `oauth_missing_state` | CWE-352 | `AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N` (login CSRF) |
| `oauth_missing_nonce` | CWE-294 | `AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N` (replay de id_token) |
| `oauth_implicit_flow` | CWE-522 | `AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N` (token no fragment vaza em log/referer) |

## Integração no pipeline

- **Fase P9.6** nova no `stiglitz.sh`, após a P9.5. Documentar no `CLAUDE.md` (lista de fases + tabela `lib/`).
- **Report:** adicionar `('oauth_findings.json', 'oauth_findings')` à lista de coletores de `stiglitz_report.py` (hoje linhas ~872–884) — mesmo mecanismo de `jwt_findings.json`/`access_findings.json`. Seção "OAuth/OIDC" no relatório HTML reusa o template das demais.
- **Criticidade:** os findings entram no `findings.json` com classe `oauth_*` → o motor existente aplica base (vetor da classe) + environmental (CR/IR/AR do CDE). KEV/EPSS não se aplicam (não há CVE) → temporal neutro.

## Tratamento de erro / degradação

Padrão do projeto — sempre avisa no terminal (PT-BR), nunca aborta a fase:

- Sem well-known **e** sem ZAP dump **e** sem env → `info "oauth-audit: nenhuma superfície OAuth detectada — pulado"`.
- well-known 404/timeout → `warn`, segue com ZAP/env.
- Perfil `production` → `info "oauth-audit: probes ativos em dry-run (perfil production)"`, só estáticos emitidos.
- Sem `client_id` (env ou capturado) → probes ativos pulados, estáticos mantidos, `warn`.
- `curl`/probe com timeout → verdict `INCONCLUSIVE` (não trava o loop).

## Testes (`tests/test_oauth_audit.py`, TDD por função)

- `parse_well_known`: PKCE `["S256"]` ✓, ausente ✓, `["plain"]` ✓, implicit anunciado ✓; JSON inválido → `{}`.
- `parse_authorize_requests`: extrai params de `/authorize`; ignora não-OAuth.
- `static_findings`: implicit flow, PKCE ausente/plain, state ausente, nonce ausente (OIDC), redirect_uri HTTP — e ausência de finding quando tudo correto.
- `build_redirect_uri_probes`: cada variação gera a URL esperada com `redirect_uri` apontando ao canary.
- `build_pkce_*`: query correta (`plain` / sem `code_challenge`).
- `classify_redirect_response`: CONFIRMED (Location→canary), REJECTED (`invalid_redirect_uri`/4xx), INCONCLUSIVE.
- `classify_pkce_response`: code aceito sem verifier / com plain → CONFIRMED.
- `build_findings`: schema, classe certa por tipo, fingerprint presente, texto EN.
- **Gating**: `run(..., profile="production")` não chama `send_probe` (mock conta zero envios); `staging` envia.
- Smoke do wiring bash: `bash -n` + `shellcheck` limpos; `grep` confirma posicionamento da P9.6 e mensagens de degradação.

## Reuso (não reinventar)

- `lib/bola.py`: `parse_zap_messages` (dump do ZAP `core/view/messages`).
- `lib/poc_validator.py`: `run_cmd`/curl com timeout/retry.
- `lib/fingerprint.py`: fingerprint estável (desbloqueia state/SARIF/diff existentes).
- `lib/vuln_catalog.py`: `open_redirect`/`csrf_state_changing` como referência de CWE; **adiciona** as 6 entradas `oauth_*`.
- `stiglitz_report.py`: coletor de raw findings (+1 linha).

## Fora de escopo (v2+)

- Fluxo completo de troca de code (capturar code real e trocá-lo no token endpoint) — os probes confirmam aceitação no `/authorize`; a troca fica para v2 com gating extra.
- Device code flow, CIBA, JAR/PAR, DPoP.
- Mais de um `client_id` por alvo / matriz de clients.
- Auditoria de escopos (over-broad scope) e consentimento.

## Pendência operacional (inalterada)

Política mantida: trabalho **local** até autorização explícita; nenhum artefato de alvo versionado. Nenhum domínio real de cliente entra em código/teste/spec/commit — exemplos usam `target.com` e o canary sentinela `oauth-probe.invalid`.

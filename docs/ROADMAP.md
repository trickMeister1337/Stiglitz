# Stiglitz — Roadmap de Maturidade

> Higienizado para versionamento: **nenhum dado de CDE/cliente/alvo** aqui. Pendências
> operacionais sensíveis ficam só na memória local. Estado snapshot — verificar contra
> o git antes de afirmar. **Última sincronização: 2026-06-26 (HEAD `5c0e2a0`).**

**Origem:** auditoria multi-agent (2026-06-06) comparando o Stiglitz com scanners comerciais
(Nessus/Qualys/InsightVM/Detectify/Burp Enterprise/Wiz/Snyk). Temas centrais: (1) dicotomia
scan↔RED (melhores features gated no RED); (2) catálogo promete o que o coletor não entrega;
(3) inteligência calculada mas não-acionada na apresentação.

**Disciplina de entrega:** TDD (teste→RED→GREEN), commits pequenos com `bash -n`+`shellcheck`
limpos, validação ao vivo dos caminhos críticos (Juice Shop+ZAP via docker; searchsploit).
Módulos novos = lógica pura + CLI primeiro (padrão `bola.py`/`takeover.py`), integração depois.

**Roadmaps temáticos:** [`ROADMAP-blackbox-cde.md`](ROADMAP-blackbox-cde.md) — melhoria dos
achados em scan black-box de CDE zero-credencial (OpenAPI como motor, OOB self-host, CDE-driver).

---

## P0 — COMPLETO e validado

base tags injeção + `nuclei -dast`/fuzzing + arjun (`lib/dast_prep.py`); OAST toggle
(`INTERACTSH_SERVER`); ZAP Context auth (`lib/zap_auth.py`); AJAX Spider; JWT ativo
(`lib/jwt_audit.py`: alg=none/crack/forge); GraphQL (`lib/graphql_audit.py`); sort por risco
unificado; SLA/aging CISA KEV (`lib/prioritization.py`); compliance multi-framework
(`lib/compliance_map.py`: CWE→OWASP/ASVS/PCI/ISO/NIST). Validado ao vivo (SQLi no Juice Shop).

## P1 — COMPLETO

**Feitos e mergeados em `main`:**
- ✅ retire.js SCA client-side (`lib/retire_parse.py`, CWE-1395→A06)
- ✅ reachability + exploit-availability (`lib/risk_context.py` + `lib/exploit_lookup.py` via
  `searchsploit -j`; `risk_priority` governa o sort). Validado: Log4Shell→10.0
- ✅ fingerprint estável de finding (`lib/fingerprint.py`: classe+host+path-template+param).
  **Desbloqueia** estado-de-finding/SLA-real/trend/DefectDojo
- ✅ estado de finding + push DefectDojo (`lib/finding_state.py` ledger NEW/PERSISTENT/
  RESOLVED/REOPENED + métricas age/MTTR/SLA; store em `STIGLITZ_STATE_DIR` fora do repo;
  SARIF partialFingerprints; `lib/trackers/` reimport-scan opt-in; `stiglitz_track.py` + fase P12)
- ✅ subdomain takeover híbrido (osint.sh Fase 8, `lib/takeover.py`: dnsx CNAME → filtro
  externo ao apex → nuclei -tags takeover → `cloud/takeover_candidates.csv`)
- ✅ BOLA/BFLA multi-token (OWASP API #1, fase **P9.5** no stiglitz.sh, `lib/bola.py`):
  opt-in `--token-a`/`--token-b`, replay com token oposto + unauth, tripla A/B/unauth +
  canário de corpo, classes bola/idor_read_pii/bfla → `access_control.json`
- ✅ **boolean-pair / canário nos validators** (`lib/active_probe.py` + integração):
  `boolean_pair_verdict` (SQLi blind boolean-based), `canary_reflection` (XSS refletido),
  builders query-string, CLI. Integrado: `validators/sqli.py` consome `ctx["bool_pair"]`,
  `validators/xss.py` consome `ctx["canary"]`, `poc_validator.validate()` repassa os kwargs,
  `confirm_nuclei` dispara os probes. Degrada sem regressão (builder None / fetch falho →
  fallback legado)
- ✅ **OAuth/OIDC audit** (fase **P9.6** no stiglitz.sh, `lib/oauth_audit.py`): descoberta
  passiva (well-known + params do dump ZAP) de redirect_uri/PKCE/state/nonce/implicit flow;
  probes ativos opt-in com `--oauth-active` (dry-run sob `STIGLITZ_PROFILE=production`);
  classifiers CONFIRMED/REJECTED/INCONCLUSIVE → `oauth_findings.json`; 6 classes novas no
  catálogo
- ✅ **bizlogic no scan** (fase **P9.7**, `lib/bizlogic_scan.py`): read-only auto-derivado do
  ZAP+tokens; mutantes opt-in (`--bizlogic-mutate` + config) com gating profile/RoE; dedup vs P9.5
- ✅ **ZAP bearer-token propagation (spider) + AJAX render chromium** (Fase 9): bearer/header
  injetados no HttpSender ANTES do spider (helper `zap_inject_auth_headers`) → ZAP Spider e
  histórico que a P9.5 (BOLA) consome rodam autenticados (fronteira do BOLA expandida);
  pré-check de `exp` (`jwt_audit.exp_status` + CLI `exp-check`); AJAX Spider via `chrome-headless`
  com preflight de browser e degradação. Validado ao vivo (alvo local)
- ✅ **OpenAPI seeding fallback** (Fase 9, `lib/openapi_seed.py`): quando o `importUrl` nativo
  do ZAP rejeita um spec válido (nomes de schema fora de `^[a-zA-Z0-9.\-_]+$` — ex.: generics
  .NET com backtick), extrai as URLs concretas do spec (resolve `{param}`, aplica `basePath`/
  `servers`, dedup) → `raw/openapi_urls.txt` semeadas no ZAP via `accessUrl`. Lógica pura + CLI.
  Estendido p/ **seeding multi-host** (alimenta o Nuclei com endpoints reais das APIs)
- ✅ **P9.6 base-url duplo-esquema corrigido** (`https://https://...` zerava a fase) — usa
  `$TARGET` direto, mesma correção da P9.7
- ✅ **P9.5 (Access Control) no orquestrador + fluxo confirmado**: a fase **P9 do `pipeline.py`
  virou unidade combinada `P9 P9_5 P9_6 P9_7`** — as sub-fases de authz consomem o ZAP vivo da P9.
  Confirmado por teste de caracterização que os findings da P9.5 chegam ao `findings.json` (com
  `fingerprint`) **e** ao `findings.sarif` (com `partialFingerprints`)
- ✅ **dedup semântico** (`lib/dedup.py`): colapsa duplicatas cross-tool + variantes de path/param
  (estágio 1 fingerprint) + fuzzy por CVE/título/evidência blocado por host (estágio 2). Auto-merge
  agressivo, proveniência no finding. Integrado no scan (`stiglitz_report.py`) e no RED
  (`evidence.py`); `STIGLITZ_DEDUP=0` desliga. CLI + lógica pura
- ✅ **hardening (Frente 5)**: bare `except:` → tipos específicos; selo HMAC do `audit.log`
  (`audit.log.seal`, `STIGLITZ_AUDIT_KEY`); `lib/scope.py` como ponto único de escopo +
  `scope_guard` em brute/sqli/xss; `phase_output_ok` valida saída antes de `phase_done`

**P1 restante:** nenhum.

## Qualidade do deliverable & reprodutibilidade (rodada jun/2026, pós-P1)

Rodada de correções guiada por validação ao vivo (API .NET 100% auth-gated atrás de ELB AWS +
duas runs divergentes do mesmo alvo). Tudo mergeado em `main`:

- ✅ **Detector de FP "JWT-gate"** (`lib/zap_authgate.py`): ZAP deslogado contra API auth-gated
  recebe 401/403 antes da query → heurístico lê dois 401 como manipulation → falso CRITICAL.
  Fase 9 captura `attack_status` (`core/view/message`); Fase 11 move os active-scan barrados
  (`attack` não-vazio E status ∈ {401,403}) p/ seção **"Deferred — Requires Authenticated
  Retest"** (HTML + `deferred_findings` no findings.json), fora das contagens/criticidade.
  Fail-safe (status ausente → não defere) + auto-ajuste (scan logado, ataque 200 → não defere)
- ✅ **OWASP Top 10 (2021) Coverage View** (`lib/compliance_map.owasp_posture`): seção de
  apresentação com veredito **FOUND/TESTED/NOT-COVERED** por categoria, **separada da
  criticidade** (CVSS+KEV+EPSS intactos, puramente aditiva). Sempre visível (sem gate de CDE)
- ✅ **Reprodutibilidade** (duas causas, dois fixes):
  - **Lock por-host** (`lib/host_lock.sh`): serializa dois `stiglitz.sh <mesmo-host>` que
    disputavam o daemon ZAP (porta fixa) + store de estado. Escape: `STIGLITZ_NO_HOSTLOCK=1`
  - **Descoberta de JS determinística** (`lib/js_chunks.discover_js_urls`): fronteira em lista,
    não `set.pop()` (variava por `PYTHONHASHSEED` → SCA divergente entre runs)
- ✅ **SCA: libs vulneráveis distintas não colapsam** — `component@version` entra no fingerprint
  só quando presente; `dedup` nunca funde componentes SCA distintos (mesma lib em chunks
  diferentes ainda colapsa). Varredura de **lazy chunks webpack** + guarda anti-FP de catch-all
  (`lib/js_chunks`: SPA devolve index.html p/ path inexistente → nunca varrer HTML como JS)
- ✅ **Criticidade: piso = `severity_tool` p/ findings `estimated`** (`lib/criticality.py`) — não
  rebaixa estimativa abaixo da ferramenta; environmental ainda eleva (ativo CDE/confirmação)
- ✅ **Correções de credibilidade**: tech inventory via `httpx -json` (`lib/httpx_parse.py`,
  deriva de `tech`/`webserver`, nunca do `title`); DMARC organizacional + downgrade MX-aware
  (`lib/email_security.py`, RFC 7489 §6.6.3); contagem TLS do terminal espelha o report
  (`lib/tls_confirm.count_terminal_tls_issues`)
- ✅ **Report (anti-bloat)**: evidência gigante vira arquivo lateral linkado; Security Headers
  replicados agrupados por tipo (`affected_urls`); HSTS missing rebaixado high→medium

## P2 — BACKLOG

- ✅ **trend multi-scan** (FEITO — `stiglitz_trend.py`): aceita N scans ordenados por timestamp,
  HTML com sparkline SVG do risk score + tabela por scan + delta primeiro↔último
- relatório PDF (WeasyPrint)
- CSPM (prowler)
- IaC/container (trivy)
- multi-tenant

## Especialização fintech / API-heavy

Itens de produto reconciliados com o código (detalhe e priorização vivem na memória local):

- ✅ **Auto-aquisição de token OAuth2** (`lib/oauth_token.py`, ex-`oauth_refresh.py`):
  grant `client_credentials` no startup do `stiglitz.sh` (opt-in via env
  `STIGLITZ_OAUTH_TOKEN_URL`/`_CLIENT_ID`/`_CLIENT_SECRET`; `_SCOPE`/`_AUDIENCE`/
  `_AUTH_STYLE`/`_REQUIRED` opcionais) → popula `AUTH_TOKEN`/`TOKEN_A` (pipeline
  inteiro autenticado, sem JWT manual). Fail-closed default. `refresh_token` grant
  mantém a renovação on-401 na Fase 5. POST herda proxy+mTLS via `netproxy.urlopen`
- ✅ **mTLS client-cert** (`lib/mtls.py`, opt-in `--mtls-cert`/`--mtls-key`): par PEM (sem senha) apresentado por curl/nuclei/ffuf + módulos urllib (via `netproxy.client_ssl_context`) + ZAP (PKCS#12 efêmero). Fail-closed; coexiste com `--proxy`. httpx/katana sem suporte (limitação documentada)
- ✅ **GraphQL além de introspection** (`lib/graphql_dos.py` + `lib/graphql_authz.py`):
  DoS batching/aliasing (probes `__typename`, detecção independente de introspection,
  dry-run em `production`) na Fase 9; field-level authz (BOLA/BFLA) na **P9.8** —
  replay das operações reais do histórico ZAP com 2 tokens reusando `bola.verdict`,
  queries-only por padrão (mutations via `--graphql-mutate` + gating de profile)
- ⏳ **FAPI / Open Banking Brasil**: PAR, mTLS-bound tokens, JARM (estender `oauth_audit.py`)
- ⏳ **OAST always-on**: hoje opt-in via `INTERACTSH_SERVER` (`lib/oob.py`); reframe p/ sempre-ligado

## Follow-ups conhecidos

- ✅ **Cobertura PCI (FEITO)** — porte do swarm-pci entregue: `lib/cde_scope.py`,
  `lib/pan_scanner.py` (PAN com Luhn+máscara, 3.5.1), `lib/payment_page_monitor.py` (integridade
  de scripts/Magecart 6.4.3/11.6.1), `lib/pci_verdicts.py`; tag `pci_req`; escopo via
  `cde_targets.txt` (gitignored); Fase 7.5 ativa multi-alvo (Reqs 2/4.2.1/8/10/12.10 com
  evidência positiva/negativa). Texto dos findings em EN (deliverable)
- ⏳ **Propagação do bearer ao active scanner + browser do AJAX:** o replacer cobre o ZAP Spider
  clássico, mas validação ao vivo mostrou que o **active scanner** e o **browser do AJAX Spider**
  rodam deslogados (requests sem `Authorization`). Propagação completa exige mais que o replacer
  (httpSender script, ou contexto forced-user adaptado a bearer estático). Não bloqueia a fronteira
  do BOLA, que depende do histórico do spider — já autenticado
- ⏳ **OpenAPI seeding — só paths GET via `accessUrl`:** o fallback registra os nós no site-tree,
  mas não passa schemas de request (body/params) p/ endpoints mutantes (POST/PUT). IDs de path
  usam valor de amostra (`1`) → 404 comum sem credenciais. Follow-up: sanitizar nomes inválidos e
  reimportar via `openapi/action/importFile` (recupera cobertura mutante do active scanner)
- (nota de design) **Dedup semântico × dedup bizlogic (P9.7):** o dedup semântico (P2) roda a
  jusante da dedup especializada P9.7×P9.5. Quando P9.5 inconclusiva e P9.7 confirmada colidem no
  mesmo recurso, o dedup semântico as **mescla em 1** (o confirmado/maior-severidade vence; a outra
  fonte entra em `sources`) — decisão deliberada (dedup semântico autoritativo, confirmado não some,
  muda só a contagem). `test_inconclusive_access_does_not_suppress_confirmed_bizlogic` reflete isso

## Pendência operacional

Higienização de dados de scan/CDE — **detalhes e comandos só na memória local** (nunca aqui).

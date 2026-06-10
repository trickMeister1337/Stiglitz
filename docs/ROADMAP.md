# Stiglitz — Roadmap de Maturidade

> Higienizado para versionamento: **nenhum dado de CDE/cliente/alvo** aqui. Pendências
> operacionais sensíveis ficam só na memória local. Estado snapshot — verificar contra
> o git antes de afirmar.

**Origem:** auditoria multi-agent (2026-06-06) comparando o Stiglitz com scanners comerciais
(Nessus/Qualys/InsightVM/Detectify/Burp Enterprise/Wiz/Snyk). Temas centrais: (1) dicotomia
scan↔RED (melhores features gated no RED); (2) catálogo promete o que o coletor não entrega;
(3) inteligência calculada mas não-acionada na apresentação.

**Disciplina de entrega:** TDD (teste→RED→GREEN), commits pequenos com `bash -n`+`shellcheck`
limpos, validação ao vivo dos caminhos críticos (Juice Shop+ZAP via docker; searchsploit).
Módulos novos = lógica pura + CLI primeiro (padrão `bola.py`/`takeover.py`), integração depois.

---

## P0 — COMPLETO e validado

base tags injeção + `nuclei -dast`/fuzzing + arjun (`lib/dast_prep.py`); OAST toggle
(`INTERACTSH_SERVER`); ZAP Context auth (`lib/zap_auth.py`); AJAX Spider; JWT ativo
(`lib/jwt_audit.py`: alg=none/crack/forge); GraphQL (`lib/graphql_audit.py`); sort por risco
unificado; SLA/aging CISA KEV (`lib/prioritization.py`); compliance multi-framework
(`lib/compliance_map.py`: CWE→OWASP/ASVS/PCI/ISO/NIST). Validado ao vivo (SQLi no Juice Shop).

## P1 — EM ANDAMENTO

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
  catálogo. Suite combinada: 514 passed / 4 skipped
- ✅ **bizlogic no scan** (fase **P9.7**, `lib/bizlogic_scan.py`): read-only auto-derivado do ZAP+tokens; mutantes opt-in (`--bizlogic-mutate` + config) com gating profile/RoE; dedup vs P9.5
- ✅ **ZAP bearer-token propagation (spider) + AJAX render chromium** (Fase 9): bearer/header
  injetados no HttpSender ANTES do spider (helper `zap_inject_auth_headers`) → ZAP Spider e
  histórico que a P9.5 (BOLA) consome rodam autenticados (fronteira do BOLA expandida);
  pré-check de `exp` (`jwt_audit.exp_status` + CLI `exp-check`); AJAX Spider via `chrome-headless`
  com preflight de browser e degradação. Validado ao vivo (alvo local): spider autenticado
  descobre rota protegida, AJAX renderiza via chromium (confinamento snap não bloqueou), exp-check OK
- ✅ **OpenAPI seeding fallback** (Fase 9, `lib/openapi_seed.py`): quando o `importUrl` nativo
  do ZAP rejeita um spec válido (nomes de schema fora de `^[a-zA-Z0-9.\-_]+$` — ex.: generics
  .NET com backtick), extrai as URLs concretas do spec (resolve `{param}`, aplica `basePath`/
  `servers`, dedup) → `raw/openapi_urls.txt` semeadas no ZAP via `accessUrl`. Descoberto em
  validação ao vivo (API .NET): sem o fallback, a superfície documentada — incl. endpoint
  multi-tenant alvo de BOLA — escapava do spider/active-scan. Lógica pura + CLI (7 testes).
  Banner "Retomando scan" silenciado sob `pipeline.py` (só standalone); suíte 550 passed / 4 skipped
- ✅ **P9.6 base-url duplo-esquema corrigido** (Fase 9.6 OAuth): a descoberta well-known (curl)
  e o `--target` do `oauth_audit` usavam `https://${TARGET}` com `TARGET` já normalizado com
  esquema → `https://https://...` (zerava a fase, como zerava na bizlogic antes da P9.7). Agora
  usam `$TARGET` direto (mesma correção da P9.7). Validado: URLs bem-formadas, shellcheck limpo

**P1 restante (ordem de retorno):**
- (nenhum — itens P1 concluídos; próximo é o backlog P2)

## P2 — BACKLOG

dedup semântico; trend multi-scan; relatório PDF (WeasyPrint); CSPM (prowler);
IaC/container (trivy); multi-tenant.

## Follow-ups conhecidos (não feitos)

- **BOLA:** confirmar se os findings de P9.5 chegam ao `findings.json` enriquecido + SARIF
  (hoje entram via agregação do report). Adicionar P9.5 ao `pipeline.py` PHASES (hoje só roda
  no scan full, não como passo isolado do orquestrador)
- **Cobertura PCI:** porte seletivo do swarm-pci (PAN/Luhn, Magecart, tag `pci_req`); escopo
  via `cde_targets.txt` (gitignored). Design aprovado, implementação pendente
- **Propagação do bearer ao active scanner + browser do AJAX:** o replacer cobre o ZAP Spider
  clássico, mas validação ao vivo mostrou que o **active scanner** e o **browser do AJAX Spider**
  rodam deslogados (requests sem `Authorization`). Propagação completa exige mais que o replacer
  (httpSender script, ou contexto forced-user adaptado a bearer estático). Não bloqueia a fronteira
  do BOLA, que depende do histórico do spider — já autenticado
- **OpenAPI seeding — só paths GET via `accessUrl`:** o fallback registra os nós no site-tree
  do ZAP, mas não passa schemas de request (body/params) para endpoints mutantes (POST/PUT). Os
  IDs de path usam um valor de amostra (`1`), então 404 é comum sem credenciais — bom p/ estrutura,
  insuficiente p/ derivar IDOR read 2xx na P9.7. Follow-up: sanitizar nomes inválidos e reimportar
  via `openapi/action/importFile` (recupera cobertura mutante do active scanner)

## Pendência operacional

Higienização de dados de scan/CDE — **detalhes e comandos só na memória local** (nunca aqui).

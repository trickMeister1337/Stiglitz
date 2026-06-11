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
- ✅ **dedup semântico** (`lib/dedup.py`): colapsa duplicatas cross-tool + variantes de path/param (estágio 1 fingerprint) + fuzzy por CVE/título/evidência blocado por host (estágio 2). Auto-merge agressivo, proveniência no finding. Integrado no scan (`stiglitz_report.py`) e no RED (`evidence.py`); `STIGLITZ_DEDUP=0` desliga. CLI + lógica pura

**P1 restante (ordem de retorno):**
- (nenhum — itens P1 concluídos; próximo é o backlog P2)

## P2 — BACKLOG

trend multi-scan; relatório PDF (WeasyPrint); CSPM (prowler);
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
- **base-url duplo-esquema na P9.6 (OAuth):** o bloco da P9.6 invoca `oauth_audit` com
  `--target "https://${TARGET}"`, mas `TARGET` já carrega esquema → `https://https://...`. A P9.7
  tinha o mesmo padrão e foi corrigida (usa `$TARGET`); a P9.6 permanece com o padrão antigo (não
  verificado se zera a fase como zerava na bizlogic). Avaliar/corrigir
- **Dedup semântico × dedup bizlogic (P9.7) — decisão de comportamento:** o dedup semântico (P2)
  roda a jusante da dedup especializada P9.7×P9.5 no `stiglitz_report.py`. Quando P9.5 inconclusiva
  e P9.7 confirmada colidem no mesmo recurso (mesmo fingerprint), o dedup semântico as **mescla em
  1** (o confirmado/maior-severidade vence como representante; a outra fonte entra em `sources`) —
  decisão deliberada: dedup semântico é autoritativo, fidelidade preservada (confirmado não some),
  muda só a contagem. `test_inconclusive_access_does_not_suppress_confirmed_bizlogic` reflete isso

## Pendência operacional

Higienização de dados de scan/CDE — **detalhes e comandos só na memória local** (nunca aqui).

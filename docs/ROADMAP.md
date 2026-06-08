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

**P1 restante (ordem de retorno):**
1. ZAP bearer-token session propagation (fronteira do BOLA) + fix render AJAX
   (firefox/geckodriver no env)

## P2 — BACKLOG

dedup semântico; trend multi-scan; relatório PDF (WeasyPrint); CSPM (prowler);
IaC/container (trivy); multi-tenant.

## Follow-ups conhecidos (não feitos)

- **BOLA:** confirmar se os findings de P9.5 chegam ao `findings.json` enriquecido + SARIF
  (hoje entram via agregação do report). Adicionar P9.5 ao `pipeline.py` PHASES (hoje só roda
  no scan full, não como passo isolado do orquestrador)
- **Cobertura PCI:** porte seletivo do swarm-pci (PAN/Luhn, Magecart, tag `pci_req`); escopo
  via `cde_targets.txt` (gitignored). Design aprovado, implementação pendente

## Pendência operacional

Higienização de dados de scan/CDE — **detalhes e comandos só na memória local** (nunca aqui).

# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Contexto do Ambiente

Este é um ambiente de red team / pentest autorizado. Os scripts são ferramentas de segurança ofensiva para uso exclusivo em ambientes com Rules of Engagement (RoE) assinado.

**Idioma:** mensagens de console/operador são em PT-BR; os **relatórios HTML** (deliverables) são em **inglês** — manter essa separação ao editar.

---

## Scripts Principais

### `stiglitz.sh` — Scanner de Recon e Varredura (12 fases)
Pipeline de recon e varredura de vulnerabilidades. Metodologia de risco: **KEV > EPSS > CVSS**.

1. **Fase 1** — Descoberta de subdomínios (subfinder)
2. **Fase 2** — Mapeamento de superfície (httpx tech-detect + nmap)
3. **Fase 2.5** — WAF detection (wafw00f) + tech profile adaptativo
4. **Fase 3** — TLS (testssl) — em paralelo com nuclei
5. **Fase 4** — Varredura de vulnerabilidades (nuclei, tags adaptativas)
6. **Fase 5** — Confirmação ativa de exploits (min 60% confidence)
7. **Fase 6** — Enriquecimento CVE/EPSS (NVD + FIRST.org + CISA KEV)
8. **Fase 8** — Email Security (SPF/DMARC/DKIM)
9. **Fase 9** — ZAP Spider + Active Scan
   - **Bearer token / header custom** são injetados no HttpSender do ZAP (replacer) **antes** do spider (helper `zap_inject_auth_headers`), de modo que o ZAP Spider e o histórico que a Fase 9.5 (BOLA) consome rodem autenticados — expandindo a superfície de endpoints protegidos descobertos. Pré-check de `exp` do JWT (`jwt_audit.exp_status` + CLI `exp-check`) avisa (sem abortar) se o token expira dentro da janela estimada do scan. (Obs.: o replacer cobre o spider clássico; active scanner e browser do AJAX ainda rodam deslogados — ver follow-up no ROADMAP.) As chamadas `replacer/action/addRule` passam `matchRegex=false` (exigido pela API do ZAP 2.17).
   - **Escopo/sessão (fronteira de RoE):** a Fase 9 roda `core/action/newSession` ao iniciar (zera site tree/histórico/contextos herdados de um daemon ZAP **reutilizado** — que podiam ser de OUTRO alvo/cliente) e restringe o escopo ao alvo (`includeInContext` + `setContextInScope`). Assim o AJAX spider (`inScope=true`, mesmo sem auth) não segue redirects de login (ex.: OAuth → `accounts.google.com`) e o active scan recursivo não ataca hosts fora de escopo (sem fallback p/ site arbitrário da árvore). O `DomXssScanRule` (plugin 40026) é desabilitado por padrão (trava ~130s/host no marionette quebrado e podia abortar a fase com `zap_alerts.json` vazio); `STIGLITZ_ZAP_DOMXSS=1` reativa.
   - **AJAX Spider** seleciona o browser por preflight (`chrome-headless` preferido; `firefox-headless` como fallback), com degradação graciosa quando nenhum browser está disponível.
   - **Fase 9.5** — Access Control (BOLA/BFLA) — opt-in com `--token-a` + `--token-b`: replay multi-token de requisições do ZAP, confirma acesso indevido por tripla A/B/unauth + canário de corpo
   - **Fase 9.6** — OAuth/OIDC Audit — descoberta passiva (well-known + params do ZAP) de redirect_uri/PKCE/state/nonce/implicit flow; probes ativos opt-in com `--oauth-active` (dry-run sob `STIGLITZ_PROFILE=production`)
   - **Fase 9.7** — Business Logic Authz (`lib/bizlogic_scan.py`) — reusa `lib/bizlogic.py`: read-only auto-derivado (idor_read/privesc) do histórico ZAP + 2 tokens; mutantes (idor_write/amount-tampering/race/idempotency) opt-in via `--bizlogic-mutate` + `bizlogic.yaml` + gating de profile/RoE. Dedup vs P9.5 por `(host, path, vuln_class)`.
10. **Fase 10** — JS Analysis + secret detection (katana)
11. **Fase 10.5** — Testes complementares (ffuf + smuggler + wpscan/joomscan/droopescan + trufflehog)
12. **Fase 11** — Relatório HTML + findings.json (enriquecido com `state` por fingerprint) + SARIF 2.1.0 (com `partialFingerprints`)
13. **Fase 12** — Tracker sync (DefectDojo, opt-in) — push do SARIF via reimport-scan

```bash
bash stiglitz.sh <target>                       # scan único
bash stiglitz.sh <target> --token "eyJ..."      # scan autenticado (--token/-t é apelido de --token-a)
bash stiglitz.sh <target> --token-a "<jwt>" --token-b "<jwt2>"  # habilita BOLA/BFLA (Fase 9.5)
bash stiglitz.sh <target> --osint-dir osint_*/  # reaproveita descoberta do osint.sh
bash stiglitz.sh <target> --proxy socks5h://127.0.0.1:9050  # roteia tráfego do alvo pelo proxy
```

**Proxy (opt-in, `--proxy`/`STIGLITZ_PROXY`):** roteia **só o tráfego do alvo** (Go tools, testssl, curl-ao-alvo, ZAP upstream, módulos lib via `lib/netproxy.py`, e curl via subprocess em bola/cors/headers/oauth/poc_validator) pelo proxy HTTP/SOCKS. **nmap é pulado** em modo proxy (sem proxy nativo — rodá-lo direto vazaria atribuição); **testssl é pulado sob SOCKS** (seu `--proxy` é HTTP-only). Controle (ZAP API localhost), enriquecimento (NVD/EPSS/KEV), notificações e subfinder (DNS passivo) vão **direto**. SOCKS para os módulos Python requer PySocks; sem ele a sondagem é pulada (nunca conexão direta). Proxy autenticado (`user:pass@`) não é suportado nesta entrega.

As fases são individualmente invocáveis (usado pelo `pipeline.py`):
```bash
bash stiglitz.sh <target> --outdir <dir> --only-phase "P3 P4"
```

Output: `scan_<domain>_<timestamp>/` (relatório `stiglitz_report.html`, gerado por `stiglitz_report.py`).

### `pipeline.py` — Orquestrador de Fases (Python)
Dirige as fases do `stiglitz.sh` via `--only-phase`, com **checkpoint real** (pula fases já concluídas), retry por fase, dry-run e logging. A lógica das ferramentas permanece no `stiglitz.sh`; aqui mora só a orquestração. P3+P4 rodam como unidade combinada (paralelismo testssl/nuclei). A fase **P9 também é combinada** (`P9 P9_5 P9_6 P9_7`): as sub-fases de authz (Access Control/OAuth/BizLogic) consomem o ZAP vivo iniciado pela P9 — que é encerrado no `trap EXIT` a cada invocação —, então rodam na mesma invocação; o gating por token degrada sozinho quando ausente.

```bash
python3 pipeline.py <target>                       # scan completo orquestrado
python3 pipeline.py <target> --dry-run             # só o plano
python3 pipeline.py <target> --outdir <dir>        # retomar scan interrompido
python3 pipeline.py <target> --retries 2 --only P1,P3_P4,P11
```

Estado em `<outdir>/raw/.pipeline_state.json`. `--no-resume` força re-run limpo.

### `stiglitz_red.sh` — Engine de Exploração Automatizada (8 fases)
Consome resultados do scan e executa exploração (recon → surface → crawl → sqli → xss → brute → services → report).

```bash
bash stiglitz_red.sh -t <target> --standalone -p <profile>   # standalone
bash stiglitz_red.sh -d ~/scan_<domain>_<timestamp>/         # consumindo scan
bash stiglitz_red.sh -t <target> --standalone --dry-run      # simulação
```

Output: `stiglitz_red_<target>_<timestamp>/` (relatório `stiglitz_red_report.html`).

### `osint.sh` — Coleta de Inteligência Pré-Engajamento (10 fases)
Coleta passiva/semi-ativa executada **antes** do scan ativo: Domain Intel, subdomain discovery passivo, email/employee harvesting, historical URLs, GitHub dorking, HIBP, Shodan, cloud surface, build de outputs, relatório.

```bash
bash osint.sh <target>
bash osint.sh <target> --shodan-key $KEY --hibp-key $KEY --github-token $TOKEN
echo "SHODAN_API_KEY=xxx" >> ~/.osint.conf       # config persistente (chmod 600)
bash osint.sh <target> --no-roe                  # pular confirmação RoE (CI/CD)
```

Output: `osint_<domain>_<timestamp>/` — arquivos-chave: `targets_enriched.txt`, `leaked_creds.csv`, `osint_summary.json`, `osint_report.html`. Integra via `stiglitz.sh <target> --osint-dir osint_*/`.

**Subdomain takeover (Fase 8 / cloud surface) — híbrido:** `dnsx` coleta CNAMEs dos subdomínios vivos → `lib/takeover.py` filtra os **externos ao apex** (`BASE_DOMAIN`) → `nuclei -tags takeover` confirma por fingerprint de body → `cloud/takeover_candidates.csv` (schema legado `subdomain,cname,service,status`, status `CONFIRMED`). Degrada com `warn` no terminal quando `dnsx`/`nuclei` faltam, sem abortar a fase. O `validate_tools` (preflight) cobre `nuclei`/`shodan` e avisa toda dependência/chave de API ausente (Hunter/Shodan incluídos).

### `stiglitz_full.sh` — Orquestrador End-to-End
Executa `osint.sh → stiglitz.sh → stiglitz_red.sh` em sequência e gera índice HTML consolidado (`index.html`).

```bash
bash stiglitz_full.sh -t <target> [-p staging] [--skip-osint] [--skip-red] [--dry-run]
```

Output: `full_<domain>_<timestamp>/`.

### `stiglitz_batch.sh` — Multi-target
```bash
bash stiglitz_batch.sh -f targets.txt -p staging [--workers N]
```

### `stiglitz_diff.py` — Comparação scan-a-scan
Gera diff HTML entre dois scans (tracking de remediação).

### `stiglitz_track.py` — Push de findings/estado para trackers (opt-in)
Runner standalone que lê um scan dir (`findings.json` + `raw/state_summary.json`) e
dispara os trackers habilitados via env (hoje: DefectDojo, via reimport-scan SARIF).
No-op informativo quando nenhum configurado. Também é chamado pela fase **P12** do `stiglitz.sh`.

```bash
python3 stiglitz_track.py <scan_dir|findings.json>
DEFECTDOJO_URL=https://dd.local DEFECTDOJO_TOKEN=xxx python3 stiglitz_track.py scan_*/
```

Env: `DEFECTDOJO_URL`, `DEFECTDOJO_TOKEN` (obrigatórias p/ habilitar), `DEFECTDOJO_PRODUCT`,
`DEFECTDOJO_ENGAGEMENT`, `DEFECTDOJO_VERIFY_SSL` (default `true`).

---

## Perfis de Execução

| Perfil | sqlmap L/R | Brute Force | Uso |
|--------|-----------|-------------|-----|
| `staging` | 3/2 | Sim | Homolog/QA |
| `lab` | 5/3 | Sim | Lab descartável |
| `production` | 1/1 | Não | Prod (janela aprovada) |

---

## Módulos `lib/`

Os módulos Python e bash vivem em `lib/` como **arquivos reais** (lidos diretamente, NÃO re-extraídos de heredocs).

| Arquivo | Responsabilidade |
|---------|-----------------|
| `parsers.py` | Parse de Nuclei JSONL, ZAP JSON, extração de URLs e CVEs |
| `evidence.py` | Coleta e consolidação de evidências de todas as fontes |
| `report_generator.py` | Gera `stiglitz_red_report.html` (relatório RED, estilo Big4, EN) |
| `poc_validator.py` / `poc_generator.py` | Confirmação ativa + geração de PoCs |
| `oob.py` | Confirmação Out-of-Band (OAST) via interactsh-client — SSRF/RCE/SSTI cego. Opt-in via `INTERACTSH_SERVER` (self-hosted); desabilitado por padrão |
| `cve_enricher.py` | Enriquecimento NVD/EPSS/KEV com cache diário |
| `js_analysis.py`, `email_security.py`, `security_headers.py`, `secscan.py` | Coletores das fases do scan. `email_security.py`: SPF/DMARC/DKIM com herança organizacional de DMARC (RFC 7489 §6.6.3 — sobe ao eTLD+1, honra `sp=`) + downgrade MX-aware (host sem MX → impacto rebaixado) |
| `js_chunks.py` | Helpers puros consumidos por `js_analysis.py`: `webpack_chunk_urls` resolve os **lazy chunks** do manifest webpack (`i.u`: id→hash/nome + public path) — código real de SPAs que não aparece como `<script src>` (antes só a entry era varrida); `is_js_payload` é a **guarda anti-FP de catch-all** (SPA devolve index.html 200/text/html p/ path inexistente → nunca varrer HTML como JS, origem de falso "secret em bundle"). Lógica pura + CLI (`chunks <entry.js> <url>`) |
| `httpx_parse.py` | Parsing estruturado da saída `httpx -json` (Fase 2): `parse_jsonl` + `tech_inventory` (deriva tech de `tech`/`webserver`, nunca do `title` — evita que título HTTP/HSTS virem "tecnologia") + `to_legacy_text` (regenera o `httpx_results.txt` legado: URL na 1ª coluna + tokens CDN/tech p/ o detector de edge). Consumido por `tech_profile.py`. Lógica pura + CLI (`to-txt`) |
| `service_versions.py` | Parse do nmap XML (`-sV --script vulners`) → `service_findings.json`: versões de serviços de rede + CVEs por banner (software desatualizado). Usa `defusedxml` |
| `bola.py` | Detecção de BOLA/IDOR e BFLA (OWASP API #1, fase P9.5) — reproduz requisições do ZAP com dois tokens (`--token-a`/`-b`), confirma acesso indevido por tripla A/B/unauth + canário de corpo → `access_control.json` (classes `bola`/`idor_read_pii`/`bfla`, com fingerprint). Só GET/HEAD/OPTIONS; tokens via env. Lógica pura + CLI |
| `oauth_audit.py` | Auditoria OAuth 2.0/OIDC (fase P9.6) — well-known + params do ZAP → findings de `redirect_uri` (CWE-601), PKCE ausente/downgrade, state/nonce, implicit flow. Probes ativos opt-in (`--oauth-active`), dry-run em `production`. Lógica pura + CLI; `send_fn` injetável (testável sem rede) |
| `bizlogic_scan.py` | Builder de config do `bizlogic` para a fase P9.7 do scan: deriva read-only do dump ZAP (`bola.parse_zap_messages`) + claims JWT (`jwt_audit`); mescla `bizlogic.yaml` para mutantes; grava `raw/bizlogic_findings.json`. Lógica pura + CLI |
| `openapi_seed.py` | Fallback de seeding OpenAPI/Swagger (fase P9): quando o import nativo do ZAP rejeita um spec válido (ex.: nomes de schema .NET com backtick fora de `^[a-zA-Z0-9.\-_]+$`), extrai as URLs concretas do spec (resolve `{param}`, aplica `basePath`/`servers`) → `raw/openapi_urls.txt`, semeadas no ZAP via `accessUrl`. Lógica pura + CLI; sem rede |
| `takeover.py` | Detecção de subdomain takeover (osint.sh Fase 8) — filtro de CNAME externo ao apex + parse do JSONL do `nuclei` → `cloud/takeover_candidates.csv` (schema legado, status `CONFIRMED`). Lógica pura + CLI (`select-external`/`build-csv`); sem rede, sem domínio hardcoded |
| `scope.py` | Escopo de engajamento — `in_scope(url, scope_domains)` (host igual/subdomínio; **fail-open só sem escopo**) + `filter_in_scope` (tolera o formato `score|url` do `targets_scored.txt`, preserva a linha) + `filter_alerts_in_scope(alerts, domain)` (fronteira de escopo p/ alertas de scanner: o AJAX spider do ZAP pode navegar p/ terceiros e vazar findings ao relatório — filtrado no `stiglitz_report.py` antes de processar). Ponto único de verdade reusado pelo ingest/scoring e pelas fases ofensivas (brute/sqli/xss via `scope_guard`). Lógica pura + CLI (filtra stdin) |
| `finding_quality.py` | Heurísticas puras de qualidade de findings (consumidas pelo `stiglitz_report.py`): `is_low_value_zap_alert` (rebaixa FP previsível — Timestamp/Suspicious-Comments disclosure em `.js`/`.css` de terceiro — p/ info, sem deixar a reclassificação CWE inflá-lo); `enrich_vulnerable_js`/`identify_js_library` (dá nome+versão ao genérico "Vulnerable JS Library" do ZAP, ex.: Swagger UI 3.1.6); `coverage_gap_finding` (meta-finding info quando há superfície de API autenticada e nenhum token — evita falso "0 High"); `swagger_exposure_severity` (spec OpenAPI público → medium em escopo CDE, info fora); `severity_counts` (contagem canônica por severidade, espelha o findings.json — sumário do terminal e export usam a mesma base). Lógica pura |
| `tls_confirm.py` | Cross-check ativo de NULL/anon cipher (Fase 3 + `stiglitz_report.py`): o testssl reporta `cipherlist_NULL`/`aNULL` "offered" de forma FALSA atrás de LB/WAF (AWS ALB) — um único HIGH falso destrói a credibilidade do deliverable. Enumera os ciphers realmente negociáveis via `nmap ssl-enum-ciphers` (fonte independente, ignora o `compressors: NULL` benigno) e refuta o achado quando só há ciphers fortes → `raw/tls_confirm.json`; o report rebaixa o FP a info com nota. Também expõe `count_terminal_tls_issues` (CLI `count <testssl.json>`), que espelha o filtro de findings TLS do `stiglitz_report.py` (dedup por `id`, ignora `scanTime` + artefatos "not supported by local OpenSSL") para o sumário do terminal não divergir do `findings.json`. Lógica pura + runner injetável + CLI (`confirm <host> <port>`); pulado sob proxy (usa nmap) |
| `repro.py` | Bloco "How to Reproduce / Proof" do relatório (item 6 fintech): gate (confirmado/High/Critical), captura do comando real (curl/HTTP request) com fallback de template por classe, sanitização de Bearer/cookie/PAN/PII por padrão (`--repro-raw`/`STIGLITZ_REPRO_RAW=1` desliga), `safe_note` non-destructive p/ endpoints de dinheiro, e `render_panel_html` (EN). Lógica pura + CLI; reusa `pan_scanner`/`pii_detect`. Consumido pelo `stiglitz_report.py` |
| `netproxy.py` | Proxy opt-in (item 2 fintech) — lê `STIGLITZ_PROXY` (http(s)/socks5(h)). `make_opener`/`build_opener`/`urlopen` (drop-in) p/ módulos que tocam o alvo; `curl_proxy_args()` (`-x`) p/ curl via subprocess. HTTP via `ProxyHandler` (stdlib); SOCKS via PySocks (urllib) ou `-x` nativo (curl). **Fail-closed**: esquema desconhecido ou SOCKS-sem-PySocks → `ProxyUnavailable` (URLError) → o chamador pula, nunca conexão direta. `cve_enrich`/subfinder/notificações ficam diretos. Lógica pura |
| `cde_scope.py`, `pan_scanner.py`, `payment_page_monitor.py`, `pci_verdicts.py` | Cobertura PCI DSS restrita ao CDE (lê `cde_targets.txt`, gitignored): PAN com Luhn+máscara (3.5.1), integridade de scripts/Magecart (6.4.3/11.6.1), tag `pci_req`. Texto dos findings em EN (deliverable) |
| `finding_state.py` | Ledger de estado por `fingerprint`: reconcile NEW/PERSISTENT/RESOLVED/REOPENED com `first_seen`/`last_seen`/`resolved_at` + métricas (age, MTTR, SLA breach). Store JSON fora do repo em `STIGLITZ_STATE_DIR` (default `~/.stiglitz/state/`) — **nunca versiona dado de alvo**. Enriquece `findings.json` com `state` e grava `raw/state_summary.json` |
| `dedup.py` | Dedup semântico de findings (P2) — colapsa duplicatas cross-tool + variantes de path/param via fingerprint (estágio 1) e fuzzy por CVE/título/evidência blocado por host (estágio 2). Auto-merge agressivo; proveniência no finding (`sources`/`merged_from`/`merge_score`). Roda no scan (`stiglitz_report.py`, antes de state/SARIF) e no RED (`evidence.py`). `STIGLITZ_DEDUP=0` desliga; `STIGLITZ_DEDUP_THRESHOLD` ajusta. Lógica pura + CLI |
| `trackers/` (`base.py`, `defectdojo.py`) | Interface genérica de tracker + adapter DefectDojo (push via reimport-scan SARIF, dedup nativa por `partialFingerprints`). Opt-in via env; degrada sem erro (padrão `oob.py`). HTTP injetável (testável sem rede) |
| `recon.sh`, `crawl.sh`, `sqli.sh`, `xss.sh`, `brute.sh`, `msf.sh`, `web.sh` | Módulos bash do `stiglitz_red.sh` |

O relatório do **scan** (`stiglitz.sh`) é gerado pelo `stiglitz_report.py` (top-level), que deriva os KPIs dos arquivos em `raw/` quando as env vars não estão presentes (permite a fase P11 rodar standalone sob o `pipeline.py`).

---

## Ferramentas Externas Necessárias

**Go (ProjectDiscovery):** subfinder, httpx, nuclei, katana, ffuf
**Sistema:** nmap, sqlmap, metasploit, hydra, nikto, zaproxy, testssl.sh
**Python pip:** requests, wafw00f, trufflehog

```bash
nuclei -update && nuclei -update-templates
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
```

---

## Critérios de Confirmação de PoC (`poc_validator.py`)

- Threshold mínimo: 60% de confidence (`MIN_CONFIRM_CONFIDENCE`)
- Padrões externos **opcionais** em `vuln_patterns.json` (override; o módulo tem defaults inline para todas as consultas — a ausência do arquivo não é erro e degrada em silêncio)
- Lê alertas ZAP do XML, testssl, e resultados de email security (SPF/DMARC/DKIM)

Um exploit do RED é **CONFIRMADO** somente com: databases + tabelas enumeradas + dump_count > 0 + payload capturado.

---

## Validação

```bash
# Sintaxe bash
bash -n stiglitz.sh stiglitz_red.sh stiglitz_full.sh stiglitz_batch.sh osint.sh setup.sh lib/*.sh

# Lint (gate do CI = warning)
shellcheck --severity=warning stiglitz.sh stiglitz_red.sh stiglitz_full.sh stiglitz_batch.sh osint.sh setup.sh lib/*.sh

# Testes Python (suíte completa vive em tests/)
python3 -m pytest tests/

# Compilar módulos
python3 -m py_compile stiglitz_report.py pipeline.py lib/*.py
```

CI (`.github/workflows/ci.yml`): 3 jobs — bash syntax + shellcheck (gate warning) + smoke dry-run; unit tests; integration scan (Juice Shop).

**Audit trail (RED):** o `audit.log` é um hash-chain tamper-evident; com `STIGLITZ_AUDIT_KEY` definido, o `stiglitz_red.sh` grava no finalize um selo `audit.log.seal` = `HMAC-SHA256(chave, cabeça-do-chain)` (sem chave, degrada com `SEAL_SKIPPED`). Verificar offline:
```bash
python3 tests/verify_audit.py <scan_dir>/audit.log                                   # só o chain
python3 tests/verify_audit.py <scan_dir>/audit.log --seal <scan_dir>/audit.log.seal --key "$STIGLITZ_AUDIT_KEY"
```
Fronteira de ameaça: o selo detecta adulteração/re-encadeamento por quem tem acesso ao arquivo mas **não** à chave; não protege contra quem detém a chave (mesma máquina durante o run).

---

## Pós-Scan (Higiene de Dados)

```bash
tar czf results.tar.gz stiglitz_red_*/
gpg -c results.tar.gz
shred -vfz results.tar.gz
rm -rf stiglitz_red_*/
```

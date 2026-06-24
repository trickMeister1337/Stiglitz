# Changelog

All notable changes to Stiglitz are documented here. Dates are approximate.

## Unreleased

- **Reprodutibilidade de scan (motivado por duas runs do mesmo alvo gerarem relatórios divergentes)** — duas causas, dois fixes:
  - **Lock por-host (`lib/host_lock.sh`)** — o lock existente é por-OUTDIR (único por timestamp) e não impedia dois `stiglitz.sh <mesmo-host>` em paralelo, que disputavam o daemon ZAP (porta fixa) e o store de estado (`finding_state`, load→reconcile→save não-atômico entre processos) → ZAP cross-contaminado + métricas de estado divergentes. Novo lock por-host (PID-file + `flock` de vida curta na seção crítica, sem vazar fd p/ filhos; `kill -9` vira stale recuperável) serializa scans do mesmo host. Adquirido antes do `mkdir` do OUTDIR; liberado no cleanup. Escape hatches: `STIGLITZ_NO_HOSTLOCK=1`, `STIGLITZ_HOSTLOCK_WAIT=<s>`, `STIGLITZ_LOCK_DIR`.
  - **Descoberta de JS determinística (`lib/js_chunks.discover_js_urls`)** — o crawl em `js_analysis.py` usava um `set` como fronteira e `set.pop()` (ordem dependente do `PYTHONHASHSEED`, que varia por processo); com o teto de páginas, cada run varria páginas diferentes → entry bundles/lazy-chunks diferentes → findings de SCA (retire.js) divergentes (ex.: axios numa run, pdf.js na outra). Crawl extraído p/ função pura e injetável, com fronteira em lista (ordem de inserção) → seleção sob o teto reprodutível.
- **SCA: libs vulneráveis distintas deixam de colapsar numa só** — o `vuln_class` de todo finding do retire.js é `CWE-1395`, então o fingerprint (`vuln_class+host+path+param`) era idêntico p/ libs diferentes e o dedup as fundia (estágio-1 quando no mesmo chunk; estágio-2 fuzzy por título templatizado), descartando as de menor severidade — ex.: axios CRITICAL sobrevivia e **pdf.js/quill sumiam do relatório**. Fix: `retire_parse.py` emite `component`/`version`; `fingerprint.py` inclui `component@version` na chave **só quando presente** (corpus geral/state inalterados); `dedup._score` nunca funde componentes SCA distintos (a MESMA lib em chunks diferentes ainda colapsa). Validado regenerando o relatório de um scan real: 1 → 3 libs vulneráveis.
- **Criticidade: findings `estimated` não são rebaixados abaixo da ferramenta (`lib/criticality.py`)** — quando não há CVSS real (NVD/catálogo), o vetor base é retro-derivado da própria severity qualitativa; aplicar temporal (E:P/RC:R "teórico") + environmental e deixar a banda CAIR abaixo da `severity_tool` dava precisão falsa a uma estimativa (ex.: axios CRITICAL do retire.js virava HIGH: base 9.8 → temporal 8.9). Agora `score_finding` aplica um **piso** = `severity_tool` quando `score_source == "estimated"` — o environmental ainda pode ELEVAR (ativo CDE/confirmação), nunca é teto. Para `nvd`/`catalog` o modelo CVSS governa livremente (rebaixa e eleva) — inalterado. Validado: axios volta a CRITICAL no relatório de um scan real.
- **Correções de credibilidade do deliverable (3 apontamentos de validação ao vivo)** — três fontes de ruído/FP que chegavam ao relatório:
  - **Tech inventory poluído (`lib/tech_profile.py`)** — a Fase 2 passou a emitir `httpx -json` (`raw/httpx_results.jsonl`); o novo `lib/httpx_parse.py` deriva o inventário de `tech`/`webserver` (nunca do `title`), então título HTTP (`Not Found`) e flag `HSTS` deixam de virar "tecnologia". Efeito colateral resolvido: o framework real (ex.: Django) volta a ser detectado → dispara nuclei tags + ffuf profile dirigidos. O `httpx_results.txt` legado é regenerado a partir do JSONL (URL na 1ª coluna + tokens CDN/tech para o detector de edge).
  - **DMARC organizacional (`lib/email_security.py`)** — RFC 7489 §6.6.3: sem DMARC no FQDN, sobe ao domínio organizacional (eTLD+1) e honra a política herdada (`sp=` governa subdomínios) antes de cravar MISSING — elimina o HIGH falso de spoofing em subdomínios cobertos pelo apex. Acrescenta downgrade MX-aware (host sem MX não envia/recebe email → impacto rebaixado) para SPF e DMARC.
  - **Contagem TLS do terminal (`lib/tls_confirm.py`)** — `count_terminal_tls_issues` espelha o filtro do `stiglitz_report.py` (dedup por `id`, ignora `scanTime` e artefatos "not supported by local OpenSSL"); o `stiglitz.sh` passou a usá-la, eliminando a divergência entre o sumário do terminal e o `findings.json`.
- **bizlogic no scan (Fase P9.7)** — `lib/bizlogic_scan.py` ativa a engine de lógica de negócio/authz no `stiglitz.sh`. Read-only (idor_read/privesc) auto-derivado do histórico ZAP + tokens; mutantes opt-in via `--bizlogic-mutate` + `bizlogic.yaml` + gating de profile (production→dry-run) + RoE. Findings deduplicados contra a P9.5 (access control) por `(host, path, vuln_class)` — a P9.5 confirmada vence. `lib/bizlogic.py` permanece intacto.

## v8.1 — Backlog menor: validators completos, PCI ampliado, OAuth no ZAP

Patch consolidando o backlog menor pós-v8.0:

- **Migração completa dos validators para plug-ins** — todos os 16 tipos (`sqli`, `xss`, `lfi`, `ssrf`, `cors`, `default_login`, `exposure`, `security_header`, `tls`, `email`, `auth_bypass`, `redirect`, `takeover`, `jwt`, `secret_aws`, `generic`) agora em `lib/validators/*.py`. Lógica anti-FP preservada por tipo (size-only-com-double-check em sqli/xss/lfi). Novo teste de cobertura garante que cada tipo retornado por `classify_vuln` tem plug-in registrado.
- **PCI Fase 7.5 multi-alvo** — itera `WEB_TARGETS` (cap configurável `PCI_ACTIVE_TARGETS_MAX=5` por padrão). Permite evidência ativa em múltiplos alvos sem explodir o nº de requests.
- **PCI Req 4.2.1 — TLS legado** — probe ativo via `openssl s_client -tls1`/`-tls1_1`: se o servidor aceita, registra finding HIGH; se recusa, evidência POSITIVA de conformidade.
- **PCI Req 12.10 — security.txt (RFC 9116)** — verifica `/.well-known/security.txt`. Ausência → LOW; presença → INFO com snippet do conteúdo.
- **OAuth refresh no ZAP path** — `confirm_zap` agora também refresca tokens (startup + retry em 401). Antes só `confirm_nuclei` tinha integração.
- **Total: 207 testes** (era 206 na v8.0; +1 de cobertura dos validators).

## v8.0 — Audit expandido, profile DSL, plug-in validators, trend, multi-target RED, OAuth refresh

Release maior — 6 entregas, conjuntamente:

- **Audit chain expandida** — todos os eventos do RED agora vão para a hash chain: `PHASE_START` / `PHASE_END` (com `result=ok|skipped`) e `FINDING_CONFIRMED` (sqli/xss/brute). `verify_audit.py` detecta adulteração em qualquer ponto. Útil para entrega forense em engagement regulado.
- **Profile DSL (JSON-Schema)** — `--profile-file engagement.json` em `stiglitz_red.sh`. `lib/profile_loader.py` valida estrutura/ranges (level 1-5, risk 1-3, techniques em enum, timeouts >0) e emite assignments bash com `declare -gA` (corrige bug aritmético quando o nome do perfil contém '-'). Permite perfis customizados por engagement sem editar `lib/profiles.conf`.
- **Plug-in de validadores** — registry em `lib/validators/` com decorator `@register("vuln_type")`. Migrados como POC: `sqli` e `xss` (mesma lógica anti-FP de tamanho-só-com-doublecheck). `poc_validator.validate()` faz dispatch para o plug-in se registrado, senão cai no if/elif legado (migração incremental).
- **Diff longitudinal cross-engagement** — `stiglitz_trend.py` aceita N scans (ordenados por timestamp) e gera HTML com sparkline SVG do risk score + tabela por scan + delta entre primeiro e último. Útil para tracking trimestral.
- **Multi-target paralelo no RED** — `stiglitz_red_batch.sh` com semáforo FIFO. `--targets file.txt --workers N --roe FILE -p staging` roda N exploits em paralelo, cada um com seu próprio outdir, audit.log e exploits_confirmed.csv. Manifesto agregado em `manifest.csv`.
- **OAuth refresh nativo** — `lib/oauth_refresh.py` com `is_enabled()`, `refresh_access_token()` (POST ao token endpoint), `apply_to_curl()` (injeta/substitui Authorization Bearer com `shlex.quote`). Integrado no `confirm_nuclei`: refresh inicial no startup + retry em 401 (uma vez, com novo token). Configurado via env `STIGLITZ_OAUTH_TOKEN_URL` / `STIGLITZ_OAUTH_REFRESH_TOKEN` / opcionais `CLIENT_ID`/`CLIENT_SECRET`/`GRANT_TYPE`.
- **+30 testes** — 4 audit (PHASE_END skipped/ok), 7 profile_loader, 6 validator plugins, 6 trend, 4 red_batch, 7 OAuth refresh (incl. mini-server HTTP local). Total: **123 unit + 26 pytest + 57 RED = 206 testes**.

## v7.8 — Caps OOB, audit hash chain, PCI ativo, refactor de relatório

- **Cap por scan no OOB** — `OOB_MAX_PAYLOADS` (default 25) limita quantos findings disparam payloads OOB num scan, evitando stress em alvos sensíveis. `OOB_EVIDENCE_BYTES` (default 800) controla o tamanho da evidência (raw-request do callback) anexada ao card.
- **Audit trail tamper-evident (hash chain)** — `stiglitz_red.sh` agora mantém um `audit.log` Merkle-like: cada entrada inclui `prev_hash:curr_hash` onde `curr_hash = sha256(prev || ts || event)[:16]`. Seed da chain é o SHA-256 do RoE — amarra criptograficamente o trail ao documento de autorização. `verify_audit.py` valida offline e detecta adulteração entre as duas entradas envolvidas.
- **Checagens PCI não-derivadas (Reqs 2/8/10)** — `pci_scan.sh` ganha a Fase 7.5 com checks ATIVOS que emitem evidência positiva ou negativa por requisito (em vez de inferir conformidade da ausência de findings):
  - Req 2.2.4 / 8.3 — probe de 25 combinações default × paths comuns (`/admin`, `/login`, etc.); registra `default-creds-probe` com hit ou ausência de hits.
  - Req 8.4 — heurística de MFA: procura no HTML por `mfa|otp|2fa|totp|authenticator`. Sem indicadores → MEDIUM com nota; com indicadores → INFO.
  - Req 10.2 — headers de correlação (`X-Request-ID`, `Correlation-Id`, etc.) presentes na resposta indicam logging robusto.
- **Refactor de `stiglitz_report.py`** — extração de 376 linhas em 3 módulos puros sob `lib/report/`: `cwe_data.py` (CWE→CVSS/impacto/remediação + helpers `cwe_enrich`/`cvss_to_sev`), `sarif.py` (`build_sarif` — SARIF 2.1.0 puro, testável), `exec_summary.py` (`build_exec_summary` — HTML do resumo executivo puro). `stiglitz_report.py` reduzido de 2432 a 2179 linhas; output dos relatórios permanece byte-equivalente (test_e2e verde).
- **Testes** — +14 (4 audit chain, 9 report modules, 1 PCI active controls). Total: 93 unit + 26 pytest + 57 RED = **176 testes**.

## v7.7 — OOB confirmation, argv-list exec, risk_score testable

- **Out-of-Band confirmation (`lib/oob.py`)** — Confirma vulnerabilidades cegas (SSRF/RCE/SSTI) via callbacks DNS/HTTP coletados por um `interactsh-client` self-hosted. Findings sem evidência por conteúdo recebem um payload OOB único; um callback correlacionado eleva o finding a CONFIRMADO com 98% de confiança. Por padrão usa apenas servidor self-hosted (`INTERACTSH_SERVER`) — não vaza callbacks para a infra pública da ProjectDiscovery.
- **Múltiplas engines SSTI** — `inject_oob_url` para `vuln_type=ssti` agora dispara payloads para Log4j (JNDI), Jinja2/Python, Twig, ERB, Velocity, Smarty, Spring SpEL e FreeMarker. Cada engine ignora o que não entende; qualquer callback confirma o finding.
- **`run_cmd` → argv-list por padrão** — `subprocess.run` agora é `shell=False` com lista de args (parse via `shlex.split` quando vem string). `shell=True` ficou isolado em `run_shell_pipe` para os 2 call sites que legitimamente precisam de pipe (chains do `openssl`). Fecha o último vetor arquitetônico de command-injection em `poc_validator`.
- **OOB com gate de escopo** — `poc_validator` lê `STIGLITZ_SCOPE_DOMAINS` do env e só dispara payloads OOB em hosts em escopo. Evita injetar em URLs externas que vazaram no output do scan.
- **`stiglitz_report.py` testável** — lógica do Risk Score (KEV>EPSS>CVSS, caps por componente, banda crítica gated por crítico-real-ou-KEV) extraída para `lib/risk_score.py` como função pura. Output do relatório permanece byte-equivalente; agora há cobertura com valores absolutos.
- **Brand-neutral reports** — relatórios consolidado e de scan deixam de mencionar marca do cliente.
- **`interactsh-client` flags corretas** — `-s`/`-t` em vez das antigas.
- **Testes** — +18 (10 risk_score com valores absolutos, 4 perfil production, 2 OOB SSTI multi-engine, 2 gate de escopo do OOB). Total: 79 unit + 26 pytest + 57 RED = **162 testes**.

## v7.6 — Safety, scope & injection hardening

Security-focused pass closing gaps that mattered most for an offensive tool.

- **Scope enforcement in RED** — `stiglitz_red.sh` now hard-filters `targets_scored.txt` by `SCOPE_DOMAINS` (host == domain or subdomain). Out-of-scope hosts captured from scan output (external redirects, partner CDNs) can no longer become sqlmap/dalfox/hydra targets.
- **Profiles consolidated + production hardened** — removed the dead `profiles/*.conf` (never sourced; only `lib/profiles.conf` is). Production now genuinely restricts: sqlmap technique `BEU` (no stacked/time, read-only; staging `BEUT`), Metasploit runs `check`-only (no exploit/auxiliary firing) when payload is `NONE`, and nmap uses `-T2`.
- **Authorization gate hardened** — env-var bypass renamed/standardized to `STIGLITZ_AUTHORIZED` and now **requires a `--roe <file>`** (signed Rules of Engagement; SHA-256 logged to the audit trail). Non-interactive runs without orchestration abort. `stiglitz_full.sh` requires `--roe` for any non-dry exploitation.
- **Command-injection fixes** — `poc_validator` no longer runs nuclei/ZAP-derived data through an unsanitized `shell=True`: all target-controlled values are `shlex.quote`d and Nuclei `curl-command` strings with shell metacharacters are rejected. Bash heredocs in `stiglitz_full.sh` switched to env-passed values (no string interpolation); `TARGET`/`OUTDIR`/scope domains are validated against a strict charset.
- **`--dry-run` is honest end-to-end** — `stiglitz.sh` and `osint.sh` now understand `--dry-run` (print plan, run no tools); previously `stiglitz_full.sh --dry-run` silently launched real scans.
- **False-positive reduction in confirmation** — size-only response diffs no longer confirm SQLi/XSS/LFI on their own (they require double-check corroboration); `build_safe_baseline` now neutralizes double-quoted payloads too; removed a duplicate `_clamp_confidence`; TLS findings without active re-verification are labeled testssl-derived rather than independently confirmed.
- **Misc correctness** — `parsers.py` domain filter fixed (`lstrip("www.")` corrupted hosts like `web.com`); `stiglitz_diff.py` keys no longer include severity (eliminating phantom new/fixed) and the risk-score regex matches the current English label; PCI SLA age now measured from discovery (`first_seen`) instead of CVE publication year; `epss_bonus` capped; batch ZAP `pgrep` pattern fixed.
- **Tests** — new coverage for poc_validator confidence/injection, the domain filter, and RED scope enforcement.

## v7.5 — Report & risk-score quality

- **Non-saturating risk score** — previously summed per-URL occurrences (the same alert across N URLs blew up the number; almost every scan hit 100/100). Now uses unique types with a base tier from the highest severity present + a quantity bonus with diminishing returns. The CRITICAL band requires a real critical finding or a KEV CVE — soft bonuses (EPSS/JS) cannot manufacture a CRITICAL on their own.
- **Confirmed exploit ≠ verified** — active confirmation separates abusable vulnerabilities (default-login, SQLi, weak ciphers) from hardening verifications (headers, HSTS/CAA, TLS config). Distinct card badges (✓ EXPLOIT CONFIRMED / ✓ VERIFIED) and separate report sections.
- **Effort × Impact matrix** — Big4-style prioritization grid with the high-impact/low-effort quadrant highlighted as ★ quick wins.
- **Diff with previous scan** — "Evolution Since Last Scan" section: new / fixed / persistent vs the previous scan of the same domain.
- **CVSS vector on cards** — shows the full vector (`CVSS:3.1/AV:N/...`) plus a decode of the exploitability fields (attack vector, complexity, privileges, interaction).
- **False-positive reduction** — JS secrets: "Hardcoded Password" no longer matches UI labels; "Private Key" requires a full PEM block. poc_validator no longer flags testssl metadata (scanTime) as an exploit.
- **Scheme normalization** — `target.com` without `https://` now assumes HTTPS, fixing an HTTP 000 abort on HTTPS-only targets.
- **Full English report** — the entire HTML/JSON report and all finding text translated to English.

## v7.4 — stiglitz.sh modularization

The main scanner carried ~2,500 lines of Python embedded in 12 bash heredocs — no syntax check, lint, tests or debugging possible. Extracted into standalone modules, shrinking the scanner from **4,991 → ~1,870 lines**.

- **Report generator → `stiglitz_report.py`** (1,817 lines). Validated byte-identical HTML/JSON output.
- **11 collection heredocs → `lib/*.py`** (scan_metadata, security_headers, version_fingerprint, tech_profile, monitoring_check, secscan, cve_enrich, email_security, zap_config_fix, js_analysis, ratelimit_check). Bodies validated byte-identical to the originals.
- **`eval` removed** from the Nuclei invocation — flag/input strings became bash arrays, which correctly preserve arguments with spaces (e.g. `-H "User-Agent: ..."`).
- **Active confirmation linked to cards** — findings with a matching confirmation show a badge in the report.
- **CI hardened** — new `py_compile` step validates the report generator and all `lib/*.py` on every push/PR.

## v7.3 — Adaptive scanning by technology stack

The scanner detects the target's stack and automatically tunes every tool (Nuclei, ffuf, PROBES, CMS scanners) based on what it finds.

- **Tech Profile Builder** — aggregates httpx `-tech-detect`, katana URL fingerprinting and confirmed version PROBES into `raw/tech_profile.json`.
- **Dynamic Nuclei tags** — extends base tags with stack-specific tags (WordPress → `wordpress,wp`; Spring Boot → `spring,springboot,actuator`; etc.).
- **Expanded version PROBES** — WordPress, Drupal, Joomla, Spring Boot Actuator, Django Debug, Laravel Debug, Apache Struts.
- **Conditional ffuf wordlists** — 10 stack profiles select extra paths on top of the generic list.
- **Conditional CMS scanners** — wpscan / joomscan / droopescan triggered automatically when the CMS is detected (`WPSCAN_API_TOKEN` supported).
- **Technology Inventory report section** — component, detected version, status, known CVEs and detection source.

## v7.3.1 — Report counting & CI fixes

- TLS and email findings now included in the master findings list (`all_f`) — terminal and HTML counts match.
- `email_security` dict converted to standardized findings with CWE.
- CI: `pytest` added via `requirements-dev.txt`; install errors no longer silently swallowed.

## v7.2 — Expanded surface coverage + exploitation engine improvements

- **Dangerous-service scan** — nmap now includes Redis, MongoDB, Elasticsearch, Kubernetes API, etcd, CouchDB, Memcached, MSSQL, PostgreSQL, MySQL. Exposed databases highlighted.
- **security.txt (RFC-9116) check** and **internal IP exposure** detection.
- **Expanded ffuf wordlist** — PHP debug, .NET ELMAH, Laravel, Symfony paths.
- **HTTP form brute force** — auto-detects `/login`, `/signin`, `/auth` and runs hydra `http-post-form`.
- **Advisory-URL filter** — excludes advisory domains (nvd.nist.gov, github.com/security, etc.) from SQLi/XSS targets.
- **`--swarm-dir`** integrates origin-scan findings into the exploitation report.

## v7.1 — Tooling updates

- Go 1.26.3 toolchain; recompiled all ProjectDiscovery binaries.
- sqlmap 1.10.5, nikto 2.6.0, hydra 9.8-dev, katana 1.6.1, trufflehog 3.95.3.
- amass intentionally pinned to v3.19.2 (v5 breaks the CLI interface).

## v7.0 — Full pipeline + CI/CD

- **End-to-end orchestrator** chaining OSINT → recon/scan → exploitation → PCI, with a single authorization gate and consolidated HTML index.
- **Exploitation engine refactored** into a thin orchestrator delegating to independent `lib/` modules (recon, crawl, sqli, xss, brute, msf, web).
- **Scan-completion notifications** — Telegram, Slack, Microsoft Teams.
- **Automatic scan diff** — detects the previous scan of the same domain and generates a diff report.
- **CI/CD** — GitHub Actions syntax check + Python unit tests on every push/PR.

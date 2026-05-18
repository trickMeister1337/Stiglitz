# SWARM

> Pipeline automatizado de pentest ofensivo — reconhecimento, varredura, exploração e relatório em um único comando.

[![Shell](https://img.shields.io/badge/Shell-Bash-4EAA25?logo=gnu-bash)](https://www.gnu.org/software/bash/)
[![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?logo=python)](https://python.org)
[![CI](https://github.com/trickMeister1337/SWARM/actions/workflows/ci.yml/badge.svg)](https://github.com/trickMeister1337/SWARM/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Author](https://img.shields.io/badge/Author-trickMeister1337-red)](https://github.com/trickMeister1337)

---

## ⚠ Aviso Legal

**Uso exclusivo em ambientes com autorização formal documentada (Rules of Engagement).**

Todos os scripts exigem confirmação explícita antes de qualquer execução ativa.
Uso não autorizado é crime (Art. 154-A CP / CFAA / Computer Misuse Act).

---

## Visão Geral

O SWARM é uma suite completa de segurança ofensiva composta por scripts independentes que se integram em pipeline:

```
[osint.sh] → [swarm.sh] → [swarm_red.sh] → relatório HTML
  OSINT        Recon/Scan    Exploração

[swarm_full.sh] — orquestra as três fases acima em um único comando
[pci_scan.sh]   — scanner de conformidade PCI DSS (independente)
```

| Script | Função | Quando usar |
|---|---|---|
| `osint.sh` | Inteligência passiva pré-engajamento | Antes de qualquer scan |
| `swarm.sh` | Reconhecimento e varredura (11 fases) | Mapeamento da superfície |
| `swarm_red.sh` | Exploração automatizada (8 fases) | Após recon ou standalone |
| `pci_scan.sh` | Conformidade PCI DSS 4.0.1 | Ambientes de pagamento |
| `swarm_full.sh` | Pipeline completo em um comando | Relatório consolidado end-to-end |
| `swarm_batch.sh` | Wrapper multi-alvo para `swarm.sh` | Múltiplos alvos em série |
| `swarm_diff.py` | Comparação entre dois scans | Rastreamento de remediação |

---

## Últimas Atualizações

### v7.0 — Blackbox Engine + CI/CD + Pipeline Completo (Mai 2026)

- **`swarm_full.sh` adicionado** — orquestrador end-to-end que encadeia osint.sh → swarm.sh → swarm_red.sh → pci_scan.sh com gate único de autorização, índice HTML consolidado e métricas por fase
- **`swarm_red.sh` refatorado em arquitetura modular** — orquestrador thin de 845 linhas delegando para 7 módulos independentes em `lib/` (recon, crawl, sqli, xss, brute, msf, web)
- **Notificações ao finalizar scan** — suporte a Telegram, Slack e Microsoft Teams via variáveis de ambiente; disparadas ao término de `swarm.sh`, `swarm_red.sh` e `swarm_full.sh`
- **`swarm_diff.py` integrado ao pipeline** — ao finalizar cada scan, `swarm_red.sh` detecta automaticamente o scan anterior do mesmo domínio e gera relatório de diff (novos/corrigidos/persistentes)
- **CI/CD com GitHub Actions** — syntax check (`bash -n`) em todos os scripts incluindo `swarm_full.sh` + 42 testes unitários Python em cada push/PR
- **Testes expandidos de 18 para 42** — adicionadas classes `TestIngest` (11 testes) e `TestPocGenerator` (10 testes); bug real corrigido em `evidence.py` (falso-positivo de tabela sqlmap)
- **`osint.sh` e `pci_scan.sh` publicados** no repositório principal
- **`swarm_batch.sh` e `swarm_diff.py`** incorporados da branch de desenvolvimento
- **`lib/evidence.py`** — adicionadas funções `is_valid_url` e `strip_ansi`; filtro de timestamps falsos na extração de tabelas

---

## `osint.sh` — Inteligência Pré-Engajamento

Coleta passiva/semi-ativa executada **antes** do `swarm.sh`. Produz um mapa de superfície completo sem disparar alertas no alvo.

### Pipeline de 10 Fases

| Fase | Módulo | O que faz |
|---|---|---|
| 1 | Domain Intelligence | WHOIS, DNS, crt.sh, SPF/DMARC/DKIM, ASN |
| 2 | Subdomain Discovery | subfinder + amass + crt.sh + dnsx |
| 3 | Email & Employee Harvesting | theHarvester + Hunter.io |
| 4 | Historical URLs | waybackurls + gau + endpoints dinâmicos |
| 5 | GitHub Dorking | trufflehog + GitHub Search API |
| 6 | Leaked Credentials | HaveIBeenPwned API v3 |
| 7 | Shodan Intelligence | hostname search + CVEs por IP |
| 8 | Cloud Surface | S3/Azure buckets + subdomain takeover |
| 9 | Build outputs | targets_enriched.txt + osint_summary.json |
| 10 | Relatório HTML | osint_report.html |

```bash
# Básico
bash osint.sh alvo.com

# Com APIs externas
bash osint.sh alvo.com \
    --shodan-key $SHODAN_KEY \
    --hibp-key $HIBP_KEY \
    --github-token $GITHUB_TOKEN

# Pular confirmação RoE (CI/CD)
bash osint.sh alvo.com --no-roe
```

**Arquivos gerados:**

| Arquivo | Uso |
|---|---|
| `targets_enriched.txt` | Subdomínios + IPs para `--osint-dir` no swarm.sh |
| `leaked_creds.csv` | Contas vazadas para hydra no swarm_red.sh |
| `osint_summary.json` | Metadados legíveis por máquina |
| `osint_report.html` | Relatório completo |

---

## `swarm.sh` — Reconhecimento e Varredura

Pipeline de 11 fases que mapeia a superfície de ataque completa, valida vulnerabilidades e gera relatório HTML.

### Pipeline de 11 Fases

```
  ┌──────────────────────────────────────────────────────────────┐
  │                    SWARM — Consultant Edition                │
  │                                                              │
  │  [1]  Subdomain Discovery   subfinder                        │
  │  [2]  Surface Mapping       httpx + nmap                     │
  │  [3]  TLS Analysis          testssl (paralelo com nuclei)    │
  │  [4]  Vulnerability Scan    nuclei (CVE + exposure + tech)   │
  │  [5]  PoC Confirmation      poc_validator.py (min 60%)       │
  │  [6]  CVE Enrichment        NVD API v2 + EPSS + CISA KEV     │
  │  [7]  WAF Detection         wafw00f + evasão passiva         │
  │  [8]  Email Security        SPF / DMARC / DKIM               │
  │  [9]  ZAP Active Scan       Spider + Ajax + Active Scan      │
  │  [10] JS Analysis           katana + trufflehog + ffuf       │
  │  [11] Relatório             HTML + sumário executivo + JSON  │
  └──────────────────────────────────────────────────────────────┘
```

```bash
# Básico
bash swarm.sh https://alvo.com

# Com output OSINT
bash swarm.sh https://alvo.com --osint-dir osint_alvo.com_*/

# Multi-alvo
bash swarm_batch.sh -f targets.txt -p staging

# Scan autenticado
bash swarm.sh https://alvo.com --token "eyJ..."

# Docker
docker run --rm -v $(pwd)/output:/swarm/output \
    trickmeister1337/swarm https://alvo.com
```

**Output gerado:**

| Arquivo | Conteúdo |
|---|---|
| `relatorio_swarm.html` | Relatório técnico completo com evidências e curl reproduzível |
| `sumario_executivo.html` | Página única de risco para gestão |
| `findings.json` | Export estruturado para SIEM/Jira |
| `raw/` | nuclei JSONL, ZAP alerts, TLS issues, JS analysis |

---

## `swarm_red.sh` — Exploração Automatizada

Motor de exploração que opera em dois modos: **Blackbox** (standalone a partir de uma URL) ou **Integração** (consumindo output do `swarm.sh`).

### Pipeline de 8 Fases

```
  ┌──────────────────────────────────────────────────────────────┐
  │                    SWARM RED v7.0                            │
  │                                                              │
  │  [1] RECON       subfinder → subdomínios                     │
  │       ↓          httpx    → hosts ativos                     │
  │  [2] SURFACE     nmap     → portas/serviços/versões          │
  │       ↓                                                      │
  │  [3] CRAWL       katana   → endpoints + JS                   │
  │       ↓          ffuf     → directory fuzzing                │
  │  [4] INGEST      Scorer   → priorização por parâmetros       │
  │       ↓          CVEs     → extração de nuclei/ZAP           │
  │  [5] SQLi        sqlmap   → testes com tamper adaptativo     │
  │       ↓                                                      │
  │  [6] XSS         dalfox   → paralelo por URL                 │
  │       ↓                                                      │
  │  [7] BRUTE       hydra    → SSH/FTP/MySQL/RDP/SMB            │
  │       ↓                                                      │
  │  [8] SERVICES    nikto + msfconsole + searchsploit           │
  │       ↓                                                      │
  │  [REL] RELATÓRIO HTML Big4-style + auto-diff com scan anterior│
  └──────────────────────────────────────────────────────────────┘
```

```bash
# Blackbox standalone
bash swarm_red.sh -t https://alvo.com -p staging

# Integração com output do swarm.sh
bash swarm_red.sh -d scan_alvo.com_20260514_120000/

# Com escopo e autenticação
bash swarm_red.sh -t https://alvo.com \
    --scope-file escopo.txt \
    --auth-cookie "session=abc123" \
    --auth-header "Authorization: Bearer <token>"

# Apenas SQLi e XSS, sem brute force
bash swarm_red.sh -t https://alvo.com --only sqli,xss

# Simulação sem executar
bash swarm_red.sh -t https://alvo.com --dry-run

# Retomar scan interrompido
bash swarm_red.sh -t https://alvo.com --resume \
    --output-dir swarm_red_alvo_20260514_120000
```

### Perfis de Execução

| Parâmetro | `lab` | `staging` | `production` |
|---|---|---|---|
| sqlmap level/risk | 5 / 3 | 3 / 2 | 1 / 1 |
| sqlmap threads | 10 | 5 | 1 |
| Brute force | ✅ | ✅ | ❌ |
| Nikto | ✅ | ✅ | ❌ |
| MSF payload | reverse_tcp | reverse_tcp | NONE |
| XSS workers | 5 | 3 | 1 |
| Max exploits | 999 | 50 | 10 |

**`lab`** — Ambiente descartável. Sem restrições.  
**`staging`** — Homologação/pré-produção. Agressividade alta com limites razoáveis.  
**`production`** — Janela de manutenção aprovada. Impacto mínimo, sem dump, sem brute force.

---

## `pci_scan.sh` — Conformidade PCI DSS 4.0.1

Scanner de conformidade que cobre requisitos 1.3, 2.2, 3.5, 4.2.1, 6.x, 8.x, 11.x e 12.5.2.

> **Não substitui** ASV scan externo (Req 11.3.2) nem pentest humano (Req 11.4).

```bash
bash pci_scan.sh https://alvo.com
```

---

## `swarm_full.sh` — Pipeline Completo em Um Comando

Orquestrador que encadeia toda a suite em sequência com um único gate de autorização e gera um índice HTML consolidando os relatórios de todas as fases.

```
  osint.sh  →  swarm.sh  →  swarm_red.sh
     ↓              ↓              ↓
  OSINT          Recon          Exploit
     └──────────────┴──────────────┘
              full_<alvo>_<ts>/index.html
```

```bash
# Pipeline completo (padrão)
bash swarm_full.sh -t https://alvo.com

# Com perfil de produção, apenas recon (sem exploração)
bash swarm_full.sh -t https://alvo.com -p production --skip-red

# Pular OSINT (quando já foi executado antes)
bash swarm_full.sh -t https://alvo.com --skip-osint

# Simulação completa sem executar ferramentas
bash swarm_full.sh -t https://alvo.com --dry-run

# Com autenticação e escopo
bash swarm_full.sh -t https://alvo.com \
    --scope-file escopo.txt \
    --auth-cookie "session=abc123" \
    --auth-header "Authorization: Bearer <token>"
```

### Flags disponíveis

| Flag | Descrição |
|---|---|
| `-t, --target URL` | URL do alvo (obrigatório) |
| `-p, --profile` | `lab` / `staging` / `production` (padrão: `staging`) |
| `--skip-osint` | Pular fase OSINT |
| `--skip-scan` | Pular fase swarm.sh |
| `--skip-red` | Pular fase swarm_red.sh |
| `--dry-run` | Simular pipeline sem executar ferramentas |
| `--scope-file FILE` | Arquivo com domínios/IPs em escopo |
| `--auth-cookie` | Cookie de autenticação |
| `--auth-header` | Header de autenticação (ex: `Authorization: Bearer …`) |
| `--output-dir DIR` | Diretório base customizado |

### Output gerado

```
full_alvo.com_20260514_120000/
├── index.html              # Índice consolidado com links e métricas por fase
├── osint_alvo.com_*/       # Diretório OSINT
├── scan_alvo.com_*/        # Diretório swarm.sh
└── swarm_red_alvo.com_*/   # Diretório swarm_red.sh
```

O `index.html` exibe métricas por fase (subdomínios, findings, exploits confirmados), tempo de execução de cada etapa e links diretos para os relatórios individuais.

> Os scripts individuais continuam funcionando normalmente de forma independente — `swarm_full.sh` é uma opção adicional para quando você quer o relatório completo end-to-end de um único engajamento.
>
> Para scan PCI DSS, use `pci_scan.sh` separadamente após o pipeline.

---

## `swarm_diff.py` — Rastreamento de Remediação

Compara dois diretórios de scan e classifica vulnerabilidades em novas, corrigidas e persistentes. Integrado automaticamente ao final de cada execução do `swarm_red.sh`.

```bash
# Manual
python3 swarm_diff.py scan_alvo_anterior/ scan_alvo_novo/

# Com relatório HTML
python3 swarm_diff.py scan_anterior/ scan_novo/ --html
```

Output:
- Terminal colorido com contadores por severidade
- `swarm_diff_<timestamp>.html` com tabelas e KPIs de remediação

---

## Notificações

`swarm.sh` e `swarm_red.sh` enviam notificação ao finalizar. Configure via variáveis de ambiente:

```bash
# Telegram
export SWARM_TELEGRAM_TOKEN="<bot_token>"
export SWARM_TELEGRAM_CHAT="<chat_id>"

# Microsoft Teams (legacy connector ou Power Automate Workflow)
export SWARM_TEAMS_WEBHOOK="https://outlook.office.com/webhook/..."

# Slack / webhook genérico
export SWARM_NOTIFY_WEBHOOK="https://hooks.slack.com/..."
```

Todos os canais são independentes — você pode ter Telegram **e** Teams ativos ao mesmo tempo.

**Como obter a URL do Teams:**  
Canal → `⋯` → `Connectors` → `Incoming Webhook` (legacy)  
ou Canal → `Workflows` → `Post to a channel when a webhook request is received` (Power Automate)

---

## Instalação

### Requisitos

- Linux (Ubuntu 22.04+, Debian 12, Kali) ou WSL2
- bash ≥ 4.4, Python 3.8+, Go 1.21+

### Automática (recomendado)

```bash
git clone https://github.com/trickMeister1337/SWARM.git
cd SWARM
bash setup.sh
```

O `setup.sh` detecta a distribuição (apt / dnf / pacman / zypper) e instala:

- Sistema: `nmap`, `hydra`, `nikto`, `sqlmap`, `curl`, `jq`, `testssl.sh`
- Go tools: `subfinder`, `httpx`, `katana`, `nuclei`, `ffuf`, `dalfox`, `waybackurls`
- Python: `wafw00f`, `trufflehog`, `arjun`
- Metasploit Framework (repositório oficial)
- OWASP ZAP (snap)
- SecLists em `/opt/SecLists`

### Atualizar ferramentas

```bash
nuclei -update && nuclei -update-templates
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/hahwul/dalfox/v2@latest
```

---

## Fluxo completo recomendado

```bash
# 1. OSINT pré-engajamento
bash osint.sh alvo.com --shodan-key $KEY --github-token $TOKEN

# 2. Recon e varredura com contexto OSINT
bash swarm.sh https://alvo.com --osint-dir osint_alvo.com_*/

# 3. Exploração dirigida pelos findings do scan
bash swarm_red.sh -d scan_alvo.com_*/ -p staging

# 4. Segunda rodada → swarm_diff gerado automaticamente
bash swarm_red.sh -d scan_alvo.com_*/ -p staging

# 5. Higiene pós-scan
tar czf resultados.tar.gz swarm_red_*/ scan_*/ osint_*/
gpg -c resultados.tar.gz
shred -vfz resultados.tar.gz
rm -rf swarm_red_*/ scan_*/ osint_*/
```

---

## Arquitetura

```
SWARM/
├── swarm.sh                  # Scanner principal (11 fases)
├── swarm_red.sh              # Engine de exploração (8 fases)
├── osint.sh                  # OSINT pré-engajamento (10 fases)
├── pci_scan.sh               # Conformidade PCI DSS 4.0.1 (independente)
├── swarm_full.sh             # Orquestrador end-to-end (osint → swarm → red)
├── swarm_batch.sh            # Wrapper multi-alvo
├── swarm_diff.py             # Comparação entre scans
├── setup.sh                  # Instalador universal
├── test_lib.py               # 42 testes unitários Python
├── test_swarm_red.sh         # Testes de integração bash
├── lib/
│   ├── recon.sh              # subfinder + httpx
│   ├── crawl.sh              # katana + ffuf
│   ├── sqli.sh               # sqlmap
│   ├── xss.sh                # dalfox
│   ├── brute.sh              # hydra
│   ├── msf.sh                # metasploit
│   ├── web.sh                # nikto
│   ├── ingest.py             # Priorização de URLs por score
│   ├── evidence.py           # Extração de evidências sqlmap/ZAP
│   ├── parsers.py            # Parse de nuclei JSONL e ZAP JSON
│   ├── poc_generator.py      # Geração de PoCs reproduzíveis
│   ├── poc_validator.py      # Validação ativa (min 60% confiança)
│   ├── report_generator.py   # Relatório HTML Big4-style
│   ├── cve_enricher.py       # NVD API v2 + EPSS + CISA KEV
│   ├── header_check.py       # Verificação de security headers
│   └── profiles.conf         # Perfis de execução (arrays bash)
├── profiles/
│   ├── lab.conf
│   ├── staging.conf
│   └── production.conf
└── .github/
    └── workflows/
        └── ci.yml            # Syntax check + pytest em cada push
```

### Módulos Python — responsabilidades

| Módulo | Responsabilidade |
|---|---|
| `ingest.py` | Lê output do swarm.sh (findings.json, nuclei, ZAP, nmap) e produz listas priorizadas por score para cada fase de exploração |
| `evidence.py` | Extrai evidência estruturada dos logs sqlmap; funções `is_valid_url` e `strip_ansi` |
| `parsers.py` | Parse de nuclei JSONL, ZAP JSON, extração de URLs e CVEs com filtros de domínio externo e parâmetros HTTP |
| `poc_generator.py` | Gera PoCs reproduzíveis (curl time-based, boolean, CORS) e `poc/verify.sh` para times de desenvolvimento |
| `poc_validator.py` | Reexecuta cada finding via curl com threshold mínimo de 60% de confiança |
| `report_generator.py` | Gera `relatorio_swarm_red.html` no padrão Big4 com seções MITRE ATT&CK |
| `cve_enricher.py` | Enriquecimento NVD/EPSS/KEV com cache diário |

---

## CI/CD

Cada push ou PR para `main` dispara dois jobs em paralelo:

```yaml
syntax:       bash -n em swarm.sh, swarm_red.sh, osint.sh, pci_scan.sh,
              setup.sh, swarm_batch.sh, swarm_full.sh e todos os lib/*.sh
unit-tests:   python3 -m pytest test_lib.py (42 testes)
```

Status visível em: `https://github.com/trickMeister1337/SWARM/actions`

---

## Testes

```bash
# Testes unitários Python (42 testes)
python3 -m pytest test_lib.py -v

# Suite bash (integração)
bash test_swarm_red.sh

# Syntax check manual
bash -n swarm.sh && bash -n swarm_red.sh && bash -n osint.sh

# Dry-run completo
echo "EU AUTORIZO" | bash swarm_red.sh -t https://example.com --dry-run
```

---

## Estrutura de Output

### `swarm_red.sh`

```
swarm_red_alvo.com_20260514_120000/
├── data/
│   ├── live_hosts.txt          # Hosts ativos
│   ├── nmap.txt                # Output nmap completo
│   ├── open_services.txt       # Portas abertas
│   ├── targets_scored.txt      # URLs priorizadas (score|url)
│   └── cves_found.txt          # CVEs extraídos
├── crawl/                      # URLs katana + ffuf
├── sqlmap/                     # Logs por URL testada
├── xss/                        # XSS confirmados
├── hydra/                      # Logs hydra por serviço
├── metasploit/                 # Resource script + outputs
├── searchsploit/               # Lookup por CVE
├── exploits_confirmed.csv      # Todos os findings confirmados
├── swarm_red.log               # Log cronológico (trilha de auditoria)
└── relatorio_swarm_red.html    # Relatório HTML final
```

### `swarm.sh`

```
scan_alvo.com_20260514_120000/
├── raw/
│   ├── nuclei.json             # Findings nuclei (JSONL)
│   ├── zap_alerts.json         # Alerts ZAP
│   ├── nmap.txt                # Output nmap
│   └── tls_issues.txt          # Problemas TLS (testssl)
├── relatorio_swarm.html        # Relatório técnico completo
├── sumario_executivo.html      # Sumário de risco para gestão
└── findings.json               # Export para SIEM/Jira
```

---

## Dependências

### Obrigatórias

| Ferramenta | Versão mínima |
|---|---|
| bash | 4.4 |
| python3 | 3.8 |
| curl | qualquer |

### Opcionais por fase

| Ferramenta | Fase | Instalação |
|---|---|---|
| subfinder | Recon | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| httpx | Recon / Surface | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| nmap | Surface | `apt install nmap` |
| katana | Crawl | `go install github.com/projectdiscovery/katana/cmd/katana@latest` |
| nuclei | Varredura | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| ffuf | Crawl | `go install github.com/ffuf/ffuf/v2@latest` |
| sqlmap | SQLi | `apt install sqlmap` |
| dalfox | XSS | `go install github.com/hahwul/dalfox/v2@latest` |
| hydra | Brute Force | `apt install hydra` |
| nikto | Web Scanner | `apt install nikto` |
| msfconsole | Metasploit | `bash setup.sh` |
| testssl.sh | TLS | `apt install testssl` |
| wafw00f | WAF Detection | `pip3 install wafw00f` |
| zaproxy | ZAP Active Scan | `snap install zaproxy --classic` |
| trufflehog | Secrets | `pip3 install trufflehog` |
| searchsploit | CVE lookup | `apt install exploitdb` |

---

## Licença

MIT — veja [LICENSE](LICENSE).

---

*Para uso exclusivo em atividades de segurança ofensiva autorizadas.*

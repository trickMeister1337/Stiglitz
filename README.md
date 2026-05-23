<h1 align="center">Stiglitz</h1>

<p align="center">
  <b>The all-in-one offensive security pipeline.</b><br>
  OSINT → Recon → Adaptive Scanning → Active Exploitation → Big4-grade reports — in one command.
</p>

<p align="center">
  <a href="https://www.gnu.org/software/bash/"><img src="https://img.shields.io/badge/Shell-Bash-4EAA25?logo=gnu-bash&logoColor=white"></a>
  <a href="https://python.org"><img src="https://img.shields.io/badge/Python-3.8%2B-3776AB?logo=python&logoColor=white"></a>
  <a href="https://github.com/trickMeister1337/Stiglitz/actions/workflows/ci.yml"><img src="https://github.com/trickMeister1337/Stiglitz/actions/workflows/ci.yml/badge.svg"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg"></a>
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20WSL2-333">
</p>

---

> ### ⚠ Authorized use only
> Stiglitz is offensive tooling for **authorized engagements** with a signed Rules of Engagement (RoE).
> Every script requires explicit confirmation before any active execution.
> Unauthorized use is a crime (Art. 154-A CP / CFAA / Computer Misuse Act).

---

## What is Stiglitz?

Stiglitz chains the tools a red-teamer already uses — `subfinder`, `httpx`, `nuclei`, `katana`, `testssl`, OWASP ZAP, `sqlmap`, `hydra`, Metasploit and more — into a single, coordinated pipeline. It doesn't just run them: it **reads the target**, tunes each tool to the detected stack, **actively confirms** what it finds, and produces a client-ready report with a defensible risk score.

```
┌──────────┐    ┌──────────┐    ┌──────────────┐    ┌──────────────┐
│ OSINT    │ →  │ Recon &  │ →  │ Active        │ →  │ Big4-grade   │
│ (passive)│    │ Scanning │    │ Exploitation  │    │ HTML report  │
└──────────┘    └──────────┘    └──────────────┘    └──────────────┘
  osint.sh        stiglitz.sh         stiglitz_red.sh        auto-generated

            stiglitz_full.sh  ── runs the whole chain in one command
```

## Why Stiglitz?

- **🎯 Adaptive scanning** — detects the target's stack (`httpx` tech-detect + path fingerprinting + version probes) and automatically tunes Nuclei tags, ffuf wordlists and CMS scanners. No manual configuration.
- **🔬 Active confirmation, not just alerts** — every eligible finding is re-executed with a reproducible `curl` PoC. The report distinguishes a **confirmed exploit** from a merely **verified** hardening issue.
- **📊 A risk score you can defend** — KEV > EPSS > CVSS methodology. The CRITICAL band requires a real critical finding or a CVE under active exploitation (CISA KEV) — soft signals can't inflate it.
- **📁 Client-ready reports** — executive summary, scope & methodology, effort×impact prioritization matrix, evolution diff vs the last scan, CVSS vectors, and reproducible evidence. Plus `findings.json` for SIEM/Jira.
- **🧩 One pipeline, full kill chain** — passive OSINT feeds active recon, recon feeds exploitation, every stage hands structured data to the next.

## Quick start

**Docker (recommended — no host setup, pinned tooling):**

```bash
docker build -t stiglitz .
docker run --rm -v "$PWD/output:/scans" stiglitz https://target.com
# or with compose:
docker compose run --rm stiglitz https://target.com
```

**Native:**

```bash
git clone https://github.com/trickMeister1337/Stiglitz.git
cd Stiglitz
bash setup.sh                      # installs system + Go + Python tooling

bash stiglitz.sh https://target.com   # recon + adaptive scan + report
```

Output lands in `scan_<domain>_<timestamp>/` — open `stiglitz_report.html`
(and `findings.sarif` for GitHub code scanning / DefectDojo).

> The Docker image ships the core scan path (recon, adaptive Nuclei, TLS, JS,
> report/SARIF). Heavy/optional engines (OWASP ZAP, Metasploit, sqlmap, hydra)
> are not bundled; those phases are skipped gracefully when the tool is absent.

## Components

| Tool | Role | When to use |
|---|---|---|
| `osint.sh` | Passive pre-engagement intelligence (10 phases) | Before any active scan |
| `stiglitz.sh` | Recon & adaptive vulnerability scanning (11 phases) | Map the attack surface |
| `stiglitz_red.sh` | Automated exploitation engine (8 phases) | After recon, or standalone |
| `stiglitz_full.sh` | End-to-end orchestrator | One-command full engagement |
| `stiglitz_batch.sh` | Multi-target wrapper | Many targets in series |
| `stiglitz_diff.py` | Scan-to-scan comparison | Remediation tracking |

## The scan pipeline

```
[1]    Subdomain discovery    subfinder
[2]    Surface mapping        httpx (tech-detect) + nmap
[2.5]  WAF + tech profile     wafw00f + adaptive stack detection
[3]    TLS analysis           testssl (parallel with nuclei)
[4]    Vulnerability scan     nuclei (adaptive tags)
[5]    PoC confirmation       active re-execution (min 60% confidence)
[6]    CVE enrichment         NVD API v2 + EPSS + CISA KEV
[7]    WAF detection          wafw00f + passive evasion
[8]    Email security         SPF / DMARC / DKIM
[9]    ZAP active scan        Spider + Ajax + Active Scan
[10]   JS analysis            katana + secret detection
[10.5] Extra checks           ffuf (adaptive wordlist) + wpscan/joomscan/droopescan
[11]   Report                 HTML + technology inventory + findings.json
```

### Adaptive scanning in action

Stiglitz fingerprints the stack and reshapes the scan automatically:

```
httpx -tech-detect → "[WordPress:6.3, PHP:8.1, Nginx:1.18.0]"
katana URLs        → /wp-admin/, /actuator/, /_next/   (CMS/framework fingerprint)
HTTP probes        → /feed/, /CHANGELOG.txt, /actuator (confirmed version)
        ↓
tech_profile.json  → nuclei tags · ffuf wordlist · CMS scanner
```

| Detected stack | Extra Nuclei tags | ffuf wordlist | CMS scanner |
|---|---|---|---|
| WordPress | `wordpress, wp` | wp-admin, xmlrpc.php, wp-config backups | wpscan |
| Drupal | `drupal` | CHANGELOG.txt, sites/default, modules/ | droopescan |
| Joomla | `joomla` | administrator/, components/ | joomscan |
| Spring Boot | `spring, actuator` | /actuator/* (heapdump, env, shutdown) | — |
| Laravel | `laravel` | .env, telescope/, horizon/, storage/logs | — |
| Django | `django` | admin/, __debug__/, api/v1/ | — |
| Apache Struts | `struts` | *.action, struts2-showcase/ | — |

## What you get

| File | Contents |
|---|---|
| `stiglitz_report.html` | Full technical report — exec summary, methodology, tech inventory, prioritization matrix, scan diff, reproducible evidence |
| `executive_summary.html` | One-page risk summary for management |
| `findings.json` | Structured export for SIEM / Jira |
| `findings.sarif` | SARIF 2.1.0 — ingest into GitHub code scanning, DefectDojo, CI/CD |
| `raw/` | nuclei JSONL, ZAP alerts, TLS issues, tech_profile.json, JS analysis, CVE enrichment |

## Usage

```bash
# Recon + adaptive scan (most common)
bash stiglitz.sh https://target.com

# Reuse OSINT discovery (skips subfinder, feeds historical endpoints)
bash osint.sh target.com --shodan-key $KEY --github-token $TOKEN
bash stiglitz.sh target.com --osint-dir osint_target.com_*/

# Authenticated scan
bash stiglitz.sh https://target.com --token "eyJ..."

# Automated exploitation from a scan's output
bash stiglitz_red.sh -d scan_target.com_*/ -p staging

# Full engagement in one command
bash stiglitz_full.sh target.com

# Multiple targets
bash stiglitz_batch.sh -f targets.txt -p staging
```

### Execution profiles

| Profile | sqlmap level/risk | Brute force | Use |
|---|---|---|---|
| `staging` | 3 / 2 | Yes | Homolog / QA |
| `lab` | 5 / 3 | Yes | Disposable lab |
| `production` | 1 / 1 | No | Production (approved window) |

## Installation

**Requirements:** Linux (Ubuntu 22.04+, Debian 12, Kali) or WSL2 · bash ≥ 4.4 · Python 3.8+ · Go 1.26+

```bash
bash setup.sh
```

`setup.sh` detects the distro (apt/dnf/pacman/zypper) and installs nmap, hydra, nikto, sqlmap, testssl.sh, the ProjectDiscovery Go tools (subfinder, httpx, katana, nuclei, ffuf, dalfox), Python tooling (wafw00f, trufflehog), Metasploit, OWASP ZAP and SecLists.

## Recommended workflow

```bash
bash osint.sh target.com --shodan-key $KEY --github-token $TOKEN   # 1. passive OSINT
bash stiglitz.sh https://target.com --osint-dir osint_target.com_*/   # 2. recon + scan
bash stiglitz_red.sh -d scan_target.com_*/ -p staging                 # 3. exploitation
bash stiglitz_red.sh -d scan_target.com_*/ -p staging                 # 4. re-run → auto diff

# 5. post-engagement hygiene
tar czf results.tar.gz stiglitz_red_*/ scan_*/ osint_*/
gpg -c results.tar.gz && shred -vfz results.tar.gz
rm -rf stiglitz_red_*/ scan_*/ osint_*/
```

## Notifications

Set any of these and Stiglitz pings on scan completion: `STIGLITZ_TELEGRAM_TOKEN` + `STIGLITZ_TELEGRAM_CHAT`, `STIGLITZ_NOTIFY_WEBHOOK` (Slack/generic), `STIGLITZ_TEAMS_WEBHOOK`.

## Project layout

```
stiglitz.sh            Main scanner (11 phases)
stiglitz_red.sh        Exploitation engine (8 phases)
osint.sh            Pre-engagement OSINT (10 phases)
stiglitz_full.sh       End-to-end orchestrator
stiglitz_report.py     HTML/JSON report generator
stiglitz_diff.py       Scan comparison
lib/                Python modules (parsers, evidence, poc_validator, cve_enrich, …)
                    + bash modules (recon, crawl, sqli, xss, brute, msf, web)
Dockerfile          Containerized core scan pipeline
docker-compose.yml  Build/run + optional Juice Shop demo target
.github/workflows/  CI: bash syntax + Python compile + unit + integration tests
```

Full version history in [CHANGELOG.md](CHANGELOG.md).

## Contributing

Issues and PRs welcome. CI runs on every push: bash syntax checks, `py_compile` on all Python, the unit-test suite, and an **end-to-end integration scan against OWASP Juice Shop** (real target → findings → report → SARIF). Keep it green.

## License

MIT — see [LICENSE](LICENSE). Use responsibly and only where you are authorized.

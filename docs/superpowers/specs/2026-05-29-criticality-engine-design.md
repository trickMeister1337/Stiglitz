# Design — Motor de Criticidade (Fase 0)

- **Data:** 2026-05-29
- **Status:** Aprovado (brainstorming) — aguardando revisão do spec
- **Escopo:** Fase 0 de um conjunto maior de melhorias. Este spec cobre **apenas o motor de criticidade**. As demais frentes (detecções de lógica de negócio/authz, testes de authn, fase 3DS, paralelização + relatório consolidado de batch, adapters DefectDojo/Jira, hardening) terão specs próprios e dependerão deste motor.

## 1. Problema

Hoje existem dois níveis de "criticidade" no Stiglitz, tratados de forma inconsistente:

1. **Severidade por finding** (`critical/high/medium/low/info`) — herdada crua da ferramenta (nuclei/ZAP/sqlmap) ou definida como string ad-hoc em cada módulo (ex.: `lib/email_security.py` retorna `"high"` no braço). **Não há metodologia uniforme.**
2. **Risk score agregado do scan** (0–100) — `lib/risk_score.py` (KEV>EPSS>CVSS). Sólido, porém por-alvo e dependente de CVE.

As novas detecções planejadas (lógica de negócio, IDOR/BOLA, authz, JWT, 3DS) **não têm CVE**, então hoje cairiam em severidades chutadas pelo autor do módulo. Como a criticidade **guia o esforço de correção dos times**, ela precisa ser padronizada, defensável e sensível ao contexto de negócio (fintech).

## 2. Objetivo

Um motor que atribui a **cada finding** uma criticidade **CVSS 3.1 completa** — Base (técnica) → Temporal (confirmação) → Environmental (impacto de negócio) — produzindo um score final (0–10) e uma banda, com **proveniência transparente** do score. Vale tanto para findings com CVE quanto para findings próprios sem CVE.

## 3. Metodologia (CVSS 3.1)

- **Base** — severidade técnica intrínseca. Origem do vetor, em ordem de preferência:
  1. Vetor do NVD via CVE enrichment (`lib/cve_enrich.py`), quando há CVE.
  2. Catálogo de classes (`lib/vuln_catalog.py`) por classe/CWE do finding (findings sem CVE).
  3. *Fallback estimado* a partir da severidade qualitativa da ferramenta — **sempre** marcado `score_source: estimated` (nunca silencioso).
- **Temporal** — reflete exploração comprovada (por nós OU pelo mundo real), separando "comprovado" de "teórico" sem rebaixar CVE realmente explorado. Regra (KEV/EPSS-aware):
  - Confirmado pelo nosso PoC/OOB **OU** CVE em CISA KEV **OU** EPSS ≥ 0.5: `E:H` (Exploit Maturity High), `RC:C` (Report Confidence Confirmed).
  - EPSS em [0.1, 0.5): `E:F` (Functional), `RC:C`.
  - Caso contrário (teórico / não confirmado / sem sinal de exploração): `E:P` (Proof-of-Concept), `RC:R` (Reasonable) — **cai uma banda** vs comprovado.
  - `RL` (Remediation Level): `U` (Unavailable) por padrão, sempre presente no vetor serializado.
- **Environmental** — impacto de negócio fintech, dirigido pela classe do ativo:
  - Requisitos de segurança `CR/IR/AR` (Confidentiality/Integrity/Availability Requirements).
  - `MAV` (Modified Attack Vector) por exposição (ativo só interno → `A`).
  - **Score final = Environmental score (0–10)**.
- **Banda** — mapeamento qualitativo CVSS 3.1:
  `0.0` None · `0.1–3.9` Low · `4.0–6.9` Medium · `7.0–8.9` High · `9.0–10.0` Critical.

### 3.1 Classe de ativo → requisitos (CR/IR/AR)

| Classe | Significado | CR | IR | AR |
|---|---|---|---|---|
| `cde` | Cardholder Data Environment (PAN, dados de cartão) | H | H | M |
| `funds` | Movimentação de fundos / transações | H | H | M |
| `pii` | Dados pessoais / autenticação | H | M | L |
| `internal` | Infra/observabilidade não exposta a dados sensíveis | M | M | M |
| `public` | Conteúdo público/estático | L | L | L |
| (default) | Não classificado | M | M | M |

> `AR` (Availability) é deliberadamente conservador (M/L) — o foco fintech é confidencialidade e **integridade** (fraude/manipulação), não disponibilidade. Ajustável por engagement.

### 3.2 Inferência de classe (padrões Example) — override sempre vence

| Padrão no host/path (regex, case-insensitive) | Classe inferida |
|---|---|
| `card`, `pan`, `tokenize`, `vcn`, `3ds`, `acs`, `acquirera`, `acquirerb` | `cde` |
| `gateway`, `checkout`, `splitter`, `cielo`, `getnet`, `rede`, `mercadopago` | `funds` |
| `auth`, `token`, `login`, `onetime`, `sso`, `saml`, `oauth`, `keycloak`, `kc.`, `back-token` | `pii` |
| `fraudsvc`, `buyer`, `reservation`, `hotel`, `chargeback`, `receivable`, `notification`, `email-service`, `simples-nacional` | `pii` |
| `kibana`, `grafana`, `apm`, `elastic`, `logs`, `jenkins`, `nexus`, `uptime`, `longhorn` | `internal` |
| `www`, `cdn`, `static`, `assets`, `portal`, `sidebar`, `topbar` | `public` |
| (sem match) | default (M/M/M) |

Override por arquivo `assets.yaml`/`assets.json` (lista de `{match: <host/path glob>, data_class: <classe>}`). Override > inferência > default.

## 4. Componentes (módulos puros, sem dependência em runtime)

| Módulo | Responsabilidade | Interface principal |
|---|---|---|
| `lib/cvss.py` | Calculadora CVSS 3.1 (Base+Temporal+Environmental): parse/serialização de vetor + cálculo com `roundup` correto | `base_score(metrics)`, `temporal_score(...)`, `environmental_score(...)`, `parse_vector(str)`, `to_vector(dict)` |
| `lib/vuln_catalog.py` | Catálogo *classe de vuln → vetor base + CWE + título* | `lookup(vuln_class_or_cwe) -> {vector, cwe, title}` |
| `lib/asset_classifier.py` | Classe do ativo por inferência + override | `classify_asset(host, path, overrides) -> str` |
| `lib/criticality.py` | Orquestra Base→Temporal→Environmental e devolve o resultado por finding | `score_finding(finding, asset_class, confirmation) -> dict` |

Cada módulo é testável em isolamento e segue o estilo de funções puras de `lib/risk_score.py`.

### 4.1 Catálogo de classes inicial (`vuln_catalog.py`)

Sementes mínimas (classe → vetor base CVSS 3.1) para o que as próximas fases vão emitir, além de classes comuns. Exemplos:

| Classe | CWE | Vetor base (exemplo) |
|---|---|---|
| `idor_read_pii` | CWE-639 | `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` |
| `idor_write` / `bola` | CWE-639 | `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N` |
| `broken_auth` | CWE-287 | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` |
| `amount_tampering` | CWE-840 | `AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N` |
| `race_condition_funds` | CWE-362 | `AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:N` |
| `jwt_alg_none` / `jwt_weak_secret` | CWE-347 | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` |
| `csrf_state_changing` | CWE-352 | `AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N` |
| `ssrf` | CWE-918 | `AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N` |
| `missing_security_header` | CWE-693 | `AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N` |

(Lista completa definida na implementação; reutiliza CWE de `lib/report/cwe_data.py` quando aplicável.)

## 5. Esquema de saída (por finding, em `findings.json`)

```json
{
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N/E:H/RC:C/CR:H/IR:H",
  "cvss_base": 6.5,
  "cvss_temporal": 6.5,
  "cvss_environmental": 8.1,
  "severity": "high",          // banda final (Environmental) — AUTORITATIVA
  "severity_tool": "medium",   // severidade original da ferramenta — rastreio
  "score_source": "catalog",   // nvd | tool | catalog | estimated
  "asset_class": "cde",
  "requirements": {"CR": "H", "IR": "H", "AR": "M"}
}
```

## 6. Integração

- **`lib/evidence.py` / `lib/parsers.py`**: cada finding é enriquecido chamando `criticality.score_finding(...)`. A `severity` autoritativa passa a ser a banda Environmental; a original é preservada em `severity_tool`.
- **`lib/risk_score.py` (`compute_risk`)**: refatorado para consumir as **bandas novas** (contagens por severidade derivadas do Environmental). Mantém as camadas KEV/EPSS como sinal de exploração ativa **no agregado**, sem duplicar o Temporal por-finding.
- **Relatório (`stiglitz_report.py`, `lib/report_generator.py`)**: card do finding mostra score final + vetor + banda + classe do ativo + proveniência; aviso visível quando `score_source == estimated`.
- **SARIF (`lib/report/sarif.py`)**: `security-severity` = score Environmental.

## 7. Transparência & compatibilidade

- **Zero-config**: inferência + defaults funcionam out-of-the-box (importante para batches grandes). Override é opcional.
- **Sem score inventado em silêncio**: `score_source` explícito; `estimated` sinalizado no relatório.
- **Auditável**: `severity_tool` sempre preservada; vetor CVSS completo no output.

## 8. Testes (`tests/test_criticality.py`)

- **Calculadora** validada **contra a biblioteca `cvss`** (adicionada a `requirements-dev.txt` como dep de teste) numa matriz de vetores Base/Temporal/Environmental — igualdade exata de score (incluindo `roundup`).
- **Classifier**: host/path → classe (padrões Example + override; override vence).
- **`score_finding` ponta a ponta**: finding com CVE (vetor NVD) vs catálogo vs estimado; confirmado vs potencial altera o score; `cde` vs `public` altera o score; `estimated` é sinalizado.
- **Erros**: vetor inválido → exceção tipada; fallback para estimado com flag. Sem `except:` mudo.

## 9. Tratamento de erros

- Exceções tipadas (`ValueError`/classe própria) para vetor inválido.
- Falha ao resolver base → fallback estimado **com `score_source: estimated`**, nunca exceção silenciosa.

## 10. Fora de escopo (Fase 0)

- Detecções novas (bizlogic/authz, authn, 3DS) — specs próprios; vão **consumir** este motor.
- Adapters DefectDojo/Jira, paralelização de batch, hardening — specs próprios.
- SLA/prazos de correção — **descartado** nesta fase (decisão do usuário: só banda + score).
- CVSS 4.0 — não nesta fase (fontes ainda emitem 3.1).

## 11. Critérios de aceite

1. `lib/cvss.py` calcula Base/Temporal/Environmental idêntico à lib `cvss` numa matriz de teste.
2. Todo finding em `findings.json` carrega `cvss_vector`, `cvss_environmental`, `severity` (banda final), `severity_tool` e `score_source`.
3. Findings sem CVE recebem vetor via catálogo; sem match → `estimated` sinalizado.
4. Classe do ativo afeta o score (CDE > público para o mesmo finding); confirmação afeta o score.
5. `compute_risk` agregado permanece coerente com as novas bandas; suíte (`tests/`) verde, incluindo `test_criticality.py`.
6. Relatório e SARIF refletem o score Environmental e a proveniência.

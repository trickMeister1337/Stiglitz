# OWASP Top 10 Coverage View — Design

**Data:** 2026-06-24
**Status:** Aprovado (brainstorming) — pronto para plano de implementação

## Problema

O OWASP Top 10 (2021) é um documento de **conscientização**, não uma metodologia de
priorização per-finding — a própria OWASP é explícita nisso. A metodologia de
criticidade do Stiglitz (CVSS 3.1 base→temporal→environmental + KEV/EPSS, via
`lib/criticality.py` e `lib/prioritization.py`) é risk-based e exploit-aware, alinhada
a FIRST/CISA/SSVC. Injetar o Top 10 como fator de score introduziria dupla contagem,
granularidade errada (10 baldes amplos) e um sinal estático num score dinâmico —
degradaria a metodologia sem ganho.

Onde o OWASP Top 10 **agrega valor** é em **comunicação e cobertura**: mostrar quais
categorias foram exercitadas pelo scan, quais foram testadas sem achado, e quais o
scan automatizado **não cobre** (exigem revisão manual). Esse é o objetivo desta
feature: uma seção de apresentação **separada da metodologia de criticidade**, que não
toca em severidade, ordenação nem SLA.

## Não-objetivos (YAGNI)

- **Não** altera criticidade, severidade, ordenação ou SLA de nenhum finding.
- **Não** adiciona OWASP a `criticality.py`/`prioritization.py`/`risk_*`.
- Sem linha-resumo no terminal.
- Sem export em SARIF (SARIF é por-finding; cobertura é agregada — não encaixa).
- Sem mapa configurável por arquivo (hardcoded, como `_MAP`/`_REQ_COVERAGE` já são).

## Arquitetura

Espelha o padrão `pci_posture` já existente em `lib/compliance_map.py`. Reutiliza
infraestrutura: `extract_cwe`, `frameworks_for_cwe`, o `_MAP` (CWE→OWASP) e o dict
`_coverage` que o `stiglitz_report.py` já deriva de quais `raw/*.json` foram gerados.

Dois pontos de mudança:

1. **`lib/compliance_map.py`** (backend, lógica pura): nova função
   `owasp_posture(findings, coverage)` + 3 constantes (`_OWASP_CATEGORIES`,
   `_OWASP_COVERAGE`, `_OWASP_NOTES`).
2. **`stiglitz_report.py`** (wiring): deriva o coverage (acrescenta sinal `retire`),
   chama `owasp_posture`, renderiza a seção HTML (irmã da de PCI, **sem gate de CDE**)
   e injeta um bloco no `findings.json`.

## Componente 1 — `owasp_posture(findings, coverage)`

Função pura em `lib/compliance_map.py`, análoga a `pci_posture`.

### Constantes

```
_OWASP_CATEGORIES = [  # lista canônica + título oficial 2021, ordem A01→A10
    ("A01:2021", "Broken Access Control"),
    ("A02:2021", "Cryptographic Failures"),
    ("A03:2021", "Injection"),
    ("A04:2021", "Insecure Design"),
    ("A05:2021", "Security Misconfiguration"),
    ("A06:2021", "Vulnerable and Outdated Components"),
    ("A07:2021", "Identification and Authentication Failures"),
    ("A08:2021", "Software and Data Integrity Failures"),
    ("A09:2021", "Security Logging and Monitoring Failures"),
    ("A10:2021", "Server-Side Request Forgery"),
]

# categoria → capability-keys (do _coverage); TESTED se QUALQUER uma rodou.
# Lista vazia = NOT-COVERED por design (automação não exercita).
_OWASP_COVERAGE = {
    "A01:2021": ["webapp", "authz"],
    "A02:2021": ["tls"],
    "A03:2021": ["webapp"],
    "A04:2021": [],
    "A05:2021": ["headers", "webapp"],
    "A06:2021": ["components", "retire"],
    "A07:2021": ["authn", "webapp"],
    "A08:2021": [],
    "A09:2021": [],
    "A10:2021": ["webapp"],
}

# nota textual fixa p/ categorias com cobertura parcial/manual.
_OWASP_NOTES = {
    "A04:2021": "Design-level — requires manual review; not exercised by automated DAST.",
    "A08:2021": "Insecure deserialization (CWE-502) is covered; CI/CD & SRI integrity require manual review.",
    "A09:2021": "Not exercised by DAST — requires log/monitoring configuration review.",
}
```

### Lógica

A categoria de cada finding vem de `frameworks_for_cwe(extract_cwe(f))["owasp"]`. O
prefixo `A0N:2021` é extraído para casar com `_OWASP_CATEGORIES` (o `_MAP` guarda a
string completa "A03:2021-Injection"; casamos pelo prefixo antes do `-`).

Por categoria, na ordem A01→A10:
```
count = nº de findings cujo CWE mapeia para a categoria
top_findings = até 3 nomes de findings da categoria (só quando FOUND)
if count > 0:
    verdict = "FOUND"
elif _OWASP_COVERAGE[cat] e alguma capability está ativa em coverage:
    verdict = "TESTED"
else:
    verdict = "NOT-COVERED"
note = _OWASP_NOTES.get(cat)  # pode ser None
```

Retorna **sempre as 10 categorias** (mesmo as sem CWE no `_MAP`), como lista de:
```
{"category": "A03:2021", "title": "Injection", "verdict": "TESTED",
 "count": 0, "top_findings": [], "note": None}
```

## Componente 2 — Wiring em `stiglitz_report.py`

### Coverage

Reusa o dict `_coverage` (linha ~2273). Acrescenta o sinal do retire:
```
"retire": _raw_has("retire_findings.json"),
```
(`components` continua = `nuclei.json`; A06 fica coberto por qualquer um dos dois.)

### Seção HTML

Irmã da seção PCI (renderizada logo após, ~linha 2313). **Sem gate de CDE** — o Top 10
aplica a qualquer aplicação web.

```
<h2>OWASP Top 10 (2021) — Coverage</h2>
<p>{summary}</p>   # ex.: "10 categories assessed: 3 FOUND, 5 TESTED, 2 NOT-COVERED."
<p style=...>FOUND = finding mapped to category; TESTED = capability exercised, no
finding; NOT-COVERED = not exercised by automated scan (manual review).</p>
<table>
  <tr><th>Category</th><th>Verdict</th><th>Findings</th><th>Top findings / Note</th></tr>
  ... uma linha por categoria ...
</table>
```

- Coluna "Category": `A01:2021 — Broken Access Control`.
- Cores do verdict: FOUND `#c0392b`; TESTED `#27ae60`; NOT-COVERED `#888`.
- Coluna 4: `top_findings` (quando FOUND) ou a `note` (quando presente), HTML-escapado.
- Texto em inglês (deliverable), conforme a convenção do repo.

### Bloco no `findings.json`

No dict `findings_out` (linha ~2472), novo campo top-level:
```
"owasp_coverage": [ {category, title, verdict, count, top_findings, note}, ... ]
```

## Fluxo de dados

```
all_f (findings já pontuados)  ─┐
                                ├─→ owasp_posture(all_f, _coverage)
_coverage (raw/*.json gerados) ─┘         │
                                          ├─→ seção HTML (sempre)
                                          └─→ findings_out["owasp_coverage"]
```

## Tratamento de erros / degradação

- `owasp_posture` é puro e tolerante: findings sem CWE simplesmente não contam para
  nenhuma categoria (não levantam exceção) — mesma postura defensiva do `_MAP`.
- Coverage ausente/parcial → categorias sem sinal caem em NOT-COVERED (default
  conservador — nunca afirma TESTED falso), idêntico ao `pci_posture`.
- A seção HTML e o bloco JSON são aditivos; se `owasp_posture` falhar, envolve-se num
  try/except que degrada omitindo a seção (padrão do report), sem abortar o relatório.

## Testes — `tests/test_compliance_map.py`

Adicionar à classe de testes do compliance_map:
- `owasp_posture` retorna sempre as 10 categorias, ordenadas A01→A10.
- FOUND: finding com CWE-89 → A03 FOUND, count correto, top_findings preenchido.
- TESTED: 0 findings em A03 + `coverage={"webapp": True}` → TESTED.
- NOT-COVERED (capability inativa): 0 findings em A03 + `coverage={}` → NOT-COVERED.
- NOT-COVERED por design: A04/A08/A09 → NOT-COVERED mesmo com coverage cheio, e com
  `note` não-nula.
- count>0 vence cobertura: finding CWE-502 (A08) → FOUND, apesar de A08 ser
  NOT-COVERED por design.

## Critérios de sucesso

1. Relatório de um scan real exibe a seção com as 10 categorias e vereditos coerentes
   (ex.: A06 FOUND quando há lib vulnerável; A04/A09 NOT-COVERED com nota).
2. `findings.json` contém `owasp_coverage` com as 10 entradas.
3. Severidades, ordenação e contagens do relatório **não mudam** vs. antes (a feature é
   puramente aditiva — diff de severidade = zero).
4. Suíte de testes verde, incluindo os novos casos de `owasp_posture`.

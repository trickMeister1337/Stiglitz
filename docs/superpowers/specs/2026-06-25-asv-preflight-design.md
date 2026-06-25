# Modo ASV-Preflight — previsão de resultado de scan ASV PCI — Design

**Data:** 2026-06-25
**Status:** Aprovado (brainstorming) — pronto para plano de implementação

## Problema

Clientes sujeitos a PCI DSS precisam de um **scan ASV trimestral** (Req. 11.3.2),
emitido por um *Approved Scanning Vendor* certificado (Qualys/Tenable/etc). Esse
scan reprova por critérios próprios do *ASV Program Guide* — em especial **CVSS base
≥ 4.0 = falha** e uma lista de **gatilhos de falha automática** (SQLi, XSS, TLS
fraco, default creds, etc.) independentes de score. Hoje o Stiglitz coleta quase
todos os dados que um ASV avalia (TLS via testssl+nmap, portas/serviços via nmap,
CVE via nuclei+NVD/KEV/EPSS, SQLi/XSS, default-login, exposições), mas **não aplica
o critério do ASV** nem apresenta o resultado nesse formato. O operador descobre que
o alvo reprovaria só quando paga o scan oficial e recebe o FAIL — gerando re-scan e
retrabalho.

O próprio toolkit já se posiciona como complemento, não substituto, do ASV
(`pci_scan.sh:11`: *"NÃO substitui: ASV scan externo (Req 11.3.2)"*). Este design
**não muda** esse posicionamento — adiciona uma camada de *previsão* para remediar
antes do scan oficial.

## Objetivo

Prever se um alvo **PASSARIA / NÃO PASSARIA** num scan ASV, aplicando o critério do
*ASV Program Guide* aos findings que o Stiglitz já coleta, rodando **só fases
não-intrusivas e deslogadas** (espelhando o que um ASV realmente faz). Saída: o
veredito + a lista exata do que reprova, com motivo, host/porta, CVSS base, requisito
e remediação, mais um inventário agregado de componentes escaneados.

## Não-objetivos (YAGNI)

- **Não** gera AoC (Attestation of Scan Compliance), assinatura, nem identificação de
  testador/ASV. Não é documento de conformidade — é previsão de remediação.
- **Não** substitui o ASV certificado nem o scan interno do Req. 11.3.1.
- **Não** faz web-app *active scanning* na v1 (P9/ZAP active scan fica de fora — ver
  Limitações). SQLi/XSS são cobertos pelo nuclei não-destrutivo.
- **Não** toca em `stiglitz.sh`, no scoring `KEV>EPSS>CVSS`, nem em
  `criticality.py`/`compliance_map.py` — o veredito ASV é uma camada **paralela e
  separada**, derivada de `findings.json`.
- **Não** roda nenhuma fase intrusiva (P5 confirmação de exploit, P9.x authz/ZAP
  active, P10.5 smuggler/brute, P12 tracker).

## Arquitetura

Três peças; o núcleo é um módulo puro reusável (padrão `lib/tls_confirm.py` /
`lib/zap_authgate.py`: lógica pura + CLI, sem rede própria):

1. **`lib/asv_preflight.py`** (novo) — núcleo puro: critério de veredito + mapa de
   categorias + inventário de componentes + render da seção HTML. Consome
   `findings.json` + arquivos de `raw/`. CLI para teste standalone.
2. **`stiglitz_report.py`** (hook) — quando `STIGLITZ_ASV_PREFLIGHT=1`, chama
   `asv_preflight`, injeta a seção "ASV Preflight Verdict" e grava `asv_verdict.json`.
   Aditivo; sem o env, comportamento idêntico ao atual.
3. **`asv_preflight.sh`** (novo, top-level fino — padrão `stiglitz_full.sh`) —
   orquestra o subconjunto ASV-safe via `pipeline.py` com perfil `production`, seta
   `STIGLITZ_ASV_PREFLIGHT=1`, e entrega o relatório.

`stiglitz.sh` permanece intacto.

## Componente 1 — `lib/asv_preflight.py` (núcleo puro)

### Critério de veredito por finding (cascata)

```
def asv_verdict_for(finding) -> ("FAIL"|"PASS"|"NOT_COUNTED", reason):
    1. Gatilho de falha automática (independe de CVSS) -> FAIL
       categorias: sqli, xss, command/lfi/rfi/xxe/ssti injection,
       directory_traversal, tls_insecure (SSLv2/3, TLS1.0/1.1, cipher
       NULL/anon/weak, cert inválido/expirado/auto-assinado),
       default_credentials, sensitive_data_exposed (PAN/PII/backup/source),
       open_db_service (Redis/Mongo/ES sem auth)
    2. Senão, se tem CVSS base: FAIL se base >= 4.0; PASS se < 4.0
    3. Senão (sem CVSS — ZAP/headers/misconfig): decidir pelo MAPA DE CATEGORIA
       - categorias que CONTAM (high/critical exploráveis) -> FAIL
       - categorias informativas (missing security headers, info-disclosure de
         baixo valor, e tudo que finding_quality.py já rebaixou) -> NOT_COUNTED
```

- **CVSS base, não environmental.** Usa o `cvss_base` do finding (v3.1, o que o
  Stiglitz calcula). A divergência v2/v3 do ASV Program Guide é registrada em
  `criteria_notes` (ver Saídas).
- **Mapa de categorias** (`_ASV_CATEGORY`): tabela explícita
  `categoria -> {auto_fail | counts | informational}`. É o coração da fidelidade —
  evita o falso "NÃO PASSARIA" inflado por headers/ruído. Reusa as heurísticas de
  `finding_quality.is_low_value_zap_alert` (o que já é rebaixado vira `NOT_COUNTED`).
- Classificação da categoria a partir de `cwe`, `source`, `name`/`template-id` do
  finding (mesmas chaves que `pci_verdicts.py`/`compliance_map.py` já leem).

### Veredito agregado

```
def aggregate(findings, scope_domains) -> dict:
    fails = [asv_verdict_for(f) == FAIL para f em escopo]
    would_pass = (len(fails) == 0)
    cada fail: {name, host, port, cvss_base, reason, asv_trigger|cvss,
                requirement (via compliance_map), remediation}
```

Reusa `scope.in_scope` para a fronteira de escopo (mesma fonte de verdade do resto
do pipeline).

### CLI

```
python3 lib/asv_preflight.py verdict <findings.json> [raw_dir]   # -> asv_verdict.json em stdout
python3 lib/asv_preflight.py inventory <raw_dir>                 # -> tabela de componentes
```

## Componente 2 — Inventário de componentes

Tabela agregada `host | ip | port | service/version | tls`, derivada de:

- `raw/httpx_results.txt` / httpx json (hosts web vivos, portas, tech) via
  `httpx_parse.py`.
- `raw/nmap.xml` / `raw/service_findings.json` (portas/serviços/versões) via
  `service_versions.py`.

Preenche o item de inventário exigido no formato ASV e serve de conferência de
escopo. Lógica pura sobre os arquivos já gravados; sem rede.

## Componente 3 — Hook em `stiglitz_report.py`

Após `findings.json` estar montado (pós-dedup/state, antes do fim do render), sob
`STIGLITZ_ASV_PREFLIGHT=1`:

- `asv_verdict.py` calcula o veredito agregado + inventário.
- Grava `asv_verdict.json` no scan dir.
- Injeta a seção HTML **"ASV Preflight Verdict"** (irmã das seções PCI/OWASP, EN —
  deliverable): banner PASSARIA/NÃO PASSARIA, tabela de FAILs (nome, host:porta,
  CVSS base, motivo, requisito, fix), tabela de inventário, e o disclaimer de
  não-conformidade. Renderizada só sob o env.

Sem o env, zero diferença vs. comportamento atual (aditivo).

## Componente 4 — `asv_preflight.sh` (orquestrador)

```
asv_preflight.sh <target> [--outdir <dir>] [--proxy ...]
  → STIGLITZ_ASV_PREFLIGHT=1 \
    python3 pipeline.py <target> -p production \
      --only-phase "P1 P2 P3_P4 P6 P8 P10 P11"
  → relatório com a seção ASV + asv_verdict.json
```

**Subconjunto ASV-safe (incluídas):** P1 (subdomínios), P2/P2.5 (httpx+nmap+WAF),
P3_P4 (TLS + nuclei com tags não-destrutivas), P6 (CVE/EPSS/KEV), P8 (email/DNS),
P10 (JS/SCA), P11 (relatório).
**Excluídas (intrusivas/autenticadas):** P5, P9/9.5/9.6/9.7, P10.5, P12.

Wrapper fino: valida target, monta o env e delega ao `pipeline.py` (reusa
checkpoint/retry/dry-run existentes). Sem lógica de scan própria.

## Fluxo de dados

```
asv_preflight.sh <target>
  → pipeline.py (subconjunto ASV-safe, production, STIGLITZ_ASV_PREFLIGHT=1)
       P1..P10  → raw/ (nmap.xml, httpx, testssl, nuclei, cve_enrichment, ...)
       P11 (stiglitz_report.py):
         findings.json normalizado (dedup/CVSS/CWE/state)
           → asv_preflight.aggregate(findings, scope)   → veredito + fails
           → asv_preflight.inventory(raw/)              → componentes
           → asv_verdict.json
           → seção "ASV Preflight Verdict" no stiglitz_report.html
```

## Tratamento de erros / edge cases (fail-safe: na dúvida, não fabricar FAIL)

| Situação | Comportamento |
|---|---|
| Finding sem CVSS e categoria desconhecida | `NOT_COUNTED` (não infla o FAIL) |
| Finding fora de escopo (`scope.in_scope` False) | Ignorado no veredito |
| `raw/nmap.xml` ausente (scan parcial) | Inventário degrada (só httpx); seção avisa |
| FP já rebaixado por `finding_quality` | `NOT_COUNTED` por construção |
| `findings.json` vazio / sem fails | `would_pass=True`, seção informa |
| `STIGLITZ_ASV_PREFLIGHT` não setado | Nenhuma diferença vs. hoje |

## Testes (TDD)

**`tests/test_asv_preflight.py` (puro):**
- `asv_verdict_for` matriz: SQLi → FAIL (auto); XSS → FAIL (auto); TLS 1.0 → FAIL
  (auto); cipher forte / cert válido → PASS; CVSS base 3.9 → PASS; 4.0 → FAIL; 9.8 →
  FAIL; default-login confirmado → FAIL; missing HSTS → NOT_COUNTED; info-disclosure
  de baixo valor → NOT_COUNTED.
- `aggregate`: 1+ FAIL → `would_pass=False` com lista; 0 FAIL → `would_pass=True`;
  finding fora de escopo não conta; cada fail carrega motivo + requisito.
- `inventory`: a partir de fixtures `nmap.xml` + httpx → linhas host/ip/porta/serviço
  corretas; nmap ausente → degrada só com httpx.
- mapa de categorias: cada categoria mapeia para o bucket esperado.

**Wiring (`tests/test_report_*_wiring.py`, padrão existente):**
- Com `STIGLITZ_ASV_PREFLIGHT=1` e um SQLi no `findings.json` → `asv_verdict.json`
  tem `would_pass=False` e a seção HTML é renderizada.
- Sem o env → `asv_verdict.json` não é gerado e o HTML é idêntico ao atual.

**Smoke:** `bash -n asv_preflight.sh`; `python3 -m py_compile lib/asv_preflight.py`;
dry-run do wrapper.

## Limitações conhecidas (registradas no relatório, seção e `criteria_notes`)

1. **Não substitui ASV** nem é conformidade — é previsão.
2. **Sem web-app active scanning na v1** (P9/ZAP active fora). SQLi/XSS via nuclei
   não-destrutivo. Extensão v2: ZAP em modo *spider + passive-only*.
3. **CVSS v3.1 base** (o ASV Program Guide histórico usa v2 base); a divergência é
   documentada — pode haver borda em vulns cujo v2 e v3 cruzam o limiar 4.0 de forma
   diferente.
4. Veredito é **previsão**, não garantia do resultado do scan oficial.

## Critérios de sucesso

1. `asv_preflight.sh <target>` roda só o subconjunto não-intrusivo e produz
   `asv_verdict.json` + seção "ASV Preflight Verdict" no relatório.
2. Um alvo com SQLi, TLS 1.0, ou qualquer CVSS base ≥ 4.0 em escopo → **NÃO
   PASSARIA**, com o item listado e o motivo correto (gatilho automático vs ≥4.0).
3. Um alvo só com headers ausentes / ruído informativo → **PASSARIA** (não inflado).
4. Inventário lista host/IP/porta/serviço de tudo que foi escaneado.
5. Sem `STIGLITZ_ASV_PREFLIGHT`, o relatório e o `findings.json` são idênticos aos
   de hoje (aditivo, zero regressão).
6. Suíte de testes verde, incluindo os novos casos.

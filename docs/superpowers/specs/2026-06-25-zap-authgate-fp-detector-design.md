# Detector de FP "JWT-gate" para alertas ZAP active-scan — Design

**Data:** 2026-06-25
**Status:** Aprovado (brainstorming) — pronto para plano de implementação

## Problema

Quando o ZAP roda **deslogado** contra uma API auth-gated, a requisição de ataque
(com payload) recebe **401/403 antes de qualquer processamento**. O heurístico
active-scan do ZAP (ex.: SQLi boolean-based) compara a resposta "true" vs "false",
vê dois 401 idênticos e reporta "results successfully manipulated using boolean
conditions" — um **falso positivo**. Hoje esse alerta sobe como **CRITICAL** no
relatório (`confirmed=None`, `score_source=estimated`), erodindo a credibilidade do
deliverable. Padrão recorrente no ambiente: observado em múltiplas APIs JWT-gated e
re-confirmado ao vivo (todas as variações de payload retornam 401/0 bytes idênticos).

Verificação ao vivo: benigno, boolean-TRUE (`1' AND '1'='1`), boolean-FALSE
(`1' AND '1'='2`) e sem-param **todos** retornam HTTP 401 / 0 bytes no endpoint
auth-gated — o gate dispara antes da query.

## Objetivo

Detectar esses FPs pelo **status HTTP que a própria requisição de ataque recebeu**
e movê-los para uma seção **"Deferred — Requires Authenticated Retest"**, fora das
contagens de severidade e da criticidade. O achado nunca é destruído — o lead
(endpoints + params) é preservado para um futuro scan autenticado / code review.

### Propriedade de auto-ajuste (central)

A lógica chaveia em `attack_status`, não em "o scan tinha token?". Se o scan
**fosse** autenticado (token válido), a requisição de ataque receberia 200/processada
— o status não seria 401 — e o finding **não** seria deferido. Um SQLi autenticado
real nunca cai na seção deferred. Não há checagem separada de autenticação.

## Não-objetivos (YAGNI)

- **Não** atesta que o parâmetro é seguro atrás da auth (isso exige code review ou
  scan autenticado — fora de escopo). A seção é explicitamente "retest required".
- **Não** re-sonda o alvo no report-time (a detecção é passiva, a partir do
  `attack_status` capturado na Fase 9). Zero tráfego novo no relatório.
- **Não** reprocessa scans antigos: vale para scans futuros (que terão
  `attack_status` no raw). Conforme escolha do usuário.
- **Não** toca em `criticality.py`/`prioritization.py` — o finding é particionado
  ANTES de entrar no pipeline de score.

## Arquitetura

Espelha o padrão `lib/tls_confirm.py`: lógica pura + runner injetável (testável sem
rede) + integração que respeita o gating de proxy. Três mudanças:

1. **`lib/zap_authgate.py`** (novo) — lógica pura + enrich injetável.
2. **Fase 9 (`stiglitz.sh`)** — enriquece `zap_alerts.json` com `attack_status`.
3. **Fase 11 (`stiglitz_report.py`)** — particiona, renderiza seção deferred, bloco
   no `findings.json`.

## Componente 1 — `lib/zap_authgate.py`

Lógica pura, sem rede (o fetch é injetado). Funções:

```
def extract_status(response_header):
    """Status HTTP da 1ª linha do response header do ZAP.
    'HTTP/1.1 401 Unauthorized\r\n...' -> 401. Vazio/malformado -> None."""

def needs_status(alert):
    """True se o alerta é active-scan (campo `attack` não-vazio) e ainda não tem
    `attack_status`. Passivos (sem attack) -> False."""

def enrich(alerts, fetch_fn):
    """Para cada alerta com needs_status(), resolve messageId -> attack_status via
    fetch_fn(message_id) -> response_header_str (injetável). Dedup por messageId
    (resolve cada messageId uma vez). Muta os alerts in place e retorna a lista.
    fetch_fn que levanta exceção / devolve None -> attack_status fica ausente."""

def is_authgated_fp(alert):
    """True quando o alerta active-scan foi barrado pelo gate de auth:
    bool(alert.get('attack')) and alert.get('attack_status') in (401, 403).
    Conservador: status ausente ou != 401/403 -> False (não esconde).
    Usado inline pelo loop de ingestão ZAP da Fase 11."""
```

**CLI/runner real (rede):** `enrich` recebe um `fetch_fn` que, em produção, faz
GET em `http://127.0.0.1:<ZAP_PORT>/JSON/core/view/message/?id=<messageId>` e extrai
o `responseHeader` do JSON retornado. O runner vive no módulo (ex.: `main()` que lê
`zap_alerts.json` + base URL do ZAP via argv/env), invocado pela Fase 9. Localhost
(controle do ZAP), portanto **não** passa por proxy — consistente com o resto do
controle ZAP.

## Componente 2 — Fase 9 (`stiglitz.sh`)

Após gravar `zap_alerts.json` (linha ~1993), com o daemon ZAP ainda vivo, invocar:

```
python3 "$SCRIPT_DIR/lib/zap_authgate.py" enrich \
    "$OUTDIR/raw/zap_alerts.json" "http://${ZAP_HOST}:${ZAP_PORT}"
```

O runner lê os alerts, resolve `attack_status` para os active-scan, regrava o JSON.
Degrada em silêncio: se a API do ZAP não responder, deixa `attack_status` ausente
(o detector trata ausência como desconhecido → não defere). Não bloqueia a fase.

## Componente 3 — Fase 11 (`stiglitz_report.py`)

No bloco de ingestão ZAP (zap_dedup, ~linha 329–410), antes de um alerta virar
`f_entry` que entra em `zap_findings`/`all_f`:

- Aplicar `zap_authgate.is_authgated_fp(alert)` sobre o alerta cru do ZAP.
- Se True: rotear para uma lista `_deferred_authgated` (com nome, url, param,
  attack, attack_status) — **nunca** entra em `all_f`, contagens de severidade ou
  criticidade.
- Se False: fluxo atual inalterado.

**Seção HTML** (irmã das demais, após a seção PCI/OWASP): `<h2>Deferred — Requires
Authenticated Retest</h2>`, com nota explicando o critério, e uma tabela agrupando
por endpoint os candidatos (nome do alerta, params, "all returned 40x unauth").
Renderizada só se houver itens deferred.

**`findings.json`:** novo campo top-level `deferred_findings` (lista dos itens
deferred com category/endpoint/param/attack_status). Aditivo.

## Fluxo de dados

```
Fase 9 (ZAP vivo):
  zap_alerts.json (alerts com messageId)
    → zap_authgate.enrich(alerts, fetch=core/view/message)
    → zap_alerts.json + attack_status por alerta active-scan

Fase 11 (report):
  alerts crus → is_authgated_fp() ?
    sim → _deferred_authgated → seção HTML + deferred_findings (JSON)
    não → fluxo atual (zap_findings → all_f → criticidade → contagens)
```

## Tratamento de erros / edge cases (fail-safe: na dúvida, não esconder)

| Situação | Comportamento |
|---|---|
| `attack_status` ausente/desconhecido | NÃO defere — mantém como hoje |
| `attack_status` ∈ {200,500,…} (não 401/403) | NÃO defere — query pode ter rodado |
| Alerta passivo (sem `attack`) | NÃO defere por construção |
| `attack_status` ∈ {401,403} | Defere para a seção retest |
| Scan autenticado (token válido) | Auto-ajuste: ataque → 200, não defere |

## Testes

**`tests/test_zap_authgate.py` (puro):**
- `extract_status`: `"HTTP/1.1 401 Unauthorized\r\n"` → 401; `"HTTP/2 403 ..."` → 403;
  `""`/`"lixo"` → None.
- `is_authgated_fp` (matriz): attack+401 → True; attack+403 → True; attack+200 →
  False; attack + status ausente → False; **sem attack + 401 → False** (passivo);
  attack+500 → False.
- `enrich`: com `fetch_fn` que mapeia messageId→header (sem rede), popula
  `attack_status`; dedup (mesmo messageId resolvido uma vez — fetch_fn contado);
  alerta passivo não recebe status; fetch_fn que falha → status ausente.
- `partition`: separa kept/deferred; não muta a entrada; ordem preservada.

**Wiring (`tests/test_report_*_wiring.py`, padrão existente):**
- Um SQLi com `attack` + `attack_status=401` NÃO entra nas contagens de severidade e
  aparece em `deferred_findings`.
- Um alerta active-scan com `attack_status=200` PERMANECE nas contagens (não escondido).
- Um alerta passivo (header ausente) com nenhum `attack` permanece normal.

## Critérios de sucesso

1. Scan futuro deslogado contra API auth-gated: o falso CRITICAL de SQLi sai das
   contagens de topo e aparece na seção "Deferred — Requires Authenticated Retest".
2. `findings.json` contém `deferred_findings` com os endpoints/params.
3. Findings legítimos (active-scan com 200, ou passivos) **não** mudam — severidades
   e ordenação idênticas vs. antes para o que não é auth-gated.
4. Scan antigo sem `attack_status`: nada é deferido (fail-safe).
5. Suíte de testes verde, incluindo os novos casos.

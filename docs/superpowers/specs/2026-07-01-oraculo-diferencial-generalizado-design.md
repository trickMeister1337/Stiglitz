# Design — Generalização do oráculo de confirmação diferencial (LFI / SSTI / cmd-injection)

> Higienizado para versionamento: **nenhum dado de CDE/cliente/alvo**. Estado snapshot —
> verificar contra o git antes de afirmar. **Criado: 2026-07-01.**

**Origem:** Tier 0.2 do parecer de 2026-07-01 sobre o Stiglitz. Estende o item #1 do
`ROADMAP-analyst-parity.md` (oráculos de confirmação diferencial), hoje limitado a **open
redirect** e **SQLi error-based**, para mais três classes **in-band**: **LFI/path-traversal**,
**SSTI** e **command-injection**. Classes **cegas** (blind SSRF/RCE/SSTI/XXE) permanecem fora —
são o Tier 0.1 (OOB self-host), item separado.

**Tese (herdada do item #1):** nada é finding sem passar no experimento de controle. Um candidato
só é `CONFIRMED` quando um par diferencial mostra que o efeito é atribuível à **semântica do
payload** — presente no ataque, ausente num controle do mesmo formato que **não** deveria disparar.

**Disciplina de entrega:** TDD (teste→RED→GREEN); lógica pura + CLI + `send_fn`/`fetch_fn`
injetável primeiro (padrão `confirm_oracle.py`/`bola.py`/`apm_probe.py`), integração depois.
`bash -n` + `shellcheck --severity=warning` limpos, `py_compile`, `pytest`. Fail-safe / fail-closed.
Findings/evidence em EN (deliverable); console/comentários PT-BR.

---

## A ideia unificadora — efeito por "valor computado"

O que torna as três classes sólidas (baixo-FP) é que, em todas, o efeito é um **valor derivado
que um mero eco do payload não consegue produzir**. Isso mata de raiz o falso-positivo da "página
que reflete o payload":

| Classe | Ataque | Efeito (valor computado) | Controle | FP que o controle mata |
|---|---|---|---|---|
| **LFI/traversal** | param → `../../../../etc/passwd` | assinatura `root:.*:0:0:` no corpo | mesma profundidade → nome de arquivo inexistente | página que sempre contém `root:` por motivo alheio |
| **SSTI** | `{{1337*1337}}` (templado) | produto `1787569` no corpo | mesma expressão **sem** delimitadores (não-templada) | página que ecoa `{{1337*1337}}` literal |
| **Cmd-injection** | `;expr 1000 + 337` | resultado `1337` no corpo | `;expr 1000 + 336` → `1336` | página que reflete `expr 1000 + 337` literal |

Em cada caso o `differential_verdict(attack_signal, control_signal, cls)` **já existente** decide:
efeito no ataque ∧ ausente no controle → `CONFIRMED`; presente em ambos → `REJECTED` (barreira/eco
genérico); ausente no ataque → `REJECTED` (sem sinal diferencial). Nenhuma mudança no núcleo de
decisão — só novos detectores de efeito e builders.

---

## Pré-requisito: roteamento correto no `classify_vuln` (poc_validator.py)

Hoje `classify_vuln` (linha ~413) retorna `"sqli"` para **qualquer** id/nome/tag contendo
`"injection"` — então `template-injection` e `command-injection` do nuclei caem no validador
**sqli** (misclassificação). Além disso, o bloco OOB (linha ~997) já referencia
`vuln_type in ("ssrf", "rce", "ssti")`, mas `classify_vuln` **nunca** retorna `"ssti"`/`"rce"` —
esse caminho OOB é **código morto** hoje.

**Mudança:** adicionar dois ramos **antes** da linha gulosa do sqli:

```
if any(x in tid for x in ["ssti", "template-injection", "server-side-template"]):  return "ssti"
if any(x in tid for x in ["command-injection", "cmd-injection", "os-command",
                          "rce", "remote-code-exec"]):                             return "cmdi"
```

`"lfi"` já existe (linha ~415, com `validators/lfi.py`) — para LFI **não** há mudança de classify,
só o oráculo novo.

**Consequências (intencionais):**
1. Findings de SSTI/cmd-injection deixam de ser processados pelo validador sqli e passam a ter
   validador dedicado (correção de bug de roteamento). É **mudança de comportamento** para esses
   findings — os novos validadores precisam de fallback legado sólido (nuclei match + diff) para
   não regredir quem não tiver par-oráculo limpo.
2. O caminho OOB de **SSTI** (linha ~997) torna-se alcançável quando `INTERACTSH_SERVER` está setado
   (efeito colateral benéfico, gated). Durante a implementação, verificar que `oob.new_payload("ssti")`
   e `inject_oob_url(..., "ssti", ...)` já tratam `"ssti"`; se não tratarem, o gate degrada em no-op
   (fail-safe), sem regressão.
3. OOB para **cmdi** fica como **follow-up anotado** (não incluir `"cmdi"` na tupla da linha 997
   nesta entrega — evita depender de payload OOB inexistente para essa chave).

O teste `test_nuclei_template_coverage` exige um plug-in registrado para **cada** tipo retornado
por `classify_vuln`, então adicionar `"ssti"`/`"cmdi"` **obriga** criar `validators/ssti.py` e
`validators/cmdi.py` (o teste é o gate de completude).

---

## Componente 1 — `confirm_oracle.py` (núcleo puro, sem rede)

Novos símbolos, espelhando `build_sqli_error_variants` / `sqli_error_effect` já existentes.

### LFI / path traversal
- `passwd_signature(body)` → `{"signal", "detail"}`. Assinaturas inequívocas: unix
  `root:.*:0:0:` (regex ancorada em campo UID/GID `:0:0:`), Windows `\[extensions\]` /
  `for 16-bit app support` (win.ini), `\[boot loader\]`.
- `lfi_effect(resp)` → adapta `{"status","headers","body"}` → sinal via `passwd_signature`.
- `build_lfi_variants(url, method, body)` → `(attack, control) | None`.
  - Seleciona o parâmetro-alvo: valor contendo `../`, `..\`, `%2e%2e`, `/etc/`, `passwd`,
    `boot.ini`, `win.ini` (payload que o nuclei já injetou); senão o 1º parâmetro.
  - `attack`: param = traversal profundo (`../` × N) + `etc/passwd`.
  - `control`: **mesma** profundidade + nome inexistente (`etc/stiglitz_absent_<sufixo-fixo>`),
    para que qualquer assinatura só-no-ataque seja atribuível à leitura do arquivo real.
  - `None` se a query não tiver parâmetros (fail-safe → oráculo ausente → fallback legado).

### SSTI
- `ssti_product_present(body, expected)` → `{"signal","detail"}`. Substring exata do produto.
- `ssti_effect(resp, expected)` → adaptador (o `expected` entra por closure na orquestração).
- `build_ssti_variants(url, method, body)` → `(attack, control, expected) | None`.
  - Detecta a sintaxe do payload já injetado (`{{...}}` Jinja/Twig, `${...}` EL/Freemarker,
    `#{...}`, `<%= %>`); default `{{ }}` se indetectável.
  - Fatores distintos (dois números de 4 dígitos) → `expected` = produto (substring improvável
    de ocorrer por acaso). `attack`: expressão **templada**. `control`: a **mesma** expressão
    **sem** os delimitadores (string literal, não avaliada) — se o motor avalia templates,
    `expected` aparece só no ataque; se a página ecoa, `expected` some de ambos → `REJECTED`.
  - `None` se não houver parâmetro injetável.

### Command injection (in-band)
- `cmdi_result_present(body, expected)` → `{"signal","detail"}`. Substring exata do resultado.
- `cmdi_effect(resp, expected)` → adaptador (`expected` por closure).
- `build_cmdi_variants(url, method, body)` → `(attack, control, expected) | None`.
  - `expected` = soma computada (número distinto). `attack`: `<sep>expr <A> + <B>` com
    separador de shell (`;`, `$( )`, crase, `|`, `&&`) — **unix** nesta entrega.
  - `control`: **mesma** forma com `<B-1>` → resultado difere de `expected`. Reflexão do payload
    mostraria `expr <A> + <B>` (não o resultado) em ambos → `expected` ausente → `REJECTED`.
  - **Windows (`set /a`) é follow-up anotado** — YAGNI nesta entrega.
  - `None` se não houver parâmetro injetável.

Notas de robustez (reusar helpers existentes do módulo): `_safe_int` para status não-numérico
(`parse_http_response` pode devolver `'???'`/`'000'`/`'ERR'`); `parse_header_block` para headers
crus; sem domínio hardcoded; sem rede no núcleo.

---

## Componente 2 — wiring em `poc_validator.confirm_nuclei`

Três blocos novos, **idênticos em forma** aos de redirect/sqli (linhas ~906–952), guardados por
`_CONFIRM_ORACLE_AVAILABLE and vuln_type == "<classe>"`:

- Constrói variantes via `build_<classe>_variants(url, method, req_body)`.
- `_send_<classe>(req)` local: `run_cmd(_apply_oauth(_req_to_curl(req)), timeout=15, retries=1)`;
  erro → `{"status":"000","headers":{},"body":""}`; senão `parse_http_response` +
  `parse_header_block`. (LFI/SSTI/cmdi seguem redirects por padrão — sem `follow=False`, que é
  específico do redirect.)
- `run_differential(url, attack, control, effect_fn, send_fn, "<cls>")`. Para SSTI/cmdi o
  `effect_fn` é uma closure que fecha sobre o `expected` retornado pelo builder.
- Novos kwargs em `validate(...)`: `lfi_oracle=None`, `ssti_oracle=None`, `cmdi_oracle=None`
  (default `None`), repassados ao `ctx`. Builder `None`/fetch falho → oracle `None` → fallback.

---

## Componente 3 — validadores (`lib/validators/`)

Semântica **uniforme** nas três classes:

- `oracle = ctx.get("<classe>_oracle")`; se `oracle and oracle["state"] == "CONFIRMED"` →
  `return (True, oracle["confidence"], "…confirmed by differential oracle: <evidence>")`.
- `REJECTED` **ou ausente** → **cai no fallback legado** (não veta). Preserva "aditivo, nunca some"
  e o precedente do SQLi (`REJECTED` não veta os demais sinais). Escolha conservadora: as três
  classes têm sinal legado forte independente (regex de `/etc/passwd`, match do nuclei), e o
  oráculo é um **caminho adicional** de confirmação, não um gate.

Arquivos:
- `validators/lfi.py` — **editar**: prepend do bloco do oráculo antes da lógica de assinatura atual.
- `validators/ssti.py` — **novo**: bloco do oráculo + fallback (nuclei match + `diff_changed`/
  `diff_conf`, no molde de `lfi.py`).
- `validators/cmdi.py` — **novo**: idem.

---

## Plano de teste (TDD)

- **Puros por classe** (`tests/test_confirm_oracle.py`, estender): cada `*_signature`/`*_present`/
  `*_effect`/builder com casos — positivo, controle-limpo, **eco-FP** (payload refletido não
  dispara), parâmetro-ausente (→ `None`), status não-numérico, evasão de profundidade (LFI).
- **`differential_verdict`**: já coberto; acrescentar os `cls` novos (`lfi`/`ssti`/`cmdi`).
- **`classify_vuln`**: casos garantindo que `template-injection`→`"ssti"`, `command-injection`→
  `"cmdi"`, e que `sqli`/`union` seguem `"sqli"` (não-regressão do roteamento).
- **Cobertura de validador**: `test_nuclei_template_coverage` deve continuar verde (os novos tipos
  têm plug-in).
- **Wiring/degradação** (`tests/test_poc_validator_*`, molde redirect/sqli): builder `None`/fetch
  falho → oracle `None` → fallback legado (sem regressão).
- Ao final: `bash -n` (n/a, sem mudança de bash) · `python3 -m py_compile lib/*.py` ·
  `shellcheck` (inalterado) · `python3 -m pytest tests/` limpos.

---

## Fora de escopo (YAGNI)

- Classes **cegas** (OOB) — Tier 0.1 (OOB self-host on-by-default).
- **SSRF refletido** in-band — escopo recusado (SSRF real de payment API é dominado pelo OOB).
- **Windows `set /a`** no cmdi — follow-up anotado.
- Integração OOB de **cmdi** (tupla da linha ~997) — follow-up.
- Refatorar `confirm_oracle.py` em pacote — prematuro (YAGNI); arquivo único (~300→~450 linhas).

---

## Integração com o pipeline (inalterada)

Nenhuma mudança de fase no `stiglitz.sh`: os oráculos rodam dentro do `poc_validator.confirm_nuclei`
(Fase 5 — confirmação ativa de exploits), que já é chamado no fluxo existente. Sem nova env var,
sem nova dependência externa. Findings entram com `state` `CONFIRMED`/`REJECTED` + `evidence`
diferencial, como redirect/sqli.

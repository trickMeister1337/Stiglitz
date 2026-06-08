# Design — Boolean-pair / canário nos validators (redução de FP/FN)

**Data:** 2026-06-07
**Roadmap:** P1 — item "verificação boolean-pair/canário nos *validators existentes* (poc_validator, FP/FN) — o canário já foi feito no bola.py, generalizar".
**Status:** aprovado (design); pendente plano de implementação.

## Problema

Os validators de injeção (`lib/validators/sqli.py`, `xss.py`) hoje confirmam por:
1. regex de padrão no corpo (prova direta), ou
2. `response_diff` — um **diff único** entre a resposta do payload e um baseline com
   payload neutralizado (`build_safe_baseline`).

O diff só-por-tamanho (`diff_conf≈15`) é explicitamente "a maior fonte de FP": conteúdo
dinâmico legítimo varia de tamanho e dispara o sinal. Exigir `double_check` mitiga FP mas
introduz FN (blind real sem mudança de tamanho perceptível passa batido). Falta um sinal
**determinístico** de confirmação para casos cegos.

O `lib/bola.py` já provou o padrão correto: um veredito puro (`verdict()`) sobre respostas
comparadas + canário de corpo, com reuso de `normalize`/`response_diff`. Esta entrega
**generaliza** duas técnicas desse espírito para os validators de injeção.

## Decisões (travadas no brainstorming)

- **Profundidade:** lógica pura **+** wiring ativo (probes disparados no `confirm_nuclei`).
- **Gating:** **sempre on** em todos os perfis (par booleano e canário são read-only:
  `AND 1=1`/`AND 1=2` e marcador aleatório — sem `UNION`/`DROP`/mutação; o `confirm_nuclei`
  já replica payloads + baseline + métodos).
- **Cobertura:** par booleano só em `sqli`; canário de reflexão só em `xss`. O módulo puro
  fica genérico o suficiente para estender (lfi/generic) num plano futuro.
- **Arquitetura:** módulo puro `lib/active_probe.py` calcula o veredito; o orquestrador o
  injeta no `ctx`; o validator apenas **eleva** o sinal quando presente (espelha bola/takeover).

## Arquitetura & fluxo

```
confirm_nuclei (rede)                lib/active_probe.py (puro)         validators/ (puro)
─────────────────────                ─────────────────────────         ──────────────────
finding sqli/xss
  já busca: safe-baseline + payload
  ── se sqli:
       build_boolean_variants(curl) ──► (true_curl,false_curl) | None
       fetch true,false
       boolean_pair_verdict(base,t,f) ─► {confirmed,confidence,note}
                                          → ctx["bool_pair"] ─────────► sqli.py: se bool_pair.confirmed
                                                                          → usa (prioridade sobre size-diff)
  ── se xss:
       build_canary_variant(curl,tok) ─► canary_curl | None
       fetch canary
       canary_reflection(tok,body) ────► {reflected,encoded,confidence,note}
                                          → ctx["canary"] ────────────► xss.py: refletido não-encodado
                                                                          → confirma; encodado → baixa
```

**Propriedade de segurança central (não-regressão):** se o builder não identifica um ponto
de injeção limpo (quoting/param ambíguo) **ou** o fetch do probe falha, retorna `None` →
`ctx` sem o campo → o validator cai **exatamente** no comportamento atual. O caminho novo
**só adiciona** sinal de confirmação; ausência de probe = zero regressão.

## Componente: `lib/active_probe.py` (novo — puro + CLI)

Reusa `normalize`/`response_diff` de `poc_validator` via try-import com fallback (mesmo
padrão de `bola.py`), para ser importável fora do pacote e testável sem rede.

### Builders de payload (transformam o curl reconstruído)

```python
def build_boolean_variants(curl_cmd, safe="safe-test-value-123"):
    """(true_curl, false_curl) | None.
    Substitui a região de injeção (mesmas âncoras do build_safe_baseline:
    keyword SQL entre aspas e/ou valor de parâmetro de query) por:
        <safe>' AND '1'='1   (true / tautologia)
        <safe>' AND '1'='2   (false / contradição)
    Retorna None se nenhuma região injetável for identificada → fallback."""

def new_canary_token():
    """Marcador único, curto e busca-seguro: 'stg' + 8 hex (os.urandom).
    Improvável de colidir com conteúdo legítimo do alvo. Alfanumérico puro
    para busca inequívoca no corpo."""

PROBE_CHARS = '<">'   # quebra-de-contexto benigna anexada ao token

def build_canary_variant(curl_cmd, token):
    """canary_curl | None. Injeta `token + PROBE_CHARS` na região de payload XSS
    detectada (mesmas âncoras XSS do build_safe_baseline). Os chars de quebra
    permitem distinguir reflexão crua (XSS provável) de reflexão escapada (safe).
    None se nada substituível."""
```

### Vereditos puros

```python
def boolean_pair_verdict(baseline_norm, true_norm, false_norm):
    """{confirmed: bool, confidence: int, note: str}.

      TRUE≈baseline ∧ FALSE≠baseline ∧ TRUE≠FALSE → confirmed=True,  conf=88
      tudo ≈ igual (condição sem efeito)           → confirmed=False, conf=25
      sinal parcial (só um dos critérios)          → confirmed=False, conf=40
      baseline < guard mínimo (50B, via response_diff) → inconclusivo, conf=20
    Comparações via response_diff(normalize(...))."""

def canary_reflection(token, resp_body):
    """{reflected: bool, encoded: bool, confidence: int, note: str}.

      token seguido dos PROBE_CHARS crus (< " >) no corpo → reflected, !encoded, conf=90
      token presente mas PROBE_CHARS HTML-escapados        → reflected,  encoded, conf=35 (provável safe)
        (procura `&lt;`/`&quot;`/`&gt;` ou `&#x..` adjacentes ao token)
      token ausente                                        → reflected=False,     conf=0

    O token (alfanumérico) localiza a região de reflexão de forma inequívoca; o
    estado dos PROBE_CHARS adjacentes decide cru (XSS provável) vs escapado (safe)."""
```

### CLI

`python3 lib/active_probe.py verdict-bool <baseline> <true> <false>` e
`verdict-canary <token> <body-file>` — paridade com `bola.py`/`takeover.py`,
testável standalone sem rede.

## Mudanças nos validators existentes

`validators/sqli.py` — **antes** do bloco de size-diff:
```python
bp = ctx.get("bool_pair")
if bp and bp.get("confirmed"):
    return True, bp["confidence"], f"Par booleano confirmado: {bp['note']}"
# segue a lógica atual (regex de erro → diff≥20 → size-diff+double-check)
```

`validators/xss.py` — **antes** do bloco de reflexão por regex/size:
```python
cn = ctx.get("canary")
if cn and cn.get("reflected") and not cn.get("encoded"):
    return True, cn["confidence"], f"Canário refletido sem encoding: {cn['note']}"
if cn and cn.get("reflected") and cn.get("encoded"):
    return False, cn["confidence"], f"Refletido mas HTML-encodado (provável safe): {cn['note']}"
# segue a lógica atual
```

## Mudanças no `poc_validator.py`

- `validate(...)`: dois novos kwargs `bool_pair=None, canary=None`, repassados no dict `ctx`
  do dispatch de plugin (o `ctx` já é montado nas linhas ~407-414).
- `confirm_nuclei`: após o cálculo de `diff_changed`/`diff_conf`:
  - `vuln_type == "sqli"`: `build_boolean_variants(clean_curl)` → 2 fetches
    (reusa `run_cmd` + `parse_http_response`) → `boolean_pair_verdict(normalize(base), …)`.
  - `vuln_type == "xss"`: `token = new_canary_token()` → `build_canary_variant(clean_curl, token)`
    → 1 fetch → `canary_reflection(token, body)`.
  - Passa os dicts resultantes a `validate(...)`. **Sempre on** (sem gate de profile).
  - Custo: ~+2 req (sqli) / +1 req (xss) por finding desses tipos.
- `confirm_zap`: inalterado nesta fase (o ZAP não reconstrói payload de injeção do mesmo
  modo; o `build_*` retornaria None na maioria dos casos). A chamada `validate()` apenas não
  passa os novos kwargs → fallback. Integração ZAP fica para plano futuro, se houver ganho.

## Testes (TDD)

- `tests/test_active_probe.py` (novo):
  - builders: caso feliz (substituição correta) e caso `None` (sem região injetável).
  - `boolean_pair_verdict`: confirmado / sem-efeito / parcial / baseline-pequeno.
  - `canary_reflection`: não-encodado / encodado / ausente.
  - CLI: `verdict-bool` e `verdict-canary`.
- `tests/test_lib.py` (`TestValidatorPlugins`):
  - `sqli` confirma via `ctx['bool_pair']` e prioriza sobre size-diff fraco.
  - `sqli` sem `bool_pair` mantém comportamento atual (regressão).
  - `xss` confirma via canário não-encodado; rebaixa canário encodado; sem `canary` mantém atual.
- **Validação ao vivo:** Juice Shop + ZAP via docker — SQLi em `/rest/products/search?q=`
  (par booleano) e um XSS refletido (canário); confirmar elevação de confiança sem FP no baseline.

## Tratamento de erro / não-regressão

- Builder `None` → sem campo no `ctx` → comportamento atual idêntico.
- Fetch do probe com timeout/erro → ausência de sinal (não confirma por par incompleto);
  nunca derruba a confirmação do caminho legado.
- `boolean_pair_verdict` herda o guard de baseline mínimo (50B) do `response_diff`;
  baseline pequeno → inconclusivo.

## Fora de escopo (YAGNI / plano futuro)

- Boolean-pair para `lfi`/`auth_bypass`; canário para `generic`.
- Wiring no `confirm_zap`.
- Variantes de quoting numérico/múltiplas formas de payload (hoje: uma forma quoted padrão;
  ausência de região limpa → fallback, sem FN novo introduzido além do já existente).

## Disciplina de entrega

TDD (teste→RED→GREEN), commits pequenos com `bash -n`/`shellcheck`/`py_compile` limpos,
validação ao vivo dos caminhos críticos. Reuso de `normalize`/`response_diff`/`run_cmd`/
`parse_http_response` (sem duplicar). Núcleo puro + CLI (convenção bola/takeover).

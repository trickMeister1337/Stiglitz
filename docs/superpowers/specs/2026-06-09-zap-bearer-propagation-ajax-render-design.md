# ZAP bearer-token session propagation + AJAX render (chromium) — Design

> Higienizado para versionamento: **nenhum dado de CDE/cliente/alvo** aqui.
> Data: 2026-06-09. Item P1 restante do `docs/ROADMAP.md`.

## Problema

Na Fase 9 do `stiglitz.sh`, quando o operador passa só um bearer token (`--token`/`-t`,
sem login form via `STIGLITZ_AUTH_*`), o token chega **tarde demais**: o replacer rule
`Authorization: Bearer <token>` é adicionado no bloco de pre-warm (~linha 1505), **depois**
do ZAP Spider e do AJAX Spider já terem rodado. Consequências:

1. **Spider e AJAX Spider crawleiam deslogados** — rotas/parâmetros atrás de auth nunca
   entram no site-tree nem no histórico do ZAP. O token só passa a valer no active-scan,
   no force-crawl manual e no katana autenticado.
2. **Fronteira do BOLA reduzida** — a Fase 9.5 (`lib/bola.py`) replica requisições gravadas
   no histórico do ZAP com tokens A/B. Se o spider rodou deslogado, os endpoints autenticados
   nem existem no histórico → BOLA tem menos superfície real para testar acesso indevido.

Em paralelo, o **AJAX Spider não renderiza** neste ambiente: o ZAP usa o browser default
(`firefox-headless`) e não há firefox/geckodriver instalado — só **chromium**
(`/snap/bin/chromium`, `/usr/bin/chromium-browser`). O bloco já degrada com
`[○] AJAX Spider indisponível (add-on/browser ausente)`, mas nunca chega a rodar.

## Objetivos

- Propagar o bearer token (e header customizado `--header`) para **todo** o tráfego ZAP da
  Fase 9 — spider, AJAX spider, active-scan e, por consequência, o histórico que a P9.5 consome.
- Avisar o operador **antes** do scan se o JWT vai expirar dentro da janela estimada, evitando
  queimar 30+ min de scan com token morto.
- Fazer o AJAX Spider efetivamente renderizar via **chromium-headless** neste ambiente,
  com preflight de detecção de browser e degradação graciosa quando indisponível.

## Não-objetivos (fora de escopo)

- **Auto-refresh de token** (re-login ao detectar 401). Decisão tomada: token estático +
  pré-check de `exp`; o operador renova e re-roda. Documentado como limitação.
- Instalar firefox/geckodriver no ambiente.
- Follow-ups conhecidos da P9.5/P9.6 (wiring de findings no `findings.json`/SARIF; adicionar
  as fases ao `pipeline.py` PHASES). Continuam no roadmap, não entram aqui.

## Arquitetura

Todas as mudanças ficam na **Fase 9** do `stiglitz.sh`, mais um helper puro novo em
`lib/jwt_audit.py`. **Nenhum módulo bash novo** — diferente de `bola.py`/`takeover.py`,
porque isto é orquestração de fase (ordem de chamadas à API do ZAP), não lógica de domínio
isolável. A disciplina "lógica pura + CLI primeiro" se aplica apenas ao pedaço testável
(pré-check de `exp`), que vai pro `jwt_audit.py`.

### Parte A — propagação do bearer token

**Helper bash novo `zap_inject_auth_headers()`** (junto dos demais helpers ZAP, perto de
`zap_setup_auth_context`):

1. Se `AUTH_TOKEN` setado: roda o pré-check de `exp` (ver abaixo) e emite aviso; depois
   adiciona o replacer rule `Authorization: Bearer <token>`
   (`matchType=REQ_HEADER&matchString=Authorization`). Semântica do Replacer do ZAP:
   com a Authorization ausente na requisição, a regra **adiciona** o header; presente, **substitui**.
2. Se `AUTH_HEADER` setado: adiciona o replacer rule do header customizado (mesma lógica
   hoje na ~linha 1543).
3. Degrada sem abortar (padrão das demais chamadas ZAP: `> /dev/null 2>&1`, mensagens `[○]`).

**Ponto de chamada:** logo após `zap_setup_auth_context` (~linha 1428) e **antes** do
`spider/action/scan`/`scanAsUser`. Assim spider → AJAX → active-scan → histórico (P9.5)
herdam o header.

**Remoção do duplicado:** retirar o `replacer/action/addRule` de `Authorization` do bloco
de pre-warm (~linhas 1506-1513) e o de header customizado (~1543-1551). O **force-crawl**
de endpoints protegidos e o **katana autenticado** continuam no pre-warm — dependem do
token, que agora já foi injetado antes (ordem preservada, sem regressão).

**Interação com form-auth (`STIGLITZ_AUTH_*`):** o replacer atua no HttpSender do ZAP e é
global; coexiste com o contexto `scanAsUser` (form-auth) sem conflito — o header é somado por
cima. Na prática o operador usa um modo OU outro; ambos setados é suportado mas não é o caso
comum.

### Pré-check de `exp` (pure + CLI, em `jwt_audit.py`)

Função pura nova:

```python
def exp_status(token, window_seconds, now_ts):
    """Classifica o exp do JWT contra uma janela de scan.
    Retorna dict: {"state": "expired"|"expires_within"|"ok"|"no_exp"|"malformed",
                   "exp": <int|None>, "remaining": <int|None>}.
    now_ts injetado (não usa relógio) → testável de forma determinística.
    """
```

- `malformed`: `decode_jwt` levanta → não é JWT decodificável.
- `no_exp`: payload sem `exp`.
- `expired`: `exp <= now_ts`.
- `expires_within`: `now_ts < exp <= now_ts + window_seconds`.
- `ok`: `exp > now_ts + window_seconds`.

Reusa `decode_jwt` já existente. Subcomando CLI:
`python3 lib/jwt_audit.py exp-check <token> <window_seconds> <now_ts>` → imprime o `state`
(e `remaining` quando aplicável) em uma linha parseável pelo bash.

**Consumo no bash:** o `zap_inject_auth_headers()` calcula
`window = ZAP_SPIDER_TIMEOUT + ZAP_AJAX_TIMEOUT + ZAP_SCAN_TIMEOUT` (com defaults atuais
600 + 180 + 1200 = 1980s ≈ 33min), passa `$(date +%s)` como `now_ts`, e mapeia:
- `expired` → aviso **vermelho** `[✗] token JWT já expirou — scan rodará deslogado`.
- `expires_within` → aviso **amarelo** `[!] token expira em ~Nmin (janela ~33min) — pode perder cobertura no fim`.
- `ok`/`no_exp`/`malformed` → silencioso ou `[○]` informativo; segue normal.

Sem abortar em nenhum caso (degradação).

### Parte B — render AJAX (chromium-headless)

**Preflight de browser** dentro do bloco `if [ "${STIGLITZ_AJAX_SPIDER:-1}" = "1" ]`, antes
do `ajaxSpider/action/scan`:

1. Detectar browser disponível, nesta ordem de preferência:
   - `chromium`/`chromium-browser`/`google-chrome`/`chrome` → `browserId=chrome-headless`
   - `firefox`/`firefox-esr` (+ geckodriver) → `browserId=firefox-headless`
   - nenhum → setar flag de skip; manter a mensagem `[○] AJAX Spider indisponível` existente.
2. `zap_api_call "ajaxSpider/action/setOptionBrowserId" "String=<browserId>"` antes de iniciar.
3. Se o chromium não for localizado pelo ZAP, apontar o binário via
   `selenium/action/setOptionChromeBinaryPath` (path do `command -v chromium`).

**Risco conhecido (snap):** o ZAP é snap (`/snap/bin/zaproxy`) e o chromium do sistema também
é snap — o confinamento pode bloquear o launch de um snap por outro. Isto será resolvido na
**validação ao vivo**, não comprometido às cegas no design. Fallbacks candidatos, em ordem,
se o launch falhar: (a) webdriver embutido do add-on Selenium do ZAP; (b) chromium/chromedriver
não-snap (apt); (c) ZAP não-snap. Independente do resultado, a fase **degrada sem abortar**
(a mensagem `[○]` já cobre).

## Fluxo de dados (Fase 9, ordem nova)

```
ZAP API up
  → WAF evasion replacer (se WAF)
  → OpenAPI import
  → JWT audit estático
  → GraphQL introspection
  → injeção de URLs do Katana
  → zap_setup_auth_context            (form-auth, se STIGLITZ_AUTH_*)
  → zap_inject_auth_headers   ← NOVO  (exp pre-check + replacer Bearer/header customizado)
  → ZAP Spider                        (agora COM token no HttpSender)
  → preflight browser + setOptionBrowserId   ← NOVO  (escolhe chrome-headless)
  → AJAX Spider                       (agora COM token E renderizando via chromium)
  → contagem de URLs
  → pre-warm + force-crawl + katana autenticado   (replacer removido daqui)
  → Active Scan                       (COM token)
  → [P9.5 BOLA consome histórico mais rico]
```

## Tratamento de erros / degradação

- `exp_status` malformado/sem-exp → segue sem aviso bloqueante.
- `setOptionBrowserId`/`setOptionChromeBinaryPath` falham → `[○]` e fallback de browser ou skip.
- AJAX Spider não inicia (browser ausente/confinado) → mensagem existente, fase continua.
- Replacer falha → `[○]`, scan segue (não autenticado), sem abortar.

## Testes

**Unit (pytest, `tests/test_lib.py`):**
- `exp_status`: `expired`, `expires_within`, `ok`, `no_exp`, `malformed`. `now_ts` fixo →
  determinístico, sem dependência de relógio.

**Estático:**
- `bash -n stiglitz.sh` limpo.
- `shellcheck --severity=warning stiglitz.sh` limpo.
- `python3 -m py_compile lib/jwt_audit.py`.

**Ao vivo (Juice Shop + ZAP via docker):**
- **Bearer:** rodar `bash stiglitz.sh <juice-shop> --token <jwt>`; confirmar rotas
  autenticadas no site-tree do ZAP (ex.: contagem de URLs com token-antes vs baseline sem).
- **AJAX:** `ajaxSpider/view/status` chega a `stopped` com `numberOfResults > 0` (renderizou)
  em vez de cair no `[○] indisponível`.
- **BOLA:** P9.5 enxerga mais requisições candidatas a replay (efeito da fronteira expandida).

## Critério de pronto

- Suite verde (atual 514 passed / 4 skipped + os novos casos de `exp_status`).
- `bash -n` + `shellcheck` limpos.
- Validação ao vivo dos três pontos acima registrada (ou, se o confinamento snap bloquear o
  AJAX, a degradação confirmada + caminho documentado para destravar).
- Commits pequenos, TDD (teste → RED → GREEN) no pedaço puro.

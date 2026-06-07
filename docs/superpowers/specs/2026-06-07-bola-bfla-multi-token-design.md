# BOLA/BFLA multi-token (OWASP API #1) — Design

> Spec de design. Fonte de verdade para o plano de implementação. Verificar assinaturas contra o código antes de afirmar (este doc é snapshot de 2026-06-07).

## Objetivo

Adicionar detecção de **Broken Object Level Authorization (BOLA / IDOR)** e **Broken Function Level Authorization (BFLA)** — OWASP API Security #1 — ao `stiglitz.sh`, usando **dois tokens** (`--token-a` / `--token-b`). Um motor de replay reproduz requisições reais gravadas pelo ZAP com a identidade do outro usuário e confirma o acesso indevido por **comparação de resposta + canário de corpo**, sem falso-positivo de recurso público.

Hoje o scan só suporta um token (`--token`/`AUTH_TOKEN`) e não testa autorização cruzada. As classes `bola`, `idor_read_pii`, `idor_write` (CWE-639) **já existem** em `lib/vuln_catalog.py` mas nenhum coletor as produz; falta a classe `bfla` (CWE-285), que este design **adiciona** (uma entrada nova). Este design fecha essa lacuna.

## Decisões (brainstorming 2026-06-07)

| Tema | Decisão |
|------|---------|
| Escopo v1 | BOLA **e** BFLA, motor de replay compartilhado |
| Fonte do corpus | ZAP message history (`core/view/messages`) do crawl autenticado |
| Métodos reproduzidos | Só **GET/HEAD/OPTIONS** (read-only; sem mutação de dado alheio) |
| Confirmação | Tripla **A / B / unauth** + **canário de corpo** (corpo do cross contém ID/PII do objeto do dono) |
| Modelo de tokens | **Simétrico bidirecional** (testa B→objetos de A e A→objetos de B; sem assumir hierarquia) |
| Posicionamento | Nova fase **P9.5 Access Control** no `stiglitz.sh`, após a P9 (ZAP) — no scan, não gated no RED |

## Arquitetura

Lógica pura e testável em `lib/bola.py` (funções sem rede) + orquestração de rede fina no mesmo módulo; o `stiglitz.sh` (nova fase P9.5) captura os dois corpora via ZAP e invoca o módulo. Reuso deliberado: `response_diff`/`normalize` (`poc_validator.py`), classes `bola`/`idor_read_pii`/`idor_write` (`vuln_catalog.py`), `fingerprint.py`. **Única adição ao catálogo:** uma entrada `bfla` (CWE-285) no `vuln_catalog.py`.

### CLI e ativação (`stiglitz.sh`)

- Novos args: `--token-a <jwt>` e `--token-b <jwt>`.
- Retrocompat: `--token`/`-t` continua e é **apelido de `--token-a`**.
- A fase P9.5 **só ativa quando ambos** `--token-a` e `--token-b` estão presentes. Com um token só → comportamento atual inalterado (fase silenciosa, opt-in).
- Invocável isoladamente pelo `pipeline.py` (`--only-phase`), com checkpoint, no padrão das demais fases.

### Captura dos dois corpora (P9 + P9.5)

- A **P9** (spider + active scan autenticado) passa a usar **`token-a`** (via o caminho atual do `AUTH_TOKEN`/replacer rule). Seu message history é o corpus de A.
- A **P9.5** dispara um **spider-only leve autenticado como `token-b`** (troca a replacer rule do `Authorization` para B, **sem** active scan; profundidade reduzida em `production`). Captura o corpus de B.
- Os dois históricos são exportados via `core/view/messages` para `raw/zap_messages_a.json` e `raw/zap_messages_b.json`.

### Gating de perfil / segurança

- A fase é read-only (só GET/HEAD/OPTIONS) → roda inclusive em `production`, com o spider-B em profundidade reduzida.
- Tokens passam por env (`BOLA_TOKEN_A` / `BOLA_TOKEN_B`), **nunca em argv** (evita vazamento em `ps`/argv).
- `access_control.json` e os dumps do ZAP ficam no `OUTDIR` (gitignored) — **nunca versionados** (diretriz: nenhum resultado de scan vai ao git).

## Componentes — `lib/bola.py`

### Funções puras (núcleo testável, sem rede)

- `parse_zap_messages(json_text) -> [Request]` — lê o dump do `core/view/messages`; extrai por mensagem `{method, url, req_headers, req_body, status, resp_body}`. Objetos/linhas inválidos ignorados.
- `is_object_ref_request(req) -> bool` — filtra candidatos com referência a objeto: ID numérico em path (`/users/123`), UUID, ou param de query tipo `id=`/`user_id=`/`account=`. Sem object-ref, replay é ruído.
- `is_safe_method(method) -> bool` — só `GET/HEAD/OPTIONS` retornam True.
- `extract_canary(resp_body, content_type) -> set[str]` — extrai identificadores do baseline (o objeto do dono): valores de campos id/email/cpf/pan-mascarado, tokens longos. É o que se procura no corpo do cross-replay.
- `verdict(baseline, cross, unauth, canary) -> dict` — coração da confirmação (ver "Lógica de confirmação"). Retorna `{state, klass, confidence, canary_hit, direction}`.
- `build_findings(verdicts, direction) -> [finding]` — monta entradas no schema do `findings.json` usando as classes do `vuln_catalog.py` (`bola`/`idor_read_pii` p/ leitura de PII; `bfla` p/ vertical — entrada nova), com `fingerprint` (via `lib/fingerprint.py`) e direção (`A→B` / `B→A`).

### Orquestração de rede (isolada)

- `replay(req, token) -> Response` — reemite a requisição via `curl` (mesmo padrão de `poc_validator.run_cmd`: timeout/retry), trocando só o header `Authorization` (ou removendo-o, no caso unauth).
- `run(messages_a, messages_b, token_a, token_b, outdir) -> result` — loop **bidirecional**: candidato → tripla de replays → `verdict` → `build_findings`. Grava `access_control.json` no `outdir`.

### CLI

```
python3 lib/bola.py run <zap_messages_a.json> <zap_messages_b.json> <outdir>
```
Tokens via env `BOLA_TOKEN_A` / `BOLA_TOKEN_B`. Funções puras exercidas direto pelos testes com dados sintéticos (sem rede, domínio `target.com`).

## Fluxo de dados

```
--token-a, --token-b  ──►  P9 (ZAP): crawl+activescan como A  ──►  raw/zap_messages_a.json
                            P9.5: spider-only como B           ──►  raw/zap_messages_b.json
                                       │
                                       ▼
        lib/bola.py run(msgs_a, msgs_b, outdir)   [tokens via env BOLA_TOKEN_A/_B]
                                       │
            ┌──────────────────────────┴───────────────────────────┐
        direção B→A (candidatos de A)              direção A→B (candidatos de B)
        para cada req com object-ref + safe-method:
            baseline = resposta gravada do dono
            cross    = replay(req, token_oposto)
            unauth   = replay(req, sem token)
            canary   = extract_canary(baseline)
            v        = verdict(baseline, cross, unauth, canary)
                                       │
                                       ▼
        access_control.json  +  entradas em findings.json (classes bola/idor/bfla, com fingerprint)
                                       │
                                       ▼
                  relatório HTML (seção nova) + SARIF (já via fingerprint)
```

## Lógica de confirmação (`verdict`)

Por candidato, com `baseline` (dono), `cross` (token oposto) e `unauth`:

1. **PROTECTED** (sem achado): `cross.status ∈ {401, 403}` → autorização funciona. Nada emitido.
2. **PUBLIC** (sem achado): `unauth.status` 2xx **e** corpo ≈ baseline (`response_diff` abaixo do limiar) → recurso público. Descarta (evita o FP clássico).
3. **CONFIRMED**: `cross.status` 2xx **e** `response_diff(baseline, cross)` ≈ idêntico **e** **canário bate** (corpo do cross contém ≥1 identificador do objeto do dono) **e** unauth negado/diferente → BOLA/IDOR confirmado, `confidence` ≥ 85%.
4. **INCONCLUSIVE**: cross 2xx mas corpo *parecido, não idêntico* (mesmo template, dados diferentes) **ou** canário não bate → suspeita de baixa confiança (<60%, **não** confirmada) para triagem. Nunca emitida como CONFIRMED.

### Classe do finding

- Corpo do dono tem PII (email/cpf/pan) → `idor_read_pii`; senão → `bola`.
- **BFLA (vertical) por assimetria de 403:** quando, na **mesma** função, um token alcança 2xx e o outro recebe 403, a assimetria é a evidência → classe `bfla`. Endpoints com path privilegiado (`/admin`, `/internal`) reforçam a classificação. Não se assume hierarquia entre A e B — a direção em que o acesso indevido ocorre é registrada no finding.

### Constantes ajustáveis

Limiar de `response_diff` e o conjunto de campos-canário ficam em **constantes nomeadas no topo do módulo**, com defaults conservadores (preferir FN a FP — alinhado ao threshold de 60% do `poc_validator`).

## Tratamento de erro / degradação

Padrão do projeto — sempre avisa no terminal, nunca aborta a fase:

- Sem `--token-a` **ou** `--token-b` → P9.5 nem ativa (silenciosa; opt-in).
- ZAP não rodou / `zap_messages_a.json` ausente ou vazio → `warn "access-control: sem corpus do ZAP (P9 não rodou?) — BOLA/BFLA pulado"`.
- Spider-only como B falhou → `warn`, segue só com a direção B→A.
- `curl`/replay com timeout → candidato vira `INCONCLUSIVE` (não trava o loop).
- Nenhum candidato com object-ref → `info "access-control: nenhuma requisição com referência a objeto"`.

## Testes (`tests/test_bola.py`, TDD por função)

- `parse_zap_messages`: dump válido + linhas/objetos inválidos ignorados.
- `is_object_ref_request`: `/users/123` e `?id=` ✓; `/about`, `/login` ✗.
- `is_safe_method`: GET/HEAD/OPTIONS ✓; POST/PUT/DELETE ✗.
- `extract_canary`: extrai email/cpf/id; corpo sem PII → set vazio.
- `verdict`: os 4 estados (PROTECTED / PUBLIC / CONFIRMED / INCONCLUSIVE) com fixtures sintéticas — incluindo o FP do recurso público e o canário que não bate.
- `build_findings`: schema correto, classes certas (bola vs idor_read_pii vs bfla), fingerprint presente, direção registrada.
- BFLA por assimetria de 403.
- Smoke do wiring bash: `bash -n` + `shellcheck` limpos; `grep` confirma ativação só-com-dois-tokens e mensagens de degradação.

## Reuso (não reinventar)

- `lib/poc_validator.py`: `response_diff`, `normalize`, padrão `run_cmd` (curl com timeout/retry).
- `lib/vuln_catalog.py`: classes `bola`, `idor_read_pii`, `idor_write` (CWE-639) reusadas; **adiciona** `bfla` (CWE-285, vetor PR:L/C:H/I:H no padrão das demais entradas authz).
- `lib/fingerprint.py`: fingerprint estável (desbloqueia state/SARIF/diff já existentes).
- ZAP replacer rule + `core/view/messages` (já usados na P9).

## Fora de escopo (v2+)

- Replay de métodos mutantes (POST/PUT/DELETE) — exigirá flag opt-in + gating de perfil.
- Mais de dois tokens / matriz de papéis (RBAC completo).
- Mass-assignment e outras classes OWASP API além de BOLA/BFLA.

## Pendência operacional (inalterada)

Política mantida: trabalho **local** até autorização explícita; nenhum artefato de alvo versionado. Continua pendente o shred seguro de `scan_pos.bee2pay.com_20260606_144522/` + `scan_pos_full.log` (dados CDE) quando autorizado.

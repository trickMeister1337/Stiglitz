# Subdomain Takeover via nuclei (osint.sh) — Design

**Data:** 2026-06-07
**Item de roadmap:** P1 — subdomain takeover via nuclei templates (substitui o string-match frágil do `osint.sh`).
**Status:** design aprovado; implementação pendente (TDD).

---

## Problema

Hoje o `osint.sh` (fase 8 "active-cloud", opt-in) detecta subdomain takeover assim
(linhas ~903–947):

1. Lista **hardcoded** de ~17 serviços (`s3.amazonaws.com`, `github.io`, `herokuapp.com`, …).
2. `dig CNAME` + `grep -qi "$svc"` — **string-match frágil**.
3. Veredicto de takeover **só pelo HTTP status code** (`404|410|422` → `POSSIBLE`).

Problemas:
- A lista desatualiza (mesmo motivo que motiva a troca).
- Status-code sozinho gera **muitos falsos positivos** — um 404 genérico do GitHub Pages
  não confirma takeover; é preciso o **fingerprint do body** (ex.: "There isn't a GitHub
  Pages site here") mantido pelo projeto `can-i-take-over-xyz`.

O motor confiável **já existe no projeto**: o `stiglitz.sh` roda `nuclei -tags takeover`
(templates `http/takeovers/*`, fingerprints de body da comunidade). Falta usá-lo no `osint.sh`.

---

## Objetivo

Substituir a heurística frágil por uma detecção **híbrida**: o CNAME filtra os candidatos,
o `nuclei` confirma por fingerprint de body. Zero falso positivo no CSV final (só sai o que
o nuclei confirmar). Toda dependência ausente ou falha de execução é **sempre informada no
terminal** (PT-BR, operador), sem abortar a fase.

---

## Arquitetura

Lógica pura e testável em `lib/takeover.py` (padrão do projeto: `lib/*.py` testável, bash
orquestra as ferramentas). O `osint.sh` orquestra `dnsx` + `nuclei` e chama o módulo.

### Fluxo (fase 8, opt-in via `--active-cloud` / `ACTIVE_CLOUD`)

1. **Coleta de CNAME** — `dnsx -l subdomains_live.txt -cname -json -silent` → `cloud/cnames.json`
   (objetos `{"host": "...", "cname": ["..."]}`). `dnsx` já é dependência-core do osint.
2. **Filtro externo** — `lib/takeover.py:select_external(cnames, BASE_DOMAIN)` retorna só os
   `(host, cname)` cujo CNAME **não** termina em `BASE_DOMAIN` (aponta para terceiro). Grava
   `cloud/takeover_targets.txt`. Sem candidatos externos → encerra o sub-passo com `info`.
3. **Confirmação nuclei** — `nuclei -l cloud/takeover_targets.txt -tags takeover -jsonl -silent`
   → `cloud/takeover_nuclei.jsonl` (raw). Se nuclei ausente/falha → `warn` e encerra sem emitir
   confirmados (o bucket-probing da fase segue normal).
4. **Parse** — `lib/takeover.py:parse_nuclei(jsonl)` extrai `{host, service, severity, matched_at}`;
   `build_candidates_csv(confirmed, cname_map)` monta `cloud/takeover_candidates.csv`.

### Determinação de "CNAME externo"

Critério robusto **sem PSL/tldextract**: usa o apex do alvo, que o osint já conhece em
`BASE_DOMAIN` (linha 202). Um CNAME é **interno** se for o próprio apex ou terminar em
`"." + BASE_DOMAIN`; caso contrário é **externo** (candidato a takeover). CNAME vazio → não externo.

```
is_external_cname("x.target.com.s3.amazonaws.com", "target.com")  -> True   (externo)
is_external_cname("cdn.target.com",                "target.com")  -> False  (interno)
is_external_cname("target.com",                    "target.com")  -> False  (apex)
is_external_cname("",                              "target.com")  -> False
```

---

## Módulo `lib/takeover.py` (interface)

Lógica pura (sem rede, sem domínio hardcoded); a data/IO ficam no bash.

| Função | Assinatura | Responsabilidade |
|--------|-----------|------------------|
| `is_external_cname` | `(cname: str, base_domain: str) -> bool` | CNAME aponta para terceiro? |
| `select_external` | `(cnames: list[dict], base_domain: str) -> list[tuple[str,str]]` | Filtra `(host, cname)` externos a partir do JSON do dnsx |
| `parse_nuclei` | `(jsonl_text: str) -> list[dict]` | Extrai `{host, service, severity, matched_at}` das linhas JSONL de takeover |
| `build_candidates_csv` | `(confirmed: list[dict], cname_map: dict) -> str` | Monta o CSV (header + linhas), juntando o CNAME do mapa |

`select_external` lida com a forma do dnsx `-json` (`cname` é lista; pega o primeiro não-vazio).
`parse_nuclei` ignora linhas não-JSON/sem `host`; `service` deriva de `template-id`/`info.name`.

---

## Output e compatibilidade

- `cloud/takeover_candidates.csv` mantém **exatamente** o schema atual
  `subdomain,cname,service,status` com `status = CONFIRMED`. O relatório (`section2`,
  "Subdomain Takeover Candidates", e `count_lines`) **não muda**.
- `cloud/takeover_nuclei.jsonl` (raw) guarda o detalhe rico (template, `matched_at`, severity)
  para auditoria/integração futura, sem afetar o CSV.
- `cloud/takeover_targets.txt` lista os candidatos externos enviados ao nuclei (rastreabilidade:
  o operador vê os externos não-confirmados ali).

Se há externos mas o nuclei não confirma nenhum, o CSV fica só com header (0 confirmados) → o
relatório mostra 0, sem FP.

---

## Avisos de dependência e tratamento de erro (sempre no terminal)

Escopo escolhido: **takeover + preflight completo** (não há sweep de error-handling nas demais fases).

### A. Preflight completo (`validate_tools`, roda no início do scan)

- Adicionar `nuclei` e `shodan` (CLI) à lista `optional` — hoje ausentes da validação.
- Mensagens específicas para o que afeta a feature:
  - sem `nuclei` → `warn` "nuclei não encontrado — confirmação de subdomain takeover será pulada";
  - sem `dnsx` → `warn` "dnsx não encontrado — coleta de CNAME/takeover indisponível".
- As demais ferramentas mantêm o aviso genérico já existente.

### B. Tratamento de erro no sub-passo de takeover

Cada ponto de falha emite `warn`/`info` no terminal e **segue sem abortar a fase**. Nenhum
`2>/dev/null || true` silencioso no código novo:

| Condição | Mensagem (PT-BR) | Efeito |
|----------|------------------|--------|
| `dnsx` ausente | `warn` "takeover: dnsx indisponível — pulando" | encerra sub-passo |
| `dnsx` exit≠0 ou `cnames.json` vazio | `warn` "takeover: coleta de CNAME falhou / sem CNAMEs" | encerra sub-passo |
| Nenhum CNAME externo | `info` "takeover: nenhum candidato externo" | encerra sub-passo |
| `nuclei` ausente | `warn` "takeover: nuclei indisponível — confirmação pulada" | encerra sem confirmados |
| `nuclei` exit≠0 | `warn` "takeover: nuclei retornou erro (código N)" | encerra sem confirmados |
| Parse Python falha | `warn` com a mensagem do erro | CSV não é corrompido |
| Confirmados > 0 | `warn` "Subdomain takeover CONFIRMADO → N" | CSV escrito |

### C. Serviços com API key — pular mas informar em tela

As 4 fases com API key (Shodan, HIBP, GitHub, Hunter) já pulam corretamente em runtime; o
preflight deve avisar **todas** de forma consistente:

- Corrigir a linha 238: Hunter.io sem chave passa a emitir `warn` "Hunter.io key → não
  configurada (fase ignorada)" — elimina o `|| true` silencioso.
- Padrão uniforme: `info` quando configurada; `warn "→ não configurada (fase X ignorada)"` quando ausente.
- **Shodan** depende de binário *e* chave: o aviso distingue "binário shodan ausente" de
  "SHODAN_KEY não configurada"; ambos levam a pular a fase, cada um com sua mensagem.

---

## Testes

### Unit — `tests/test_takeover.py` (TDD, lógica pura)

- `is_external_cname`: externo (`*.github.io`, `*.s3.amazonaws.com`), interno (`*.target.com`),
  apex exato, CNAME vazio.
- `select_external`: filtra corretamente a partir de um `cnames.json` sintético (mistura de
  internos/externos, lista de cname vazia, múltiplos cname).
- `parse_nuclei`: extrai `host`/`service`/`severity`/`matched_at` de linhas JSONL de takeover;
  ignora linhas inválidas/sem host.
- `build_candidates_csv`: header correto, `status=CONFIRMED`, junção do cname pelo mapa, ordem estável.

### Bash / integração

- `bash -n osint.sh` + `shellcheck --severity=warning osint.sh` limpos.
- `validate_tools` lista `nuclei` e `shodan` (grep no script).
- Smoke com PATH restrito (`nuclei`/`dnsx` "ausentes") confirma o `warn` de degradação no
  sub-passo (dry-run), sem erro.

---

## Política de dados sensíveis

- `lib/takeover.py` é lógica pura, **sem domínio/URL hardcoded**.
- Todos os artefatos (`cloud/cnames.json`, `cloud/takeover_targets.txt`,
  `cloud/takeover_nuclei.jsonl`, `cloud/takeover_candidates.csv`) ficam no `OUTDIR` do osint
  (`osint_<domain>_<timestamp>/`, gitignored) — **nunca versionados**.
- Nenhum dado de alvo entra em testes (fixtures usam `target.com`/`ex.com` sintéticos).
- Mantém a diretriz [[escopo-cde-nunca-no-github]] e a política de não subir nada sensível:
  o trabalho permanece local até autorização explícita de push.

---

## Fora de escopo (YAGNI)

- Sweep de error-handling nas demais fases do osint (decidido: só preflight + takeover).
- Reescrita do bucket-probing (S3/Azure) da mesma fase — permanece como está.
- Emissão dos takeovers confirmados como findings no `stiglitz.sh` (o scan já roda `-tags takeover`
  por conta própria; integração cruzada fica para outro item).
- Atualização/empacotamento de templates nuclei (o `stiglitz.sh` já cuida do `-update-templates`).

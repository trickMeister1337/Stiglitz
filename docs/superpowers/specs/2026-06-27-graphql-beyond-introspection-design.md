# Design — GraphQL além de introspection (DoS + field-level authz)

**Data:** 2026-06-27
**Status:** aprovado (brainstorming) — pronto para plano de implementação
**Roadmap:** item "APIs aprimoradas" / `docs/ROADMAP.md:133` ("GraphQL além de introspection: batching/aliasing DoS + field-level authz (reusar `bola.py`). `graphql_audit.py` ainda só faz introspection").

## Problema

O `lib/graphql_audit.py` hoje só faz introspection (enumera tipos/mutations + heurística de mutations sensíveis por nome). Falta cobrir duas classes reais de risco de API GraphQL em fintech:

1. **Resource exhaustion (batching/aliasing)** — servidores GraphQL sem limite de complexidade/profundidade/batch permitem amplificação de carga (CWE-770).
2. **Broken field-level authorization** — campos/mutations sensíveis sem checagem de autorização por objeto/função (OWASP API1/API5) — o risco #1 de API, hoje não confirmado ativamente em GraphQL.

A auto-descoberta OpenAPI já está entregue (`openapi_discover.py` + `openapi_seed.py`); este spec cobre **apenas** o GraphQL. O upgrade de seeding OpenAPI (`ROADMAP.md:150`) é um sub-projeto separado, posterior.

## Decisões fechadas (brainstorming)

1. **Escopo:** ambas as metades (DoS + field-level authz).
2. **Fonte das operações de authz:** histórico do ZAP (operações reais do app capturadas pelo spider autenticado) — reusa `bola.parse_zap_messages`. Sem síntese a partir do schema (frágil/perigoso).
3. **Segurança do replay de authz:** só **queries** (read) por padrão; mutations puladas a menos que opt-in `--graphql-mutate` + gating de profile (espelha P9.7 bizlogic mutate).
4. **Gating do DoS:** probe limitado em staging/lab; **dry-run** (descreve, não envia) em `production` (espelha `oauth_audit --oauth-active`).
5. **Módulos:** três focados — `graphql_audit.py` (introspection, +helper `is_mutation`), `graphql_dos.py`, `graphql_authz.py`.

## Arquitetura

### `lib/graphql_audit.py` (existente, +1 helper)

Permanece o módulo de introspection/recon. Adiciona um helper de domínio reusado pelo authz:

- `is_mutation(operation_body) -> bool` — True se a operação GraphQL é uma mutation. Heurística pura: detecta o keyword de operação top-level (`mutation` antes do primeiro `{`, com ou sem nome/variáveis), ignorando queries anônimas (`{ ... }` = query) e `query`/`subscription` explícitos. Não faz parse completo de AST.

### `lib/graphql_dos.py` (novo) — batching/aliasing

Lógica pura + `send_fn` injetável (testável sem rede). Não requer introspection (usa `__typename`, meta-campo universal).

- `build_alias_probe(n) -> dict` — `{"query": "{ a0:__typename a1:__typename … a{n-1}:__typename }"}`. Aliases de `__typename` (sem args, leitura trivial server-side).
- `build_batch_probe(m) -> list` — `[{"query": "{__typename}"}] * m` (array JSON = batch).
- `classify_alias_response(status, body, n) -> dict|None` — finding quando `status==200` E o `data` resolveu os `n` aliases (sem `errors` de complexidade). Classe `graphql_no_complexity_limit`, CWE-770, severity **medium**.
- `classify_batch_response(status, body, m) -> dict|None` — finding quando a resposta é um **array** JSON de comprimento ≥ 2 (servidor processou o batch). Classe `graphql_batching_enabled`, CWE-770, severity **low**.
- `run(url, profile, send_fn, n=None, m=None) -> list` — orquestra. **Primeiro detecta o endpoint** enviando `{__typename}` (leitura trivial, não-destrutiva): se a resposta não é GraphQL-shaped (`data.__typename` ou envelope `errors` de GraphQL), retorna `[]` (no-op). A detecção **não depende de introspection** — funciona mesmo com introspection desabilitada (comum em prod). Detectado o endpoint: em `profile == "production"` → **dry-run** dos probes de amplificação (não chama `send_fn` para alias/batch; emite finding info `graphql_dos_dryrun` descrevendo o que seria enviado); em staging/lab → envia cada probe (request único) e classifica. A detecção `{__typename}` roda em todos os profiles (é como se sabe que há endpoint). Fail-soft: exceção de rede → no-op (sem finding falso). `n`/`m` default de env (ver Config).
- CLI `main(argv)` para o runner bash.

### `lib/graphql_authz.py` (novo) — field-level authz (BOLA/BFLA GraphQL)

Reusa a lógica de veredito do `bola.py`; replay GraphQL-aware (POST + body + header de token). `replay_fn` injetável.

- `select_graphql_messages(messages, endpoint_substr="graphql") -> list` — dos `messages` do dump ZAP (`bola.parse_zap_messages`), seleciona POSTs cujo path contém `endpoint_substr` E cujo body é uma operação GraphQL (contém `"query"`/`"mutation"`/`operationName`).
- `run(messages, token_a, token_b, outdir, replay_fn=_replay, mutate=False, profile="staging") -> list` — para cada operação selecionada:
  - pula mutations a menos que `mutate=True` **e** `profile != "production"` (gating duplo, consistente com P9.7);
  - replaya com token-a (baseline), token-b (cross), unauth via `replay_fn(req, token) -> (status, body, headers)`;
  - extrai canário com `bola.extract_canary(body, content_type)`;
  - aplica `bola.verdict(baseline, cross, unauth, canary)`;
  - acumula resultados e gera findings via `bola.build_findings(results)`, com `vuln_class` `graphql_bola` (token-b lê dado de token-a) / `graphql_bfla` (unauth/priv-menor executa op privilegiada).
  - **Dedup** vs P9.5/P9.7 pelo mesmo critério das fases authz existentes — `(host, path, vuln_class)`.
  - Grava `raw/graphql_authz.json`.
- `_replay(req, token)` — POST default via `netproxy` (herda proxy+mTLS); injeta `Authorization: Bearer <token>` (ou remove p/ unauth); reusa o padrão de `bola.replay`.
- CLI `main(argv)` — lê o dump ZAP + 2 tokens do env (como `bola.py`).

### Configuração (env + flags)

| Item | Onde | Default |
|------|------|---------|
| `--graphql-mutate` | flag CLI do stiglitz.sh | off (mutations puladas no authz) |
| `STIGLITZ_GQL_ALIAS_N` | env | `100` (nº de aliases no probe) |
| `STIGLITZ_GQL_BATCH_M` | env | `15` (nº de ops no batch) |
| `STIGLITZ_PROFILE` | env (já existe) | gating de DoS dry-run + mutate |

Tokens de authz: `--token-a`/`--token-b` (já existem, alimentam `TOKEN_A`/`TOKEN_B`).

### Integração no `stiglitz.sh`

- **DoS** — estende o bloco GraphQL da Fase 9 (~linha 1791-1800). Hoje o bloco itera endpoints candidatos e só age quando a introspection responde (`grep -q '"__schema"'`); como o DoS **não depende de introspection**, o bloco passa a chamar `python3 lib/graphql_dos.py <outdir> <gql_url>` para o(s) endpoint(s) candidato(s) — o próprio `graphql_dos.run` faz a detecção via `{__typename}` e é no-op em URL não-GraphQL. Assim o DoS é avaliado mesmo quando a introspection está desabilitada (comum em prod), enquanto os findings de introspection continuam saindo quando `__schema` está presente. Roda deslogado (não precisa token). `STIGLITZ_PROFILE` no env controla o dry-run. Findings → `raw/graphql_dos.json`.
- **Field-level authz** — nova sub-fase **P9.8 "GraphQL Authz"**, análoga a P9.5: gated em `[ -n "$TOKEN_A" ] && [ -n "$TOKEN_B" ]`; roda após o dump de mensagens do ZAP existir (mesmo input do P9.5); passa `--graphql-mutate`→`mutate` e `STIGLITZ_PROFILE`. No-op silencioso sem os 2 tokens. Findings → `raw/graphql_authz.json`.
- Ambos os JSONs são ingeridos pelo `stiglitz_report.py`/pipeline de evidências como os demais `raw/*_findings.json` (o report já agrega `raw/graphql_findings.json`; adicionar os dois novos à mesma coleta).

## Tratamento de erro / não-destrutivo

- **Fail-soft em tudo:** endpoint GraphQL ausente, erro de rede, JSON inválido → no-op silencioso, nunca aborta a fase (padrão da introspection atual).
- **DoS não-destrutivo por construção:** probes são leituras (`__typename`), request único cada, N/M limitados; `production` → dry-run (zero tráfego ativo).
- **Authz não-destrutivo por padrão:** só queries (read); mutations exigem opt-in duplo (`--graphql-mutate` + profile ≠ production).
- **Sanitização:** findings em **inglês** (deliverable); nenhum token/PAN/PII cru no output — reusa a sanitização de `bola`/`repro`. Tokens via env, nunca em CLI/log.

## Testes (TDD)

`tests/` (novos arquivos por módulo), lógica pura + injeção:

- **`graphql_audit.is_mutation`** (regressão no arquivo de teste existente ou novo): `mutation {...}` / `mutation Name(...) {...}` → True; `{...}` (anônima) / `query {...}` / `subscription {...}` → False.
- **`graphql_dos.py`**: `build_alias_probe(n)` gera n aliases de `__typename`; `build_batch_probe(m)` gera array de m; `classify_alias_response` (200 + n aliases em data → finding; resposta com `errors` de complexidade → None); `classify_batch_response` (array len≥2 → finding; objeto único → None); `run` no-op quando a resposta de `{__typename}` não é GraphQL-shaped (URL não-GraphQL → `[]`); `run` em `production` faz a detecção mas NÃO chama `send_fn` para os probes de amplificação e emite finding de dry-run; `run` em staging chama `send_fn` e classifica. `send_fn` injetável (sem rede).
- **`graphql_authz.py`**: `select_graphql_messages` filtra POSTs GraphQL do dump; mutation pulada com `mutate=False`; mutation considerada com `mutate=True` e profile≠production; `run` replaya a/b/unauth via `replay_fn` injetável e produz veredito reusando `bola` (cross 2xx com canário de A → `graphql_bola`); dedup por `(host, path, vuln_class)`. Sem rede.
- **Bash:** `bash -n stiglitz.sh` + `shellcheck --severity=warning`. Guard source-level: a P9.8 é gated em `TOKEN_A`+`TOKEN_B`; o bloco DoS passa `STIGLITZ_PROFILE`.
- Output dos testes pristino.

## Não-objetivos (v1)

- Síntese de operações a partir do schema (queries ou mutations).
- Profundidade recursiva/circular como vetor de DoS (só aliasing + batching).
- Confirmação ativa de DoS por carga real (só detecção de ausência de limite com probe único limitado).
- Replay de mutations sem opt-in.
- Cost-analysis/complexity-scoring de queries arbitrárias.
- Upgrade de seeding OpenAPI (`ROADMAP.md:150`) — sub-projeto separado.

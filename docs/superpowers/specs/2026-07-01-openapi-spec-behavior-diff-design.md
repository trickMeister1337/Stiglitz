# OpenAPI Spec-vs-Behavior Diff — Design

> **Higienizado:** nenhum dado de CDE/cliente/alvo aqui. Snapshot de design —
> verificar contra o git antes de afirmar estado de implementação.
> **Data:** 2026-07-01. **Origem:** item #2 do [`ROADMAP-analyst-parity.md`](../../ROADMAP-analyst-parity.md)
> (técnica de analista "diff spec-vs-comportamento"), realizando também o P0.1 estendido do
> [`ROADMAP-blackbox-cde.md`](../../ROADMAP-blackbox-cde.md).

## Problema

O caso de uso dominante do Stiglitz é scan **black-box de CDE (API de pagamento), zero-credencial**.
O sintoma real recorrente: **~13 findings / 0 High** — o arsenal de authz (BOLA P9.5, bizlogic P9.7)
degrada a zero sem token, e o achado mais valioso disponível (Swagger público documentando
endpoints de pagamento) só era *semeado* no ZAP, não *explorado*.

O item #1 (`confirm_oracle`) e o P0.1 (`openapi_probe.broken_auth`) já usam o spec como motor de
detecção de **broken-auth**. Falta a segunda metade da técnica de analista: **comparar o que o
spec DECLARA com o que a API OBSERVAVELMENTE faz** — três divergências de alto valor:

1. **Excessive Data Exposure** — a resposta traz campos **fora** do schema declarado (ex.: PAN
   completo quando o schema documenta só os 4 últimos dígitos).
2. **Shadow Endpoint** — um path **observado** (crawl/histórico) que **não** existe no spec
   (superfície não-documentada, fora do inventário de segurança).
3. **Mass Assignment** — um campo **não-declarado** é **aceito** num body de escrita.

## Objetivo

Entregar as **duas primeiras** divergências (Excessive Data Exposure + Shadow Endpoint) num módulo
novo `lib/openapi_diff.py`, wired na mesma fase do `openapi_probe` e ingerido no relatório.
**Mass Assignment fica de fora deste corte** (ver Decisões).

## Decisões de design

| Decisão | Escolha | Justificativa |
|---|---|---|
| Escopo (1º corte) | **Excessive Data Exposure + Shadow Endpoint** | Ambos **não-destrutivos** e **puros**; alavancam direto o caso "0 High" zero-cred. Mass Assignment é de outra classe de risco |
| Mass Assignment | **Deferido** (follow-up) | Exige requisição **mutante** (POST/PUT com campo extra) → destrutivo, precisa de token p/ alcançar writes, e **sobrepõe** a `bizlogic` (P9.7 `idor_write`/amount-tampering, já com gating profile/RoE). Casa natural é a bizlogic, não aqui |
| Módulo | **Novo `lib/openapi_diff.py`** | `openapi_probe.py` (198 linhas) é focado em broken-auth; embutir as detecções o levaria a ~400 linhas/3 responsabilidades. Módulo focado, reusa helpers de `openapi_probe` |
| Fonte do "observado" | Excessive-data: **respostas GET que o probe já busca**; Shadow: **`raw/katana_urls.txt`** (+ paths do histórico ZAP quando disponível) | Zero requisição nova p/ excessive-data; shadow é set-diff puro sobre dados já coletados |
| Severidade | **Contextual** via detectores existentes | Não compõe criticidade fora do modelo do projeto — só define `severity` do finding, elevada por PAN/PII |

## Componente 1 — `lib/openapi_diff.py`

Lógica pura + fetch injetável + CLI (padrão `openapi_probe.py`/`apm_probe.py`). Findings em EN
(deliverable); console/comentários PT-BR. **Reusa** de `openapi_probe`: `_as_dict`,
`documented_operations`, `op_url`. **Reusa** de `pii_detect`/`pan_scanner`/`bola`: classificação de
dado sensível.

### Resolver de schema (novo)
- `resolve_response_schema(spec, path, method) -> set[str]` — conjunto dos **nomes de campo
  declarados** na resposta 2xx da operação. Resolve `$ref` contra `components/schemas` (OpenAPI 3)
  **e** `definitions` (Swagger 2); lê `properties` inline; **guarda anti-ciclo** (set de refs
  visitados). **Só o 1º nível** de `properties` (YAGNI — aninhamento profundo fora do 1º corte).
  Spec sem schema resolvível → `set()` vazio (sinaliza "não comparável", não erro).

### Detecção — Excessive Data Exposure
- `excessive_fields(observed_body, declared_fields, content_type="") -> set[str]` — chaves de topo
  do JSON de resposta **ausentes** do `declared_fields`. Se `declared_fields` vazio (schema não
  resolvível) → `set()` (não inventa exposição sem baseline).
- `classify_excessive(extra_fields, observed_body) -> severity` — base **medium**; **high** se um
  campo extra carrega PII (CPF/CNPJ/email via `pii_detect`/`extract_canary`); **critical** se
  carrega PAN (Luhn via `pan_scanner.scan_text`). CWE-213.
- Emite `openapi_excessive_data` finding por operação com campos extras (lista os campos; sanitiza
  valores sensíveis na evidência).

### Detecção — Shadow Endpoint
- `documented_path_matchers(spec) -> list[regex]` — cada `spec.paths` vira um regex (`{param}` →
  `[^/]+`), respeitando o prefixo (`_prefix`/`op_url`).
- `shadow_paths(observed_urls, matchers, scope_host) -> list[str]` — paths observados (query-string
  removida; fora de escopo/host descartado) que **não** casam nenhum matcher. Dedup por path.
- Emite `openapi_shadow_endpoint` finding por path não-documentado. Severidade base **low**
  (superfície não-documentada = info-disclosure). **Elevação opcional a medium**: se o `fetch_fn`
  estiver disponível, sonda GET o shadow e reusa `unauth_verdict` do `openapi_probe` — 2xx com dados
  → medium. A elevação usa o **mesmo `fetch_fn` injetável** (testável/pulável); a detecção-base
  (set-diff) **não** depende de rede. CWE-1059 (superfície fora do inventário).

### Findings
Schema igual ao `openapi_probe.build_finding` (`type`/`name`/`severity`/`cwe`/`url`/`source`/`tool`/
`description`/`evidence` + `fingerprint`). `source="openapi_diff"`. Texto EN.

## Componente 2 — Orquestração e wiring

- `probe(spec, base_url, observed_urls, fetch_fn, ...) -> list[finding]` — roda as duas detecções.
- `run(spec_path, base_url, outdir, observed_urls_path=None, fetch_fn=_default_fetch) -> int` — lê
  spec + `katana_urls.txt`, sonda, grava `<outdir>/raw/openapi_diff.json`, retorna a contagem.
- **`stiglitz.sh`** (logo após o bloco P0.1 do broken-auth, `~:1293`): invoca
  `python3 lib/openapi_diff.py <openapi_spec.json> <TARGET> <OUTDIR> <katana_urls.txt>` sob o mesmo
  gate `[ -s raw/openapi_spec.json ]`, com `timeout` e `|| echo 0` (padrão do broken-auth).
- **`stiglitz_report.py`** (junto do ingest de `openapi_authz.json`, `~:1014`): adiciona
  `('openapi_diff.json', 'openapi_diff')` à lista de ingest — findings `estimated` (piso preserva
  severidade; padrão APM/service_exposure).

## Fluxo de dados
```
raw/openapi_spec.json ─┐
                       ├─► openapi_diff.probe ─► raw/openapi_diff.json ─► ingest report
raw/katana_urls.txt ───┘        │
   (paths observados)           ├─ excessive: GET responses (fetch) vs schema resolvido
                                └─ shadow: set-diff (observed − documented)
```

## Tratamento de erro
- Spec malformado / sem `components`/`definitions` → resolver devolve `set()` → excessive não emite
  (sem baseline, não inventa). Shadow ainda roda (só precisa de `paths`).
- `katana_urls.txt` ausente → shadow no-op; excessive ainda roda.
- Fetch falha numa operação → pula (padrão `openapi_probe.probe`).
- Escrita de JSON falha → aviso stderr, não aborta. `|| echo 0` no wiring.

## Testes (TDD)
- **`resolve_response_schema`**: `$ref` OAS3 (`components/schemas`), `$ref` Swagger2 (`definitions`),
  `properties` inline, `$ref` cíclico (não trava, termina), spec sem schema (→ vazio).
- **`excessive_fields`**: campos extras detectados; sem extras → vazio; `declared_fields` vazio →
  vazio (não inventa).
- **`classify_excessive`**: base medium; PII → high; PAN → critical.
- **`shadow_paths`**: path observado fora do spec vira shadow; path com `{param}` casa e **não** vira
  shadow; query-string ignorada; host fora de escopo descartado.
- **`probe`/`run`**: integra as duas detecções, grava `openapi_diff.json`, no-op sem spec.
- **Caracterização**: `openapi_diff.json` chega ao `findings.json` com `fingerprint` (subprocess do
  report, formato `findings` dict confirmado no trabalho anterior).

## Validação
- `python3 -m pytest tests/` verde (baseline atual 1007 passed / 3 skipped + novos).
- `python3 -m py_compile lib/openapi_diff.py stiglitz_report.py`.
- `bash -n stiglitz.sh` + shellcheck (gate do CI).
- CLI manual: `python3 lib/openapi_diff.py <spec.json> <url> <outdir> <katana.txt>` (no-op gracioso
  sem alvo real).

## Fora de escopo (YAGNI / follow-ups)
- **Mass Assignment** (mutante, gated) → `bizlogic`.
- Schemas aninhados profundos (só 1º nível de `properties` no 1º corte).
- Inferência de tipo/formato por valor (só presença/ausência de campo agora).
- Composição `oneOf`/`anyOf`/`allOf` (1º corte: `$ref` direto + `properties` inline).

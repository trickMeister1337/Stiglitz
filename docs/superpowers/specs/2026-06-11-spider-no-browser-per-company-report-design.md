# Spider — Descontinuar navegador + relatório por empresa + Axur SOLVED (design)

**Data:** 2026-06-11
**Contexto:** red team autorizado, sob RoE. Projeto Spider (CLI), repo `github/spider`.
Continuação da validação de credenciais expostas (Axur ingest + validação diferencial + PDF).

## Problema / objetivo

Hoje o Spider tenta furar Cloudflare/WAF/login-JS com **navegador** (`browser.py`,
`browser_nodriver.py`) e **modo assistido manual** (`--assist`/`--headful`). Isso é frágil,
exige humano e display gráfico. Decisão do operador:

1. **Descontinuar navegador e ação manual.** A validação passa a ser 100% server-side (HTTP).
2. **Reservar `bloqueado`** para URLs que **não dão para verificar automaticamente** (Cloudflare/
   WAF/Turnstile/IP-block **ou** login dinâmico/SPA). Essas são "pendentes de validação manual".
3. **Novo deliverable:** **um PDF por empresa** com as credenciais que precisam de ação
   (vulneráveis + bloqueadas + pendentes), com login/e-mail, **senha completa** e URL — para
   direcionar direto ao time de cada empresa fazer o reset.
4. **Axur:** as bloqueadas continuam **taggeadas `bloqueado`**, porém **após a extração** para o
   PDF passam a `SOLVED` (resolvido). As demais regras de status ficam como estão.

## Decisões (aprovadas)

### Status / classificação
- Validação 100% HTTP (server-side). Sem navegador, sem modo assistido.
- `bloqueado` = **não verificável automaticamente**:
  - WAF/Cloudflare/Turnstile/IP-1020 (já detectado por `pagetype.is_blocked`/`classify_block`);
  - **login dinâmico/SPA** (OAuth/IdentityServer/React/Angular/Vue) — antes exigia navegador;
    agora classifica como `bloqueado` (não há POST HTTP confiável).
- Evidências deixam de citar `--assist`/`--browser`; passam a "validação manual"
  (ex.: `"Cloudflare/WAF — validação manual"`, `"login dinâmico/JS — validação manual"`,
  `"desafio interativo (Turnstile) — validação manual"`, `"bloqueio por reputação de IP (1020) — validação manual"`).
- Taxonomia final:

  | Status | Significado | No relatório |
  |---|---|---|
  | `vulneravel` / `vulneravel_mfa` | credencial confirmada (auto) | **Sim** |
  | `bloqueado` | não verificável (Cloudflare/WAF/dinâmico) | **Sim** |
  | `verificar` | alcançável mas resultado ambíguo (pendente) | **Sim** |
  | `seguro` | senha não funciona (confirmado) | Não |
  | `sem_login` | URL sem formulário (combolist antiga) | Não |
  | `offline` | host inalcançável | Não |

### Relatório PDF — um por empresa
- **Empresa derivada da URL/domínio** (`_company_from_host`, já existente). O domínio sempre
  contém o nome da empresa; **não** depende de `companies.conf` (que segue como override opcional,
  gitignored). Nenhum nome de cliente fica hardcoded no repo.
- **Um arquivo por empresa**: cada label distinto → um PDF próprio.
  Nome: `Relatorio_<Empresa>_<timestamp>.pdf` (`<Empresa>` slugificado: sem espaços/acentos).
- Cada PDF traz, em **seções**: **Vulneráveis**, **Bloqueadas**, **Pendentes** daquela empresa.
- **Colunas:** Login/E-mail · Senha (completa, sem máscara) · URL · Status · Data.
- Idioma: **PT-BR** (deliverable interno para os times de reset — diferente do Stiglitz, que é EN).
- Empresas sem nenhuma credencial acionável (só seguro/sem_login/offline) **não** geram PDF.
- Resumo no stderr: nº de PDFs gerados e contagem por empresa/status.

### Workflow na Axur (`--push`)
Mapa veredito → status (ENUM `NEW`/`IN_TREATMENT`/`SOLVED`/`DISCARDED`):
- `vulneravel` / `vulneravel_mfa` → **`IN_TREATMENT`** + tag (inalterado).
- `bloqueado` → tag **`bloqueado`** + **`SOLVED`** — **somente após** os PDFs serem gerados com
  sucesso ("após a extração"). Se a geração do PDF falhar, **não** fecha (segurança).
- `seguro` / `sem_login` → **`SOLVED`** (inalterado).
- `verificar` → fica **`NEW`** (re-check; não fechar sem confirmar).
- `offline` → fica `NEW`; `DISCARDED` após 3 runs (`OFFLINE_DISCARD_AFTER`, inalterado).
- Duplicadas do ingest → `DISCARDED` (inalterado).
- Sem `--push` = **dry-run** (não escreve; só mostra o que faria, incluindo `SOLVED(bloqueado)=N`).

**Mudança consciente vs. design anterior** (`2026-06-01-spider-axur-status-workflow-design.md`):
antes `bloqueado` ficava `NEW` ("nunca fechar sem confirmar"). Agora, como as bloqueadas vão
direto ao time de reset via PDF, viram `SOLVED` **após a extração**. `verificar` **permanece
`NEW`** (não fecha) — só as bloqueadas mudam.

## Arquitetura

Refatoração + extensão dos módulos existentes. Núcleo da validação diferencial (canário)
preservado; sai toda a camada de navegador.

### Remoções
- Arquivos: `browser.py`, `browser_nodriver.py`, `test_browser_nodriver.py`.
- `spider_report.py`: `select_engine`; flags `--browser`, `--engine`, `--assist`, `--headful`;
  toda a fiação de import/instanciação de engine e `_imp`.
- `differential.py`: params `browser_attempt`, `browser_probe_fn`, `use_browser` de
  `validate_batch`; `_with_http_fallback`; campo `assisted` em `fingerprint`; ramos
  `assisted`/`browser` em `compare` e `validate_batch`.

### `differential.py` — roteamento simplificado
`validate_batch(creds, http_attempt=None, probe_fn=None, timeout, delay, progress, canary_count=2, rand, rewrite_fn)`:
- `static_form` → valida por HTTP (canário + real), como hoje.
- `dynamic` → emite `bloqueado` ("login dinâmico/JS — validação manual").
- `blocked` → emite `bloqueado` (subtipo via `classify_block`, evidência "validação manual").
- `offline` → `offline`; `dead` → `sem_login` (inalterado).
- `canary_count` default volta a `2` (não há mais `--assist` para forçar `1`).

`compare(real, base)`: remove o parâmetro/efeito de `assisted`. `blocked` → sempre `bloqueado`
(sem o "e não assisted"). Mantém a lógica de canário/ganho de cookie/MFA para `static_form`.

### `pagetype.py`
Inalterado em detecção. Só ajusto strings de evidência se houver referência a `--assist`
(hoje os textos de `--assist` moram em `differential._EV_BLOCK`).

### `spider_report.py` — geração e push
1. **Validação**: chama `differential.validate_batch` (sem browser).
2. **Agrupamento por empresa**: nova função `group_by_company(validated)` → `{empresa: [rows]}`,
   incluindo só status acionáveis (`vulneravel`, `vulneravel_mfa`, `bloqueado`, `verificar`).
   Inclui **todas** as acionáveis validadas na run atual (não filtra por `novas`/ledger). No modo
   Axur, a própria mudança de status (`IN_TREATMENT`/`SOLVED`) tira a detecção de `NEW` → ela não
   reaparece na próxima run; o ledger `reported` local segue como rede de segurança da fonte CSV.
   O apêndice "inconclusivos" do relatório único antigo é descontinuado (bloqueado/verificar agora
   têm seção própria por empresa).
3. **Render por empresa**: nova função `render_company_pdfs(grupos, meta, out_dir)`:
   para cada empresa com ≥1 credencial acionável, monta HTML (seções Vulneráveis/Bloqueadas/
   Pendentes) e renderiza `Relatorio_<slug>_<ts>.pdf`. Devolve lista de caminhos gerados.
   - `build_html` é generalizado para receber as 3 seções (ou reusado por seção).
   - Slug de empresa: minúsculas, sem acento, `[^a-z0-9]+`→`_`.
4. **Push (opt-in)**, **na ordem**:
   a. Render dos PDFs **primeiro**. Guarda `pdf_ok = bool(paths)` (ou "render sem exceção").
   b. `DISCARDED` (duplicadas + offline persistente).
   c. `IN_TREATMENT` + tag para vulneráveis (marca `reported` só se OK).
   d. `SOLVED` para `seguro`+`sem_login`.
   e. **`SOLVED` para `bloqueado` — somente se `pdf_ok`.** Se o render falhou, loga aviso e
      mantém as bloqueadas como estão (não fecha).
   f. Tags por status (loop existente) — garante a tag `bloqueado` nas bloqueadas.
5. **CLI**: `planilha`, `--source`, `--since`, `--limit`, `--push`, `--out-dir` (substitui
   `--out`; default `.`), `--timeout`, `--delay`, `--yes`, `--recheck`. Saem as flags de browser.

### `axur_client.py`
Sem mudança de API. `set_status`/`add_tag` já cobrem o necessário.

### `deploy/run_daily.sh` + `README.md`
- `run_daily.sh`: remove `--browser --engine playwright`; remove export WSLg/DISPLAY/Wayland
  (só servia ao headful). Chamada vira `spider_report.py --source axur --push --yes "$@"`.
- `README.md`: remove seções/flags de browser/nodriver/playwright/--assist; atualiza a tabela
  de status (bloqueado→SOLVED após extração), a descrição do roteamento (dynamic→bloqueado) e
  a seção "Cloudflare/WAF — bloqueadas" (agora validação manual via PDF por empresa).

## Fluxo (modo Axur + push)
`fetch → ingest(dedup + dup_ids) → validar(HTTP) → agrupar por empresa →
render PDFs por empresa → [push] DISCARDED(dups+offline≥3) · IN_TREATMENT+tag(vuln) ·
SOLVED(seguro/sem_login) · SOLVED(bloqueado, se PDF ok)+tag bloqueado · verificar/offline ficam NEW
→ resumo`.

## Tratamento de erro
- Cada `set_status`/`add_tag` independente: falha de um lote é logada, segue os demais.
- Falha no render dos PDFs → exit ≠ 0 **e** bloqueadas **não** viram `SOLVED` (não fechar sem extrair).
- Falha no `IN_TREATMENT`/tag das vulneráveis → não marca `reported` (ficam `NEW`, re-tenta).
- Fonte CSV (sem `axur_id`) → ações de status puladas (aviso); PDFs + ledger local normais.

## Segurança / privacidade
- `--push` muda o workflow real → opt-in; default dry-run.
- PDFs contêm **senha em texto claro** (intencional: reset pelos times) → gitignored
  (`*.pdf`/`Relatorio_*` já no `.gitignore`), confidencial sob RoE.
- Nomes de clientes/alvos derivados de runtime (domínio); nada hardcoded no repo.
- Token Axur só de env/`~/.spider.conf`, nunca logado.

## Testes
- **Remover** `test_browser_nodriver.py`.
- `test_differential.py`: remover ramos de browser/assisted; novo caso `dynamic → bloqueado`;
  `blocked → bloqueado` com evidência de "validação manual"; `static_form` continua validando.
- `test_spider_report.py`:
  - `group_by_company` agrupa por domínio e inclui só status acionáveis.
  - `render_company_pdfs` gera 1 arquivo por empresa (mock de `render_pdf`); empresas sem
    acionáveis não geram PDF; slug correto.
  - Push: `bloqueado → SOLVED` **só após** PDFs; render falho **não** fecha bloqueadas;
    `verificar` permanece `NEW`; vulnerável→IN_TREATMENT+tag; dry-run não escreve.
- `test_spider_validator.py`: inalterado em essência (classify HTTP); ajustar se algum teste
  tocava browser.

## Fora de escopo (YAGNI)
- Reabrir detecções (voltar a `NEW`); `verificar`→`SOLVED`; webhooks; PDF índice consolidado;
  qualquer reintrodução de navegador/headless.

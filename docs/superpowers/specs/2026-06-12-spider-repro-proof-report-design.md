# Design — Bloco "How to Reproduce / Proof" no relatório do scan

**Data:** 2026-06-12
**Escopo:** Item 6 do roadmap fintech — evidência/PoC acionável no `stiglitz_report.py`.
**Status:** Aprovado, pronto para plano de implementação.

## Contexto e motivação

O relatório do scan (`stiglitz_report.py`) já renderiza por finding: Evidence, HTTP
Request/Response, Recommendation e, para confirmados, os campos `curl_reproducible`/
`poc_note`/`response_body`. Falta um **bloco padronizado** que o time de validação
(blue team / QA de segurança) consiga seguir para **reproduzir e provar** cada finding:
passos numerados, comando copiável e resultado esperado.

Este design adiciona um bloco **"How to Reproduce / Proof"** por finding, em inglês
(deliverable), derivado de forma híbrida e com sanitização de segredos por padrão —
requisito não-negociável para alvos fintech sob PCI/CDE.

## Decisões travadas

1. **Fonte (híbrida):** usa o comando real capturado quando existe; cai para um
   template por classe de vulnerabilidade quando não há captura.
2. **Sanitização (redige por padrão):** Bearer → `<TOKEN_A>`, cookie/sessão →
   `<SESSION>`, tokens em querystring redigidos, PAN e PII (email/CPF/CNPJ) mascarados.
   Flag `--repro-raw` (env `STIGLITZ_REPRO_RAW=1`) mantém cru para uso interno.
3. **Alcance (união):** o bloco é renderizado para findings **confirmados**
   (`exploit`/`verified`) **OU** com severity ∈ {critical, high}. Demais findings não
   recebem o bloco.

## Arquitetura

Abordagem escolhida: **novo módulo puro `lib/repro.py`** consumido pelo
`stiglitz_report.py`. Segue o padrão `bola.py`/`dast_prep.py`/`zap_auth.py` (lógica pura
+ CLI), é testável isolado via pytest e não engorda o `stiglitz_report.py` (2407 linhas).
Reusa `pan_scanner.scan_text`/`pan_scanner.mask` e `pii_detect` para mascaramento.

Abordagens descartadas: (B) inline no relatório — acopla lógica ao HTML e incha arquivo
grande; (C) cada fase emite `repro` no finding JSON — mais fiel porém toca muitos módulos,
fica como evolução futura (ver "Fora de escopo").

### Componente 1 — `lib/repro.py` (puro + CLI)

Interface pública:

- `passes_gate(finding) -> bool`
  Retorna `True` quando `severity` normalizado ∈ {`critical`, `high`} **ou** o finding
  é confirmado. Para evitar duplicar a heurística do relatório, o sinal de "confirmado"
  vem de um campo explícito: `render_finding` já computa `_cat = _confirmed_category(f)`
  e passa a injetar `f["confirmed_category"] = _cat` **antes** de chamar `repro`;
  `passes_gate` lê `finding.get("confirmed_category") in {"exploit", "verified"}` (com
  fallback para o booleano `finding.get("confirmed")`). Único ponto de decisão de alcance.

- `build_repro(finding, raw=False) -> dict | None`
  Retorna `None` se `not passes_gate(finding)`. Caso contrário, retorna:
  ```
  {
    "prerequisites": str,      # ex.: "Valid session token (user A); target reachable"
    "steps": [str, ...],       # passos numerados, imperativos, em inglês
    "command": str,            # comando copiável (curl), já sanitizado salvo raw=True
    "expected": str,           # resultado que PROVA a vuln
    "sanitized": bool,         # True se algum valor foi redigido/mascarado
    "safe_note": str | "",     # aviso non-destructive p/ classes de dinheiro/mutação
  }
  ```

- `sanitize_command(text) -> (str, bool)` e `sanitize_text(text) -> (str, bool)`
  Redigem segredos e mascaram PAN/PII; retornam o texto tratado e um flag indicando se
  houve alteração. `raw=True` no `build_repro` ignora ambos.

Lógica interna:

- **Captura:** ordem de preferência — campos `curl_command` → `curl_reproducible` →
  `curl-command`; se ausentes, monta um `curl` a partir do bloco `--- HTTP REQUEST ---`
  já presente no campo `evidence` (parse de método, path, headers e corpo).
- **Template fallback:** `CLASS_TEMPLATES`, dicionário keyed por classe derivada de
  CWE / `vuln_type` / `source`. Cada entrada define `steps`, `command_template`
  (com placeholders `<TARGET>`, `<endpoint>`, `<id>`, `<token>`) e `expected`.
  Seed inicial (foco fintech): `bola_idor`, `bfla`, `sqli`, `xss`, `ssrf`, `ssti`,
  `auth_bypass`, `oauth_redirect_uri`, `graphql_introspection`,
  `missing_security_header` (one-liner `curl -sI | grep`), `tls_weak`. Classe não
  mapeada recai num template genérico ("replay the captured request and observe…").
- **`safe_note`:** preenchido quando a classe ou o endpoint indicam movimentação de
  dinheiro/mutação (regex `transfer|refund|withdraw|payment|delete|create|update` ou
  método HTTP non-GET). Texto: "Non-destructive validation: prefer staging, use an
  idempotency-key, or a read-only variant before replaying on production."

CLI: `python3 lib/repro.py <finding.json>` imprime o dict resultante (debug/teste),
seguindo o padrão de CLI dos módulos `lib/`.

### Componente 2 — `stiglitz_report.py`

- `import` do `repro` (com fallback gracioso se o módulo faltar, padrão do projeto).
- Lê `REPRO_RAW = os.environ.get("STIGLITZ_REPRO_RAW") == "1"`.
- Em `render_finding(f)`, **após a linha Recommendation**: se `repro.passes_gate(f)`,
  chama `repro.build_repro(f, raw=REPRO_RAW)` e renderiza um painel destacado
  **"How to Reproduce / Proof"** (estilo Big4, EN) contendo:
  - **Prerequisites** (quando não vazio)
  - **Steps** — lista numerada `<ol>`
  - **Command** — bloco copiável (`<pre>`, reusa estilo `evidence-box`)
  - **Expected Result (Proof)**
  - **Safe-test note** — só quando `safe_note` não vazio
  - badge **"values sanitized"** quando `sanitized` é `True`
- Sem regressão: findings que não passam no gate renderizam exatamente como hoje.

### Componente 3 — `stiglitz.sh`

- Nova flag `--repro-raw` no parser de args (junto de `--oauth-active`/`--bizlogic-mutate`).
- Quando presente, `export STIGLITZ_REPRO_RAW=1` antes da invocação do relatório na
  fase P11.
- Atualizar help/usage e o comentário do bloco de flags.

## Testes (`tests/test_repro.py`, pytest, TDD)

Escrever os testes antes da implementação. Casos:

1. **Sanitização:** `Authorization: Bearer eyJ…` → `<TOKEN_A>`; `Cookie:`/`Set-Cookie:`
   → `<SESSION>`; `access_token=`/`id_token=` em querystring redigidos; um PAN válido
   por Luhn é mascarado; CPF/CNPJ/email mascarados. `raw=True` preserva tudo e
   `sanitized=False`.
2. **Gate:** finding confirmado (`vuln_type=sqli`) passa; severity `high`/`critical`
   passa; `info`/`low` não passam → `build_repro` retorna `None`.
3. **Captura:** `build_repro` usa o `curl_command` quando presente; monta curl a partir
   do bloco `--- HTTP REQUEST ---` quando só há `evidence`.
4. **Template fallback:** finding de classe conhecida sem captura retorna o template
   correto; classe desconhecida retorna o template genérico.
5. **`safe_note`:** classe/endpoint de dinheiro (ex.: `/transfer`, método POST) produz
   `safe_note` não vazio; GET read-only não produz.

## Validação (gates do projeto)

```bash
python3 -m py_compile lib/repro.py stiglitz_report.py
python3 -m pytest tests/test_repro.py
bash -n stiglitz.sh
shellcheck --severity=warning stiglitz.sh
```

## Idioma

Bloco e textos do relatório em **inglês** (deliverable). Mensagens de console e
comentários de código em **PT-BR**. Mantém a separação já vigente no repo.

## Fora de escopo (evolução futura)

- Abordagem C (cada fase emite `repro` estruturado no finding JSON na origem) — mais
  fiel, mas ampla; reavaliar depois desta entrega.
- Estender o bloco para Medium/Low/info (alcance maior) — decisão de produto posterior.
- Repro interativo/executável (script gerado que roda a validação) — não nesta entrega.

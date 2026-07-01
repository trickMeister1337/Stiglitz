# Stiglitz — Paridade com analista black-box (sem LLM)

> Higienizado para versionamento: **nenhum dado de CDE/cliente/alvo** aqui.
> Estado snapshot — verificar contra o git antes de afirmar. **Criado: 2026-06-30 (HEAD `6e38790`).**

**Origem:** conversa de 2026-06-30 comparando as capacidades de um **analista black-box**
(raciocínio humano/assistido) com o que o `stiglitz.sh` entrega hoje. A pergunta original
("adicionar uma camada LLM de triagem") foi **descartada por restrição dura**:

> **Sem LLM nas máquinas de trabalho** — risco de egress de dado de CDE/cliente para
> serviço de inferência. Vale para modelo local também (superfície de risco/infra no
> engajamento). Toda melhoria aqui é **determinística, offline, zero-egress**.

**Tese:** a maior parte do "edge" de um analista black-box **não é raciocínio irredutível**,
são três técnicas determinísticas que ainda não foram codificadas:

1. **Rodar o experimento de controle e comparar** — o analista forma uma hipótese e testa a
   hipótese nula; o scanner dispara o payload e **confia no retorno**. (→ item #1)
2. **Correlacionar o que a ferramenta reporta separado** — juntar N lows num critical; o
   Stiglitz lista os N isolados. (→ item #5)
3. **Saber com o que "sensível" se parece** — classificar o corpo da resposta; hoje só
   `pan_scanner` (PAN via Luhn). (→ item #3)

O resíduo que **de fato** exige raciocínio (lógica de negócio inédita, hipótese zero-day
sobre stack novo, chain não-catalogado) **não vira código** — vira **apoio ao operador**
(hypothesis worksheet, ver seção final).

**Disciplina de entrega (herdada do ROADMAP.md):** TDD (teste→RED→GREEN), lógica pura +
CLI + `send_fn`/`fetch_fn` injetável primeiro (padrão `active_probe.py`/`apm_probe.py`/`bola.py`),
integração depois. `bash -n` + `shellcheck --severity=warning` limpos, `py_compile`, `pytest`.
Fail-closed. Findings em EN (deliverable); console/comentários PT-BR.

---

## Os 6 itens (determinísticos, sem LLM)

Ranqueados por alavanca no caso dominante (black-box CDE, zero-cred, sintoma "~13 findings / 0 High"):

| # | Capacidade de analista | Técnica determinística que a captura | Estende / novo | Alavanca | Status |
|---|---|---|---|---|---|
| **1** | Confirmar por experimento de controle (matar FP e nascer TP por diferencial, não por confiar no scanner) | **Oráculos de confirmação diferencial:** todo finding candidato passa por baseline vs. ataque **+ um payload-controle que NÃO deveria disparar**. Confirmado só se o efeito existe no ataque **e ausente no controle** → o efeito é atribuível ao payload, não a gate/WAF/eco genérico. Generaliza `active_probe` (boolean-pair/canary) p/ todas as classes. | `lib/confirm_oracle.py` (novo) + integração em `poc_validator.py` | **Máxima** | ✅ **núcleo + open redirect end-to-end** (SQLi-error só falta plugar) |
| **2** | Diff spec-vs-comportamento (mass assignment, excessive data exposure, shadow endpoints, campos não-documentados na resposta) | Parse OpenAPI + compara `schema`/`security:` **declarado** ao **observado**: resposta traz campos fora do schema → exposição; path observado ∉ spec → shadow; campo não-declarado aceito no body → mass assignment. | `lib/openapi_probe.py` (P0.1 do ROADMAP-blackbox-cde) | **Alta** | ⏳ pendente |
| **3** | Classificar o que é sensível numa resposta (além de PAN: JWT no body, CPF/email/telefone, ID interno sequencial, stack trace, IP privado, erro verboso) | **Classificador de corpo de resposta:** catálogo de detectores regex/schema. Reusa `pan_scanner` + `pii_detect`, amplia alcance → severidade contextual em escopo CDE. | `lib/response_classify.py` (novo) | **Alta** | ⏳ pendente |
| **4** | Descobrir falha de lógica por padrão estrutural (tampering de valor monetário, ID sequencial, quebra de máquina de estado) | **Engine de semântica de parâmetro:** classifica params por nome/tipo/schema (money/id/qty/state) e aplica **catálogo de mutação por classe** (negativo, zero, overflow, precisão decimal, moeda trocada, reordenar passos). Determinístico; pega o grosso, não a lógica inédita. | `lib/bizlogic.py` (hoje só executa config fixo) | **Média-alta** | ⏳ pendente |
| **5** | Encadear findings num attack path (open-redirect no host de auth + param refletido no fluxo OAuth = ATO candidate) | **Motor de correlação por regra:** biblioteca de padrões de chain conhecidos como predicados sobre o conjunto de findings. Não descobre chain inédito; captura os de alto valor que somem no report per-finding. | `lib/finding_chain.py` (novo; Hector já faz p/ infra) | **Média** | ⏳ pendente |
| **6** | Adaptar payload ao WAF observado | **Biblioteca de bypass por-WAF:** `wafw00f` já detecta o WAF → tabela de permutações (encoding/case/comment/chunking) keyed pelo WAF. Captura os bypasses *conhecidos*. | `lib/dast_prep.py` | **Média-baixa** | ⏳ pendente |

---

## Item #1 — Oráculos de confirmação diferencial (em implementação)

**Por que é o de maior alavanca:** muda a *postura* do scan. Hoje o Stiglitz **confia no veredito
da ferramenta** e depois se escreve um FP-reducer reativo por classe (`zap_authgate`, `tls_confirm`,
`finding_quality`). O oráculo **inverte** isso — *nada é finding sem passar no experimento de
controle*. É a técnica #1 do analista virada em código, e ataca direto o sintoma "0 High vs ruído".

**A cláusula-de-controle é o coração.** O que mata o FP de auth-gate/WAF de forma **genérica**
(sem um reducer por classe) é: se o **ataque** e o **controle** produzem a **mesma** resposta de
barreira (ambos 401/403, ambos a mesma página de bloqueio, corpos ≈ iguais), **não há diferencial**
→ o efeito não é atribuível à semântica do payload → `REJECTED`. Isso generaliza o insight do
`zap_authgate` para qualquer classe.

**Núcleo (puro, sem rede, testável):**

- `differential_verdict(attack_signal, control_signal, cls)` — decisão central:
  - efeito no ataque **e ausente** no controle → `CONFIRMED`
  - efeito no ataque **e presente** no controle → `REJECTED` ("efeito também no controle — gate/WAF/eco genérico, não atribuível ao payload")
  - sem efeito no ataque → `REJECTED` ("sem sinal diferencial")
- **Detectores de efeito** (predicados puros sobre a resposta), começando pelos inequívocos e ainda **não** cobertos em `active_probe`:
  - `redirect_effective_host(base_url, location)` + `is_offsite_redirect(...)` — **open redirect** (novo no suite; comum em fluxo OAuth do caso CDE). Resolve as evasões clássicas: `//evil`, `https:evil`, backslash `/\evil`, userinfo `target@evil`.
  - `db_error_signature(body)` — **SQLi error-based** (complementa o boolean-based do `active_probe`).
- **Adaptadores de efeito**: `redirect_effect(resp, ...)`, `sqli_error_effect(resp)` — mapeiam resposta→`{signal, detail}`.
- **Orquestração fina injetável**: `run_differential(base_url, attack_req, control_req, effect_fn, send_fn, cls)` — `send_fn` injetável (testável sem rede, padrão `apm_probe`).
- **CLI** `_main(argv)`.

**Fora de escopo do #1 (YAGNI):** correlação de chain (é o #5), classificação de dado sensível
(é o #3). O #1 só decide "este candidato é real?".

**Integração (feita p/ open redirect):** `poc_validator.confirm_nuclei` computa o oráculo quando
`vuln_type == "redirect"` (builder `build_redirect_variants` injeta host-canário externo; probe
sem `-L` via `_req_to_curl(follow=False)`; `parse_header_block` adapta os headers crus) e passa
`redir_oracle` ao `validate()`; o `validators/redirect.py` consome `ctx["redir_oracle"]` — degrada
sem regressão (builder None / fetch falho → fallback legado). Findings entram com `state`
`CONFIRMED`/`REJECTED` + `evidence` diferencial.

**Falta plugar (amanhã, extensão trivial):** o oráculo **SQLi error-based** já existe no núcleo
(`db_error_signature`/`sqli_error_effect`), mas o branch `vuln_type == "sqli"` do `confirm_nuclei`
ainda só roda o `boolean_pair` do `active_probe`. Basta um probe controle-vs-ataque com `'` e
threadar como sinal complementar (mesmo padrão do bloco de redirect).

---

## O que NÃO se replica sem raciocínio (resíduo → apoio ao operador)

- Falha de **lógica de negócio inédita** (exige entender o que *aquele* app faz).
- Hipótese estilo **zero-day** sobre stack nunca visto.
- **Chain novo** que ninguém catalogou.

Não vira detector. Vira **hypothesis worksheet**: o scan agrupa a evidência crua ociosa
(endpoints do OpenAPI sem detector, params "money" não-testados, respostas com dado sensível não
classificado) num artefato que o operador revisa em minutos. **Apoio, não substituição.** (Backlog,
depois dos itens 1–3.)

---

## Sequenciamento sugerido

1. **#1** (oráculos de confirmação) — em andamento; isolado, testável, ataca a dor #1, sem token/infra.
2. **#2** (spec-vs-comportamento) — maior conversão de "0 High" → High real no caso de API de pagamento.
3. **#3** (classificador de resposta) — reusa `pan_scanner`/`pii_detect`; barato depois do #2.
4. **#4/#5/#6** — profundidade; ordem conforme achado de campo.
5. **Hypothesis worksheet** — depois de 1–3 (consome o que eles deixam ocioso).

## Decisões registradas (2026-06-30)

- **Sem LLM, ponto.** Nem remoto nem local nas máquinas de trabalho. Todo item aqui é
  determinístico e offline.
- **Cláusula-de-controle genérica > FP-reducer por classe.** O #1 substitui a necessidade de
  escrever um reducer novo a cada FP visto em campo.
- **Não compõe criticidade fora do que já existe.** Oráculo decide confirmação (`CONFIRMED`/
  `REJECTED`); o score CVSS+KEV+EPSS+environmental segue intacto (mesma disciplina do
  `compliance_map`/`owasp_posture`).

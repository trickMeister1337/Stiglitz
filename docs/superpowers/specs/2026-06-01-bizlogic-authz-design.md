# Design — Detecções de Lógica de Negócio / Authz (Fase 1)

- **Data:** 2026-06-01
- **Status:** Aprovado (brainstorming) — aguardando revisão do spec
- **Escopo:** Fase 1 do roadmap de melhorias. Depende da Fase 0 (motor de criticidade, já concluída). Cobre detecções ativas de lógica de negócio e autorização para fintech. As demais frentes (authn, 3DS, paralelização de batch, adapters, hardening) têm specs próprios.

## 1. Problema

O Stiglitz é forte em vulnerabilidades de superfície (envelopa nuclei/ZAP/sqlmap) mas **não testa lógica de negócio nem autorização granular** — exatamente os riscos centrais de uma fintech (gateways, 3DS, VCN, split, chargebacks). Scanners genéricos não pegam: IDOR/BOLA multi-tenant, manipulação de valor/transação, double-spend por race condition, falha de idempotência, escalação de privilégio. Esses testes exigem **contexto da aplicação** (quais params são IDs de objeto, quais endpoints movem dinheiro) e **duas contas de usuário** para provar acesso cross-user.

## 2. Objetivo

Um módulo de detecção **spec-driven** que, a partir de um arquivo declarativo do operador (contas de teste + endpoints-alvo), executa testes estruturados e seguros de lógica de negócio/authz, emite findings confirmados com `vuln_class`, e alimenta o motor de criticidade (Fase 0) e o relatório. Seguro para rodar em staging de uma fintech: mutações gated por profile + contas-sentinela + gate RoE + escopo.

## 3. Modelo de operação

**Spec-driven + descoberta leve.** O operador fornece `bizlogic.yaml` (contas + endpoints). O módulo executa os testes declarados. Complementarmente, faz descoberta heurística de candidatos a IDOR (read-only) a partir de URLs do scan/OpenAPI — apenas como sugestão de cobertura, nunca mutando.

## 4. Componentes (módulos focados)

| Componente | Responsabilidade |
|---|---|
| `lib/bizlogic.py` | Núcleo: parse do yaml, auth multi-conta, execução das 4 famílias, comparação de respostas, verdito, emissão de findings. Lógica de decisão em funções puras. |
| `lib/bizlogic.sh` | Wrapper fino: aplica profile (lab/staging/production), gate RoE, escopo, timeouts; chama `bizlogic.py`; emite audit. |
| Nova fase em `stiglitz_red.sh` | Roda após a ingestão, antes dos exploits; consome `scan_dir` + `bizlogic.yaml`. |
| `lib/profiles.conf` | Acrescenta entradas de profile para bizlogic (mutação on/off, max_requests, timeout, race_workers). |

**Standalone:** `python3 lib/bizlogic.py --config bizlogic.yaml --scan-dir <dir> --profile staging --outdir <dir>`.

## 5. Arquivo de contexto `bizlogic.yaml`

```yaml
base_url: https://app.example.com
accounts:
  A:     { auth: { type: bearer, token: "eyJ..." }, id: "user-123", tenant: "org-1" }
  B:     { auth: { type: bearer, token: "eyJ..." }, id: "user-456", tenant: "org-2" }
  admin: { auth: { type: cookie, cookie: "session=..." } }      # opcional
# auth.type ∈ {bearer, cookie, header}; header → { type: header, headers: {X-Auth: "..."} }
sentinel: { amount: "0.01", recipient: "test-recipient-id" }
endpoints:
  - name: get_account
    method: GET
    path: /api/accounts/{id}
    owner_param: id            # param que identifica o dono do recurso
    object_of: A               # o recurso pertence à conta A
    tests: [idor_read]
  - name: update_account
    method: PUT
    path: /api/accounts/{id}
    owner_param: id
    object_of: A
    body: { nickname: "stiglitz-canary" }
    tests: [idor_write]
  - name: transfer
    method: POST
    path: /api/transfer
    body: { amount: "{amount}", to: "{recipient}", from_account: "{owner}" }
    money_params: [amount]
    idempotency_header: Idempotency-Key
    tests: [amount_tampering, race, idempotency]
  - name: admin_users
    method: GET
    path: /admin/users
    tests: [privesc]           # A (não-admin) tenta acessar
```

Placeholders: `{id}`/`{owner}` resolvem do `id` da conta; `{amount}`/`{recipient}` do `sentinel`. Override de classificação de ativo continua via `assets.json` (Fase 0).

## 6. As 4 famílias de teste — lógica de confirmação

### 6.1 IDOR read (`vuln_class: idor_read_pii` ou `bola`)
1. Como **A**, GET no recurso de A → baseline (espera 2xx, captura corpo).
2. Como **B**, GET no MESMO recurso de A (troca `owner_param`).
3. **Confirmado** se B recebe 2xx **e** o corpo é equivalente ao baseline de A (similaridade por campos-chave / normalização de tokens dinâmicos). Read-only. `confirmed=True`.
4. Caso B receba 401/403/404 ou corpo divergente → não vulnerável.

### 6.2 IDOR write + privilege escalation
- **idor_write** (`vuln_class: idor_write`): como **B**, PUT/POST/DELETE no recurso de A com `body` declarado (valor canário). 2xx + efeito confirmável (re-leitura como A mostra a mudança) → confirmado. **Mutating** → gated.
- **privesc** (`vuln_class: priv_escalation`): como **A** (não-admin), acessa o endpoint admin. 2xx → confirmado. Read-only se GET; mutante → gated.

### 6.3 Amount/currency tampering (`vuln_class: amount_tampering`)
Como **A**, envia a transação (sentinela: `amount=0.01`, `recipient` de teste) com variações adulteradas nos `money_params`: negativo (`-0.01`), zero, casas extras (`0.001`), string não-numérica, moeda trocada, overflow. **Confirmado** se alguma variação é **aceita** (2xx, sem rejeição de validação) onde deveria ser recusada. **Mutating** → gated.

### 6.4 Race condition + idempotency (`vuln_class: race_condition_funds`)
- **race:** dispara `race_workers` (por profile) requisições concorrentes da MESMA operação sentinela (ex.: transfer de valor X). **Confirmado** se mais de uma sucede além do permitido (double-spend) — detectado por contagem de 2xx vs. esperado 1. **Mutating** → gated.
- **idempotency replay:** reenvia a MESMA requisição com a MESMA `Idempotency-Key`. **Confirmado** se processada 2× (ambas 2xx com efeito) em vez de a 2ª retornar o resultado cacheado. **Mutating** → gated.

## 7. Segurança (gating)

- **Profile** (`lib/profiles.conf`):
  - `production`: somente não-mutantes (idor_read, privesc-GET) + **dry-run** dos mutantes — monta e registra a requisição maliciosa e a resposta a um **probe benigno**, sem enviar a mutação. `race_workers=1`.
  - `staging`/`lab`: mutação real **apenas** contra contas/sentinela declaradas. `race_workers` 5/10.
- **Gate RoE:** exige digitar `EU AUTORIZO` (reusa o gate do `stiglitz_red.sh`) antes de qualquer envio mutante.
- **Escopo:** todo host derivado de `base_url`/endpoints é validado contra `SCOPE_DOMAINS` antes de cada request; fora de escopo → pulado e logado.
- **Sentinela obrigatória:** testes mutantes recusam-se a rodar se `sentinel` não estiver definido. Nunca usa valores/destinatários reais.
- **Limites:** `max_requests` e timeouts por profile.

## 8. Saída e integração

- Findings em `<outdir>/raw/bizlogic.json`: lista de `{name, vuln_class, url, method, severity (baseline da família), confirmed (bool), evidence: {request, response, baseline?}, account_pair?}`.
- Severidade baseline por família (ferramenta); a **criticidade final** vem do motor da Fase 0: `confirmed=True → E:H` (Temporal) e `asset_class` do host (funds/cde → CR:H/IR:H) elevam o Environmental.
- `audit "FINDING_CONFIRMED type=bizlogic class=<vuln_class> target=<url>"` na hash-chain.
- **Caminho de ingestão (concreto):** `lib/ingest.py` (RED) passa a ler `raw/bizlogic.json`; os findings entram na consolidação do `lib/evidence.py`, que já chama `criticality.enrich_findings` (Fase 0) e renderiza os campos de criticidade no relatório RED. (`idempotency replay` usa `vuln_class: race_condition_funds` por ora — mesma família de integridade transacional; um CWE próprio pode ser adicionado ao catálogo numa fase futura.)

## 9. Tratamento de erros

- Exceções tipadas (`ValueError` p/ yaml inválido; erros de rede capturados por request, não derrubam a fase). Sem `except:` mudo.
- Nunca envia request fora de escopo, nem mutação sem profile permitir + gate + sentinela.
- Auth inválida de uma conta → loga e pula os testes que a exigem; segue com os demais.

## 10. Testes (`tests/test_bizlogic.py`)

- **Funções puras:** comparação de equivalência de resposta (mesma vs diferente, com normalização de tokens), construção de payload adulterado, detecção de double-spend a partir de N respostas, parse/validação do `bizlogic.yaml`, resolução de placeholders.
- **App falso** (servidor HTTP mock em-memória, estilo `FakeSMTP` do `test_email_spoof.py`): um endpoint **vulnerável** e um **seguro** por família; assert que cada detecção **confirma** o vulnerável e **não** falsa-positiva o seguro.
- **Gating:** profile `production` não envia mutação (só dry-run); host fora de `SCOPE_DOMAINS` é bloqueado; testes mutantes recusam sem `sentinel`.
- **Integração com criticidade:** finding `confirmed=True` em ativo `funds` resulta em banda alta/crítica via `criticality.enrich_findings`.

## 11. Fora de escopo (Fase 1)

- Authn (JWT alg=none/segredo fraco; OAuth) — Fase 2.
- 3DS/MPI — fase própria no `pci_scan.sh`.
- Descoberta totalmente autônoma de endpoints de negócio (só descoberta leve read-only de candidatos a IDOR).
- Adapters DefectDojo/Jira, paralelização de batch, hardening — frentes próprias.

## 12. Critérios de aceite

1. `bizlogic.py` parseia `bizlogic.yaml` (contas com bearer/cookie/header; endpoints; sentinel) e valida campos obrigatórios.
2. As 4 famílias confirmam corretamente o caso vulnerável e não falsa-positivam o seguro (provado contra o app falso).
3. Mutação só ocorre em lab/staging, contra sentinela, após gate RoE; production faz dry-run; escopo é enforçado.
4. Findings em `raw/bizlogic.json` com `vuln_class` + `confirmed`; ao passar pelo motor de criticidade, `confirmed` em ativo financeiro produz criticidade alta/crítica.
5. Nova fase integrada ao `stiglitz_red.sh` (e standalone) com audit na hash-chain.
6. Suíte `tests/test_bizlogic.py` verde; sem regressão na suíte existente; sem `except:` mudo nos arquivos novos.

# Design — Email Spoof (prova de loop fechado) + Compliance Mapping só-PCI

**Data:** 2026-06-14
**Status:** Aprovado (design) — aguardando revisão do spec antes dos planos
**Contexto:** Red team / pentest autorizado (RoE assinado). Console/operador em PT-BR;
campos de relatório/JSON destinados a deliverable em EN (convenção do suite).

> **Higiene CDE (crítica):** nenhum domínio/caixa de cliente entra em arquivo
> versionado, teste ou fixture. Este spec e todos os testes usam placeholders
> genéricos (`example.com`, `operator@example.com`). Os outputs reais da POC
> (`spoof_poc_*/`) já são ignorados pela estratégia "ignore tudo, libera só o
> projeto" do `.gitignore`.

---

## 1. Motivação

Dois problemas independentes, levantados em operação:

**A) A POC de email spoof reporta "vulnerável" mas nunca PROVA exploração.**
O scanner (`lib/email_security.py`) classifica SPF/DMARC ausentes como `high` por
análise de DNS — correto como *risco teórico*, daí "quase todo scan = crítico". Mas a
POC (`email_spoof_poc.py --send`) não consegue fechar a prova. Causa raiz:

1. **Transporte frágil:** entrega direta na **porta 25** ao MX do destinatário. Da
   máquina do operador a porta 25 de saída costuma estar bloqueada (timeout) ou o MX
   recusa por reputação de IP (sem rDNS/PTR). Resultado `accepted=False` →
   "REJEITADO/FALHOU", lido como "não consegui provar". Mas é **falha de transporte,
   não DMARC bloqueando** — o teste nem chega ao ponto onde o DMARC é avaliado.
2. **Mede o sinal errado:** mesmo com `250` no DATA, a POC trata como prova. `250` só
   diz "MX aceitou para a fila". Não prova entrega na **inbox** nem revela o **veredito
   de autenticação do recebedor** (`Authentication-Results: dmarc=...`). A prova real é
   o email **chegar na caixa** com `From:` forjado e header `dmarc=fail`.

**B) "Compliance Mapping" do relatório é multi-framework; operador quer foco PCI.**
A seção mostra OWASP/ASVS/PCI/ISO/NIST com contagem por controle. O pedido: **só PCI
DSS 4.0.1**, com veredito **PASS/FAIL/N-A** por requisito e **resumo breve**.

---

## 2. Parte A — POC de email spoof (prova de loop fechado)

**Abordagem escolhida:** confirmação **manual** em duas etapas (envio + finalize). IMAP
automatizado fica como evolução futura (fora de escopo). Envio via **relay autenticado
controlado pelo operador** (resolve a raiz de transporte/reputação).

### 2.1 Mudanças em `email_spoof_poc.py`

1. **Relay vira caminho primário.** Hoje `deliver_relay` só roda como *fallback* se a
   entrega direta falha (linha ~304). Inverter: havendo `--smtp` / `STIGLITZ_SMTP_*`, o
   relay é o caminho principal. Com relay presente, a entrega direta na porta 25
   **só** ocorre se `--allow-direct` for passado; sem essa flag, não há fallback
   para a 25 (evita reintroduzir o transporte frágil pela porta de trás).

2. **Reclassificação honesta do resultado SMTP** (substitui o booleano `accepted`):
   - falha em CONNECT/EHLO → `TRANSPORT_FAILED` (inconclusivo — **não** prova segurança)
   - rejeição em MAIL/RCPT → `BLOCKED_BY_RELAY` (a política do relay barrou o envio)
   - `250` no DATA → `QUEUED` (aceito para entrega — **ainda não** é spoof provado)

   O `smtp_stage` passa a ser registrado na evidência junto do transcript.

3. **Confirmação manual + modo `--finalize`.** Após `QUEUED`, a POC imprime instruções
   (PT-BR) e grava `spoof_evidence.json` com `manual_confirmation` pendente (guarda o
   `message_id` e o `forged_from`). O operador abre a caixa, copia o header e roda:
   ```
   python3 email_spoof_poc.py --finalize <outdir> \
       --auth-results "<colar Authentication-Results>" --landed inbox|spam|not_delivered
   ```
   (`--auth-results-file <path>` como alternativa para headers longos.)

4. **Parser puro de `Authentication-Results`.** Função `parse_auth_results(header)` →
   `{"dmarc": "pass|fail|none", "spf": "...", "dkim": "...", "compauth": "..."}`,
   tolerante a múltiplas linhas e à ausência de campos. Sem rede; testável.

5. **Verdito empírico final** `compute_empirical_verdict(analytic, smtp_stage, landed,
   auth)` — combina o analítico (DNS) com a confirmação manual (ver matriz em 2.3).

### 2.2 Interface CLI (deltas)

| Flag (nova/alterada) | Efeito |
|----------------------|--------|
| `--smtp HOST[:PORT]` | (existente) agora **primário** quando presente |
| `--allow-direct`     | permite fallback de entrega direta na 25 mesmo com relay |
| `--finalize DIR`     | modo de finalização: lê a evidência pendente em `DIR` |
| `--auth-results STR` | header `Authentication-Results` colado da caixa (com `--finalize`) |
| `--auth-results-file PATH` | idem, lido de arquivo |
| `--landed VALUE`     | `inbox` \| `spam` \| `not_delivered` (com `--finalize`) |

Flags existentes (`--send`, `--to`, `--from`, `--dry-run`, `--roe-accept`, gate RoE,
`STIGLITZ_SMTP_PASS`) permanecem.

### 2.3 Matriz de verdito empírico

| `smtp_stage` | `landed` | `dmarc` (header) | Verdito empírico | Severidade |
|--------------|----------|------------------|------------------|-----------|
| TRANSPORT_FAILED | — | — | `INCONCLUSIVE_TRANSPORT` | info (não conclui nada) |
| BLOCKED_BY_RELAY | — | — | `BLOCKED_BY_RELAY` | info (caminho de envio barrou) |
| QUEUED | (sem finalize) | — | `QUEUED_PENDING_CONFIRMATION` | pendente |
| QUEUED | inbox | fail | `SPOOF_PROVEN_INBOX` | **critical (provado)** |
| QUEUED | spam | fail | `SPOOF_PROVEN_SPAM` | medium (provado, filtrado) |
| QUEUED | inbox/spam | pass | `NOT_SPOOFABLE` | info (recebedor autenticou; forjado não passou) |
| QUEUED | not_delivered | — | `NOT_DELIVERED` | info (descartado/silencioso) |

`NOT_SPOOFABLE` é o ponto-chave: separa **"crítico teórico" (DNS fraco)** de
**"explorável de fato"**. Reconcilia o "sempre crítico" do scanner com o que a evidência
empírica sustenta.

### 2.4 Aviso técnico (relay que alinha o From:)

Relays gerenciados (Gmail/SES/SendGrid/Mailgun) **reescrevem ou rejeitam** `From:` de
domínio não-verificado — invalidam o teste de spoof. Para forjar `From:` de um domínio
alvo, o relay precisa **preservar** o `From:` (SMTP próprio com rDNS/reputação). A POC
**avisa** no console quando `--smtp` é usado e relembra esse pré-requisito. (Não há como
detectar a reescrita sem ler a caixa — daí o aviso + a confirmação manual.)

### 2.5 Testes (`tests/test_email_spoof.py`, estendido)

- `parse_auth_results`: pass/fail/none, multilinha, campos ausentes, lixo.
- `compute_empirical_verdict`: toda a matriz de 2.3.
- reclassificação `smtp_stage`: MAIL/RCPT 5xx → `BLOCKED_BY_RELAY`; connect erro →
  `TRANSPORT_FAILED`; 250 → `QUEUED` (via `smtp_factory` fake, sem rede).
- `--finalize`: lê evidência pendente, grava verdito final, idempotente.
- Placeholders genéricos apenas (`example.com`).

---

## 3. Parte B — Compliance Mapping só-PCI (PASS/FAIL/N-A)

Repagina **apenas** a seção "Compliance Mapping" (`stiglitz_report.py:~2213-2229`). A
seção "PCI DSS CDE Coverage" (linhas ~2193-2211) permanece intacta.

### 3.1 Regra de veredito por requisito PCI

Universo = requisitos PCI que o scanner consegue exercitar: união dos valores `pci` do
crosswalk `compliance_map._MAP` com os requisitos de `pci_verdicts.py`
(`2.2.1, 2.2.5, 3.2, 4.2.1, 6.2.4, 6.3.3, 7.2.1, 8.3.1, 8.3.4, 8.6.1, 10.2.1`).

Para cada requisito do universo:
1. **FAIL** — ≥1 finding mapeado (via CWE→`pci` **ou** via `pci_req` do CDE).
2. **PASS** — sem finding **e** o sinal de cobertura presente (capacidade rodou).
3. **N/A** — capacidade não exercida. Default conservador: na dúvida, **N/A** (nunca
   PASS falso — mesma filosofia anti-"0 High enganoso").

### 3.2 Mapa requisito → sinal de cobertura

| Req | Capacidade | Sinal de "rodou" (em `raw/`) |
|-----|-----------|------------------------------|
| 2.2.1 | Hardening/misconfig | `security_headers.json` ou findings nuclei |
| 2.2.5 | Serviços de rede expostos | `service_findings.json` (nmap `-sV`) |
| 3.2   | Proteção de dados no CDE | escopo CDE ativo (`cde_targets.txt`) |
| 4.2.1 | TLS forte | output testssl presente |
| 6.2.4 | App seguro (injeção/XSS/CSRF/SSRF) | findings nuclei/ZAP presentes |
| 6.3.3 | Componentes atualizados | nuclei (cve/tech) presente |
| 7.2.1 | Controle de acesso | scan autenticado (token presente) |
| 8.3.1 / 8.3.4 / 8.6.1 | Autenticação | scan autenticado (token presente) |
| 10.2.1 | Logging/monitoring | só FAIL se houver finding; senão N/A (DAST não exercita) |

"Scan autenticado" = `AUTH_TOKEN`/`TOKEN_A` presente **e** sem
`raw/.coverage_gap_authed_api`. Sem token → access control/autenticação = **N/A**, não
PASS.

### 3.3 Implementação

- **`lib/compliance_map.py`** — nova função pura
  `pci_posture(findings, coverage) -> list[{req, verdict, count, top_findings}]`.
  `coverage` é um dict de flags booleanas (um por sinal de 3.2). Não toca em rede nem
  arquivo; recebe tudo pronto. Testável isoladamente.
- **`stiglitz_report.py`** — deriva `coverage` dos artefatos em `raw/` (presença de
  arquivos / flags já lidas), chama `pci_posture`, e renderiza:
  - **resumo** (uma linha): `PCI DSS 4.0.1 — N requisitos avaliados: X FAIL, Y PASS,
    Z N/A. Principais gaps: <req (count)> ...`
  - **tabela** PASS/FAIL/N-A por requisito, com a contagem e os títulos dos findings de
    topo nos requisitos FAIL.

### 3.4 Testes (`tests/test_compliance_map.py`, estendido)

- `pci_posture`: FAIL com finding; PASS com cobertura sem finding; N/A sem cobertura;
  N/A para access control sem token; precedência FAIL sobre cobertura.
- Wiring no relatório: `tests/test_report_*_wiring.py` no padrão existente — a seção sai
  só com PCI, com as três tags possíveis e o resumo.

---

## 4. Fora de escopo (YAGNI)

- **Confirmação por IMAP automatizada** — evolução futura; hoje confirmação manual.
- **Mudar a severidade do `lib/email_security.py`** — o verdito de DNS continua válido
  como risco. A reconciliação "teórico × provado" acontece na POC (verdito empírico),
  não no scanner. Não alterar sem pedido explícito.
- **Listar requisitos PCI fora do universo do scanner** — ruído; a tabela cobre só o
  que o scanner endereça.

---

## 5. Decomposição de implementação

Dois planos em sequência (a POC é a dor ativa, vai primeiro):

1. **Plano 1 — POC de email spoof (loop fechado):** relay primário, reclassificação de
   estágio SMTP, `--finalize`, parser de `Authentication-Results`, verdito empírico,
   testes.
2. **Plano 2 — Compliance Mapping só-PCI:** `pci_posture` + derivação de `coverage` +
   render PASS/FAIL/N-A + resumo, testes.

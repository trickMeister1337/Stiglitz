# Design — `email_spoof_poc.py` (Evidência de Exploração de SPF/DMARC/DKIM)

**Data:** 2026-05-28
**Status:** Aprovado (design) — aguardando revisão final antes do plano de implementação
**Contexto:** Red team / pentest autorizado (RoE assinado). Ferramenta experimental, testada em
paralelo ao SWARM suite; avaliar incorporação posterior.

---

## 1. Propósito

O módulo de Email Security do `stiglitz.sh` (`lib/email_security.py`) **detecta** fraquezas de
SPF/DMARC/DKIM analisando registros DNS, mas não prova que o spoofing é de fato explorável. Este
script preenche essa lacuna: dado um domínio alvo, produz **evidência de exploitabilidade** de
spoofing de remetente.

- **Sempre** emite um *verdito analítico* (sem enviar nada).
- **Opcionalmente** (`--send`, opt-in atrás de gate RoE) entrega um email forjado a um destinatário
  controlado pelo operador e captura o **transcript SMTP** como prova de aceitação.

Abordagem escolhida: **script Python standalone, único arquivo** no top-level
(`email_spoof_poc.py`), reaproveitando a lógica de classificação do `lib/email_security.py`. Mantém
o detector (read-only) desacoplado do atacante (envia email), coerente com a separação
detecção/exploração do suite.

---

## 2. Interface (CLI)

```
python3 email_spoof_poc.py <domain> [opções]

Posicional:
  domain                  Domínio alvo — o domínio forjado em From:/MAIL FROM

Modo padrão (sem flags)   → só verdito analítico, NÃO envia nada
  --dry-run               → mostra o envelope/headers que SERIAM enviados, sem enviar

Envio real (opt-in):
  --send                  → ativa entrega forjada (exige gate RoE)
  --to ADDR               → destinatário (obrigatório com --send)
  --from ADDR             → remetente forjado (default: security-test@<domain>)
  --subject STR           → assunto (default marca como teste autorizado)
  --body STR              → corpo
  --body-file PATH        → corpo a partir de arquivo
  --smtp HOST[:PORT]      → relay de fallback (opcional; porta default 587)
  --smtp-user STR         → usuário do relay (opcional → ativa STARTTLS+login)
  --smtp-pass STR         → senha do relay (opcional)
  --helo NAME             → nome no EHLO/HELO (default: hostname local)

Gate RoE:
  --roe-accept            → confirma autorização não-interativamente
  --no-roe                → pula o prompt (CI/CD), igual ao osint.sh

Saída:
  --outdir DIR            → default: spoof_poc_<domain>_<timestamp>/
```

**Idioma:** console/operador em PT-BR; campos de relatório/JSON destinados a deliverable em EN
(mesma convenção do suite).

---

## 3. Verdito analítico

Reaproveita as funções de classificação do `lib/email_security.py` (importadas, sem duplicar
lógica). Caso a importação direta não seja viável sem refatorar o módulo, o design prevê extrair as
três funções de classificação (`classify_spf`, `classify_dmarc`, `classify_dkim`) para funções puras
reutilizáveis — refactor mínimo e focado, sem alterar comportamento do detector.

**Princípio técnico central:** quem bloqueia spoofing do `From:` visível é o **DMARC** (com
alinhamento), não o SPF isolado — SPF protege o envelope (`MAIL FROM`), não o `From:` exibido. O
verdito modela isso honestamente.

### Matriz de verdito

| DMARC                | SPF                 | Verdito                  | Significado |
|----------------------|---------------------|--------------------------|-------------|
| MISSING ou `p=none`  | qualquer            | **SPOOFABLE_INBOX**      | `From:` forjado do domínio exato chega na inbox |
| `p=quarantine`       | fraco/ok            | **SPOOFABLE_SPAM**       | chega, mas tende a quarentena/spam |
| `p=reject` (alinhado)| ok                  | **BLOCKED (exato)**      | spoofing do domínio exato barrado; registra que lookalike/cousin domain segue viável |
| qualquer             | MISSING/`+all`/`?all` | agrava o caso atual    | envelope-from livre, facilita bypass/bounce |

Saída do verdito inclui, por execução:
- Status de cada registro (SPF/DMARC/DKIM) + valor bruto (via reuso do detector)
- O **envelope exato** que o atacante usaria: `MAIL FROM:<...>` e `From: <...>`
- Linha de impacto em PT-BR (console) e EN (JSON)

---

## 4. Fluxo de envio (`--send`)

1. **Gate RoE** (salvo `--no-roe`): imprime escopo (domínio forjado, destinatário, método) e exige
   confirmação explícita — padrão do `osint.sh`.
2. **Monta a mensagem** com `email.message.EmailMessage`: `From:` forjado, `To:`, `Subject`,
   `Date`, **`Message-ID` gerado e capturado**, corpo marcado como teste de segurança autorizado.
3. **Resolve o MX** do domínio do `--to` via `dig MX` (mesmo padrão do detector); escolhe a menor
   preferência.
4. **Entrega direta na porta 25** via `smtplib` em modo low-level
   (`.ehlo()` → `.mail()` → `.rcpt()` → `.data()`), capturando cada par `(código, resposta)`.
5. **Fallback**: se a porta 25 estiver bloqueada/recusada/timeout → usa `--smtp`
   (com STARTTLS + login quando `--smtp-user` informado).
6. **`250` após DATA = mensagem aceita** pelo MX → evidência de aceitação no envelope.
7. Captura o **transcript SMTP completo**.

Sem IMAP, sem leitura de inbox, sem envio em massa (um único destinatário por execução).

---

## 5. Saída e evidência

Em `<outdir>/`:

- **`spoof_evidence.json`** — estrutura:
  ```json
  {
    "domain": "...",
    "timestamp": "...",
    "dns_records": { "spf": {...}, "dmarc": {...}, "dkim": {...} },
    "verdict": {
      "status": "SPOOFABLE_INBOX|SPOOFABLE_SPAM|BLOCKED|...",
      "forged_envelope": { "mail_from": "...", "header_from": "..." },
      "impact_en": "..."
    },
    "send": {              // presente apenas se --send executou
      "recipient": "...",
      "forged_from": "...",
      "mx_used": "...",
      "delivery_method": "direct|relay",
      "message_id": "...",
      "accepted": true,
      "smtp_transcript": "...",
      "timestamp": "..."
    }
  }
  ```
- **`smtp_transcript.txt`** — diálogo SMTP cru (a "smoking gun").
- **Console** — resumo em PT-BR.

---

## 6. Segurança e escopo

- Gate RoE obrigatório antes de qualquer envio.
- Um destinatário por execução — não é mailer em massa.
- `Subject`/corpo identificam a mensagem como teste autorizado.
- `--dry-run` mostra envelope + headers sem enviar.
- Nenhuma credencial de mailbox manuseada (sem IMAP).

---

## 7. Testes (`test_email_spoof.py`)

- **Verdito offline:** registros DNS falsos (mock do `dig`) → verdito esperado, cobrindo cada linha
  da matriz da seção 3.
- **Smoke `--dry-run`** sem rede (verifica montagem de envelope/headers).
- **`py_compile`** do script e do módulo reusado.

Não há componente bash → `shellcheck` não se aplica.

---

## 8. Fora de escopo (YAGNI)

- Verificação via IMAP / leitura de inbox / extração de `Authentication-Results` do correio recebido.
- Envio em massa / lista de destinatários.
- Geração de relatório HTML dedicado (o JSON + transcript bastam para a fase experimental).
- Integração no `stiglitz.sh`/`pipeline.py` (decisão posterior, após avaliação paralela).

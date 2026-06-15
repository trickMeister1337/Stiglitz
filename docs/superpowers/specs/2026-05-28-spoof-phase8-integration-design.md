# Design — Integração do `email_spoof_poc` como parte da Fase 8 do `stiglitz.sh`

**Data:** 2026-05-28
**Status:** Aprovado (design) — aguardando revisão final antes do plano
**Contexto:** Red team / pentest autorizado (RoE assinado). Pluga a PoC de spoofing
(`email_spoof_poc.py`, já no suite) no pipeline de scan, estendendo a Fase 8.

---

## 1. Propósito

A Fase 8 (`SEGURANÇA DE EMAIL`) do `stiglitz.sh` já coleta SPF/DMARC/DKIM via
`lib/email_security.py` (grava `raw/email_security.json`), mas para apenas na detecção dos
registros. Esta integração adiciona o **verdito de exploitabilidade de spoofing** ao scan,
reusando o `email_spoof_poc.py`.

Decisões de design (do brainstorming):
- **Verdito analítico sempre** durante o scan; **envio forjado é opt-in** por flag.
- **Estende a Fase 8** (não cria nova fase, não renumera, não toca no `pipeline.py`).
- **Enriquecimento da seção Email Security** no relatório — **não** vira finding separado
  (evita contar a mesma causa-raiz duas vezes no risk score).

---

## 2. `email_spoof_poc.py` — flag `--records-json`

Única mudança no tool. Adiciona `--records-json PATH` ao `parse_args`. No `main()`:

```python
if args.records_json:
    with open(args.records_json) as f:
        records = json.load(f)
else:
    records = analyze(domain)
```

Todo o resto (compute_verdict, build_message, RoE gate, deliver_*, write_evidence) permanece
inalterado. Isso permite à Fase 8 reusar os registros DNS já coletados, sem re-resolução e sem
risco de divergência se o DNS oscilar.

Comportamento preservado: sem `--send`/`--dry-run`, o `main()` apenas computa o verdito e grava
`spoof_evidence.json` com `send=None` (modo analítico).

---

## 3. `stiglitz.sh` — Fase 8: novas flags e wiring

### Novas flags (parser de argumentos do `stiglitz.sh`)

| Flag | Descrição |
|------|-----------|
| `--spoof-send` | Ativa o envio forjado durante o scan (opt-in) |
| `--spoof-to ADDR` | Destinatário (obrigatório com `--spoof-send`) |
| `--spoof-from ADDR` | Remetente forjado (opcional; default do tool: `security-test@<domínio>`) |
| `--spoof-smtp HOST[:PORT]` | Relay de fallback (opcional) |

Guard: se `--spoof-send` sem `--spoof-to`, o `stiglitz.sh` erra e sai (mesmo estilo dos
guards de argumentos existentes). Variáveis internas: `SPOOF_SEND`, `SPOOF_TO`, `SPOOF_FROM`,
`SPOOF_SMTP`.

### Wiring na Fase 8

Após o bloco atual que roda `email_security.py` e calcula `EMAIL_ISSUES`, dentro do
`if command -v dig` e somente se `raw/email_security.json` existir:

```bash
SPOOF_ARGS=(--records-json "$OUTDIR/raw/email_security.json" --outdir "$OUTDIR/raw")
if [ -n "$SPOOF_SEND" ]; then
    SPOOF_ARGS+=(--send --to "$SPOOF_TO" --roe-accept)
    [ -n "$SPOOF_FROM" ] && SPOOF_ARGS+=(--from "$SPOOF_FROM")
    [ -n "$SPOOF_SMTP" ] && SPOOF_ARGS+=(--smtp "$SPOOF_SMTP")
fi
python3 "$SCRIPT_DIR/email_spoof_poc.py" "$DOMAIN" "${SPOOF_ARGS[@]}"
SPOOF_VERDICT=$(python3 -c "
import json
try:
    d = json.load(open('$OUTDIR/raw/spoof_evidence.json'))
    print(d.get('verdict',{}).get('status',''))
except Exception: print('')" 2>/dev/null || echo '')
export SPOOF_VERDICT
```

Mensagens de console em PT-BR (ex.: `[✓] Verdito de spoofing: SPOOFABLE_INBOX`). Quando `dig`
não está disponível, a parte de spoofing é pulada junto com a análise de email (já é o caso hoje).

### Autorização (RoE)

`--spoof-send` é o opt-in explícito do operador; o gate RoE do próprio `stiglitz.sh` (no início
do scan) cobre a autorização do engajamento. Por isso a fase repassa `--roe-accept` ao tool — o
prompt per-envio do `email_spoof_poc.py` seria redundante num scan desacompanhado. Operadores
que rodam o scan com `--no-roe` (CI) e adicionam `--spoof-send` estão optando explicitamente por
ambos.

---

## 4. `stiglitz_report.py` — enriquecimento da seção Email Security

- Carrega `raw/spoof_evidence.json` de forma graceful (ausência → seção sem o box; scans antigos
  seguem funcionando).
- Na seção Email Security existente (próximo da renderização atual de SPF/DMARC/DKIM, ~linha
  1271), renderiza um **box de verdito** (idioma EN, padrão deliverable):
  - `Spoofing verdict: <status> — <impact_en>`
  - Envelope forjado: `MAIL FROM:<...>` / `From: <...>`
- Se houver bloco `send` com `accepted: true`, renderiza o **transcript SMTP** (de
  `send.smtp_transcript`) como evidência/PoC de entrega.
- **Não** alimenta `findings`/estatísticas/risk score — é enriquecimento de exibição.

---

## 5. Testes e validação

- **Unit** (`test_email_spoof.py`): novo teste do modo `--records-json` — escreve um JSON de
  registros falso num tempdir, chama `main(["dom", "--records-json", path, "--outdir", d])`,
  confirma que `spoof_evidence.json` é gerado com o verdito esperado e `send` ausente, **sem rede
  e sem chamar `analyze`**.
- **Bash:** `bash -n stiglitz.sh` e `shellcheck --severity=warning stiglitz.sh` (gate do CI).
- **Python:** `python3 -m py_compile email_spoof_poc.py stiglitz_report.py`.
- **Regressão:** `python3 -m pytest test_email_spoof.py test_lib.py test_swarm_modules.py test_pipeline.py`.

---

## 6. Fora de escopo (YAGNI)

- Forwarding da flag `--spoof-send` pelo `pipeline.py` (dirige fases via `--only-phase`; o verdito
  analítico roda na P8 de qualquer modo — só o envio fica restrito ao `stiglitz.sh` direto).
- Verificação de entrega via IMAP (já fora de escopo do tool).
- Tornar o verdito um finding com severidade (decisão explícita: enriquecimento, não finding).
- Fix de hardening do `lib/profile_loader.py` (finding de segurança pré-existente da v8.1 —
  tratado em commit/escopo separado).

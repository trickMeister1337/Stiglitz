# Estado de Finding + Push para Trackers (DefectDojo) — Design

- **Data:** 2026-06-06
- **Roadmap:** P1 (próximo item após retire.js SCA, reachability/exploit-availability, fingerprint estável)
- **Chave estável:** `lib/fingerprint.py` (já existe) — `fingerprint(finding)` = sha1(classe_vuln, host, path-template, param)[:16]

## Problema

`stiglitz_diff.py` calcula NEW/FIXED/PERSISTENT **em tempo de diff**, comparando dois
scan dirs. Não há estado persistente: sem `first_seen`/`last_seen`, sem idade real de
finding, sem MTTR, sem burndown, sem SLA de verdade (a SLA atual é só o prazo CISA/KEV
derivado por finding, não o tempo decorrido aberto). Também não há push para o sistema
de gestão de vulnerabilidade (DefectDojo) nem ticketing.

Com o `fingerprint` estável já presente em cada finding do `findings.json`, dá para
manter um ledger de estado keyed por fingerprint e habilitar:
SLA real, retest tracking, burndown/MTTR e sincronização com DefectDojo.

## Escopo deste incremento

1. **Ledger de estado** (`lib/finding_state.py`) — lógica pura, persistente, cross-scan.
2. **Enriquecimento** do `findings.json` com `state` por finding + `raw/state_summary.json`.
3. **SARIF**: emitir `partialFingerprints` para dedup nativa no DefectDojo.
4. **Trackers** (`lib/trackers/`) — interface genérica + adapter DefectDojo, opt-in via env.
5. **Wiring**: fase P12 em `stiglitz.sh` + runner standalone `stiglitz_track.py`.

### Fora de escopo (YAGNI / follow-up)
- Adapters Jira / ServiceNow (reusarão `trackers/base.Tracker`).
- Burndown chart renderizado no HTML (só os dados são produzidos agora).
- Webhook bidirecional / sync de estado de volta do DefectDojo.

## Componentes

### 1. `lib/finding_state.py` — ledger de estado (puro, sem rede)

Datas injetadas (`today` como `datetime.date`) para testabilidade.

**Store:** `STIGLITZ_STATE_DIR` (default `~/.stiglitz/state/`). Um JSON por target:
`<target>.json`. Fora do repo → zero risco de versionar dado CDE (alinhado à diretriz
"nada de alvo CDE no GitHub"). Diretório criado com `exist_ok=True`; arquivo ausente
= primeiro scan (store vazio).

**Schema por entry (keyed por `fingerprint`):**
```json
{
  "fingerprint": "ab12...",
  "name": "...",
  "severity": "high",
  "url": "https://...",
  "first_seen": "2026-05-01",
  "last_seen":  "2026-06-06",
  "last_scan_id": "scan_...",
  "status": "open",          // open | resolved
  "resolved_at": null,        // ISO date quando resolvido
  "reopened_count": 0,
  "sla_due": "2026-05-15",    // de prioritization.sla_for_finding (se houver)
  "history": [                // append-only, auditável
    {"date": "2026-05-01", "event": "new",      "scan_id": "..."},
    {"date": "2026-06-06", "event": "persistent","scan_id": "..."}
  ]
}
```

**API:**

- `load_store(target, state_dir=None) -> dict` — lê o JSON do target; `{}` se ausente.
- `save_store(target, store, state_dir=None) -> path` — grava atômico (tmp + replace).
- `reconcile(store, current_findings, today, scan_id) -> (new_store, transitions)`
  - `current_findings`: lista de findings (cada um com `fingerprint`). Findings sem
    fingerprint são ignorados pelo ledger (degrada sem erro; logado pelo caller).
  - Para cada fingerprint do scan atual:
    - **ausente no store** → entry novo, `status=open`, `first_seen=last_seen=today`,
      evento `new`.
    - **presente, status=open** → `last_seen=today`, evento `persistent`.
    - **presente, status=resolved** → `status=open`, `last_seen=today`,
      `resolved_at=None`, `reopened_count += 1`, evento `reopened`.
  - Para entries no store **ausentes no scan atual** e ainda `open` →
    `status=resolved`, `resolved_at=today`, evento `resolved`.
  - `transitions`: lista `{fingerprint, event, severity}` para o resumo PT-BR.
- `derive_metrics(store, today) -> dict` — `state_summary`:
  - por finding (anexado ao próprio entry no retorno enriquecido):
    `age_days` (today − first_seen), `mttr_days` (resolved_at − first_seen, se resolvido).
  - agregados: `open_total`, `open_by_severity`, `resolved_total`,
    `mttr_days_avg` (média sobre resolvidos), `sla_breached` (lista de fingerprints
    `open` com `age_days > prazo`), `oldest_open_days`.
- `attach_state(findings, store, today) -> findings` — anexa
  `f["state"] = {status, first_seen, last_seen, age_days, mttr_days, reopened_count,
  sla_breached}` a cada finding (in place / cópia rasa).

**SLA:** reusa `prioritization.sla_for_finding(finding, today)` (já existente) para o
prazo; `sla_breached = (status=="open") and (age_days > prazo)`.

### 2. Enriquecimento em `stiglitz_report.py`

Após montar `all_f` (com fingerprint já presente — feito na linha ~1021) e antes de
gravar `findings.json`:

1. `store = finding_state.load_store(TARGET)`
2. `store, transitions = finding_state.reconcile(store, all_f, today, scan_id)`
3. `summary = finding_state.derive_metrics(store, today)`
4. `finding_state.attach_state(all_f, store, today)` → `state` por finding no JSON.
5. `finding_state.save_store(TARGET, store)`
6. grava `raw/state_summary.json` (= `summary`).

Tolerante a falha (try/except como os demais blocos do report): se o ledger falhar,
o report não quebra. `scan_id` derivado do basename do `OUTDIR`.

### 3. SARIF — `lib/report/sarif.py`

No dict de cada `result`, adicionar:
```python
"partialFingerprints": {"stiglitzFingerprint/v1": f.get("fingerprint", "")}
```
(omitir/usar string vazia se ausente). O parser SARIF do DefectDojo mapeia
`partialFingerprints` → `unique_id_from_tool`, habilitando dedup/reopen/mitigate
nativos pelo nosso fingerprint estável.

### 4. `lib/trackers/` — push opt-in

**`base.py`:**
```python
class Tracker:
    def enabled(self) -> bool: ...
    def sync(self, scan_dir, findings, state_summary) -> dict: ...
    # retorno: {"tracker": name, "created": int, "updated": int,
    #           "reopened": int, "errors": [str]}
```
Transport HTTP injetável: `__init__(self, session=None)`, `self.session =
session or requests.Session()` → testes passam um fake sem rede.

**`defectdojo.py`:** `class DefectDojo(Tracker)`
- Env: `DEFECTDOJO_URL`, `DEFECTDOJO_TOKEN` (obrigatórios p/ `enabled()`),
  `DEFECTDOJO_PRODUCT`, `DEFECTDOJO_ENGAGEMENT` (default `Stiglitz`),
  `DEFECTDOJO_VERIFY_SSL` (default `true`).
- `enabled()` = bool(URL) and bool(TOKEN).
- `sync()`:
  - `POST {URL}/api/v2/reimport-scan/`, header `Authorization: Token {TOKEN}`.
  - multipart: `scan_type=SARIF`, `file=@findings.sarif`,
    `product_name`, `engagement_name`, `auto_create_context=true`,
    `active=true`, `verified=false`, `close_old_findings=true`,
    `deduplication_on_engagement=true`.
  - parseia resposta JSON (`new_findings`/`reactivated`/`closed`/`untouched` quando
    presentes) → `{created, reopened, ...}`; erro HTTP/conexão → `errors[]`,
    nunca levanta para o caller.
  - `verify=` conforme `DEFECTDOJO_VERIFY_SSL`.
- Sem env → `enabled()=False`; runner pula silenciosamente (padrão `oob.py`).

### 5. Wiring

**`stiglitz_track.py <scan_dir | findings.json>`** (top-level, allowlisted no gitignore):
- Resolve scan_dir; carrega `findings.json` + `raw/state_summary.json`.
- Instancia trackers conhecidos (`DefectDojo`); para cada `enabled()`, chama `sync()`.
- Imprime resumo **PT-BR** (operador): habilitados, criados/reabertos/erros.
- Exit 0 mesmo sem tracker configurado (no-op informativo).

**Fase P12** em `stiglitz.sh` (após P11):
- Bloco `[P12] Tracker sync` que invoca `python3 stiglitz_track.py "$OUTDIR"`.
- Mensagens de console PT-BR. No-op silencioso quando nenhum env de tracker presente.
- Invocável via `--only-phase P12` (consistente com o padrão das demais fases).

## Testes (TDD — escrever teste, ver RED, depois GREEN)

Ordem de implementação:

1. **`tests/test_finding_state.py`**
   - reconcile NEW (store vazio → entry open, first_seen=today, evento new).
   - reconcile PERSISTENT (last_seen avança, first_seen preservado).
   - reconcile RESOLVED (fingerprint some → status resolved, resolved_at).
   - reconcile REOPENED (resolved reaparece → open, reopened_count++).
   - findings sem fingerprint são ignorados.
   - derive_metrics: age_days, mttr_days, mttr_avg, open_by_severity, sla_breached.
   - load/save round-trip (store_dir temporário; sem tocar ~/.stiglitz real).

2. **`tests/test_sarif_fingerprint.py`**
   - `build_sarif` → cada result tem `partialFingerprints["stiglitzFingerprint/v1"]`
     == `fingerprint` do finding de origem.

3. **`tests/test_trackers_defectdojo.py`**
   - `enabled()`: False sem env; True com URL+TOKEN (monkeypatch env).
   - `sync()`: monta multipart correto (campos esperados, scan_type=SARIF) usando
     `session` fake que captura o request e devolve resposta canned; parse de
     created/reopened. Erro de transporte → `errors[]`, sem exceção. **Sem rede.**

4. **Validação ao vivo** (caminho crítico):
   - `stiglitz_track.py` contra um `findings.json` sintético, com `DefectDojo`
     recebendo um `requests.Session` apontando para um `http.server` local que captura
     e valida o request (multipart + headers). Sobe serviço real só se necessário;
     caso contrário, transport injetável cobre.

## Validação (gates do projeto)

- `python3 -m pytest tests/ -q` (antes e depois — suite limpa).
- `bash -n stiglitz.sh` + `shellcheck --severity=warning stiglitz.sh stiglitz_track.py`
  (este último é Python; shellcheck só nos .sh tocados).
- `python3 -m py_compile stiglitz_report.py stiglitz_track.py lib/finding_state.py
  lib/report/sarif.py lib/trackers/*.py`.

## Disciplina de commits (pequenos, verde a cada passo)

1. `lib/finding_state.py` + testes (ledger puro).
2. SARIF `partialFingerprints` + teste.
3. Enriquecimento em `stiglitz_report.py` (wire do ledger no report).
4. `lib/trackers/base.py` + `defectdojo.py` + testes.
5. `stiglitz_track.py` runner + validação ao vivo.
6. Fase P12 em `stiglitz.sh`.

## Pendência operacional (pré-push, sob autorização)

Antes de qualquer push: shred seguro de `scan_pos.example.com_20260606_144522/` +
`scan_pos_full.log` (dados CDE de cliente da validação). Só executar quando o usuário
autorizar explicitamente.

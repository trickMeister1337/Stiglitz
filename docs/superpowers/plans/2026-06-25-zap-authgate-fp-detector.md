# Detector de FP JWT-gate (ZAP active-scan) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Mover alertas ZAP active-scan que são falsos positivos de "JWT-gate" (a requisição de ataque recebeu 401/403 antes da query) para uma seção "Deferred — Requires Authenticated Retest", fora das contagens de severidade.

**Architecture:** Espelha `lib/tls_confirm.py` — lógica pura + runner injetável. Fase 9 enriquece `zap_alerts.json` com `attack_status` (resolvido via API do ZAP); Fase 11 particiona os FPs por `is_authgated_fp` ANTES de entrarem no pipeline de score, renderiza a seção deferred e adiciona `deferred_findings` ao `findings.json`. Fail-safe: na dúvida, não esconde.

**Tech Stack:** Python 3 (stdlib), bash/curl (ZAP API localhost), pytest.

## Global Constraints

- Lógica em `lib/zap_authgate.py` é PURA (sem rede); o fetch da Fase 9 é injetável.
- Fail-safe: `attack_status` ausente/desconhecido ou ∉ {401,403} → NÃO defere.
- Só alertas active-scan (campo `attack` não-vazio) podem ser deferidos; passivos nunca.
- A partição acontece ANTES de criticidade/contagens — NÃO tocar `criticality.py`/`prioritization.py`.
- A seção deferred é aditiva e não-destrutiva (o achado nunca some, só muda de lugar).
- Texto de relatório em inglês; mensagens de console em PT-BR.
- Degradação silenciosa: falha da API do ZAP na Fase 9 → `attack_status` ausente, fase não aborta.
- Sem nomes de cliente/tokens em código, testes ou docs (varrer antes de push).

---

### Task 1: `lib/zap_authgate.py` (lógica pura + enrich injetável)

**Files:**
- Create: `lib/zap_authgate.py`
- Test: `tests/test_zap_authgate.py`

**Interfaces:**
- Produces:
  - `extract_status(response_header: str) -> int | None`
  - `needs_status(alert: dict) -> bool`
  - `enrich(alerts: list[dict], fetch_fn) -> list[dict]` — `fetch_fn(message_id) -> response_header_str | None`; muta `alerts` in place (seta `attack_status`), dedup por `messageId`.
  - `is_authgated_fp(alert: dict) -> bool` — usado inline pelo loop de ingestão ZAP (Task 3).

- [ ] **Step 1: Escrever os testes falhando**

Criar `tests/test_zap_authgate.py`:

```python
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
import zap_authgate as Z


def test_extract_status_parses_first_line():
    assert Z.extract_status("HTTP/1.1 401 Unauthorized\r\nServer: x\r\n") == 401
    assert Z.extract_status("HTTP/2 403 Forbidden\n") == 403
    assert Z.extract_status("HTTP/1.1 200 OK\r\n") == 200


def test_extract_status_handles_garbage_and_empty():
    assert Z.extract_status("") is None
    assert Z.extract_status("not an http response") is None
    assert Z.extract_status(None) is None


def test_needs_status_only_for_active_scan_without_status():
    assert Z.needs_status({"attack": "1 OR 1=1", "messageId": "5"}) is True
    assert Z.needs_status({"attack": "", "messageId": "5"}) is False          # passivo
    assert Z.needs_status({"attack": "x", "attack_status": 401}) is False     # já tem


def test_is_authgated_fp_matrix():
    assert Z.is_authgated_fp({"attack": "1 OR 1=1", "attack_status": 401}) is True
    assert Z.is_authgated_fp({"attack": "1 OR 1=1", "attack_status": 403}) is True
    assert Z.is_authgated_fp({"attack": "1 OR 1=1", "attack_status": 200}) is False
    assert Z.is_authgated_fp({"attack": "1 OR 1=1", "attack_status": 500}) is False
    assert Z.is_authgated_fp({"attack": "1 OR 1=1"}) is False                  # status ausente
    assert Z.is_authgated_fp({"attack": "", "attack_status": 401}) is False    # passivo + 401


def test_enrich_populates_status_and_dedups_by_message_id():
    calls = []
    def fetch(mid):
        calls.append(mid)
        return "HTTP/1.1 401 Unauthorized\r\n"
    alerts = [
        {"attack": "a", "messageId": "7"},
        {"attack": "b", "messageId": "7"},   # mesmo messageId -> não refetch
        {"attack": "", "messageId": "9"},    # passivo -> ignorado
    ]
    Z.enrich(alerts, fetch)
    assert alerts[0]["attack_status"] == 401
    assert alerts[1]["attack_status"] == 401   # reusa o status do messageId 7
    assert "attack_status" not in alerts[2]    # passivo não recebe
    assert calls == ["7"]                       # uma única chamada (dedup)


def test_enrich_tolerates_fetch_failure():
    def fetch(mid):
        raise RuntimeError("zap down")
    alerts = [{"attack": "a", "messageId": "7"}]
    Z.enrich(alerts, fetch)
    assert "attack_status" not in alerts[0]    # falha -> status ausente (fail-safe)
```

- [ ] **Step 2: Rodar e ver falhar**

Run: `cd /home/trick/Stiglitz && python3 -m pytest tests/test_zap_authgate.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'zap_authgate'`

- [ ] **Step 3: Implementar `lib/zap_authgate.py`**

```python
#!/usr/bin/env python3
"""zap_authgate.py — detector de FP "JWT-gate" para alertas ZAP active-scan.

Quando o ZAP roda DESLOGADO contra uma API auth-gated, a requisição de ataque
recebe 401/403 ANTES de qualquer processamento; o heurístico active-scan compara
dois 401 idênticos e reporta um falso positivo (SQLi/XSS/etc.). Aqui detectamos
esses casos pelo status HTTP que a PRÓPRIA requisição de ataque recebeu
(capturado na Fase 9) e os separamos para uma seção "deferred / requires
authenticated retest" — fora das contagens de severidade.

Auto-ajuste: se o scan fosse autenticado, o ataque receberia 200 (não 401) e o
finding NÃO seria deferido — sem checagem separada de "tinha token?".

Padrão do projeto: lógica pura + runner injetável (testável sem rede) + CLI.
"""
import json
import re
import sys
import urllib.request

_STATUS_RE = re.compile(r"^HTTP/[0-9.]+\s+(\d{3})\b")
_GATE_STATUSES = (401, 403)


def extract_status(response_header):
    """Status HTTP da 1ª linha do response header do ZAP, ou None."""
    if not response_header:
        return None
    m = _STATUS_RE.match(str(response_header).lstrip())
    return int(m.group(1)) if m else None


def needs_status(alert):
    """True se o alerta é active-scan (tem `attack`) e ainda não tem attack_status."""
    return bool(alert.get("attack")) and "attack_status" not in alert


def enrich(alerts, fetch_fn):
    """Resolve attack_status para os alertas active-scan via fetch_fn(message_id)
    -> response_header_str. Dedup por messageId; falha do fetch -> status ausente.
    Muta `alerts` in place e retorna a lista."""
    cache = {}
    for a in alerts:
        if not needs_status(a):
            continue
        mid = a.get("messageId")
        if mid in (None, ""):
            continue
        if mid not in cache:
            try:
                cache[mid] = extract_status(fetch_fn(mid))
            except Exception:
                cache[mid] = None
        st = cache[mid]
        if st is not None:
            a["attack_status"] = st
    return alerts


def is_authgated_fp(alert):
    """True quando o alerta active-scan foi barrado pelo gate de auth:
    tem `attack` E attack_status ∈ {401,403}. Conservador: status ausente ou
    fora desse conjunto -> False (não esconde)."""
    return bool(alert.get("attack")) and alert.get("attack_status") in _GATE_STATUSES


def _fetch_message_header(base_url):
    """fetch_fn real: GET core/view/message/?id=<mid> no ZAP (localhost) ->
    responseHeader. Sem proxy (controle ZAP é sempre direto)."""
    def fetch(mid):
        u = f"{base_url}/JSON/core/view/message/?id={mid}"
        with urllib.request.urlopen(u, timeout=10) as r:
            data = json.loads(r.read().decode("utf-8", "replace"))
        return (data.get("message") or {}).get("responseHeader", "")
    return fetch


def main(argv):
    # uso: zap_authgate.py enrich <zap_alerts.json> <zap_base_url>
    if len(argv) >= 3 and argv[0] == "enrich":
        path, base = argv[1], argv[2].rstrip("/")
        try:
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, ValueError):
            return 0  # degrada em silêncio
        alerts = data.get("alerts", []) if isinstance(data, dict) else []
        try:
            enrich(alerts, _fetch_message_header(base))
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(data, fh, ensure_ascii=False)
        except Exception:
            return 0  # nunca aborta a fase
        return 0
    print("uso: zap_authgate.py enrich <zap_alerts.json> <zap_base_url>", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
```

- [ ] **Step 4: Rodar e ver passar (+ suíte completa)**

Run: `cd /home/trick/Stiglitz && python3 -m pytest tests/test_zap_authgate.py -v && python3 -m pytest tests/ --ignore=tests/test_integration.py -q`
Expected: testes novos PASS; suíte completa sem regressão.

- [ ] **Step 5: Commit**

```bash
cd /home/trick/Stiglitz
git add lib/zap_authgate.py tests/test_zap_authgate.py
git commit -m "feat(zap): zap_authgate — detector de FP JWT-gate (lógica pura)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: Enriquecer `zap_alerts.json` com `attack_status` na Fase 9

**Files:**
- Modify: `stiglitz.sh` (após a coleta de alertas, ~linha 1995, antes da validação de output ~linha 2005)

**Interfaces:**
- Consumes: `lib/zap_authgate.py main("enrich", ...)` (Task 1); variáveis em escopo: `ZAP_HOST`, `ZAP_PORT`, `OUTDIR`, `SCRIPT_DIR`.
- Produces: `zap_alerts.json` com `attack_status` por alerta active-scan (consumido pela Task 3).

- [ ] **Step 1: Inserir a chamada de enriquecimento**

Em `stiglitz.sh`, logo após o bloco que grava `zap_evidencias.xml` (a linha
`curl -s "http://${ZAP_HOST}:${ZAP_PORT}/OTHER/core/other/xmlreport/" ... -o "$OUTDIR/raw/zap_evidencias.xml"`)
e ANTES do bloco `ALERT_COUNT=$(python3 ...)`, inserir:

```bash
        # Enriquece cada alerta active-scan com o status HTTP que a requisição de
        # ataque recebeu (resolve messageId via API do ZAP, com o daemon ainda vivo).
        # Permite a Fase 11 separar FPs de "JWT-gate" (ataque barrado por 401/403
        # antes da query). Degrada em silêncio se a API falhar. Ver lib/zap_authgate.py.
        if [ -s "$OUTDIR/raw/zap_alerts.json" ]; then
            python3 "$SCRIPT_DIR/lib/zap_authgate.py" enrich \
                "$OUTDIR/raw/zap_alerts.json" "http://${ZAP_HOST}:${ZAP_PORT}" \
                2>/dev/null || true
        fi
```

- [ ] **Step 2: Verificar sintaxe bash**

Run: `cd /home/trick/Stiglitz && bash -n stiglitz.sh && echo OK`
Expected: `OK`

- [ ] **Step 3: Teste de fumaça do runner enrich (sem ZAP, com fixture)**

Cria um `zap_alerts.json` de fixture e confirma que o runner não quebra quando a
API do ZAP não existe (degrada deixando o JSON intacto, sem attack_status):

```bash
cd /home/trick/Stiglitz
TMP="$(mktemp -d)"
printf '%s' '{"alerts":[{"name":"SQL Injection","attack":"1 OR 1=1","messageId":"3"},{"name":"X","attack":""}]}' > "$TMP/zap_alerts.json"
python3 lib/zap_authgate.py enrich "$TMP/zap_alerts.json" "http://127.0.0.1:0" 2>/dev/null; echo "rc=$?"
python3 -c "
import json
d=json.load(open('$TMP/zap_alerts.json'))
assert isinstance(d.get('alerts'),list) and len(d['alerts'])==2, 'json deve permanecer íntegro'
assert 'attack_status' not in d['alerts'][0], 'sem ZAP, status fica ausente (fail-safe)'
print('smoke OK: json íntegro, sem attack_status (degradação correta)')
"
rm -rf "$TMP"
```
Expected: `rc=0` e `smoke OK: ...` (degradação correta, JSON íntegro).

- [ ] **Step 4: Commit**

```bash
cd /home/trick/Stiglitz
git add stiglitz.sh
git commit -m "feat(zap): Fase 9 enriquece zap_alerts.json com attack_status

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: Particionar e renderizar a seção deferred (Fase 11)

**Files:**
- Modify: `stiglitz_report.py`
  - import de `zap_authgate` (junto dos outros imports de lib, topo do arquivo).
  - no loop de ingestão ZAP (~linha 318, logo após o `if conf in SKIP_CONFIDENCE: continue`): desviar os auth-gated FPs para `_deferred_authgated`.
  - inicializar `_deferred_authgated = []` antes do loop ZAP (~linha 314).
  - montar `deferred_section_html` após a seção OWASP (~linha 2313, perto de `owasp_section_html`).
  - injetar `{deferred_section_html}` no template (~linha 2435, após `{owasp_section_html}`).
  - adicionar `"deferred_findings": _deferred_authgated` ao `findings_out` (~linha 2573, antes de `"security_headers"`).
- Test: `tests/test_report_authgate_wiring.py` (novo)

**Interfaces:**
- Consumes: `zap_authgate.is_authgated_fp(alert)` (Task 1); `attack_status` no alerta cru (Task 2). No ponto de inserção do loop, a variável do alerta cru é `a` (dict do ZAP). `html`, `errors` em escopo.
- Produces: lista `_deferred_authgated`, seção HTML, bloco `deferred_findings` no JSON.

- [ ] **Step 1: Escrever o teste de wiring (falhando)**

`stiglitz_report.py` roda como script via env vars; testa-se regenerando de uma
fixture. Criar `tests/test_report_authgate_wiring.py`:

```python
import json, os, subprocess, sys, tempfile, shutil

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _run_report(tmp):
    env = dict(os.environ, OUTDIR=tmp, TARGET="https://t.example.com",
               DOMAIN="t.example.com", STIGLITZ_STATE_DIR=os.path.join(tmp, "state"))
    subprocess.run([sys.executable, os.path.join(ROOT, "stiglitz_report.py")],
                   env=env, cwd=ROOT, capture_output=True, timeout=120)


def _seed(tmp, alerts):
    raw = os.path.join(tmp, "raw"); os.makedirs(raw)
    with open(os.path.join(raw, "zap_alerts.json"), "w") as f:
        json.dump({"alerts": alerts}, f)


def test_authgated_sqli_deferred_not_in_counts():
    tmp = tempfile.mkdtemp()
    try:
        _seed(tmp, [
            {"name": "SQL Injection", "risk": "High", "confidence": "Medium",
             "url": "https://t.example.com/api/x", "param": "id",
             "attack": "1 OR 1=1 --", "attack_status": 401, "cweid": "89"},
        ])
        _run_report(tmp)
        out = json.load(open(os.path.join(tmp, "findings.json")))
        deferred = out.get("deferred_findings", [])
        assert any("SQL Injection" in (d.get("name", "")) for d in deferred), \
            "SQLi auth-gated deveria estar em deferred_findings"
        # não conta como severidade de topo
        names = [f.get("name", "") for f in
                 (out if isinstance(out, list) else out.get("findings", []))]
        assert not any("SQL Injection" in n for n in names), \
            "SQLi auth-gated não deveria aparecer nos findings principais"
        html = open(os.path.join(tmp, "stiglitz_report.html")).read()
        assert "Requires Authenticated Retest" in html
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_active_scan_with_200_status_is_kept():
    tmp = tempfile.mkdtemp()
    try:
        _seed(tmp, [
            {"name": "SQL Injection", "risk": "High", "confidence": "Medium",
             "url": "https://t.example.com/api/y", "param": "id",
             "attack": "1 OR 1=1 --", "attack_status": 200, "cweid": "89"},
        ])
        _run_report(tmp)
        out = json.load(open(os.path.join(tmp, "findings.json")))
        assert not out.get("deferred_findings"), \
            "status 200 não deve ser deferido"
        names = [f.get("name", "") for f in
                 (out if isinstance(out, list) else out.get("findings", []))]
        assert any("SQL Injection" in n for n in names), \
            "active-scan com 200 deve permanecer nos findings principais"
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
```

- [ ] **Step 2: Rodar e ver falhar**

Run: `cd /home/trick/Stiglitz && python3 -m pytest tests/test_report_authgate_wiring.py -v`
Expected: FAIL — `deferred_findings` ausente / SQLi ainda nos findings principais / seção ausente no HTML.

- [ ] **Step 3: Adicionar o import de `zap_authgate`**

No topo de `stiglitz_report.py`, junto aos outros `import` de módulos `lib/`
(onde estão `import finding_quality`, `import compliance_map as _comp_map`, etc.),
acrescentar:

```python
import zap_authgate as _zap_authgate
```

- [ ] **Step 4: Inicializar a lista e desviar os auth-gated no loop ZAP**

Antes do loop `for i,a in enumerate(zap_data.get("alerts",[])):` (~linha 314),
inicializar a lista:

```python
        _deferred_authgated = []
```

Dentro do loop, logo após o bloco:
```python
                conf = a.get("confidence","").lower()
                if conf in SKIP_CONFIDENCE:
                    continue
```
inserir o desvio:

```python
                # FP "JWT-gate": a requisição de ataque recebeu 401/403 antes da
                # query (scan deslogado em API auth-gated). Move p/ a seção deferred
                # — fora das contagens/criticidade. Fail-safe: status ausente não
                # defere. Ver lib/zap_authgate.py. (NÃO esconde: vira lead de retest.)
                if _zap_authgate.is_authgated_fp(a):
                    _deferred_authgated.append({
                        "name": a.get("name", "Alerta"),
                        "url": a.get("url", ""),
                        "param": a.get("param", "") or "",
                        "attack_status": a.get("attack_status"),
                        "confidence": a.get("confidence", ""),
                    })
                    continue
```

- [ ] **Step 5: Montar a seção HTML deferred**

Logo após o bloco que monta `owasp_section_html` (procure o fim dele, perto da
linha 2313 onde `owasp_section_html` é atribuído), inserir:

```python
# ── Deferred: alertas active-scan barrados por auth (JWT-gate) — retest logado ──
# Não são findings confirmados nem FPs limpos: a superfície não foi alcançada sem
# token. Agrupados por endpoint como lead para scan autenticado / code review.
deferred_section_html = ""
if _deferred_authgated:
    _drows = ""
    for d in _deferred_authgated:
        _drows += (f"<tr><td>{html.escape(d['name'])}</td>"
                   f"<td>{html.escape(d.get('param') or '')}</td>"
                   f"<td>{html.escape(str(d.get('attack_status') or ''))}</td>"
                   f"<td style='font-size:12px'>{html.escape(d.get('url') or '')}</td></tr>")
    deferred_section_html = (
        "<h2>Deferred — Requires Authenticated Retest</h2>"
        f"<p>{len(_deferred_authgated)} active-scan alert(s) whose attack request was "
        "rejected by authentication (HTTP 401/403) before the payload could run. "
        "Not confirmed and not cleared — the parameter must be retested with a valid "
        "token or reviewed in code.</p>"
        "<table><tr><th>Alert</th><th>Parameter</th><th>Attack status</th><th>URL</th></tr>"
        + _drows + "</table>")
```

- [ ] **Step 6: Injetar a seção no template HTML**

Na linha do template que contém `{owasp_section_html}` (~2435), acrescentar a seção
deferred logo após:

```python
{owasp_section_html}
{deferred_section_html}
```

- [ ] **Step 7: Adicionar `deferred_findings` ao findings.json**

No dict `findings_out`, imediatamente antes da entrada `"owasp_coverage": _owasp_posture,`
(~linha 2573), acrescentar:

```python
        "deferred_findings": _deferred_authgated,
        "owasp_coverage": _owasp_posture,
```

- [ ] **Step 8: Rodar os testes de wiring + suíte completa**

Run: `cd /home/trick/Stiglitz && python3 -m py_compile stiglitz_report.py && python3 -m pytest tests/test_report_authgate_wiring.py -v && python3 -m pytest tests/ --ignore=tests/test_integration.py -q`
Expected: wiring PASS; suíte completa sem regressão.

- [ ] **Step 9: Validação end-to-end com dados reais (partição demonstrada)**

Como scans antigos não têm `attack_status`, injeta-se 401 numa cópia do raw para
demonstrar a partição (mais recente que tenha SQLi do ZAP; ajuste `<SCAN>`):

```bash
cd /home/trick/Stiglitz
SRC="$(ls -dt ~/scans/*/scan_* 2>/dev/null | head -1)"; echo "fixture base: $SRC"
TMP="$(mktemp -d)"; cp -r "$SRC/raw" "$TMP/raw"
# injeta attack_status=401 nos alertas que têm attack (simula scan futuro)
python3 -c "
import json
p='$TMP/raw/zap_alerts.json'
d=json.load(open(p))
n=0
for a in d.get('alerts',[]):
    if a.get('attack'): a['attack_status']=401; n+=1
json.dump(d,open(p,'w'))
print(f'injetado attack_status=401 em {n} alerta(s) active-scan')
"
OUTDIR="$TMP" TARGET="https://t.example.com" DOMAIN="t.example.com" \
  STIGLITZ_STATE_DIR="$TMP/state" python3 stiglitz_report.py >/dev/null 2>&1
python3 -c "
import json
d=json.load(open('$TMP/findings.json'))
print('deferred_findings:', len(d.get('deferred_findings',[])))
for x in d.get('deferred_findings',[])[:5]: print('  -', x.get('name'), x.get('param'), x.get('attack_status'))
"
grep -c "Requires Authenticated Retest" "$TMP/stiglitz_report.html"
rm -rf "$TMP"
```
Expected: `deferred_findings` > 0 quando o raw tem alertas active-scan; grep retorna `1`.

- [ ] **Step 10: Commit**

```bash
cd /home/trick/Stiglitz
git add stiglitz_report.py tests/test_report_authgate_wiring.py
git commit -m "feat(zap): seção Deferred (auth-gated retest) no relatório + findings.json

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Notas de validação final (após as 3 tasks)

- Suíte completa verde: `python3 -m pytest tests/ --ignore=tests/test_integration.py -q`.
- `bash -n stiglitz.sh` e `python3 -m py_compile stiglitz_report.py lib/zap_authgate.py` limpos.
- Confirmar aditividade: findings não-auth-gated mantêm severidade/ordenação iguais.
- Atualizar `CHANGELOG.md` (Unreleased) e a tabela de módulos do `CLAUDE.md` (linha `zap_authgate.py`) — commit de docs separado ou no commit da Task 3.
- Varrer nomes de cliente antes de qualquer push.

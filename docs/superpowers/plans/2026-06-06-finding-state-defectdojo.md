# Estado de Finding + Push DefectDojo — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ledger de estado persistente por fingerprint (SLA real, MTTR, retest) + push opt-in para DefectDojo via reimport-scan SARIF.

**Architecture:** `lib/finding_state.py` mantém um store JSON por target (fora do repo, em `STIGLITZ_STATE_DIR`), reconciliando findings por `fingerprint` (NEW/PERSISTENT/RESOLVED/REOPENED) com datas e métricas. `stiglitz_report.py` enriquece `findings.json` com `state` e grava `raw/state_summary.json`. O SARIF passa a emitir `partialFingerprints` para dedup nativa. `lib/trackers/` expõe interface genérica + adapter DefectDojo (opt-in via env, HTTP injetável). `stiglitz_track.py` é o runner standalone, também chamado pela fase P12 do `stiglitz.sh`.

**Tech Stack:** Python 3 (stdlib + `requests`), pytest, bash. Padrão de opt-in/degradação do `lib/oob.py`.

---

## Referências de assinaturas reais (do código atual)

- `prioritization.sla_for_finding(f, today, sla_days=None)` → dict `{due_date, days_remaining, overdue, source}`. `today` é `datetime.date`.
- `report.sarif.build_sarif(findings, target, tool_name="Stiglitz", info_uri=...)` → dict SARIF. Cada `result` é montado no loop `for f in findings`.
- Testes: `tests/test_*.py`, pytest plano (funções `def test_...`), `sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))`.
- `findings.json` gravado em `stiglitz_report.py:2324`; `all_f` já tem `fingerprint` (linha ~1021).

---

## Task 1: Ledger de estado — reconcile NEW

**Files:**
- Create: `lib/finding_state.py`
- Test: `tests/test_finding_state.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_finding_state.py
import os, sys, datetime, json, tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
import finding_state as S

D = datetime.date

def _f(fp, sev="high", name="X", url="http://t/a"):
    return {"fingerprint": fp, "severity": sev, "name": name, "url": url}

def test_reconcile_new_finding_creates_open_entry():
    store, trans = S.reconcile({}, [_f("aaa")], today=D(2026, 6, 1), scan_id="s1")
    e = store["aaa"]
    assert e["status"] == "open"
    assert e["first_seen"] == "2026-06-01"
    assert e["last_seen"] == "2026-06-01"
    assert e["reopened_count"] == 0
    assert e["resolved_at"] is None
    assert e["history"][-1]["event"] == "new"
    assert {"fingerprint": "aaa", "event": "new", "severity": "high"} in trans
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_finding_state.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'finding_state'`

- [ ] **Step 3: Write minimal implementation**

```python
# lib/finding_state.py
#!/usr/bin/env python3
"""
finding_state.py — ledger de estado de finding por fingerprint (P1).

Mantém um store JSON persistente (um por target) reconciliando os findings de
cada scan pela chave estável fingerprint (lib/fingerprint.py): NEW, PERSISTENT,
RESOLVED, REOPENED — com first_seen/last_seen/resolved_at e métricas (age, MTTR,
SLA breach). Habilita SLA real, retest tracking e burndown.

Store fora do repo (STIGLITZ_STATE_DIR, default ~/.stiglitz/state/) → nunca
versiona dado de alvo. Lógica pura: a data corrente é injetada (testabilidade).
"""
import os
import json
import datetime

try:
    import prioritization as _prio
except Exception:  # pragma: no cover - prioritization sempre presente em runtime
    _prio = None


def _entry(f, today_iso):
    return {
        "fingerprint": f.get("fingerprint"),
        "name": f.get("name", ""),
        "severity": f.get("severity", "info"),
        "url": f.get("url", ""),
        "first_seen": today_iso,
        "last_seen": today_iso,
        "last_scan_id": None,
        "status": "open",
        "resolved_at": None,
        "reopened_count": 0,
        "sla_due": None,
        "history": [],
    }


def reconcile(store, current_findings, today, scan_id):
    """Reconcilia o store com os findings do scan atual.

    Retorna (novo_store, transitions). transitions = lista de
    {fingerprint, event, severity}. Findings sem fingerprint são ignorados.
    """
    store = dict(store)
    today_iso = today.isoformat()
    transitions = []
    seen = set()

    for f in current_findings:
        fp = f.get("fingerprint")
        if not fp:
            continue
        seen.add(fp)
        e = store.get(fp)
        if e is None:
            e = _entry(f, today_iso)
            event = "new"
        elif e["status"] == "resolved":
            e["status"] = "open"
            e["resolved_at"] = None
            e["reopened_count"] += 1
            event = "reopened"
        else:
            event = "persistent"
        e["last_seen"] = today_iso
        e["last_scan_id"] = scan_id
        e["severity"] = f.get("severity", e.get("severity", "info"))
        e["history"].append({"date": today_iso, "event": event, "scan_id": scan_id})
        store[fp] = e
        transitions.append({"fingerprint": fp, "event": event,
                            "severity": e["severity"]})

    return store, transitions
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_finding_state.py -q`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add lib/finding_state.py tests/test_finding_state.py
git commit -m "feat(state): ledger de finding — reconcile NEW (P1)"
```

---

## Task 2: reconcile PERSISTENT / RESOLVED / REOPENED + sem fingerprint

**Files:**
- Modify: `lib/finding_state.py` (já completo p/ estes casos — Task valida e cobre)
- Test: `tests/test_finding_state.py`

- [ ] **Step 1: Write the failing tests**

```python
def test_reconcile_persistent_advances_last_seen_keeps_first():
    s1, _ = S.reconcile({}, [_f("aaa")], today=D(2026, 6, 1), scan_id="s1")
    s2, trans = S.reconcile(s1, [_f("aaa")], today=D(2026, 6, 5), scan_id="s2")
    assert s2["aaa"]["first_seen"] == "2026-06-01"
    assert s2["aaa"]["last_seen"] == "2026-06-05"
    assert s2["aaa"]["status"] == "open"
    assert trans[0]["event"] == "persistent"

def test_reconcile_missing_finding_becomes_resolved():
    s1, _ = S.reconcile({}, [_f("aaa")], today=D(2026, 6, 1), scan_id="s1")
    s2, trans = S.reconcile(s1, [], today=D(2026, 6, 10), scan_id="s2")
    assert s2["aaa"]["status"] == "resolved"
    assert s2["aaa"]["resolved_at"] == "2026-06-10"
    assert {"fingerprint": "aaa", "event": "resolved", "severity": "high"} in trans

def test_reconcile_resolved_reappears_reopens():
    s1, _ = S.reconcile({}, [_f("aaa")], today=D(2026, 6, 1), scan_id="s1")
    s2, _ = S.reconcile(s1, [], today=D(2026, 6, 10), scan_id="s2")
    s3, trans = S.reconcile(s2, [_f("aaa")], today=D(2026, 6, 20), scan_id="s3")
    assert s3["aaa"]["status"] == "open"
    assert s3["aaa"]["resolved_at"] is None
    assert s3["aaa"]["reopened_count"] == 1
    assert trans[0]["event"] == "reopened"

def test_reconcile_ignores_findings_without_fingerprint():
    store, trans = S.reconcile({}, [{"severity": "low", "name": "no-fp"}],
                               today=D(2026, 6, 1), scan_id="s1")
    assert store == {}
    assert trans == []
```

- [ ] **Step 2: Run tests to verify the new ones for RESOLVED fail**

Run: `python3 -m pytest tests/test_finding_state.py -q`
Expected: FAIL — `test_reconcile_missing_finding_becomes_resolved` falha (resolução de ausentes ainda não implementada). Os demais podem já passar.

- [ ] **Step 3: Add resolution of absent entries to `reconcile`**

Em `lib/finding_state.py`, antes do `return store, transitions`, inserir:

```python
    for fp, e in store.items():
        if fp not in seen and e["status"] == "open":
            e["status"] = "resolved"
            e["resolved_at"] = today_iso
            e["history"].append({"date": today_iso, "event": "resolved",
                                "scan_id": scan_id})
            transitions.append({"fingerprint": fp, "event": "resolved",
                                "severity": e.get("severity", "info")})
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m pytest tests/test_finding_state.py -q`
Expected: PASS (todos)

- [ ] **Step 5: Commit**

```bash
git add lib/finding_state.py tests/test_finding_state.py
git commit -m "feat(state): reconcile PERSISTENT/RESOLVED/REOPENED (P1)"
```

---

## Task 3: load/save store (persistência atômica)

**Files:**
- Modify: `lib/finding_state.py`
- Test: `tests/test_finding_state.py`

- [ ] **Step 1: Write the failing test**

```python
def test_load_save_roundtrip(tmp_path):
    d = str(tmp_path)
    store, _ = S.reconcile({}, [_f("aaa")], today=D(2026, 6, 1), scan_id="s1")
    p = S.save_store("ex.com", store, state_dir=d)
    assert os.path.exists(p)
    loaded = S.load_store("ex.com", state_dir=d)
    assert loaded["aaa"]["first_seen"] == "2026-06-01"

def test_load_missing_store_returns_empty(tmp_path):
    assert S.load_store("never.com", state_dir=str(tmp_path)) == {}

def test_save_sanitizes_target_into_filename(tmp_path):
    d = str(tmp_path)
    p = S.save_store("https://a.b.com/x", {}, state_dir=d)
    assert os.path.dirname(p) == d
    assert "/" not in os.path.basename(p).replace(".json", "")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_finding_state.py -q`
Expected: FAIL — `AttributeError: module 'finding_state' has no attribute 'save_store'`

- [ ] **Step 3: Implement load_store / save_store**

Adicionar a `lib/finding_state.py`:

```python
import re as _re


def _state_dir(state_dir=None):
    d = state_dir or os.environ.get("STIGLITZ_STATE_DIR") or \
        os.path.join(os.path.expanduser("~"), ".stiglitz", "state")
    os.makedirs(d, exist_ok=True)
    return d


def _slug(target):
    s = _re.sub(r"^https?://", "", str(target or "unknown"))
    s = _re.sub(r"[^A-Za-z0-9._-]", "_", s).strip("_")
    return s or "unknown"


def load_store(target, state_dir=None):
    p = os.path.join(_state_dir(state_dir), _slug(target) + ".json")
    if not os.path.exists(p):
        return {}
    try:
        with open(p, encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return {}


def save_store(target, store, state_dir=None):
    p = os.path.join(_state_dir(state_dir), _slug(target) + ".json")
    tmp = p + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(store, fh, ensure_ascii=False, indent=2)
    os.replace(tmp, p)
    return p
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_finding_state.py -q`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add lib/finding_state.py tests/test_finding_state.py
git commit -m "feat(state): load/save store atômico em STIGLITZ_STATE_DIR (P1)"
```

---

## Task 4: métricas (age, MTTR, SLA breach) + attach_state

**Files:**
- Modify: `lib/finding_state.py`
- Test: `tests/test_finding_state.py`

- [ ] **Step 1: Write the failing test**

```python
def test_derive_metrics_age_mttr_and_open_counts():
    s1, _ = S.reconcile({}, [_f("aaa", sev="high")], today=D(2026, 6, 1), scan_id="s1")
    # bbb aberto e depois resolvido em 4 dias (MTTR=4)
    s1, _ = S.reconcile(s1, [_f("aaa"), _f("bbb", sev="low")],
                        today=D(2026, 6, 1), scan_id="s1b")
    s2, _ = S.reconcile(s1, [_f("aaa")], today=D(2026, 6, 5), scan_id="s2")
    m = S.derive_metrics(s2, today=D(2026, 6, 10))
    assert m["open_total"] == 1
    assert m["open_by_severity"]["high"] == 1
    assert m["resolved_total"] == 1
    assert m["mttr_days_avg"] == 4.0       # bbb: 2026-06-05 - 2026-06-01
    assert m["oldest_open_days"] == 9      # aaa: 2026-06-10 - 2026-06-01

def test_attach_state_marks_sla_breach_for_overdue_open():
    # high SLA policy padrão; finding aberto há muito tempo → breach
    s1, _ = S.reconcile({}, [_f("aaa", sev="critical")],
                        today=D(2026, 1, 1), scan_id="s1")
    findings = [_f("aaa", sev="critical")]
    S.attach_state(findings, s1, today=D(2026, 6, 1))
    st = findings[0]["state"]
    assert st["status"] == "open"
    assert st["age_days"] == 151
    assert st["sla_breached"] is True
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_finding_state.py -q`
Expected: FAIL — `derive_metrics` / `attach_state` inexistentes.

- [ ] **Step 3: Implement derive_metrics / attach_state**

Adicionar a `lib/finding_state.py`:

```python
def _date(iso):
    return datetime.date.fromisoformat(iso) if iso else None


def _age_days(first_seen, today):
    d = _date(first_seen)
    return (today - d).days if d else None


def _sla_prazo(entry, today):
    """Prazo em dias via prioritization.sla_for_finding; fallback por severidade."""
    if _prio is not None:
        try:
            sla = _prio.sla_for_finding(
                {"severity": entry.get("severity", "info"), "in_kev": False}, today)
            return sla.get("days_remaining")
        except Exception:
            pass
    return {"critical": 15, "high": 30, "medium": 60, "low": 90}.get(
        entry.get("severity", "info"), 90)


def derive_metrics(store, today):
    open_by_sev = {}
    mttrs = []
    open_ages = []
    open_total = resolved_total = 0
    breached = []
    for fp, e in store.items():
        if e["status"] == "open":
            open_total += 1
            sev = e.get("severity", "info")
            open_by_sev[sev] = open_by_sev.get(sev, 0) + 1
            age = _age_days(e["first_seen"], today)
            if age is not None:
                open_ages.append(age)
                prazo = _sla_prazo(e, today)
                if prazo is not None and age > prazo:
                    breached.append(fp)
        else:
            resolved_total += 1
            f, r = _date(e["first_seen"]), _date(e.get("resolved_at"))
            if f and r:
                mttrs.append((r - f).days)
    return {
        "open_total": open_total,
        "open_by_severity": open_by_sev,
        "resolved_total": resolved_total,
        "mttr_days_avg": round(sum(mttrs) / len(mttrs), 1) if mttrs else None,
        "oldest_open_days": max(open_ages) if open_ages else 0,
        "sla_breached": breached,
    }


def attach_state(findings, store, today):
    for f in findings:
        e = store.get(f.get("fingerprint"))
        if not e:
            continue
        age = _age_days(e["first_seen"], today)
        mttr = None
        if e["status"] == "resolved":
            fd, rd = _date(e["first_seen"]), _date(e.get("resolved_at"))
            mttr = (rd - fd).days if fd and rd else None
        prazo = _sla_prazo(e, today)
        f["state"] = {
            "status": e["status"],
            "first_seen": e["first_seen"],
            "last_seen": e["last_seen"],
            "age_days": age,
            "mttr_days": mttr,
            "reopened_count": e["reopened_count"],
            "sla_breached": bool(e["status"] == "open" and age is not None
                                 and prazo is not None and age > prazo),
        }
    return findings
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_finding_state.py -q`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add lib/finding_state.py tests/test_finding_state.py
git commit -m "feat(state): métricas age/MTTR/SLA-breach + attach_state (P1)"
```

---

## Task 5: SARIF emite partialFingerprints

**Files:**
- Modify: `lib/report/sarif.py` (bloco `results.append({...})`, ~linha 85-99)
- Test: `tests/test_sarif_fingerprint.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_sarif_fingerprint.py
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
from report.sarif import build_sarif

def test_each_result_carries_fingerprint_as_partial_fingerprint():
    findings = [
        {"name": "SQLi", "severity": "high", "url": "http://t/a",
         "fingerprint": "deadbeef0001", "cve": ""},
        {"name": "XSS", "severity": "medium", "url": "http://t/b",
         "fingerprint": "deadbeef0002", "cve": ""},
    ]
    doc = build_sarif(findings, "http://t")
    results = doc["runs"][0]["results"]
    fps = [r["partialFingerprints"]["stiglitzFingerprint/v1"] for r in results]
    assert "deadbeef0001" in fps and "deadbeef0002" in fps
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_sarif_fingerprint.py -q`
Expected: FAIL — `KeyError: 'partialFingerprints'`

- [ ] **Step 3: Add partialFingerprints to each result**

Em `lib/report/sarif.py`, no dict passado a `results.append(...)`, após o bloco
`"properties": {...}` adicionar a chave:

```python
            "partialFingerprints": {
                "stiglitzFingerprint/v1": f.get("fingerprint", "")
            },
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_sarif_fingerprint.py -q`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add lib/report/sarif.py tests/test_sarif_fingerprint.py
git commit -m "feat(report): SARIF partialFingerprints p/ dedup nativa DefectDojo (P1)"
```

---

## Task 6: wire do ledger no stiglitz_report.py

**Files:**
- Modify: `stiglitz_report.py` (após o loop que anexa `fingerprint`/`sla` ~linha 1016-1022; antes de gravar `findings.json` ~linha 2324)
- Test: `tests/test_report_state_wiring.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_report_state_wiring.py
import os, sys, datetime
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
import finding_state as S

def test_report_helper_enriches_and_persists(tmp_path):
    """Helper apply_state: reconcile + attach + persist + summary, num único passo."""
    findings = [{"fingerprint": "aaa", "severity": "high", "name": "X",
                 "url": "http://t/a"}]
    summary = S.apply_state(findings, target="ex.com", scan_id="scan_x",
                            today=datetime.date(2026, 6, 1), state_dir=str(tmp_path))
    assert findings[0]["state"]["status"] == "open"
    assert summary["open_total"] == 1
    # store persistido
    assert S.load_store("ex.com", state_dir=str(tmp_path))["aaa"]["status"] == "open"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_report_state_wiring.py -q`
Expected: FAIL — `apply_state` inexistente.

- [ ] **Step 3: Add apply_state convenience to finding_state.py**

Adicionar a `lib/finding_state.py`:

```python
def apply_state(findings, target, scan_id, today=None, state_dir=None):
    """Fluxo completo p/ o report: load → reconcile → attach → save → metrics.

    Retorna o state_summary. Idempotente por (today, scan_id).
    """
    today = today or datetime.date.today()
    store = load_store(target, state_dir=state_dir)
    store, _trans = reconcile(store, findings, today, scan_id)
    attach_state(findings, store, today)
    save_store(target, store, state_dir=state_dir)
    return derive_metrics(store, today)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_report_state_wiring.py -q`
Expected: PASS

- [ ] **Step 5: Wire em stiglitz_report.py**

Logo após o bloco que anexa `sla`/`fingerprint` aos findings (perto da linha 1022),
adicionar (try/except tolerante, padrão dos demais blocos do arquivo):

```python
# (P1) Estado de finding por fingerprint: SLA real, MTTR, retest cross-scan.
try:
    import finding_state as _state
    _scan_id = os.path.basename(os.path.normpath(OUTDIR))
    _state_summary = _state.apply_state(all_f, TARGET, _scan_id)
    with open(os.path.join(OUTDIR, "raw", "state_summary.json"), "w",
              encoding="utf-8") as _sfh:
        json.dump(_state_summary, _sfh, ensure_ascii=False, indent=2)
    print(f"[✓] Finding state: {_state_summary['open_total']} open, "
          f"{_state_summary['resolved_total']} resolved")
except Exception as _e:
    print(f"[!] finding state: {_e}")
```

> Verificar antes que `import finding_state` resolve: `stiglitz_report.py` já faz
> `import fingerprint as _fp` (linha 988), logo `lib/` está no `sys.path`. Reusar o
> mesmo mecanismo; não adicionar novo path.

- [ ] **Step 6: Verify report still compiles and JSON gains `state`**

Run:
```bash
python3 -m py_compile stiglitz_report.py
python3 -m pytest tests/test_report_state_wiring.py tests/test_finding_state.py -q
```
Expected: compila; testes PASS.

- [ ] **Step 7: Commit**

```bash
git add stiglitz_report.py lib/finding_state.py tests/test_report_state_wiring.py
git commit -m "feat(report): wire ledger de estado no findings.json + state_summary (P1)"
```

---

## Task 7: interface Tracker + adapter DefectDojo

**Files:**
- Create: `lib/trackers/__init__.py`
- Create: `lib/trackers/base.py`
- Create: `lib/trackers/defectdojo.py`
- Test: `tests/test_trackers_defectdojo.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_trackers_defectdojo.py
import os, sys, io, json
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
import importlib

def _fresh_dd():
    import trackers.defectdojo as dd
    return importlib.reload(dd)

class _Resp:
    def __init__(self, status=201, payload=None):
        self.status_code = status
        self._p = payload or {}
        self.text = json.dumps(self._p)
    def json(self):
        return self._p

class _Session:
    """Captura o request e devolve resposta canned. Sem rede."""
    def __init__(self, resp):
        self.resp = resp
        self.calls = []
    def post(self, url, **kw):
        self.calls.append((url, kw))
        return self.resp

def test_enabled_requires_url_and_token(monkeypatch):
    monkeypatch.delenv("DEFECTDOJO_URL", raising=False)
    monkeypatch.delenv("DEFECTDOJO_TOKEN", raising=False)
    dd = _fresh_dd()
    assert dd.DefectDojo().enabled() is False
    monkeypatch.setenv("DEFECTDOJO_URL", "https://dd.local")
    monkeypatch.setenv("DEFECTDOJO_TOKEN", "tok")
    assert _fresh_dd().DefectDojo().enabled() is True

def test_sync_posts_reimport_with_sarif(monkeypatch, tmp_path):
    monkeypatch.setenv("DEFECTDOJO_URL", "https://dd.local")
    monkeypatch.setenv("DEFECTDOJO_TOKEN", "tok")
    monkeypatch.setenv("DEFECTDOJO_PRODUCT", "Acme")
    dd = _fresh_dd()
    sarif = tmp_path / "findings.sarif"
    sarif.write_text('{"runs":[]}')
    sess = _Session(_Resp(201, {"test": 7}))
    res = dd.DefectDojo(session=sess).sync(str(tmp_path), findings=[], state_summary={})
    url, kw = sess.calls[0]
    assert url == "https://dd.local/api/v2/reimport-scan/"
    assert kw["headers"]["Authorization"] == "Token tok"
    assert kw["data"]["scan_type"] == "SARIF"
    assert kw["data"]["product_name"] == "Acme"
    assert kw["data"]["auto_create_context") if False else kw["data"]["auto_create_context"] == "true"
    assert "file" in kw["files"]
    assert res["errors"] == []

def test_sync_records_transport_error(monkeypatch, tmp_path):
    monkeypatch.setenv("DEFECTDOJO_URL", "https://dd.local")
    monkeypatch.setenv("DEFECTDOJO_TOKEN", "tok")
    dd = _fresh_dd()
    (tmp_path / "findings.sarif").write_text("{}")
    class _Boom:
        def post(self, *a, **k):
            raise OSError("conn refused")
    res = dd.DefectDojo(session=_Boom()).sync(str(tmp_path), findings=[], state_summary={})
    assert res["errors"] and "conn refused" in res["errors"][0]
```

> Nota: corrigir a linha do teste com expressão estranha — usar simplesmente
> `assert kw["data"]["auto_create_context"] == "true"`. (Mantida intencionalmente
> simples no Step abaixo.)

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_trackers_defectdojo.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'trackers'`

- [ ] **Step 3: Implement base + defectdojo**

```python
# lib/trackers/__init__.py
"""Adapters de push para sistemas de gestão de vulnerabilidade / ticketing."""
```

```python
# lib/trackers/base.py
#!/usr/bin/env python3
"""Interface comum de tracker. Opt-in via env; degrada sem erro (padrão oob.py)."""


class Tracker:
    name = "tracker"

    def enabled(self):
        raise NotImplementedError

    def sync(self, scan_dir, findings, state_summary):
        """Sincroniza findings/estado com o sistema externo.

        Retorna {"tracker", "created", "updated", "reopened", "errors": [str]}.
        NUNCA levanta — erros vão para errors[].
        """
        raise NotImplementedError

    @staticmethod
    def _result(name, created=0, updated=0, reopened=0, errors=None):
        return {"tracker": name, "created": created, "updated": updated,
                "reopened": reopened, "errors": errors or []}
```

```python
# lib/trackers/defectdojo.py
#!/usr/bin/env python3
"""
defectdojo.py — push para DefectDojo via reimport-scan (SARIF).

Opt-in: requer DEFECTDOJO_URL + DEFECTDOJO_TOKEN. Usa o findings.sarif (que carrega
partialFingerprints = fingerprint estável); o DefectDojo deduplica/reabre/mitiga
nativamente por unique_id_from_tool. Sem env → enabled()=False (no-op).
"""
import os

try:
    import requests
except Exception:  # pragma: no cover
    requests = None

from .base import Tracker


class DefectDojo(Tracker):
    name = "defectdojo"

    def __init__(self, session=None):
        self.url = (os.environ.get("DEFECTDOJO_URL") or "").rstrip("/")
        self.token = os.environ.get("DEFECTDOJO_TOKEN") or ""
        self.product = os.environ.get("DEFECTDOJO_PRODUCT") or "Stiglitz"
        self.engagement = os.environ.get("DEFECTDOJO_ENGAGEMENT") or "Stiglitz"
        self.verify = (os.environ.get("DEFECTDOJO_VERIFY_SSL", "true").lower()
                       != "false")
        self.session = session or (requests.Session() if requests else None)

    def enabled(self):
        return bool(self.url and self.token)

    def sync(self, scan_dir, findings, state_summary):
        if not self.enabled():
            return self._result(self.name, errors=["not configured"])
        if self.session is None:
            return self._result(self.name, errors=["requests indisponível"])
        sarif = os.path.join(scan_dir, "findings.sarif")
        if not os.path.exists(sarif):
            return self._result(self.name, errors=[f"SARIF ausente: {sarif}"])
        data = {
            "scan_type": "SARIF",
            "product_name": self.product,
            "engagement_name": self.engagement,
            "auto_create_context": "true",
            "active": "true",
            "verified": "false",
            "close_old_findings": "true",
            "deduplication_on_engagement": "true",
        }
        try:
            with open(sarif, "rb") as fh:
                resp = self.session.post(
                    f"{self.url}/api/v2/reimport-scan/",
                    headers={"Authorization": f"Token {self.token}"},
                    data=data,
                    files={"file": ("findings.sarif", fh, "application/json")},
                    verify=self.verify,
                    timeout=60,
                )
        except Exception as e:
            return self._result(self.name, errors=[str(e)])
        if resp.status_code >= 400:
            return self._result(self.name,
                                errors=[f"HTTP {resp.status_code}: {resp.text[:200]}"])
        try:
            body = resp.json()
        except Exception:
            body = {}
        return self._result(
            self.name,
            created=len(body.get("new_findings", []) or []),
            reopened=len(body.get("reactivated_findings", []) or []),
            updated=len(body.get("untouched_findings", []) or []),
        )
```

- [ ] **Step 4: Fix the odd assert line and run tests**

Editar `tests/test_trackers_defectdojo.py`: trocar a linha
`assert kw["data"]["auto_create_context") if False else ...` por:
```python
    assert kw["data"]["auto_create_context"] == "true"
```
Run: `python3 -m pytest tests/test_trackers_defectdojo.py -q`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add lib/trackers/ tests/test_trackers_defectdojo.py
git commit -m "feat(trackers): interface Tracker + adapter DefectDojo (reimport SARIF, P1)"
```

---

## Task 8: runner standalone stiglitz_track.py + validação ao vivo

**Files:**
- Create: `stiglitz_track.py`
- Modify: `.gitignore` (allowlist do novo top-level script)
- Test: `tests/test_stiglitz_track.py`

- [ ] **Step 1: Write the failing test (validação ao vivo do request via httpd local)**

```python
# tests/test_stiglitz_track.py
import os, sys, json, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
sys.path.insert(0, os.path.dirname(os.path.join(os.path.dirname(__file__), "..")))
ROOT = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, ROOT)

CAPTURED = {}

class _H(BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        CAPTURED["path"] = self.path
        CAPTURED["auth"] = self.headers.get("Authorization")
        CAPTURED["body_has_sarif"] = b"findings.sarif" in self.rfile.read(n)
        self.send_response(201)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"new_findings": [1, 2]}).encode())
    def log_message(self, *a):
        pass

def test_run_trackers_posts_to_live_defectdojo(monkeypatch, tmp_path):
    srv = HTTPServer(("127.0.0.1", 0), _H)
    threading.Thread(target=srv.handle_request, daemon=True).start()
    port = srv.server_address[1]
    # scan dir sintético
    (tmp_path / "findings.json").write_text(json.dumps({"findings": []}))
    (tmp_path / "raw").mkdir()
    (tmp_path / "raw" / "state_summary.json").write_text("{}")
    (tmp_path / "findings.sarif").write_text('{"runs":[]}')
    monkeypatch.setenv("DEFECTDOJO_URL", f"http://127.0.0.1:{port}")
    monkeypatch.setenv("DEFECTDOJO_TOKEN", "tok")
    import importlib
    track = importlib.import_module("stiglitz_track")
    importlib.reload(track)
    results = track.run_trackers(str(tmp_path))
    assert CAPTURED["path"] == "/api/v2/reimport-scan/"
    assert CAPTURED["auth"] == "Token tok"
    assert CAPTURED["body_has_sarif"] is True
    assert results[0]["created"] == 2

def test_run_trackers_noop_without_env(monkeypatch, tmp_path):
    monkeypatch.delenv("DEFECTDOJO_URL", raising=False)
    monkeypatch.delenv("DEFECTDOJO_TOKEN", raising=False)
    (tmp_path / "findings.json").write_text(json.dumps({"findings": []}))
    import importlib
    track = importlib.reload(importlib.import_module("stiglitz_track"))
    assert track.run_trackers(str(tmp_path)) == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_stiglitz_track.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'stiglitz_track'`

- [ ] **Step 3: Implement stiglitz_track.py**

```python
#!/usr/bin/env python3
"""
stiglitz_track.py — push de findings/estado para trackers (opt-in).

Resolve um scan dir (ou findings.json), lê o state_summary e dispara os trackers
habilitados via env (hoje: DefectDojo). No-op informativo quando nenhum configurado.
Mensagens de console em PT-BR (operador); deliverable já saiu no scan.

Uso:
    python3 stiglitz_track.py <scan_dir|findings.json>
"""
import os
import sys
import json

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))

from trackers.defectdojo import DefectDojo

TRACKERS = [DefectDojo]


def _resolve_scan_dir(arg):
    if os.path.isdir(arg):
        return arg
    if os.path.isfile(arg) and arg.endswith(".json"):
        return os.path.dirname(os.path.abspath(arg)) or "."
    raise SystemExit(f"[!] caminho inválido: {arg}")


def _load_json(path, default):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return default


def run_trackers(scan_dir):
    fj = _load_json(os.path.join(scan_dir, "findings.json"), {})
    findings = fj.get("findings", []) if isinstance(fj, dict) else []
    summary = _load_json(os.path.join(scan_dir, "raw", "state_summary.json"), {})
    results = []
    for cls in TRACKERS:
        t = cls()
        if not t.enabled():
            continue
        res = t.sync(scan_dir, findings, summary)
        results.append(res)
    return results


def main(argv):
    if len(argv) < 2:
        print("uso: python3 stiglitz_track.py <scan_dir|findings.json>")
        return 2
    scan_dir = _resolve_scan_dir(argv[1])
    results = run_trackers(scan_dir)
    if not results:
        print("[○] Nenhum tracker configurado (defina DEFECTDOJO_URL/TOKEN p/ habilitar).")
        return 0
    for r in results:
        if r["errors"]:
            print(f"[!] {r['tracker']}: erros: {'; '.join(r['errors'])}")
        else:
            print(f"[✓] {r['tracker']}: {r['created']} criados, "
                  f"{r['reopened']} reabertos, {r['updated']} inalterados")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
```

- [ ] **Step 4: Allowlist no .gitignore**

Adicionar perto das outras linhas `!/stiglitz_*.py` (ex.: após `!/stiglitz_trend.py`):
```
!/stiglitz_track.py
```
Confirmar: `git check-ignore stiglitz_track.py` → sem saída (não ignorado).

- [ ] **Step 5: Run test to verify it passes**

Run: `python3 -m pytest tests/test_stiglitz_track.py -q`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add stiglitz_track.py .gitignore tests/test_stiglitz_track.py
git commit -m "feat(track): runner standalone stiglitz_track.py + validação ao vivo (P1)"
```

---

## Task 9: fase P12 no stiglitz.sh

**Files:**
- Modify: `stiglitz.sh` (após o bloco da fase P11; e no dispatch de `--only-phase`)

- [ ] **Step 1: Localizar o fim da P11 e o dispatcher de fases**

Run:
```bash
grep -n "P11\|only.phase\|only_phase\|ONLY_PHASE\|run_phase" stiglitz.sh | head -30
```
Expected: identificar onde P11 termina e como as fases são selecionadas (variável de fases / case).

- [ ] **Step 2: Adicionar o bloco da fase P12**

Após o término da fase P11 (geração de relatório), inserir, seguindo o estilo dos
blocos de fase existentes (mensagens PT-BR, guard pela seleção de fase):

```bash
# ── Fase P12 — Tracker sync (DefectDojo) — opt-in ──
if should_run_phase "P12"; then
    echo -e "${BLUE}[P12]${NC} Sincronização com tracker (DefectDojo)..."
    if [[ -n "${DEFECTDOJO_URL:-}" && -n "${DEFECTDOJO_TOKEN:-}" ]]; then
        python3 "$SCRIPT_DIR/stiglitz_track.py" "$OUTDIR" || \
            echo -e "${YELLOW}[P12]${NC} push falhou (não-fatal)"
    else
        echo -e "${YELLOW}[P12]${NC} nenhum tracker configurado — pulando (defina DEFECTDOJO_URL/TOKEN)."
    fi
fi
```

> Ajustar `should_run_phase`, `${BLUE}`/`${NC}`/`${YELLOW}`, `$SCRIPT_DIR` e `$OUTDIR`
> aos nomes reais encontrados no Step 1. Se o seletor de fases for um `case`/lista,
> registrar `P12` lá também (como as demais fases).

- [ ] **Step 3: Validar sintaxe e lint**

Run:
```bash
bash -n stiglitz.sh
shellcheck --severity=warning stiglitz.sh
```
Expected: sem erros; shellcheck limpo.

- [ ] **Step 4: Smoke da seleção de fase**

Run:
```bash
DEFECTDOJO_URL= DEFECTDOJO_TOKEN= bash stiglitz.sh example.com --only-phase P12 --dry-run 2>&1 | grep -i "P12" || true
```
Expected: a P12 é reconhecida e reporta "nenhum tracker configurado" (ou equivalente do dry-run), sem erro.

- [ ] **Step 5: Commit**

```bash
git add stiglitz.sh
git commit -m "feat(scan): fase P12 — tracker sync opt-in (DefectDojo) (P1)"
```

---

## Task 10: validação final + docs

**Files:**
- Modify: `CLAUDE.md` (registrar P12 + stiglitz_track.py + finding_state)

- [ ] **Step 1: Suite completa verde**

Run: `python3 -m pytest tests/ -q`
Expected: PASS (sem regressões).

- [ ] **Step 2: Compilar módulos tocados**

Run:
```bash
python3 -m py_compile stiglitz_report.py stiglitz_track.py \
  lib/finding_state.py lib/report/sarif.py lib/trackers/base.py lib/trackers/defectdojo.py
```
Expected: sem saída (ok).

- [ ] **Step 3: Atualizar CLAUDE.md**

- Acrescentar a fase **P12 — Tracker sync** na lista de fases do `stiglitz.sh`.
- Acrescentar `stiglitz_track.py` na seção de scripts (runner de push opt-in).
- Acrescentar `finding_state.py` e `trackers/` na tabela de módulos `lib/`.
- Documentar env vars: `STIGLITZ_STATE_DIR`, `DEFECTDOJO_URL/TOKEN/PRODUCT/ENGAGEMENT/VERIFY_SSL`.

- [ ] **Step 4: Commit**

```bash
git add CLAUDE.md
git commit -m "docs: P12 tracker sync, stiglitz_track.py, finding_state/trackers (P1)"
```

---

## Self-review (preenchido pelo autor do plano)

- **Cobertura do spec:** ledger (T1-T4), SARIF partialFingerprints (T5), enriquecimento report (T6), trackers base+DefectDojo (T7), runner+validação ao vivo (T8), fase P12 (T9), docs+suite (T10). ✓ todos os itens do spec mapeados.
- **Placeholders:** nenhum "TODO/TBD"; todo passo de código tem o código. A única ressalva intencional é a Task 7 Step 4 que corrige uma linha do próprio teste (mantida para o executor ver o erro e a correção).
- **Consistência de tipos:** `reconcile/derive_metrics/attach_state/apply_state/load_store/save_store` usados com as mesmas assinaturas em T1-T6; `Tracker.sync/enabled` e retorno `{tracker,created,updated,reopened,errors}` consistentes em T7-T8; `run_trackers(scan_dir)` idem em T8-T9.

## Pendência operacional (pré-push)

Antes de QUALQUER `git push`: shred seguro de `scan_pos.bee2pay.com_20260606_144522/`
+ `scan_pos_full.log` (dados CDE de cliente). Só sob autorização explícita do usuário.
Os commits deste plano são locais até então.

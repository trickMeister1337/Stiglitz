# OWASP Top 10 Coverage View Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Adicionar uma seção "OWASP Top 10 (2021) — Coverage" ao relatório (HTML + `findings.json`), separada da metodologia de criticidade, com veredito FOUND/TESTED/NOT-COVERED por categoria.

**Architecture:** Espelha o padrão `pci_posture` já existente em `lib/compliance_map.py`. Uma função pura nova (`owasp_posture`) consome os findings já pontuados (`all_f`) e o dict `_coverage` que o `stiglitz_report.py` já deriva de quais `raw/*.json` foram gerados. Puramente aditivo — não toca em severidade, ordenação nem SLA.

**Tech Stack:** Python 3 (stdlib + módulos `lib/` do Stiglitz), pytest.

## Global Constraints

- Texto da seção/relatório em **inglês** (deliverable); mensagens de console em PT-BR (convenção do repo).
- **Nenhuma** mudança em `criticality.py`/`prioritization.py`/`risk_*` — a feature não altera score/ordenação/SLA.
- Lógica em `compliance_map.py` é **pura** (sem rede, sem I/O) e testável.
- A seção OWASP é **sempre visível** (sem gate de CDE — diferente da seção PCI).
- Capability-keys reutilizadas do `_coverage` existente: `headers`, `services`, `cde`, `tls`, `webapp`, `components`, `authn`, `authz`, `logging`; acrescenta-se `retire`.
- Sem nomes de cliente/tokens em código, testes ou docs (varrer antes de commitar).

---

### Task 1: `owasp_posture` + constantes (backend puro)

**Files:**
- Modify: `lib/compliance_map.py` (acrescentar após `pci_posture`, fim do arquivo ~linha 146)
- Test: `tests/test_compliance_map.py` (acrescentar ao fim)

**Interfaces:**
- Consumes: `frameworks_for_cwe(cwe)` e `extract_cwe(finding)` (já existem em `compliance_map.py`).
- Produces:
  - `owasp_posture(findings, coverage=None) -> list[dict]` — sempre 10 itens, ordem A01→A10, cada item `{"category": str, "title": str, "verdict": str, "count": int, "top_findings": list[str], "note": str|None}`. `verdict` ∈ {"FOUND","TESTED","NOT-COVERED"}.
  - Constantes `_OWASP_CATEGORIES`, `_OWASP_COVERAGE`, `_OWASP_NOTES`.

- [ ] **Step 1: Escrever os testes falhando**

Acrescentar ao fim de `tests/test_compliance_map.py`:

```python
def test_owasp_posture_returns_all_ten_categories_ordered():
    out = C.owasp_posture([], {})
    assert [p["category"] for p in out] == [
        "A01:2021", "A02:2021", "A03:2021", "A04:2021", "A05:2021",
        "A06:2021", "A07:2021", "A08:2021", "A09:2021", "A10:2021"]
    # cada item tem o shape esperado
    assert all(set(p) == {"category", "title", "verdict", "count",
                          "top_findings", "note"} for p in out)


def test_owasp_posture_found_when_finding_maps_to_category():
    f = {"name": "SQL Injection", "cwe": "CWE-89"}  # CWE-89 -> A03
    out = {p["category"]: p for p in C.owasp_posture([f], {"webapp": True})}
    assert out["A03:2021"]["verdict"] == "FOUND"
    assert out["A03:2021"]["count"] == 1
    assert out["A03:2021"]["top_findings"] == ["SQL Injection"]


def test_owasp_posture_tested_when_capability_active_and_no_finding():
    out = {p["category"]: p for p in C.owasp_posture([], {"webapp": True})}
    assert out["A03:2021"]["verdict"] == "TESTED"
    assert out["A03:2021"]["count"] == 0
    assert out["A03:2021"]["top_findings"] == []


def test_owasp_posture_not_covered_when_capability_inactive():
    out = {p["category"]: p for p in C.owasp_posture([], {})}
    assert out["A03:2021"]["verdict"] == "NOT-COVERED"


def test_owasp_posture_a04_a08_a09_not_covered_by_design_with_note():
    full = {"webapp": True, "authz": True, "tls": True, "headers": True,
            "components": True, "retire": True, "authn": True}
    out = {p["category"]: p for p in C.owasp_posture([], full)}
    for cat in ("A04:2021", "A08:2021", "A09:2021"):
        assert out[cat]["verdict"] == "NOT-COVERED", cat
        assert out[cat]["note"], f"{cat} deveria ter nota textual"


def test_owasp_posture_finding_overrides_not_covered_by_design():
    # CWE-502 (insecure deserialization) -> A08, que é NOT-COVERED por design;
    # havendo finding, count>0 vence e vira FOUND.
    f = {"name": "Insecure deserialization", "cwe": "CWE-502"}
    out = {p["category"]: p for p in C.owasp_posture([f], {})}
    assert out["A08:2021"]["verdict"] == "FOUND"
    assert out["A08:2021"]["count"] == 1


def test_owasp_posture_a06_tested_via_retire_capability():
    # A06 é coberto por 'components' OU 'retire'; só retire ativo já dá TESTED.
    out = {p["category"]: p for p in C.owasp_posture([], {"retire": True})}
    assert out["A06:2021"]["verdict"] == "TESTED"


def test_owasp_posture_ignores_findings_without_cwe():
    out_empty = C.owasp_posture([{"name": "no cwe here"}], {})
    assert all(p["count"] == 0 for p in out_empty)
```

- [ ] **Step 2: Rodar os testes e verificar que falham**

Run: `cd /home/trick/Stiglitz && python3 -m pytest tests/test_compliance_map.py -k owasp -v`
Expected: FAIL — `AttributeError: module 'compliance_map' has no attribute 'owasp_posture'`

- [ ] **Step 3: Implementar as constantes e a função**

Acrescentar ao fim de `lib/compliance_map.py`:

```python
# ── OWASP Top 10 (2021) coverage — espelha o padrão pci_posture ──────────
# Lista canônica (ordem oficial A01→A10) + título.
_OWASP_CATEGORIES = [
    ("A01:2021", "Broken Access Control"),
    ("A02:2021", "Cryptographic Failures"),
    ("A03:2021", "Injection"),
    ("A04:2021", "Insecure Design"),
    ("A05:2021", "Security Misconfiguration"),
    ("A06:2021", "Vulnerable and Outdated Components"),
    ("A07:2021", "Identification and Authentication Failures"),
    ("A08:2021", "Software and Data Integrity Failures"),
    ("A09:2021", "Security Logging and Monitoring Failures"),
    ("A10:2021", "Server-Side Request Forgery"),
]

# categoria → capability-keys do _coverage; TESTED se QUALQUER uma rodou.
# Lista vazia = NOT-COVERED por design (scan automatizado não exercita).
_OWASP_COVERAGE = {
    "A01:2021": ["webapp", "authz"],
    "A02:2021": ["tls"],
    "A03:2021": ["webapp"],
    "A04:2021": [],
    "A05:2021": ["headers", "webapp"],
    "A06:2021": ["components", "retire"],
    "A07:2021": ["authn", "webapp"],
    "A08:2021": [],
    "A09:2021": [],
    "A10:2021": ["webapp"],
}

# nota textual fixa para categorias parcial/manualmente cobertas.
_OWASP_NOTES = {
    "A04:2021": "Design-level — requires manual review; not exercised by automated DAST.",
    "A08:2021": "Insecure deserialization (CWE-502) is covered; CI/CD & SRI integrity require manual review.",
    "A09:2021": "Not exercised by DAST — requires log/monitoring configuration review.",
}


def _owasp_category(finding):
    """Prefixo 'A0N:2021' da categoria OWASP do finding, ou None.

    _MAP guarda a string completa ('A03:2021-Injection'); casamos pelo prefixo
    antes do '-' para bater com _OWASP_CATEGORIES.
    """
    owasp = frameworks_for_cwe(extract_cwe(finding)).get("owasp", "")
    return owasp.split("-", 1)[0] if owasp else None


def owasp_posture(findings, coverage=None):
    """Veredito de cobertura por categoria OWASP Top 10 2021.

    FOUND:       >=1 finding mapeado à categoria (count>0 sempre vence).
    TESTED:      sem finding e alguma capability da categoria ativa em `coverage`.
    NOT-COVERED: categoria sem capability automatizada (A04/A08/A09) ou nenhuma
                 capability ativa neste scan (default conservador — nunca afirma
                 cobertura falsa).

    Retorna SEMPRE as 10 categorias (ordem A01→A10), cada uma:
    {category, title, verdict, count, top_findings, note}. Puro — sem rede.
    """
    coverage = coverage or {}
    counts, tops = {}, {}
    for f in findings:
        cat = _owasp_category(f)
        if not cat:
            continue
        counts[cat] = counts.get(cat, 0) + 1
        bucket = tops.setdefault(cat, [])
        name = f.get("name")
        if name and len(bucket) < 3:
            bucket.append(name)
    out = []
    for cat, title in _OWASP_CATEGORIES:
        n = counts.get(cat, 0)
        if n > 0:
            verdict = "FOUND"
        elif any(coverage.get(c) for c in _OWASP_COVERAGE.get(cat, [])):
            verdict = "TESTED"
        else:
            verdict = "NOT-COVERED"
        out.append({"category": cat, "title": title, "verdict": verdict,
                    "count": n,
                    "top_findings": tops.get(cat, []) if n > 0 else [],
                    "note": _OWASP_NOTES.get(cat)})
    return out
```

- [ ] **Step 4: Rodar os testes e verificar que passam**

Run: `cd /home/trick/Stiglitz && python3 -m pytest tests/test_compliance_map.py -v && python3 -m pytest tests/ --ignore=tests/test_integration.py -q`
Expected: todos PASS (os novos `owasp` + suíte completa sem regressão).

- [ ] **Step 5: Commit**

```bash
cd /home/trick/Stiglitz
git add lib/compliance_map.py tests/test_compliance_map.py
git commit -m "feat(owasp): owasp_posture — cobertura por categoria Top 10 (backend puro)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: Wiring no relatório (HTML + findings.json)

**Files:**
- Modify: `stiglitz_report.py`
  - `_coverage` dict (~linha 2279): acrescentar sinal `retire`.
  - Após a seção PCI (~linha 2313, após `+ _rows + "</table>")`): computar `_owasp_posture` e montar `owasp_section_html`.
  - Template HTML (~linha 2398, após `{compliance_section_html}`): injetar `{owasp_section_html}`.
  - `findings_out` (~linha 2537, antes de `"security_headers": ...`): acrescentar `"owasp_coverage": _owasp_posture`.

**Interfaces:**
- Consumes: `_comp_map.owasp_posture(all_f, _coverage)` (Task 1); variáveis já em escopo no ponto de inserção: `all_f`, `_coverage`, `_comp_map`, `html`, `errors`, `findings_out`.
- Produces: seção HTML `<h2>OWASP Top 10 (2021) — Coverage</h2>` no relatório; campo top-level `owasp_coverage` (lista de 10) no `findings.json`.

- [ ] **Step 1: Acrescentar o sinal `retire` ao `_coverage`**

Em `stiglitz_report.py`, no dict `_coverage` (a linha `"components": _raw_has("nuclei.json"),`), acrescentar logo abaixo:

```python
    "components": _raw_has("nuclei.json"),
    "retire":     _raw_has("retire_findings.json"),
```

- [ ] **Step 2: Computar `_owasp_posture` e montar a seção HTML**

Logo após o fim da montagem da seção PCI (a linha `        + _rows + "</table>")` que fecha `compliance_section_html`), inserir:

```python
# ── OWASP Top 10 (2021) Coverage — sempre visível (sem gate de CDE) ──
# Apresentação separada da metodologia de criticidade: reagrupa os findings já
# pontuados por categoria OWASP; NÃO altera severidade/ordenação/SLA.
try:
    _owasp_posture = _comp_map.owasp_posture(all_f, _coverage)
except Exception as _owasp_e:
    _owasp_posture = []
    errors.append(f"owasp_posture: {_owasp_e}")
owasp_section_html = ""
if _owasp_posture:
    _ocolor = {"FOUND": "#c0392b", "TESTED": "#27ae60", "NOT-COVERED": "#888"}
    _ofound = sum(1 for p in _owasp_posture if p["verdict"] == "FOUND")
    _otested = sum(1 for p in _owasp_posture if p["verdict"] == "TESTED")
    _onc = sum(1 for p in _owasp_posture if p["verdict"] == "NOT-COVERED")
    _osummary = (f"OWASP Top 10 (2021) — 10 categories assessed: "
                 f"{_ofound} FOUND, {_otested} TESTED, {_onc} NOT-COVERED.")
    _orows = ""
    for p in _owasp_posture:
        _detail = ("; ".join(p["top_findings"]) if p["verdict"] == "FOUND"
                   else (p.get("note") or ""))
        _orows += (f"<tr><td>{html.escape(p['category'])} — {html.escape(p['title'])}</td>"
                   f"<td><span style='color:{_ocolor[p['verdict']]};font-weight:bold'>"
                   f"{p['verdict']}</span></td>"
                   f"<td>{p['count'] or ''}</td>"
                   f"<td style='font-size:12px'>{html.escape(_detail)}</td></tr>")
    owasp_section_html = (
        "<h2>OWASP Top 10 (2021) — Coverage</h2>"
        f"<p>{html.escape(_osummary)}</p>"
        "<p style='font-size:12px;color:#666'>FOUND = finding mapped to category; "
        "TESTED = capability exercised, no finding; "
        "NOT-COVERED = not exercised by automated scan (manual review).</p>"
        "<table><tr><th>Category</th><th>Verdict</th><th>Findings</th>"
        "<th>Top findings / Note</th></tr>"
        + _orows + "</table>")
```

- [ ] **Step 3: Injetar a seção no template HTML**

No template HTML final, na linha que contém `{compliance_section_html}` (~2398), acrescentar a seção OWASP logo após:

```python
{compliance_section_html}
{owasp_section_html}
```

- [ ] **Step 4: Acrescentar `owasp_coverage` ao `findings.json`**

No dict `findings_out`, imediatamente antes da entrada `"security_headers": security_headers_data,`, acrescentar:

```python
        "owasp_coverage": _owasp_posture,
        "security_headers": security_headers_data,
```

- [ ] **Step 5: Validar regenerando o relatório de um scan real**

Usa o `raw/` de um scan existente como fixture (não faz scan novo). Substituir `<SCAN_DIR>` por um diretório de scan com `raw/` populado (ex.: o scan mais recente em `~/scans/`).

```bash
cd /home/trick/Stiglitz
python3 -m py_compile stiglitz_report.py && echo "compile OK"
SRC="$(ls -dt ~/scans/*/scan_* 2>/dev/null | head -1)"; echo "fixture: $SRC"
TMP="$(mktemp -d)"; cp -r "$SRC/raw" "$TMP/raw"
OUTDIR="$TMP" TARGET="https://example.com" DOMAIN="example.com" \
  STIGLITZ_STATE_DIR="$TMP/state" python3 stiglitz_report.py >/dev/null 2>&1
echo "-- HTML tem a seção? --"
grep -c "OWASP Top 10 (2021) — Coverage" "$TMP/stiglitz_report.html"
echo "-- findings.json tem owasp_coverage com 10 categorias? --"
python3 -c "
import json
d=json.load(open('$TMP/findings.json'))
oc=d.get('owasp_coverage')
assert isinstance(oc,list) and len(oc)==10, f'esperava 10, veio {oc and len(oc)}'
cats=[p['category'] for p in oc]
assert cats==['A01:2021','A02:2021','A03:2021','A04:2021','A05:2021','A06:2021','A07:2021','A08:2021','A09:2021','A10:2021'], cats
assert all(p['verdict'] in ('FOUND','TESTED','NOT-COVERED') for p in oc)
for cat in ('A04:2021','A08:2021','A09:2021'):
    p=[x for x in oc if x['category']==cat][0]
    assert p['verdict'] in ('FOUND','NOT-COVERED') and (p['verdict']=='FOUND' or p['note']), cat
print('owasp_coverage OK:', [(p[\"category\"],p[\"verdict\"]) for p in oc])
"
rm -rf "$TMP"
```
Expected: `grep` retorna `1`; o python imprime `owasp_coverage OK: [...]` sem AssertionError.

- [ ] **Step 6: Commit**

```bash
cd /home/trick/Stiglitz
git add stiglitz_report.py
git commit -m "feat(owasp): seção OWASP Top 10 Coverage no relatório (HTML + findings.json)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Notas de validação final (após as duas tasks)

- Rodar a suíte completa: `python3 -m pytest tests/ --ignore=tests/test_integration.py -q` (deve ficar verde).
- Confirmar que a feature é aditiva: o sumário de severidades e a ordenação do relatório **não mudam** vs. antes (a seção OWASP não toca em `criticality`/`prioritization`).
- Atualizar `CHANGELOG.md` (seção Unreleased) e a tabela de módulos do `CLAUDE.md` (entrada `compliance_map.py`) descrevendo o `owasp_posture` — incluir no commit da Task 2 ou num commit de docs separado.
- Varrer nomes de cliente antes de qualquer push (política do repo).

# Compliance Mapping só-PCI (PASS/FAIL/N-A) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Repaginar a seção "Compliance Mapping" do relatório para mostrar **só PCI DSS 4.0.1**, com veredito **PASS/FAIL/N-A** por requisito e um **resumo breve** dos achados.

**Architecture:** A lógica de veredito mora em `lib/compliance_map.py` como função pura `pci_posture(findings, coverage)` (testável isolada). O `stiglitz_report.py` deriva o dict `coverage` da presença de artefatos em `raw/` e troca o render multi-framework (linhas ~2213-2230) pela tabela só-PCI. A seção "PCI DSS CDE Coverage" (linhas ~2193-2211) permanece intacta.

**Tech Stack:** Python 3 stdlib (`re`, `os`, `html`), `pytest` (`tests/test_compliance_map.py`).

**Dependência:** independente do Plano 1 — pode rodar antes ou depois.

---

### Task 1: Função pura `pci_posture` em `compliance_map.py`

**Files:**
- Modify: `lib/compliance_map.py` (adiciona `_REQ_COVERAGE`, `_req_key`, `pci_posture`)
- Test: `tests/test_compliance_map.py`

Regra: **FAIL** se ≥1 finding mapeado ao requisito (via CWE→`pci` **ou** campo `pci_req`); **PASS** se sem finding e a capacidade de cobertura está ativa; **N/A** caso contrário (default conservador — nunca PASS falso).

- [ ] **Step 1: Write the failing test**

Adicione ao final de `tests/test_compliance_map.py`:

```python
def test_pci_posture_fail_when_finding_maps_to_req():
    # CWE-79 → pci 6.2.4 no crosswalk
    out = C.pci_posture([{"cve": "CWE-79"}], coverage={"webapp": True})
    by = {p["req"]: p for p in out}
    assert by["6.2.4"]["verdict"] == "FAIL"
    assert by["6.2.4"]["count"] == 1


def test_pci_posture_pass_when_covered_and_no_finding():
    out = C.pci_posture([], coverage={"tls": True})
    by = {p["req"]: p for p in out}
    assert by["4.2.1"]["verdict"] == "PASS"


def test_pci_posture_na_when_capability_not_run():
    out = C.pci_posture([], coverage={"tls": False})
    by = {p["req"]: p for p in out}
    assert by["4.2.1"]["verdict"] == "N/A"


def test_pci_posture_authz_na_without_token_signal():
    # sem sinal de scan autenticado → access control = N/A, não PASS falso
    out = C.pci_posture([], coverage={"authz": False, "authn": False})
    by = {p["req"]: p for p in out}
    assert by["7.2.1"]["verdict"] == "N/A"
    assert by["8.3.1"]["verdict"] == "N/A"


def test_pci_posture_fail_precedes_coverage():
    # finding presente mas cobertura ausente → ainda FAIL (FAIL tem precedência)
    out = C.pci_posture([{"pci_req": "4.2.1", "name": "TLS 1.0"}], coverage={"tls": False})
    by = {p["req"]: p for p in out}
    assert by["4.2.1"]["verdict"] == "FAIL"


def test_pci_posture_top_findings_only_on_fail():
    out = C.pci_posture([{"cve": "CWE-79", "name": "Reflected XSS"}],
                        coverage={"webapp": True})
    by = {p["req"]: p for p in out}
    assert by["6.2.4"]["top_findings"] == ["Reflected XSS"]
    # requisitos não-FAIL não carregam top_findings
    assert by["4.2.1"]["top_findings"] == []


def test_pci_posture_sorts_numerically():
    out = C.pci_posture([], coverage={})
    reqs = [p["req"] for p in out]
    # 2.2.1 deve vir antes de 10.2.1 (ordenação numérica, não lexicográfica)
    assert reqs.index("2.2.1") < reqs.index("10.2.1")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_compliance_map.py -q`
Expected: FAIL com `AttributeError: module 'compliance_map' has no attribute 'pci_posture'`

- [ ] **Step 3: Write minimal implementation**

Em `lib/compliance_map.py`, adicione ao final do arquivo:

```python
# Requisito PCI → chave de capacidade do scan (sinal de "a fase rodou").
# Universo = requisitos que o scanner consegue exercitar (crosswalk _MAP + pci_verdicts).
_REQ_COVERAGE = {
    "2.2.1":  "headers",     # hardening / misconfig
    "2.2.5":  "services",    # serviços de rede expostos
    "3.2":    "cde",         # proteção de dados no CDE
    "4.2.1":  "tls",         # TLS forte
    "6.2.4":  "webapp",      # app seguro (injeção/XSS/CSRF/SSRF)
    "6.3.3":  "components",  # componentes atualizados
    "7.2.1":  "authz",       # controle de acesso
    "8.3.1":  "authn",       # autenticação
    "8.3.4":  "authn",
    "8.6.1":  "authn",
    "10.2.1": "logging",     # logging/monitoring — DAST não exercita → só FAIL se houver finding
}


def _req_key(req):
    """Ordena requisitos PCI numericamente ('2.2.1' antes de '10.2.1')."""
    return tuple(int(x) for x in re.findall(r"\d+", req))


def pci_posture(findings, coverage=None):
    """Veredito PASS/FAIL/N-A por requisito PCI.

    FAIL: >=1 finding mapeado (CWE->pci OU campo pci_req).
    PASS: sem finding e a capacidade de cobertura está ativa em `coverage`.
    N/A:  capacidade não exercida (default conservador — nunca PASS falso).

    Retorna lista de {req, verdict, count, top_findings} ordenada por requisito.
    """
    coverage = coverage or {}
    counts, tops = {}, {}
    for f in findings:
        reqs = set()
        fr = frameworks_for_cwe(extract_cwe(f))
        if fr.get("pci"):
            reqs.add(fr["pci"])
        if f.get("pci_req"):
            reqs.add(f["pci_req"])
        for r in reqs:
            counts[r] = counts.get(r, 0) + 1
            bucket = tops.setdefault(r, [])
            name = f.get("name")
            if name and len(bucket) < 3:
                bucket.append(name)
    out = []
    for req in sorted(set(_REQ_COVERAGE) | set(counts), key=_req_key):
        n = counts.get(req, 0)
        if n > 0:
            verdict = "FAIL"
        else:
            cov_key = _REQ_COVERAGE.get(req)
            verdict = "PASS" if (cov_key and coverage.get(cov_key)) else "N/A"
        out.append({"req": req, "verdict": verdict, "count": n,
                    "top_findings": tops.get(req, [])})
    return out
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_compliance_map.py -q`
Expected: PASS (todos, incluindo os antigos)

- [ ] **Step 5: Commit**

```bash
git add lib/compliance_map.py tests/test_compliance_map.py
git commit -m "feat(compliance): pci_posture PASS/FAIL/N-A por requisito

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 2: Render só-PCI no relatório + derivação de `coverage`

**Files:**
- Modify: `stiglitz_report.py:2213-2230` (substitui o bloco "Compliance Mapping section")
- Verify: `python3 -m py_compile stiglitz_report.py`

- [ ] **Step 1: Substituir o bloco de render**

Em `stiglitz_report.py`, substitua **todo** o bloco entre o comentário `# ── Compliance Mapping section (#10) ─────────────────────────` e a linha que fecha `compliance_section_html = (... + _blocks)` (linhas ~2213-2230) por:

```python
# ── Compliance Mapping section — PCI DSS only (PASS/FAIL/N-A) ─
_raw_dir = os.path.join(OUTDIR, "raw")
def _raw_has(_n):
    return os.path.exists(os.path.join(_raw_dir, _n))
_coverage = {
    "headers":    _raw_has("security_headers.json"),
    "services":   _raw_has("service_findings.json"),
    "cde":        bool(_pci_findings),
    "tls":        _raw_has("testssl.json"),
    "webapp":     _raw_has("nuclei.json") or _raw_has("zap_alerts.json"),
    "components": _raw_has("nuclei.json"),
    "authz":      _raw_has("access_control.json"),
    "authn":      _raw_has("access_control.json"),
    "logging":    False,
}
_posture = _comp_map.pci_posture(all_f, _coverage)
compliance_section_html = ""
if _posture:
    _fail = [p for p in _posture if p["verdict"] == "FAIL"]
    _pass = [p for p in _posture if p["verdict"] == "PASS"]
    _na = [p for p in _posture if p["verdict"] == "N/A"]
    _gaps = ", ".join(f"{p['req']} ({p['count']})"
                      for p in sorted(_fail, key=lambda p: -p["count"])[:4])
    _summary = (f"PCI DSS 4.0.1 — {len(_posture)} requirements assessed: "
                f"{len(_fail)} FAIL, {len(_pass)} PASS, {len(_na)} N/A."
                + (f" Top gaps: {_gaps}." if _gaps else ""))
    _vcolor = {"FAIL": "#c0392b", "PASS": "#27ae60", "N/A": "#888"}
    _rows = ""
    for p in _posture:
        _tf = html.escape("; ".join(p["top_findings"])) if p["verdict"] == "FAIL" else ""
        _rows += (f"<tr><td>{html.escape(p['req'])}</td>"
                  f"<td><span style='color:{_vcolor[p['verdict']]};font-weight:bold'>"
                  f"{p['verdict']}</span></td>"
                  f"<td>{p['count'] or ''}</td>"
                  f"<td style='font-size:12px'>{_tf}</td></tr>")
    compliance_section_html = (
        "<h2>Compliance Mapping — PCI DSS 4.0.1</h2>"
        f"<p>{html.escape(_summary)}</p>"
        "<p style='font-size:12px;color:#666'>FAIL = finding mapped to the requirement; "
        "PASS = capability exercised, no finding; N/A = capability not exercised in this scan.</p>"
        "<table><tr><th>Requirement</th><th>Verdict</th><th>Findings</th><th>Top findings</th></tr>"
        + _rows + "</table>")
```

(Observação: `_pci_findings`, `all_f`, `_comp_map`, `OUTDIR`, `html` já estão no escopo — definidos acima desse ponto no arquivo.)

- [ ] **Step 2: Compile para validar sintaxe**

Run: `python3 -m py_compile stiglitz_report.py`
Expected: sem saída (sucesso)

- [ ] **Step 3: Verificar que `compliance_section_html` ainda é injetado no HTML**

Run: `grep -n "compliance_section_html" stiglitz_report.py`
Expected: além da definição, deve haver a referência que injeta a variável no template HTML final (era usada antes; a mudança preserva o nome da variável, então a injeção continua válida). Confirme que o nome não foi renomeado.

- [ ] **Step 4: Suíte de compliance + py_compile dos módulos**

Run: `python3 -m pytest tests/test_compliance_map.py -q && python3 -m py_compile stiglitz_report.py lib/compliance_map.py`
Expected: PASS + sem erros de compile

- [ ] **Step 5: Commit**

```bash
git add stiglitz_report.py
git commit -m "feat(report): Compliance Mapping so-PCI com veredito PASS/FAIL/N-A + resumo

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 3: Smoke do relatório (opcional, se houver scan local)

**Files:** nenhuma alteração — verificação opcional.

- [ ] **Step 1: Se existir um `scan_*/` local, regerar o relatório e inspecionar a seção**

Run (substitua `<scan_dir>` por um diretório de scan existente, se houver):
```bash
ls -d scan_*/ 2>/dev/null | head -1
```
Se houver, regenere o relatório conforme o fluxo da fase P11 do projeto e abra o HTML, conferindo que a seção "Compliance Mapping — PCI DSS 4.0.1" mostra a tabela PASS/FAIL/N-A e o resumo. Se não houver scan local, pule — a lógica já está coberta pelos testes de `pci_posture` e o render por `py_compile`.

- [ ] **Step 2: Nada a commitar** (verificação apenas).

---

## Self-check de cobertura do spec (Parte B)

- Só-PCI: render restrito a PCI DSS 4.0.1 — Task 2. ✓
- PASS/FAIL/N-A: `pci_posture` — Task 1. ✓
- Resumo breve: `_summary` no render — Task 2. ✓
- N/A conservador (sem PASS falso): default N/A + `authz/authn` por sinal de scan autenticado — Task 1. ✓
- "PCI DSS CDE Coverage" intacta: o plano não toca as linhas ~2193-2211. ✓

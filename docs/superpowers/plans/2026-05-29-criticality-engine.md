# Motor de Criticidade — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Atribuir a cada finding uma criticidade CVSS 3.1 completa (Base+Temporal+Environmental), sensível ao contexto fintech e ao status de confirmação, com proveniência transparente.

**Architecture:** Quatro módulos puros em `lib/` (`cvss.py` calculadora, `vuln_catalog.py`, `asset_classifier.py`, `criticality.py` orquestrador), validados contra a biblioteca `cvss` nos testes, e depois integrados em `evidence.py`, `risk_score.py`, relatório e SARIF.

**Tech Stack:** Python 3 puro (sem dependência em runtime); `cvss` (PyPI) como dependência de teste; `unittest`/`pytest`; convenções do `lib/` existente.

**Spec:** `docs/superpowers/specs/2026-05-29-criticality-engine-design.md`

---

## File Structure

- **Create** `lib/cvss.py` — calculadora CVSS 3.1 pura (constantes, parse/serialização de vetor, base/temporal/environmental, roundup, banda).
- **Create** `lib/vuln_catalog.py` — `lookup(key)` → `{vector, cwe, title}` por classe de vuln ou CWE.
- **Create** `lib/asset_classifier.py` — `classify_asset(host, path, overrides)` + `requirements_for(asset_class)`.
- **Create** `lib/criticality.py` — `score_finding(finding, asset_class, confirmed)` orquestrando os anteriores.
- **Create** `tests/test_criticality.py` — testes dos quatro módulos + matriz validada contra a lib `cvss`.
- **Modify** `requirements-dev.txt` — adicionar `cvss`.
- **Modify** `lib/evidence.py` — enriquecer findings com criticalidade.
- **Modify** `lib/risk_score.py` — `compute_risk` consome as bandas novas.
- **Modify** `lib/report_generator.py` e `stiglitz_report.py` — exibir score/vetor/banda/proveniência.
- **Modify** `lib/report/sarif.py` — `security-severity` = score Environmental.

---

## PARTE 1 — Calculadora CVSS 3.1 (`lib/cvss.py`)

### Task 1: Constantes + métricas Base e parse de vetor

**Files:**
- Create: `lib/cvss.py`
- Test: `tests/test_criticality.py`

- [ ] **Step 1: Escrever o teste que falha**

```python
#!/usr/bin/env python3
"""Testes do motor de criticidade (cvss, catalog, classifier, criticality)."""
import os
import sys
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
sys.path[:0] = [_ROOT, os.path.join(_ROOT, "lib")]


class TestCVSSParse(unittest.TestCase):
    def test_parse_vector_extracts_metrics(self):
        import cvss as c
        m = c.parse_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        self.assertEqual(m["AV"], "N")
        self.assertEqual(m["S"], "U")
        self.assertEqual(m["C"], "H")

    def test_parse_vector_rejects_bad_prefix(self):
        import cvss as c
        with self.assertRaises(ValueError):
            c.parse_vector("AV:N/AC:L")
```

- [ ] **Step 2: Rodar o teste para confirmar que falha**

Run: `python3 -m pytest tests/test_criticality.py::TestCVSSParse -v`
Expected: FAIL com `ModuleNotFoundError: No module named 'cvss'` (nosso módulo ainda não existe).

- [ ] **Step 3: Implementação mínima**

```python
#!/usr/bin/env python3
"""
cvss.py — Calculadora CVSS 3.1 (Base + Temporal + Environmental).

Implementação pura (sem IO, sem dependência em runtime) conforme a
especificação oficial CVSS v3.1. Validada contra a biblioteca `cvss`
nos testes. Funções no estilo de risk_score.py.
"""
import math

PREFIX = "CVSS:3.1"

# Métricas válidas por chave (X = Not Defined, usado em Temporal/Environmental).
_VALID = {
    "AV": "NALP", "AC": "LH", "PR": "NLH", "UI": "NR", "S": "UC",
    "C": "HLN", "I": "HLN", "A": "HLN",
    "E": "XHFPU", "RL": "XOTWU", "RC": "XCRU",
    "CR": "XHML", "IR": "XHML", "AR": "XHML",
    "MAV": "XNALP", "MAC": "XLH", "MPR": "XNLH", "MUI": "XNR", "MS": "XUC",
    "MC": "XHLN", "MI": "XHLN", "MA": "XHLN",
}


def parse_vector(vector):
    """Parseia uma string de vetor CVSS 3.1 → dict {metric: value}."""
    if not vector.startswith(PREFIX + "/"):
        raise ValueError(f"Vetor CVSS 3.1 inválido (prefixo): {vector!r}")
    metrics = {}
    for part in vector[len(PREFIX) + 1:].split("/"):
        if not part:
            continue
        if ":" not in part:
            raise ValueError(f"Componente inválido: {part!r}")
        key, _, val = part.partition(":")
        if key not in _VALID or val not in _VALID[key]:
            raise ValueError(f"Métrica inválida: {part!r}")
        metrics[key] = val
    for req in ("AV", "AC", "PR", "UI", "S", "C", "I", "A"):
        if req not in metrics:
            raise ValueError(f"Métrica base ausente: {req}")
    return metrics
```

- [ ] **Step 4: Rodar o teste para confirmar que passa**

Run: `python3 -m pytest tests/test_criticality.py::TestCVSSParse -v`
Expected: PASS (2 passed)

- [ ] **Step 5: Commit**

```bash
git add lib/cvss.py tests/test_criticality.py
git commit -m "feat(cvss): parser de vetor CVSS 3.1"
```

---

### Task 2: Base score com roundup

**Files:**
- Modify: `lib/cvss.py`
- Test: `tests/test_criticality.py`

- [ ] **Step 1: Escrever o teste que falha**

```python
class TestCVSSBase(unittest.TestCase):
    def test_roundup_examples(self):
        import cvss as c
        self.assertEqual(c.roundup(4.0), 4.0)
        self.assertEqual(c.roundup(4.02), 4.1)
        self.assertEqual(c.roundup(6.000001), 6.1)

    def test_base_critical_rce(self):
        import cvss as c
        # Log4Shell-like: AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H → 10.0
        m = c.parse_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")
        self.assertEqual(c.base_score(m), 10.0)

    def test_base_scope_unchanged(self):
        import cvss as c
        # AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H → 9.8
        m = c.parse_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        self.assertEqual(c.base_score(m), 9.8)

    def test_base_zero_when_no_impact(self):
        import cvss as c
        m = c.parse_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")
        self.assertEqual(c.base_score(m), 0.0)
```

- [ ] **Step 2: Rodar o teste para confirmar que falha**

Run: `python3 -m pytest tests/test_criticality.py::TestCVSSBase -v`
Expected: FAIL com `AttributeError: module 'cvss' has no attribute 'roundup'`

- [ ] **Step 3: Implementação mínima (adicionar a `lib/cvss.py`)**

```python
# ── Pesos das métricas (CVSS 3.1) ────────────────────────────────────────────
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}   # Scope Unchanged
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.5}    # Scope Changed
_UI = {"N": 0.85, "R": 0.62}
_IMPACT = {"H": 0.56, "L": 0.22, "N": 0.0}


def roundup(x):
    """Roundup oficial CVSS 3.1 (arredonda para cima na 1ª casa decimal)."""
    int_input = round(x * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000.0
    return (math.floor(int_input / 10000) + 1) / 10.0


def _pr_weight(pr, scope):
    return (_PR_C if scope == "C" else _PR_U)[pr]


def _iss(c_, i_, a_):
    return 1 - (1 - _IMPACT[c_]) * (1 - _IMPACT[i_]) * (1 - _IMPACT[a_])


def base_score(m):
    """Calcula o Base Score CVSS 3.1 a partir do dict de métricas."""
    iss = _iss(m["C"], m["I"], m["A"])
    if m["S"] == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    expl = 8.22 * _AV[m["AV"]] * _AC[m["AC"]] * _pr_weight(m["PR"], m["S"]) * _UI[m["UI"]]
    if impact <= 0:
        return 0.0
    if m["S"] == "U":
        return roundup(min(impact + expl, 10))
    return roundup(min(1.08 * (impact + expl), 10))
```

- [ ] **Step 4: Rodar o teste para confirmar que passa**

Run: `python3 -m pytest tests/test_criticality.py::TestCVSSBase -v`
Expected: PASS (4 passed)

- [ ] **Step 5: Commit**

```bash
git add lib/cvss.py tests/test_criticality.py
git commit -m "feat(cvss): base score + roundup"
```

---

### Task 3: Temporal score

**Files:**
- Modify: `lib/cvss.py`
- Test: `tests/test_criticality.py`

- [ ] **Step 1: Escrever o teste que falha**

```python
class TestCVSSTemporal(unittest.TestCase):
    def test_temporal_confirmed_equals_base(self):
        import cvss as c
        # E:H/RC:C/RL:U → multiplicadores 1.0 → temporal == base
        m = c.parse_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:H/RC:C")
        self.assertEqual(c.temporal_score(m), 9.8)

    def test_temporal_potential_lower_than_base(self):
        import cvss as c
        m = c.parse_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:P/RC:R")
        self.assertLess(c.temporal_score(m), 9.8)
```

- [ ] **Step 2: Rodar o teste para confirmar que falha**

Run: `python3 -m pytest tests/test_criticality.py::TestCVSSTemporal -v`
Expected: FAIL com `AttributeError: ... 'temporal_score'`

- [ ] **Step 3: Implementação mínima (adicionar a `lib/cvss.py`)**

```python
_E = {"X": 1.0, "H": 1.0, "F": 0.97, "P": 0.94, "U": 0.91}
_RL = {"X": 1.0, "U": 1.0, "W": 0.97, "T": 0.96, "O": 0.95}
_RC = {"X": 1.0, "C": 1.0, "R": 0.96, "U": 0.92}


def temporal_score(m):
    """Temporal = roundup(Base × E × RL × RC)."""
    base = base_score(m)
    return roundup(base * _E[m.get("E", "X")] * _RL[m.get("RL", "X")] * _RC[m.get("RC", "X")])
```

- [ ] **Step 4: Rodar o teste para confirmar que passa**

Run: `python3 -m pytest tests/test_criticality.py::TestCVSSTemporal -v`
Expected: PASS (2 passed)

- [ ] **Step 5: Commit**

```bash
git add lib/cvss.py tests/test_criticality.py
git commit -m "feat(cvss): temporal score"
```

---

### Task 4: Environmental score

**Files:**
- Modify: `lib/cvss.py`
- Test: `tests/test_criticality.py`

- [ ] **Step 1: Escrever o teste que falha**

```python
class TestCVSSEnvironmental(unittest.TestCase):
    def test_env_requirements_raise_score(self):
        import cvss as c
        low  = c.parse_vector("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N/CR:L")
        high = c.parse_vector("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N/CR:H")
        self.assertGreater(c.environmental_score(high), c.environmental_score(low))

    def test_env_defaults_to_base_when_no_modifiers(self):
        import cvss as c
        m = c.parse_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        self.assertEqual(c.environmental_score(m), 9.8)

    def test_env_zero_when_no_impact(self):
        import cvss as c
        m = c.parse_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/CR:H")
        self.assertEqual(c.environmental_score(m), 0.0)
```

- [ ] **Step 2: Rodar o teste para confirmar que falha**

Run: `python3 -m pytest tests/test_criticality.py::TestCVSSEnvironmental -v`
Expected: FAIL com `AttributeError: ... 'environmental_score'`

- [ ] **Step 3: Implementação mínima (adicionar a `lib/cvss.py`)**

```python
_CIA_REQ = {"X": 1.0, "H": 1.5, "M": 1.0, "L": 0.5}


def _mod(m, key):
    """Valor de métrica modificada: usa M<key> se definido (≠X), senão a base."""
    mkey = "M" + key
    v = m.get(mkey, "X")
    return m[key] if v == "X" else v


def environmental_score(m):
    """Environmental Score CVSS 3.1 (com Temporal aplicado)."""
    mav, mac, mui, ms = _mod(m, "AV"), _mod(m, "AC"), _mod(m, "UI"), _mod(m, "S")
    mc, mi, ma = _mod(m, "C"), _mod(m, "I"), _mod(m, "A")
    # MPR depende do Modified Scope
    mpr = m["PR"] if m.get("MPR", "X") == "X" else m["MPR"]

    cr = _CIA_REQ[m.get("CR", "X")]
    ir = _CIA_REQ[m.get("IR", "X")]
    ar = _CIA_REQ[m.get("AR", "X")]

    miss = min(
        1 - (1 - cr * _IMPACT[mc]) * (1 - ir * _IMPACT[mi]) * (1 - ar * _IMPACT[ma]),
        0.915,
    )
    if ms == "U":
        mimpact = 6.42 * miss
    else:
        mimpact = 7.52 * (miss - 0.029) - 3.25 * (miss * 0.9731 - 0.02) ** 13
    mexpl = 8.22 * _AV[mav] * _AC[mac] * _pr_weight(mpr, ms) * _UI[mui]

    if mimpact <= 0:
        return 0.0
    e = _E[m.get("E", "X")] * _RL[m.get("RL", "X")] * _RC[m.get("RC", "X")]
    if ms == "U":
        return roundup(roundup(min(mimpact + mexpl, 10)) * e)
    return roundup(roundup(min(1.08 * (mimpact + mexpl), 10)) * e)
```

- [ ] **Step 4: Rodar o teste para confirmar que passa**

Run: `python3 -m pytest tests/test_criticality.py::TestCVSSEnvironmental -v`
Expected: PASS (3 passed)

- [ ] **Step 5: Commit**

```bash
git add lib/cvss.py tests/test_criticality.py
git commit -m "feat(cvss): environmental score"
```

---

### Task 5: Banda qualitativa + serialização de vetor

**Files:**
- Modify: `lib/cvss.py`
- Test: `tests/test_criticality.py`

- [ ] **Step 1: Escrever o teste que falha**

```python
class TestCVSSBandAndSerialize(unittest.TestCase):
    def test_band_mapping(self):
        import cvss as c
        self.assertEqual(c.band(0.0), "info")
        self.assertEqual(c.band(3.9), "low")
        self.assertEqual(c.band(4.0), "medium")
        self.assertEqual(c.band(7.0), "high")
        self.assertEqual(c.band(9.0), "critical")

    def test_to_vector_roundtrip(self):
        import cvss as c
        s = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:H/RC:C/CR:H"
        self.assertEqual(c.to_vector(c.parse_vector(s)), s)
```

- [ ] **Step 2: Rodar o teste para confirmar que falha**

Run: `python3 -m pytest tests/test_criticality.py::TestCVSSBandAndSerialize -v`
Expected: FAIL com `AttributeError: ... 'band'`

- [ ] **Step 3: Implementação mínima (adicionar a `lib/cvss.py`)**

```python
# Ordem canônica das métricas para serialização determinística.
_ORDER = ["AV", "AC", "PR", "UI", "S", "C", "I", "A",
          "E", "RL", "RC",
          "CR", "IR", "AR",
          "MAV", "MAC", "MPR", "MUI", "MS", "MC", "MI", "MA"]


def band(score):
    """Mapeia score 0-10 → banda qualitativa CVSS 3.1 (usa 'info' para None)."""
    if score == 0.0:
        return "info"
    if score < 4.0:
        return "low"
    if score < 7.0:
        return "medium"
    if score < 9.0:
        return "high"
    return "critical"


def to_vector(m):
    """Serializa dict de métricas → string de vetor (ordem canônica, omite X)."""
    parts = [PREFIX]
    for key in _ORDER:
        v = m.get(key)
        if v and v != "X":
            parts.append(f"{key}:{v}")
    return "/".join(parts)
```

- [ ] **Step 4: Rodar o teste para confirmar que passa**

Run: `python3 -m pytest tests/test_criticality.py::TestCVSSBandAndSerialize -v`
Expected: PASS (2 passed)

- [ ] **Step 5: Commit**

```bash
git add lib/cvss.py tests/test_criticality.py
git commit -m "feat(cvss): banda qualitativa + serialização de vetor"
```

---

### Task 6: Validação contra a biblioteca `cvss` (dep de teste)

**Files:**
- Modify: `requirements-dev.txt`
- Test: `tests/test_criticality.py`

- [ ] **Step 1: Adicionar a dependência de teste**

Adicionar a linha ao final de `requirements-dev.txt`:

```
cvss>=3.0
```

Instalar localmente: `pip install 'cvss>=3.0'`

- [ ] **Step 2: Escrever o teste que falha (matriz validada)**

```python
class TestCVSSAgainstReference(unittest.TestCase):
    """Valida a calculadora in-house contra a biblioteca `cvss` (referência)."""

    VECTORS = [
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:N",
        "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N/E:H/RC:C",
        "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N/E:P/RC:R",
        "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N/CR:H/IR:H",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:H/RC:C/CR:H/IR:H/AR:L",
        "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N/MAV:A/CR:L",
    ]

    def test_base_temporal_environmental_match_reference(self):
        from cvss import CVSS3  # biblioteca de referência
        import cvss as c
        for v in self.VECTORS:
            ref = CVSS3(v)
            ref_base, ref_temp, ref_env = ref.scores()  # (base, temporal, environmental)
            m = c.parse_vector(v)
            self.assertEqual(c.base_score(m), ref_base, f"BASE divergiu: {v}")
            self.assertEqual(c.temporal_score(m), ref_temp, f"TEMPORAL divergiu: {v}")
            self.assertEqual(c.environmental_score(m), ref_env, f"ENV divergiu: {v}")
```

- [ ] **Step 3: Rodar a matriz**

Run: `python3 -m pytest tests/test_criticality.py::TestCVSSAgainstReference -v`
Expected: PASS. Se algum vetor divergir, corrigir a fórmula correspondente em `lib/cvss.py` (provável causa: roundup intermediário no Environmental ou expoente do Modified Impact em Scope Changed) e repetir até verde.

- [ ] **Step 4: Commit**

```bash
git add requirements-dev.txt tests/test_criticality.py
git commit -m "test(cvss): valida calculadora contra a lib de referência"
```

---

## PARTE 2 — Catálogo, classificador e orquestrador

### Task 7: Catálogo de classes de vuln (`lib/vuln_catalog.py`)

**Files:**
- Create: `lib/vuln_catalog.py`
- Test: `tests/test_criticality.py`

- [ ] **Step 1: Escrever o teste que falha**

```python
class TestVulnCatalog(unittest.TestCase):
    def test_lookup_known_class(self):
        import vuln_catalog as vc
        e = vc.lookup("idor_read_pii")
        self.assertEqual(e["cwe"], "CWE-639")
        self.assertIn("C:H", e["vector"])

    def test_lookup_by_cwe(self):
        import vuln_catalog as vc
        e = vc.lookup("CWE-352")
        self.assertIsNotNone(e)
        self.assertIn("csrf", e["title"].lower())

    def test_lookup_unknown_returns_none(self):
        import vuln_catalog as vc
        self.assertIsNone(vc.lookup("classe_inexistente"))
```

- [ ] **Step 2: Rodar o teste para confirmar que falha**

Run: `python3 -m pytest tests/test_criticality.py::TestVulnCatalog -v`
Expected: FAIL com `ModuleNotFoundError: No module named 'vuln_catalog'`

- [ ] **Step 3: Implementação mínima**

```python
#!/usr/bin/env python3
"""
vuln_catalog.py — Catálogo: classe de vulnerabilidade → vetor CVSS 3.1 base + CWE.

Dá um vetor base defensável a findings que NÃO têm CVE (lógica de negócio,
IDOR/BOLA, authz, JWT, etc.). Indexável por nome de classe ou por CWE.
"""

# Cada entrada: classe -> {cwe, vector (base, sem CVSS:3.1/ prefixo de temporal/env), title}
CATALOG = {
    "idor_read_pii":      {"cwe": "CWE-639", "title": "IDOR — leitura de dados de outro usuário",
                           "vector": "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"},
    "idor_write":         {"cwe": "CWE-639", "title": "IDOR/BOLA — escrita em recurso de outro usuário",
                           "vector": "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"},
    "bola":               {"cwe": "CWE-639", "title": "Broken Object Level Authorization",
                           "vector": "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"},
    "broken_auth":        {"cwe": "CWE-287", "title": "Autenticação quebrada",
                           "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"},
    "priv_escalation":    {"cwe": "CWE-269", "title": "Escalação de privilégio",
                           "vector": "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"},
    "amount_tampering":   {"cwe": "CWE-840", "title": "Manipulação de valor/transação",
                           "vector": "AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N"},
    "race_condition_funds": {"cwe": "CWE-362", "title": "Race condition em fluxo financeiro",
                           "vector": "AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:N"},
    "jwt_alg_none":       {"cwe": "CWE-347", "title": "JWT aceita alg=none",
                           "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"},
    "jwt_weak_secret":    {"cwe": "CWE-347", "title": "JWT com segredo fraco (HS256)",
                           "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"},
    "csrf_state_changing": {"cwe": "CWE-352", "title": "CSRF em ação que altera estado",
                           "vector": "AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N"},
    "ssrf":               {"cwe": "CWE-918", "title": "Server-Side Request Forgery",
                           "vector": "AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N"},
    "open_redirect":      {"cwe": "CWE-601", "title": "Open redirect",
                           "vector": "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"},
    "missing_security_header": {"cwe": "CWE-693", "title": "Cabeçalho de segurança ausente",
                           "vector": "AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N"},
    "spf_dmarc_weak":     {"cwe": "CWE-290", "title": "SPF/DMARC permite spoofing",
                           "vector": "AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N"},
    "rate_limit_missing": {"cwe": "CWE-307", "title": "Falta de rate limiting",
                           "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:L"},
}

# Índice secundário por CWE (primeira classe que mapeia para o CWE).
_BY_CWE = {}
for _k, _v in CATALOG.items():
    _BY_CWE.setdefault(_v["cwe"], dict(_v, **{"class": _k}))


def lookup(key):
    """Retorna {vector, cwe, title} por nome de classe ou por CWE; None se ausente."""
    if key in CATALOG:
        return dict(CATALOG[key])
    if key in _BY_CWE:
        e = dict(_BY_CWE[key])
        e.pop("class", None)
        return e
    return None
```

- [ ] **Step 4: Rodar o teste para confirmar que passa**

Run: `python3 -m pytest tests/test_criticality.py::TestVulnCatalog -v`
Expected: PASS (3 passed)

- [ ] **Step 5: Commit**

```bash
git add lib/vuln_catalog.py tests/test_criticality.py
git commit -m "feat(catalog): classe de vuln -> vetor CVSS base + CWE"
```

---

### Task 8: Classificador de ativos (`lib/asset_classifier.py`)

**Files:**
- Create: `lib/asset_classifier.py`
- Test: `tests/test_criticality.py`

- [ ] **Step 1: Escrever o teste que falha**

```python
class TestAssetClassifier(unittest.TestCase):
    def test_infer_cde(self):
        import asset_classifier as ac
        self.assertEqual(ac.classify_asset("app-tokenize.dev2.example.com", "/"), "cde")
        self.assertEqual(ac.classify_asset("3ds.example.com", "/"), "cde")

    def test_infer_funds(self):
        import asset_classifier as ac
        self.assertEqual(ac.classify_asset("app-gateway-cielo.hml2.example.com", "/"), "funds")
        self.assertEqual(ac.classify_asset("checkout.example.com", "/"), "funds")

    def test_infer_internal_and_public(self):
        import asset_classifier as ac
        self.assertEqual(ac.classify_asset("app-hml-kibana-v2.hml2.example.com", "/"), "internal")
        self.assertEqual(ac.classify_asset("www.example.com", "/"), "public")

    def test_default_when_no_match(self):
        import asset_classifier as ac
        self.assertEqual(ac.classify_asset("acme-widget.example.com", "/"), "default")

    def test_override_wins(self):
        import asset_classifier as ac
        ov = [{"match": "checkout.example.com", "data_class": "cde"}]
        self.assertEqual(ac.classify_asset("checkout.example.com", "/", ov), "cde")

    def test_requirements_for(self):
        import asset_classifier as ac
        self.assertEqual(ac.requirements_for("cde"), {"CR": "H", "IR": "H", "AR": "M"})
        self.assertEqual(ac.requirements_for("public"), {"CR": "L", "IR": "L", "AR": "L"})
        self.assertEqual(ac.requirements_for("default"), {"CR": "M", "IR": "M", "AR": "M"})
```

- [ ] **Step 2: Rodar o teste para confirmar que falha**

Run: `python3 -m pytest tests/test_criticality.py::TestAssetClassifier -v`
Expected: FAIL com `ModuleNotFoundError: No module named 'asset_classifier'`

- [ ] **Step 3: Implementação mínima**

```python
#!/usr/bin/env python3
"""
asset_classifier.py — Classifica um ativo (host/path) por sensibilidade de dados,
dirigindo os requisitos CVSS Environmental (CR/IR/AR). Inferência por padrões
(Example-aware) com override opcional por arquivo. Override > inferência > default.
"""
import fnmatch
import re

# Ordem importa: padrões mais sensíveis primeiro.
_PATTERNS = [
    ("cde",      r"card|pan|tokenize|vcn|3ds|acs|acquirera|acquirerb"),
    ("funds",    r"gateway|checkout|splitter|cielo|getnet|\brede\b|mercadopago"),
    ("pii",      r"auth|token|login|onetime|sso|saml|oauth|keycloak|kc\.|back-token|"
                 r"fraudsvc|buyer|reservation|hotel|chargeback|receivable|"
                 r"notification|email-service|simples-nacional"),
    ("internal", r"kibana|grafana|apm|elastic|logs|jenkins|nexus|uptime|longhorn"),
    ("public",   r"www|cdn|static|assets|portal|sidebar|topbar"),
]

_REQUIREMENTS = {
    "cde":      {"CR": "H", "IR": "H", "AR": "M"},
    "funds":    {"CR": "H", "IR": "H", "AR": "M"},
    "pii":      {"CR": "H", "IR": "M", "AR": "L"},
    "internal": {"CR": "M", "IR": "M", "AR": "M"},
    "public":   {"CR": "L", "IR": "L", "AR": "L"},
    "default":  {"CR": "M", "IR": "M", "AR": "M"},
}


def classify_asset(host, path="/", overrides=None):
    """Classe do ativo. overrides: lista de {match: glob de host[/path], data_class}."""
    target = f"{host}{path}"
    if overrides:
        for ov in overrides:
            pat = ov.get("match", "")
            if fnmatch.fnmatch(host, pat) or fnmatch.fnmatch(target, pat):
                return ov.get("data_class", "default")
    hay = target.lower()
    for cls, rx in _PATTERNS:
        if re.search(rx, hay):
            return cls
    return "default"


def requirements_for(asset_class):
    """Mapeia classe → requisitos Environmental CVSS (CR/IR/AR)."""
    return dict(_REQUIREMENTS.get(asset_class, _REQUIREMENTS["default"]))
```

- [ ] **Step 4: Rodar o teste para confirmar que passa**

Run: `python3 -m pytest tests/test_criticality.py::TestAssetClassifier -v`
Expected: PASS (6 passed)

- [ ] **Step 5: Commit**

```bash
git add lib/asset_classifier.py tests/test_criticality.py
git commit -m "feat(classifier): classificação de ativo + requisitos CVSS env"
```

---

### Task 9: Orquestrador `score_finding` (`lib/criticality.py`)

**Files:**
- Create: `lib/criticality.py`
- Test: `tests/test_criticality.py`

- [ ] **Step 1: Escrever o teste que falha**

```python
class TestScoreFinding(unittest.TestCase):
    def test_cve_finding_uses_nvd_vector(self):
        import criticality as cr
        f = {"name": "RCE", "severity": "critical",
             "cvss_vector_nvd": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
        out = cr.score_finding(f, asset_class="default", confirmed=False)
        self.assertEqual(out["score_source"], "nvd")
        self.assertEqual(out["severity"], "critical")

    def test_catalog_finding_without_cve(self):
        import criticality as cr
        f = {"name": "IDOR", "severity": "medium", "vuln_class": "idor_read_pii"}
        out = cr.score_finding(f, asset_class="cde", confirmed=True)
        self.assertEqual(out["score_source"], "catalog")
        # CDE (CR:H) + confirmado deve elevar acima do base puro
        self.assertGreater(out["cvss_environmental"], out["cvss_base"])

    def test_estimated_when_no_cve_no_class(self):
        import criticality as cr
        f = {"name": "Algo", "severity": "high"}
        out = cr.score_finding(f, asset_class="default", confirmed=False)
        self.assertEqual(out["score_source"], "estimated")
        self.assertIn(out["severity"], ("high", "critical", "medium"))

    def test_confirmed_raises_score(self):
        import criticality as cr
        f = {"name": "IDOR", "severity": "medium", "vuln_class": "idor_write"}
        pot = cr.score_finding(f, "funds", confirmed=False)
        con = cr.score_finding(f, "funds", confirmed=True)
        self.assertGreaterEqual(con["cvss_environmental"], pot["cvss_environmental"])

    def test_severity_tool_preserved(self):
        import criticality as cr
        f = {"name": "x", "severity": "low", "vuln_class": "ssrf"}
        out = cr.score_finding(f, "cde", confirmed=True)
        self.assertEqual(out["severity_tool"], "low")
```

- [ ] **Step 2: Rodar o teste para confirmar que falha**

Run: `python3 -m pytest tests/test_criticality.py::TestScoreFinding -v`
Expected: FAIL com `ModuleNotFoundError: No module named 'criticality'`

- [ ] **Step 3: Implementação mínima**

```python
#!/usr/bin/env python3
"""
criticality.py — Orquestra a criticidade CVSS 3.1 por finding.

Base (NVD > catálogo > estimado) → Temporal (confirmação) → Environmental
(classe do ativo). Funções puras. Proveniência explícita via score_source.
"""
import cvss
import vuln_catalog
import asset_classifier

# Fallback estimado: severidade qualitativa → vetor base conservador.
_ESTIMATED = {
    "critical": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "high":     "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "medium":   "AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
    "low":      "AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N",
    "info":     "AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:N",
}


def _resolve_base(finding):
    """Retorna (base_vector_str_sem_extras, score_source, cwe)."""
    nvd = finding.get("cvss_vector_nvd")
    if nvd:
        m = cvss.parse_vector(nvd)
        # Mantém só as 8 métricas base na string base.
        base_only = {k: m[k] for k in ("AV", "AC", "PR", "UI", "S", "C", "I", "A")}
        return cvss.to_vector(base_only)[len(cvss.PREFIX) + 1:], "nvd", finding.get("cwe", "")
    cls = finding.get("vuln_class") or finding.get("cwe")
    if cls:
        entry = vuln_catalog.lookup(cls)
        if entry:
            return entry["vector"], "catalog", entry["cwe"]
    sev = (finding.get("severity") or "info").lower()
    return _ESTIMATED.get(sev, _ESTIMATED["info"]), "estimated", finding.get("cwe", "")


def score_finding(finding, asset_class="default", confirmed=False):
    """Calcula a criticidade CVSS 3.1 completa de um finding."""
    base_vec, source, cwe = _resolve_base(finding)

    # Temporal a partir da confirmação.
    temporal = "E:H/RC:C" if confirmed else "E:P/RC:R"
    # Environmental a partir da classe do ativo.
    req = asset_classifier.requirements_for(asset_class)
    env = "/".join(f"{k}:{v}" for k, v in req.items())

    full = f"{cvss.PREFIX}/{base_vec}/{temporal}/{env}"
    m = cvss.parse_vector(full)

    base_s = cvss.base_score(m)
    temp_s = cvss.temporal_score(m)
    env_s = cvss.environmental_score(m)
    return {
        "cvss_vector": cvss.to_vector(m),
        "cvss_base": base_s,
        "cvss_temporal": temp_s,
        "cvss_environmental": env_s,
        "severity": cvss.band(env_s),
        "severity_tool": (finding.get("severity") or "info").lower(),
        "score_source": source,
        "asset_class": asset_class,
        "cwe": cwe,
        "requirements": req,
    }
```

- [ ] **Step 4: Rodar o teste para confirmar que passa**

Run: `python3 -m pytest tests/test_criticality.py::TestScoreFinding -v`
Expected: PASS (5 passed)

- [ ] **Step 5: Rodar TODA a suíte do motor**

Run: `python3 -m pytest tests/test_criticality.py -v`
Expected: PASS (todos)

- [ ] **Step 6: Commit**

```bash
git add lib/criticality.py tests/test_criticality.py
git commit -m "feat(criticality): orquestrador score_finding (base->temporal->env)"
```

---

## PARTE 3 — Integração

### Task 10: Enriquecer findings em `lib/evidence.py`

**Files:**
- Modify: `lib/evidence.py`
- Test: `tests/test_criticality.py`

- [ ] **Step 1: Ler o ponto de consolidação**

Run: `grep -n "def collect_and_consolidate\|findings\|severity" lib/evidence.py | head -30`
Objetivo: localizar a função que monta a lista final de findings (onde cada finding já tem `severity`, `url`/`host`, e possivelmente `cve_ids`/`confirmed`). Anotar o nome exato da função e a variável da lista de findings.

- [ ] **Step 2: Escrever o teste que falha**

```python
class TestEnrichFindings(unittest.TestCase):
    def test_enrich_adds_criticality_fields(self):
        import criticality as cr
        findings = [
            {"name": "IDOR", "severity": "medium", "vuln_class": "idor_read_pii",
             "url": "https://app-tokenize.dev2.example.com/api/x", "confirmed": True},
        ]
        out = cr.enrich_findings(findings, overrides=None)
        f = out[0]
        self.assertIn("cvss_environmental", f)
        self.assertEqual(f["asset_class"], "cde")
        self.assertEqual(f["severity_tool"], "medium")
        self.assertIn(f["severity"], ("high", "critical", "medium", "low", "info"))

    def test_enrich_infers_host_from_url(self):
        import criticality as cr
        findings = [{"name": "x", "severity": "high", "url": "https://www.example.com/p"}]
        out = cr.enrich_findings(findings, overrides=None)
        self.assertEqual(out[0]["asset_class"], "public")
```

- [ ] **Step 3: Rodar o teste para confirmar que falha**

Run: `python3 -m pytest tests/test_criticality.py::TestEnrichFindings -v`
Expected: FAIL com `AttributeError: module 'criticality' has no attribute 'enrich_findings'`

- [ ] **Step 4: Implementar `enrich_findings` em `lib/criticality.py`**

```python
import re as _re
from urllib.parse import urlparse as _urlparse


def _host_path(finding):
    url = finding.get("url") or finding.get("matched_at") or finding.get("host") or ""
    if "://" in url:
        p = _urlparse(url)
        return p.hostname or "", p.path or "/"
    # host puro
    return _re.sub(r"[:/].*$", "", url), "/"


def enrich_findings(findings, overrides=None):
    """Aplica score_finding a cada finding, in place, e devolve a lista.

    Usa finding['confirmed'] (bool) e infere a classe do ativo do host/path
    do finding (url/matched_at/host).
    """
    for f in findings:
        host, path = _host_path(f)
        asset_class = asset_classifier.classify_asset(host, path, overrides)
        scored = score_finding(f, asset_class=asset_class,
                               confirmed=bool(f.get("confirmed")))
        f.update(scored)
    return findings
```

- [ ] **Step 5: Rodar o teste para confirmar que passa**

Run: `python3 -m pytest tests/test_criticality.py::TestEnrichFindings -v`
Expected: PASS (2 passed)

- [ ] **Step 6: Chamar `enrich_findings` no fim da consolidação de `lib/evidence.py`**

No fim da função identificada no Step 1 (logo antes do `return` da lista de findings consolidada), inserir:

```python
    # Criticidade CVSS 3.1 por finding (Base+Temporal+Environmental).
    try:
        import criticality
        import json as _json
        _ov = None
        _ovp = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "assets.json")
        if os.path.exists(_ovp):
            with open(_ovp, encoding="utf-8") as _fh:
                _ov = _json.load(_fh)
        criticality.enrich_findings(findings, overrides=_ov)
    except Exception as _e:
        print(f"  [!] criticality: enrich falhou ({_e}) — mantendo severidade da ferramenta")
```

(Garantir que `import os` já existe no topo de `lib/evidence.py`; se não, adicioná-lo. Ajustar o nome da variável `findings` ao identificado no Step 1.)

- [ ] **Step 7: Rodar a suíte de evidence/parsers + criticality**

Run: `python3 -m pytest tests/test_lib.py tests/test_criticality.py -q`
Expected: PASS (sem regressão)

- [ ] **Step 8: Commit**

```bash
git add lib/criticality.py lib/evidence.py tests/test_criticality.py
git commit -m "feat(criticality): enrich_findings + integração no evidence"
```

---

### Task 11: `compute_risk` consome as bandas novas (`lib/risk_score.py`)

**Files:**
- Modify: `lib/risk_score.py`
- Test: `tests/test_lib.py`

- [ ] **Step 1: Ler o teste atual de risk_score**

Run: `grep -n "compute_risk\|def test" tests/test_lib.py | grep -i risk`
Objetivo: confirmar a assinatura/uso de `compute_risk` nos testes existentes (não quebrá-los).

- [ ] **Step 2: Escrever o teste que falha**

```python
# Em tests/test_lib.py, dentro da classe de testes de risk_score (ou nova classe):
    def test_compute_risk_uses_environmental_band_counts(self):
        import risk_score
        # stats derivadas das bandas finais (Environmental) — não da ferramenta
        stats = {"critical": 1, "high": 0, "medium": 0, "low": 0, "info": 0}
        out = risk_score.compute_risk(stats, {}, [], [])
        self.assertGreaterEqual(out["risk"], 70)  # 1 crítico → banda CRÍTICA
```

- [ ] **Step 3: Rodar para confirmar comportamento**

Run: `python3 -m pytest tests/test_lib.py -k compute_risk_uses_environmental -v`
Expected: PASS já com a implementação atual (a função já aceita stats por banda). Este teste **documenta o contrato**: `compute_risk` recebe contagens por banda final.

- [ ] **Step 4: Ajustar o chamador de `compute_risk`**

Run: `grep -rn "compute_risk" --include=*.py lib/ *.py`
No chamador (provavelmente `stiglitz_report.py`), garantir que o dict `stats` é montado a partir do campo `severity` **já enriquecido** (banda Environmental), não de `severity_tool`. Se o chamador conta `f["severity"]`, nenhuma mudança é necessária (o enrich já sobrescreveu `severity`). Documentar isso com um comentário no ponto de contagem:

```python
    # stats por banda FINAL (Environmental) — 'severity' já foi reescrita pelo
    # criticality.enrich_findings; 'severity_tool' guarda a original.
```

- [ ] **Step 5: Rodar a suíte completa**

Run: `python3 -m pytest tests/test_lib.py tests/test_criticality.py -q`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add lib/risk_score.py tests/test_lib.py stiglitz_report.py
git commit -m "feat(risk): agregado consome bandas Environmental por finding"
```

---

### Task 12: Exibir criticidade no relatório (`lib/report_generator.py`, `stiglitz_report.py`)

**Files:**
- Modify: `lib/report_generator.py`
- Modify: `stiglitz_report.py`
- Test: `tests/test_lib.py`

- [ ] **Step 1: Localizar o render de finding**

Run: `grep -n "_render_finding_card\|cvss\|MITRE\|security-severity\|def _build_html" lib/report_generator.py stiglitz_report.py`
Objetivo: localizar onde cada card de finding é montado (em RED: `_render_finding_card`; no scan: equivalente em `stiglitz_report.py`).

- [ ] **Step 2: Escrever o teste que falha**

```python
class TestReportShowsCriticality(unittest.TestCase):
    def test_card_includes_cvss_vector_and_source(self):
        # usa o gerador do RED report (já testado em TestReportGenerator)
        from report_generator import _render_finding_card
        f = {"sev": "High", "tool": "stiglitz", "title": "IDOR", "target": "https://x",
             "type": "stiglitz", "detail": "", "count": 1, "endpoints": [],
             "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N/E:H/RC:C/CR:H/IR:H",
             "cvss_environmental": 8.1, "score_source": "catalog", "asset_class": "cde"}
        html = _render_finding_card(1, f)
        self.assertIn("CVSS:3.1", html)
        self.assertIn("8.1", html)
        self.assertIn("cde", html)
```

- [ ] **Step 3: Rodar o teste para confirmar que falha**

Run: `python3 -m pytest tests/test_lib.py -k card_includes_cvss -v`
Expected: FAIL (o card ainda não imprime o vetor/score)

- [ ] **Step 4: Adicionar a linha de criticidade ao card em `_render_finding_card`**

Logo após a linha que monta a `<table>` do card (a que mostra Target/MITRE/Impact), inserir uma linha extra quando os campos existirem:

```python
    if f.get("cvss_vector"):
        _src = f.get("score_source", "")
        _est = " <em>(estimado)</em>" if _src == "estimated" else ""
        h += (f'<tr><th>CVSS</th><td><code>{esc(f["cvss_vector"])}</code> '
              f'— <strong>{f.get("cvss_environmental", "")}</strong> '
              f'[{esc(f.get("asset_class", ""))} · {esc(_src)}]{_est}</td></tr>\n')
```

(Inserir dentro da construção da tabela, antes do fechamento `</table>`. Ajustar à estrutura exata vista no Step 1.)

- [ ] **Step 5: Rodar o teste para confirmar que passa**

Run: `python3 -m pytest tests/test_lib.py -k card_includes_cvss -v`
Expected: PASS

- [ ] **Step 6: Replicar no relatório de scan (`stiglitz_report.py`)**

No ponto equivalente de render de finding identificado no Step 1, adicionar a mesma linha de CVSS (vetor + score Environmental + asset_class + proveniência, com aviso `estimado`). Se `stiglitz_report.py` tiver teste E2E (`tests/test_e2e.py`), rodar para garantir que o HTML continua sendo gerado.

Run: `python3 -m pytest tests/test_e2e.py -q`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add lib/report_generator.py stiglitz_report.py tests/test_lib.py
git commit -m "feat(report): exibe vetor CVSS, score Environmental, ativo e proveniência"
```

---

### Task 13: `security-severity` do SARIF = score Environmental (`lib/report/sarif.py`)

**Files:**
- Modify: `lib/report/sarif.py`
- Test: `tests/test_lib.py` (ou onde houver teste de SARIF)

- [ ] **Step 1: Localizar a geração de security-severity**

Run: `grep -n "security-severity\|securitySeverity\|cvss\|severity" lib/report/sarif.py`
Objetivo: achar onde a propriedade `security-severity` (string numérica) é setada por resultado.

- [ ] **Step 2: Escrever/ajustar o teste que falha**

```python
class TestSarifEnvironmental(unittest.TestCase):
    def test_security_severity_uses_environmental(self):
        import importlib, sys, os
        sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "lib", "report"))
        import sarif
        f = {"name": "IDOR", "severity": "high", "cvss_environmental": 8.1}
        # função existente que mapeia finding -> result SARIF (ver nome no Step 1)
        result = sarif.finding_to_result(f) if hasattr(sarif, "finding_to_result") else None
        self.assertIsNotNone(result, "ajustar para o nome real da função em sarif.py")
        ss = result["properties"]["security-severity"]
        self.assertEqual(str(ss), "8.1")
```

(Ajustar `finding_to_result`/caminho de `security-severity` ao identificado no Step 1.)

- [ ] **Step 3: Rodar para confirmar que falha**

Run: `python3 -m pytest tests/test_lib.py -k security_severity_uses_environmental -v`
Expected: FAIL

- [ ] **Step 4: Usar `cvss_environmental` como `security-severity`**

No ponto identificado, preferir `cvss_environmental` quando presente:

```python
    ss = finding.get("cvss_environmental")
    if ss is None:
        ss = _SEVERITY_TO_SCORE.get((finding.get("severity") or "").lower(), 0.0)
    result_properties["security-severity"] = str(ss)
```

(`_SEVERITY_TO_SCORE` é o mapa já existente; se não existir, manter o fallback atual do arquivo.)

- [ ] **Step 5: Rodar o teste + validar SARIF**

Run: `python3 -m pytest tests/test_lib.py -k security_severity_uses_environmental -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add lib/report/sarif.py tests/test_lib.py
git commit -m "feat(sarif): security-severity usa score Environmental"
```

---

### Task 14: Suíte completa + atualização de CI/docs

**Files:**
- Modify: `.github/workflows/ci.yml`
- Test: toda a suíte

- [ ] **Step 1: Adicionar o teste de criticality ao CI**

Em `.github/workflows/ci.yml`, na linha do pytest de unit tests, acrescentar `tests/test_criticality.py`:

```yaml
        run: python3 -m pytest tests/test_lib.py tests/test_stiglitz_modules.py tests/test_pipeline.py tests/test_e2e.py tests/test_email_spoof.py tests/test_criticality.py -v --tb=short
```

- [ ] **Step 2: Rodar a suíte completa local**

Run: `python3 -m pytest tests/test_lib.py tests/test_stiglitz_modules.py tests/test_pipeline.py tests/test_e2e.py tests/test_email_spoof.py tests/test_criticality.py -q`
Expected: PASS (todos)

- [ ] **Step 3: Rodar a suíte bash (sanidade)**

Run: `bash tests/test_stiglitz_red.sh`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: inclui tests/test_criticality.py na suíte"
```

---

## Self-Review (preenchido)

- **Cobertura do spec:** §3 metodologia → Tasks 1-5,9; §3.1/3.2 classes/inferência → Task 8; §4.1 catálogo → Task 7; §5 schema de saída → Tasks 9-10; §6 integração → Tasks 10-13; §8 testes/validação → Tasks 6,9,14; §9 erros → Tasks 1,9 (exceções tipadas, fallback estimado sinalizado). Todos os requisitos têm task.
- **Placeholders:** nenhum passo de código sem código. Tasks de integração (10-13) começam com um Step de localização (grep) porque tocam arquivos existentes cujos números de linha variam — o código a inserir é fornecido integralmente.
- **Consistência de tipos:** `score_finding`/`enrich_findings` usam os mesmos nomes de campo do schema (§5) em todas as tasks; `cvss.parse_vector`/`base_score`/`temporal_score`/`environmental_score`/`band`/`to_vector` definidos nas Tasks 1-5 e usados consistentemente depois.

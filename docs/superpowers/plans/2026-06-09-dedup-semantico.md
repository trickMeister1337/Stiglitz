# Dedup Semântico — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Colapsar findings que são o mesmo problema mas escapam do dedup sintático por-fonte (cross-tool + variantes de path/param + fuzzy por CVE/título), com contagem consistente em HTML, SARIF, finding_state e trackers.

**Architecture:** Módulo puro `lib/dedup.py` (lógica + CLI), reusando `lib/fingerprint.py`. Dois estágios: bucket exato por fingerprint (O(n)) + fuzzy entre representantes do mesmo host (score único agressivo ≥ threshold). Integrado em dois call-sites: `stiglitz_report.py` (scan, antes de enrich/state/SARIF/HTML) e `lib/evidence.py` (RED, substituindo o dedup cru). Degrada sem abortar nos dois pontos.

**Tech Stack:** Python 3 (stdlib: `difflib`, `re`, `urllib.parse`, `hashlib` via fingerprint), pytest. Sem dependências novas.

**Spec:** `docs/superpowers/specs/2026-06-09-dedup-semantico-design.md`

---

## File Structure

- **Create** `lib/dedup.py` — módulo puro de dedup semântico (helpers + `dedupe()` + CLI). Responsabilidade única: dado uma lista de findings, devolver a lista colapsada.
- **Create** `tests/test_dedup.py` — testes unitários do módulo.
- **Modify** `stiglitz_report.py` (~linha 970) — chama `dedupe` em `_all_f_raw` antes de enrich/sort/state/SARIF.
- **Modify** `lib/evidence.py` (~linhas 391-397) — substitui o dedup cru por `dedupe` com fallback legado.
- **Modify** `CLAUDE.md` (tabela `lib/`) e `docs/ROADMAP.md` (marcar item P2).

Convenção de import nos testes (padrão do repo): `sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))` e `import dedup as D`.

---

## Task 1: `lib/dedup.py` — helpers + estágio 1 (bucket exato) + merge

**Files:**
- Create: `lib/dedup.py`
- Test: `tests/test_dedup.py`

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_dedup.py
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
import dedup as D


def test_exact_cross_tool_merge():
    fs = [
        {"name": "Reflected XSS", "cwe": "CWE-79", "url": "http://t/s", "param": "q",
         "severity": "high", "tool": "nuclei", "count": 1},
        {"name": "Cross Site Scripting", "cwe": "CWE-79", "url": "http://t/s", "param": "q",
         "severity": "medium", "tool": "zap", "count": 1},
    ]
    out = D.dedupe(fs)
    assert len(out) == 1
    assert out[0]["severity"] == "high"            # severidade máxima
    assert out[0]["count"] == 2                     # soma
    assert set(out[0]["sources"]) == {"nuclei", "zap"}
    assert len(out[0]["merged_from"]) == 1          # mesmo fingerprint
    assert out[0]["merge_score"] == 1.0             # bucket exato


def test_path_variant_collapse():
    fs = [{"cwe": "CWE-89", "url": f"http://t/user/{i}/orders", "param": "id",
           "name": "SQLi", "severity": "high", "tool": "nuclei"} for i in (1, 2, 3)]
    out = D.dedupe(fs)
    assert len(out) == 1
    assert len(out[0]["endpoints"]) == 3            # /user/1, /user/2, /user/3 unidos


def test_red_target_form():
    fs = [
        {"type": "xss", "target": "http://t/p", "sev": "Medium", "tool": "zap", "count": 1},
        {"type": "xss", "target": "http://t/p", "sev": "High", "tool": "nuclei", "count": 1},
    ]
    out = D.dedupe(fs)
    assert len(out) == 1
    assert out[0]["count"] == 2


def test_singleton_passes_through_unchanged():
    f = {"cwe": "CWE-79", "url": "http://t/a", "param": "q", "name": "x", "tool": "nuclei"}
    out = D.dedupe([f])
    assert len(out) == 1
    assert out[0] is f                              # não muta nem copia singleton


def test_degrade_on_malformed():
    out = D.dedupe([{"name": "x"}, {}, {"url": "http://t/a", "cwe": "CWE-79"}])
    assert isinstance(out, list)                    # não levanta
    assert len(out) == 3                             # fingerprints distintos → nenhum merge
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /home/trick/Stiglitz && python3 -m pytest tests/test_dedup.py -v`
Expected: FAIL com `ModuleNotFoundError: No module named 'dedup'`.

- [ ] **Step 3: Write minimal implementation (helpers + estágio 1 + merge)**

```python
# lib/dedup.py
#!/usr/bin/env python3
"""
dedup.py — dedup semântico de findings (P2).

Colapsa findings que são o MESMO problema mas escapam do dedup sintático por-fonte:
duplicatas cross-tool (nuclei+ZAP+retire no mesmo CWE/lugar) e variantes de path/param.

Estágios:
  1. bucket exato por fingerprint (classe, host, path-template, param) — O(n).
  2. fuzzy entre representantes do MESMO host: score único (CVE/classe/título/evidência)
     >= threshold -> mescla. (Task 2)

Auto-merge agressivo (sem gate de revisão). Proveniência no próprio finding
(sources/merged_from/merge_score). Puro — sem rede. Reusa fingerprint.py.
"""
import os
import re
import sys
import json
import difflib
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fingerprint as _fp  # noqa: E402

DEFAULT_THRESHOLD = float(os.environ.get("STIGLITZ_DEDUP_THRESHOLD", "0.80"))
W_CLASS = 0.30
W_TITLE = 0.50
W_EVIDENCE = 0.20

_SEV_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2,
             "info": 1, "informational": 1}
_CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.I)
_VERSION_RE = re.compile(r"\b\d+(?:\.\d+)+\b")
_WORD_RE = re.compile(r"[a-z0-9]+")


def _url(f):
    return f.get("url") or f.get("target") or f.get("matched_at") or ""


def _host(f):
    return urllib.parse.urlsplit(_url(f)).netloc or f.get("host", "") or ""


def _cve_str(f):
    v = f.get("cve", "")
    if isinstance(v, (list, tuple, set)):
        return " ".join(str(x) for x in v)
    return str(v or "")


def _shim(f):
    """View normalizada p/ fingerprint/vuln_class — tolera scan(url) e RED(target)."""
    return {"url": _url(f), "host": _host(f), "param": f.get("param", ""),
            "cwe": f.get("cwe", ""), "cve": _cve_str(f),
            "type": f.get("type", ""), "name": f.get("name") or f.get("title", "")}


def _fp_of(f):
    return _fp.fingerprint(_shim(f))


def _class(f):
    return _fp.vuln_class(_shim(f))


def _sev(f):
    s = str(f.get("severity") or f.get("sev") or "info").strip().lower()
    return _SEV_RANK.get(s, 1)


def _tool(f):
    return f.get("tool") or f.get("source") or ""


def _cves(f):
    return {m.group(0).upper() for m in _CVE_RE.finditer(_cve_str(f))}


def _merge(group):
    """Coalesce um grupo de findings num único. Singleton passa inalterado."""
    if len(group) == 1:
        return group[0]
    top = max(_sev(f) for f in group)
    rep = min((f for f in group if _sev(f) == top), key=_fp_of)  # determinístico
    m = dict(rep)                                                # preserva escalares
    m["count"] = sum(int(f.get("count") or 1) for f in group)
    eps = []
    for f in group:
        for e in (f.get("endpoints") or []):
            if e and e not in eps:
                eps.append(e)
        u = _url(f)
        if u and u not in eps:
            eps.append(u)
    m["endpoints"] = eps
    m["sources"] = sorted({_tool(f) for f in group if _tool(f)})
    cves = sorted(set().union(*[_cves(f) for f in group]))
    if cves:
        m["cves"] = cves
    m["merged_from"] = sorted({_fp_of(f) for f in group})
    exact = len({_fp_of(f) for f in group}) == 1
    m["merge_score"] = 1.0 if exact else round(
        max(_score(rep, f) for f in group if f is not rep), 4)
    m["fingerprint"] = _fp_of(rep)
    return m


def dedupe(findings, threshold=None):
    """Colapsa findings semanticamente equivalentes. Determinístico, sem rede.
    Não muta a entrada; singletons passam inalterados."""
    if not findings:
        return list(findings or [])
    if threshold is None:
        threshold = DEFAULT_THRESHOLD

    # Estágio 1 — bucket exato por fingerprint (preserva ordem de 1ª aparição).
    order, buckets = [], {}
    for f in findings:
        try:
            fp = _fp_of(f)
        except Exception:
            fp = ("__bad__", id(f))                 # malformado -> bucket próprio
        if fp not in buckets:
            buckets[fp] = []
            order.append(fp)
        buckets[fp].append(f)
    groups = [buckets[fp] for fp in order]

    # Estágio 2 (fuzzy) entra na Task 2; por ora, 1 grupo = 1 saída.
    return [_merge(g) for g in groups]
```

> Nota: `_score` é referenciado por `_merge` mas só é definido na Task 2. Para a Task 1
> rodar isolada, `_merge` só chama `_score` quando `exact is False`, e na Task 1 todos os
> grupos vêm de bucket exato (estágio 1 apenas) → `exact` é sempre `True` → `_score` nunca
> é chamado. Os testes da Task 1 passam sem `_score` definido.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /home/trick/Stiglitz && python3 -m pytest tests/test_dedup.py -v && python3 -m py_compile lib/dedup.py`
Expected: PASS (5 testes) + py_compile sem erro.

- [ ] **Step 5: Commit**

```bash
cd /home/trick/Stiglitz
git add lib/dedup.py tests/test_dedup.py
git commit -m "feat(dedup): módulo lib/dedup.py — estágio 1 (bucket exato por fingerprint)

Colapsa cross-tool idêntico + variantes de path/param via fingerprint.
Merge preserva sources/merged_from/count/endpoints; singleton inalterado.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 2: estágio 2 (fuzzy) — CVE compartilhado + similaridade de título/evidência

**Files:**
- Modify: `lib/dedup.py`
- Test: `tests/test_dedup.py`

- [ ] **Step 1: Write the failing tests**

```python
# Acrescentar em tests/test_dedup.py

def test_fuzzy_merge_shared_cve():
    fs = [
        {"name": "Apache RCE", "cve": "CVE-2021-41773", "cwe": "CWE-22",
         "url": "http://t/", "severity": "critical", "tool": "nuclei"},
        {"name": "Path traversal Apache", "cve": "CVE-2021-41773", "cwe": "CWE-98",
         "url": "http://t/", "severity": "high", "tool": "nmap"},
    ]
    out = D.dedupe(fs)
    assert len(out) == 1                            # CVE igual -> merge mesmo c/ CWE divergente
    assert out[0]["severity"] == "critical"
    assert len(out[0]["merged_from"]) == 2          # 2 fingerprints distintos


def test_fuzzy_title_above_threshold_merges():
    # mesmo host + mesma classe, paths diferentes (fingerprints diferentes),
    # título/evidência quase idênticos -> score acima do threshold.
    fs = [
        {"name": "Server version disclosure in header", "cwe": "CWE-200",
         "url": "http://t/login", "severity": "low", "tool": "nuclei",
         "evidence": "Server: nginx disclosed"},
        {"name": "Server version disclosure in header", "cwe": "CWE-200",
         "url": "http://t/admin", "severity": "low", "tool": "zap",
         "evidence": "Server: nginx disclosed"},
    ]
    out = D.dedupe(fs)
    assert len(out) == 1


def test_fuzzy_below_threshold_kept_separate():
    # mesma classe + host, mas títulos/evidência divergentes -> score < threshold.
    fs = [
        {"name": "SQL injection in search", "cwe": "CWE-89", "url": "http://t/search",
         "severity": "high", "tool": "nuclei", "evidence": "error-based payload"},
        {"name": "Open redirect on logout", "cwe": "CWE-89", "url": "http://t/logout",
         "severity": "high", "tool": "zap", "evidence": "location header attacker"},
    ]
    out = D.dedupe(fs)
    assert len(out) == 2


def test_distinct_host_never_merges():
    # CVE igual mas hosts distintos -> fingerprint difere e fuzzy é blocado por host.
    fs = [
        {"name": "X", "cve": "CVE-2021-1234", "url": "http://a/p", "severity": "high", "tool": "nuclei"},
        {"name": "X", "cve": "CVE-2021-1234", "url": "http://b/p", "severity": "high", "tool": "nuclei"},
    ]
    out = D.dedupe(fs)
    assert len(out) == 2
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /home/trick/Stiglitz && python3 -m pytest tests/test_dedup.py -k fuzzy -v`
Expected: FAIL — `test_fuzzy_merge_shared_cve` e `test_fuzzy_title_above_threshold_merges` retornam 2 (sem estágio 2). (`below_threshold` e `distinct_host` já passam por acidente, mas confirmam o comportamento depois.)

- [ ] **Step 3: Add `_score` and the fuzzy agglomeration stage**

Adicionar `_score` e helpers de texto após `_cves` (antes de `_merge`):

```python
def _title(f):
    return str(f.get("name") or f.get("title") or f.get("type") or "")


def _norm_title(f):
    t = _VERSION_RE.sub(" ", _title(f).lower())
    return " ".join(_WORD_RE.findall(t))


def _evidence_txt(f):
    raw = str(f.get("evidence") or f.get("detail") or "").lower()
    return " ".join(_WORD_RE.findall(raw))


def _ratio(a, b):
    if not a and not b:
        return 0.0
    return difflib.SequenceMatcher(None, a, b).ratio()


def _score(a, b):
    """Score combinado [0,1]. CVE compartilhado -> 1.0 (merge imediato)."""
    if _cves(a) & _cves(b):
        return 1.0
    if _host(a) != _host(b):                        # defensivo (já blocado por host)
        return 0.0
    s = W_CLASS if _class(a) == _class(b) else 0.0
    s += W_TITLE * _ratio(_norm_title(a), _norm_title(b))
    s += W_EVIDENCE * _ratio(_evidence_txt(a), _evidence_txt(b))
    return s
```

Substituir o `return` final de `dedupe` (a linha `# Estágio 2 (fuzzy)...` + o `return`) por:

```python
    # Estágio 2 — fuzzy entre representantes do MESMO host (union-find guloso).
    reps = [g[0] for g in groups]
    parent = list(range(len(groups)))

    def find(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    def union(i, j):
        ri, rj = find(i), find(j)
        if ri != rj:
            parent[max(ri, rj)] = min(ri, rj)

    by_host = {}
    for i, r in enumerate(reps):
        by_host.setdefault(_host(r), []).append(i)
    for idxs in by_host.values():
        for a in range(len(idxs)):
            for b in range(a + 1, len(idxs)):
                try:
                    if _score(reps[idxs[a]], reps[idxs[b]]) >= threshold:
                        union(idxs[a], idxs[b])
                except Exception:
                    pass

    coalesced, out_order = {}, []
    for i in range(len(groups)):
        root = find(i)
        if root not in coalesced:
            coalesced[root] = []
            out_order.append(root)
        coalesced[root].extend(groups[i])
    return [_merge(coalesced[r]) for r in out_order]
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /home/trick/Stiglitz && python3 -m pytest tests/test_dedup.py -v && python3 -m py_compile lib/dedup.py`
Expected: PASS (9 testes).

- [ ] **Step 5: Commit**

```bash
cd /home/trick/Stiglitz
git add lib/dedup.py tests/test_dedup.py
git commit -m "feat(dedup): estágio 2 fuzzy — CVE compartilhado + similaridade título/evidência

Union-find guloso entre representantes do mesmo host (bloqueio por host
segura o O(n^2) e evita merge cross-host). Score único agressivo >= threshold.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 3: CLI + validação ao vivo

**Files:**
- Modify: `lib/dedup.py`
- Test: `tests/test_dedup.py`

- [ ] **Step 1: Write the failing test**

```python
# Acrescentar em tests/test_dedup.py

def test_summary_string():
    fs = [{"cwe": "CWE-79", "url": "http://t/s", "param": "q", "name": "x", "tool": "nuclei"},
          {"cwe": "CWE-79", "url": "http://t/s", "param": "q", "name": "x", "tool": "zap"}]
    out = D.dedupe(fs)
    s = D._summary(fs, out)
    assert "2 findings" in s and "1" in s           # 2 -> 1 (1 merge)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /home/trick/Stiglitz && python3 -m pytest tests/test_dedup.py::test_summary_string -v`
Expected: FAIL com `AttributeError: module 'dedup' has no attribute '_summary'`.

- [ ] **Step 3: Add `_summary` + CLI entrypoint**

Adicionar ao fim de `lib/dedup.py`:

```python
def _summary(findings, deduped):
    n, m = len(findings), len(deduped)
    return f"{n} findings -> {m} após dedup ({n - m} merges)"


def _main(argv):
    if not argv:
        print("uso: python3 dedup.py <findings.json>", file=sys.stderr)
        return 2
    try:
        with open(argv[0], encoding="utf-8") as fh:
            data = json.load(fh)
    except Exception as e:
        print(f"[x] não consegui ler {argv[0]}: {e}", file=sys.stderr)
        return 1
    findings = data.get("findings", data) if isinstance(data, dict) else data
    if not isinstance(findings, list):
        print("[x] entrada não é lista de findings", file=sys.stderr)
        return 1
    deduped = dedupe(findings)
    print(_summary(findings, deduped), file=sys.stderr)
    print(json.dumps(deduped, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /home/trick/Stiglitz && python3 -m pytest tests/test_dedup.py -v && python3 -m py_compile lib/dedup.py`
Expected: PASS (10 testes).

- [ ] **Step 5: Validação ao vivo num findings.json real**

Run (escolher um scan real existente, sem versionar o dado):
```bash
cd /home/trick/Stiglitz
F=$(ls -1 ~/scans/*/findings.json ~/scans/*/*/findings.json 2>/dev/null | head -1)
echo "alvo: $F"
python3 lib/dedup.py "$F" > /tmp/dedup_out.json
```
Expected: linha em stderr no formato `N findings -> M após dedup (K merges)` com `M <= N`, sem traceback. Inspecionar 1-2 merges em `/tmp/dedup_out.json` (campo `sources`/`merged_from`) e confirmar que não há merge cross-host/cross-classe óbvio. Se nenhum `findings.json` existir, pular com nota (validação fica para o run de integração da Task 4).

- [ ] **Step 6: Commit**

```bash
cd /home/trick/Stiglitz
git add lib/dedup.py tests/test_dedup.py
git commit -m "feat(dedup): CLI (python3 lib/dedup.py <findings.json>) + resumo N->M

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 4: Integração no path do scan (`stiglitz_report.py`)

**Files:**
- Modify: `stiglitz_report.py` (logo após a linha 970, onde `_all_f_raw` é montado)

- [ ] **Step 1: Confirmar o ponto de inserção**

Run: `cd /home/trick/Stiglitz && grep -n "_all_f_raw = findings" stiglitz_report.py`
Expected: a linha `_all_f_raw = findings + zap_findings + header_findings + version_findings + tls_findings + email_findings` (~970). O dedup entra imediatamente DEPOIS dela e ANTES de `_criticality.enrich_findings(_all_f_raw, ...)` (~979).

- [ ] **Step 2: Inserir a chamada guardada**

Inserir logo após a linha `_all_f_raw = findings + zap_findings + ...`:

```python
# (P2) Dedup semântico cross-tool + fuzzy ANTES de enrich/sort/state/SARIF/HTML —
# garante contagem consistente em todos os artefatos. Degrada sem abortar.
if os.environ.get("STIGLITZ_DEDUP", "1") != "0":
    try:
        import dedup as _dedup
        _n_before = len(_all_f_raw)
        _all_f_raw = _dedup.dedupe(_all_f_raw)
        print(f"[✓] Dedup semântico: {_n_before} → {len(_all_f_raw)} findings")
    except Exception as _dd_e:
        print(f"[!] dedup: falhou ({_dd_e}) — mantendo findings não-deduplicados")
```

> `os` já está importado no topo do `stiglitz_report.py`; `lib/` já está no `sys.path`
> (o script importa `fingerprint`, `criticality`, etc.). O `import dedup` está dentro do
> `try` — se a resolução falhar, degrada para a lista não-deduplicada.

- [ ] **Step 3: py_compile**

Run: `cd /home/trick/Stiglitz && python3 -m py_compile stiglitz_report.py`
Expected: sem saída (sucesso).

- [ ] **Step 4: Validação ao vivo (regenera relatório de um scan existente)**

Run (usar um scan dir real; gera HTML/SARIF/state a partir do `raw/` sem re-scan):
```bash
cd /home/trick/Stiglitz
D=$(ls -1d ~/scans/*/ 2>/dev/null | head -1)   # ou um scan_*/ local
echo "scan dir: $D"
python3 stiglitz_report.py "$D" 2>&1 | grep -E "Dedup semântico|Finding state|findings.sarif" || true
```
Expected: linha `[✓] Dedup semântico: N → M findings` (M ≤ N), seguida de `Finding state: ...` e geração do SARIF sem erro. Confirma que o dedup roda a montante de state/SARIF. Se nenhum scan dir for utilizável, registrar e validar no ambiente do próximo scan real.

- [ ] **Step 5: Rodar a suíte completa (garante zero regressão)**

Run: `cd /home/trick/Stiglitz && python3 -m pytest tests/ -q`
Expected: toda a suíte passa (inclui os 10 de `test_dedup.py`).

- [ ] **Step 6: Commit**

```bash
cd /home/trick/Stiglitz
git add stiglitz_report.py
git commit -m "feat(dedup): wire dedup semântico no scan-path (stiglitz_report.py)

Deduplica _all_f_raw antes de enrich/sort/state/SARIF/HTML — contagem
consistente em todos os artefatos. STIGLITZ_DEDUP=0 desliga; degrada sem abortar.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 5: Integração no path do RED (`lib/evidence.py`)

**Files:**
- Modify: `lib/evidence.py` (~linhas 391-397, dentro de `collect_and_consolidate`)

- [ ] **Step 1: Confirmar o bloco a substituir**

Run: `cd /home/trick/Stiglitz && sed -n '391,398p' lib/evidence.py`
Expected: o bloco `# Dedup` com `key = (f["tool"], f["type"], f.get("target", "")[:60])`.

- [ ] **Step 2: Extrair o dedup legado para um helper (fallback) no topo do módulo**

Adicionar como função module-level em `lib/evidence.py` (após os imports, antes de `collect_and_consolidate`):

```python
def _legacy_dedup(findings):
    """Dedup cru por (tool, type, target[:60]) — fallback quando lib/dedup.py falha."""
    seen, out = set(), []
    for f in findings:
        key = (f.get("tool"), f.get("type"), f.get("target", "")[:60])
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out
```

- [ ] **Step 3: Substituir o bloco cru pela chamada ao dedup semântico**

Trocar:

```python
    # Dedup
    seen: set = set()
    deduped = []
    for f in findings:
        key = (f["tool"], f["type"], f.get("target", "")[:60])
        if key not in seen:
            seen.add(key); deduped.append(f)
```

por:

```python
    # Dedup semântico (lib/dedup.py) — cross-tool + fuzzy; degrada p/ dedup cru legado.
    if os.environ.get("STIGLITZ_DEDUP", "1") != "0":
        try:
            import dedup as _dedup
            deduped = _dedup.dedupe(findings)
        except Exception as _dd_e:
            print(f"  [!] dedup: falhou ({_dd_e}) — fallback dedup cru")
            deduped = _legacy_dedup(findings)
    else:
        deduped = _legacy_dedup(findings)
```

> `os` já está importado em `evidence.py` (linha 9). `import dedup` resolve do mesmo
> `lib/` (o módulo já faz `import criticality` mais abaixo sem manipular `sys.path`).

- [ ] **Step 4: Teste de fallback (não depende de scan real)**

Adicionar em `tests/test_dedup.py`:

```python
def test_evidence_legacy_dedup_fallback():
    import importlib
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
    ev = importlib.import_module("evidence")
    fs = [{"tool": "zap", "type": "xss", "target": "http://t/p"},
          {"tool": "zap", "type": "xss", "target": "http://t/p"},
          {"tool": "nuclei", "type": "sqli", "target": "http://t/q"}]
    out = ev._legacy_dedup(fs)
    assert len(out) == 2                            # colapsa a duplicata exata zap/xss
```

- [ ] **Step 5: Run + py_compile**

Run: `cd /home/trick/Stiglitz && python3 -m pytest tests/test_dedup.py -v && python3 -m py_compile lib/evidence.py`
Expected: PASS (11 testes) + py_compile sem erro.

- [ ] **Step 6: Commit**

```bash
cd /home/trick/Stiglitz
git add lib/evidence.py tests/test_dedup.py
git commit -m "feat(dedup): wire dedup semântico no RED-path (evidence.py) + fallback legado

Substitui a chave crua (tool,type,target[:60]) por lib/dedup.dedupe; mantém
o dedup cru como _legacy_dedup p/ degradação. STIGLITZ_DEDUP=0 desliga.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 6: Docs — `CLAUDE.md` + `ROADMAP.md`

**Files:**
- Modify: `CLAUDE.md` (tabela de módulos `lib/`)
- Modify: `docs/ROADMAP.md` (item P2)

- [ ] **Step 1: Adicionar linha na tabela `lib/` do `CLAUDE.md`**

Inserir na tabela de módulos (após a linha de `finding_state.py`, mantendo o estilo):

```markdown
| `dedup.py` | Dedup semântico de findings (P2) — colapsa duplicatas cross-tool + variantes de path/param via fingerprint (estágio 1) e fuzzy por CVE/título/evidência blocado por host (estágio 2). Auto-merge agressivo; proveniência no finding (`sources`/`merged_from`/`merge_score`). Roda no scan (`stiglitz_report.py`, antes de state/SARIF) e no RED (`evidence.py`). `STIGLITZ_DEDUP=0` desliga; `STIGLITZ_DEDUP_THRESHOLD` ajusta. Lógica pura + CLI |
```

- [ ] **Step 2: Atualizar o ROADMAP**

Em `docs/ROADMAP.md`, na seção `## P2 — BACKLOG`, remover `dedup semântico;` da lista e registrar como concluído (seguir o estilo dos itens P1 feitos, ex. uma linha `- ✅ **dedup semântico** (`lib/dedup.py`): ...`). Não incluir dado de alvo.

- [ ] **Step 3: Commit**

```bash
cd /home/trick/Stiglitz
git add CLAUDE.md docs/ROADMAP.md
git commit -m "docs(dedup): registra lib/dedup.py no CLAUDE.md + marca item P2 no ROADMAP

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Self-Review (preenchido)

**Spec coverage:**
- Cross-tool + fuzzy → Tasks 1 (exato) + 2 (fuzzy). ✓
- Auto-merge agressivo, score único, sem audit separado → `_score` + threshold, sem `dedup_report`. ✓
- Proveniência no finding → `_merge` (`sources`/`merged_from`/`merge_score`/`endpoints`/`cves`). ✓
- Módulo compartilhado, ambos os paths → Task 4 (scan) + Task 5 (RED). ✓
- Fingerprint representante estável p/ finding_state → `_merge` define `fingerprint=_fp_of(rep)`, e a linha 1023 do report recomputa idêntico. ✓
- `STIGLITZ_DEDUP=0` / threshold env → presente nos dois call-sites e em `DEFAULT_THRESHOLD`. ✓
- Degradação sem abortar → try/except nos dois call-sites + fallback legado no RED. ✓
- CLI → Task 3. ✓
- Testes do spec (8 casos) → cobertos em Tasks 1-3 (cross-tool, path-variant, CVE-fuzzy, boundary, guard, severity/count/merged_from, malformado, forma RED). ✓
- Validação ao vivo → Task 3 Step 5 + Task 4 Step 4. ✓

**Placeholder scan:** sem TBD/TODO; todo step de código mostra o código real. A única dependência forward (`_score` usado por `_merge` na Task 1) está explicada: não é exercido na Task 1 (todos os grupos são exatos → `exact=True`). ✓

**Type consistency:** `dedupe`/`_merge`/`_score`/`_summary`/`_fp_of`/`_class`/`_host`/`_url`/`_cves` usados com a mesma assinatura em todas as tasks. Campos do finding mesclado (`sources`,`merged_from`,`merge_score`,`endpoints`,`cves`,`fingerprint`,`count`) consistentes entre `_merge` e os asserts dos testes. ✓

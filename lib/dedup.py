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
    # str() defensivo: tolera url/target não-string (mantém o estágio 2 robusto,
    # simetria com a tolerância a malformados do estágio 1).
    return str(f.get("url") or f.get("target") or f.get("matched_at") or "")


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
    fps = {_fp_of(f) for f in group}
    m["merged_from"] = sorted(fps)
    exact = len(fps) == 1
    if exact:
        m["merge_score"] = 1.0
    else:
        try:
            m["merge_score"] = round(
                max(_score(rep, f) for f in group if f is not rep), 4)
        except Exception:
            m["merge_score"] = None
    m["fingerprint"] = _fp_of(rep)
    return m


def dedupe(findings, threshold=None):
    """Colapsa findings semanticamente equivalentes. Determinístico, sem rede.
    Não muta a entrada; singletons passam inalterados."""
    if not findings:
        return list(findings or [])
    if threshold is None:
        threshold = DEFAULT_THRESHOLD  # threshold só é exercido no estágio 2 (fuzzy)

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

    # Agrupa por host: O(n^2) só DENTRO de cada host. Findings sem host caem no bucket
    # "" — raro em scans reais (host-less é exceção); não há cap explícito.
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

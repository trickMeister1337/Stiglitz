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
    fps = {_fp_of(f) for f in group}
    m["merged_from"] = sorted(fps)
    exact = len(fps) == 1
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

    # Estágio 2 (fuzzy) entra na Task 2; por ora, 1 grupo = 1 saída.
    return [_merge(g) for g in groups]

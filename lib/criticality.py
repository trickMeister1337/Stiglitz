#!/usr/bin/env python3
"""
criticality.py — Orquestra a criticidade CVSS 3.1 por finding.

Base (NVD > catálogo > estimado) → Temporal (confirmação) → Environmental
(classe do ativo). Funções puras. Proveniência explícita via score_source.
"""
import re as _re
from urllib.parse import urlparse as _urlparse

import cvss
import vuln_catalog
import asset_classifier

_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

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


def score_finding(finding, asset_class="default", confirmed=False,
                  in_kev=False, epss=0.0):
    """Calcula a criticidade CVSS 3.1 completa de um finding.

    Temporal KEV/EPSS-aware:
      - Confirmado por PoC/OOB  OU  CVE em CISA KEV  OU  EPSS ≥ 0.5  → E:H/RC:C/RL:U
      - EPSS em [0.1, 0.5)                                             → E:F/RC:C/RL:U
      - Caso contrário (teórico)                                       → E:P/RC:R/RL:U

    RL:U está sempre presente em todos os casos.
    """
    base_vec, source, cwe = _resolve_base(finding)

    # Temporal: regra KEV/EPSS-aware (RL:U sempre presente).
    epss = epss or 0.0
    if confirmed or in_kev or epss >= 0.5:
        temporal = "E:H/RC:C/RL:U"
    elif epss >= 0.1:
        temporal = "E:F/RC:C/RL:U"
    else:
        temporal = "E:P/RC:R/RL:U"

    # Environmental: requisitos CR/IR/AR da classe do ativo.
    req = asset_classifier.requirements_for(asset_class)
    env = "/".join(f"{k}:{v}" for k, v in req.items())

    # Métricas modificadas extras (ex.: MAV:A para ativos internos).
    mod = asset_classifier.modified_metrics_for(asset_class)
    mod_str = ("/" + "/".join(f"{k}:{v}" for k, v in mod.items())) if mod else ""

    full = f"{cvss.PREFIX}/{base_vec}/{temporal}/{env}{mod_str}"
    m = cvss.parse_vector(full)

    base_s = cvss.base_score(m)
    temp_s = cvss.temporal_score(m)
    env_s = cvss.environmental_score(m)

    sev_final = cvss.band(env_s)
    sev_tool = (finding.get("severity") or "info").lower()
    # Piso p/ score_source == "estimated": o vetor base foi retro-derivado da
    # própria severity_tool (não há CVSS real do NVD/catálogo), então deixar o
    # temporal/environmental REBAIXAR a banda abaixo da ferramenta dá precisão
    # falsa a uma estimativa e descarta avaliação curada (ex.: advisory do
    # retire.js que marca axios como critical). O environmental ainda pode
    # ELEVAR (ativo CDE, confirmação) — é piso, nunca teto. Para nvd/catalog o
    # modelo governa livremente (rebaixa e eleva).
    if source == "estimated" and _SEV_RANK.get(sev_tool, 0) > _SEV_RANK.get(sev_final, 0):
        sev_final = sev_tool

    return {
        "cvss_vector": cvss.to_vector(m),
        "cvss_base": base_s,
        "cvss_temporal": temp_s,
        "cvss_environmental": env_s,
        "severity": sev_final,
        "severity_tool": sev_tool,
        "score_source": source,
        "asset_class": asset_class,
        "cwe": cwe,
        "requirements": req,
    }


def _host_path(finding):
    url = finding.get("url") or finding.get("matched_at") or finding.get("host") or ""
    if "://" in url:
        p = _urlparse(url)
        host = p.hostname or ""
        if host:
            return host, p.path or "/"
    return _re.sub(r"[:/].*$", "", url), "/"


def load_asset_overrides(base_dir):
    """Carrega assets.json de base_dir, se existir; senão None."""
    import json, os
    p = os.path.join(base_dir, "assets.json")
    if os.path.exists(p):
        try:
            with open(p, encoding="utf-8") as fh:
                return json.load(fh)
        except (OSError, ValueError):
            return None
    return None


def enrich_findings(findings, overrides=None):
    """Aplica score_finding a cada finding, in place, e devolve a lista.

    Usa finding['confirmed'] (bool) e infere a classe do ativo do host/path
    do finding (url/matched_at/host).
    """
    for f in findings:
        host, path = _host_path(f)
        # Dica explícita do produtor (ex.: findings de PII sabem que a classe de
        # dado é 'pii' independentemente da URL — um vazamento de dado pessoal num
        # asset estático NÃO deve herdar a classe 'public'/CR:L da URL).
        ac = f.get("data_class") or asset_classifier.classify_asset(host, path, overrides)
        scored = score_finding(
            f,
            asset_class=ac,
            confirmed=bool(f.get("confirmed")),
            in_kev=bool(f.get("in_kev")),
            epss=float(f.get("epss") or f.get("epss_score") or 0.0),
        )
        f.update(scored)
    return findings

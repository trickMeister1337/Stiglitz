#!/usr/bin/env python3
"""
sarif.py — Geração de findings.sarif (SARIF 2.1.0).

Pure function: recebe a lista de findings normalizados + target, devolve
o dict pronto para `json.dump`. Sem side effects, testável em isolamento.
Saída ingerível por GitHub code scanning, DefectDojo, CI/CD.
"""
import re

_SARIF_LEVEL = {
    "critical": "error",
    "high":     "error",
    "medium":   "warning",
    "low":      "note",
    "info":     "none",
}

_SEV_TO_SCORE = {
    "critical": "9.5",
    "high":     "7.5",
    "medium":   "5.0",
    "low":      "3.0",
    "info":     "0.0",
}


def _rule_id(f):
    """ID estável: 1º CVE, senão CWE, senão slug do nome."""
    cve = str(f.get("cve", ""))
    m = re.search(r"CVE-\d{4}-\d{4,7}", cve, re.IGNORECASE)
    if m:
        return m.group(0).upper()
    m = re.search(r"CWE-?\d+", cve, re.IGNORECASE)
    if m:
        return m.group(0).upper().replace("CWE", "CWE-").replace("CWE--", "CWE-")
    slug = re.sub(r"[^a-z0-9]+", "-",
                  str(f.get("name", "finding")).lower()).strip("-")
    return ("stiglitz-" + slug)[:80] or "stiglitz-finding"


def build_sarif(findings, target,
                tool_name="Stiglitz",
                info_uri="https://github.com/trickMeister1337/Stiglitz"):
    """Constrói o documento SARIF 2.1.0 a partir dos findings.

    Args:
        findings: lista de dicts com chaves usuais (name, severity, cve,
                  url, description, source, cvss, epss_score, in_kev).
        target:   URL alvo (fallback de location).
        tool_name, info_uri: identificação da ferramenta no SARIF.

    Returns:
        dict pronto para json.dump (compatível com schema SARIF 2.1.0).
    """
    rules, seen, results = [], set(), []
    for f in findings:
        rid = _rule_id(f)
        if rid not in seen:
            seen.add(rid)
            # Preferir score Environmental (calculado por criticality.enrich_findings)
            # sobre o CVSS sintético da ferramenta; fallback para mapa de severidade.
            _env = f.get("cvss_environmental")
            if _env is not None:
                sev_score = str(_env)
            else:
                sev_score = str(f.get("cvss") or
                                _SEV_TO_SCORE.get(f.get("severity", ""), "0.0"))
            rule = {
                "id": rid,
                "name": re.sub(r"[^A-Za-z0-9]", "", f.get("name", "Finding")) or "Finding",
                "shortDescription": {"text": f.get("name", "")[:200] or rid},
                "properties": {
                    "tags": [f.get("source", ""), f.get("severity", "")],
                    "security-severity": sev_score,
                },
            }
            if rid.startswith("CVE-"):
                rule["helpUri"] = f"https://nvd.nist.gov/vuln/detail/{rid}"
            rules.append(rule)

        msg = f.get("name", "")
        if f.get("description"):
            msg += ": " + f["description"]
        results.append({
            "ruleId":   rid,
            "level":    _SARIF_LEVEL.get(f.get("severity", ""), "warning"),
            "message":  {"text": msg[:1000] or rid},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": f.get("url") or target},
            }}],
            "properties": {
                "severity": f.get("severity", ""),
                "source":   f.get("source", ""),
                "cve":      f.get("cve", ""),
                "epss":     f.get("epss_score"),
                "in_kev":   f.get("in_kev", False),
            },
        })

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name":           tool_name,
                "informationUri": info_uri,
                "rules":          rules,
            }},
            "results": results,
        }],
    }

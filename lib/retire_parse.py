#!/usr/bin/env python3
"""
retire_parse.py — SCA client-side: bibliotecas JS vulneráveis (retire.js) → findings.

(P1) Antes o pipeline não detectava libs JS desatualizadas (jQuery/Angular/lodash
com CVE) — só secrets via trufflehog. Aqui parseamos a saída JSON do retire.js
(rodado sobre raw/js_files na Fase 10.5) para findings padrão, reaproveitando a
agregação + enriquecimento EPSS/KEV do cve_enrich.py. Vulns sem CVE recebem
CWE-1395 para casar A06:2021 (Vulnerable & Outdated Components) no compliance_map.

Parser puro — testável sem rede.
"""
import sys
import os
import json

_SEV = {"critical", "high", "medium", "low", "info"}


def _norm_sev(s):
    s = str(s or "").lower()
    return s if s in _SEV else "medium"


def parse(retire_json, target=""):
    findings = []
    for entry in (retire_json or {}).get("data", []) or []:
        fname = entry.get("file", "")
        short = os.path.basename(fname) or fname
        for res in entry.get("results", []) or []:
            component = res.get("component", "library")
            version = res.get("version", "")
            for vuln in res.get("vulnerabilities", []) or []:
                idents = vuln.get("identifiers", {}) or {}
                cves = [c.upper() for c in (idents.get("CVE") or [])]
                summary = idents.get("summary", "") or (idents.get("issue", "") or "")
                cve = ", ".join(sorted(set(cves))) if cves else "CWE-1395"
                refs = "; ".join(vuln.get("info", []) or [])
                findings.append({
                    "tool": "retire.js",
                    "type": "vulnerable_js_library",
                    "source": "retire.js",
                    "name": f"Vulnerable JS library: {component} {version}".strip(),
                    "url": fname or target,
                    "severity": _norm_sev(vuln.get("severity")),
                    "description": (f"retire.js flagged {component} {version} ({short}) as "
                                    f"vulnerable. {summary}".strip()
                                    + (f" Refs: {refs}" if refs else "")),
                    "remediation": f"Update {component} to a non-vulnerable version.",
                    "cve": cve,
                    # Componente vulnerável é sempre A06:2021 — marca o CWE p/ o
                    # compliance_map mapear mesmo quando há CVE (que vai no campo cve).
                    "cwe": "CWE-1395",
                })
    return findings


def main(outdir, target=""):
    raw = os.path.join(outdir, "raw")
    in_path = os.path.join(raw, "retire_raw.json")
    findings = []
    if os.path.exists(in_path):
        try:
            with open(in_path, encoding="utf-8", errors="ignore") as fh:
                findings = parse(json.load(fh), target)
        except (ValueError, OSError):
            findings = []
    for i, f in enumerate(findings, 1):
        f["id"] = f"RETIRE-{i:03d}"
    out = os.path.join(raw, "retire_findings.json")
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(findings, fh, indent=2, ensure_ascii=False)
    print(f"  [{'✓' if findings else '○'}] retire.js: {len(findings)} lib(s) vulnerável(is) → retire_findings.json")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else "")

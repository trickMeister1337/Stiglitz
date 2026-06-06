#!/usr/bin/env python3
"""
risk_context.py — reachability + exploit-availability na priorização (P1).

Estende a inteligência do P0 (cvss_environmental/EPSS/KEV) com os dois eixos que
faltavam vs Tenable VPR / Qualys TruRisk / Wiz:
- REACHABILITY: um CVE atrás de WAF ou em ativo interno é menos alcançável que o
  mesmo na borda exposta — modula a prioridade (sinais que o scan já coleta:
  wafw00f + asset_class).
- EXPLOIT AVAILABILITY: além do CISA KEV (binário, ~pequeno), promove findings com
  exploit público (ExploitDB/Metasploit), capturando o gap "tem CVE" → "tem como
  explorar amanhã".

Resultado: f["risk_priority"] (0-10) que governa a ordenação, + anotações
reachability/exploit_intel. Lógica pura — os lookups (searchsploit/msf) entram
injetados pelo report (ver exploit_lookup.py).
"""

_REACH_MULT = {"internet": 1.0, "waf": 0.9, "internal": 0.6}


def reachability_tier(behind_waf=False, internal=False):
    if internal:
        return "internal"
    if behind_waf:
        return "waf"
    return "internet"


def reachability_multiplier(tier):
    return _REACH_MULT.get(tier, 1.0)


def exploit_label(exploitdb=False, metasploit=False):
    if metasploit:
        return "Metasploit module available"
    if exploitdb:
        return "Public exploit (ExploitDB)"
    return ""


def exploit_boost(exploitdb=False, metasploit=False):
    if metasploit:
        return 1.2
    if exploitdb:
        return 1.1
    return 1.0


def risk_priority(cvss_env, reach_mult, boost):
    try:
        v = float(cvss_env) * float(reach_mult) * float(boost)
    except (TypeError, ValueError):
        return 0.0
    return round(min(10.0, v), 2)


def annotate(finding, behind_waf=False, exploitdb=False, metasploit=False):
    """Anota o finding com reachability, exploit_intel e risk_priority."""
    internal = finding.get("asset_class") == "internal"
    tier = reachability_tier(behind_waf=behind_waf, internal=internal)
    mult = reachability_multiplier(tier)
    boost = exploit_boost(exploitdb, metasploit)
    finding["reachability"] = {"tier": tier, "multiplier": mult}
    finding["exploit_intel"] = {
        "exploitdb": bool(exploitdb),
        "metasploit": bool(metasploit),
        "available": bool(exploitdb or metasploit),
        "label": exploit_label(exploitdb, metasploit),
    }
    finding["risk_priority"] = risk_priority(
        finding.get("cvss_environmental") or finding.get("cvss_base") or 0.0, mult, boost)
    return finding

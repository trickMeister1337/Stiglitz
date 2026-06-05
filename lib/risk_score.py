#!/usr/bin/env python3
"""
risk_score.py — Cálculo do Risk Score do Stiglitz.

Metodologia 2026: KEV > EPSS > CVSS, não-saturante.
- Base por severidade mais alta presente + bônus de quantidade com cap.
- Camada 1 (KEV): CVE em exploração ativa pesa mais (CISA KEV).
- Camada 2 (EPSS): probabilidade de exploração nos próximos 30 dias.
- Camada 3 (JS): secrets/frameworks vulneráveis agravam.
- Teto da banda CRÍTICA exige severidade crítica real OU KEV — bônus
  brandos (EPSS/JS) não devem fabricar um CRÍTICO sozinhos.

A função `compute_risk` é pura — sem side effects, sem IO — para
permitir teste em isolamento com valores absolutos.
"""

HIGH_JS_TYPES = {
    "AWS Access Key", "AWS Secret", "Private Key", "Stripe Live Key",
    "GitHub Token", "GitLab PAT", "OpenAI Key", "Anthropic Key",
    "Hardcoded Password", "DB Connection String",
}


def compute_risk(stats, cve_enrichment, js_secrets, js_frameworks):
    """Calcula o risk score 0-100 e os componentes que o compõem.

    Args:
        stats:           dict com contagens por severidade
                         (chaves: critical, high, medium, low, info).
        cve_enrichment:  dict {cve_id: {in_kev: bool, epss_score: float, ...}}.
        js_secrets:      list de dicts com chave "type".
        js_frameworks:   list de dicts com chave "vulnerable" (bool).

    Returns:
        dict com base_risk, kev_bonus, kev_count, epss_bonus,
        js_high, js_medium, js_vuln_fw, js_bonus, risk.
    """
    # Base: floor por severidade mais alta + bônus de quantidade (cap 25)
    if   stats.get("critical", 0) > 0: _floor = 70
    elif stats.get("high",     0) > 0: _floor = 40
    elif stats.get("medium",   0) > 0: _floor = 15
    elif stats.get("low",      0) > 0: _floor = 5
    else:                              _floor = 0
    _qty = min(stats.get("critical", 0) * 6 + stats.get("high", 0) * 3
               + stats.get("medium", 0) * 1 + stats.get("low", 0) * 0.5, 25)
    base_risk = int(_floor + _qty)

    # Camada 1 — KEV (exploração ativa confirmada)
    kev_count = sum(1 for ev in cve_enrichment.values() if ev.get("in_kev"))
    kev_bonus = min(kev_count * 25, 50) if kev_count > 0 else 0

    # Camada 2 — EPSS (probabilidade de exploit)
    epss_bonus = 0
    for ev in cve_enrichment.values():
        epss = ev.get("epss_score") or 0
        if   epss >= 0.5:  epss_bonus += 15
        elif epss >= 0.1:  epss_bonus += 7
        elif epss >= 0.01: epss_bonus += 2
    epss_bonus = min(epss_bonus, 30)

    # Camada 3 — JS (secrets + frameworks vulneráveis)
    js_high    = [s for s in js_secrets    if s.get("type", "") in HIGH_JS_TYPES]
    js_medium  = [s for s in js_secrets    if s.get("type", "") not in HIGH_JS_TYPES]
    js_vuln_fw = [f for f in js_frameworks if f.get("vulnerable")]
    js_bonus   = min(len(js_high) * 15 + len(js_medium) * 5 + len(js_vuln_fw) * 8, 30)

    risk = min(base_risk + kev_bonus + epss_bonus + js_bonus, 100)
    # Teto da banda CRÍTICA: exige severidade crítica real OU KEV.
    if stats.get("critical", 0) == 0 and kev_count == 0:
        risk = min(risk, 69)

    return {
        "base_risk":  base_risk,
        "kev_bonus":  kev_bonus,
        "kev_count":  kev_count,
        "epss_bonus": epss_bonus,
        "js_high":    js_high,
        "js_medium":  js_medium,
        "js_vuln_fw": js_vuln_fw,
        "js_bonus":   js_bonus,
        "risk":       risk,
    }

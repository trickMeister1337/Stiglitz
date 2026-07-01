#!/usr/bin/env python3
"""coverage_report.py — declara lacunas de cobertura do scan ("Coverage & Blind Spots").

Lógica pura: recebe SINAIS já derivados pelo stiglitz_report.py e devolve as
dimensões de lacuna (transforma achado-oculto em lacuna-declarada). NÃO é finding
— não entra em severity_counts; é seção de apresentação (Modo B do roadmap de
cobertura). Findings/relatório em EN; comentários PT-BR.
"""
import html as _html

_STATUS_LABEL = {"not_run": "Not run", "partial": "Partial", "ok": "OK"}


def blind_spots(signals):
    """Retorna a lista de dimensões de lacuna (status != ok) a partir de `signals`.

    signals (todas opcionais, default seguro):
      nmap_ran: bool                      — port scan rodou e produziu saída
      nmap_note: str                      — nota custom (proxy/edge/timeout)
      fingerprinted_services: [str]       — serviços de infra detectados (tech_profile)
      probed_services: [str]              — serviços p/ os quais HÁ sonda ativa
      live_hosts_no_surface: int          — hosts vivos só com '/' e sem spec
      authed_api: {count:int, has_token:bool}
    """
    s = signals or {}
    dims = []

    if not s.get("nmap_ran"):
        dims.append({
            "area": "Network port scan",
            "status": "not_run",
            "not_exercised": s.get("nmap_note") or (
                "TCP port enumeration did not run, so services on non-web ports "
                "(databases, caches, orchestration) were not discovered."),
            "how_to_close": "Run a dedicated port scan (naabu/nmap) without proxy/edge "
                            "constraints, then re-scan the services it reveals.",
        })

    _unprobed = sorted(set(s.get("fingerprinted_services") or [])
                       - set(s.get("probed_services") or []))
    if _unprobed:
        dims.append({
            "area": "Fingerprinted services not probed",
            "status": "partial",
            "not_exercised": ("Detected by fingerprint but not actively probed for "
                              "unauthenticated exposure: " + ", ".join(_unprobed) + "."),
            "how_to_close": "Add a service_exposure catalog entry for each, or review "
                            "their access controls manually.",
        })

    _lh = s.get("live_hosts_no_surface") or 0
    if _lh:
        dims.append({
            "area": "Live host, minimal discovered surface",
            "status": "partial",
            "not_exercised": (f"{_lh} live host(s) exposed only '/' with no crawlable links "
                              "and no OpenAPI spec — pure-API services here are reached only "
                              "via targeted probes, not by the spider."),
            "how_to_close": "Provide an OpenAPI/Swagger spec (--osint-dir or seeding) or a "
                            "list of known endpoints for active probing.",
        })

    _api = s.get("authed_api") or {}
    try:
        _n = int(_api.get("count", 0))
    except (TypeError, ValueError):
        _n = 0
    if _n > 0 and not _api.get("has_token"):
        dims.append({
            "area": "Authenticated API surface",
            "status": "not_run",
            "not_exercised": (f"{_n} documented endpoint(s) require authentication, but no "
                              "token was supplied; access-control (BOLA/IDOR) and "
                              "business-logic risks were not exercised."),
            "how_to_close": "Re-run with --token-a/--token-b (two test accounts) to enable "
                            "the access-control (P9.5) and business-logic (P9.7) phases.",
        })

    return dims


def render_section_html(dimensions):
    """Seção HTML 'Coverage & Blind Spots'. Vazia quando não há lacunas (cobertura
    completa). NÃO entra em severity_counts — é apresentação."""
    if not dimensions:
        return ""
    rows = ""
    for d in dimensions:
        rows += ("<tr>"
                 f"<td>{_html.escape(str(d.get('area', '')))}</td>"
                 f"<td>{_html.escape(_STATUS_LABEL.get(d.get('status', ''), str(d.get('status', ''))))}</td>"
                 f"<td style='font-size:12px'>{_html.escape(str(d.get('not_exercised', '')))}</td>"
                 f"<td style='font-size:12px'>{_html.escape(str(d.get('how_to_close', '')))}</td>"
                 "</tr>")
    return ("<h2>Coverage &amp; Blind Spots</h2>"
            "<p>Areas the automated scan did not fully exercise. Declared so that a low "
            "finding count is read against actual coverage, not as an all-clear.</p>"
            "<table><tr><th>Area</th><th>Status</th><th>Not exercised</th>"
            "<th>How to close</th></tr>" + rows + "</table>")

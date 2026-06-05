#!/usr/bin/env python3
"""
report_helpers.py — Funções auxiliares puras compartilhadas pelo caminho
de geração de relatório (stiglitz_report.py) e testáveis de forma isolada.
"""
import re as _re


def inject_cve_signals(finding, cve_enrichment):
    """Injeta sinais KEV/EPSS/CVSS NVD num finding Nuclei a partir do
    cve_enrichment produzido por cve_enrich.py.

    Regras:
    - ``in_kev``: True se QUALQUER CVE do finding tiver in_kev=True.
    - ``epss_score``: o MAIOR epss_score entre os CVEs do finding.
    - ``cvss_vector_nvd``: vetor CVSS v3 completo do CVE com maior score, APENAS
      se o campo ``cvss_vector`` contiver um vetor válido (string não-vazia com
      'AV:'); se só houver score numérico, não injeta (evita estimativas).

    Extrai CVE IDs do campo ``cve`` (string) e também de ``cve_ids`` (lista).
    Modifica ``finding`` in-place; retorna o dict por conveniência.
    """
    if not cve_enrichment:
        return finding

    # Coletar todos os CVE IDs do finding
    cve_str = finding.get("cve", "") or ""
    cve_ids_from_str = _re.findall(r"CVE-\d{4}-\d{4,7}", cve_str, _re.IGNORECASE)
    cve_ids_from_list = finding.get("cve_ids") or []
    all_cve_ids = list({c.upper() for c in list(cve_ids_from_str) + list(cve_ids_from_list)})

    if not all_cve_ids:
        return finding

    in_kev = False
    best_epss = None
    best_cvss_score = None
    best_cvss_vector = None

    for cid in all_cve_ids:
        ev = cve_enrichment.get(cid)
        if not ev:
            continue

        # KEV: True se qualquer CVE estiver no catálogo
        if ev.get("in_kev"):
            in_kev = True

        # EPSS: maior score entre os CVEs
        epss_val = ev.get("epss_score")
        if epss_val is not None:
            try:
                epss_f = float(epss_val)
                if best_epss is None or epss_f > best_epss:
                    best_epss = epss_f
            except (TypeError, ValueError):
                pass

        # CVSS vector NVD: pegar o do CVE com maior score (só se vetor válido)
        cvss_score = ev.get("cvss_v3") or ev.get("cvss_v2")
        cvss_vec = ev.get("cvss_vector", "") or ""
        if cvss_score is not None and cvss_vec and "AV:" in cvss_vec:
            try:
                score_f = float(cvss_score)
                if best_cvss_score is None or score_f > best_cvss_score:
                    best_cvss_score = score_f
                    best_cvss_vector = cvss_vec
            except (TypeError, ValueError):
                pass

    # Injetar campos no finding
    if in_kev:
        finding["in_kev"] = True
    elif "in_kev" not in finding:
        finding["in_kev"] = False
    if best_epss is not None and (best_epss > 0 or "epss_score" not in finding):
        finding["epss_score"] = best_epss
    if best_cvss_vector is not None:
        finding["cvss_vector_nvd"] = best_cvss_vector

    return finding

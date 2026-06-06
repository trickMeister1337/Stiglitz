#!/usr/bin/env python3
"""
prioritization.py — ordenação por risco unificado + SLA/aging.

(#8) O relatório ordenava findings só pela banda de severidade da ferramenta
(stiglitz_report.py), ignorando o cvss_environmental e o EPSS já computados por
criticality.py. risk_sort_key faz a apresentação ser governada pelo risco real
(estilo VPR/TruRisk).

(#9) O Action Plan usava prazos estáticos por severidade, ignorando o due_date
da CISA KEV já coletado (cve_enrich.py). sla_for_finding deriva prazo/atraso real:
KEV → prazo CISA (BOD 22-01); demais → SLA por severidade.

Funções puras (today injetável) para teste determinístico.
"""
import datetime

SEV_BAND = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# SLA padrão (dias a partir do scan) quando não há due_date regulatório.
DEFAULT_SLA_DAYS = {"critical": 7, "high": 14, "medium": 30, "low": 90, "info": 180}


def _f(v, default=0.0):
    try:
        return float(v)
    except (TypeError, ValueError):
        return default


def risk_sort_key(f):
    """Chave de ordenação: cvss_environmental desc, epss desc, KEV, banda.

    cvss_environmental já incorpora o sinal KEV via Temporal (E:H/RC:C em
    criticality.py), então é o score unificado; KEV entra como desempate.
    Retorna tupla para sorted() ascendente (menor = mais prioritário)."""
    env = _f(f.get("cvss_environmental"))
    epss = _f(f.get("epss") if f.get("epss") is not None else f.get("epss_score"))
    in_kev = bool(f.get("in_kev"))
    band = SEV_BAND.get(f.get("severity", ""), 5)
    return (-env, -epss, 0 if in_kev else 1, band)


def days_until_due(due_date, today):
    """Dias até o prazo (negativo = atrasado). None se data ausente/inválida."""
    if not due_date:
        return None
    try:
        d = datetime.datetime.strptime(due_date.strip(), "%Y-%m-%d").date()
    except (ValueError, AttributeError):
        return None
    return (d - today).days


def sla_for_finding(f, today, sla_days=None):
    """Prazo de remediação do finding. KEV → due_date CISA; senão → SLA por severidade."""
    sla_days = sla_days or DEFAULT_SLA_DAYS
    kev_due = (f.get("kev") or {}).get("due_date", "")
    if f.get("in_kev") and kev_due:
        dr = days_until_due(kev_due, today)
        return {
            "due_date": kev_due,
            "days_remaining": dr,
            "overdue": dr is not None and dr < 0,
            "source": "CISA KEV",
        }
    band = f.get("severity", "info")
    days = sla_days.get(band, 90)
    due = today + datetime.timedelta(days=days)
    return {
        "due_date": due.isoformat(),
        "days_remaining": days,
        "overdue": False,
        "source": "policy",
    }

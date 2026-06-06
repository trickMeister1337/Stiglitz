import os, sys, datetime
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
import prioritization as P


# ── risk_sort_key (#8: ordenar por risco unificado, não banda da ferramenta) ──
def test_risk_sort_orders_by_environmental_then_epss():
    a = {"severity": "high", "cvss_environmental": 9.1, "epss": 0.1, "in_kev": False}
    b = {"severity": "critical", "cvss_environmental": 7.0, "epss": 0.9, "in_kev": False}
    c = {"severity": "medium", "cvss_environmental": 9.1, "epss": 0.5, "in_kev": False}
    # a e c empatam env 9.1; c tem epss maior → c antes de a; b (env 7) por último,
    # mesmo sendo banda 'critical' — o score de risco governa, não a banda.
    assert sorted([b, a, c], key=P.risk_sort_key) == [c, a, b]


def test_risk_sort_kev_breaks_env_epss_tie():
    a = {"severity": "high", "cvss_environmental": 8.0, "epss": 0.2, "in_kev": True}
    b = {"severity": "high", "cvss_environmental": 8.0, "epss": 0.2, "in_kev": False}
    assert sorted([b, a], key=P.risk_sort_key) == [a, b]


def test_risk_sort_handles_missing_fields():
    a = {"severity": "low"}
    b = {"severity": "critical", "cvss_environmental": 9.0}
    assert sorted([a, b], key=P.risk_sort_key) == [b, a]


# ── SLA / aging (#9: dirigido pelo due_date da CISA KEV) ──
def test_days_until_due():
    today = datetime.date(2026, 6, 6)
    assert P.days_until_due("2026-06-01", today) == -5
    assert P.days_until_due("2026-06-20", today) == 14
    assert P.days_until_due("", today) is None
    assert P.days_until_due("lixo", today) is None


def test_sla_for_kev_finding_overdue():
    today = datetime.date(2026, 6, 6)
    f = {"in_kev": True, "severity": "high", "kev": {"due_date": "2026-06-01"}}
    s = P.sla_for_finding(f, today)
    assert s["source"] == "CISA KEV"
    assert s["days_remaining"] == -5
    assert s["overdue"] is True


def test_sla_for_non_kev_uses_severity_policy():
    today = datetime.date(2026, 6, 6)
    f = {"in_kev": False, "severity": "critical", "kev": {}}
    s = P.sla_for_finding(f, today)
    assert s["source"] == "policy"
    assert s["days_remaining"] == P.DEFAULT_SLA_DAYS["critical"]
    assert s["overdue"] is False
    assert s["due_date"] == (today + datetime.timedelta(days=7)).isoformat()

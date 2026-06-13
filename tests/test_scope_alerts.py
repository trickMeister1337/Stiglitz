import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
import scope  # noqa: E402


def test_filter_alerts_drops_out_of_scope():
    # Reproduz o vazamento: ZAP gerou um alerta sobre www.google.com (AJAX spider
    # saiu do escopo) e ele fluiu para o relatório do cliente.
    alerts = [
        {"name": "CSP", "url": "https://transactions.bee2pay.com/api/v1/Transactions"},
        {"name": "HSTS", "url": "https://www.google.com/async/folae?async=_fmt:pb"},
    ]
    out = scope.filter_alerts_in_scope(alerts, "transactions.bee2pay.com")
    urls = [a["url"] for a in out]
    assert "https://transactions.bee2pay.com/api/v1/Transactions" in urls
    assert all("google.com" not in u for u in urls)
    assert len(out) == 1


def test_filter_alerts_keeps_subdomain_and_urlless():
    alerts = [
        {"name": "Z", "url": "https://sub.transactions.bee2pay.com/x"},
        {"name": "W"},  # sem url → mantém (consumidor aplica o alvo como fallback)
        {"name": "U", "uri": "https://transactions.bee2pay.com/y"},  # campo 'uri'
    ]
    out = scope.filter_alerts_in_scope(alerts, "transactions.bee2pay.com")
    assert len(out) == 3


def test_filter_alerts_no_domain_failopen():
    alerts = [{"name": "A", "url": "https://anything.com/x"}]
    assert scope.filter_alerts_in_scope(alerts, "") == alerts

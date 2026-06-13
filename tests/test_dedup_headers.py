import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
from dedup import dedupe  # noqa: E402


def test_dedup_collapses_csp_cross_source():
    # Mesmo header ausente (CSP), fontes diferentes (módulo próprio vs ZAP),
    # mesmo host — é o mesmo problema e deve colapsar num único finding.
    findings = [
        {"name": "Content Security Policy (CSP) Header Not Set", "source": "OWASP ZAP",
         "url": "https://t.bee2pay.com/api/v1/Transactions", "severity": "medium"},
        {"name": "Missing Security Header: content-security-policy", "source": "Security Headers",
         "url": "https://t.bee2pay.com/", "severity": "medium"},
    ]
    out = dedupe(findings)
    assert len(out) == 1


def test_dedup_collapses_clickjacking_xframe_cross_source():
    findings = [
        {"name": "Missing Anti-clickjacking Header", "source": "OWASP ZAP",
         "url": "https://t.bee2pay.com/swagger/index.html", "severity": "medium"},
        {"name": "Missing Security Header: x-frame-options", "source": "Security Headers",
         "url": "https://t.bee2pay.com/", "severity": "medium"},
    ]
    out = dedupe(findings)
    assert len(out) == 1


def test_dedup_keeps_different_headers_separate():
    # Headers distintos NÃO devem ser fundidos.
    findings = [
        {"name": "Missing Security Header: content-security-policy", "source": "Security Headers",
         "url": "https://t.bee2pay.com/", "severity": "medium"},
        {"name": "Missing Security Header: x-frame-options", "source": "Security Headers",
         "url": "https://t.bee2pay.com/", "severity": "medium"},
    ]
    out = dedupe(findings)
    assert len(out) == 2


def test_dedup_does_not_merge_headers_across_hosts():
    findings = [
        {"name": "Content Security Policy (CSP) Header Not Set", "source": "OWASP ZAP",
         "url": "https://a.bee2pay.com/", "severity": "medium"},
        {"name": "Missing Security Header: content-security-policy", "source": "Security Headers",
         "url": "https://b.bee2pay.com/", "severity": "medium"},
    ]
    out = dedupe(findings)
    assert len(out) == 2

# tests/test_asv_preflight.py
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from lib import asv_preflight as ap


def _f(**kw):
    base = {"name": "", "source": "", "url": "", "severity": "info", "other": ""}
    base.update(kw)
    return base


def test_classify_auto_fail_categories():
    assert ap.classify_category(_f(name="SQL Injection", source="Nuclei")) == "sqli"
    assert ap.classify_category(_f(name="Cross-Site Scripting (Reflected)", source="OWASP ZAP")) == "xss"
    assert ap.classify_category(_f(name="Remote Code Execution via mod_cgi")) == "rce"
    assert ap.classify_category(_f(name="Local File Inclusion / Path Traversal")) == "lfi"
    assert ap.classify_category(_f(name="Default Login (admin:admin) accepted")) == "default_creds"
    assert ap.classify_category(_f(name="Exposed PAN / cardholder data")) == "sensitive_data"


def test_classify_tls_and_db_and_headers():
    assert ap.classify_category(_f(name="SSLv3 supported", source="testssl.sh", severity="high")) == "tls_insecure"
    assert ap.classify_category(_f(name="Exposed Service: Redis on 6379/tcp", source="Exposed Service")) == "open_db"
    assert ap.classify_category(_f(name="Missing Anti-clickjacking Header", source="Security Headers")) == "security_header"


def test_classify_low_value_zap_is_low_value():
    # is_low_value_zap_alert: disclosure ruidoso em asset estático
    cat = ap.classify_category(_f(name="Timestamp Disclosure - Unix",
                                  source="OWASP ZAP",
                                  url="https://x.com/app.bundle.js"))
    assert cat == "low_value"


def test_verdict_auto_fail():
    v, why = ap.asv_verdict_for(_f(name="SQL Injection", source="Nuclei", severity="high"))
    assert v == "FAIL"
    assert "automatic" in why.lower()


def test_verdict_cvss_threshold():
    assert ap.asv_verdict_for(_f(name="Some CVE", cvss_base=3.9, severity="low"))[0] == "PASS"
    assert ap.asv_verdict_for(_f(name="Some CVE", cvss_base=4.0, severity="medium"))[0] == "FAIL"
    assert ap.asv_verdict_for(_f(name="Some CVE", cvss_base=9.8, severity="critical"))[0] == "FAIL"


def test_verdict_headers_not_counted():
    v, _ = ap.asv_verdict_for(_f(name="Missing CSP Header", source="Security Headers", severity="high"))
    assert v == "NOT_COUNTED"


def test_verdict_low_value_not_counted():
    v, _ = ap.asv_verdict_for(_f(name="Timestamp Disclosure - Unix",
                                 source="OWASP ZAP",
                                 url="https://x.com/app.bundle.js",
                                 severity="low"))
    assert v == "NOT_COUNTED"


def test_verdict_severity_fallback_without_cvss():
    # sem cvss_base, cai na banda de severidade
    assert ap.asv_verdict_for(_f(name="Some misconfig", source="Nuclei", severity="medium"))[0] == "FAIL"
    assert ap.asv_verdict_for(_f(name="Some info", source="Nuclei", severity="info"))[0] == "PASS"

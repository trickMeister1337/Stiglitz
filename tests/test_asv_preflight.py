# tests/test_asv_preflight.py
import os, sys, tempfile
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


def test_requirement_via_cwe():
    assert ap.requirement_for(_f(name="XSS", cwe="CWE-79")) == "6.2.4"


def test_requirement_fallback_by_category():
    # sem CWE, deriva da categoria
    assert ap.requirement_for(_f(name="SSLv3 supported", source="testssl.sh", severity="high")) == "4.2.1"
    assert ap.requirement_for(_f(name="SQL Injection")) == "6.2.4"


def test_aggregate_would_not_pass():
    findings = [
        _f(name="SQL Injection", source="Nuclei", severity="high", url="https://a.com/x?id=1"),
        _f(name="Missing CSP Header", source="Security Headers", severity="high", url="https://a.com/"),
    ]
    out = ap.aggregate(findings, ["a.com"])
    assert out["would_pass"] is False
    assert out["counted"] == 1                  # header não conta
    assert out["fails"][0]["name"] == "SQL Injection"
    assert out["fails"][0]["host"] == "a.com"
    assert out["fails"][0]["requirement"] == "6.2.4"


def test_aggregate_would_pass():
    findings = [_f(name="Missing CSP Header", source="Security Headers", severity="high")]
    out = ap.aggregate(findings, ["a.com"])
    assert out["would_pass"] is True
    assert out["fails"] == []


def test_aggregate_respects_scope():
    findings = [_f(name="SQL Injection", source="Nuclei", severity="high", url="https://evil.com/x")]
    out = ap.aggregate(findings, ["a.com"])     # finding fora de escopo
    assert out["would_pass"] is True
    assert out["fails"] == []


def test_aggregate_no_url_finding_counted_with_scope():
    # finding without URL cannot be scope-checked => conservatively counted
    findings = [_f(name="SQL Injection", source="Nuclei", severity="high")]
    out = ap.aggregate(findings, ["a.com"])
    assert out["would_pass"] is False
    assert out["counted"] == 1
    assert out["fails"][0]["host"] == ""


_NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="203.0.113.10" addrtype="ipv4"/>
    <hostnames><hostname name="a.com"/></hostnames>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https" product="nginx" version="1.18.0" tunnel="ssl"/>
      </port>
      <port protocol="tcp" portid="6379">
        <state state="open"/>
        <service name="redis" product="Redis key-value store" version="6.0.5"/>
      </port>
      <port protocol="tcp" portid="9">
        <state state="closed"/>
        <service name="discard"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

_HTTPX_TXT = "https://a.com [200] [nginx] [Django]\nhttps://api.a.com:8443 [200] [nginx]\n"


def test_build_inventory_from_nmap_and_httpx():
    with tempfile.TemporaryDirectory() as d:
        raw = os.path.join(d, "raw")
        os.makedirs(raw)
        with open(os.path.join(raw, "nmap.xml"), "w") as fh:
            fh.write(_NMAP_XML)
        with open(os.path.join(raw, "httpx_results.txt"), "w") as fh:
            fh.write(_HTTPX_TXT)
        inv = ap.build_inventory(raw)

    keyed = {(r["host"], r["port"]): r for r in inv}
    # porta fechada não entra
    assert ("a.com", 9) not in keyed
    # serviço nmap estruturado
    assert keyed[("a.com", 443)]["service"] == "https"
    assert keyed[("a.com", 443)]["version"] == "nginx 1.18.0"
    assert keyed[("a.com", 443)]["tls"] is True
    assert keyed[("a.com", 6379)]["service"] == "redis"
    # host só do httpx (não estava no nmap)
    assert ("api.a.com", 8443) in keyed
    # nmap precedence: IP vem só do nmap
    assert keyed[("a.com", 443)]["ip"] == "203.0.113.10"


def test_build_inventory_missing_files_degrades():
    with tempfile.TemporaryDirectory() as d:
        raw = os.path.join(d, "raw")
        os.makedirs(raw)
        assert ap.build_inventory(raw) == []   # nada para inventariar, sem erro

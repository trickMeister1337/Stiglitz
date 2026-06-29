# tests/test_asv_preflight.py
import json
import os
import subprocess
import sys
import tempfile
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


# Regression: port 443 with a cleartext service must NOT be marked as TLS.
_NMAP_XML_PLAIN_443 = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="198.51.100.5" addrtype="ipv4"/>
    <hostnames><hostname name="b.com"/></hostnames>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="http" product="SomeApp"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


def test_inventory_plain_http_on_443_not_tls():
    """Port 443 with service name='http' and no tunnel attr must yield tls=False.

    This regresses the bare `or portid == 443` heuristic: a cleartext service
    deliberately bound to 443 was previously misclassified as TLS in the inventory.
    nmap reliably sets tunnel='ssl' (or service name https/ssl) for real TLS services,
    so TLS evidence must come from those fields only.
    """
    with tempfile.TemporaryDirectory() as d:
        raw = os.path.join(d, "raw")
        os.makedirs(raw)
        with open(os.path.join(raw, "nmap.xml"), "w") as fh:
            fh.write(_NMAP_XML_PLAIN_443)
        inv = ap.build_inventory(raw)
    keyed = {(r["host"], r["port"]): r for r in inv}
    assert ("b.com", 443) in keyed
    assert keyed[("b.com", 443)]["tls"] is False


# Task 4: render + CLI tests

def test_render_section_fail_banner():
    verdict = {"would_pass": False, "counted": 1, "fails": [
        {"name": "SQL Injection", "host": "a.com", "port": 443, "cvss_base": 9.8,
         "reason": "ASV automatic-failure category: sqli", "requirement": "6.2.4",
         "remediation": "Use parameterized queries", "severity": "high"}]}
    inv = [{"host": "a.com", "ip": "203.0.113.10", "port": 443,
            "service": "https", "version": "nginx 1.18.0", "tls": True}]
    html_out = ap.render_section_html(verdict, inv)
    assert "ASV Preflight" in html_out
    assert "WOULD NOT PASS" in html_out
    assert "SQL Injection" in html_out
    assert "203.0.113.10" in html_out
    assert "does not replace" in html_out.lower()   # disclaimer


def test_render_section_pass_banner():
    out = ap.render_section_html({"would_pass": True, "counted": 0, "fails": []}, [])
    assert "WOULD PASS" in out


def test_render_section_escapes_html():
    verdict = {"would_pass": False, "counted": 1, "fails": [
        {"name": "<script>alert(1)</script>", "host": "a.com", "port": 443,
         "cvss_base": 9.8, "reason": "x", "requirement": "6.2.4",
         "remediation": "y", "severity": "high"}]}
    out = ap.render_section_html(verdict, [])
    assert "<script>alert(1)</script>" not in out      # not a live tag
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in out  # escaped form present


def test_cli_verdict(tmp_path):
    findings = {"summary": {"findings": [
        {"name": "SQL Injection", "source": "Nuclei", "severity": "high",
         "url": "https://a.com/x?id=1"}]}}
    fj = tmp_path / "findings.json"
    with open(fj, "w") as fh:
        fh.write(json.dumps(findings))
    res = subprocess.run(
        ["python3", os.path.join(os.path.dirname(__file__), "..", "lib", "asv_preflight.py"),
         "verdict", str(fj)],
        capture_output=True, text=True)
    assert res.returncode == 0
    payload = json.loads(res.stdout)
    assert payload["verdict"]["would_pass"] is False


def test_cli_verdict_scope_excludes_out_of_scope(tmp_path):
    # Without --scope: out-of-scope FAIL finding is counted (fail-open) -> would_pass False.
    # With --scope a.com: finding on evil.com is excluded -> would_pass True.
    findings = {"summary": {"findings": [
        {"name": "SQL Injection", "source": "Nuclei", "severity": "high",
         "url": "https://evil.com/x?id=1"}]}}
    fj = tmp_path / "findings.json"
    with open(fj, "w") as fh:
        fh.write(json.dumps(findings))
    lib_path = os.path.join(os.path.dirname(__file__), "..", "lib", "asv_preflight.py")
    # Without --scope: fail-open -> FAIL finding counted -> would_pass False
    res_no_scope = subprocess.run(
        ["python3", lib_path, "verdict", str(fj)],
        capture_output=True, text=True)
    assert res_no_scope.returncode == 0
    payload_no_scope = json.loads(res_no_scope.stdout)
    assert payload_no_scope["verdict"]["would_pass"] is False

    # With --scope a.com: evil.com finding excluded -> would_pass True
    res_scoped = subprocess.run(
        ["python3", lib_path, "verdict", str(fj), "--scope", "a.com"],
        capture_output=True, text=True)
    assert res_scoped.returncode == 0
    payload_scoped = json.loads(res_scoped.stdout)
    assert payload_scoped["verdict"]["would_pass"] is True


def test_cli_verdict_criteria_notes_present(tmp_path):
    findings = {"summary": {"findings": [
        {"name": "SQL Injection", "source": "Nuclei", "severity": "high",
         "url": "https://a.com/x?id=1"}]}}
    fj = tmp_path / "findings.json"
    with open(fj, "w") as fh:
        fh.write(json.dumps(findings))
    res = subprocess.run(
        ["python3", os.path.join(os.path.dirname(__file__), "..", "lib", "asv_preflight.py"),
         "verdict", str(fj)],
        capture_output=True, text=True)
    assert res.returncode == 0
    payload = json.loads(res.stdout)
    assert "criteria_notes" in payload
    assert "v3.1" in payload["criteria_notes"]
    assert "v2" in payload["criteria_notes"]

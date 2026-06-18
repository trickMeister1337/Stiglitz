import os, sys, json, subprocess

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
REPORT = os.path.join(ROOT, "stiglitz_report.py")

# Finding KEV com due_date no passado (sempre overdue) + CWE p/ compliance.
KEV_FINDING = [{
    "id": "SVC-001", "tool": "nmap", "type": "service_version", "source": "Service Version",
    "name": "Outdated OpenSSH", "url": "t:22/tcp", "severity": "high",
    "description": "x", "remediation": "y", "cve": "CVE-2020-15778",
    "cve_ids": ["CVE-2020-15778"], "in_kev": True,
    "kev": {"due_date": "2020-01-01", "date_added": "2019-12-01"},
}]


def _run(tmp_path, cde=False):
    raw = tmp_path / "raw"
    raw.mkdir()
    (raw / "service_findings.json").write_text(json.dumps(KEV_FINDING))
    (raw / "cms_findings.json").write_text(json.dumps([{
        "id": "CMS-001", "tool": "wpscan", "type": "cms_vulnerability", "source": "wpscan",
        "name": "WP plugin XSS", "url": "http://t", "severity": "medium",
        "description": "x", "remediation": "y", "cve": "CWE-79"}]))
    # Isola o escopo CDE do teste do cde_targets.txt real do repo. A seção de
    # compliance PCI só deve sair quando o alvo está declarado no CDE (gating).
    cde_file = tmp_path / "cde_targets.txt"
    cde_file.write_text("web http://t test-app\n" if cde else "")
    env = dict(os.environ, OUTDIR=str(tmp_path), TARGET="http://t", DOMAIN="t",
               STIGLITZ_CDE_TARGETS=str(cde_file))
    subprocess.run([sys.executable, REPORT], cwd=ROOT, env=env, check=True, capture_output=True)
    return json.load(open(tmp_path / "findings.json")).get("findings", [])


def test_findings_carry_sla_and_overdue(tmp_path):
    findings = _run(tmp_path)
    kev = next(f for f in findings if f["name"] == "Outdated OpenSSH")
    assert kev["sla"]["source"] == "CISA KEV"
    assert kev["sla"]["overdue"] is True
    assert kev["sla"]["days_remaining"] < 0


def test_findings_carry_compliance_mapping(tmp_path):
    findings = _run(tmp_path)
    xss = next(f for f in findings if f["name"] == "WP plugin XSS")
    assert xss["compliance"]["owasp"].startswith("A03")


def test_report_html_has_compliance_section(tmp_path):
    # Alvo declarado no CDE → a seção de compliance PCI deve ser renderizada.
    _run(tmp_path, cde=True)
    html = open(tmp_path / "stiglitz_report.html", encoding="utf-8").read()
    assert "Compliance Mapping" in html
    assert "OVERDUE" in html  # seção de SLA atrasado (CISA KEV)


def test_compliance_section_gated_by_cde(tmp_path):
    # Alvo NÃO declarado no CDE → a seção de compliance PCI não deve aparecer,
    # mas a seção de SLA (independente de CDE) permanece.
    _run(tmp_path, cde=False)
    html = open(tmp_path / "stiglitz_report.html", encoding="utf-8").read()
    assert "Compliance Mapping" not in html
    assert "PCI DSS CDE Coverage" not in html
    assert "OVERDUE" in html

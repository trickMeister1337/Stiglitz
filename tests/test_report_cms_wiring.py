import os, sys, json, subprocess

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
REPORT = os.path.join(ROOT, "stiglitz_report.py")

CMS_FINDING = [{
    "id": "CMS-001", "tool": "wpscan", "type": "cms_vulnerability",
    "source": "wpscan", "name": "WordPress plugin foo: Unauth RCE",
    "url": "http://t", "severity": "high", "description": "x",
    "remediation": "y", "cve": "CVE-2020-99999",
}]


def test_report_aggregates_cms_findings(tmp_path):
    raw = tmp_path / "raw"
    raw.mkdir()
    (raw / "cms_findings.json").write_text(json.dumps(CMS_FINDING))
    env = dict(os.environ, OUTDIR=str(tmp_path), TARGET="http://t", DOMAIN="t")
    subprocess.run([sys.executable, REPORT], cwd=ROOT, env=env,
                   check=True, capture_output=True)
    findings = json.load(open(tmp_path / "findings.json")).get("findings", [])
    assert any("WordPress plugin foo: Unauth RCE" in f.get("name", "")
               for f in findings)

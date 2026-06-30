"""Regressão: os findings do APM Probe (raw/apm_probe.json — unauth ingestion /
agent config) chegam ao findings.json enriquecido e ao HTML (com o painel
'How to Reproduce' do repro, pois são High/Medium). Espelha test_report_access_wiring."""
import os, sys, json, subprocess, tempfile, shutil

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _run_report_with_apm(apm):
    outdir = tempfile.mkdtemp()
    os.makedirs(os.path.join(outdir, "raw"), exist_ok=True)
    with open(os.path.join(outdir, "raw", "apm_probe.json"), "w") as f:
        json.dump(apm, f)
    env = dict(os.environ, OUTDIR=outdir, TARGET="https://apm.example.com",
               DOMAIN="apm.example.com")
    r = subprocess.run([sys.executable, os.path.join(ROOT, "stiglitz_report.py")],
                       env=env, cwd=ROOT, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    findings = json.load(open(os.path.join(outdir, "findings.json"))).get("findings", [])
    html_path = os.path.join(outdir, "stiglitz_report.html")
    html = open(html_path, encoding="utf-8").read() if os.path.exists(html_path) else ""
    return outdir, findings, html


_APM = [
    {"tool": "apm_probe", "type": "apm_unauth_ingestion", "source": "APM Probe",
     "name": "APM Server accepts telemetry ingestion without authentication",
     "url": "https://apm.example.com/intake/v2/events", "severity": "high",
     "cwe": "CWE-306", "fingerprint": "abc123def456aaaa",
     "description": "intake processes events without a token",
     "remediation": "require secret_token", "evidence": "noauth=400 badtoken=401"},
    {"tool": "apm_probe", "type": "apm_central_config_exposed", "source": "APM Probe",
     "name": "APM agent central configuration readable without authentication",
     "url": "https://apm.example.com/config/v1/agents", "severity": "medium",
     "cwe": "CWE-306", "fingerprint": "abc123def456bbbb",
     "description": "agent config readable", "remediation": "require auth",
     "evidence": "noauth=200 badtoken=401"},
]


def test_apm_findings_reach_findings_json_with_fingerprint():
    outdir, findings, _ = _run_report_with_apm(_APM)
    try:
        ing = [f for f in findings if f.get("url") == "https://apm.example.com/intake/v2/events"]
        cfg = [f for f in findings if f.get("url") == "https://apm.example.com/config/v1/agents"]
        assert len(ing) == 1, f"ingestion finding deveria estar no findings.json, veio {len(ing)}"
        assert len(cfg) == 1, f"config finding deveria estar no findings.json, veio {len(cfg)}"
        assert ing[0].get("fingerprint"), "finding sem fingerprint (perde dedup/estado)"
        # High preservado pelo piso do 'estimated' (consistente com TLS/headers):
        # o environmental pode elevar, mas não rebaixa um High curado sem CVE.
        assert ing[0].get("severity") == "high", \
            f"ingestion deveria permanecer High, veio {ing[0].get('severity')!r}"
        assert abs(float(ing[0].get("cvss_base") or 0) - 7.5) < 0.01
        assert cfg[0].get("severity") == "medium"
    finally:
        shutil.rmtree(outdir)


def test_apm_high_finding_renders_reproduction_panel():
    outdir, _, html = _run_report_with_apm(_APM)
    try:
        assert "How to Reproduce / Proof" in html, "painel de reprodução ausente no HTML"
        assert "/intake/v2/events" in html, "comando de reprodução do APM ausente no HTML"
    finally:
        shutil.rmtree(outdir)

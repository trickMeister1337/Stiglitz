import json, os, subprocess, sys, tempfile, shutil

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _run_report(tmp):
    env = dict(os.environ, OUTDIR=tmp, TARGET="https://t.example.com",
               DOMAIN="t.example.com", STIGLITZ_STATE_DIR=os.path.join(tmp, "state"))
    subprocess.run([sys.executable, os.path.join(ROOT, "stiglitz_report.py")],
                   env=env, cwd=ROOT, capture_output=True, timeout=120)


def _seed(tmp, alerts):
    raw = os.path.join(tmp, "raw"); os.makedirs(raw)
    with open(os.path.join(raw, "zap_alerts.json"), "w") as f:
        json.dump({"alerts": alerts}, f)


def test_authgated_sqli_deferred_not_in_counts():
    tmp = tempfile.mkdtemp()
    try:
        _seed(tmp, [
            {"name": "SQL Injection", "risk": "High", "confidence": "Medium",
             "url": "https://t.example.com/api/x", "param": "id",
             "attack": "1 OR 1=1 --", "attack_status": 401, "cweid": "89"},
        ])
        _run_report(tmp)
        out = json.load(open(os.path.join(tmp, "findings.json")))
        deferred = out.get("deferred_findings", [])
        assert any("SQL Injection" in (d.get("name", "")) for d in deferred), \
            "SQLi auth-gated deveria estar em deferred_findings"
        # não conta como severidade de topo
        names = [f.get("name", "") for f in
                 (out if isinstance(out, list) else out.get("findings", []))]
        assert not any("SQL Injection" in n for n in names), \
            "SQLi auth-gated não deveria aparecer nos findings principais"
        html = open(os.path.join(tmp, "stiglitz_report.html")).read()
        assert "Requires Authenticated Retest" in html
        assert "Medium" in html
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_active_scan_with_200_status_is_kept():
    tmp = tempfile.mkdtemp()
    try:
        _seed(tmp, [
            {"name": "SQL Injection", "risk": "High", "confidence": "Medium",
             "url": "https://t.example.com/api/y", "param": "id",
             "attack": "1 OR 1=1 --", "attack_status": 200, "cweid": "89"},
        ])
        _run_report(tmp)
        out = json.load(open(os.path.join(tmp, "findings.json")))
        assert not out.get("deferred_findings"), \
            "status 200 não deve ser deferido"
        names = [f.get("name", "") for f in
                 (out if isinstance(out, list) else out.get("findings", []))]
        assert any("SQL Injection" in n for n in names), \
            "active-scan com 200 deve permanecer nos findings principais"
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

"""Confirma (regressão) que os findings de Access Control da P9.5 (BOLA/BFLA)
chegam aos outputs estruturados: findings.json enriquecido + findings.sarif com
partialFingerprints. O fluxo é a agregação de `raw/access_findings.json` no
stiglitz_report.py (mesma lista de oauth_findings/bizlogic_findings)."""
import os, sys, json, subprocess, tempfile, shutil

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _run_report_with_access(access):
    outdir = tempfile.mkdtemp()
    os.makedirs(os.path.join(outdir, "raw"), exist_ok=True)
    with open(os.path.join(outdir, "raw", "access_findings.json"), "w") as f:
        json.dump(access, f)
    env = dict(os.environ, OUTDIR=outdir, TARGET="t.com", DOMAIN="t.com")
    r = subprocess.run([sys.executable, os.path.join(ROOT, "stiglitz_report.py")],
                       env=env, cwd=ROOT, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    findings = json.load(open(os.path.join(outdir, "findings.json"))).get("findings", [])
    sarif = json.load(open(os.path.join(outdir, "findings.sarif")))
    return outdir, findings, sarif


def test_access_finding_reaches_findings_json_with_fingerprint():
    access = [{"type": "bola", "severity": "high", "source": "bola", "confirmed": True,
               "name": "BOLA: cross-account read", "method": "GET",
               "url": "https://t.com/api/orders/123"}]
    outdir, findings, _ = _run_report_with_access(access)
    try:
        hit = [f for f in findings if f.get("url") == "https://t.com/api/orders/123"]
        assert len(hit) == 1, f"access finding deveria estar no findings.json, veio {len(hit)}"
        assert hit[0].get("fingerprint"), "finding sem fingerprint (perde dedup/estado)"
    finally:
        shutil.rmtree(outdir)


def test_access_finding_reaches_sarif_with_partial_fingerprints():
    access = [{"type": "bola", "severity": "high", "source": "bola", "confirmed": True,
               "name": "BOLA: cross-account read", "method": "GET",
               "url": "https://t.com/api/orders/123"}]
    outdir, _, sarif = _run_report_with_access(access)
    try:
        results = sarif["runs"][0]["results"]
        hit = [r for r in results if "orders/123" in json.dumps(r)]
        assert len(hit) == 1, f"access finding deveria estar no SARIF, veio {len(hit)}"
        assert hit[0].get("partialFingerprints"), \
            "SARIF result sem partialFingerprints (dedup do tracker quebra)"
    finally:
        shutil.rmtree(outdir)

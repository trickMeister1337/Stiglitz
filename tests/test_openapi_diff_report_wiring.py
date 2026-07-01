import os, sys, json, subprocess, pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent


def _run_report(outdir):
    env = dict(os.environ, OUTDIR=str(outdir), DOMAIN="host", TARGET="https://host",
               STIGLITZ_DEDUP="0")
    return subprocess.run([sys.executable, str(ROOT / "stiglitz_report.py")],
                          env=env, capture_output=True, text=True, cwd=str(ROOT))


def test_openapi_diff_finding_reaches_findings_json(tmp_path):
    raw = tmp_path / "raw"
    raw.mkdir(parents=True)
    (raw / "openapi_diff.json").write_text(json.dumps([{
        "type": "openapi_excessive_data",
        "name": "Excessive Data Exposure vs OpenAPI schema",
        "severity": "critical", "cwe": "CWE-213",
        "url": "https://host/cards/1", "method": "GET",
        "source": "openapi_diff", "tool": "openapi_diff",
        "description": "d", "evidence": "e", "fingerprint": "abc123def456ab00",
    }]))
    r = _run_report(tmp_path)
    assert r.returncode == 0, r.stderr
    fj = json.load(open(tmp_path / "findings.json"))
    arr = fj["findings"] if isinstance(fj, dict) else fj
    hit = [f for f in arr if f.get("id", "").endswith("openapi_excessive_data")
           or f.get("name", "").startswith("Excessive Data Exposure")]
    assert hit, "finding do openapi_diff não chegou ao findings.json"

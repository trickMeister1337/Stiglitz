import os, sys, json, subprocess, tempfile, pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent


def _run_report(outdir):
    env = dict(os.environ, OUTDIR=str(outdir), DOMAIN="host", TARGET="https://host",
               STIGLITZ_DEDUP="0")
    return subprocess.run([sys.executable, str(ROOT / "stiglitz_report.py")],
                          env=env, capture_output=True, text=True, cwd=str(ROOT))


def test_service_exposure_finding_reaches_findings_json(tmp_path):
    raw = tmp_path / "raw"
    raw.mkdir(parents=True)
    (raw / "service_exposure.json").write_text(json.dumps([{
        "tool": "service_exposure", "type": "docker_api_exposed", "source": "Service Exposure",
        "name": "Docker Engine API exposed without authentication",
        "url": "https://host/containers/json", "severity": "critical",
        "description": "x", "remediation": "y", "evidence": "z",
        "cwe": "CWE-306", "fingerprint": "abc123def456",
    }]))
    r = _run_report(tmp_path)
    assert r.returncode == 0, r.stderr
    fj = json.load(open(tmp_path / "findings.json"))
    arr = fj["findings"] if isinstance(fj, dict) else fj
    hit = [f for f in arr if f.get("id", "").startswith("svc-docker_api_exposed")]
    assert hit, "service_exposure finding não chegou ao findings.json"
    assert hit[0]["severity"] == "critical"   # estimated preserva a severidade

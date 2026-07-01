import os, sys, json, subprocess, pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent


def _run_report(outdir, extra_env=None):
    env = dict(os.environ, OUTDIR=str(outdir), DOMAIN="host", TARGET="https://host",
               STIGLITZ_DEDUP="0")
    if extra_env:
        env.update(extra_env)
    return subprocess.run([sys.executable, str(ROOT / "stiglitz_report.py")],
                          env=env, capture_output=True, text=True, cwd=str(ROOT))


def test_coverage_section_rendered_when_authed_api_untested(tmp_path):
    raw = tmp_path / "raw"
    raw.mkdir(parents=True)
    (raw / ".coverage_gap_authed_api").write_text("15")   # 15 endpoints, sem token
    r = _run_report(tmp_path)
    assert r.returncode == 0, r.stderr
    html = (tmp_path / "stiglitz_report.html").read_text()
    assert "Coverage &amp; Blind Spots" in html
    assert "Authenticated API surface" in html


def test_coverage_gap_not_counted_as_info_finding(tmp_path):
    raw = tmp_path / "raw"
    raw.mkdir(parents=True)
    (raw / ".coverage_gap_authed_api").write_text("15")
    _run_report(tmp_path)
    fj = json.load(open(tmp_path / "findings.json"))
    arr = fj["findings"] if isinstance(fj, dict) else fj
    # migrou: NÃO há mais finding 'Coverage' info inflando a contagem
    assert not any((f.get("source") == "Coverage") for f in arr)

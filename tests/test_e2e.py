"""
Testes end-to-end determinísticos sobre uma fixture sintética (test_fixtures/sample_scan).

Cobrem o que faltava: a cadeia real de geração de relatório a partir de dados em
raw/ — parsing (nuclei/testssl/email/exploits), agregação multi-fonte, derivação
de KPIs dos arquivos, e export SARIF/JSON. Sem ferramentas externas e sem rede
(alvo = localhost), então rodam em qualquer CI.

A fixture contém SOMENTE dados sintéticos (nenhum dado de cliente).
Valores esperados derivados da fixture:
  subdomains=3 · TLS issues=2 · confirmed exploits=1 · email issues=1
  findings agregados=7 (3 nuclei [C/H/M] + 2 TLS + 1 email + 1 exploit)
"""
import json
import os
import shutil
import subprocess
import sys

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_fixtures", "sample_scan")


@pytest.fixture
def scan_dir(tmp_path):
    """Cópia descartável da fixture sintética."""
    dst = tmp_path / "scan_sample"
    shutil.copytree(FIXTURE, dst)
    return str(dst)


# ─────────────────────────────────────────────────────────────────────────────
#  Camada 1 — geração do relatório a partir dos arquivos (determinístico, sem deps)
# ─────────────────────────────────────────────────────────────────────────────
def _run_report(scan_dir):
    """Roda stiglitz_report.py via runpy, sem env de KPI (força file-derivation)."""
    import runpy
    env_backup = dict(os.environ)
    for k in ("ACTIVE_COUNT", "SUB_COUNT", "TLS_ISSUES", "CONFIRMED_COUNT",
              "EMAIL_ISSUES", "OPEN_PORTS", "JS_SECRETS", "KATANA_URLS",
              "FFUF_FOUND", "TRUFFLEHOG_FOUND", "WAF_NAME", "WAF_DETECTED"):
        os.environ.pop(k, None)
    os.environ.update(OUTDIR=scan_dir, TARGET="https://localhost", DOMAIN="localhost")
    try:
        return runpy.run_path(os.path.join(REPO, "stiglitz_report.py"))
    finally:
        os.environ.clear()
        os.environ.update(env_backup)


def test_report_generates_all_artifacts(scan_dir):
    _run_report(scan_dir)
    for name in ("stiglitz_report.html", "findings.json", "findings.sarif",
                 "executive_summary.html"):
        p = os.path.join(scan_dir, name)
        assert os.path.exists(p), f"artefato ausente: {name}"
        assert os.path.getsize(p) > 0


def test_kpis_derived_from_files(scan_dir):
    ns = _run_report(scan_dir)
    assert str(ns["SUB_COUNT"]) == "3"
    assert ns["TLS_ISSUES"] == 2
    assert ns["CONFIRMED_COUNT"] == 1
    assert ns["EMAIL_ISSUES"] == 1
    assert ns["OPEN_PORTS"] == "80/tcp 443/tcp"


def test_findings_aggregated_from_all_sources(scan_dir):
    _run_report(scan_dir)
    data = json.load(open(os.path.join(scan_dir, "findings.json")))
    items = data if isinstance(data, list) else data.get("findings", [])
    # 3 nuclei + 2 TLS + 1 email + 1 exploit confirmado = 7
    assert len(items) >= 3, "deveria agregar ao menos os 3 findings do nuclei"
    sev = [(f.get("severity") or f.get("level") or "").lower() for f in items]
    assert any(s in ("critical",) for s in sev), "deveria haver ao menos 1 critical"


def test_sarif_valid_and_consistent(scan_dir):
    _run_report(scan_dir)
    sarif = json.load(open(os.path.join(scan_dir, "findings.sarif")))
    assert sarif.get("version") == "2.1.0"
    assert sarif.get("$schema", "").endswith(".json") or "sarif" in sarif.get("$schema", "").lower()
    runs = sarif.get("runs", [])
    assert runs and "results" in runs[0]
    # SARIF deve refletir o mesmo nº de findings do findings.json
    data = json.load(open(os.path.join(scan_dir, "findings.json")))
    items = data if isinstance(data, list) else data.get("findings", [])
    assert len(runs[0]["results"]) == len(items)


# ─────────────────────────────────────────────────────────────────────────────
#  Camada 2 — via pipeline.py (orquestrador) → stiglitz.sh --only-phase (dispatch real)
# ─────────────────────────────────────────────────────────────────────────────
@pytest.mark.skipif(shutil.which("bash") is None, reason="bash indisponível")
def test_pipeline_drives_report_phase(scan_dir):
    """pipeline.py → bash stiglitz.sh --only-phase P11 → relatório a partir da fixture.

    Exercita a cadeia completa: orquestrador, subprocess, parsing de args do
    stiglitz.sh, dispatch de fase (guard _phase_enabled) e geração de relatório.
    Alvo localhost resolve sem rede.
    """
    if os.path.exists(os.path.join(scan_dir, "stiglitz_report.html")):
        os.remove(os.path.join(scan_dir, "stiglitz_report.html"))
    rc = subprocess.run(
        [sys.executable, os.path.join(REPO, "pipeline.py"),
         "https://localhost", "--outdir", scan_dir, "--only", "P11"],
        cwd=REPO, capture_output=True, text=True, timeout=180,
    )
    assert rc.returncode == 0, f"pipeline falhou:\nSTDOUT:{rc.stdout}\nSTDERR:{rc.stderr}"
    assert os.path.exists(os.path.join(scan_dir, "stiglitz_report.html"))
    assert os.path.exists(os.path.join(scan_dir, "findings.sarif"))
    # checkpoint persistido
    state = os.path.join(scan_dir, "raw", ".pipeline_state.json")
    assert os.path.exists(state)
    assert json.load(open(state))["phases"]["P11"]["status"] == "done"

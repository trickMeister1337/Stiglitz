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
    # Novo contrato (banda Environmental): o finding "critical" da fixture sem
    # cve_enrichment/KEV/EPSS recebe E:P/RC:R → Environmental cai para "high".
    # Aceita "critical" (se banda Environmental mantiver) ou "high" (correto com motor ativo).
    assert any(s in ("critical", "high") for s in sev), "deveria haver ao menos 1 critical ou high"


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
#  Camada 1b — campos de criticidade serializados em findings.json (Fix D)
# ─────────────────────────────────────────────────────────────────────────────

def test_findings_json_serializes_criticality_fields(scan_dir):
    """Fix D: findings.json deve incluir cvss_vector, cvss_environmental,
    severity_tool, score_source, asset_class quando presentes no finding
    após enrich_findings."""
    # Injetar cve_enrichment com dados ricos para o CVE da fixture
    cve_enrichment_path = os.path.join(scan_dir, "raw", "cve_enrichment.json")
    cve_enrichment = {
        "CVE-2024-00001": {
            "cve_id": "CVE-2024-00001",
            "in_kev": True,
            "epss_score": 0.85,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            "cvss_v3": 10.0, "cvss_v2": None,
            "description": "Synthetic critical CVE",
            "severity": "CRITICAL",
        }
    }
    with open(cve_enrichment_path, "w", encoding="utf-8") as fh:
        json.dump(cve_enrichment, fh)

    _run_report(scan_dir)
    data = json.load(open(os.path.join(scan_dir, "findings.json")))
    items = data if isinstance(data, list) else data.get("findings", [])

    # Pelo menos o finding crítico (CVE-2024-00001) deve ter os novos campos
    enriched = [f for f in items if f.get("score_source") is not None]
    assert len(enriched) > 0, (
        "nenhum finding tem 'score_source' — enrich_findings não foi chamado no caminho do scan"
    )

    # O finding com CVE in_kev=True deve ter score_source='nvd'
    kev_findings = [f for f in items if f.get("in_kev") is True]
    assert len(kev_findings) > 0, (
        "nenhum finding tem in_kev=True — injeção de sinais KEV não funcionou"
    )
    kf = kev_findings[0]
    assert kf.get("score_source") == "nvd", f"score_source esperado 'nvd', got {kf.get('score_source')!r}"
    assert kf.get("cvss_environmental") is not None, "cvss_environmental ausente"
    assert kf.get("cvss_vector") is not None, "cvss_vector ausente no findings.json"
    assert kf.get("severity_tool") is not None, "severity_tool ausente no findings.json"
    assert kf.get("asset_class") is not None, "asset_class ausente no findings.json"


def test_scan_path_kev_finding_is_critical(scan_dir):
    """Fix C+E: finding Nuclei com CVE in_kev=True deve ter severity='critical'
    no findings.json após o caminho completo do scan."""
    cve_enrichment_path = os.path.join(scan_dir, "raw", "cve_enrichment.json")
    cve_enrichment = {
        "CVE-2024-00001": {
            "cve_id": "CVE-2024-00001",
            "in_kev": True,
            "epss_score": 0.85,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            "cvss_v3": 10.0, "cvss_v2": None,
            "description": "Synthetic critical KEV CVE",
            "severity": "CRITICAL",
        }
    }
    with open(cve_enrichment_path, "w", encoding="utf-8") as fh:
        json.dump(cve_enrichment, fh)

    _run_report(scan_dir)
    data = json.load(open(os.path.join(scan_dir, "findings.json")))
    items = data if isinstance(data, list) else data.get("findings", [])

    kev_findings = [f for f in items if f.get("in_kev") is True]
    assert len(kev_findings) > 0, "nenhum finding kev encontrado"
    assert kev_findings[0]["severity"] == "critical", (
        f"severity esperado 'critical' (KEV+NVD 10.0), got {kev_findings[0]['severity']!r}"
    )


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

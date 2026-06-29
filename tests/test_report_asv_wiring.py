"""Wiring: emit_artifacts grava o JSON e devolve a seção HTML (código real,
chamado pelo stiglitz_report.py sob STIGLITZ_ASV_PREFLIGHT=1)."""
import os, sys, json, tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from lib import asv_preflight as ap


def test_emit_artifacts_writes_json_and_returns_html():
    with tempfile.TemporaryDirectory() as d:
        os.makedirs(os.path.join(d, "raw"))
        findings = [{"name": "SQL Injection", "source": "Nuclei",
                     "severity": "high", "url": "https://a.com/x?id=1"}]
        html_out = ap.emit_artifacts(d, findings, ["a.com"])
        assert "ASV Preflight" in html_out
        assert os.path.exists(os.path.join(d, "asv_verdict.json"))
        with open(os.path.join(d, "asv_verdict.json")) as fh:
            data = json.load(fh)
        assert data["verdict"]["would_pass"] is False
        assert "inventory" in data


def test_emit_artifacts_pass_case():
    with tempfile.TemporaryDirectory() as d:
        os.makedirs(os.path.join(d, "raw"))
        findings = [{"name": "Missing CSP Header", "source": "Security Headers",
                     "severity": "high", "url": "https://a.com/"}]
        html_out = ap.emit_artifacts(d, findings, ["a.com"])
        assert "WOULD PASS" in html_out
        with open(os.path.join(d, "asv_verdict.json")) as fh:
            data = json.load(fh)
        assert data["verdict"]["would_pass"] is True

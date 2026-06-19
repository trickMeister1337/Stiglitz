import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
import finding_group as G


def _hdr(name, url, sev="medium"):
    return {"name": name, "url": url, "source": "Security Headers", "severity": sev}


def test_collapses_same_header_across_hosts():
    findings = [
        _hdr("Missing Security Header: content-security-policy", "https://a.ex"),
        _hdr("Missing Security Header: content-security-policy", "https://b.ex"),
        _hdr("Missing Security Header: content-security-policy", "https://c.ex"),
    ]
    out = G.group_by_name(findings)
    assert len(out) == 1
    assert out[0]["affected_count"] == 3
    assert set(out[0]["affected_urls"]) == {"https://a.ex", "https://b.ex", "https://c.ex"}


def test_keeps_different_headers_separate():
    findings = [
        _hdr("Missing Security Header: content-security-policy", "https://a.ex"),
        _hdr("Missing Security Header: x-frame-options", "https://a.ex"),
    ]
    out = G.group_by_name(findings)
    assert len(out) == 2


def test_single_host_passes_unchanged_without_affected_count():
    findings = [_hdr("Missing Security Header: referrer-policy", "https://only.ex")]
    out = G.group_by_name(findings)
    assert len(out) == 1
    assert "affected_count" not in out[0]


def test_other_sources_pass_through():
    findings = [
        _hdr("Missing Security Header: content-security-policy", "https://a.ex"),
        _hdr("Missing Security Header: content-security-policy", "https://b.ex"),
        {"name": "SQL Injection", "url": "https://a.ex/q", "source": "Nuclei", "severity": "high"},
    ]
    out = G.group_by_name(findings)
    names = [f["name"] for f in out]
    assert "SQL Injection" in names
    assert len([f for f in out if f["source"] == "Security Headers"]) == 1


def test_group_takes_highest_severity():
    findings = [
        _hdr("Missing Security Header: x-frame-options", "https://a.ex", sev="low"),
        _hdr("Missing Security Header: x-frame-options", "https://b.ex", sev="medium"),
    ]
    out = G.group_by_name(findings)
    assert out[0]["severity"] == "medium"


def test_dedups_same_host_in_affected_urls():
    findings = [
        _hdr("Missing Security Header: x-frame-options", "https://a.ex"),
        _hdr("Missing Security Header: x-frame-options", "https://a.ex"),
        _hdr("Missing Security Header: x-frame-options", "https://b.ex"),
    ]
    out = G.group_by_name(findings)
    assert out[0]["affected_count"] == 2   # a.ex contado uma vez

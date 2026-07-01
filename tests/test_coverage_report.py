import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
import coverage_report as cov


def test_empty_when_full_coverage():
    sig = {"nmap_ran": True, "fingerprinted_services": [], "probed_services": [],
           "live_hosts_no_surface": 0, "authed_api": {"count": 0, "has_token": False}}
    assert cov.blind_spots(sig) == []


def test_nmap_not_run_dimension():
    dims = cov.blind_spots({"nmap_ran": False})
    assert any(d["area"] == "Network port scan" and d["status"] == "not_run" for d in dims)


def test_fingerprinted_unprobed_dimension():
    dims = cov.blind_spots({"nmap_ran": True,
                            "fingerprinted_services": ["Redis", "Grafana"],
                            "probed_services": ["Grafana"]})
    d = [x for x in dims if x["area"] == "Fingerprinted services not probed"]
    assert d and "Redis" in d[0]["not_exercised"] and "Grafana" not in d[0]["not_exercised"]


def test_live_host_minimal_surface_dimension():
    dims = cov.blind_spots({"nmap_ran": True, "live_hosts_no_surface": 1})
    assert any(d["area"].startswith("Live host") for d in dims)


def test_authed_api_dimension_only_without_token():
    dims = cov.blind_spots({"nmap_ran": True, "authed_api": {"count": 12, "has_token": False}})
    assert any(d["area"] == "Authenticated API surface" for d in dims)
    dims2 = cov.blind_spots({"nmap_ran": True, "authed_api": {"count": 12, "has_token": True}})
    assert not any(d["area"] == "Authenticated API surface" for d in dims2)


def test_render_empty_when_no_dimensions():
    assert cov.render_section_html([]) == ""


def test_render_contains_section_and_rows():
    html = cov.render_section_html([
        {"area": "Network port scan", "status": "not_run",
         "not_exercised": "x", "how_to_close": "y"}])
    assert "Coverage &amp; Blind Spots" in html
    assert "Network port scan" in html
    assert "Not run" in html   # label legível


def test_render_escapes_html():
    html = cov.render_section_html([
        {"area": "<svg>", "status": "partial", "not_exercised": "<b>", "how_to_close": "z"}])
    assert "<svg>" not in html and "&lt;svg&gt;" in html

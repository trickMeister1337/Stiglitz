import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
import retire_parse as R

SAMPLE = {
    "version": "5.0.0",
    "data": [{
        "file": "/js/jquery.min.js",
        "results": [{
            "component": "jquery", "version": "1.8.3",
            "vulnerabilities": [{
                "severity": "medium",
                "identifiers": {"CVE": ["CVE-2012-6708"], "summary": "jQuery before 1.9.0 XSS"},
                "info": ["https://example/advisory"],
            }],
        }],
    }],
}


def test_parse_extracts_library_vuln_with_cve():
    findings = R.parse(SAMPLE)
    assert len(findings) == 1
    f = findings[0]
    assert f["source"] == "retire.js"
    assert f["type"] == "vulnerable_js_library"
    assert "jquery" in f["name"].lower()
    assert "1.8.3" in f["name"]
    assert "CVE-2012-6708" in f["cve"]
    assert f["severity"] == "medium"
    assert "jquery.min.js" in f["url"]


def test_parse_vuln_without_cve_maps_to_a06_cwe():
    data = {"data": [{"file": "x.js", "results": [{
        "component": "lodash", "version": "4.0.0",
        "vulnerabilities": [{"severity": "high",
                             "identifiers": {"summary": "Prototype pollution"}}]}]}]}
    f = R.parse(data)[0]
    # sem CVE → CWE-1395 (Vulnerable & Outdated Components) p/ casar A06 no compliance_map
    assert f["cve"] == "CWE-1395"
    assert f["severity"] == "high"
    assert "Prototype pollution" in f["description"]


def test_parse_multiple_components_and_vulns():
    data = {"data": [{"file": "bundle.js", "results": [
        {"component": "angular", "version": "1.5.0",
         "vulnerabilities": [{"severity": "high", "identifiers": {"CVE": ["CVE-2019-1"]}},
                             {"severity": "low", "identifiers": {"CVE": ["CVE-2019-2"]}}]},
        {"component": "moment", "version": "2.0.0",
         "vulnerabilities": [{"severity": "medium", "identifiers": {"CVE": ["CVE-2020-1"]}}]},
    ]}]}
    findings = R.parse(data)
    assert len(findings) == 3


def test_parse_empty_and_malformed():
    assert R.parse({}) == []
    assert R.parse({"data": []}) == []
    assert R.parse({"data": [{"file": "x", "results": []}]}) == []


def test_severity_normalization():
    data = {"data": [{"file": "x", "results": [{"component": "c", "version": "1",
            "vulnerabilities": [{"severity": "CRITICAL", "identifiers": {"CVE": ["CVE-1"]}}]}]}]}
    assert R.parse(data)[0]["severity"] == "critical"


# retire.js roda sobre os JS BAIXADOS em raw/js_files/<md5>.js, então o campo
# "file" é o caminho LOCAL do operador. O finding NUNCA pode expor esse path
# (vaza ambiente + é inacionável); deve apontar para a URL de origem do JS.
def test_url_maps_local_file_to_origin_url():
    data = {"data": [{"file": "/home/op/scan/raw/js_files/4ccd1900.js", "results": [{
        "component": "swiper", "version": "8.4.5",
        "vulnerabilities": [{"severity": "high",
                             "identifiers": {"summary": "Prototype pollution"}}]}]}]}
    url_map = {"4ccd1900.js": "https://t.example/static/swiper.min.js?ver=8.4.5"}
    f = R.parse(data, target="https://t.example", url_map=url_map)[0]
    assert f["url"] == "https://t.example/static/swiper.min.js?ver=8.4.5"
    assert "/home/" not in f["url"]          # jamais vaza caminho local

def test_url_never_leaks_local_path_without_map():
    data = {"data": [{"file": "/home/op/scan/raw/js_files/zzz.js", "results": [{
        "component": "x", "version": "1",
        "vulnerabilities": [{"severity": "low", "identifiers": {"CVE": ["CVE-1"]}}]}]}]}
    f = R.parse(data, target="https://t.example")[0]   # sem url_map → fallback
    assert "/home/" not in f["url"]
    assert f["url"] in ("https://t.example", "zzz.js")

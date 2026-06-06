import os, sys, json
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
import cms_findings as cms

# ─────────────────────────── wpscan ───────────────────────────
def test_parse_wpscan_plugin_vuln_with_cve():
    data = {"plugins": {"contact-form-7": {
        "vulnerabilities": [{
            "title": "Contact Form 7 < 5.1.4 - Unrestricted File Upload",
            "references": {"cve": ["2020-35489"]},
            "fixed_in": "5.1.4"}]}}}
    findings = cms.parse_wpscan(data)
    assert len(findings) == 1
    f = findings[0]
    assert f["source"] == "wpscan"
    assert f["severity"] == "high"
    assert "CVE-2020-35489" in f["cve"]
    assert "Contact Form 7" in f["name"]
    assert "5.1.4" in f["remediation"]


def test_parse_wpscan_vuln_without_cve():
    data = {"plugins": {"foo": {"vulnerabilities": [
        {"title": "Foo Stored XSS", "references": {}}]}}}
    f = cms.parse_wpscan(data)[0]
    assert f["cve"] == "N/A"
    assert f["severity"] == "high"
    assert "Foo Stored XSS" in f["name"]


def test_parse_wpscan_core_and_theme_vulns():
    data = {
        "version": {"vulnerabilities": [
            {"title": "WP Core RCE", "references": {"cve": ["2021-0001"]}}]},
        "main_theme": {"vulnerabilities": [
            {"title": "Theme LFI", "references": {"cve": ["2021-0002"]}}]},
    }
    names = [f["name"] for f in cms.parse_wpscan(data)]
    assert any("WP Core RCE" in n for n in names)
    assert any("Theme LFI" in n for n in names)
    assert len(names) == 2


def test_parse_wpscan_empty_is_empty():
    assert cms.parse_wpscan({}) == []
    assert cms.parse_wpscan({"plugins": {"foo": {"vulnerabilities": []}}}) == []


# ─────────────────────────── joomscan ───────────────────────────
def test_parse_joomscan_bang_lines_become_findings():
    text = ("[+] Detecting Joomla Version\n"
            "[++] Joomla 3.7.0\n"
            "[!] Core Joomla Vulnerability: SQL Injection (CVE-2017-8917)\n"
            "[++] some info\n"
            "[!] Directory listing enabled\n")
    findings = cms.parse_joomscan(text)
    assert len(findings) == 2
    assert findings[0]["source"] == "joomscan"
    assert "CVE-2017-8917" in findings[0]["cve"]
    assert findings[0]["severity"] == "high"
    assert findings[1]["cve"] == "N/A"
    assert findings[1]["severity"] == "medium"


def test_parse_joomscan_no_bang_lines_is_empty():
    assert cms.parse_joomscan("[+] info\n[++] result\n") == []


# ─────────────────────────── droopescan ───────────────────────────
def test_parse_droopescan_version_disclosure():
    text = ("[+] Possible version(s):\n"
            "    7.50\n"
            "    7.51\n"
            "[+] Scan finished\n")
    findings = cms.parse_droopescan(text)
    vf = [f for f in findings if "version" in f["name"].lower()]
    assert len(vf) == 1
    assert "7.50" in vf[0]["description"]
    assert vf[0]["source"] == "droopescan"


def test_parse_droopescan_interesting_urls():
    text = ("[+] Possible interesting urls found:\n"
            "    Default changelog file - http://ex.com/CHANGELOG.txt\n"
            "    Default admin - http://ex.com/user/login\n"
            "\n")
    findings = cms.parse_droopescan(text)
    urls = [f["url"] for f in findings if f["type"] == "cms_exposure"]
    assert "http://ex.com/CHANGELOG.txt" in urls
    assert "http://ex.com/user/login" in urls


# ─────────────────────────── main() integração ───────────────────────────
def test_main_aggregates_all_three_into_cms_findings(tmp_path):
    raw = tmp_path / "raw"
    raw.mkdir()
    (raw / "wpscan.json").write_text(json.dumps({"plugins": {"foo": {
        "vulnerabilities": [{"title": "Foo RCE", "references": {"cve": ["2020-1"]}}]}}}))
    (raw / "joomscan.txt").write_text("[!] Joomla LFI vuln\n")
    (raw / "droopescan.txt").write_text("[+] Possible version(s):\n    7.50\n")
    cms.main(str(tmp_path), "http://target")
    out = json.load(open(raw / "cms_findings.json"))
    sources = {f["source"] for f in out}
    assert sources == {"wpscan", "joomscan", "droopescan"}


def test_main_writes_empty_list_when_no_scanner_output(tmp_path):
    raw = tmp_path / "raw"
    raw.mkdir()
    cms.main(str(tmp_path), "http://target")
    out = json.load(open(raw / "cms_findings.json"))
    assert out == []

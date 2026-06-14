import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
import compliance_map as C


def test_frameworks_for_known_cwe_xss():
    fr = C.frameworks_for_cwe("79")
    assert fr["owasp"].startswith("A03")
    assert fr["pci"]
    assert fr["iso"]
    assert fr["nist"]


def test_frameworks_for_cwe_accepts_prefixed_form():
    assert C.frameworks_for_cwe("CWE-89") == C.frameworks_for_cwe("89")
    assert C.frameworks_for_cwe("89")["owasp"].startswith("A03")


def test_frameworks_for_unknown_cwe_is_empty():
    assert C.frameworks_for_cwe("999999") == {}
    assert C.frameworks_for_cwe("") == {}


def test_extract_cwe_from_finding():
    assert C.extract_cwe({"cve": "CWE-79"}) == "79"
    assert C.extract_cwe({"cve": "CVE-2020-1 | Conf: High"}) is None
    assert C.extract_cwe({"cwe": "CWE-352", "cve": "N/A"}) == "352"


def test_compliance_summary_aggregates_by_control():
    findings = [{"cve": "CWE-79"}, {"cve": "CWE-89"}, {"cwe": "CWE-79", "cve": "N/A"}]
    summary = C.compliance_summary(findings)
    # 79 (XSS) e 89 (SQLi) caem ambos em A03:2021 (Injection) → 3 ocorrências
    a03 = [k for k in summary["owasp"] if k.startswith("A03")]
    assert a03 and summary["owasp"][a03[0]] == 3


def test_tag_finding_adds_compliance_block():
    f = {"cve": "CWE-918"}
    C.tag_finding(f)
    assert "compliance" in f
    assert f["compliance"]["owasp"].startswith("A10")  # SSRF


def test_pci_posture_fail_when_finding_maps_to_req():
    # CWE-79 → pci 6.2.4 no crosswalk
    out = C.pci_posture([{"cve": "CWE-79"}], coverage={"webapp": True})
    by = {p["req"]: p for p in out}
    assert by["6.2.4"]["verdict"] == "FAIL"
    assert by["6.2.4"]["count"] == 1


def test_pci_posture_pass_when_covered_and_no_finding():
    out = C.pci_posture([], coverage={"tls": True})
    by = {p["req"]: p for p in out}
    assert by["4.2.1"]["verdict"] == "PASS"


def test_pci_posture_na_when_capability_not_run():
    out = C.pci_posture([], coverage={"tls": False})
    by = {p["req"]: p for p in out}
    assert by["4.2.1"]["verdict"] == "N/A"


def test_pci_posture_authz_na_without_token_signal():
    out = C.pci_posture([], coverage={"authz": False, "authn": False})
    by = {p["req"]: p for p in out}
    assert by["7.2.1"]["verdict"] == "N/A"
    assert by["8.3.1"]["verdict"] == "N/A"


def test_pci_posture_fail_precedes_coverage():
    out = C.pci_posture([{"pci_req": "4.2.1", "name": "TLS 1.0"}], coverage={"tls": False})
    by = {p["req"]: p for p in out}
    assert by["4.2.1"]["verdict"] == "FAIL"


def test_pci_posture_top_findings_only_on_fail():
    out = C.pci_posture([{"cve": "CWE-79", "name": "Reflected XSS"}],
                        coverage={"webapp": True})
    by = {p["req"]: p for p in out}
    assert by["6.2.4"]["top_findings"] == ["Reflected XSS"]
    # requisitos não-FAIL não carregam top_findings
    assert by["4.2.1"]["top_findings"] == []


def test_pci_posture_sorts_numerically():
    out = C.pci_posture([], coverage={})
    reqs = [p["req"] for p in out]
    assert reqs.index("2.2.1") < reqs.index("10.2.1")

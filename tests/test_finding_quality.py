import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
import finding_quality as fq  # noqa: E402


def test_timestamp_disclosure_in_static_js_is_noise():
    # FP clássico do ZAP: números em .js minificado parecem timestamps Unix.
    assert fq.is_low_value_zap_alert(
        "Timestamp Disclosure - Unix",
        "https://t.bee2pay.com/swagger/swagger-ui-standalone-preset.js") is True


def test_suspicious_comments_in_static_js_is_noise():
    assert fq.is_low_value_zap_alert(
        "Information Disclosure - Suspicious Comments",
        "https://t.bee2pay.com/swagger/swagger-ui-bundle.js") is True


def test_timestamp_disclosure_on_api_endpoint_is_not_noise():
    # Num endpoint dinâmico de API, timestamp pode ser sensível — não suprimir.
    assert fq.is_low_value_zap_alert(
        "Timestamp Disclosure - Unix",
        "https://t.bee2pay.com/api/v1/Transactions") is False


def test_real_vuln_in_static_js_is_not_noise():
    # Só as classes de disclosure ruidoso são ruído — não vulnerabilidades reais.
    assert fq.is_low_value_zap_alert(
        "Cross Site Scripting (Reflected)",
        "https://t.bee2pay.com/swagger/swagger-ui-bundle.js") is False


def test_identify_js_version_from_evidence():
    lib, ver = fq.identify_js_library(
        "https://t.bee2pay.com/swagger/swagger-ui-bundle.js",
        evidence="Swagger UI 3.1.6 is vulnerable")
    assert lib == "Swagger UI"
    assert ver == "3.1.6"


def test_identify_js_version_from_filename():
    lib, ver = fq.identify_js_library(
        "https://t.bee2pay.com/js/jquery-1.12.4.min.js", evidence="")
    assert lib == "jQuery"
    assert ver == "1.12.4"


def test_enrich_vulnerable_js_names_component():
    out = fq.enrich_vulnerable_js(
        "Vulnerable JS Library",
        "https://t.bee2pay.com/swagger/swagger-ui-bundle.js",
        evidence="Swagger UI 3.1.6")
    assert out == "Vulnerable JS Library: Swagger UI 3.1.6"


def test_enrich_returns_none_for_unrelated_alert():
    assert fq.enrich_vulnerable_js(
        "SQL Injection", "https://t.bee2pay.com/api", evidence="") is None


def test_coverage_gap_finding_when_authed_api_no_token():
    f = fq.coverage_gap_finding(12, has_token=False)
    assert f is not None
    assert f["severity"] == "info"
    assert "12" in f["name"]
    assert "token" in f["description"].lower()


def test_no_coverage_gap_when_token_present():
    assert fq.coverage_gap_finding(12, has_token=True) is None


def test_no_coverage_gap_when_no_api():
    assert fq.coverage_gap_finding(0, has_token=False) is None


def test_swagger_severity_elevated_in_cde():
    # Spec público numa API de pagamentos (CDE) revela arquitetura → medium.
    assert fq.swagger_exposure_severity(True) == "medium"


def test_swagger_severity_info_outside_cde():
    assert fq.swagger_exposure_severity(False) == "info"

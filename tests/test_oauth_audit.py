import os, sys
import json
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))

from vuln_catalog import CATALOG
import oauth_audit


def test_oauth_classes_registered():
    expected = {
        "oauth_redirect_uri":  "CWE-601",
        "oauth_pkce_missing":  "CWE-287",
        "oauth_pkce_downgrade": "CWE-757",
        "oauth_missing_state": "CWE-352",
        "oauth_missing_nonce": "CWE-294",
        "oauth_implicit_flow": "CWE-522",
    }
    for klass, cwe in expected.items():
        assert klass in CATALOG, f"{klass} ausente do CATALOG"
        assert CATALOG[klass]["cwe"] == cwe
        assert CATALOG[klass]["vector"].startswith("AV:")
        assert CATALOG[klass]["title"]


def test_parse_well_known_normalizes():
    doc = """{"authorization_endpoint":"https://target.com/authorize",
              "token_endpoint":"https://target.com/token",
              "response_types_supported":["code","token","id_token"],
              "code_challenge_methods_supported":["S256"],
              "grant_types_supported":["authorization_code"]}"""
    wk = oauth_audit.parse_well_known(doc)
    assert wk["authorization_endpoint"] == "https://target.com/authorize"
    assert wk["response_types_supported"] == ["code", "token", "id_token"]
    assert wk["code_challenge_methods_supported"] == ["S256"]


def test_parse_well_known_invalid_returns_empty():
    assert oauth_audit.parse_well_known("not json") == {}
    assert oauth_audit.parse_well_known("[1,2,3]") == {}
    assert oauth_audit.parse_well_known("") == {}


def test_parse_authorize_requests_extracts_params():
    dump = json.dumps({"messages": [
        {"requestHeader": "GET https://target.com/oauth2/authorize?client_id=abc&"
                          "redirect_uri=https%3A%2F%2Ftarget.com%2Fcb&response_type=code&"
                          "scope=openid%20profile&state=xyz&code_challenge=ch&"
                          "code_challenge_method=S256 HTTP/1.1",
         "responseHeader": "HTTP/1.1 302 Found", "responseBody": ""},
        {"requestHeader": "GET https://target.com/about HTTP/1.1",
         "responseHeader": "HTTP/1.1 200 OK", "responseBody": ""},
    ]})
    flows = oauth_audit.parse_authorize_requests(dump)
    assert len(flows) == 1
    f = flows[0]
    assert f["client_id"] == "abc"
    assert f["redirect_uri"] == "https://target.com/cb"
    assert f["response_type"] == "code"
    assert f["scope"] == "openid profile"
    assert f["state"] == "xyz"
    assert f["code_challenge_method"] == "S256"


def test_parse_authorize_requests_ignores_non_oauth():
    dump = json.dumps({"messages": [
        {"requestHeader": "GET https://target.com/home HTTP/1.1",
         "responseHeader": "HTTP/1.1 200 OK", "responseBody": ""}]})
    assert oauth_audit.parse_authorize_requests(dump) == []

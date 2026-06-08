import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))

from vuln_catalog import CATALOG


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

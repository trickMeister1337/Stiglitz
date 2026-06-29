import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
import openapi_probe as P


def test_documented_operations_marks_global_security():
    spec = {
        "security": [{"oauth2": []}],
        "paths": {
            "/accounts/{id}": {"get": {}, "post": {}},
            "/public/health": {"get": {"security": []}},
        },
    }
    ops = P.documented_operations(spec)
    by = {(o["path"], o["method"]): o["requires_auth"] for o in ops}
    assert by[("/accounts/{id}", "GET")] is True
    assert by[("/accounts/{id}", "POST")] is True
    # security: [] na operação remove a exigência global -> público
    assert by[("/public/health", "GET")] is False


def test_documented_operations_operation_level_security():
    spec = {"paths": {"/x": {"get": {"security": [{"bearer": []}]}}}}
    ops = P.documented_operations(spec)
    assert ops[0]["requires_auth"] is True


def test_documented_operations_no_security_anywhere_is_false():
    spec = {"paths": {"/x": {"get": {}}}}
    assert P.documented_operations(spec)[0]["requires_auth"] is False


def test_op_url_applies_prefix_and_resolves_param():
    spec = {"basePath": "/api/v1", "paths": {}}
    assert P.op_url(spec, "https://t.example", "/accounts/{id}") == \
        "https://t.example/api/v1/accounts/1"


def test_documented_operations_accepts_json_text_and_bad_input():
    assert P.documented_operations("not json") == []
    assert P.documented_operations({"paths": "nope"}) == []


def test_verdict_denied_is_protected():
    for s in (401, 403, 302, 301):
        assert P.unauth_verdict(s, '{"data":1}', "application/json")["state"] == "PROTECTED"


def test_verdict_2xx_with_pii_is_broken_auth_high():
    body = '{"users":[{"id":7,"email":"alice@bank.example"}]}'
    v = P.unauth_verdict(200, body, "application/json")
    assert v["state"] == "BROKEN_AUTH"
    assert v["severity"] == "high"
    assert v["confidence"] >= 80


def test_verdict_2xx_json_without_pii_is_broken_auth():
    v = P.unauth_verdict(200, '{"balance": 1234, "currency": "BRL"}', "application/json")
    assert v["state"] == "BROKEN_AUTH"
    assert v["severity"] == "high"


def test_verdict_2xx_auth_error_envelope_is_protected():
    # API que devolve 200 + corpo de erro de auth (anti-FP)
    v = P.unauth_verdict(200, '{"error":"Unauthorized: token missing"}', "application/json")
    assert v["state"] == "PROTECTED"


def test_verdict_2xx_empty_or_tiny_is_inconclusive():
    assert P.unauth_verdict(200, "", "application/json")["state"] == "INCONCLUSIVE"
    assert P.unauth_verdict(200, "ok", "text/plain")["state"] == "INCONCLUSIVE"


def test_verdict_404_405_5xx_inconclusive():
    for s in (404, 405, 500):
        assert P.unauth_verdict(s, "x", "")["state"] == "INCONCLUSIVE"

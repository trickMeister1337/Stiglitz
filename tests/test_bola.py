# tests/test_bola.py
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
import vuln_catalog
import bola as B


def test_catalog_has_bfla_entry():
    e = vuln_catalog.CATALOG["bfla"]
    assert e["cwe"] == "CWE-285"
    assert "AV:N" in e["vector"]
    assert e["title"]


def test_parse_zap_messages_extracts_requests():
    dump = {
        "messages": [
            {"requestHeader": "GET /users/123 HTTP/1.1\r\nHost: t.com\r\nAuthorization: Bearer X\r\n\r\n",
             "requestBody": "",
             "responseHeader": "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n",
             "responseBody": '{"id":123,"email":"a@t.com"}'},
            {"requestHeader": "POST /login HTTP/1.1\r\nHost: t.com\r\n\r\n",
             "requestBody": "u=1", "responseHeader": "HTTP/1.1 302 Found\r\n\r\n",
             "responseBody": ""},
        ]
    }
    import json
    reqs = B.parse_zap_messages(json.dumps(dump))
    assert len(reqs) == 2
    r0 = reqs[0]
    assert r0["method"] == "GET"
    assert r0["url"].endswith("/users/123")
    assert r0["status"] == 200
    assert "email" in r0["resp_body"]
    assert reqs[1]["method"] == "POST"


def test_parse_zap_messages_ignores_garbage():
    assert B.parse_zap_messages("not json") == []
    assert B.parse_zap_messages('{"messages": "x"}') == []
    assert B.parse_zap_messages("") == []


def test_is_object_ref_request_detects_object_handles():
    assert B.is_object_ref_request({"url": "/users/123"}) is True
    assert B.is_object_ref_request({"url": "/api/orders/42/items"}) is True
    assert B.is_object_ref_request(
        {"url": "/x?account=550e8400-e29b-41d4-a716-446655440000"}) is True
    assert B.is_object_ref_request({"url": "/profile?id=7"}) is True
    assert B.is_object_ref_request({"url": "/about"}) is False
    assert B.is_object_ref_request({"url": "/login"}) is False
    assert B.is_object_ref_request({"url": ""}) is False


def test_is_safe_method():
    assert B.is_safe_method("GET") is True
    assert B.is_safe_method("head") is True
    assert B.is_safe_method("OPTIONS") is True
    assert B.is_safe_method("POST") is False
    assert B.is_safe_method("DELETE") is False
    assert B.is_safe_method("") is False

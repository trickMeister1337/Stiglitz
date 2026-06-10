import os, sys, json
sys.path[:0] = [os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "lib")]
import bizlogic_scan as BS
import jwt_audit


def _jwt(payload):
    import base64
    def b64(d): return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
    return f"{b64({'alg':'none'})}.{b64(payload)}.sig"


def test_account_id_from_sub_claim():
    tok = _jwt({"sub": "user-42"})
    assert BS._account_id(tok, fallback="X") == "user-42"


def test_account_id_prefers_sub_then_uid_then_user_id():
    assert BS._account_id(_jwt({"uid": "u1"}), fallback="X") == "u1"
    assert BS._account_id(_jwt({"user_id": "u2"}), fallback="X") == "u2"
    assert BS._account_id(_jwt({"sub": "s", "uid": "u"}), fallback="X") == "s"
    assert BS._account_id(_jwt({"uid": "u", "user_id": "ui"}), fallback="X") == "u"


def test_account_id_fallback_when_opaque_token():
    assert BS._account_id("not-a-jwt", fallback="A") == "A"


def _zap_dump(entries):
    # entries: list[(method, url, status)]
    msgs = [{"requestHeader": f"{m} {u} HTTP/1.1\r\nHost: x\r\n\r\n",
             "responseHeader": f"HTTP/1.1 {s} OK\r\n\r\n", "responseBody": "{}"}
            for (m, u, s) in entries]
    return json.dumps({"messages": msgs})


def test_derive_endpoints_picks_idlike_get_2xx():
    dump = _zap_dump([
        ("GET", "https://t.com/api/orders/12345", 200),   # id-like → entra
        ("GET", "https://t.com/api/health", 200),          # sem id → fora
        ("POST", "https://t.com/api/orders/1", 200),       # não-GET → fora
        ("GET", "https://t.com/admin/users/7", 200),       # privilegiado → privesc
    ])
    eps = BS._derive_endpoints(dump, base_url="https://t.com", priv_prefixes=("/admin",))
    paths = {e["path"]: e for e in eps}
    assert "/api/orders/12345" in paths
    assert paths["/api/orders/12345"]["tests"] == ["idor_read"]
    assert paths["/api/orders/12345"]["object_of"] == "A"
    assert paths["/api/orders/12345"]["method"] == "GET"
    assert "/api/health" not in paths
    assert "privesc" in paths["/admin/users/7"]["tests"]


def test_derive_endpoints_empty_when_no_candidates():
    dump = _zap_dump([("GET", "https://t.com/api/health", 200)])
    assert BS._derive_endpoints(dump, "https://t.com", ("/admin",)) == []

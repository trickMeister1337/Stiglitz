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


def test_account_id_fallback_when_opaque_token():
    assert BS._account_id("not-a-jwt", fallback="A") == "A"

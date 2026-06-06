import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
import jwt_audit as J

HDR = {"alg": "HS256", "typ": "JWT"}
PAY = {"sub": "1", "name": "admin", "exp": 9999999999}


def test_encode_decode_roundtrip():
    tok = J.encode_hs256(HDR, PAY, "s3cr3t")
    header, payload = J.decode_jwt(tok)
    assert header["alg"] == "HS256"
    assert payload["name"] == "admin"
    assert tok.count(".") == 2


def test_verify_hs256():
    tok = J.encode_hs256(HDR, PAY, "s3cr3t")
    assert J.verify_hs256(tok, "s3cr3t") is True
    assert J.verify_hs256(tok, "wrong") is False


def test_forge_alg_none_sets_alg_and_empty_signature():
    tok = J.encode_hs256(HDR, PAY, "s3cr3t")
    forged = J.forge_alg_none(tok)
    assert forged.endswith(".")
    header, payload = J.decode_jwt(forged)
    assert header["alg"] == "none"
    assert payload["name"] == "admin"   # payload preservado


def test_crack_hs256_finds_weak_secret():
    tok = J.encode_hs256(HDR, PAY, "secret")
    assert J.crack_hs256(tok, ["foo", "secret", "bar"]) == "secret"


def test_crack_hs256_returns_none_when_absent_or_wrong_alg():
    tok = J.encode_hs256(HDR, PAY, "verylongunlikelysecret")
    assert J.crack_hs256(tok, ["foo", "bar"]) is None
    none_tok = J.forge_alg_none(tok)
    assert J.crack_hs256(none_tok, ["foo"]) is None  # alg != HS256


def test_static_findings_weak_secret_is_critical():
    tok = J.encode_hs256(HDR, PAY, "secret")
    fnds = J.static_findings(tok, target="http://t", wordlist=["secret"])
    weak = [f for f in fnds if f["type"] == "jwt_weak_secret"]
    assert weak and weak[0]["severity"] == "critical"
    assert "secret" in weak[0]["evidence"]


def test_static_findings_flags_missing_exp():
    tok = J.encode_hs256({"alg": "HS256"}, {"sub": "1"}, "x")
    fnds = J.static_findings(tok, target="http://t", wordlist=[])
    assert any(f["type"] == "jwt_missing_exp" for f in fnds)


def test_static_findings_flags_alg_none_token():
    tok = J.forge_alg_none(J.encode_hs256(HDR, PAY, "s3cr3t"))
    fnds = J.static_findings(tok, target="http://t")
    assert any(f["type"] == "jwt_alg_none" for f in fnds)

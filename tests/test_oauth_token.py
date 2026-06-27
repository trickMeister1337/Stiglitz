# tests/test_oauth_token.py
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
import oauth_token as oa
import pytest


@pytest.fixture(autouse=True)
def _clear_env(monkeypatch):
    for k in ("STIGLITZ_OAUTH_TOKEN_URL", "STIGLITZ_OAUTH_CLIENT_ID",
              "STIGLITZ_OAUTH_CLIENT_SECRET", "STIGLITZ_OAUTH_SCOPE",
              "STIGLITZ_OAUTH_AUDIENCE", "STIGLITZ_OAUTH_AUTH_STYLE",
              "STIGLITZ_OAUTH_REFRESH_TOKEN"):
        monkeypatch.delenv(k, raising=False)


def _set_creds(monkeypatch):
    monkeypatch.setenv("STIGLITZ_OAUTH_TOKEN_URL", "https://idp/token")
    monkeypatch.setenv("STIGLITZ_OAUTH_CLIENT_ID", "cid")
    monkeypatch.setenv("STIGLITZ_OAUTH_CLIENT_SECRET", "csecret")


def test_is_acquire_enabled_matrix(monkeypatch):
    assert oa.is_acquire_enabled() is False
    _set_creds(monkeypatch)
    assert oa.is_acquire_enabled() is True
    monkeypatch.delenv("STIGLITZ_OAUTH_CLIENT_SECRET")
    assert oa.is_acquire_enabled() is False


def test_acquire_post_style_body(monkeypatch):
    captured = {}
    def fake_request(data, headers=None, timeout=15):
        captured["data"] = data
        captured["headers"] = headers
        return {"access_token": "AT-1"}
    monkeypatch.setattr(oa, "_request_token", fake_request)
    _set_creds(monkeypatch)
    tok = oa.acquire_access_token()
    assert tok == "AT-1"
    assert captured["data"]["grant_type"] == "client_credentials"
    assert captured["data"]["client_id"] == "cid"
    assert captured["data"]["client_secret"] == "csecret"
    assert captured["headers"] is None


def test_acquire_basic_style_header(monkeypatch):
    captured = {}
    def fake_request(data, headers=None, timeout=15):
        captured["data"] = data
        captured["headers"] = headers
        return {"access_token": "AT-2"}
    monkeypatch.setattr(oa, "_request_token", fake_request)
    _set_creds(monkeypatch)
    monkeypatch.setenv("STIGLITZ_OAUTH_AUTH_STYLE", "basic")
    tok = oa.acquire_access_token()
    assert tok == "AT-2"
    # credenciais vão no header Basic, não no corpo
    assert "client_secret" not in captured["data"]
    assert captured["headers"]["Authorization"].startswith("Basic ")
    import base64
    assert base64.b64decode(captured["headers"]["Authorization"].split()[1]).decode() == "cid:csecret"


def test_acquire_includes_scope_and_audience(monkeypatch):
    captured = {}
    monkeypatch.setattr(oa, "_request_token",
                        lambda data, headers=None, timeout=15: captured.update(data) or {"access_token": "AT"})
    _set_creds(monkeypatch)
    monkeypatch.setenv("STIGLITZ_OAUTH_SCOPE", "accounts payments")
    monkeypatch.setenv("STIGLITZ_OAUTH_AUDIENCE", "https://api/aud")
    oa.acquire_access_token()
    assert captured["scope"] == "accounts payments"
    assert captured["audience"] == "https://api/aud"


def test_acquire_raises_without_config(monkeypatch):
    with pytest.raises(oa.OAuthError):
        oa.acquire_access_token()


def test_acquire_raises_without_access_token(monkeypatch):
    monkeypatch.setattr(oa, "_request_token",
                        lambda data, headers=None, timeout=15: {"token_type": "Bearer"})
    _set_creds(monkeypatch)
    with pytest.raises(oa.OAuthError):
        oa.acquire_access_token()

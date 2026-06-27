# tests/test_poc_validator_oauth.py
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
import poc_validator as pv


def _reset():
    pv._OAUTH_TOKEN = ""


def test_refresh_path_chosen_when_enabled(monkeypatch):
    _reset()
    monkeypatch.setattr(pv, "_OAUTH_AVAILABLE", True)
    monkeypatch.setattr(pv._oauth, "is_enabled", lambda: True)
    monkeypatch.setattr(pv._oauth, "is_acquire_enabled", lambda: True)
    monkeypatch.setattr(pv._oauth, "refresh_access_token", lambda: "R-TOK")
    monkeypatch.setattr(pv._oauth, "acquire_access_token", lambda: "A-TOK")
    assert pv._refresh_oauth_safe() == "R-TOK"


def test_acquire_path_chosen_when_only_acquire(monkeypatch):
    _reset()
    monkeypatch.setattr(pv, "_OAUTH_AVAILABLE", True)
    monkeypatch.setattr(pv._oauth, "is_enabled", lambda: False)
    monkeypatch.setattr(pv._oauth, "is_acquire_enabled", lambda: True)
    monkeypatch.setattr(pv._oauth, "acquire_access_token", lambda: "A-TOK")
    assert pv._refresh_oauth_safe() == "A-TOK"


def test_noop_when_neither(monkeypatch):
    _reset()
    monkeypatch.setattr(pv, "_OAUTH_AVAILABLE", True)
    monkeypatch.setattr(pv._oauth, "is_enabled", lambda: False)
    monkeypatch.setattr(pv._oauth, "is_acquire_enabled", lambda: False)
    assert pv._refresh_oauth_safe() == ""

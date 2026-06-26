# tests/test_netproxy_mtls.py
import os, sys, ssl
import urllib.request
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
import netproxy


def _https_handlers(opener):
    return [h for h in opener.handlers if isinstance(h, urllib.request.HTTPSHandler)]


def test_make_opener_uses_mtls_context_when_none(monkeypatch):
    called = []
    ctx = ssl.create_default_context()
    monkeypatch.setattr(netproxy, "_mtls_context", lambda: (called.append(1) or ctx))
    monkeypatch.delenv("STIGLITZ_PROXY", raising=False)
    opener = netproxy.make_opener()
    assert called, "make_opener deve consultar o mtls quando ssl_context é None"
    hs = _https_handlers(opener)
    assert hs and getattr(hs[0], "_context", None) is ctx


def test_make_opener_keeps_explicit_context(monkeypatch):
    called = []
    monkeypatch.setattr(netproxy, "_mtls_context", lambda: called.append(1))
    explicit = ssl.create_default_context()
    monkeypatch.delenv("STIGLITZ_PROXY", raising=False)
    netproxy.make_opener(ssl_context=explicit)
    assert not called, "context explícito não deve ser sobrescrito pelo mtls"


def test_mtls_context_returns_none_without_module(monkeypatch):
    # sem env mTLS, client_ssl_context retorna None → opener sem HTTPSHandler custom
    monkeypatch.delenv("STIGLITZ_MTLS_CERT", raising=False)
    monkeypatch.delenv("STIGLITZ_MTLS_KEY", raising=False)
    monkeypatch.delenv("STIGLITZ_PROXY", raising=False)
    assert netproxy._mtls_context() is None

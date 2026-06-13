# tests/test_netproxy.py
import os, sys
import urllib.request
import urllib.error
import pytest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
import netproxy as N


def test_proxy_url_reads_env(monkeypatch):
    monkeypatch.delenv("STIGLITZ_PROXY", raising=False)
    assert N.proxy_url() == ""
    monkeypatch.setenv("STIGLITZ_PROXY", "http://127.0.0.1:8080")
    assert N.proxy_url() == "http://127.0.0.1:8080"


def test_no_proxy_has_no_proxyhandler(monkeypatch):
    monkeypatch.delenv("STIGLITZ_PROXY", raising=False)
    assert N._proxy_handlers() == []


def test_http_proxy_builds_proxyhandler(monkeypatch):
    monkeypatch.setenv("STIGLITZ_PROXY", "http://127.0.0.1:8080")
    handlers = N._proxy_handlers()
    ph = [h for h in handlers if isinstance(h, urllib.request.ProxyHandler)]
    assert ph, "esperado um ProxyHandler"
    assert ph[0].proxies.get("https") == "http://127.0.0.1:8080"


def test_proxy_unavailable_is_urlerror():
    assert issubclass(N.ProxyUnavailable, urllib.error.URLError)


def test_socks_never_yields_direct_opener(monkeypatch):
    # Propriedade anti-vazamento: SOCKS ou produz um handler de proxy, ou levanta
    # ProxyUnavailable — NUNCA retorna [] (que seria conexão direta).
    monkeypatch.setenv("STIGLITZ_PROXY", "socks5h://127.0.0.1:9050")
    try:
        handlers = N._proxy_handlers()
        assert handlers, "SOCKS não pode resultar em opener direto (lista vazia)"
        assert not isinstance(handlers[0], urllib.request.ProxyHandler)
    except N.ProxyUnavailable:
        pass  # PySocks ausente — aceitável (chamador pula)


def test_make_opener_with_ssl_context_has_https_handler(monkeypatch):
    import ssl
    monkeypatch.delenv("STIGLITZ_PROXY", raising=False)
    ctx = ssl.create_default_context()
    opener = N.make_opener(ssl_context=ctx)
    assert any(isinstance(h, urllib.request.HTTPSHandler) for h in opener.handlers)


def test_unknown_scheme_fails_closed(monkeypatch):
    monkeypatch.setenv("STIGLITZ_PROXY", "ftp://x:1")
    with pytest.raises(N.ProxyUnavailable):
        N._proxy_handlers()


def test_socks_make_opener_no_direct_https_handler(monkeypatch):
    import ssl
    monkeypatch.setenv("STIGLITZ_PROXY", "socks5://127.0.0.1:9050")
    ctx = ssl.create_default_context()
    try:
        opener = N.make_opener(ssl_context=ctx)
    except N.ProxyUnavailable:
        return  # PySocks ausente — make_opener falha fechado, sem opener direto
    https_chain = opener.handle_open.get("https", [])
    assert https_chain
    assert type(https_chain[0]).__name__ == "SocksiPyHandler", \
        [type(h).__name__ for h in https_chain]

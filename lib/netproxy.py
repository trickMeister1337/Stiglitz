#!/usr/bin/env python3
"""
netproxy.py — opener urllib com proxy opt-in (item 2 fintech), só p/ tráfego do alvo.

Lê STIGLITZ_PROXY (http(s):// ou socks5(h)://). Sem proxy → opener default (idêntico
ao comportamento atual). HTTP/HTTPS via ProxyHandler (stdlib). SOCKS via PySocks; se
PySocks ausente, levanta ProxyUnavailable — o chamador pula+avisa (NUNCA cai p/ direto),
preservando a garantia anti-vazamento. Módulos de terceiros (cve_enrich) NÃO usam isto.

Console em PT-BR.
"""
import os
import sys
import socket
import urllib.request
import urllib.error


class ProxyUnavailable(urllib.error.URLError):
    """Proxy configurado mas não pôde ser construído (ex.: SOCKS sem PySocks).

    Subclasse de URLError p/ ser capturada pelo tratamento de rede já existente nos
    módulos (degrada como falha de rede; nunca envia direto)."""


def proxy_url():
    """URL do proxy (STIGLITZ_PROXY) ou '' se não configurado."""
    return os.environ.get("STIGLITZ_PROXY", "").strip()


_WARNED = {"socks": False}


def _warn_once_socks(reason):
    if not _WARNED["socks"]:
        _WARNED["socks"] = True
        print(f"  [!] proxy SOCKS indisponível ({reason}) — sondagem pulada "
              f"(sem fallback direto, p/ não vazar atribuição)", file=sys.stderr)


def _proxy_handlers(ssl_context=None):
    """Handlers de proxy p/ o opener. [] se sem proxy. Levanta ProxyUnavailable se
    SOCKS sem PySocks (o chamador pula; nunca conexão direta)."""
    url = proxy_url()
    if not url:
        return []
    if url.startswith(("http://", "https://")):
        return [urllib.request.ProxyHandler({"http": url, "https": url})]
    if url.startswith(("socks5://", "socks5h://")):
        try:
            import socks  # PySocks
            from sockshandler import SocksiPyHandler
        except ImportError:
            _warn_once_socks("PySocks não instalado")
            raise ProxyUnavailable("SOCKS requer PySocks (pip install PySocks)")
        host, _, port = url.split("://", 1)[1].partition(":")
        kw = {"rdns": url.startswith("socks5h://")}
        if ssl_context is not None:
            kw["context"] = ssl_context
        return [SocksiPyHandler(socks.PROXY_TYPE_SOCKS5, host, int(port or 1080), **kw)]
    return []  # esquema desconhecido — a validação no stiglitz.sh já barra


def make_opener(ssl_context=None):
    """OpenerDirector com proxy (se configurado) + ssl_context p/ HTTPS."""
    handlers = []
    if ssl_context is not None:
        handlers.append(urllib.request.HTTPSHandler(context=ssl_context))
    handlers.extend(_proxy_handlers(ssl_context=ssl_context))
    return urllib.request.build_opener(*handlers)


def build_opener(*extra_handlers, ssl_context=None):
    """build_opener incluindo os handlers de proxy. Para módulos com handlers próprios
    (ex.: bizlogic _ScopedRedirectHandler)."""
    handlers = list(extra_handlers)
    if ssl_context is not None:
        handlers.append(urllib.request.HTTPSHandler(context=ssl_context))
    handlers.extend(_proxy_handlers(ssl_context=ssl_context))
    return urllib.request.build_opener(*handlers)


def urlopen(req, timeout=socket._GLOBAL_DEFAULT_TIMEOUT, context=None):
    """Drop-in p/ urllib.request.urlopen roteado pelo proxy (se configurado).
    `context` = ssl context (mesma semântica do urlopen)."""
    return make_opener(ssl_context=context).open(req, timeout=timeout)

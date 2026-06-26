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


def _is_socks():
    """True se STIGLITZ_PROXY é um proxy SOCKS."""
    return proxy_url().lower().startswith(("socks5://", "socks5h://"))


def _proxy_handlers(ssl_context=None):
    """Handlers de proxy p/ o opener. [] só quando NÃO há proxy. Levanta
    ProxyUnavailable se o proxy estiver configurado mas não puder ser construído
    (SOCKS sem PySocks, esquema não suportado, host/porta inválidos) — fail-closed:
    o chamador pula, NUNCA conexão direta."""
    url = proxy_url()
    if not url:
        return []
    low = url.lower()
    if low.startswith(("http://", "https://")):
        return [urllib.request.ProxyHandler({"http": url, "https": url})]
    if low.startswith(("socks5://", "socks5h://")):
        try:
            import socks  # PySocks
            from sockshandler import SocksiPyHandler
        except ImportError:
            _warn_once_socks("PySocks não instalado")
            raise ProxyUnavailable("SOCKS requer PySocks (pip install PySocks)")
        rest = url.split("://", 1)[1]
        host, _, port = rest.partition(":")
        if not host:
            raise ProxyUnavailable(f"host de proxy SOCKS ausente em {url!r}")
        try:
            port_n = int(port or 1080)
        except ValueError:
            raise ProxyUnavailable(f"porta de proxy SOCKS inválida em {url!r}")
        kw = {"rdns": low.startswith("socks5h://")}
        if ssl_context is not None:
            kw["context"] = ssl_context
        return [SocksiPyHandler(socks.PROXY_TYPE_SOCKS5, host, port_n, **kw)]
    # esquema não suportado: fail-closed (nunca conexão direta com proxy configurado)
    raise ProxyUnavailable(f"STIGLITZ_PROXY com esquema não suportado: {url!r}")


def _mtls_context():
    """ssl_context com client-cert do lib/mtls, ou None. Import tardio p/ não criar
    ciclo e manter o netproxy standalone quando o mtls não está presente."""
    try:
        import mtls
    except ImportError:
        return None
    return mtls.client_ssl_context()


def make_opener(ssl_context=None):
    """OpenerDirector com proxy (se configurado) + ssl_context p/ HTTPS.

    Com proxy SOCKS, o ssl_context é entregue ao SocksiPyHandler (que já trata HTTPS);
    NÃO se adiciona um HTTPSHandler separado, senão ele venceria a cadeia https e o
    tráfego HTTPS sairia DIRETO (vazamento de atribuição)."""
    if ssl_context is None:
        ssl_context = _mtls_context()
    proxy_handlers = _proxy_handlers(ssl_context=ssl_context)
    handlers = []
    if ssl_context is not None and not _is_socks():
        handlers.append(urllib.request.HTTPSHandler(context=ssl_context))
    handlers.extend(proxy_handlers)
    return urllib.request.build_opener(*handlers)


def build_opener(*extra_handlers, ssl_context=None):
    """build_opener incluindo os handlers de proxy. Para módulos com handlers próprios
    (ex.: bizlogic _ScopedRedirectHandler). Mesma regra do make_opener p/ SOCKS+ssl."""
    if ssl_context is None:
        ssl_context = _mtls_context()
    proxy_handlers = _proxy_handlers(ssl_context=ssl_context)
    handlers = list(extra_handlers)
    if ssl_context is not None and not _is_socks():
        handlers.append(urllib.request.HTTPSHandler(context=ssl_context))
    handlers.extend(proxy_handlers)
    return urllib.request.build_opener(*handlers)


def urlopen(req, timeout=socket._GLOBAL_DEFAULT_TIMEOUT, context=None):
    """Drop-in p/ urllib.request.urlopen roteado pelo proxy (se configurado).
    `context` = ssl context (mesma semântica do urlopen)."""
    return make_opener(ssl_context=context).open(req, timeout=timeout)


def curl_proxy_args():
    """Args de proxy p/ um comando curl construído à mão (subprocess): [] sem proxy,
    senão ['-x', url]. curl suporta http(s) e socks5(h) nativamente — sem PySocks."""
    url = proxy_url()
    return ["-x", url] if url else []

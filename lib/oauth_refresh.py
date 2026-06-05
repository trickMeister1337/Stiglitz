#!/usr/bin/env python3
"""
oauth_refresh.py — Refresh nativo de access tokens OAuth para scans longos.

Permite manter sessões autenticadas que excedem o lifetime do access_token:
quando o validator detecta 401, chama refresh_access_token() para obter um
novo access_token via refresh_token, e retenta uma vez.

Configuração via env (todas opcionais; sem TOKEN_URL, a feature é no-op):
    STIGLITZ_OAUTH_TOKEN_URL      — endpoint do POST de refresh
    STIGLITZ_OAUTH_REFRESH_TOKEN  — refresh_token (obrigatório se TOKEN_URL)
    STIGLITZ_OAUTH_CLIENT_ID      — opcional
    STIGLITZ_OAUTH_CLIENT_SECRET  — opcional
    STIGLITZ_OAUTH_GRANT_TYPE     — default 'refresh_token'

A função é pura (não toca estado global). O caller decide quando refrescar e
onde guardar o token (env STIGLITZ_ACCESS_TOKEN é a convenção).
"""
import json
import os
import urllib.error
import urllib.parse
import urllib.request


class OAuthError(Exception):
    """Erro de refresh OAuth (rede, status não-2xx, JSON inválido, etc.)."""


def is_enabled():
    """True se TOKEN_URL e REFRESH_TOKEN estão configurados no env."""
    return bool(os.environ.get("STIGLITZ_OAUTH_TOKEN_URL")
                and os.environ.get("STIGLITZ_OAUTH_REFRESH_TOKEN"))


def refresh_access_token(timeout=15):
    """Chama o endpoint de refresh e retorna o novo access_token (str).

    Raises OAuthError em qualquer falha (rede, parse, sem access_token).
    """
    token_url = os.environ.get("STIGLITZ_OAUTH_TOKEN_URL", "").strip()
    refresh   = os.environ.get("STIGLITZ_OAUTH_REFRESH_TOKEN", "").strip()
    if not token_url or not refresh:
        raise OAuthError("STIGLITZ_OAUTH_TOKEN_URL / STIGLITZ_OAUTH_REFRESH_TOKEN não configurados")

    grant   = os.environ.get("STIGLITZ_OAUTH_GRANT_TYPE", "refresh_token")
    client  = os.environ.get("STIGLITZ_OAUTH_CLIENT_ID", "").strip()
    secret  = os.environ.get("STIGLITZ_OAUTH_CLIENT_SECRET", "").strip()

    data = {"grant_type": grant, "refresh_token": refresh}
    if client: data["client_id"]     = client
    if secret: data["client_secret"] = secret

    body = urllib.parse.urlencode(data).encode("utf-8")
    req  = urllib.request.Request(
        token_url, data=body, method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded",
                 "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            payload = resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        raise OAuthError(f"HTTP {e.code} do token endpoint: {e.reason}") from None
    except (urllib.error.URLError, OSError) as e:
        raise OAuthError(f"falha de rede: {e}") from None

    try:
        parsed = json.loads(payload)
    except json.JSONDecodeError as e:
        raise OAuthError(f"resposta não-JSON do token endpoint: {e}") from None

    token = parsed.get("access_token")
    if not token or not isinstance(token, str):
        raise OAuthError(f"resposta sem access_token: {payload[:200]}")
    return token


def apply_to_curl(curl_cmd, access_token, header="Authorization"):
    """Substitui (ou injeta) o header Authorization no comando curl.

    Strings de curl construídas via shlex.quote — não interpreta shell.
    Retorna o curl_cmd modificado. Idempotente para Authorization existente.
    """
    if not access_token:
        return curl_cmd
    import re
    import shlex
    new_h = f"{header}: Bearer {access_token}"
    # Remove um Authorization existente (qualquer aspas) — depois injeta o novo
    pattern = re.compile(
        r"""-H\s+(?:'[^']*\b""" + re.escape(header) + r"""\b[^']*'"""
        r"""|"[^"]*\b""" + re.escape(header) + r"""\b[^"]*\""""
        r""")""",
        re.IGNORECASE,
    )
    curl_cmd = pattern.sub("", curl_cmd).strip()
    return curl_cmd + " -H " + shlex.quote(new_h)

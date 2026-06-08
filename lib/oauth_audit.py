#!/usr/bin/env python3
"""
oauth_audit.py — auditoria ATIVA de OAuth 2.0 / OIDC (P1, fase P9.6).

Núcleo puro (parse de well-known/ZAP, análise de params, builders de probe,
classifiers de resposta) testável sem rede + orquestração de rede fina
(fetch well-known + envio de probe via curl, injetável). Espelha jwt_audit.py
e bola.py. Findings em EN, schema do jwt_audit + fingerprint.

Descoberta passiva roda sempre; probes ativos exigem flag --oauth-active e,
mesmo assim, viram dry-run sob STIGLITZ_PROFILE=production.
"""
import sys
import os
import re
import json
import urllib.parse

WELL_KNOWN_PATHS = (
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
)

try:
    from bola import parse_zap_messages
except Exception:  # importado fora de lib/
    def parse_zap_messages(_):
        return []

try:
    from fingerprint import fingerprint as _fingerprint
    from vuln_catalog import CATALOG as _CATALOG
except Exception:
    def _fingerprint(f):
        return "0" * 16
    _CATALOG = {}


_AUTHORIZE_HINT = re.compile(r'/(?:oauth2?/)?(?:authorize|auth)\b|[?&]response_type=', re.I)


def parse_well_known(json_text):
    """Normaliza o JSON do .well-known. JSON inválido/não-dict → {}."""
    try:
        d = json.loads(json_text or "")
    except Exception:
        return {}
    if not isinstance(d, dict):
        return {}

    def _list(k):
        v = d.get(k)
        return [str(x) for x in v] if isinstance(v, list) else []

    return {
        "authorization_endpoint": str(d.get("authorization_endpoint") or ""),
        "token_endpoint": str(d.get("token_endpoint") or ""),
        "response_types_supported": _list("response_types_supported"),
        "code_challenge_methods_supported": _list("code_challenge_methods_supported"),
        "grant_types_supported": _list("grant_types_supported"),
        "scopes_supported": _list("scopes_supported"),
    }


def parse_authorize_requests(zap_messages_text):
    """Extrai fluxos /authorize observados no dump do ZAP. Reusa bola.parse_zap_messages."""
    flows = []
    for r in parse_zap_messages(zap_messages_text):
        url = r.get("url") or ""
        if not _AUTHORIZE_HINT.search(url):
            continue
        q = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)

        def g(k):
            v = q.get(k)
            return v[0] if v else ""

        flows.append({
            "authorize_url": url,
            "client_id": g("client_id"),
            "redirect_uri": g("redirect_uri"),
            "response_type": g("response_type"),
            "state": g("state"),
            "nonce": g("nonce"),
            "code_challenge": g("code_challenge"),
            "code_challenge_method": g("code_challenge_method"),
            "scope": g("scope"),
        })
    return flows

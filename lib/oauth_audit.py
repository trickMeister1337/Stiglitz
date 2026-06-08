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


def _finding(klass, url, name, severity, description, remediation, evidence=""):
    """Schema do finding (igual jwt_audit + cwe + fingerprint). Texto em EN."""
    f = {
        "tool": "oauth_audit", "type": klass, "source": "OAuth Audit",
        "name": name, "url": url, "severity": severity,
        "description": description, "remediation": remediation,
        "evidence": evidence, "cwe": _CATALOG.get(klass, {}).get("cwe", ""),
    }
    f["fingerprint"] = _fingerprint(f)
    return f


def _dedup(findings):
    """Remove duplicatas por fingerprint, preservando ordem."""
    seen, out = set(), []
    for f in findings:
        fp = f.get("fingerprint")
        if fp in seen:
            continue
        seen.add(fp)
        out.append(f)
    return out


def static_findings(wellknown, flows, target):
    """Findings derivados sem rede do well-known + fluxos observados."""
    out = []
    wk = wellknown or {}
    rts = [r.lower() for r in wk.get("response_types_supported", [])]
    ccm = [m.lower() for m in wk.get("code_challenge_methods_supported", [])]

    if any("token" in rt.split() for rt in rts):
        out.append(_finding(
            "oauth_implicit_flow", wk.get("authorization_endpoint") or target,
            "Implicit flow enabled (response_type=token advertised)", "medium",
            "The authorization server advertises the implicit grant (response_type=token), "
            "which returns the access_token in the URL fragment where it leaks via browser "
            "history, Referer headers and logs.",
            "Disable the implicit grant; use authorization code flow with PKCE."))

    if wk.get("authorization_endpoint"):
        if not ccm:
            out.append(_finding(
                "oauth_pkce_missing", wk.get("authorization_endpoint"),
                "PKCE not advertised by the authorization server", "high",
                "code_challenge_methods_supported is absent from the discovery document; "
                "the server likely does not enforce PKCE, exposing public clients to "
                "authorization code interception.",
                "Advertise and enforce PKCE with the S256 method for all clients."))
        elif ccm == ["plain"]:
            out.append(_finding(
                "oauth_pkce_downgrade", wk.get("authorization_endpoint"),
                "Only the 'plain' PKCE method is supported", "medium",
                "The server advertises only code_challenge_method=plain, which provides no "
                "protection if the authorization request is observed.",
                "Support and require the S256 PKCE method; reject 'plain'."))

    for f in flows:
        au = f.get("authorize_url") or target
        rt = (f.get("response_type") or "").lower().split()
        if "token" in rt:
            out.append(_finding(
                "oauth_implicit_flow", au,
                "Implicit flow observed in live request (response_type=token)", "medium",
                "An observed /authorize request uses response_type=token; the access_token "
                "is returned in the URL fragment and leaks via history/Referer/logs.",
                "Migrate the client to authorization code flow with PKCE.",
                evidence=f"response_type={f.get('response_type')}"))
        if "code" in rt and not f.get("code_challenge"):
            out.append(_finding(
                "oauth_pkce_missing", au,
                "Authorization code request without PKCE", "high",
                "An observed code-flow /authorize request carries no code_challenge, so the "
                "client is not protected against authorization code interception.",
                "Send and enforce a code_challenge (S256) on every code-flow request.",
                evidence="no code_challenge in request"))
        if (f.get("code_challenge_method") or "").lower() == "plain":
            out.append(_finding(
                "oauth_pkce_downgrade", au,
                "PKCE downgrade observed (code_challenge_method=plain)", "medium",
                "An observed request uses code_challenge_method=plain instead of S256.",
                "Use and require S256.", evidence="code_challenge_method=plain"))
        if rt and not f.get("state"):
            out.append(_finding(
                "oauth_missing_state", au,
                "OAuth request without state parameter", "medium",
                "An observed /authorize request omits the state parameter, exposing the flow "
                "to login CSRF / authorization response fixation.",
                "Send an unguessable state on every request and validate it on callback.",
                evidence="no state parameter"))
        if "openid" in (f.get("scope") or "").lower().split() and not f.get("nonce"):
            out.append(_finding(
                "oauth_missing_nonce", au,
                "OIDC request without nonce", "low",
                "An OpenID Connect request (scope=openid) omits nonce, allowing id_token replay.",
                "Send and validate a nonce for OIDC requests.", evidence="no nonce parameter"))
        if (f.get("redirect_uri") or "").startswith("http://"):
            out.append(_finding(
                "oauth_redirect_uri", au,
                "OAuth redirect_uri uses cleartext HTTP", "high",
                "An observed redirect_uri uses http://, so the authorization code/token can be "
                "intercepted on the network.",
                "Register and require https:// redirect URIs only.",
                evidence=f"redirect_uri={f.get('redirect_uri')}"))
    return _dedup(out)


def _with_query(url, params):
    """Reescreve a query da URL com params (descarta valores vazios)."""
    s = urllib.parse.urlsplit(url)
    q = urllib.parse.urlencode({k: v for k, v in params.items() if v != ""})
    return urllib.parse.urlunsplit((s.scheme, s.netloc, s.path, q, ""))


def build_redirect_uri_probes(authorize_url, params, canary):
    """Variações maliciosas de redirect_uri apontando ao host canary (sentinela)."""
    host = urllib.parse.urlsplit(canary).netloc or canary
    legit = params.get("redirect_uri", "")
    legit_host = urllib.parse.urlsplit(legit).netloc
    # Only variants whose real destination host IS the canary can be confirmed by the
    # Location-host classifier: external (destination = canary), subdomain_suffix
    # (destination = target.com.canary, a subdomain of canary), and userinfo
    # (https://target.com@canary → real host is canary via authority confusion).
    # path_traversal (/cb/../canary normalises back to target.com) and
    # open_redirect_param (?next=canary is second-order) never make the destination
    # the canary, so they are dropped to avoid noise.
    variants = {
        "external": canary,
        "subdomain_suffix": f"https://{legit_host}.{host}/cb" if legit_host else canary,
        "userinfo": f"https://{legit_host}@{host}/cb" if legit_host else canary,
    }
    probes = []
    for label, evil in variants.items():
        p = dict(params)
        p["redirect_uri"] = evil
        probes.append({"label": f"redirect_uri:{label}",
                       "url": _with_query(authorize_url, p),
                       "expected_marker": host, "kind": "redirect"})
    return probes


def build_pkce_missing_probe(authorize_url, params):
    """Code flow sem code_challenge — testa se o servidor aceita (PKCE não enforçado)."""
    p = dict(params)
    p["response_type"] = "code"
    p.pop("code_challenge", None)
    p.pop("code_challenge_method", None)
    return {"label": "pkce:missing", "url": _with_query(authorize_url, p), "kind": "pkce"}


def build_pkce_downgrade_probe(authorize_url, params):
    """Code flow com code_challenge_method=plain — testa downgrade."""
    p = dict(params)
    p["response_type"] = "code"
    p["code_challenge"] = p.get("code_challenge") or "plainchallenge"
    p["code_challenge_method"] = "plain"
    return {"label": "pkce:downgrade", "url": _with_query(authorize_url, p), "kind": "pkce"}

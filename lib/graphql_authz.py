#!/usr/bin/env python3
"""graphql_authz.py — field-level authorization (BOLA/BFLA) em GraphQL.

Reusa o núcleo de confirmação do bola.py (verdict + extract_canary) sobre as
operações GraphQL reais capturadas no histórico do ZAP. Replaya cada operação
com token-a/token-b/unauth e confirma acesso indevido. Só queries por padrão;
mutations exigem mutate=True + profile != production. Lógica pura + replay_fn injetável.
"""
import json
import os
import sys
import urllib.parse

import bola
import graphql_audit

try:
    from fingerprint import fingerprint as _fingerprint
except Exception:
    def _fingerprint(f):
        return "0" * 16

_SENSITIVE = graphql_audit._SENSITIVE_RE


def select_graphql_messages(messages, endpoint_substr="graphql"):
    """POSTs ao endpoint GraphQL com corpo de operação, a partir do dump ZAP."""
    out = []
    for m in messages:
        if (m.get("method") or "").upper() != "POST":
            continue
        if endpoint_substr not in (m.get("url") or "").lower():
            continue
        body = m.get("req_body") or ""
        if '"query"' in body or '"mutation"' in body or "operationName" in body:
            out.append(m)
    return out


def _classify(req):
    """graphql_bfla se mutation ou nome sensível; senão graphql_bola."""
    body = req.get("req_body") or ""
    if graphql_audit.is_mutation(body) or _SENSITIVE.search(body):
        return "graphql_bfla"
    return "graphql_bola"


def _replay(req, token):
    """POST do corpo GraphQL trocando o Authorization. token=None → unauth.
    Retorna {status, body}. Reusa netproxy/mtls."""
    import subprocess
    import netproxy
    import mtls
    url = req.get("url") or ""
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return {"status": 0, "body": ""}
    cmd = ["curl", *netproxy.curl_proxy_args(), *mtls.curl_cert_args(), "-s", "-S",
           "--max-time", "15", "-X", "POST", "-H", "Content-Type: application/json",
           "-o", "-", "-w", "\n__HTTP_STATUS__:%{http_code}",
           "-d", req.get("req_body") or "", "--", url]
    if token:
        cmd += ["-H", f"Authorization: Bearer {token}"]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        raw = p.stdout or ""
    except Exception:
        return {"status": 0, "body": ""}
    status, body = 0, raw
    marker = raw.rfind("__HTTP_STATUS__:")
    if marker != -1:
        body = raw[:marker].rstrip("\n")
        try:
            status = int(raw[marker + len("__HTTP_STATUS__:"):].strip())
        except ValueError:
            status = 0
    return {"status": status, "body": body}

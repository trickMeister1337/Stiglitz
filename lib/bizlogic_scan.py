#!/usr/bin/env python3
"""
bizlogic_scan.py — Builder de config do bizlogic a partir do histórico ZAP + tokens,
para a fase P9.7 do stiglitz.sh. Lógica pura + CLI; reusa lib/bizlogic.py intacto.

Read-only auto-derivado (idor_read/privesc). Mutantes só via config manual + --mutate.
Console PT-BR; campos de evidência em EN (padrão deliverable do suite).
"""
import argparse
import json
import os
import sys
import urllib.parse

import bola
import jwt_audit
import bizlogic

_CLAIM_KEYS = ("sub", "uid", "user_id")
DEFAULT_PRIV_PREFIXES = ("/admin", "/internal", "/manage")


def _account_id(token, fallback):
    """Extrai um id estável da conta do claim JWT (sub/uid/user_id); fallback se opaco."""
    try:
        _hdr, payload = jwt_audit.decode_jwt(token)
    except Exception:
        return fallback
    if not isinstance(payload, dict):
        return fallback
    for k in _CLAIM_KEYS:
        v = payload.get(k)
        if v not in (None, ""):
            return str(v)
    return fallback


def _rel_path(url):
    """Path relativo (com query, se houver) de uma URL absoluta ou já relativa."""
    sp = urllib.parse.urlsplit(url)
    rel = sp.path or url
    if sp.query:
        rel += "?" + sp.query
    return rel


def _derive_endpoints(zap_dump_text, base_url, priv_prefixes=DEFAULT_PRIV_PREFIXES):
    """Extrai endpoints read-only candidatos do dump ZAP: GET 2xx com object-ref.
    Paths concretos (id de A embutido). object_of='A'. privesc quando bate priv_prefixes.
    base_url é aceito por contrato da fase (não usado aqui — paths emitidos são relativos)."""
    eps = []
    seen = set()
    for req in bola.parse_zap_messages(zap_dump_text):
        if req.get("method") != "GET":
            continue
        status = req.get("status") or 0
        if not (200 <= int(status) < 300):
            continue
        if not bola.is_object_ref_request(req):
            continue
        path = _rel_path(req.get("url") or "")
        if not path or path in seen:
            continue
        seen.add(path)
        tests = ["idor_read"]
        if any(path.startswith(p) for p in priv_prefixes):
            tests.append("privesc")
        eps.append({"name": f"auto {req['method']} {path}", "method": "GET",
                    "path": path, "object_of": "A", "tests": tests})
    return eps


def build_config_from_zap(zap_dump_text, token_a, token_b, base_url,
                          priv_prefixes=DEFAULT_PRIV_PREFIXES):
    """Monta config bizlogic read-only do dump ZAP + 2 tokens. None se inviável."""
    endpoints = _derive_endpoints(zap_dump_text, base_url, priv_prefixes)
    if not endpoints:
        return None
    return {
        "base_url": base_url,
        "accounts": {
            "A": {"id": _account_id(token_a, "A"),
                  "auth": {"type": "bearer", "token": token_a}},
            "B": {"id": _account_id(token_b, "B"),
                  "auth": {"type": "bearer", "token": token_b}},
        },
        "endpoints": endpoints,
    }

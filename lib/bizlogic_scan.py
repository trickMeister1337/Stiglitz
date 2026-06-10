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


def merge_manual_config(auto_cfg, manual_cfg):
    """Mescla a config manual sobre a auto: endpoints por 'name' (manual vence),
    e chaves de topo do manual (ex.: sentinel) propagam. None → retorna auto intacto."""
    if not manual_cfg:
        return auto_cfg
    merged = dict(auto_cfg)
    by_name = {e["name"]: e for e in auto_cfg.get("endpoints", [])}
    for ep in manual_cfg.get("endpoints", []):
        by_name[ep["name"]] = ep
    merged["endpoints"] = list(by_name.values())
    for k, v in manual_cfg.items():
        if k != "endpoints":
            merged[k] = v
    return merged


def _dedup_key(url, vuln_class):
    """Chave de dedup estável: (host, path, vuln_class). Casa com a P9.5 quando
    a mesma vuln_class (idor_read_pii) aparece no mesmo recurso."""
    sp = urllib.parse.urlsplit(url or "")
    return ((sp.hostname or "").lower(), sp.path or (url or ""), vuln_class)


def to_report_findings(biz_findings):
    """Transforma findings nativos do bizlogic no schema agregado pelo report
    (campos: type, name, severity, url, tool, confirmed, detail, fingerprint).
    Acrescenta _dedup_key para o passo de dedup vs access_findings (P9.5)."""
    out = []
    for f in biz_findings:
        vc = f.get("vuln_class", "bizlogic")
        url = f.get("url", "")
        host, path, _ = _dedup_key(url, vc)
        out.append({
            "type": vc,
            "name": f.get("name", vc),
            "severity": f.get("severity", "medium") if f.get("confirmed") else "info",
            "url": url,
            "target": url,
            "tool": f.get("tool", "bizlogic"),
            "confirmed": bool(f.get("confirmed")),
            "detail": json.dumps(f.get("evidence", {}), ensure_ascii=False)[:600],
            "fingerprint": f"bizlogic:{vc}:{host}:{path}",
            "_dedup_key": (host, path, vc),
        })
    return out

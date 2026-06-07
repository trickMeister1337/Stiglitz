#!/usr/bin/env python3
"""
bola.py — detecção de BOLA/IDOR e BFLA (OWASP API #1) via replay multi-token (P1).

Reproduz requisições reais (gravadas pelo ZAP como token A/B) com a identidade do
outro usuário e confirma acesso indevido por tripla A/B/unauth + canário de corpo.
Lógica pura + CLI fina (replay de rede injetável p/ teste). Sem domínio hardcoded.
"""
import sys
import os
import re
import json
import urllib.parse

# Limiares ajustáveis (defaults conservadores — preferir FN a FP).
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
PRIVILEGED_PATH = re.compile(r"/(admin|internal|manage|console|root|sudo)\b", re.I)
_NUM_SEG = re.compile(r"/\d+(?=/|$)")
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)
_ID_PARAM = re.compile(r"(^|[?&])(id|user_id|account|uid|order|customer)=", re.I)
_EMAIL = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
_CPF = re.compile(r"\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b")


def _first_line(header):
    return (header or "").split("\r\n", 1)[0].split("\n", 1)[0]


def _status_of(resp_header):
    m = re.search(r"HTTP/\S+\s+(\d{3})", resp_header or "")
    return int(m.group(1)) if m else 0


def parse_zap_messages(json_text):
    """Lê o dump do core/view/messages do ZAP. Retorna lista de dicts
    {method, url, req_headers, req_body, status, resp_body}. Itens inválidos ignorados."""
    try:
        obj = json.loads(json_text or "")
    except Exception:
        return []
    msgs = obj.get("messages") if isinstance(obj, dict) else None
    if not isinstance(msgs, list):
        return []
    out = []
    for m in msgs:
        if not isinstance(m, dict):
            continue
        line = _first_line(m.get("requestHeader"))
        parts = line.split()
        if len(parts) < 2:
            continue
        method, target = parts[0].upper(), parts[1]
        out.append({
            "method": method,
            "url": target,
            "req_headers": m.get("requestHeader") or "",
            "req_body": m.get("requestBody") or "",
            "status": _status_of(m.get("responseHeader")),
            "resp_body": m.get("responseBody") or "",
        })
    return out

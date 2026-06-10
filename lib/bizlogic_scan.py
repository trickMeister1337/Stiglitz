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

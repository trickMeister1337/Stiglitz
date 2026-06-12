#!/usr/bin/env python3
"""
repro.py — gera o bloco "How to Reproduce / Proof" por finding (item 6 fintech).

Núcleo puro (sem rede): decide se o finding entra (passes_gate), extrai/monta o
comando de reprodução (captura real do curl/HTTP request, senão template por classe),
sanitiza segredos vivos e PAN/PII por padrão, descreve o resultado esperado (prova) e
monta o HTML do painel. Texto do bloco em INGLÊS (deliverable); console/comentários PT-BR.

Uso (debug): python3 lib/repro.py <finding.json>
"""
import os
import re
import sys
import json
import html

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pan_scanner
import pii_detect


# ── Gate de alcance ───────────────────────────────────────────────────────────
_HIGH_SEVS = {"critical", "high"}
_CONFIRMED_CATS = {"exploit", "verified"}


def passes_gate(finding):
    """True se o finding deve receber o bloco: High/Critical OU confirmado."""
    sev = str(finding.get("severity", "")).strip().lower()
    if sev in _HIGH_SEVS:
        return True
    if str(finding.get("confirmed_category", "")).strip().lower() in _CONFIRMED_CATS:
        return True
    conf = finding.get("confirmed")
    if isinstance(conf, str):
        return conf.strip().lower() in {"true", "1", "yes", "confirmed"}
    return bool(conf)

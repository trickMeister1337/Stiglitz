#!/usr/bin/env python3
"""
takeover.py — detecção de subdomain takeover (P1).

Fluxo híbrido: o CNAME filtra candidatos (apontam para terceiro), o nuclei
(-tags takeover) confirma por fingerprint de body. Lógica pura + CLI fina que o
osint.sh chama. Sem rede, sem domínio hardcoded (testável e seguro p/ versionar).
"""
import sys
import json
import csv
import io


def _norm(host):
    return (host or "").strip().rstrip(".").lower()


def is_external_cname(cname, base_domain):
    """True se o CNAME aponta para fora do apex do alvo (candidato a takeover)."""
    c, b = _norm(cname), _norm(base_domain)
    if not c or not b:
        return False
    return c != b and not c.endswith("." + b)

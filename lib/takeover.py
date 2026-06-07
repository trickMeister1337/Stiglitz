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


def _cnames_of(rec):
    cl = rec.get("cname") or []
    if isinstance(cl, str):
        cl = [cl]
    return [c for c in cl if c]


def select_external(cnames, base_domain):
    """cnames: lista de dicts {host, cname:[...]}. Retorna [(host, cname_externo)],
    o primeiro CNAME externo de cada host."""
    out = []
    for rec in cnames:
        host = _norm(rec.get("host"))
        if not host:
            continue
        for c in _cnames_of(rec):
            if is_external_cname(c, base_domain):
                out.append((host, _norm(c)))
                break
    return out


def cname_map(cnames):
    """Mapa host -> primeiro CNAME (normalizado). Hosts sem CNAME são omitidos."""
    m = {}
    for rec in cnames:
        host = _norm(rec.get("host"))
        cl = _cnames_of(rec)
        if host and cl:
            m[host] = _norm(cl[0])
    return m


def _host_only(s):
    s = (s or "").replace("https://", "").replace("http://", "")
    s = s.split("/")[0].split(":")[0]
    return _norm(s)


def parse_nuclei(jsonl_text):
    """Extrai takeovers confirmados de um JSONL do nuclei.
    Retorna lista de {host, service, severity, matched_at}. Linhas inválidas
    ou sem host são ignoradas."""
    results = []
    for line in (jsonl_text or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except Exception:
            continue
        host = _host_only(obj.get("host") or obj.get("matched-at"))
        if not host:
            continue
        info = obj.get("info") or {}
        results.append({
            "host": host,
            "service": obj.get("template-id") or info.get("name") or "unknown",
            "severity": info.get("severity") or "unknown",
            "matched_at": obj.get("matched-at") or obj.get("host") or "",
        })
    return results

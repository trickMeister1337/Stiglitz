#!/usr/bin/env python3
"""
asset_classifier.py — Classifica um ativo (host/path) por sensibilidade de dados,
dirigindo os requisitos CVSS Environmental (CR/IR/AR). Inferência por padrões
(Example-aware) com override opcional por arquivo. Override > inferência > default.
"""
import fnmatch
import re

# Ordem importa: padrões mais sensíveis primeiro.
_PATTERNS = [
    ("cde",      r"card|pan|tokenize|vcn|3ds|acs|acquirera|acquirerb"),
    ("funds",    r"gateway|checkout|splitter|cielo|getnet|\brede\b|mercadopago"),
    ("pii",      r"auth|token|login|onetime|sso|saml|oauth|keycloak|kc\.|back-token|"
                 r"fraudsvc|buyer|reservation|hotel|chargeback|receivable|"
                 r"notification|email-service|simples-nacional"),
    ("internal", r"kibana|grafana|apm|elastic|logs|jenkins|nexus|uptime|longhorn"),
    ("public",   r"www|cdn|static|assets|portal|sidebar|topbar"),
]

_REQUIREMENTS = {
    "cde":      {"CR": "H", "IR": "H", "AR": "M"},
    "funds":    {"CR": "H", "IR": "H", "AR": "M"},
    "pii":      {"CR": "H", "IR": "M", "AR": "L"},
    "internal": {"CR": "M", "IR": "M", "AR": "M"},
    "public":   {"CR": "L", "IR": "L", "AR": "L"},
    "default":  {"CR": "M", "IR": "M", "AR": "M"},
}


def classify_asset(host, path="/", overrides=None):
    """Classe do ativo. overrides: lista de {match: glob de host[/path], data_class}."""
    target = f"{host}{path}"
    if overrides:
        for ov in overrides:
            pat = ov.get("match", "")
            if fnmatch.fnmatch(host, pat) or fnmatch.fnmatch(target, pat):
                return ov.get("data_class", "default")
    hay = target.lower()
    for cls, rx in _PATTERNS:
        if re.search(rx, hay):
            return cls
    return "default"


def requirements_for(asset_class):
    """Mapeia classe → requisitos Environmental CVSS (CR/IR/AR)."""
    return dict(_REQUIREMENTS.get(asset_class, _REQUIREMENTS["default"]))


# Métricas modificadas extras por classe de ativo (além de CR/IR/AR).
_MODIFIED_METRICS = {
    "internal": {"MAV": "A"},
}


def modified_metrics_for(asset_class):
    """Mapeia classe → métricas Environmental modificadas extras (ex.: MAV:A para internal).

    Retorna dict vazio para classes sem modificadores adicionais.
    """
    return dict(_MODIFIED_METRICS.get(asset_class, {}))

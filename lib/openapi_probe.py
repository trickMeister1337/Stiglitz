#!/usr/bin/env python3
"""openapi_probe.py — P0.1 (núcleo): OpenAPI/Swagger como motor de detecção de
broken-auth ZERO-credencial. Para cada operação documentada como protegida
(`security:`), faz uma requisição SEM credencial e confirma 'Missing Authentication'
(CWE-306) quando o endpoint responde 2xx com dados reais.

Lógica pura + fetch injetável + CLI. Reusa bola.extract_canary/is_safe_method e
openapi_seed._prefix. Só métodos seguros (GET/HEAD/OPTIONS) por padrão.
"""
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from openapi_seed import _prefix as _spec_prefix

_PARAM = re.compile(r"\{[^}]+\}")
_HTTP_METHODS = ("get", "put", "post", "delete", "options", "head", "patch", "trace")


def _as_dict(spec):
    if isinstance(spec, str):
        try:
            spec = json.loads(spec)
        except (ValueError, TypeError):
            return None
    return spec if isinstance(spec, dict) else None


def _op_requires_auth(spec, operation):
    """True se a operação exige auth. security:[] na operação remove a global."""
    op_sec = operation.get("security")
    if op_sec is not None:
        return bool(op_sec)
    return bool(spec.get("security"))


def documented_operations(spec):
    """Lista de {path, method(UPPER), requires_auth} para cada operação do spec."""
    spec = _as_dict(spec)
    if spec is None:
        return []
    paths = spec.get("paths")
    if not isinstance(paths, dict):
        return []
    out = []
    for raw, item in paths.items():
        if not isinstance(raw, str) or not raw.startswith("/") or not isinstance(item, dict):
            continue
        for method, operation in item.items():
            if method.lower() not in _HTTP_METHODS or not isinstance(operation, dict):
                continue
            out.append({
                "path": raw,
                "method": method.upper(),
                "requires_auth": _op_requires_auth(spec, operation),
            })
    return out


def op_url(spec, base_url, path, sample="1"):
    """URL absoluta: prefixo (basePath/servers) aplicado + {param} resolvido."""
    spec = _as_dict(spec) or {}
    prefix = _spec_prefix(spec)
    root = base_url.rstrip("/")
    full = path if (not prefix or path.startswith(prefix)) else prefix + path
    return _PARAM.sub(sample, root + full)

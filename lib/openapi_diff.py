#!/usr/bin/env python3
"""openapi_diff.py — item #2 do ROADMAP-analyst-parity: diff spec-vs-comportamento.

Compara o que o spec OpenAPI/Swagger DECLARA com o que a API OBSERVAVELMENTE faz:
  - Excessive Data Exposure: resposta traz campos fora do schema declarado (CWE-213).
  - Shadow Endpoint: path observado (crawl/histórico) que não existe no spec (CWE-1059).
Mass Assignment fica de fora (mutante/gated → bizlogic).

Lógica pura + fetch injetável + CLI (padrão openapi_probe.py). Findings em EN
(deliverable); console/comentários PT-BR. Reusa helpers de openapi_probe e os
detectores de dado sensível (pii_detect/pan_scanner/bola).
"""
import json
import os
import re
import sys
import urllib.request
import urllib.error

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from openapi_probe import _as_dict, documented_operations, op_url, unauth_verdict
import netproxy


def _resolve_ref(spec, node, seen):
    """Resolve um nó de schema, seguindo $ref (guarda anti-ciclo via `seen`)."""
    if not isinstance(node, dict):
        return {}
    ref = node.get("$ref")
    if isinstance(ref, str):
        if ref in seen:
            return {}
        seen.add(ref)
        # #/components/schemas/X  ou  #/definitions/X
        target = spec
        for part in ref.lstrip("#/").split("/"):
            if not isinstance(target, dict):
                return {}
            target = target.get(part, {})
        return _resolve_ref(spec, target, seen)
    return node


def _response_schema_node(operation):
    """Extrai o nó de schema da resposta 2xx (OAS3 content.*.schema ou Swagger2 schema)."""
    responses = operation.get("responses")
    if not isinstance(responses, dict):
        return None
    for code, resp in responses.items():
        if not str(code).startswith("2") or not isinstance(resp, dict):
            continue
        # Swagger 2: resp["schema"]
        if isinstance(resp.get("schema"), dict):
            return resp["schema"]
        # OpenAPI 3: resp["content"][mediatype]["schema"]
        content = resp.get("content")
        if isinstance(content, dict):
            for mt in content.values():
                if isinstance(mt, dict) and isinstance(mt.get("schema"), dict):
                    return mt["schema"]
    return None


def resolve_response_schema(spec, path, method):
    """Conjunto dos nomes de campo declarados na resposta 2xx da operação.

    Resolve $ref contra components/schemas (OAS3) e definitions (Swagger2), lê
    `properties` inline. Só o 1º nível. Não resolvível → set() (não é erro:
    sinaliza "sem baseline para comparar")."""
    spec = _as_dict(spec) or {}
    item = (spec.get("paths") or {}).get(path)
    if not isinstance(item, dict):
        return set()
    operation = item.get(method.lower())
    if not isinstance(operation, dict):
        return set()
    node = _response_schema_node(operation)
    if node is None:
        return set()
    resolved = _resolve_ref(spec, node, set())
    props = resolved.get("properties") if isinstance(resolved, dict) else None
    if not isinstance(props, dict):
        return set()
    return set(props.keys())

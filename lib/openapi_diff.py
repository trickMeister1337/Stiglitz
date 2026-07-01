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
from urllib.parse import urlsplit

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from openapi_probe import _as_dict, documented_operations, op_url, unauth_verdict
from openapi_seed import _prefix as _spec_prefix
import netproxy

# Imports dos detectores de dado sensível (com fallback)
try:
    from pii_detect import extract_pii
    from pan_scanner import scan_text as _pan_scan
except Exception:  # importado fora de lib/
    def extract_pii(content, corporate_domains):
        return {}

    def _pan_scan(body):
        return []


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


def observed_fields(body, content_type=""):
    """Chaves de topo de um corpo JSON de objeto. Não-JSON / lista / inválido → set()."""
    ct = (content_type or "").lower()
    text = (body or "").lstrip()
    if not ("json" in ct or text[:1] == "{"):
        return set()
    try:
        obj = json.loads(body)
    except (ValueError, TypeError):
        return set()
    return set(obj.keys()) if isinstance(obj, dict) else set()


def excessive_fields(observed_body, declared_fields, content_type=""):
    """Campos de topo na resposta AUSENTES do schema declarado. Sem baseline
    (declared_fields vazio) → set() (não inventa exposição)."""
    if not declared_fields:
        return set()
    return observed_fields(observed_body, content_type) - set(declared_fields)


def classify_excessive(extra_fields, observed_body):
    """Severidade da exposição: critical se há PAN (Luhn+contexto), high se PII
    (CPF/CNPJ/email validado), senão medium."""
    if _pan_scan(observed_body or ""):
        return "critical"
    pii = extract_pii(observed_body or "", [])
    # extract_pii retorna dict com listas; qualquer lista não-vazia = PII encontrada
    # (CPF/CNPJ/email COM validação — não campos id numéricos)
    has_pii = any(
        isinstance(v, list) and len(v) > 0
        for v in (pii or {}).values()
    )
    return "high" if has_pii else "medium"


def documented_path_matchers(spec):
    """Um regex por path do spec: {param} (segmento inteiro) -> [^/]+ ; resto escapado;
    ancorado. Respeita basePath/servers via openapi_seed._prefix."""
    spec = _as_dict(spec) or {}
    prefix = _spec_prefix(spec) or ""
    out = []
    for raw in (spec.get("paths") or {}):
        if not isinstance(raw, str) or not raw.startswith("/"):
            continue
        full = raw if (not prefix or raw.startswith(prefix)) else prefix + raw
        # constrói o regex segmento a segmento: {param} vira [^/]+, o resto é literal
        segs = ["[^/]+" if (s.startswith("{") and s.endswith("}")) else re.escape(s)
                for s in full.split("/")]
        out.append(re.compile("^" + "/".join(segs) + "$"))
    return out


def shadow_paths(observed_urls, matchers, scope_host=""):
    """Paths observados que não casam nenhum matcher. Query-string removida;
    fora do scope_host descartado; dedup preservando ordem de 1ª ocorrência."""
    seen, out = set(), []
    for u in observed_urls or []:
        parts = urlsplit(u if "://" in u else "//" + u)
        if scope_host and parts.netloc and parts.netloc != scope_host:
            continue
        path = parts.path or "/"
        if path in seen:
            continue
        if any(m.match(path) for m in matchers):
            continue
        seen.add(path)
        out.append(path)
    return out

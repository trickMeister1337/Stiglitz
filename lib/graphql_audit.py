#!/usr/bin/env python3
"""
graphql_audit.py — introspection + abuse de GraphQL.

(#7/P0) Antes o GraphQL era só uma string em listas de paths — zero introspection,
zero abuse. Aqui há a query de introspection, o parser do schema e a derivação de
findings (introspection exposta = recon facilitado; mutations sensíveis = superfície
de authz). Núcleo puro (sem rede); o runner envia a query e passa o JSON aqui.
"""
import sys
import os
import json
import re

# Query de introspection enxuta (suficiente para enumerar tipos/campos/mutations).
_INTROSPECTION = (
    "query IntrospectionQuery { __schema { "
    "queryType { name } mutationType { name } "
    "types { name fields { name } } } }"
)

# Heurística de mutations sensíveis (authz/abuse) por nome.
_SENSITIVE_RE = re.compile(
    r"(delete|remove|drop|update|create|grant|revoke|reset|set|"
    r"admin|password|role|payment|refund|transfer|withdraw)", re.I)


def introspection_query():
    return _INTROSPECTION


def is_mutation(operation_body):
    """True se a operação GraphQL é uma mutation.

    Aceita o corpo JSON do POST ({"query": "..."}), a string da operação, ou um
    array de batch (mutation se QUALQUER op for mutation). Heurística: o keyword
    de operação top-level é 'mutation'. Queries anônimas ('{ ... }'), 'query' e
    'subscription' → False. Não faz parse completo de AST.
    """
    text = operation_body or ""
    try:
        obj = json.loads(text)
        if isinstance(obj, dict) and "query" in obj:
            text = obj.get("query") or ""
        elif isinstance(obj, list):
            return any(
                is_mutation(o.get("query", "")) if isinstance(o, dict) else False
                for o in obj)
    except (ValueError, TypeError):
        pass
    text = re.sub(r"#[^\n]*", "", text).lstrip()
    return bool(re.match(r"mutation\b", text, re.I))


def is_introspection_enabled(resp):
    return bool(((resp or {}).get("data") or {}).get("__schema"))


def parse_introspection(resp):
    """Extrai {types, mutations, query_type, mutation_type} do JSON de introspection."""
    if not is_introspection_enabled(resp):
        return None
    schema = resp["data"]["__schema"]
    types = [t.get("name") for t in schema.get("types", []) if t.get("name")]
    mutation_type = (schema.get("mutationType") or {}).get("name")
    mutations = []
    for t in schema.get("types", []):
        if t.get("name") == mutation_type:
            mutations = [fld.get("name") for fld in (t.get("fields") or []) if fld.get("name")]
    return {
        "types": types,
        "mutations": mutations,
        "query_type": (schema.get("queryType") or {}).get("name"),
        "mutation_type": mutation_type,
    }


def findings_from_response(resp, url):
    info = parse_introspection(resp)
    if info is None:
        return []
    findings = [{
        "tool": "graphql_audit", "type": "graphql_introspection", "source": "GraphQL",
        "name": "GraphQL introspection enabled", "url": url, "severity": "medium",
        "description": (f"Introspection is enabled, exposing the full schema "
                        f"({len(info['types'])} types, {len(info['mutations'])} mutations) — "
                        f"this eases targeted attacks against the API."),
        "remediation": "Disable introspection in production (or restrict to authenticated admins).",
        "cve": "CWE-200",
    }]
    sensitive = [m for m in info["mutations"] if _SENSITIVE_RE.search(m or "")]
    if sensitive:
        findings.append({
            "tool": "graphql_audit", "type": "graphql_sensitive_mutation", "source": "GraphQL",
            "name": "GraphQL exposes sensitive mutations", "url": url, "severity": "low",
            "description": ("State-changing/sensitive mutations were discovered via introspection: "
                            + ", ".join(sensitive[:15]) + ". Each must enforce object/function "
                            "level authorization (OWASP API1/API5)."),
            "remediation": "Verify authorization on every mutation; do not rely on schema obscurity.",
            "cve": "CWE-639",
        })
    return findings


def main(outdir, url, response_json=""):
    """Coletor: lê o JSON de uma resposta de introspection (de raw/graphql_resp.json
    ou argv) e emite raw/graphql_findings.json. O fetch ao vivo é feito pelo runner."""
    findings = []
    resp = None
    path = os.path.join(outdir, "raw", "graphql_resp.json")
    if response_json:
        try:
            resp = json.loads(response_json)
        except ValueError:
            resp = None
    elif os.path.exists(path):
        try:
            with open(path, encoding="utf-8", errors="ignore") as fh:
                resp = json.load(fh)
        except ValueError:
            resp = None
    if resp is not None:
        findings = findings_from_response(resp, url)
        for i, f in enumerate(findings, 1):
            f["id"] = f"GQL-{i:03d}"
    out = os.path.join(outdir, "raw", "graphql_findings.json")
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(findings, fh, indent=2, ensure_ascii=False)
    print(f"  [{'✓' if findings else '○'}] GraphQL audit: {len(findings)} finding(s) → graphql_findings.json")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else "",
         sys.argv[3] if len(sys.argv) > 3 else "")

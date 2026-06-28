#!/usr/bin/env python3
"""graphql_dos.py — detecção de resource-exhaustion em GraphQL (batching/aliasing).

Probes não-destrutivos (leituras de __typename, request único, contagem limitada)
que detectam AUSÊNCIA de limite de complexidade/alias e de batching. Não requer
introspection (usa __typename). Em production, faz dry-run. Lógica pura + send_fn
injetável.
"""
import json
import os
import sys

ALIAS_N_DEFAULT = 100
BATCH_M_DEFAULT = 15


def _alias_n():
    try:
        return max(2, int(os.environ.get("STIGLITZ_GQL_ALIAS_N", ALIAS_N_DEFAULT)))
    except ValueError:
        return ALIAS_N_DEFAULT


def _batch_m():
    try:
        return max(2, int(os.environ.get("STIGLITZ_GQL_BATCH_M", BATCH_M_DEFAULT)))
    except ValueError:
        return BATCH_M_DEFAULT


def build_alias_probe(n):
    """Query com n aliases de __typename (meta-campo universal, sem args)."""
    aliases = " ".join(f"a{i}:__typename" for i in range(n))
    return {"query": "{ " + aliases + " }"}


def build_batch_probe(m):
    """Array JSON de m operações pequenas (batch)."""
    return [{"query": "{__typename}"} for _ in range(m)]


def _is_graphql_response(status, body):
    """True se body parece um envelope GraphQL (data/errors)."""
    try:
        obj = json.loads(body or "")
    except (ValueError, TypeError):
        return False
    if isinstance(obj, dict):
        return "data" in obj or "errors" in obj
    if isinstance(obj, list):
        return any(isinstance(x, dict) and ("data" in x or "errors" in x) for x in obj)
    return False


def classify_alias_response(status, body, n):
    """Finding quando 200 + os n aliases resolveram (sem errors de complexidade)."""
    if int(status or 0) != 200:
        return None
    try:
        obj = json.loads(body or "")
    except (ValueError, TypeError):
        return None
    if not isinstance(obj, dict) or obj.get("errors"):
        return None
    data = obj.get("data") or {}
    resolved = sum(1 for k in data if k.startswith("a"))
    if resolved < n:
        return None
    return {
        "tool": "graphql_dos", "type": "graphql_no_complexity_limit", "source": "GraphQL",
        "name": "GraphQL lacks query complexity/alias limiting",
        "severity": "medium", "cve": "CWE-770",
        "description": (f"The endpoint resolved a query with {n} aliased fields without "
                        "rejection, indicating no query-complexity/alias limiting — a "
                        "resource-exhaustion (DoS) amplification vector."),
        "remediation": "Enforce query complexity/depth/alias limits (e.g., a cost-analysis plugin).",
    }


def classify_batch_response(status, body, m):
    """Finding quando a resposta é um array de >= 2 resultados (batch processado)."""
    try:
        obj = json.loads(body or "")
    except (ValueError, TypeError):
        return None
    if isinstance(obj, list) and len(obj) >= 2:
        return {
            "tool": "graphql_dos", "type": "graphql_batching_enabled", "source": "GraphQL",
            "name": "GraphQL query batching enabled",
            "severity": "low", "cve": "CWE-770",
            "description": (f"The endpoint processed a batched array of {len(obj)} operations, "
                            "enabling request amplification (brute-force/DoS)."),
            "remediation": "Disable array-based query batching or bound the batch size.",
        }
    return None

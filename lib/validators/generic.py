"""Validador Generic — fallback conservador para tipos sem categoria.

Anti-FP: HTTP 200 sozinho NÃO confirma. Exige auth evidence ou diff por
comportamento. Era a maior fonte de FP no v2/v3 antes de endurecermos.
"""
from . import register


@register("generic")
def validate(ctx):
    auth   = ctx["auth_ev"]
    status = ctx["status"]
    diff_changed = ctx["diff_changed"]
    diff_conf    = ctx["diff_conf"]
    diff_note    = ctx["diff_note"]
    dc_bonus     = ctx["dc_bonus"]

    if auth:
        return True, 82, f"Auth evidence: {auth[0]}"
    if diff_changed and diff_conf >= 15:
        return True, 65 + dc_bonus, f"Comportamento alterado: {diff_note}"
    if status in ("401", "403"):
        return False, 40, f"Endpoint existe (HTTP {status}) — sem bypass"
    if status.startswith("2") and diff_changed:
        return False, 45, f"HTTP {status} mas sem evidência suficiente — revisar manualmente"
    return False, 20, f"HTTP {status} sem evidência de vulnerabilidade"

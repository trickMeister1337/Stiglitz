"""Validador Auth Bypass — exige diff ou auth evidence (HTTP 200 sozinho não basta)."""
from . import register


@register("auth_bypass")
def validate(ctx):
    status = ctx["status"]
    auth   = ctx["auth_ev"]
    diff_changed = ctx["diff_changed"]
    diff_conf    = ctx["diff_conf"]
    diff_note    = ctx["diff_note"]
    dc_bonus     = ctx["dc_bonus"]

    if diff_changed and diff_conf >= 15:
        return True, min(88 + dc_bonus, 99), f"Bypass confirmado com diff: {diff_note}"
    if status.startswith("2") and diff_changed:
        return True, 80 + dc_bonus, f"Acesso com header bypass (HTTP {status}) + diff"
    if auth:
        return True, 85 + dc_bonus, f"Auth evidence com bypass: {auth[0]}"
    if status in ("401", "403"):
        return False, 15, f"Bypass não funcionou (HTTP {status})"
    if status.startswith("2"):
        return False, 45, f"HTTP {status} com bypass mas sem diff — revisar manualmente"
    return False, 15, f"HTTP {status} sem evidência de bypass"

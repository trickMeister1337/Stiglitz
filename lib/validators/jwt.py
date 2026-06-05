"""Validador JWT — evidência de token na resposta ou diff com JWT alterado."""
from . import register


@register("jwt")
def validate(ctx):
    auth   = ctx["auth_ev"]
    status = ctx["status"]
    diff_changed = ctx["diff_changed"]
    diff_conf    = ctx["diff_conf"]
    diff_note    = ctx["diff_note"]
    dc_bonus     = ctx["dc_bonus"]

    if auth:
        return True, min(90 + dc_bonus, 99), f"JWT/token na resposta: {auth[0]}"
    if diff_changed and diff_conf >= 15:
        return True, 75 + dc_bonus, f"Comportamento diferente com JWT modificado: {diff_note}"
    if status.startswith("2"):
        return False, 40, "HTTP 200 mas sem JWT no response — confirmar manualmente"
    return False, 20, f"HTTP {status} sem evidência JWT"

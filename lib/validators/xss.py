"""Validador XSS — extraído de poc_validator.validate()."""
import re

from . import register


@register("xss")
def validate(ctx):
    """XSS exige reflexão do payload. Diff só por tamanho não confirma sozinho."""
    resp = ctx["resp_body"] or ""
    diff_changed = ctx["diff_changed"]
    diff_conf    = ctx["diff_conf"]
    diff_note    = ctx["diff_note"]
    dc_bonus     = ctx["dc_bonus"]
    dc_result    = ctx["dc_result"]
    patterns     = ctx["patterns"].get("patterns", [])

    # Canário de reflexão (active_probe): refletido sem encoding = XSS provável.
    cn = ctx.get("canary")
    if cn and cn.get("reflected") and not cn.get("encoded"):
        return True, cn["confidence"], f"Canário refletido sem encoding: {cn.get('note', '')}"
    if cn and cn.get("reflected") and cn.get("encoded"):
        return False, cn["confidence"], f"Canário refletido mas HTML-encodado (provável safe): {cn.get('note', '')}"

    for pat in patterns:
        try:
            if re.search(pat, resp, re.IGNORECASE):
                return True, min(95 + dc_bonus, 99), f"XSS refletido: '{pat}'"
        except re.error:
            pass

    if diff_changed and diff_conf >= 20:
        return True, 68 + dc_bonus, f"Anomalia com payload: {diff_note}"

    if diff_changed and diff_conf >= 15:
        if dc_result and dc_result[0]:
            return (True, 60 + dc_bonus,
                    f"Diferença de tamanho corroborada: {diff_note}")
        return (False, 40,
                f"Diferença de tamanho sem reflexão confirmada: {diff_note}")

    return False, 20, "Payload não refletido ou encodado"

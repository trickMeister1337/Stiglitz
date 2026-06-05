"""Validador LFI — Local File Inclusion / Path Traversal."""
import re
from . import register


@register("lfi")
def validate(ctx):
    resp = ctx["resp_body"] or ""
    diff_changed = ctx["diff_changed"]
    diff_conf    = ctx["diff_conf"]
    diff_note    = ctx["diff_note"]
    dc_bonus     = ctx["dc_bonus"]
    dc_result    = ctx["dc_result"]
    patterns     = ctx["patterns"].get("patterns", [])

    for pat in patterns:
        try:
            if re.search(pat, resp, re.IGNORECASE):
                return True, min(97 + dc_bonus, 99), f"Conteúdo de sistema: '{pat}'"
        except re.error:
            pass

    if diff_changed and diff_conf >= 20:
        return True, 72 + dc_bonus, f"Inclusão disparou anomalia: {diff_note}"
    if diff_changed and diff_conf >= 15:
        if dc_result and dc_result[0]:
            return True, 62 + dc_bonus, f"Diferença de tamanho corroborada: {diff_note}"
        return False, 42, f"Diferença de tamanho sem conteúdo de sistema: {diff_note}"
    return False, 25, "Sem conteúdo de sistema no response"

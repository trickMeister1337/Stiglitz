"""Validador SSRF — Server-Side Request Forgery. Confirmação real via OOB."""
import re
from . import register


@register("ssrf")
def validate(ctx):
    resp = ctx["resp_body"] or ""
    diff_changed = ctx["diff_changed"]
    diff_conf    = ctx["diff_conf"]
    diff_note    = ctx["diff_note"]
    dc_bonus     = ctx["dc_bonus"]
    patterns     = ctx["patterns"].get("oob_patterns", ctx["patterns"].get("patterns", []))

    for pat in patterns:
        try:
            if re.search(pat, resp, re.IGNORECASE):
                return True, min(93 + dc_bonus, 99), f"Resposta interna detectada: '{pat}'"
        except re.error:
            pass

    if diff_changed and diff_conf >= 20:
        return True, 65 + dc_bonus, f"Diff com payload SSRF: {diff_note}"
    return False, 25, "Sem evidência de SSRF (use interação OOB para confirmar)"

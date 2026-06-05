"""Validador Subdomain Takeover — padrão de serviço inativo."""
import re
from . import register


@register("takeover")
def validate(ctx):
    resp = ctx["resp_body"] or ""
    patterns = ctx["patterns"].get("patterns", [])
    for pat in patterns:
        try:
            if re.search(pat, resp, re.IGNORECASE):
                return True, 95, f"Serviço inativo: '{pat}'"
        except re.error:
            pass
    return False, 25, "Sem indicador de serviço inativo"

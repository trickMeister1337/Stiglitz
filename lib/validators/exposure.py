"""Validador Exposure — dados sensíveis em response. Anti-FP por HTTP 200 só."""
import re
from . import register


@register("exposure")
def validate(ctx):
    resp = ctx["resp_body"] or ""
    status = ctx["status"]
    p = ctx["patterns"]

    cfg = p.get("config_pattern", "")
    if cfg:
        try:
            m = re.search(cfg, resp)
            if m:
                return True, 95, f"Credencial/dado sensível: '{m.group(0)[:60]}'"
        except re.error:
            pass
    for pat in p.get("high_confidence_patterns", []):
        try:
            if re.search(pat, resp):
                return True, 94, f"Dado sensível: '{pat}'"
        except re.error:
            pass
    for pat in p.get("patterns", []):
        try:
            if re.search(pat, resp, re.IGNORECASE):
                return True, 80, f"Padrão de exposição: '{pat}'"
        except re.error:
            pass

    if status.startswith("2") and len(resp) > 500:
        return False, 45, f"Recurso acessível ({len(resp)}B) mas sem dado sensível identificado"
    return False, 25, "Sem dado sensível identificável"

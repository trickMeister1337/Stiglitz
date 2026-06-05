"""Validador TLS — verificação de conectividade do endpoint TLS. Hardening."""
from . import register


@register("tls")
def validate(ctx):
    status = ctx["status"]
    if status.startswith("2") or status in ("301", "302", "403"):
        return True, 82, f"TLS acessível (HTTP {status}) — issue de config confirmada via testssl"
    if status in ("000", "TIMEOUT", "ERR"):
        return False, 20, "Endpoint TLS inacessível — não é possível confirmar"
    return False, 35, f"Endpoint retornou HTTP {status} — verificar manualmente"

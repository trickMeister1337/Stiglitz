"""Validador Security Header — headers ausentes (informativo, hardening)."""
from . import register

_REQUIRED = {
    "content-security-policy":    "CSP",
    "strict-transport-security":  "HSTS",
    "x-frame-options":            "X-Frame-Options",
    "x-content-type-options":     "X-Content-Type-Options",
    "referrer-policy":            "Referrer-Policy",
    "permissions-policy":         "Permissions-Policy",
}


@register("security_header")
def validate(ctx):
    h = (ctx["resp_headers"] or "").lower()
    status = ctx["status"]
    if not status.startswith("2") and status not in ("301", "302"):
        return False, 15, "Endpoint não retornou 2xx/3xx — verificação inválida"
    missing = [label for hdr, label in _REQUIRED.items() if hdr not in h]
    if missing:
        return True, 82, f"Headers ausentes verificados: {', '.join(missing)}"
    return False, 15, "Todos os headers de segurança presentes"

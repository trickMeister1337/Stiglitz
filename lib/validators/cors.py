"""Validador CORS — misconfigurations reflexivas + wildcard+credentials."""
from . import register


@register("cors")
def validate(ctx):
    headers = ctx["resp_headers"] or ""
    acao = next((l for l in headers.split("\n")
                 if "access-control-allow-origin" in l.lower()), "")
    acac = next((l for l in headers.split("\n")
                 if "access-control-allow-credentials" in l.lower()), "")
    cred_bonus = 20 if acac and "true" in acac.lower() else 0

    if acao and any(x in acao.lower() for x in ["evil.com", "null", "attacker"]):
        return True, min(97 + cred_bonus, 99), f"CORS reflete origem controlável: {acao.strip()[:80]}"
    if acao and "*" in acao and cred_bonus:
        return True, 85, "CORS wildcard + credentials=true (misconfiguration real)"
    if acao and "*" in acao:
        return False, 50, "CORS wildcard sem credentials — geralmente informacional"
    return False, 15, "CORS não misconfigured"

"""Validador Default Login — credenciais default aceitas."""
from . import register


@register("default_login")
def validate(ctx):
    b        = (ctx["resp_body"] or "").lower()
    auth     = ctx["auth_ev"]
    dc_bonus = ctx["dc_bonus"]
    patterns = ctx["patterns"].get("success_patterns",
                                   ["dashboard", "logout", "welcome", "logged in", "sign out"])
    method_results = ctx.get("method_results") or {}

    if auth:
        return True, min(97 + dc_bonus, 99), f"Auth confirmada: {auth[0]}"
    for pat in patterns:
        if pat.lower() in b:
            return True, 88 + dc_bonus, f"Indicador pós-login: '{pat}'"
    if method_results:
        ps = (method_results.get("POST") or ("???",))[0]
        gs = (method_results.get("GET")  or ("???",))[0]
        if ps.startswith("2") and not gs.startswith("2"):
            return True, 78 + dc_bonus, f"POST autenticado ({ps}) vs GET sem auth ({gs})"
    return False, 20, "Sem evidência de autenticação bem-sucedida"

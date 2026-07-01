"""Validador SSTI — Server-Side Template Injection (oráculo diferencial + fallback)."""
from . import register


@register("ssti")
def validate(ctx):
    oracle = ctx.get("ssti_oracle")
    if oracle and oracle.get("state") == "CONFIRMED":
        return (True, oracle.get("confidence", 90),
                f"SSTI confirmed by differential oracle: {(oracle.get('evidence') or '')[:160]}")
    # Fallback legado: nuclei já marcou; corrobora por anomalia de resposta.
    if ctx["diff_changed"] and ctx["diff_conf"] >= 20:
        return (True, 66 + ctx["dc_bonus"],
                f"Template injection corroborated by response anomaly: {ctx['diff_note']}")
    return False, 30, "No differential template evaluation confirmed"

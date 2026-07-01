"""Validador command-injection (oráculo diferencial + fallback)."""
from . import register


@register("cmdi")
def validate(ctx):
    oracle = ctx.get("cmdi_oracle")
    if oracle and oracle.get("state") == "CONFIRMED":
        return (True, oracle.get("confidence", 90),
                f"Command injection confirmed by differential oracle: "
                f"{(oracle.get('evidence') or '')[:160]}")
    # Fallback legado: nuclei já marcou; corrobora por anomalia de resposta.
    if ctx["diff_changed"] and ctx["diff_conf"] >= 20:
        return (True, 66 + ctx["dc_bonus"],
                f"Command injection corroborated by response anomaly: {ctx['diff_note']}")
    return False, 30, "No differential command execution confirmed"

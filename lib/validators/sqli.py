"""Validador SQLi — extraído de poc_validator.validate()."""
import re

from . import register


@register("sqli")
def validate(ctx):
    """Retorna (confirmed, confidence, note) — clamping aplicado pelo caller.

    Anti-FP central: diff só por tamanho (diff_conf=15) não confirma sozinho;
    exige double-check consistente. Diff por mensagens de erro (diff_conf>=20)
    é sinal forte.
    """
    resp = ctx["resp_body"] or ""
    status = ctx["status"]
    diff_changed = ctx["diff_changed"]
    diff_conf    = ctx["diff_conf"]
    diff_note    = ctx["diff_note"]
    dc_bonus     = ctx["dc_bonus"]
    dc_result    = ctx["dc_result"]
    patterns     = ctx["patterns"].get("patterns", [])

    # Padrões de erro SQL no response são prova direta
    for pat in patterns:
        try:
            if re.search(pat, resp, re.IGNORECASE):
                return True, min(95 + dc_bonus, 99), f"Erro SQL: '{pat}'"
        except re.error:
            pass

    if diff_changed and diff_conf >= 20:
        return (True, 70 + dc_bonus + diff_conf,
                f"Payload disparou erro/anomalia: {diff_note}")

    if diff_changed and diff_conf >= 15:
        # Diff só por tamanho — sinal fraco, exige double-check
        if dc_result and dc_result[0]:
            return (True, 62 + dc_bonus,
                    f"Diferença de tamanho corroborada por double-check: {diff_note}")
        return (False, 45,
                f"Diferença de tamanho sem corroboração (possível conteúdo dinâmico): {diff_note}")

    if status.startswith("5") and diff_changed:
        return True, 65 + dc_bonus, "5xx + diff — possível crash SQLi"

    return False, 30, "Sem indicador SQLi"

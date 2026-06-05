"""Validador Secret AWS — AKIA/ASIA keys, opcionalmente com secret pareado."""
import re
from . import register

_AWS_KEY_RE    = r"(?:AKIA|ASIA|AROA|AIPA|ANPA|ANVA)[A-Z0-9]{16}"
_AWS_SECRET_RE = r"[a-zA-Z0-9+/]{40}"


@register("secret_aws")
def validate(ctx):
    resp = ctx["resp_body"] or ""
    patterns = ctx["patterns"].get("patterns", [])

    has_key    = re.search(_AWS_KEY_RE,    resp) is not None
    has_secret = re.search(_AWS_SECRET_RE, resp) is not None

    if has_key and has_secret:
        return True, 99, "AWS Key + Secret expostos"
    if has_key:
        return True, 98, "AWS Access Key ID exposto"
    for pat in patterns:
        try:
            if re.search(pat, resp, re.IGNORECASE):
                return True, 90, f"Padrão AWS: '{pat}'"
        except re.error:
            pass
    return False, 20, "Sem credenciais AWS identificadas"

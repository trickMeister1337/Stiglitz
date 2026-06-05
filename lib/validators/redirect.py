"""Validador Open Redirect — exige destino realmente externo/controlável."""
import re
from . import register


@register("redirect")
def validate(ctx):
    headers = ctx["resp_headers"] or ""
    status  = ctx["status"]
    url     = ctx["url"]
    p       = ctx["patterns"]

    loc = next((l for l in headers.split("\n")
                if "location:" in l.lower()), "")
    if not loc:
        return False, 15, "Sem header Location — não há redirect"

    malicious = p.get("malicious_destinations",
                      ["evil.com", "//evil", "@evil", "javascript:",
                       "//attacker", "//127.0.0.1", "//localhost"])
    for dest in malicious:
        if dest in loc:
            return True, 94, f"Redirect externo confirmado: {loc.strip()[:100]}"

    url_domain = re.search(r"https?://([^/]+)", url or "")
    loc_domain = re.search(r"location:\s*https?://([^/\s]+)", loc, re.IGNORECASE)
    if url_domain and loc_domain:
        if url_domain.group(1).lower() != loc_domain.group(1).lower():
            return True, 78, f"Redirect para domínio externo: {loc.strip()[:100]}"

    return False, 30, f"Redirect ({status}) para destino interno — provavelmente FP"

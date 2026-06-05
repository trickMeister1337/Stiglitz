#!/usr/bin/env python3
"""
vuln_catalog.py — Catálogo: classe de vulnerabilidade → vetor CVSS 3.1 base + CWE.

Dá um vetor base defensável a findings que NÃO têm CVE (lógica de negócio,
IDOR/BOLA, authz, JWT, etc.). Indexável por nome de classe ou por CWE.
"""

# Cada entrada: classe -> {cwe, vector (base, sem CVSS:3.1/ prefixo de temporal/env), title}
CATALOG = {
    "idor_read_pii":      {"cwe": "CWE-639", "title": "IDOR — leitura de dados de outro usuário",
                           "vector": "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"},
    "idor_write":         {"cwe": "CWE-639", "title": "IDOR/BOLA — escrita em recurso de outro usuário",
                           "vector": "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"},
    "bola":               {"cwe": "CWE-639", "title": "Broken Object Level Authorization",
                           "vector": "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"},
    "broken_auth":        {"cwe": "CWE-287", "title": "Autenticação quebrada",
                           "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"},
    "priv_escalation":    {"cwe": "CWE-269", "title": "Escalação de privilégio",
                           "vector": "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"},
    "amount_tampering":   {"cwe": "CWE-840", "title": "Manipulação de valor/transação",
                           "vector": "AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N"},
    "race_condition_funds": {"cwe": "CWE-362", "title": "Race condition em fluxo financeiro",
                           "vector": "AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:N"},
    "jwt_alg_none":       {"cwe": "CWE-347", "title": "JWT aceita alg=none",
                           "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"},
    "jwt_weak_secret":    {"cwe": "CWE-347", "title": "JWT com segredo fraco (HS256)",
                           "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"},
    "csrf_state_changing": {"cwe": "CWE-352", "title": "CSRF em ação que altera estado",
                           "vector": "AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N"},
    "ssrf":               {"cwe": "CWE-918", "title": "Server-Side Request Forgery",
                           "vector": "AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N"},
    "open_redirect":      {"cwe": "CWE-601", "title": "Open redirect",
                           "vector": "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"},
    "missing_security_header": {"cwe": "CWE-693", "title": "Cabeçalho de segurança ausente",
                           "vector": "AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N"},
    "spf_dmarc_weak":     {"cwe": "CWE-290", "title": "SPF/DMARC permite spoofing",
                           "vector": "AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N"},
    "rate_limit_missing": {"cwe": "CWE-307", "title": "Falta de rate limiting",
                           "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:L"},
}

# Índice secundário por CWE (primeira classe que mapeia para o CWE).
_BY_CWE = {}
for _k, _v in CATALOG.items():
    _BY_CWE.setdefault(_v["cwe"], dict(_v, **{"class": _k}))
del _k, _v


def lookup(key):
    """Retorna {vector, cwe, title} por nome de classe ou por CWE; None se ausente."""
    if key in CATALOG:
        return dict(CATALOG[key])
    if key in _BY_CWE:
        e = dict(_BY_CWE[key])
        e.pop("class", None)
        return e
    return None

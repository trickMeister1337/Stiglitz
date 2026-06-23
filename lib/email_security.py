#!/usr/bin/env python3
"""
email_security.py — SPF/DMARC/DKIM → email_security.json

Funções de classificação puras (importáveis) + CLI sob main().
"""
import subprocess, json, sys, re, os

DKIM_SELECTORS = ["default", "google", "mail", "k1", "s1", "s2", "email", "selector1", "selector2"]

# Sufixos públicos compostos (multi-label) relevantes — usados para derivar o
# domínio organizacional (eTLD+1) sem depender da Public Suffix List completa.
# Foco em BR + sufixos globais comuns; o fallback é eTLD+1 de 2 labels.
_MULTI_LABEL_SUFFIXES = {
    "com.br", "net.br", "org.br", "gov.br", "edu.br", "art.br", "blog.br",
    "co.uk", "org.uk", "gov.uk", "ac.uk", "co.jp", "or.jp", "ne.jp",
    "com.au", "net.au", "org.au", "co.nz", "co.za", "com.mx", "com.ar",
    "co.in", "com.cn", "com.tr", "com.sg", "com.hk",
}


def organizational_domain(fqdn):
    """Domínio organizacional (eTLD+1) de um FQDN — RFC 7489 §3.2.

    `webapp.example.com` -> `example.com`; `api.foo.com.br` -> `foo.com.br`.
    Heurística: sufixo composto conhecido (3 labels) antes do eTLD+1 padrão (2).
    """
    labels = fqdn.strip(".").lower().split(".")
    if len(labels) <= 2:
        return ".".join(labels)
    if ".".join(labels[-2:]) in _MULTI_LABEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _dmarc_policies(record):
    """Extrai (p, sp) de um registro DMARC — valores ou None."""
    p = re.search(r'\bp=(none|quarantine|reject)', record, re.IGNORECASE)
    sp = re.search(r'\bsp=(none|quarantine|reject)', record, re.IGNORECASE)
    return (p.group(1).lower() if p else None,
            sp.group(1).lower() if sp else None)


def dig(record_type, name, short=True):
    cmd = ["dig", "+short", record_type, name] if short else ["dig", record_type, name]
    try:
        return subprocess.check_output(cmd, timeout=10, text=True).strip()
    except Exception:
        return ""


def classify_spf(spf_records, host_has_mx=True):
    if not spf_records:
        sev = "high"
        detail = "SPF record missing — any server can send email on behalf of the domain."
        if not host_has_mx:
            sev = "low"
            detail += (" Host has no MX record and does not appear to send/receive "
                       "email, which limits the practical spoofing impact.")
        return {"status": "MISSING", "severity": sev,
                "detail": detail,
                "recommendation": "Add a TXT SPF record, e.g. v=spf1 include:_spf.google.com ~all"}
    if any("+all" in r for r in spf_records):
        return {"status": "PERMISSIVE", "severity": "high",
                "detail": "SPF with '+all' allows ANY server to send email for the domain.",
                "value": spf_records[0],
                "recommendation": "Replace '+all' with '~all' (softfail) or '-all' (hardfail)."}
    if any("?all" in r for r in spf_records):
        return {"status": "NEUTRAL", "severity": "medium",
                "detail": "SPF with '?all' (neutral) does not block unauthorized senders.",
                "value": spf_records[0],
                "recommendation": "Replace '?all' with '~all' or '-all'."}
    qual = "softfail (~all)" if "~all" in spf_records[0] else "hardfail (-all)" if "-all" in spf_records[0] else "configured"
    return {"status": "OK", "severity": "none",
            "detail": f"SPF configured correctly ({qual}).",
            "value": spf_records[0]}


def classify_dmarc(dmarc_records, domain, org_records=None, org_domain=None, host_has_mx=True):
    if not dmarc_records:
        # RFC 7489 §6.6.3: sem DMARC no FQDN, a política do domínio organizacional
        # governa o subdomínio. Honra a policy herdada (sp= governa subdomínios)
        # antes de cravar MISSING.
        if org_records and org_domain and org_domain != domain:
            org = org_records[0]
            p, sp = _dmarc_policies(org)
            effective = sp or p
            if effective in ("quarantine", "reject"):
                return {"status": "INHERITED_OK", "severity": "none", "policy": effective,
                        "inherited_from": org_domain,
                        "detail": (f"No DMARC record at {domain}, but the organizational domain "
                                   f"{org_domain} publishes p/sp={effective}, which governs this "
                                   f"subdomain (RFC 7489 §6.6.3)."),
                        "value": org}
            if effective == "none":
                return {"status": "INHERITED_MONITOR", "severity": "low", "policy": "none",
                        "inherited_from": org_domain,
                        "detail": (f"The organizational domain {org_domain} publishes DMARC but with "
                                   f"p/sp=none (monitor only) — spoofed mail using {domain} can still "
                                   f"reach recipients."),
                        "value": org,
                        "recommendation": "Set sp=quarantine or sp=reject on the organizational DMARC record."}
        sev = "high"
        detail = "DMARC record missing — no visibility or control over domain abuse."
        if not host_has_mx:
            sev = "low"
            detail += (" Host has no MX record and does not appear to send/receive email, "
                       "which limits the practical spoofing impact.")
        return {"status": "MISSING", "severity": sev,
                "detail": detail,
                "recommendation": "Adicione: _dmarc." + domain + " TXT \"v=DMARC1; p=quarantine; rua=mailto:dmarc@" + domain + "\""}
    dmarc = dmarc_records[0]
    policy_m = re.search(r'p=(none|quarantine|reject)', dmarc, re.IGNORECASE)
    policy = policy_m.group(1).lower() if policy_m else "unknown"
    if policy == "none":
        return {"status": "MONITOR_ONLY", "severity": "medium", "policy": policy,
                "detail": "DMARC with p=none only monitors — spoofed emails still reach recipients.",
                "value": dmarc,
                "recommendation": "Move to p=quarantine and then p=reject after validating reports."}
    if policy in ("quarantine", "reject"):
        return {"status": "OK", "severity": "none", "policy": policy,
                "detail": f"DMARC configured with p={policy}.",
                "value": dmarc}
    return {"status": "INVALID", "severity": "medium", "policy": policy,
            "detail": f"DMARC with invalid or unrecognized policy: {policy}",
            "value": dmarc,
            "recommendation": "Check the DMARC record syntax."}


def classify_dkim(dkim_found):
    if dkim_found:
        return {"status": "OK", "severity": "none",
                "detail": f"DKIM found for selectors: {', '.join(dkim_found)}"}
    return {"status": "NOT_FOUND", "severity": "low",
            "detail": "DKIM not detected on common selectors. It may be configured with a custom selector.",
            "recommendation": "Verify whether the email provider configured DKIM for the domain."}


def analyze(domain):
    """Resolve DNS e classifica SPF/DMARC/DKIM. Retorna o dict de resultados."""
    spf_raw = dig("TXT", domain)
    spf_records = [l for l in spf_raw.splitlines() if "v=spf1" in l.lower()]

    dmarc_raw = dig("TXT", f"_dmarc.{domain}")
    dmarc_records = [l for l in dmarc_raw.splitlines() if "v=dmarc1" in l.lower()]

    # RFC 7489 §6.6.3: se o FQDN não publica DMARC, sobe ao domínio organizacional
    # (eTLD+1) e honra a política herdada antes de reportar MISSING.
    org_domain = organizational_domain(domain)
    org_records = []
    if org_domain != domain:
        org_raw = dig("TXT", f"_dmarc.{org_domain}")
        org_records = [l for l in org_raw.splitlines() if "v=dmarc1" in l.lower()]

    # MX-awareness: um host sem MX (ex.: CNAME → LB) não recebe email e tipicamente
    # não o envia — o impacto prático de SPF/DMARC ausentes é menor.
    host_has_mx = bool(dig("MX", domain).strip())

    dkim_found = []
    for sel in DKIM_SELECTORS:
        r = dig("TXT", f"{sel}._domainkey.{domain}")
        if "v=dkim1" in r.lower() or "p=" in r:
            dkim_found.append(sel)

    return {
        "spf": classify_spf(spf_records, host_has_mx=host_has_mx),
        "dmarc": classify_dmarc(dmarc_records, domain,
                                org_records=org_records, org_domain=org_domain,
                                host_has_mx=host_has_mx),
        "dkim": classify_dkim(dkim_found),
    }


def main():
    domain = sys.argv[1]
    outdir = sys.argv[2]
    results = analyze(domain)

    with open(os.path.join(outdir, "raw", "email_security.json"), "w") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)

    issues = sum(1 for v in results.values() if v["severity"] in ("high", "medium"))
    print(f"  [{'!' if issues else '✓'}] SPF: {results['spf']['status']} | DMARC: {results['dmarc']['status']} | DKIM: {results['dkim']['status']}")
    if issues:
        print(f"  [!] {issues} problema(s) de segurança de email encontrado(s)")
        for key, val in results.items():
            if val["severity"] in ("high", "medium"):
                print(f"      • {key.upper()}: {val['detail']}")


if __name__ == "__main__":
    main()

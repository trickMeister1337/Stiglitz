#!/usr/bin/env python3
"""
compliance_map.py — crosswalk CWE → frameworks de compliance.

(#10) O relatório só tinha CWE→CVSS e 3 requisitos PCI hardcoded. Aqui mapeamos
cada CWE para OWASP Top 10 2021, OWASP ASVS 4.0, PCI DSS 4.0.1, ISO 27001:2022
Anexo A e NIST 800-53 Rev5 — puro lookup, já que Nuclei/ZAP carregam o CWE no
finding. Permite a seção "Compliance Mapping" e o filtro "só gaps de PCI".
"""
import re

# CWE -> {owasp, asvs, pci, iso, nist}. Cobre as classes que o scanner produz.
_MAP = {
    "79":   {"owasp": "A03:2021-Injection", "asvs": "V5.3.3", "pci": "6.2.4", "iso": "A.8.28", "nist": "SI-10"},
    "89":   {"owasp": "A03:2021-Injection", "asvs": "V5.3.4", "pci": "6.2.4", "iso": "A.8.28", "nist": "SI-10"},
    "943":  {"owasp": "A03:2021-Injection", "asvs": "V5.3.4", "pci": "6.2.4", "iso": "A.8.28", "nist": "SI-10"},
    "77":   {"owasp": "A03:2021-Injection", "asvs": "V5.3.8", "pci": "6.2.4", "iso": "A.8.28", "nist": "SI-10"},
    "78":   {"owasp": "A03:2021-Injection", "asvs": "V5.3.8", "pci": "6.2.4", "iso": "A.8.28", "nist": "SI-10"},
    "94":   {"owasp": "A03:2021-Injection", "asvs": "V5.2.4", "pci": "6.2.4", "iso": "A.8.28", "nist": "SI-10"},
    "1336": {"owasp": "A03:2021-Injection", "asvs": "V5.2.5", "pci": "6.2.4", "iso": "A.8.28", "nist": "SI-10"},
    "22":   {"owasp": "A01:2021-Broken Access Control", "asvs": "V12.3.1", "pci": "6.2.4", "iso": "A.8.3", "nist": "AC-3"},
    "639":  {"owasp": "A01:2021-Broken Access Control", "asvs": "V4.2.1", "pci": "6.2.4", "iso": "A.8.3", "nist": "AC-3"},
    "284":  {"owasp": "A01:2021-Broken Access Control", "asvs": "V4.1.1", "pci": "7.2.1", "iso": "A.8.3", "nist": "AC-3"},
    "862":  {"owasp": "A01:2021-Broken Access Control", "asvs": "V4.1.3", "pci": "7.2.1", "iso": "A.8.3", "nist": "AC-6"},
    "352":  {"owasp": "A01:2021-Broken Access Control", "asvs": "V4.2.2", "pci": "6.2.4", "iso": "A.8.26", "nist": "SC-8"},
    "601":  {"owasp": "A01:2021-Broken Access Control", "asvs": "V5.1.5", "pci": "6.2.4", "iso": "A.8.26", "nist": "SI-10"},
    "918":  {"owasp": "A10:2021-Server-Side Request Forgery", "asvs": "V12.6.1", "pci": "6.2.4", "iso": "A.8.28", "nist": "SC-7"},
    "611":  {"owasp": "A05:2021-Security Misconfiguration", "asvs": "V5.5.2", "pci": "6.2.4", "iso": "A.8.28", "nist": "SI-10"},
    "502":  {"owasp": "A08:2021-Software and Data Integrity Failures", "asvs": "V5.5.3", "pci": "6.2.4", "iso": "A.8.28", "nist": "SI-10"},
    "1321": {"owasp": "A08:2021-Software and Data Integrity Failures", "asvs": "V5.5.4", "pci": "6.2.4", "iso": "A.8.28", "nist": "SI-10"},
    "287":  {"owasp": "A07:2021-Identification and Authentication Failures", "asvs": "V2.1.1", "pci": "8.3.1", "iso": "A.8.5", "nist": "IA-2"},
    "307":  {"owasp": "A07:2021-Identification and Authentication Failures", "asvs": "V2.2.1", "pci": "8.3.4", "iso": "A.8.5", "nist": "AC-7"},
    "384":  {"owasp": "A07:2021-Identification and Authentication Failures", "asvs": "V3.2.1", "pci": "6.2.4", "iso": "A.8.5", "nist": "IA-2"},
    "798":  {"owasp": "A07:2021-Identification and Authentication Failures", "asvs": "V2.10.1", "pci": "8.6.1", "iso": "A.8.5", "nist": "IA-5"},
    "347":  {"owasp": "A02:2021-Cryptographic Failures", "asvs": "V3.5.2", "pci": "8.3.1", "iso": "A.8.24", "nist": "SC-13"},
    "319":  {"owasp": "A02:2021-Cryptographic Failures", "asvs": "V9.1.1", "pci": "4.2.1", "iso": "A.8.24", "nist": "SC-8"},
    "326":  {"owasp": "A02:2021-Cryptographic Failures", "asvs": "V6.2.1", "pci": "4.2.1", "iso": "A.8.24", "nist": "SC-13"},
    "327":  {"owasp": "A02:2021-Cryptographic Failures", "asvs": "V6.2.2", "pci": "4.2.1", "iso": "A.8.24", "nist": "SC-13"},
    "200":  {"owasp": "A01:2021-Broken Access Control", "asvs": "V14.3.2", "pci": "6.2.4", "iso": "A.8.12", "nist": "SC-7"},
    "16":   {"owasp": "A05:2021-Security Misconfiguration", "asvs": "V14.4.1", "pci": "2.2.1", "iso": "A.8.9", "nist": "CM-6"},
    "693":  {"owasp": "A05:2021-Security Misconfiguration", "asvs": "V14.4.3", "pci": "2.2.1", "iso": "A.8.9", "nist": "CM-6"},
    "434":  {"owasp": "A04:2021-Insecure Design", "asvs": "V12.2.1", "pci": "6.2.4", "iso": "A.8.25", "nist": "SI-10"},
    "1395": {"owasp": "A06:2021-Vulnerable and Outdated Components", "asvs": "V14.2.1", "pci": "6.3.3", "iso": "A.8.8", "nist": "SI-2"},
    "937":  {"owasp": "A06:2021-Vulnerable and Outdated Components", "asvs": "V14.2.1", "pci": "6.3.3", "iso": "A.8.8", "nist": "SI-2"},
    "1104": {"owasp": "A06:2021-Vulnerable and Outdated Components", "asvs": "V14.2.1", "pci": "6.3.3", "iso": "A.8.8", "nist": "SI-2"},
    "117":  {"owasp": "A09:2021-Security Logging and Monitoring Failures", "asvs": "V7.1.1", "pci": "10.2.1", "iso": "A.8.15", "nist": "AU-2"},
    "778":  {"owasp": "A09:2021-Security Logging and Monitoring Failures", "asvs": "V7.1.2", "pci": "10.2.1", "iso": "A.8.15", "nist": "AU-2"},
}

_CWE_RE = re.compile(r"CWE-(\d+)", re.IGNORECASE)


def frameworks_for_cwe(cwe):
    """Retorna o dict de frameworks para um CWE ('79' ou 'CWE-79'); {} se desconhecido."""
    if not cwe:
        return {}
    num = str(cwe).strip().upper().replace("CWE-", "")
    return _MAP.get(num, {})


def extract_cwe(finding):
    """Extrai o número do CWE de um finding (campo 'cwe' ou 'cve'); None se não houver."""
    for field in ("cwe", "cve"):
        m = _CWE_RE.search(str(finding.get(field, "")))
        if m:
            return m.group(1)
    return None


def tag_finding(finding):
    """Anexa finding['compliance'] = frameworks (se o CWE for conhecido)."""
    fr = frameworks_for_cwe(extract_cwe(finding))
    if fr:
        finding["compliance"] = fr
    return fr


def compliance_summary(findings):
    """Agrega contagem de findings por controle, por framework."""
    summary = {"owasp": {}, "asvs": {}, "pci": {}, "iso": {}, "nist": {}}
    for f in findings:
        fr = frameworks_for_cwe(extract_cwe(f))
        for fw, control in fr.items():
            if control:
                summary[fw][control] = summary[fw].get(control, 0) + 1
    return summary


# Requisito PCI → chave de capacidade do scan (sinal de "a fase rodou").
# Universo = requisitos que o scanner consegue exercitar (crosswalk _MAP + pci_verdicts).
_REQ_COVERAGE = {
    "2.2.1":  "headers",     # hardening / misconfig
    "2.2.5":  "services",    # serviços de rede expostos
    "3.2":    "cde",         # proteção de dados no CDE
    "4.2.1":  "tls",         # TLS forte
    "6.2.4":  "webapp",      # app seguro (injeção/XSS/CSRF/SSRF)
    "6.3.3":  "components",  # componentes atualizados
    "7.2.1":  "authz",       # controle de acesso
    "8.3.1":  "authn",       # autenticação
    "8.3.4":  "authn",
    "8.6.1":  "authn",
    "10.2.1": "logging",     # logging/monitoring — DAST não exercita → só FAIL se houver finding
}


def _req_key(req):
    """Ordena requisitos PCI numericamente ('2.2.1' antes de '10.2.1')."""
    return tuple(int(x) for x in re.findall(r"\d+", req))


def pci_posture(findings, coverage=None):
    """Veredito PASS/FAIL/N-A por requisito PCI.

    FAIL: >=1 finding mapeado (CWE->pci OU campo pci_req).
    PASS: sem finding e a capacidade de cobertura está ativa em `coverage`.
    N/A:  capacidade não exercida (default conservador — nunca PASS falso).

    Retorna lista de {req, verdict, count, top_findings} ordenada por requisito.
    """
    coverage = coverage or {}
    counts, tops = {}, {}
    for f in findings:
        reqs = set()
        fr = frameworks_for_cwe(extract_cwe(f))
        if fr.get("pci"):
            reqs.add(fr["pci"])
        if f.get("pci_req"):
            reqs.add(f["pci_req"])
        for r in reqs:
            counts[r] = counts.get(r, 0) + 1
            bucket = tops.setdefault(r, [])
            name = f.get("name")
            if name and len(bucket) < 3:
                bucket.append(name)
    out = []
    for req in sorted(set(_REQ_COVERAGE) | set(counts), key=_req_key):
        n = counts.get(req, 0)
        if n > 0:
            verdict = "FAIL"
        else:
            cov_key = _REQ_COVERAGE.get(req)
            verdict = "PASS" if (cov_key and coverage.get(cov_key)) else "N/A"
        out.append({"req": req, "verdict": verdict, "count": n,
                    "top_findings": tops.get(req, [])})
    return out


# ── OWASP Top 10 (2021) coverage — espelha o padrão pci_posture ──────────
# Lista canônica (ordem oficial A01→A10) + título.
_OWASP_CATEGORIES = [
    ("A01:2021", "Broken Access Control"),
    ("A02:2021", "Cryptographic Failures"),
    ("A03:2021", "Injection"),
    ("A04:2021", "Insecure Design"),
    ("A05:2021", "Security Misconfiguration"),
    ("A06:2021", "Vulnerable and Outdated Components"),
    ("A07:2021", "Identification and Authentication Failures"),
    ("A08:2021", "Software and Data Integrity Failures"),
    ("A09:2021", "Security Logging and Monitoring Failures"),
    ("A10:2021", "Server-Side Request Forgery"),
]

# categoria → capability-keys do _coverage; TESTED se QUALQUER uma rodou.
# Lista vazia = NOT-COVERED por design (scan automatizado não exercita).
_OWASP_COVERAGE = {
    "A01:2021": ["webapp", "authz"],
    "A02:2021": ["tls"],
    "A03:2021": ["webapp"],
    "A04:2021": [],
    "A05:2021": ["headers", "webapp"],
    "A06:2021": ["components", "retire"],
    "A07:2021": ["authn", "webapp"],
    "A08:2021": [],
    "A09:2021": [],
    "A10:2021": ["webapp"],
}

# nota textual fixa para categorias parcial/manualmente cobertas.
_OWASP_NOTES = {
    "A04:2021": "Design-level — requires manual review; not exercised by automated DAST.",
    "A08:2021": "Largely manual — only insecure deserialization (CWE-502) surfaces via automated DAST; CI/CD & SRI integrity require manual review.",
    "A09:2021": "Largely manual — logging/monitoring findings (CWE-117/778) surface via DAST only when present; full coverage requires log/monitoring configuration review.",
}


def _owasp_category(finding):
    """Prefixo 'A0N:2021' da categoria OWASP do finding, ou None.

    _MAP guarda a string completa ('A03:2021-Injection'); casamos pelo prefixo
    antes do '-' para bater com _OWASP_CATEGORIES.
    """
    owasp = frameworks_for_cwe(extract_cwe(finding)).get("owasp", "")
    # maxsplit=1: keep "A0N:2021"; the suffix after the first "-" is the title.
    return owasp.split("-", 1)[0] if owasp else None


def owasp_posture(findings, coverage=None):
    """Veredito de cobertura por categoria OWASP Top 10 2021.

    FOUND:       >=1 finding mapeado à categoria (count>0 sempre vence).
    TESTED:      sem finding e alguma capability da categoria ativa em `coverage`.
    NOT-COVERED: categoria sem capability automatizada (A04/A08/A09) ou nenhuma
                 capability ativa neste scan (default conservador — nunca afirma
                 cobertura falsa).

    Retorna SEMPRE as 10 categorias (ordem A01→A10), cada uma:
    {category, title, verdict, count, top_findings, note}. Puro — sem rede.
    """
    coverage = coverage or {}
    counts, tops = {}, {}
    for f in findings:
        cat = _owasp_category(f)
        if not cat:
            continue
        counts[cat] = counts.get(cat, 0) + 1
        bucket = tops.setdefault(cat, [])
        name = f.get("name")
        if name and len(bucket) < 3:
            bucket.append(name)
    out = []
    for cat, title in _OWASP_CATEGORIES:
        n = counts.get(cat, 0)
        if n > 0:
            verdict = "FOUND"
        elif any(coverage.get(c) for c in _OWASP_COVERAGE.get(cat, [])):
            verdict = "TESTED"
        else:
            verdict = "NOT-COVERED"
        out.append({"category": cat, "title": title, "verdict": verdict,
                    "count": n,
                    "top_findings": tops.get(cat, []) if n > 0 else [],
                    "note": _OWASP_NOTES.get(cat)})
    return out

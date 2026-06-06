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

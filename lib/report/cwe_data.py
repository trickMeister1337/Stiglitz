#!/usr/bin/env python3
"""
cwe_data.py — Tabelas CWE → CVSS sintético, impacto prático, remediação.

Extraído de stiglitz_report.py para permitir reutilização (RED, batch) e
teste em isolamento. Pure data + 2 helpers puros (sem IO).
"""
import re

# ── Tabela CWE → CVSS sintético (baseado em médias históricas NVD) ──
# Usada como fallback para alertas ZAP que não trazem CVE nas referências
CWE_CVSS_TABLE = {
    # Injeção / execução
    "89":  {"cvss": 9.8, "sev": "CRITICAL", "name": "SQL Injection"},
    "78":  {"cvss": 9.8, "sev": "CRITICAL", "name": "OS Command Injection"},
    "77":  {"cvss": 9.8, "sev": "CRITICAL", "name": "Command Injection"},
    "94":  {"cvss": 9.8, "sev": "CRITICAL", "name": "Code Injection"},
    "502": {"cvss": 9.8, "sev": "CRITICAL", "name": "Deserialization of Untrusted Data"},
    "611": {"cvss": 9.1, "sev": "CRITICAL", "name": "XXE"},
    "918": {"cvss": 9.8, "sev": "CRITICAL", "name": "SSRF"},
    # Autenticação / controle de acesso
    "287": {"cvss": 9.1, "sev": "CRITICAL", "name": "Improper Authentication"},
    "306": {"cvss": 9.1, "sev": "CRITICAL", "name": "Missing Authentication"},
    "284": {"cvss": 8.8, "sev": "HIGH",     "name": "Improper Access Control"},
    "285": {"cvss": 8.8, "sev": "HIGH",     "name": "Improper Authorization"},
    "862": {"cvss": 8.1, "sev": "HIGH",     "name": "Missing Authorization"},
    "863": {"cvss": 8.1, "sev": "HIGH",     "name": "Incorrect Authorization"},
    "269": {"cvss": 8.8, "sev": "HIGH",     "name": "Improper Privilege Management"},
    # Exposição de dados
    "22":  {"cvss": 7.5, "sev": "HIGH",     "name": "Path Traversal"},
    "23":  {"cvss": 7.5, "sev": "HIGH",     "name": "Relative Path Traversal"},
    "200": {"cvss": 5.3, "sev": "MEDIUM",   "name": "Information Disclosure"},
    "312": {"cvss": 5.5, "sev": "MEDIUM",   "name": "Cleartext Storage of Sensitive Info"},
    "319": {"cvss": 5.9, "sev": "MEDIUM",   "name": "Cleartext Transmission"},
    "359": {"cvss": 6.5, "sev": "MEDIUM",   "name": "Privacy Violation"},
    # XSS / client-side
    "79":  {"cvss": 6.1, "sev": "MEDIUM",   "name": "Cross-Site Scripting (XSS)"},
    "80":  {"cvss": 6.1, "sev": "MEDIUM",   "name": "Basic XSS"},
    "116": {"cvss": 5.4, "sev": "MEDIUM",   "name": "Improper Encoding/Escaping"},
    "1021":{"cvss": 4.7, "sev": "MEDIUM",   "name": "Clickjacking"},
    # CSRF / sessão
    "352": {"cvss": 8.8, "sev": "HIGH",     "name": "Cross-Site Request Forgery"},
    "384": {"cvss": 7.1, "sev": "HIGH",     "name": "Session Fixation"},
    "613": {"cvss": 5.4, "sev": "MEDIUM",   "name": "Insufficient Session Expiration"},
    # Criptografia / TLS
    "326": {"cvss": 7.5, "sev": "HIGH",     "name": "Inadequate Encryption Strength"},
    "327": {"cvss": 7.5, "sev": "HIGH",     "name": "Broken Crypto Algorithm"},
    "330": {"cvss": 7.5, "sev": "HIGH",     "name": "Insufficient Random Values"},
    "295": {"cvss": 7.4, "sev": "HIGH",     "name": "Improper Certificate Validation"},
    # Configuração / exposição
    "16":  {"cvss": 5.3, "sev": "MEDIUM",   "name": "Configuration"},
    "693": {"cvss": 5.3, "sev": "MEDIUM",   "name": "Missing Security Header"},
    "1004":{"cvss": 4.0, "sev": "MEDIUM",   "name": "Cookie Without HttpOnly"},
    "1395":{"cvss": 6.1, "sev": "MEDIUM",   "name": "Vulnerable JavaScript Library"},
    "404": {"cvss": 5.3, "sev": "MEDIUM",   "name": "Improper Resource Shutdown"},
    "497": {"cvss": 4.3, "sev": "MEDIUM",   "name": "Exposure of System Data"},
    "525": {"cvss": 3.7, "sev": "LOW",      "name": "Browser Caching Sensitive Info"},
}


def cwe_enrich(cweid_str):
    """Dado CWE-89 ou 89, retorna dict com cvss/sev/name ou None."""
    if not cweid_str:
        return None
    cwe_num = re.sub(r"[^0-9]", "", str(cweid_str))
    return CWE_CVSS_TABLE.get(cwe_num)


def cvss_to_sev(score):
    """Converte score CVSS para severidade pelo padrão NVD."""
    if score is None:
        return None
    score = float(score)
    if score >= 9.0: return "critical"
    if score >= 7.0: return "high"
    if score >= 4.0: return "medium"
    if score >= 0.1: return "low"
    return "info"


# ── Mapa de impacto prático por CWE (linguagem para tech lead) ──
IMPACT_MAP = {
    "89":  "An attacker can read, modify or delete database data, including user and transaction data.",
    "78":  "An attacker can execute arbitrary commands on the server, compromising the entire infrastructure.",
    "79":  "Malicious scripts can run in users' browsers, stealing sessions and credentials.",
    "352": "An attacker can force authenticated users to perform unauthorized actions (e.g. transfers, data changes).",
    "22":  "An attacker can access arbitrary server files, including configurations and private keys.",
    "287": "Unauthorized access to the application, allowing impersonation of any user including administrators.",
    "306": "Critical endpoints accessible without authentication, exposing data and functionality to anyone.",
    "284": "Users can access other users' resources or data (IDOR, privilege escalation).",
    "918": "The server can be used as a proxy to reach protected internal services (AWS metadata, databases).",
    "611": "Processing external XML can leak server files or cause denial of service.",
    "502": "Deserialization of untrusted data can result in remote code execution.",
    "326": "Encrypted communications can be intercepted and decrypted by attackers on the network.",
    "327": "Weak cryptographic algorithms can be broken, exposing sensitive data.",
    "295": "TLS communications can be intercepted by man-in-the-middle attacks.",
    "1021":"Users can be tricked into clicking invisible overlaid elements (clickjacking).",
    "319": "Data transmitted in cleartext can be intercepted by any observer on the network.",
    "200": "Information about technologies, versions or internal structure exposed to attackers.",
    "693": "Missing security headers leave the user's browser without basic protections against XSS and injection.",
    "1004":"Session cookies accessible via JavaScript can be stolen by malicious scripts (XSS).",
    "1395":"JavaScript library with a known vulnerability and publicly available exploit.",
    "312": "Sensitive data stored without encryption can be accessed directly in the database.",
    "384": "An attacker can fixate a user's session identifier and take over their account after login.",
}

# ── Mapa de remediação específica por CWE ────────────────────
REMEDIATION_MAP = {
    "89":  "Use prepared statements (parametrized queries) in all SQL queries. Never concatenate user data directly.",
    "79":  "Escape output in HTML/JS context. Implement Content-Security-Policy. Use libraries like DOMPurify.",
    "352": "Implement CSRF tokens (e.g. SameSite=Strict cookies, per-form token). Frameworks like Spring, Django and Rails have native support.",
    "22":  "Validate and normalize file paths. Use an allowlist of permitted directories. Avoid concatenating user input into paths.",
    "287": "Implement strong authentication with MFA. Use secure sessions with proper expiration.",
    "306": "Add authentication to all endpoints. Use centralized auth middleware.",
    "284": "Validate server-side that the user is allowed to access the requested resource. Do not rely solely on the URL ID.",
    "918": "Validate and filter destination URLs in any proxy/redirect functionality. Use an allowlist of permitted hosts.",
    "693": "Configure headers: Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Strict-Transport-Security.",
    "1004":"Add the HttpOnly flag to all session cookies. Also use Secure and SameSite=Strict.",
    "1395":"Update the library to the latest version. Check release notes for breaking changes.",
    "326": "Use TLS 1.2+ with modern cipher suites. Disable SSLv3, TLS 1.0, TLS 1.1 and RC4.",
    "319": "Enforce HTTPS across the application. Implement HSTS. Redirect HTTP to HTTPS.",
    "312": "Encrypt sensitive data at rest. Use bcrypt/Argon2 for passwords. Never store in cleartext.",
}

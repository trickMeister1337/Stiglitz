#!/usr/bin/env python3
"""
pii_detect.py — Detecção de PII em conteúdo textual (bundles JS, respostas HTTP).

Cobre a lacuna em que o Stiglitz baixava o bundle e só procurava
secrets/endpoints/frameworks: e-mail corporativo, CPF/CNPJ e telefone BR
passavam batido (não são "secrets" e o trufflehog ignora PII por design).

Funções puras (sem rede / sem sys.argv) — testáveis em isolamento.
Consumido por lib/js_analysis.py, que escreve raw/pii_findings.json no shape
de finding-dict ingerido pelo loader do stiglitz_report.py.
"""
import re

# TLDs de segundo nível comuns no Brasil — para reduzir o host ao domínio
# registrável (eTLD+1) e classificar e-mail corporativo corretamente.
_TWO_PART_TLDS = {
    "com.br", "net.br", "org.br", "gov.br", "edu.br", "br.com",
    "co.uk", "com.au", "co.in",
}

# Domínios de vendor/OSS/exemplo que aparecem em bundles minificados e NÃO são
# PII do alvo (e-mails de autores de bibliotecas, placeholders). Nunca entram no
# bucket corporativo; mantidos fora do ruído.
_NOISE_EMAIL_DOMAINS = {
    "example.com", "example.org", "email.com", "domain.com", "test.com",
    "sentry.io", "w3.org", "schema.org", "googleapis.com", "gstatic.com",
}

_EMAIL_RE = re.compile(r'[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}')
# CPF: formatado (XXX.XXX.XXX-XX) ou 11 dígitos crus delimitados.
_CPF_RE = re.compile(r'(?<!\d)(\d{3}\.\d{3}\.\d{3}-\d{2}|\d{11})(?!\d)')
# CNPJ: formatado (XX.XXX.XXX/XXXX-XX) ou 14 dígitos crus delimitados.
_CNPJ_RE = re.compile(r'(?<!\d)(\d{2}\.\d{3}\.\d{3}/\d{4}-\d{2}|\d{14})(?!\d)')
# Telefone BR: exige formatação (parênteses no DDD, +55 ou separador) — dígitos
# crus de 10/11 posições NÃO contam, para não confundir com IDs/CPF/timestamps.
_PHONE_RE = re.compile(
    r'(?:\+55[\s\-]?)?'
    r'(?:\(\d{2}\)[\s\-]?\d{4,5}[\s\-]?\d{4}'      # (11) 99876-5432
    r'|\+55[\s\-]?\d{2}[\s\-]?\d{4,5}[\s\-]?\d{4}'  # +55 11 99876-5432
    r'|\b\d{2}[\s]\d{4,5}[\s\-]\d{4}\b)'            # 11 99876-5432
)


def registrable_domain(host):
    """Reduz um host ao domínio registrável (eTLD+1 aproximado).

    'app.hml.acme-corp.com' -> 'acme-corp.com'
    'app.minhaempresa.com.br'   -> 'minhaempresa.com.br'
    """
    host = (host or "").strip().lower().strip(".")
    if "@" in host:
        host = host.split("@", 1)[1]
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    last_two = ".".join(labels[-2:])
    if last_two in _TWO_PART_TLDS and len(labels) >= 3:
        return ".".join(labels[-3:])
    return last_two


def mask_email(email):
    """Mascara o local-part preservando o domínio (evita derramar PII no relatório).
    'joao.silva@acme-corp.com' -> 'joa***@acme-corp.com'
    """
    if "@" not in email:
        return email
    local, _, domain = email.partition("@")
    keep = local[:3] if len(local) > 3 else local[:1]
    return f"{keep}***@{domain}"


def _digits(s):
    return re.sub(r"\D", "", s or "")


def valid_cpf(cpf):
    """Valida os dois dígitos verificadores do CPF."""
    n = _digits(cpf)
    if len(n) != 11 or n == n[0] * 11:
        return False
    for length in (9, 10):
        total = sum(int(n[i]) * ((length + 1) - i) for i in range(length))
        rem = total % 11
        check = 0 if rem < 2 else 11 - rem
        if check != int(n[length]):
            return False
    return True


def valid_cnpj(cnpj):
    """Valida os dois dígitos verificadores do CNPJ."""
    n = _digits(cnpj)
    if len(n) != 14 or n == n[0] * 14:
        return False
    for length, weights in (
        (12, [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]),
        (13, [6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]),
    ):
        total = sum(int(n[i]) * weights[i] for i in range(length))
        rem = total % 11
        check = 0 if rem < 2 else 11 - rem
        if check != int(n[length]):
            return False
    return True


def _format_cpf(n):
    return f"{n[0:3]}.{n[3:6]}.{n[6:9]}-{n[9:11]}"


def _format_cnpj(n):
    return f"{n[0:2]}.{n[2:5]}.{n[5:8]}/{n[8:12]}-{n[12:14]}"


def extract_pii(content, corporate_domains):
    """Extrai PII de um texto.

    Retorna dict com listas únicas e ordenadas:
      emails_corporate / emails_external / cpf / cnpj / phones
    `corporate_domains` é normalizado para domínio(s) registrável(is).
    """
    corp = {registrable_domain(d) for d in (corporate_domains or []) if d}

    emails_corp, emails_ext = set(), set()
    for m in _EMAIL_RE.finditer(content or ""):
        email = m.group(0).lower().rstrip(".")
        dom = email.split("@", 1)[1]
        if dom in _NOISE_EMAIL_DOMAINS:
            emails_ext.add(email)
            continue
        reg = registrable_domain(dom)
        if reg in corp:
            emails_corp.add(email)
        else:
            emails_ext.add(email)

    cpf = set()
    for m in _CPF_RE.finditer(content or ""):
        n = _digits(m.group(1))
        if valid_cpf(n):
            cpf.add(_format_cpf(n))

    cnpj = set()
    for m in _CNPJ_RE.finditer(content or ""):
        n = _digits(m.group(1))
        if valid_cnpj(n):
            cnpj.add(_format_cnpj(n))

    phones = {m.group(0).strip() for m in _PHONE_RE.finditer(content or "")}

    return {
        "emails_corporate": sorted(emails_corp),
        "emails_external": sorted(emails_ext),
        "cpf": sorted(cpf),
        "cnpj": sorted(cnpj),
        "phones": sorted(phones),
    }


def _sample(items, n=8):
    return ", ".join(items[:n]) + (f" … (+{len(items) - n})" if len(items) > n else "")


def build_pii_findings(pii, target, source_url=""):
    """Constrói finding-dicts (shape ingerido por stiglitz_report.py) a partir do
    resultado de extract_pii. Só gera achado para PII real do alvo; e-mails
    externos (vendor/OSS) são contados mas nunca viram finding.
    """
    findings = []
    loc = source_url or target

    emails = pii.get("emails_corporate", [])
    if emails:
        masked = [mask_email(e) for e in emails]
        findings.append({
            "id": "PII-EMAIL", "tool": "pii_detect", "type": "pii", "source": "pii",
            "vuln_class": "pii_email_exposure", "cwe": "CWE-359", "data_class": "pii",
            "name": "Employee PII — corporate e-mail addresses hardcoded in client-side asset",
            "url": loc, "severity": "medium",
            "description": (
                f"{len(emails)} corporate e-mail address(es) hardcoded in a public "
                f"client-side asset: {_sample(masked)}. Enables employee enumeration, "
                "targeted phishing and social engineering."),
            "remediation": (
                "Remove hardcoded recipient/assignee lists from the front-end bundle; "
                "resolve people server-side via authenticated API and never ship PII to "
                "the client."),
        })

    cpf = pii.get("cpf", [])
    if cpf:
        findings.append({
            "id": "PII-CPF", "tool": "pii_detect", "type": "pii", "source": "pii",
            "vuln_class": "pii_cpf_exposure", "cwe": "CWE-359", "data_class": "pii",
            "name": "PII — valid CPF numbers exposed in client-side asset",
            "url": loc, "severity": "high",
            "description": (
                f"{len(cpf)} checksum-valid CPF number(s) exposed in a public client-side "
                f"asset (LGPD personal data): {_sample(cpf)}."),
            "remediation": (
                "Never embed CPF in front-end code/data. Keep personal data server-side "
                "behind authentication; mask/tokenize when display is required."),
        })

    cnpj = pii.get("cnpj", [])
    if cnpj:
        findings.append({
            "id": "PII-CNPJ", "tool": "pii_detect", "type": "pii", "source": "pii",
            "vuln_class": "pii_cnpj_exposure", "cwe": "CWE-200", "data_class": "pii",
            "name": "PII — valid CNPJ numbers exposed in client-side asset",
            "url": loc, "severity": "low",
            "description": (
                f"{len(cnpj)} checksum-valid CNPJ number(s) exposed in a public "
                f"client-side asset: {_sample(cnpj)}."),
            "remediation": "Avoid embedding company registration data in client-side bundles.",
        })

    phones = pii.get("phones", [])
    if phones:
        findings.append({
            "id": "PII-PHONE", "tool": "pii_detect", "type": "pii", "source": "pii",
            "vuln_class": "pii_phone_exposure", "cwe": "CWE-359", "data_class": "pii",
            "name": "PII — phone numbers exposed in client-side asset",
            "url": loc, "severity": "low",
            "description": (
                f"{len(phones)} phone number(s) exposed in a public client-side asset: "
                f"{_sample(phones)}."),
            "remediation": "Avoid embedding contact phone numbers in front-end bundles.",
        })

    return findings

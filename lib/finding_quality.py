#!/usr/bin/env python3
"""finding_quality.py — heurísticas puras de qualidade de findings de scanner.

Reduz ruído (falsos positivos previsíveis) e melhora a acionabilidade dos
alertas de ferramentas (sobretudo ZAP) antes de virarem itens do relatório.
Lógica pura, sem rede — testável isoladamente.
"""
import re
from urllib.parse import urlsplit

# Classes de "disclosure" que são ruído quando emitidas sobre um asset estático:
# números em JS/CSS minificado de terceiros disparam Timestamp Disclosure;
# comentários de build disparam Suspicious Comments. Não são vulnerabilidades.
_NOISE_DISCLOSURE = {
    "timestamp disclosure - unix",
    "timestamp disclosure",
    "information disclosure - suspicious comments",
}

_STATIC_EXT = (".js", ".css", ".map", ".woff", ".woff2", ".ttf", ".otf",
               ".eot", ".svg", ".png", ".jpg", ".jpeg", ".gif", ".ico")


def is_low_value_zap_alert(name, url):
    """True quando o alerta é um FP previsível: classe de disclosure ruidoso
    emitida sobre um arquivo estático (lib JS/CSS de terceiro etc.).

    Conservador por desenho: só dispara para a interseção (classe ruidosa E
    asset estático). Disclosure num endpoint dinâmico pode ser real → False.
    """
    n = (name or "").strip().lower()
    if n not in _NOISE_DISCLOSURE:
        return False
    try:
        path = (urlsplit(url).path or "").lower()
    except (ValueError, AttributeError):
        return False
    return path.endswith(_STATIC_EXT)


# Bibliotecas JS de front cujo nome de arquivo carrega a versão ou é
# reconhecível — usado para enriquecer o alerta genérico "Vulnerable JS Library"
# do ZAP, que muitas vezes não traz versão nem CVE.
_JS_LIB_PATTERNS = [
    (re.compile(r"swagger-ui", re.I), "Swagger UI"),
    (re.compile(r"jquery", re.I), "jQuery"),
    (re.compile(r"angular", re.I), "AngularJS"),
    (re.compile(r"bootstrap", re.I), "Bootstrap"),
    (re.compile(r"lodash", re.I), "Lodash"),
    (re.compile(r"moment", re.I), "Moment.js"),
    (re.compile(r"react", re.I), "React"),
    (re.compile(r"vue", re.I), "Vue.js"),
]

_VERSION_RE = re.compile(r"(\d+\.\d+\.\d+)")


def identify_js_library(url, evidence=""):
    """Identifica (lib, versão) a partir da URL e da evidência do alerta.

    Retorna (lib_name|None, version|None). A versão é buscada na evidência
    (onde o retire.js/ZAP costuma colocá-la) e, como fallback, no nome do
    arquivo. Não faz rede.
    """
    text = f"{url} {evidence or ''}"
    lib = None
    for rx, name in _JS_LIB_PATTERNS:
        if rx.search(text):
            lib = name
            break
    ver = None
    m = _VERSION_RE.search(evidence or "")
    if not m:
        # tenta no nome do arquivo (ex.: swagger-ui-3.1.6.min.js)
        m = _VERSION_RE.search(urlsplit(url).path if url else "")
    if m:
        ver = m.group(1)
    return lib, ver


def enrich_vulnerable_js(name, url, evidence=""):
    """Para o alerta genérico 'Vulnerable JS Library', devolve um nome de finding
    mais acionável incluindo a biblioteca/versão identificada, ou None se nada a
    acrescentar. Não inventa CVE — só nomeia o componente concreto.
    """
    if "vulnerable js" not in (name or "").lower():
        return None
    lib, ver = identify_js_library(url, evidence)
    if not lib:
        return None
    if ver:
        return f"Vulnerable JS Library: {lib} {ver}"
    return f"Vulnerable JS Library: {lib}"


def coverage_gap_finding(openapi_count, has_token):
    """Meta-finding (info) sinalizando que a superfície AUTENTICADA da API não foi
    testada por falta de token. Retorna dict de finding ou None.

    Evita que o relatório transmita falsa sensação de segurança: um '0 High/0
    Critical' contra uma API cuja superfície de valor exige Bearer reflete apenas
    a cobertura não-autenticada, não o risco de access-control/lógica de negócio.
    """
    try:
        n = int(openapi_count)
    except (TypeError, ValueError):
        return None
    if n <= 0 or has_token:
        return None
    return {
        "source": "Coverage",
        "name": f"Authenticated API surface not tested ({n} endpoints, no token)",
        "severity": "info",
        "description": (
            f"{n} documented API endpoint(s) require authentication, but no token "
            "was supplied to the scan. Authorization-layer risks (BOLA/IDOR, "
            "business-logic abuse) on these endpoints were NOT exercised. A "
            "'0 High / 0 Critical' result here reflects unauthenticated coverage "
            "only, not the authenticated attack surface."),
        "remediation": (
            "Re-run with --token-a/--token-b (two test accounts) to enable the "
            "access-control (P9.5) and business-logic (P9.7) phases."),
        "url": "",
        "cve_ids": [],
    }


def swagger_exposure_severity(in_cde):
    """Severidade da exposição pública de spec OpenAPI/Swagger.

    Fora do CDE é informativo (apenas a presença do Swagger UI). Em escopo CDE/PCI
    o spec revela a arquitetura da API de pagamentos (endpoints, integrações,
    parâmetros) — information disclosure sensível → medium.
    """
    return "medium" if in_cde else "info"

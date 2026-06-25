"""ASV-Preflight: prevê o resultado de um scan ASV PCI sobre findings já coletados.

Camada pura e paralela ao scoring KEV>EPSS>CVSS. Aplica o critério do ASV Program
Guide: CVSS base >= 4.0 = FAIL, além de gatilhos de falha automática (SQLi/XSS/TLS
fraco/default creds/etc.) independentes de score. Sem rede própria.
"""
import os
import sys
from urllib.parse import urlparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from lib import finding_quality as _fq
    from lib import scope as _scope
    from lib import compliance_map as _cmap
except Exception:  # execução direta a partir de lib/
    import finding_quality as _fq
    import scope as _scope
    import compliance_map as _cmap

ASV_THRESHOLD = 4.0  # CVSS base >= 4.0 reprova (ASV Program Guide)

# Categorias que reprovam independentemente do CVSS (gatilhos de falha automática).
AUTO_FAIL = {"sqli", "xss", "rce", "lfi", "ssti", "xxe",
             "default_creds", "sensitive_data", "tls_insecure", "open_db"}
# Categorias que nunca contam para o veredito (informativas no contexto ASV).
INFORMATIONAL = {"security_header", "low_value"}

# Padrões (substring, lowercase) em finding["name"] -> categoria de auto-fail.
_NAME_PATTERNS = [
    ("sqli", ("sql injection", "sqli")),
    ("xss", ("cross-site scripting", "xss")),
    ("rce", ("remote code execution", "command injection", " rce")),
    ("lfi", ("local file inclusion", "path traversal", "directory traversal", "lfi")),
    ("ssti", ("server-side template", "ssti")),
    ("xxe", ("xml external entity", "xxe")),
    ("default_creds", ("default login", "default credential", "default password")),
    ("sensitive_data", ("pan ", "cardholder", "exposed pii", "private key", "sensitive data expos")),
    ("open_db", ("redis", "mongodb", "mongo on", "elasticsearch", "memcached", "couchdb")),
]


def classify_category(finding):
    """Classifica o finding numa categoria ASV a partir de name/source/url.
    Não depende de CWE (campo nem sempre presente)."""
    name = (finding.get("name") or "").lower()
    source = (finding.get("source") or "").lower()
    url = finding.get("url") or ""

    # Headers de segurança: informativos para ASV.
    if "security headers" in source or "missing" in name and "header" in name:
        return "security_header"

    # FP previsível (disclosure ruidoso em asset estático).
    if _fq.is_low_value_zap_alert(finding.get("name") or "", url):
        return "low_value"

    # TLS: findings do testssl com severidade relevante = TLS inseguro.
    if "testssl" in source and (finding.get("severity") or "").lower() in ("medium", "high", "critical"):
        return "tls_insecure"

    # Serviços de banco expostos (open_db) só quando vêm de detecção de serviço.
    if "service" in source:
        for cat, pats in _NAME_PATTERNS:
            if cat == "open_db" and any(p in name for p in pats):
                return "open_db"

    # Demais padrões de auto-fail por nome.
    for cat, pats in _NAME_PATTERNS:
        if cat == "open_db":
            continue
        if any(p in name for p in pats):
            return cat

    return "other"


def _cvss_base(finding):
    """CVSS base do finding (fallback para `cvss`); 0.0 se ausente/inválido."""
    for key in ("cvss_base", "cvss"):
        val = finding.get(key)
        try:
            if val is not None and float(val) > 0:
                return float(val)
        except (TypeError, ValueError):
            continue
    return 0.0


def asv_verdict_for(finding):
    """Veredito ASV de um finding: (verdict, reason).
    verdict ∈ {'FAIL','PASS','NOT_COUNTED'}. Fail-safe: na dúvida, não fabrica FAIL."""
    cat = classify_category(finding)

    if cat in AUTO_FAIL:
        return "FAIL", "ASV automatic-failure category: %s" % cat
    if cat in INFORMATIONAL:
        return "NOT_COUNTED", "informational under ASV criteria (%s)" % cat

    base = _cvss_base(finding)
    if base >= ASV_THRESHOLD:
        return "FAIL", "CVSS base %.1f >= %.1f" % (base, ASV_THRESHOLD)
    if base > 0:
        return "PASS", "CVSS base %.1f < %.1f" % (base, ASV_THRESHOLD)

    # Sem CVSS: fallback pela banda de severidade já calculada.
    sev = (finding.get("severity") or "info").lower()
    if sev in ("medium", "high", "critical"):
        return "FAIL", "severity %s (no CVSS, band >= 4.0)" % sev
    return "PASS", "severity %s below ASV threshold" % sev


# Requisito PCI default por categoria, quando o finding não traz CWE.
_CATEGORY_REQ = {
    "sqli": "6.2.4", "xss": "6.2.4", "rce": "6.2.4", "lfi": "6.2.4",
    "ssti": "6.2.4", "xxe": "6.2.4",
    "tls_insecure": "4.2.1",
    "default_creds": "8.3.1",
    "open_db": "2.2.5",
    "sensitive_data": "3.5.1",
}


def requirement_for(finding):
    """Requisito PCI do finding: via CWE (compliance_map) ou fallback por categoria."""
    cwe = finding.get("cwe")
    if cwe:
        pci = _cmap.frameworks_for_cwe(cwe).get("pci")
        if pci:
            return pci
    return _CATEGORY_REQ.get(classify_category(finding), "")


def _host_port(url):
    """(host, port) a partir da URL do finding; port inferida do esquema."""
    try:
        sp = urlparse(url if "://" in (url or "") else "//" + (url or ""))
        host = (sp.hostname or "").lower()
        port = sp.port or (443 if (sp.scheme == "https") else 80 if sp.scheme == "http" else "")
        return host, port
    except Exception:
        return "", ""


def aggregate(findings, scope_domains=None):
    """Veredito ASV agregado. would_pass=False sse houver >=1 FAIL em escopo."""
    scope_domains = scope_domains or []
    fails = []
    counted = 0
    for f in findings or []:
        url = f.get("url") or ""
        if scope_domains and url and not _scope.in_scope(url, scope_domains):
            continue
        verdict, reason = asv_verdict_for(f)
        if verdict == "NOT_COUNTED":
            continue
        counted += 1
        if verdict == "FAIL":
            host, port = _host_port(url)
            fails.append({
                "name": f.get("name", ""),
                "host": host,
                "port": port,
                "cvss_base": _cvss_base(f),
                "reason": reason,
                "requirement": requirement_for(f),
                "remediation": f.get("remediation", ""),
                "severity": (f.get("severity") or "info").lower(),
            })
    return {"would_pass": len(fails) == 0, "counted": counted, "fails": fails}

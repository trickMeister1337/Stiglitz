"""ASV-Preflight: prevê o resultado de um scan ASV PCI sobre findings já coletados.

Camada pura e paralela ao scoring KEV>EPSS>CVSS. Aplica o critério do ASV Program
Guide: CVSS base >= 4.0 = FAIL, além de gatilhos de falha automática (SQLi/XSS/TLS
fraco/default creds/etc.) independentes de score. Sem rede própria.
"""
import html as _html
import json as _json
import os
import re as _re
import sys
from urllib.parse import urlparse

try:
    from defusedxml import ElementTree as _ET
except Exception:  # defusedxml ausente: inventário degrada (sem nmap)
    _ET = None

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
        # No URL => cannot confirm scope; conservatively include the finding
        # (an ASV preflight prefers over-flagging to a false PASS).
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


def _inventory_from_nmap(xml_path):
    rows = []
    if _ET is None or not os.path.exists(xml_path):
        return rows
    try:
        tree = _ET.parse(xml_path)
    except Exception:
        return rows
    root = tree.getroot()
    for host_el in root.findall("host"):
        ip = ""
        for addr in host_el.findall("address"):
            if addr.get("addrtype") in ("ipv4", "ipv6"):
                ip = addr.get("addr", "")
                break
        hostname = ""
        hn = host_el.find("hostnames/hostname")
        if hn is not None:
            hostname = hn.get("name", "")
        host = hostname or ip
        ports_el = host_el.find("ports")
        if ports_el is None:
            continue
        for port_el in ports_el.findall("port"):
            state = port_el.find("state")
            if state is None or state.get("state") != "open":
                continue
            try:
                portid = int(port_el.get("portid"))
            except (TypeError, ValueError):
                continue
            svc = port_el.find("service")
            name = svc.get("name", "") if svc is not None else ""
            product = svc.get("product", "") if svc is not None else ""
            version = svc.get("version", "") if svc is not None else ""
            tunnel = svc.get("tunnel", "") if svc is not None else ""
            ver_str = (product + " " + version).strip()
            tls = (tunnel == "ssl") or name in ("https", "ssl") or portid == 443
            rows.append({"host": host, "ip": ip, "port": portid,
                         "service": name, "version": ver_str, "tls": tls})
    return rows


def _inventory_from_httpx(txt_path):
    rows = []
    if not os.path.exists(txt_path):
        return rows
    try:
        with open(txt_path, encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except Exception:
        return rows
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        url = line.split()[0]
        host, port = _host_port(url)
        if not host:
            continue
        techs = _re.findall(r"\[([^\]]+)\]", line)
        # primeiro token entre colchetes costuma ser status code numérico; ignora
        tech_tokens = [t for t in techs if not t.isdigit()]
        rows.append({"host": host, "ip": "", "port": port,
                     "service": "https" if url.startswith("https") else "http",
                     "version": ", ".join(tech_tokens), "tls": url.startswith("https")})
    return rows


def build_inventory(raw_dir):
    """Inventário agregado host/ip/port/service/version/tls (nmap + httpx), dedup
    por (host, port). nmap (estruturado) tem precedência sobre httpx."""
    nmap_rows = _inventory_from_nmap(os.path.join(raw_dir, "nmap.xml"))
    httpx_rows = _inventory_from_httpx(os.path.join(raw_dir, "httpx_results.txt"))
    keyed = {}
    for r in nmap_rows + httpx_rows:          # nmap primeiro = precedência
        key = (r["host"], r["port"])
        if key not in keyed:
            keyed[key] = r
    return list(keyed.values())


_DISCLAIMER = ("This ASV Preflight is a prediction to remediate before the official "
               "scan; it does not replace an ASV-certified scan (PCI DSS Req. 11.3.2) "
               "and is not an Attestation of Scan Compliance. Criterion: CVSS v3.1 base "
               ">= 4.0 plus automatic-failure categories.")


def render_section_html(verdict, inventory):
    """Seção HTML 'ASV Preflight Verdict' (EN, deliverable)."""
    would_pass = verdict.get("would_pass", True)
    banner = "WOULD PASS" if would_pass else "WOULD NOT PASS"
    color = "#4a7c8c" if would_pass else "#b34e4e"
    out = ["<h2>ASV Preflight Verdict</h2>"]
    out.append("<p><strong>Predicted result:</strong> "
               "<span style='color:%s;font-weight:bold'>%s</span> "
               "(%d finding(s) assessed against ASV criteria)</p>"
               % (color, banner, verdict.get("counted", 0)))

    fails = verdict.get("fails", [])
    if fails:
        out.append("<table><tr><th>Finding</th><th>Host:Port</th><th>CVSS</th>"
                   "<th>Reason</th><th>PCI Req</th><th>Remediation</th></tr>")
        for f in fails:
            out.append("<tr><td>%s</td><td><code>%s:%s</code></td><td>%s</td>"
                       "<td style='font-size:12px'>%s</td><td>%s</td>"
                       "<td style='font-size:11px'>%s</td></tr>" % (
                           _html.escape(str(f.get("name", ""))),
                           _html.escape(str(f.get("host", ""))),
                           _html.escape(str(f.get("port", ""))),
                           _html.escape("%.1f" % f.get("cvss_base", 0.0)),
                           _html.escape(str(f.get("reason", ""))),
                           _html.escape(str(f.get("requirement", ""))),
                           _html.escape(str(f.get("remediation", "")))))
        out.append("</table>")

    if inventory:
        out.append("<h3>Scanned components</h3>")
        out.append("<table><tr><th>Host</th><th>IP</th><th>Port</th>"
                   "<th>Service</th><th>Version</th><th>TLS</th></tr>")
        for r in inventory:
            out.append("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td>"
                       "<td>%s</td><td>%s</td></tr>" % (
                           _html.escape(str(r.get("host", ""))),
                           _html.escape(str(r.get("ip", ""))),
                           _html.escape(str(r.get("port", ""))),
                           _html.escape(str(r.get("service", ""))),
                           _html.escape(str(r.get("version", ""))),
                           "yes" if r.get("tls") else "no"))
        out.append("</table>")

    out.append("<p style='font-size:11px;color:#888'>%s</p>" % _html.escape(_DISCLAIMER))
    return "".join(out)


def _load_findings(path):
    """Carrega findings de um findings.json."""
    with open(path, encoding="utf-8") as fh:
        data = _json.load(fh)
    if isinstance(data, dict):
        return data.get("summary", {}).get("findings", []) or data.get("findings", [])
    return data or []


def main(argv):
    """CLI: verdict <findings.json> [raw_dir] | inventory <raw_dir>."""
    if len(argv) < 2:
        sys.stderr.write("usage: asv_preflight.py {verdict <findings.json> [raw_dir]"
                         " | inventory <raw_dir>}\n")
        return 2
    cmd = argv[0]
    if cmd == "verdict":
        findings = _load_findings(argv[1])
        raw_dir = argv[2] if len(argv) > 2 else ""
        inv = build_inventory(raw_dir) if raw_dir else []
        print(_json.dumps({"verdict": aggregate(findings), "inventory": inv},
                          ensure_ascii=False, indent=2))
        return 0
    if cmd == "inventory":
        print(_json.dumps(build_inventory(argv[1]), ensure_ascii=False, indent=2))
        return 0
    sys.stderr.write("unknown command: %s\n" % cmd)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

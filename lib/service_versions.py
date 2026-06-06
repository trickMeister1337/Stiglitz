#!/usr/bin/env python3
"""
service_versions.py — versões de serviços de rede + CVEs (nmap -sV --script vulners)

Lê o XML do nmap (raw/nmap.xml) gerado com `-sV --script vulners`, extrai cada
serviço aberto (porta, produto, versão) e os CVEs que o script vulners associou
ao banner — sinalizando software desatualizado/vulnerável (ex.: OpenSSH 7.4 →
CVE-...). Gera raw/service_findings.json no MESMO formato dos demais
*_findings.json, para ser agregado pelo stiglitz_report.py e enriquecido
(NVD/EPSS/KEV) pelo cve_enrich.py.

Uso: python3 service_versions.py <outdir> <target>
"""
import sys, os, json

# defusedxml protege contra XXE / billion-laughs — o nmap.xml carrega banners
# originados do alvo, então tratamos o parsing como entrada não-confiável.
try:
    import defusedxml.ElementTree as ET
    _XML_PARSE_ERR = ET.ParseError
except ImportError:
    import xml.etree.ElementTree as ET
    from xml.etree.ElementTree import ParseError as _XML_PARSE_ERR

outdir = sys.argv[1] if len(sys.argv) > 1 else ""
target = sys.argv[2].rstrip("/") if len(sys.argv) > 2 else ""

xml_path = os.path.join(outdir, "raw", "nmap.xml")
out_path = os.path.join(outdir, "raw", "service_findings.json")


def cvss_to_sev(score):
    """Mapeia CVSS (0-10) para severidade do relatório."""
    try:
        s = float(score)
    except (TypeError, ValueError):
        return "info"
    if s >= 9.0:
        return "critical"
    if s >= 7.0:
        return "high"
    if s >= 4.0:
        return "medium"
    if s > 0:
        return "low"
    return "info"


# Serviços sensíveis (datastores/admin) que NÃO deveriam estar expostos à
# internet — frequentemente sem autenticação por padrão. nmap só os destacava
# no console; aqui viram finding estruturado de alta severidade.
DANGEROUS_PORTS = {
    6379: "Redis", 27017: "MongoDB", 27018: "MongoDB", 28017: "MongoDB HTTP",
    9200: "Elasticsearch", 9300: "Elasticsearch", 6443: "Kubernetes API",
    2379: "etcd", 2380: "etcd", 5984: "CouchDB", 11211: "Memcached",
    9000: "Portainer/SonarQube", 5601: "Kibana",
}
_DANGEROUS_NAMES = {
    "redis": "Redis", "mongodb": "MongoDB", "mongod": "MongoDB", "mongo": "MongoDB",
    "elasticsearch": "Elasticsearch", "etcd": "etcd", "couchdb": "CouchDB",
    "memcached": "Memcached", "kubernetes": "Kubernetes API", "kibana": "Kibana",
}


def dangerous_service(portid, sname=""):
    """Rótulo do serviço sensível se a porta/serviço for exposição perigosa, senão None."""
    try:
        p = int(portid)
    except (TypeError, ValueError):
        p = None
    if p in DANGEROUS_PORTS:
        return DANGEROUS_PORTS[p]
    name = (sname or "").lower()
    for key, label in _DANGEROUS_NAMES.items():
        if key in name:
            return label
    return None


def parse_vulners_script(script_el):
    """Extrai [(cve_id, cvss, is_exploit)] de um <script id="vulners">."""
    cves = []
    # O vulners aninha: <table key="cpe..."> → <table> (1 por vuln) → <elem key=...>
    for cpe_table in script_el.findall("table"):
        for vuln_table in cpe_table.findall("table"):
            entry = {}
            for elem in vuln_table.findall("elem"):
                entry[elem.get("key")] = (elem.text or "").strip()
            cve_id = entry.get("id", "")
            if entry.get("type", "cve").lower() != "cve":
                continue
            if not cve_id.upper().startswith("CVE-"):
                continue
            cves.append({
                "id": cve_id.upper(),
                "cvss": entry.get("cvss", ""),
                "is_exploit": entry.get("is_exploit", "false").lower() == "true",
            })
    return cves


def main():
    if not os.path.exists(xml_path) or os.path.getsize(xml_path) == 0:
        # nmap pode não ter gerado XML (timeout/sem internet/sem portas) — silencioso.
        return

    try:
        root = ET.parse(xml_path).getroot()
    except _XML_PARSE_ERR as e:
        print(f"  [!] service_versions: XML do nmap inválido ({e})")
        return

    host_label = target.replace("https://", "").replace("http://", "").split("/")[0] or "target"
    findings = []
    idx = 0
    svc_with_cve = 0

    for host in root.findall("host"):
        ports_el = host.find("ports")
        if ports_el is None:
            continue
        for port in ports_el.findall("port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            portid = port.get("portid", "?")
            proto = port.get("protocol", "tcp")
            svc = port.find("service")
            sname = svc.get("name", "unknown") if svc is not None else "unknown"
            product = svc.get("product", "") if svc is not None else ""
            version = svc.get("version", "") if svc is not None else ""
            banner = " ".join(p for p in (product, version) if p).strip() or sname

            # CVEs do script vulners (se rodou nessa porta)
            cves = []
            for script in port.findall("script"):
                if script.get("id") == "vulners":
                    cves = parse_vulners_script(script)
                    break

            idx += 1
            loc = f"{host_label}:{portid}/{proto}"

            # Exposição de serviço sensível (datastore/admin) — risco distinto da
            # versão desatualizada; emitido independentemente de haver CVE.
            _danger = dangerous_service(portid, sname)
            if _danger:
                findings.append({
                    "id": f"SVC-EXP-{idx:03d}",
                    "tool": "nmap",
                    "type": "exposed_service",
                    "source": "Exposed Service",
                    "name": f"Sensitive service exposed: {_danger} on {portid}/{proto}",
                    "url": loc,
                    "severity": "high",
                    "description": (
                        f"{_danger} ({banner}) is reachable on {portid}/{proto}. "
                        f"Datastores and admin interfaces exposed to untrusted networks "
                        f"are frequently unauthenticated and can lead to full data "
                        f"compromise or remote code execution."
                    ),
                    "remediation": (
                        f"Bind {_danger} to localhost or a private subnet, enforce "
                        f"authentication, and restrict {portid}/{proto} via firewall/VPN."
                    ),
                    "cve": "N/A",
                })

            if cves:
                svc_with_cve += 1
                # Ordena por CVSS desc; severidade do card = maior CVSS
                cves.sort(key=lambda c: float(c["cvss"]) if c["cvss"] else 0, reverse=True)
                top_cvss = cves[0]["cvss"]
                sev = cvss_to_sev(top_cvss)
                cve_str = ", ".join(c["id"] for c in cves[:25])
                n_exploit = sum(1 for c in cves if c["is_exploit"])
                exploit_note = (f" {n_exploit} possuem exploit público conhecido."
                                if n_exploit else "")
                findings.append({
                    "id": f"SVC-{idx:03d}",
                    "tool": "nmap+vulners",
                    "type": "service_version",
                    "source": "Service Version",
                    "name": f"Outdated/Vulnerable {banner} on {portid}/{proto}",
                    "url": loc,
                    "severity": sev,
                    "description": (
                        f"O serviço {sname} ({banner}) exposto em {portid}/{proto} "
                        f"possui {len(cves)} CVE(s) conhecido(s) associado(s) à versão "
                        f"detectada — indício de software desatualizado.{exploit_note}"
                    ),
                    "remediation": (
                        f"Atualize {product or sname} para a versão estável mais recente. "
                        f"Restrinja o acesso à porta {portid}/{proto} (firewall/VPN) se a "
                        f"exposição pública não for necessária."
                    ),
                    "cve": cve_str,
                })
            elif version:
                # Versão detectada sem CVE conhecido — informativo (rastreabilidade).
                findings.append({
                    "id": f"SVC-{idx:03d}",
                    "tool": "nmap",
                    "type": "service_version",
                    "source": "Service Version",
                    "name": f"Service {banner} exposed on {portid}/{proto}",
                    "url": loc,
                    "severity": "info",
                    "description": (
                        f"Serviço {sname} ({banner}) detectado em {portid}/{proto}. "
                        f"Sem CVEs conhecidos para a versão via vulners — confirme "
                        f"manualmente se é a release mais recente."
                    ),
                    "remediation": (
                        f"Mantenha {product or sname} atualizado e restrinja a exposição "
                        f"da porta {portid}/{proto} ao necessário."
                    ),
                    "cve": "N/A",
                })

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(findings, f, indent=2, ensure_ascii=False)

    if findings:
        print(f"  [✓] Versões de serviço: {len(findings)} serviço(s), "
              f"{svc_with_cve} com CVE(s) conhecido(s) → service_findings.json")
    else:
        print("  [○] Versões de serviço: nenhum serviço com versão detectada")


if __name__ == "__main__":
    main()

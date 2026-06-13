#!/usr/bin/env python3
"""
Stiglitz RED — Parsers para resultados do Stiglitz scan.

Módulo independente que pode ser testado isoladamente.
Uso: python3 parsers.py <command> <args...>

Commands:
    parse_nuclei  <nuclei_jsonl> <outdir>     Parse nuclei e extrai CVEs + URLs
    parse_zap     <zap_json> <outdir>          Parse ZAP alerts
    extract_urls  <outdir> <target>            Consolida URLs de todas as fontes
"""
import sys
import os
import json
import re
import http.client
import urllib.request
import urllib.error
import netproxy
from typing import Dict, List, Set, Tuple, Optional


def parse_nuclei(nuclei_file: str, outdir: str) -> Dict[str, int]:
    """Parse nuclei JSONL e extrai CVEs, URLs com parâmetros, e todas URLs."""
    cves: Set[str] = set()
    urls_params: Set[str] = set()
    all_urls: Set[str] = set()

    with open(nuclei_file) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue

            # CVEs
            classification = obj.get("info", {}).get("classification", {})
            cve_list = classification.get("cve") or classification.get("cve-id") or []
            if isinstance(cve_list, list):
                for c in cve_list:
                    if c:
                        cves.add(c)
            elif isinstance(cve_list, str) and cve_list:
                cves.add(cve_list)

            # URLs
            url = obj.get("matched-at") or obj.get("host") or ""
            if url:
                all_urls.add(url)
                if "?" in url and "=" in url:
                    urls_params.add(url)

            # curl-command pode ter URLs com params
            curl = obj.get("curl-command", "")
            for u in re.findall(r"https?://[^\s'\"]+", curl):
                all_urls.add(u)
                if "?" in u and "=" in u:
                    urls_params.add(u)

    _write_set(f"{outdir}/cves_found.txt", cves)
    _write_set(f"{outdir}/urls_with_params.txt", urls_params)
    _write_set(f"{outdir}/all_target_urls.txt", all_urls)

    return {"cves": len(cves), "urls_params": len(urls_params), "urls_total": len(all_urls)}


def parse_zap(zap_file: str, outdir: str) -> Dict[str, int]:
    """Parse ZAP JSON (múltiplos formatos) e extrai SQLi URLs e alertas High/Critical."""
    try:
        with open(zap_file) as f:
            raw = json.load(f)
    except (json.JSONDecodeError, FileNotFoundError):
        raw = []

    alerts = _normalize_zap_alerts(raw)

    sqli_urls: Set[str] = set()
    high_crit: List[str] = []

    for a in alerts:
        if not isinstance(a, dict):
            continue
        alert_name = a.get("alert", a.get("name", ""))
        url = a.get("url", a.get("uri", ""))
        risk = a.get("risk", a.get("riskdesc", ""))
        param = a.get("param", "")

        if isinstance(risk, str):
            risk = risk.split("(")[0].strip().split(" ")[0]

        if re.search(r"sql|injection", str(alert_name), re.IGNORECASE):
            if url:
                sqli_urls.add(url)

        if risk in ("High", "Critical"):
            high_crit.append(f"{risk}|{alert_name}|{url}")

    _write_set(f"{outdir}/zap_sqli_urls.txt", sqli_urls)
    with open(f"{outdir}/zap_high_crit.txt", "w") as f:
        f.write("\n".join(high_crit) + ("\n" if high_crit else ""))

    return {"sqli": len(sqli_urls), "high_crit": len(high_crit)}


def extract_all_urls(outdir: str, target: str) -> Dict[str, int]:
    """Consolida URLs injetáveis de todas as fontes."""
    urls_with_params: Set[str] = set()
    all_urls: Set[str] = set()

    from urllib.parse import urlparse as _urlparse

    def _strip_www(h: str) -> str:
        # Remove o PREFIXO "www." (não usar lstrip, que remove caracteres soltos)
        h = (h or "").lower()
        return h[4:] if h.startswith("www.") else h

    # Extrair domínio base do target — aceita URL completa ou domínio puro
    _t = target.lower().strip()
    _t_host = _urlparse(_t).hostname if "://" in _t else _t.split("/")[0].split(":")[0]
    target_domain = _strip_www(_t_host or _t)

    def add_url(url: str):
        if not url or not isinstance(url, str):
            return
        url = url.strip()
        if not url.startswith("http"):
            return
        # FILTRAR: só aceitar URLs do domínio alvo ou subdomínios
        try:
            host = _urlparse(url).hostname
            if host:
                host = _strip_www(host)
                if host != target_domain and not host.endswith(f".{target_domain}"):
                    return  # URL externa — ignorar
        except Exception:
            return
        all_urls.add(url)
        if "?" in url and "=" in url:
            urls_with_params.add(url)

    # Fonte 1: Nuclei
    for path in [f"{outdir}/input_nuclei.jsonl"]:
        if not os.path.exists(path):
            continue
        with open(path) as f:
            for line in f:
                try:
                    obj = json.loads(line.strip())
                    add_url(obj.get("matched-at", ""))
                    add_url(obj.get("host", ""))
                    for u in re.findall(r"https?://[^\s'\"]+", obj.get("curl-command", "")):
                        add_url(u)
                except (json.JSONDecodeError, ValueError, TypeError, AttributeError):
                    pass

    # Fonte 2: ZAP (todas as URLs)
    for path in [f"{outdir}/input_zap.json"]:
        if not os.path.exists(path):
            continue
        try:
            with open(path) as f:
                raw = json.load(f)
        except (json.JSONDecodeError, ValueError, OSError):
            continue
        alerts = _normalize_zap_alerts(raw)
        for a in alerts:
            if not isinstance(a, dict):
                continue
            url = a.get("url", a.get("uri", ""))
            add_url(url)
            param = a.get("param", "")
            # ZAP "param" pode ser header HTTP — filtrar para apenas parâmetros reais
            if param and url and "?" not in url:
                # Headers HTTP comuns que o ZAP reporta como "param" mas NÃO são query params
                http_headers = {
                    "x-content-type-options", "x-frame-options", "x-xss-protection",
                    "content-security-policy", "strict-transport-security",
                    "cache-control", "pragma", "expires", "set-cookie", "cookie",
                    "content-type", "server", "x-powered-by", "access-control-allow-origin",
                    "referrer-policy", "permissions-policy", "feature-policy",
                    "x-content-security-policy", "x-webkit-csp", "x-download-options",
                    "x-permitted-cross-domain-policies", "cross-origin-opener-policy",
                    "cross-origin-resource-policy", "cross-origin-embedder-policy",
                    "accept", "accept-encoding", "accept-language", "user-agent",
                    "host", "connection", "upgrade-insecure-requests",
                }
                if param.lower().strip() not in http_headers and not param.startswith("x-"):
                    urls_with_params.add(f"{url}?{param}=test")

    # Fonte 3: httpx
    for path in [f"{outdir}/input_httpx.jsonl", f"{outdir}/input_httpx.txt"]:
        if not os.path.exists(path):
            continue
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                if line.startswith("{"):
                    try:
                        obj = json.loads(line)
                        add_url(obj.get("url", ""))
                    except (json.JSONDecodeError, ValueError):
                        pass
                else:
                    parts = line.split()
                    if parts:
                        add_url(parts[0])

    # Fonte 4: ffuf
    ffuf_path = f"{outdir}/input_ffuf.json"
    if os.path.exists(ffuf_path):
        try:
            with open(ffuf_path) as f:
                data = json.load(f)
            results = data.get("results", data) if isinstance(data, dict) else data
            if isinstance(results, list):
                for r in results:
                    if isinstance(r, dict):
                        add_url(r.get("url", ""))
        except (json.JSONDecodeError, ValueError, OSError, AttributeError):
            pass

    # Fonte 4b: Katana URLs (crawler do Stiglitz — URLs reais com parâmetros)
    katana_path = f"{outdir}/input_katana_urls.txt"
    if os.path.exists(katana_path):
        try:
            with open(katana_path) as f:
                for line in f:
                    url = line.strip()
                    if url and url.startswith("http"):
                        add_url(url)
        except (OSError, UnicodeDecodeError):
            pass

    # Fonte 4c: JS Analysis (endpoints descobertos em arquivos JavaScript)
    js_path = f"{outdir}/input_js_analysis.json"
    if os.path.exists(js_path):
        try:
            with open(js_path) as f:
                js_data = json.load(f)
            for ep in js_data.get("endpoints", []):
                if isinstance(ep, dict):
                    url = ep.get("url", ep.get("endpoint", ""))
                    add_url(url)
                elif isinstance(ep, str):
                    if ep.startswith("http"):
                        add_url(ep)
                    elif ep.startswith("/"):
                        add_url(f"https://{target}{ep}")
            # Endpoint probes (já verificados pelo Stiglitz)
            for probe in js_data.get("endpoint_probes", []):
                if isinstance(probe, dict):
                    add_url(probe.get("url", ""))
        except (json.JSONDecodeError, ValueError, OSError, AttributeError, TypeError):
            pass

    # Fonte 4d: OpenAPI spec (rotas de API — alvos primários para SQLi)
    openapi_path = f"{outdir}/input_openapi_spec.json"
    if os.path.exists(openapi_path):
        try:
            with open(openapi_path) as f:
                spec = json.load(f)
            base_url = f"https://{target}"
            # Extrair servers se disponível
            servers = spec.get("servers", [])
            if servers and isinstance(servers[0], dict):
                base_url = servers[0].get("url", base_url).rstrip("/")
            # Extrair paths
            for path_str, methods in spec.get("paths", {}).items():
                full_url = f"{base_url}{path_str}"
                add_url(full_url)
                # Se tem parâmetros no path, gerar variantes
                if isinstance(methods, dict):
                    for method, details in methods.items():
                        if isinstance(details, dict):
                            for param in details.get("parameters", []):
                                if isinstance(param, dict) and param.get("in") == "query":
                                    pname = param.get("name", "")
                                    if pname:
                                        urls_with_params.add(f"{full_url}?{pname}=1")
        except (json.JSONDecodeError, ValueError, OSError, AttributeError, TypeError):
            pass

    # Fonte 4e: Exploit confirmations do Stiglitz (URLs já confirmadas vulneráveis)
    confirm_path = f"{outdir}/input_exploit_confirmations.json"
    if os.path.exists(confirm_path):
        try:
            with open(confirm_path) as f:
                confirmations = json.load(f)
            for c in confirmations:
                if isinstance(c, dict) and c.get("confirmed", False):
                    url = c.get("url", "")
                    if url:
                        add_url(url)
                        # Estas URLs são CONFIRMADAS — adicionar com prioridade
                        if "?" in url:
                            urls_with_params.add(url)
        except (json.JSONDecodeError, ValueError, OSError, AttributeError):
            pass

    # Fonte 5: robots.txt e sitemap.xml
    for rpath in ["/robots.txt", "/sitemap.xml"]:
        try:
            req_url = f"https://{target}{rpath}"
            req = urllib.request.Request(req_url, headers={"User-Agent": "Stiglitz-RED/1.0"})
            resp = netproxy.urlopen(req, timeout=10)
            if resp.status == 200:
                content = resp.read().decode("utf-8", errors="ignore")
                if "robots" in rpath:
                    for line in content.split("\n"):
                        m = re.match(r"(?:Dis)?[Aa]llow:\s*(\S+)", line)
                        if m:
                            p = m.group(1).strip()
                            if p and p != "/" and not p.startswith("#"):
                                add_url(f"https://{target}{p}")
                if "sitemap" in rpath:
                    for loc in re.findall(r"<loc>\s*(https?://[^<]+)\s*</loc>", content):
                        add_url(loc.strip())
        except (urllib.error.URLError, OSError, ValueError, UnicodeDecodeError,
                http.client.HTTPException):
            pass

    # Fonte 6: Variantes com parâmetros comuns (APENAS em URLs dinâmicas)
    # Parâmetros reais de aplicação — não headers HTTP, não arquivos estáticos
    common_params = ["id", "page", "q", "search", "user", "name",
                     "action", "type", "file", "cat", "dir", "cmd",
                     "category", "product", "item", "view", "ref",
                     "lang", "sort", "order", "limit", "offset"]

    # Extensões de arquivo que NUNCA processam parâmetros SQL
    STATIC_EXTENSIONS = {
        ".txt", ".xml", ".json", ".css", ".js", ".map",
        ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
        ".woff", ".woff2", ".ttf", ".eot", ".otf",
        ".pdf", ".doc", ".docx", ".xls", ".xlsx",
        ".zip", ".gz", ".tar", ".rar",
        ".mp3", ".mp4", ".avi", ".mov", ".webm",
        ".robots", ".sitemap",
    }

    # Paths que NUNCA são injetáveis
    STATIC_PATHS = {
        "/robots.txt", "/sitemap.xml", "/favicon.ico",
        "/crossdomain.xml", "/.well-known/", "/ads.txt",
        "/humans.txt", "/security.txt", "/manifest.json",
        "/sw.js", "/service-worker.js",
    }

    def _is_injectable_url(url):
        """Verifica se uma URL base pode conter endpoints dinâmicos."""
        from urllib.parse import urlparse
        parsed = urlparse(url)
        path = parsed.path.lower().rstrip("/")

        # Rejeitar arquivos estáticos por extensão
        for ext in STATIC_EXTENSIONS:
            if path.endswith(ext):
                return False

        # Rejeitar paths conhecidamente estáticos
        for sp in STATIC_PATHS:
            if path == sp or path.startswith(sp):
                return False

        # Rejeitar paths de assets/static
        static_dirs = ["/static/", "/assets/", "/css/", "/js/", "/img/",
                       "/images/", "/fonts/", "/media/", "/vendor/",
                       "/node_modules/", "/dist/", "/build/", "/public/"]
        for sd in static_dirs:
            if sd in path:
                return False

        return True

    # Filtrar URLs existentes — remover estáticas do urls_with_params
    urls_with_params = {u for u in urls_with_params if _is_injectable_url(u)}

    # Gerar variantes APENAS para URLs base dinâmicas
    base_urls = {u.rstrip("/") for u in all_urls if "?" not in u and _is_injectable_url(u)}
    if len(urls_with_params) < 5:
        for base in list(base_urls)[:15]:
            for param in common_params[:8]:
                urls_with_params.add(f"{base}?{param}=1")

    _write_set(f"{outdir}/urls_with_params.txt", urls_with_params)
    _write_set(f"{outdir}/all_target_urls.txt", all_urls)

    return {"params": len(urls_with_params), "total": len(all_urls), "bases": len(base_urls)}


# ═══════════════ HELPERS ═══════════════

def _normalize_zap_alerts(raw) -> list:
    """Normaliza ZAP JSON para lista de alert dicts."""
    alerts = []
    if isinstance(raw, list):
        alerts = raw
    elif isinstance(raw, dict):
        for key in ["alerts", "site"]:
            val = raw.get(key)
            if isinstance(val, list):
                for item in val:
                    if isinstance(item, dict):
                        if "alerts" in item:
                            al = item["alerts"]
                            alerts.extend(al if isinstance(al, list) else [al])
                        else:
                            alerts.append(item)
                break
            elif isinstance(val, dict):
                alerts.append(val)
        if not alerts:
            for v in raw.values():
                if isinstance(v, list) and len(v) > 0 and isinstance(v[0], dict):
                    alerts = v
                    break
    return alerts


def _write_set(path: str, data: set):
    """Escreve um set ordenado em um arquivo, um item por linha."""
    with open(path, "w") as f:
        f.write("\n".join(sorted(data)) + ("\n" if data else ""))


# ═══════════════ CLI ═══════════════

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    cmd = sys.argv[1]
    if cmd == "parse_nuclei" and len(sys.argv) >= 4:
        result = parse_nuclei(sys.argv[2], sys.argv[3])
        print(f"NUCLEI_OK|cves={result['cves']}|urls_params={result['urls_params']}|urls_total={result['urls_total']}")
    elif cmd == "parse_zap" and len(sys.argv) >= 4:
        result = parse_zap(sys.argv[2], sys.argv[3])
        print(f"ZAP_OK|sqli={result['sqli']}|high_crit={result['high_crit']}")
    elif cmd == "extract_urls" and len(sys.argv) >= 4:
        result = extract_all_urls(sys.argv[2], sys.argv[3])
        print(f"URLS_OK|params={result['params']}|total={result['total']}|bases={result['bases']}")
    else:
        print(f"Comando desconhecido: {cmd}")
        print(__doc__)
        sys.exit(1)

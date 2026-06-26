#!/usr/bin/env python3
"""
cors_check.py — Detecta CORS misconfiguration via OPTIONS preflight.

O template nuclei cors-misconfig usa GET, que não dispara CORS em servidores
ASP.NET Core, Express, etc. que só configuram CORS via preflight OPTIONS.
Este módulo testa OPTIONS contra TARGET + URLs descobertas pelo ffuf/katana.

Detecta:
  - Access-Control-Allow-Origin: *  (wildcard explícito)
  - Access-Control-Allow-Origin: <origem-arbitrária>  (eco da origem)
  - Access-Control-Allow-Credentials: true + wildcard/eco  (crítico)

Output: raw/cors_findings.json
Uso:    python3 cors_check.py <OUTDIR> <TARGET>
"""
import subprocess, json, sys, os, re
from urllib.parse import urlparse
import netproxy
import mtls

if len(sys.argv) < 3:
    print("Uso: cors_check.py <OUTDIR> <TARGET>")
    sys.exit(1)

OUTDIR = sys.argv[1]
TARGET = sys.argv[2].rstrip("/")
EVIL_ORIGIN = "https://evil-cors-test.attacker.com"

def collect_urls():
    """URLs de teste: TARGET + paths descobertos pelo ffuf/katana, deduplicadas."""
    urls = {TARGET}
    # paths comuns de API que costumam ter CORS configurado
    for path in ["/api", "/api/v1", "/api/v2", "/graphql", "/rest"]:
        urls.add(TARGET + path)

    # ffuf results
    ffuf_path = os.path.join(OUTDIR, "raw", "ffuf.json")
    if os.path.exists(ffuf_path):
        try:
            d = json.load(open(ffuf_path))
            for r in d.get("results", []):
                u = r.get("url", "").strip()
                if u.startswith("http"):
                    urls.add(u)
        except Exception: pass

    # katana (até 30, prioriza paths /api/)
    katana_path = os.path.join(OUTDIR, "raw", "katana_urls.txt")
    if os.path.exists(katana_path):
        try:
            with open(katana_path) as f:
                api_urls = []
                others = []
                for line in f:
                    u = line.strip()
                    if not u.startswith("http"): continue
                    if "/api" in u: api_urls.append(u)
                    else: others.append(u)
                for u in api_urls[:20] + others[:10]:
                    urls.add(u)
        except Exception: pass

    return sorted(urls)

def test_cors(url):
    """Faz OPTIONS preflight e retorna dict com headers CORS encontrados."""
    try:
        r = subprocess.run(
            ["curl", *netproxy.curl_proxy_args(), *mtls.curl_cert_args(), "-sk", "-X", "OPTIONS", "--max-time", "10", "-D", "-",
             "-o", "/dev/null",
             "-H", f"Origin: {EVIL_ORIGIN}",
             "-H", "Access-Control-Request-Method: POST",
             "-H", "Access-Control-Request-Headers: authorization,content-type",
             url],
            capture_output=True, text=True, timeout=15
        )
        headers = {}
        for line in r.stdout.split("\n"):
            if ":" in line:
                k, _, v = line.partition(":")
                k = k.strip().lower()
                if k.startswith("access-control"):
                    headers[k] = v.strip()
        return headers
    except Exception:
        return {}

def classify(url, h):
    """Retorna lista de findings (sev, name, desc, evidence)."""
    findings = []
    origin = h.get("access-control-allow-origin", "")
    creds  = h.get("access-control-allow-credentials", "").lower() == "true"

    if not origin:
        return findings

    is_wildcard = origin == "*"
    is_echo     = origin == EVIL_ORIGIN

    if is_wildcard and creds:
        findings.append((
            "high",
            "CORS: wildcard + credentials habilitados",
            f"O endpoint responde com Access-Control-Allow-Origin: * E "
            f"Access-Control-Allow-Credentials: true — combinação proibida pelo spec mas "
            f"ainda perigosa: navegadores rejeitam, mas clientes não-browser executam.",
            f"OPTIONS {url} → ACAO: *, ACAC: true"
        ))
    elif is_wildcard:
        findings.append((
            "medium",
            "CORS: wildcard Access-Control-Allow-Origin",
            f"O endpoint responde com Access-Control-Allow-Origin: * — qualquer origem "
            f"pode fazer requisições cross-origin (sem credentials). Em endpoints que "
            f"retornam dados sensíveis baseados em IP, isso pode permitir vazamento.",
            f"OPTIONS {url} → Access-Control-Allow-Origin: *"
        ))
    elif is_echo and creds:
        findings.append((
            "high",
            "CORS: reflexão de Origin + credentials",
            f"O endpoint reflete a origem arbitrária ({EVIL_ORIGIN}) E permite credenciais. "
            f"Permite que um site malicioso execute requisições autenticadas com cookies/JWT "
            f"da vítima e leia a resposta.",
            f"OPTIONS {url} → ACAO: {EVIL_ORIGIN}, ACAC: true"
        ))
    elif is_echo:
        findings.append((
            "medium",
            "CORS: reflexão de Origin sem allowlist",
            f"O endpoint reflete qualquer Origin recebida ({EVIL_ORIGIN}) — não há "
            f"validação contra allowlist. Sem credentials habilitadas o risco é menor, "
            f"mas indica configuração permissiva.",
            f"OPTIONS {url} → Access-Control-Allow-Origin: {EVIL_ORIGIN}"
        ))

    return findings

# ── Executar ───────────────────────────────────────────────────────────────
urls = collect_urls()[:30]  # limita custo
results = []
seen_signatures = set()  # dedup por (url base, tipo de finding)

for url in urls:
    headers = test_cors(url)
    if not headers:
        continue
    for sev, name, desc, evidence in classify(url, headers):
        # Dedup: mesma vuln no mesmo host conta uma vez
        host = urlparse(url).netloc
        sig = (host, name)
        if sig in seen_signatures:
            continue
        seen_signatures.add(sig)
        results.append({
            "url": url, "severity": sev, "name": name,
            "description": desc, "evidence": evidence,
            "headers": headers,
        })

out_path = os.path.join(OUTDIR, "raw", "cors_findings.json")
json.dump(results, open(out_path, "w"), indent=2, ensure_ascii=False)

if results:
    print(f"  [✓] CORS check: {len(results)} misconfiguration(s) detectada(s) "
          f"(testadas {len(urls)} URLs)")
else:
    print(f"  [○] CORS check: nenhuma misconfiguration ({len(urls)} URLs testadas)")

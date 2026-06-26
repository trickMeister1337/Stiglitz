#!/usr/bin/env python3
"""
security_headers.py — Verifica security headers HTTP → security_headers.json

Extraído de stiglitz.sh (heredoc PYSECHEADERS). Recebe argumentos posicionais
via sys.argv, idêntico à invocação original do stiglitz.sh.

Além da presença/ausência dos headers, valida subdiretivas críticas:
  - HSTS: preload, includeSubDomains, max-age suficiente
  - CSP:  unsafe-inline, unsafe-eval, default-src ausente, wildcards
"""
import subprocess, json, sys, os, re
import netproxy
import mtls
outdir = sys.argv[1]
httpx_file = os.path.join(outdir,"raw","httpx_results.txt")

SECURITY_HEADERS = {
    "content-security-policy":      ("medium","CSP missing — XSS impact amplified"),
    "x-content-type-options":       ("medium","X-Content-Type-Options missing — MIME sniffing possible"),
    "x-frame-options":              ("medium","X-Frame-Options missing — Clickjacking possible"),
    "strict-transport-security":    ("medium","HSTS missing — HTTPS downgrade possible"),
    "referrer-policy":              ("low","Referrer-Policy missing — URL leakage in requests"),
    "permissions-policy":           ("low","Permissions-Policy missing — unrestricted access to browser APIs"),
    "x-xss-protection":             ("info","X-XSS-Protection legacy — prefer CSP"),
}

# ── Validações de subdiretivas ────────────────────────────────────────────
def validate_hsts(value):
    """Retorna lista de issues (severity, description) para o HSTS encontrado."""
    issues = []
    v = value.lower().strip()
    # preload
    if "preload" not in v:
        issues.append(("low",
            "HSTS sem directive 'preload' — primeiro acesso vulnerável a SSL stripping (TOFU)"))
    # includeSubDomains
    if "includesubdomains" not in v:
        issues.append(("low",
            "HSTS sem 'includeSubDomains' — subdomínios não protegidos contra downgrade"))
    # max-age
    m = re.search(r"max-age\s*=\s*(\d+)", v)
    if m:
        age = int(m.group(1))
        # Recomendação industry: ≥ 31536000 (1 ano)
        if age < 15552000:  # 6 meses
            issues.append(("medium",
                f"HSTS max-age={age}s curto demais — recomendado ≥ 31536000 (1 ano)"))
        elif age < 31536000:
            issues.append(("low",
                f"HSTS max-age={age}s — ideal é 31536000 (1 ano) para elegibilidade preload"))
    else:
        issues.append(("medium",
            "HSTS sem max-age — header efetivamente ignorado pelo browser"))
    return issues

def validate_csp(value):
    """Retorna lista de issues para a CSP encontrada."""
    issues = []
    v = value.lower().strip()

    # default-src ausente é um problema sério — CSP sem default fica permissiva por padrão
    if "default-src" not in v:
        issues.append(("medium",
            "CSP sem 'default-src' — fallback permissivo para diretivas não declaradas"))

    # unsafe-inline em script-src ou default-src — anula proteção XSS
    if re.search(r"(script-src|default-src)[^;]*'unsafe-inline'", v):
        issues.append(("high",
            "CSP com 'unsafe-inline' em script-src/default-src — XSS não mitigada"))

    # unsafe-eval em script-src
    if re.search(r"(script-src|default-src)[^;]*'unsafe-eval'", v):
        issues.append(("medium",
            "CSP com 'unsafe-eval' — permite execução de strings como código (eval/Function)"))

    # wildcard '*' em script-src ou default-src
    if re.search(r"(script-src|default-src)[^;]*(\s|^)\*(\s|;|$)", v):
        issues.append(("high",
            "CSP com wildcard '*' em script-src/default-src — qualquer origem pode executar scripts"))

    # frame-ancestors ausente (clickjacking)
    if "frame-ancestors" not in v:
        issues.append(("low",
            "CSP sem 'frame-ancestors' — depende de X-Frame-Options (legacy)"))

    # data: scheme em script-src (XSS vector clássico)
    if re.search(r"(script-src|default-src)[^;]*data:", v):
        issues.append(("medium",
            "CSP permite 'data:' em script-src — vetor clássico de XSS"))

    # object-src não restritivo
    if "object-src" not in v and "default-src" not in v:
        issues.append(("low",
            "CSP sem 'object-src 'none'' — Flash/applets podem executar"))

    return issues

# ── Coletar URLs ───────────────────────────────────────────────────────────
results = []
urls = []
if os.path.exists(httpx_file):
    with open(httpx_file) as f:
        for line in f:
            url = line.strip().split()[0] if line.strip() else ""
            if url.startswith("http"): urls.append(url)

for url in urls[:20]:  # testar as 20 primeiras URLs ativas
    try:
        r = subprocess.run(
            ["curl", *netproxy.curl_proxy_args(), *mtls.curl_cert_args(), "-sk","-I","--max-time","10","-L",url],
            capture_output=True, text=True, timeout=15
        )
        headers_raw = r.stdout.lower()
        missing = {}
        present = {}
        subdirective_issues = []  # lista de {header, severity, description, value}

        for h,(sev,desc) in SECURITY_HEADERS.items():
            if h not in headers_raw:
                missing[h] = {"severity":sev,"description":desc}
            else:
                # Extrair valor do header (último Set/redirect chain)
                value = "present"
                for line in r.stdout.split("\n"):
                    if line.lower().startswith(h + ":") or line.lower().startswith(h + " :"):
                        value = line.split(":",1)[1].strip() if ":" in line else "present"
                        break
                    elif h in line.lower() and ":" in line:
                        value = line.split(":",1)[1].strip()
                        break
                present[h] = value

                # Validar subdiretivas
                if h == "strict-transport-security":
                    for sev_sub, desc_sub in validate_hsts(value):
                        subdirective_issues.append({
                            "header": h, "severity": sev_sub,
                            "description": desc_sub, "value": value
                        })
                elif h == "content-security-policy":
                    for sev_sub, desc_sub in validate_csp(value):
                        subdirective_issues.append({
                            "header": h, "severity": sev_sub,
                            "description": desc_sub, "value": value
                        })

        results.append({
            "url": url,
            "missing": missing,
            "present": present,
            "subdirective_issues": subdirective_issues,
        })
    except Exception: pass  # handler amplo por-URL: rede/parse podem falhar de muitas formas; não mascara KeyboardInterrupt

out_file = os.path.join(outdir,"raw","security_headers.json")
json.dump(results, open(out_file,"w"), indent=2, ensure_ascii=False)

# Sumário
total_issues = sum(len(r["missing"]) for r in results)
total_subdir = sum(len(r.get("subdirective_issues",[])) for r in results)
critical_issues = sum(1 for r in results for s in r["missing"].values() if s["severity"]=="critical")
print(f"  Verificados: {len(results)} URL(s) | {total_issues} header(s) ausente(s) | {total_subdir} subdiretiva(s) fracas | {critical_issues} crítico(s)")

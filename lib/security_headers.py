#!/usr/bin/env python3
"""
security_headers.py — Verifica security headers HTTP → security_headers.json

Extraído de stiglitz.sh (heredoc PYSECHEADERS). Recebe argumentos posicionais
via sys.argv, idêntico à invocação original do stiglitz.sh.
"""
import subprocess, json, sys, os
outdir = sys.argv[1]
httpx_file = os.path.join(outdir,"raw","httpx_results.txt")

SECURITY_HEADERS = {
    "content-security-policy":      ("critical","CSP missing — XSS unmitigated"),
    "x-content-type-options":       ("medium","X-Content-Type-Options missing — MIME sniffing possible"),
    "x-frame-options":              ("medium","X-Frame-Options missing — Clickjacking possible"),
    "strict-transport-security":    ("high","HSTS missing — HTTPS downgrade possible"),
    "referrer-policy":              ("low","Referrer-Policy missing — URL leakage in requests"),
    "permissions-policy":           ("low","Permissions-Policy missing — unrestricted access to browser APIs"),
    "x-xss-protection":             ("info","X-XSS-Protection legacy — prefer CSP"),
}

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
            ["curl","-sk","-I","--max-time","10","-L",url],
            capture_output=True, text=True, timeout=15
        )
        headers_raw = r.stdout.lower()
        missing = {}
        present = {}
        for h,(sev,desc) in SECURITY_HEADERS.items():
            if h not in headers_raw:
                missing[h] = {"severity":sev,"description":desc}
            else:
                # Extrair valor do header
                for line in r.stdout.split("\n"):
                    if h in line.lower():
                        present[h] = line.split(":",1)[1].strip() if ":" in line else "present"
                        break
        results.append({"url":url,"missing":missing,"present":present})
    except: pass

out_file = os.path.join(outdir,"raw","security_headers.json")
json.dump(results, open(out_file,"w"), indent=2)

# Sumário
total_issues = sum(len(r["missing"]) for r in results)
critical_issues = sum(1 for r in results for s in r["missing"].values() if s["severity"]=="critical")
print(f"  Verificados: {len(results)} URL(s) | {total_issues} header(s) ausente(s) | {critical_issues} crítico(s)")

#!/usr/bin/env python3
"""
security_headers.py — Verifica security headers HTTP → security_headers.json

Além da presença/ausência dos headers, valida subdiretivas críticas:
  - HSTS: preload, includeSubDomains, max-age suficiente
  - CSP:  unsafe-inline, unsafe-eval, default-src ausente, wildcards

Resiliência a FP transitório (multi-sampling): um alvo atrás de load balancer pode
responder com headers divergentes entre backends, ou logo após um deploy. Uma única
amostra não-determinística levava a falso "header ausente" (HSTS reportado ausente
estando presente segundos depois). Agora coletamos N amostras (STIGLITZ_HEADER_SAMPLES,
default 3) e classificamos cada header como present / missing / inconsistent:
  - missing      — ausente em TODAS as amostras (achado confiável);
  - present      — presente em todas;
  - inconsistent — presente em algumas e ausente em outras (config drift) → NÃO é
                   contado como ausente; vira um sinal de baixa severidade.

Núcleo puro (classify_header/header_present/validate_*) testável sem rede +
orquestração fina (curl via netproxy/mtls). CLI: python3 lib/security_headers.py <outdir>
"""
import subprocess, json, sys, os, re
import netproxy
import mtls

SECURITY_HEADERS = {
    "content-security-policy":      ("medium","CSP missing — XSS impact amplified"),
    "x-content-type-options":       ("medium","X-Content-Type-Options missing — MIME sniffing possible"),
    "x-frame-options":              ("medium","X-Frame-Options missing — Clickjacking possible"),
    "strict-transport-security":    ("medium","HSTS missing — HTTPS downgrade possible"),
    "referrer-policy":              ("low","Referrer-Policy missing — URL leakage in requests"),
    "permissions-policy":           ("low","Permissions-Policy missing — unrestricted access to browser APIs"),
    "x-xss-protection":             ("info","X-XSS-Protection legacy — prefer CSP"),
}

# Nº de amostras por URL (resiliência a config drift / FP transitório).
DEFAULT_SAMPLES = max(1, int(os.environ.get("STIGLITZ_HEADER_SAMPLES", "3")))


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


# ── Núcleo puro: presença e classificação multi-amostra ──────────────────────
def header_present(headers_raw_lower, header):
    """True se o header aparece na resposta crua (já normalizada p/ lowercase)."""
    return header in (headers_raw_lower or "")


def classify_header(presence_flags):
    """Classifica um header a partir da presença em cada amostra.

    present      — em TODAS as amostras;
    missing      — em NENHUMA;
    inconsistent — em algumas sim, outras não (config drift / LB divergente).
    Sem amostras → missing (conservador).
    """
    flags = list(presence_flags)
    if not flags:
        return "missing"
    if all(flags):
        return "present"
    if not any(flags):
        return "missing"
    return "inconsistent"


def _extract_value(stdout, header):
    """Extrai o valor do header da resposta crua (heurística do scanner original)."""
    for line in (stdout or "").split("\n"):
        ll = line.lower()
        if ll.startswith(header + ":") or ll.startswith(header + " :"):
            return line.split(":", 1)[1].strip() if ":" in line else "present"
        elif header in ll and ":" in line:
            return line.split(":", 1)[1].strip()
    return "present"


def _append_subdir(subdirective_issues, header, value):
    """Anexa as issues de subdiretiva (HSTS/CSP) do valor observado."""
    if header == "strict-transport-security":
        for sev_sub, desc_sub in validate_hsts(value):
            subdirective_issues.append({"header": header, "severity": sev_sub,
                                        "description": desc_sub, "value": value})
    elif header == "content-security-policy":
        for sev_sub, desc_sub in validate_csp(value):
            subdirective_issues.append({"header": header, "severity": sev_sub,
                                        "description": desc_sub, "value": value})


def analyze_url(url, samples_raw):
    """Classifica cada header a partir de N respostas cruas (lista de stdout do curl).

    Retorna o dict por-URL no schema consumido pelo stiglitz_report.py
    (missing / present / subdirective_issues)."""
    lowered = [s.lower() for s in samples_raw]
    missing, present, subdirective_issues = {}, {}, []
    for h, (sev, desc) in SECURITY_HEADERS.items():
        flags = [header_present(s, h) for s in lowered]
        state = classify_header(flags)
        if state == "missing":
            missing[h] = {"severity": sev, "description": desc}
            continue
        # present ou inconsistent → registra valor observado + valida subdiretivas
        value = next((_extract_value(raw, h)
                      for raw, fl in zip(samples_raw, flags) if fl), "present")
        present[h] = value
        if state == "inconsistent":
            subdirective_issues.append({
                "header": h, "severity": "low",
                "description": (f"{h} inconsistently present — returned by some responses but "
                                "not others (load-balanced backends with divergent configuration "
                                "/ config drift). Not counted as missing."),
                "value": f"present in {sum(flags)}/{len(flags)} samples",
            })
        _append_subdir(subdirective_issues, h, value)
    return {"url": url, "missing": missing, "present": present,
            "subdirective_issues": subdirective_issues}


# ── Rede (uma amostra) ────────────────────────────────────────────────────────
def fetch_headers(url, timeout=15):
    """Uma amostra: stdout cru do curl -I -L, ou '' em erro."""
    try:
        r = subprocess.run(
            ["curl", *netproxy.curl_proxy_args(), *mtls.curl_cert_args(),
             "-sk", "-I", "--max-time", "10", "-L", url],
            capture_output=True, text=True, timeout=timeout)
        return r.stdout or ""
    except Exception:
        return ""  # rede/parse podem falhar de muitas formas; não mascara KeyboardInterrupt


def collect_urls(httpx_file):
    urls = []
    if os.path.exists(httpx_file):
        with open(httpx_file) as f:
            for line in f:
                url = line.strip().split()[0] if line.strip() else ""
                if url.startswith("http"):
                    urls.append(url)
    return urls


# ── Orquestração / CLI ────────────────────────────────────────────────────────
def main(outdir, samples=None):
    samples = DEFAULT_SAMPLES if samples is None else max(1, samples)
    httpx_file = os.path.join(outdir, "raw", "httpx_results.txt")
    results = []
    for url in collect_urls(httpx_file)[:20]:  # testar as 20 primeiras URLs ativas
        samples_raw = [fetch_headers(url) for _ in range(samples)]
        if not any(samples_raw):
            continue  # todas as amostras falharam (rede) — pula, como o scanner original
        results.append(analyze_url(url, samples_raw))

    out_file = os.path.join(outdir, "raw", "security_headers.json")
    json.dump(results, open(out_file, "w"), indent=2, ensure_ascii=False)

    total_issues = sum(len(r["missing"]) for r in results)
    total_subdir = sum(len(r.get("subdirective_issues", [])) for r in results)
    critical_issues = sum(1 for r in results for s in r["missing"].values()
                          if s["severity"] == "critical")
    print(f"  Verificados: {len(results)} URL(s) | {total_issues} header(s) ausente(s) | "
          f"{total_subdir} subdiretiva(s) fracas | {critical_issues} crítico(s)")
    return results


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("uso: python3 lib/security_headers.py <outdir>", file=sys.stderr)
        sys.exit(2)
    main(sys.argv[1])

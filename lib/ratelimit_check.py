#!/usr/bin/env python3
"""
ratelimit_check.py — Teste de rate limiting → ratelimit_findings.json

Extraído de stiglitz.sh (heredoc PYRATELIMIT). Recebe argumentos posicionais
via sys.argv, idêntico à invocação original do stiglitz.sh.
"""
import sys, re, json, time, urllib.request, urllib.error, ssl

outdir, target = sys.argv[1], sys.argv[2].rstrip("/")
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE

LOGIN_PATHS = ["/login", "/api/login", "/api/auth/login", "/auth/login", "/api/user/login",
               "/admin/login", "/api/v1/login", "/signin", "/api/signin"]

JSON_BODY   = b'{"user":"stiglitztest","password":"stiglitztest_probe_ratelimit"}'
FORM_BODY   = b"user=stiglitztest&password=stiglitztest_probe_ratelimit"
N_REQUESTS  = 20

def post(url, body, content_type, attempts=2, backoff=3):
    import time as _t
    for attempt in range(attempts):
        try:
            req = urllib.request.Request(url, data=body, method="POST",
                  headers={"User-Agent": "Mozilla/5.0", "Content-Type": content_type})
            r = urllib.request.urlopen(req, timeout=8, context=ctx)
            return r.status, dict(r.headers)
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers)
        except Exception as e:
            if attempt < attempts - 1:
                _t.sleep(backoff)
            else:
                print(f"  [!] post falhou: {url} — {type(e).__name__}: {e}")
    return 0, {}

findings = []
tested_paths = []

for path in LOGIN_PATHS:
    url = target + path
    # Quick probe: does this path respond to POST?
    code, headers = post(url, JSON_BODY, "application/json")
    if code == 0:
        continue
    if code not in (200, 400, 401, 403, 422, 429):
        # Try form-encoded
        code, headers = post(url, FORM_BODY, "application/x-www-form-urlencoded")
        if code not in (200, 400, 401, 403, 422, 429):
            continue

    content_type = "application/json" if code != 0 else "application/x-www-form-urlencoded"
    tested_paths.append(path)

    codes   = []
    got_429 = False
    got_retry_after = False
    t0 = time.time()
    for i in range(N_REQUESTS):
        c, hdrs = post(url, JSON_BODY if content_type == "application/json" else FORM_BODY,
                       content_type)
        codes.append(c)
        if c == 429:
            got_429 = True
        if "retry-after" in {k.lower() for k in hdrs}:
            got_retry_after = True

    elapsed = time.time() - t0
    # If total elapsed is > 3× expected (N * 0.1s), server may be throttling
    if got_429 or got_retry_after:
        print(f"  [✓] {path}: rate limiting detectado (429={got_429}, Retry-After={got_retry_after})")
        break  # rate limiting works — stop
    else:
        print(f"  [!] {path}: SEM rate limiting — {N_REQUESTS} req em {elapsed:.1f}s, codes={set(codes)}")
        findings.append({
            "id":          f"missing-rate-limit-{path.strip('/').replace('/', '-')}",
            "name":        f"Login Without Rate Limiting: {path}",
            "severity":    "medium",
            "source":      "Rate Limit Check",
            "url":         target + path,
            "cve":         "CWE-307 — Improper Restriction of Excessive Authentication Attempts",
            "cve_ids":     [],
            "description": (
                f"Endpoint {path} does not implement rate limiting. "
                f"{N_REQUESTS} POST requests with invalid credentials completed in {elapsed:.1f}s "
                f"without returning HTTP 429 or a Retry-After header. "
                "Allows brute-force and credential-stuffing attacks without restriction."
            ),
            "remediation": (
                "Implement rate limiting on the login endpoint: max 5-10 attempts per IP per minute. "
                "Options: fail2ban, nginx limit_req, Grafana built-in brute_force_login_protection = true "
                "(grafana.ini [security]), or a WAF with a throttling rule on POST /login."
            ),
            "evidence":    f"POST {path} × {N_REQUESTS} → HTTP {set(codes)} in {elapsed:.1f}s — no blocking",
            "param": "", "attack": "", "other": "",
            "severity_orig": "medium",
            "severity_reclassified": False,
        })
        break  # only report once even if multiple paths lack rate limiting

out_file = f"{outdir}/raw/ratelimit_findings.json"
with open(out_file, "w") as f:
    json.dump(findings, f, indent=2, ensure_ascii=False)

if not findings and tested_paths:
    print(f"  [✓] Rate limiting OK nos endpoints testados: {', '.join(tested_paths)}")
elif not tested_paths:
    print("  [○] Nenhum endpoint de login acessível encontrado para teste de rate limiting")

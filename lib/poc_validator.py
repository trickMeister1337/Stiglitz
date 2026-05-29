#!/usr/bin/env python3
"""
Stiglitz — PoC Validator v3
Confirma ativamente vulnerabilidades de TODAS as fontes:
  - Nuclei (curl reconstruído de método+URL+body, citado com shlex.quote)
  - OWASP ZAP (extrai request do XML)
  - testssl (TLS/SSL via openssl + curl)
  - Email security (SPF/DMARC/DKIM via dig)

Melhorias v3 (redução de falsos positivos):
  - validate(): thresholds mais rigorosos em todos os tipos
  - response_diff(): mínimo absoluto de bytes + threshold ajustável por tamanho
  - normalize(): cobertura ampliada de tokens dinâmicos
  - double_check(): ativado também para severity HIGH
  - parse_http_response(): parsing robusto, imune a status no body
  - confirm_nuclei(): reconstrução de curl com payload original quando disponível
  - auth_bypass/generic/exposure/redirect: exigem evidências reais, não apenas HTTP 200
  - security_header: classificado como informacional (não "confirmado" em alta confiança)
  - tls: verifica cipher/protocolo via openssl, não apenas conectividade
  - Confidence cap: nunca emite "confirmed" abaixo de MIN_CONFIRM_CONFIDENCE

Uso standalone: python3 lib/poc_validator.py <outdir>
"""

import json, subprocess, re, sys, os, time, shlex, xml.etree.ElementTree as ET
from datetime import datetime, timezone

# OOB/OAST é opcional — degrada sem erro se o módulo não carregar.
try:
    from oob import OOBSession, inject_oob_url
    _OOB_AVAILABLE = True
except Exception:
    _OOB_AVAILABLE = False

# OAuth refresh é opcional — só ativa quando STIGLITZ_OAUTH_TOKEN_URL estiver
# configurada. Refresh inicial no startup + retry em 401 dentro do loop.
try:
    import oauth_refresh as _oauth
    _OAUTH_AVAILABLE = True
except Exception:
    _OAUTH_AVAILABLE = False
_OAUTH_TOKEN = ""   # access_token corrente (atualizado on-401)

def _refresh_oauth_safe():
    """Tenta refresh; em falha, retorna "" e loga (não aborta o scan)."""
    global _OAUTH_TOKEN
    if not (_OAUTH_AVAILABLE and _oauth.is_enabled()):
        return ""
    try:
        _OAUTH_TOKEN = _oauth.refresh_access_token()
        print(f"  [OAuth] refresh ok — token atualizado")
        return _OAUTH_TOKEN
    except Exception as e:
        print(f"  [OAuth] refresh falhou: {e}")
        return ""

def _apply_oauth(curl_cmd):
    """Injeta Authorization Bearer no curl quando temos token."""
    if not _OAUTH_TOKEN:
        return curl_cmd
    return _oauth.apply_to_curl(curl_cmd, _OAUTH_TOKEN)

# ── Threshold mínimo para considerar um achado "confirmado" ──────
MIN_CONFIRM_CONFIDENCE = 60   # abaixo disso → force confirmed=False

# ── Carregar padrões externos ─────────────────────────────────────
def load_patterns(patterns_path=None):
    if patterns_path is None:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        candidates = [
            os.path.join(script_dir, "vuln_patterns.json"),
            os.path.join(script_dir, "..", "vuln_patterns.json"),
            os.path.join(os.path.expanduser("~"), "vuln_patterns.json"),
        ]
        for c in candidates:
            if os.path.isfile(c):
                patterns_path = c
                break
    try:
        with open(patterns_path, encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"  [!] vuln_patterns.json: {e} — usando padrões mínimos")
        return {}

PATTERNS = load_patterns()

# ── Escopo: STIGLITZ_SCOPE_DOMAINS (space-separated) ─────────────
# Exportado pelos orquestradores. Vazio → sem filtragem (uso standalone).
def _load_scope_domains():
    raw = os.environ.get("STIGLITZ_SCOPE_DOMAINS", "")
    return [d.strip().lower().lstrip("*.")
            for d in raw.split() if d.strip()]

SCOPE_DOMAINS = _load_scope_domains()

def _url_in_scope(url):
    """True se `url` é vazia/sem escopo definido OU se o host está em escopo."""
    if not SCOPE_DOMAINS:
        return True
    from urllib.parse import urlparse
    try:
        host = (urlparse(url).hostname or "").lower()
    except Exception:
        return False
    if not host:
        return False
    return any(host == d or host.endswith("." + d) for d in SCOPE_DOMAINS)

# ══════════════════════════════════════════════════════════════════
# UTILITÁRIOS
# ══════════════════════════════════════════════════════════════════

def run_cmd(cmd, timeout=20, retries=2, backoff=5):
    """Executa um comando externo SEM shell.

    Aceita `list[str]` (argv direto) ou `str` (parseada por shlex.split).
    Strings com metacaracteres de shell não-quotados (`;`, `|`, `&`, etc.)
    falham com PARSE_ERROR — esse é o ponto: shell metacharacters nunca
    são interpretados. Para comandos que realmente precisam de pipe
    (openssl chain), use `run_shell_pipe` explicitamente.
    """
    if isinstance(cmd, str):
        try:
            argv = shlex.split(cmd)
        except ValueError as e:
            return "", f"PARSE_ERROR:{e}"
    else:
        argv = list(cmd)
    if not argv:
        return "", "EMPTY"
    for attempt in range(retries):
        try:
            r = subprocess.run(argv, shell=False, capture_output=True,
                               text=True, timeout=timeout)
            return r.stdout + r.stderr, None
        except subprocess.TimeoutExpired:
            if attempt < retries - 1:
                time.sleep(backoff)
        except (OSError, ValueError) as e:
            return "", f"EXEC_ERROR:{e}"
    return "", "TIMEOUT"

def run_shell_pipe(cmd, timeout=20, retries=2, backoff=5):
    """Executa um pipeline shell legítimo (openssl chain etc.).

    Reservado para comandos compostos com `|` ou `>` que não fazem sentido
    como argv único. NUNCA passar dados controlados pelo alvo sem
    `shlex.quote` prévio — o uso de `shell=True` aqui é deliberado e
    auditável (poucos call sites, todos internos).
    """
    for attempt in range(retries):
        try:
            r = subprocess.run(cmd, shell=True, capture_output=True,
                               text=True, timeout=timeout)
            return r.stdout + r.stderr, None
        except subprocess.TimeoutExpired:
            if attempt < retries - 1:
                time.sleep(backoff)
        except (OSError, ValueError) as e:
            return "", f"EXEC_ERROR:{e}"
    return "", "TIMEOUT"

def parse_http_response(raw):
    """
    Extrai status, headers e body de curl -D - -w '...===Stiglitz_STATUS:NNN==='.
    Robusto: localiza o marker pela ÚLTIMA ocorrência para não confundir com
    conteúdo do body que possa conter a string.
    """
    if not raw:
        return "000", "", ""

    # Localizar status pela última ocorrência do marker
    marker_re = re.compile(r'===Stiglitz_STATUS:(\d+)===')
    matches = list(marker_re.finditer(raw))
    if matches:
        last_match = matches[-1]
        status = last_match.group(1)
        body_section = raw[:last_match.start()]
    else:
        status = "???"
        body_section = raw

    # Separar headers HTTP do body (primeira linha em branco após status line)
    # curl -D - injeta os headers no início
    parts = re.split(r'\r?\n\r?\n', body_section, maxsplit=1)
    headers = parts[0].strip() if parts else ""
    body = parts[1].strip()[:4000] if len(parts) > 1 else ""
    return status, headers, body

def normalize(text):
    """
    Remove tokens dinâmicos (CSRF, session IDs, timestamps, ETags, nonces,
    UUIDs, hashes) para tornar a comparação de respostas estável.
    """
    if not text:
        return ""

    default_dyn = [
        # CSRF / tokens de formulário
        r"_token=[a-zA-Z0-9+/=_\-]{16,}",
        r"csrf[_\-]?token[\"']?\s*[=:][\"']?\s*[a-zA-Z0-9+/=_\-]{10,}",
        r"authenticity_token[\"']?\s*[=:][\"']?\s*[a-zA-Z0-9+/=_\-]{10,}",
        r"__RequestVerificationToken[^\"'>]{0,5}[\"'>]\s*[a-zA-Z0-9+/=_\-]{10,}",
        # Datas e timestamps
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?",
        r"timestamp[\"']?\s*[=:]\s*\d{10,13}",
        r"(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun),\s+\d{1,2}\s+\w+\s+\d{4}\s+[\d:]+\s+GMT",
        # UUIDs
        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        # ETags, nonces, hashes
        r'ETag:\s*[W/]?"[^"\r\n]+"',
        r"Date:\s*[^\r\n]+",
        r'nonce["\s]*[=:]\s*["\s]*[a-zA-Z0-9+/=_\-]{8,}',
        r"[a-f0-9]{32,64}",   # MD5/SHA hashes soltos
        # Session cookies
        r"(?:PHPSESSID|JSESSIONID|ASP\.NET_SessionId|laravel_session)=[^\s;\"'&]+",
        # JWT
        r"eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+",
        # Números de versão / build (evita diff de "v1.2.3" vs "v1.2.4")
        r"\bv\d+\.\d+\.\d+(?:\.\d+)?\b",
    ]
    dyn = PATTERNS.get("normalization", {}).get("dynamic_tokens", default_dyn)
    norm = text
    for p in dyn:
        try:
            norm = re.sub(p, "<<DYN>>", norm, flags=re.IGNORECASE)
        except Exception:
            pass
    return re.sub(r'\s+', ' ', norm).strip()

def response_diff(base_norm, payload_norm):
    """
    Compara resposta normalizada do baseline com a do payload.

    Melhorias v3:
    - Exige mínimo de 50 bytes no baseline para comparação válida
    - Threshold relativo ajustável por tamanho: corpos pequenos exigem % maior
    - Threshold absoluto: mínimo de 200 bytes de diferença para alertar
    - Detecção de palavras-erro mais específica (evita "warning" em CSS/JS)
    """
    if not base_norm or not payload_norm:
        return False, 0, "Sem baseline para comparação"

    b_len, p_len = len(base_norm), len(payload_norm)

    if b_len < 50:
        return False, 0, f"Baseline muito pequeno ({b_len}B) — diff ignorado"

    abs_diff = abs(p_len - b_len)
    pct = abs_diff / max(b_len, 1) * 100

    # Threshold relativo adaptativo: respostas menores precisam de > variação %
    if b_len < 500:
        rel_threshold = 40.0
    elif b_len < 2000:
        rel_threshold = 25.0
    else:
        rel_threshold = 15.0

    abs_threshold = 200  # bytes absolutos mínimos de diferença

    if pct > rel_threshold and abs_diff > abs_threshold:
        return True, 15, f"Resposta mudou {pct:.0f}% (+{abs_diff}B) vs baseline ({b_len}B)"

    # Palavras de erro — buscar em contexto (evitar hits em atributos CSS/JS)
    error_words = {"sql error", "syntax error", "exception", "stack trace",
                   "fatal error", "invalid query", "odbc", "ora-", "pg::"}
    payload_lower = payload_norm.lower()
    base_lower    = base_norm.lower()
    new_errors = {w for w in error_words
                  if w in payload_lower and w not in base_lower}
    if new_errors:
        return True, 20, f"Mensagens de erro novas: {', '.join(list(new_errors)[:3])}"

    return False, 0, f"Sem diff significativo ({pct:.1f}%, {abs_diff}B abs)"

def build_safe_baseline(curl_cmd, matched_at):
    """Curl limpo + curl com payload substituído por valor seguro."""
    safe = PATTERNS.get("safe_payload_substitutes", {}).get("default", "safe-test-value-123")
    clean = re.sub(r'^curl\s+', 'curl -sk -L --max-time 15 ', curl_cmd.strip())
    for rm in ['-x http://127.0.0.1:8080', '--proxy http://127.0.0.1:8080']:
        clean = clean.replace(rm, '').strip()

    _sqli_kw = r"(?:OR|AND|UNION|SELECT|DROP|INSERT|UPDATE|DELETE|EXEC|CAST)"
    # Payload entre aspas simples
    safe_curl = re.sub(
        rf"'[^']*{_sqli_kw}[^']*'",
        f"'{safe}'", clean, flags=re.IGNORECASE)
    # Payload entre aspas duplas (antes só aspas simples eram tratadas → FN)
    safe_curl = re.sub(
        rf'"[^"]*{_sqli_kw}[^"]*"',
        f'"{safe}"', safe_curl, flags=re.IGNORECASE)
    safe_curl = re.sub(
        r"<script[^>]*>.*?</script>|javascript:[^\s\"'&]+",
        safe, safe_curl, flags=re.IGNORECASE | re.DOTALL)
    safe_curl = re.sub(
        r"(?:\.\.[\\/]){2,}(?:etc/passwd|windows[^\s\"']*)|(\.\.%2[Ff]){2,}",
        safe, safe_curl, flags=re.IGNORECASE)
    # Payloads de SSRF/SSTI/template injection
    safe_curl = re.sub(
        r"\{\{[^}]{1,50}\}\}|\$\{[^}]{1,50}\}|#\{[^}]{1,50}\}",
        safe, safe_curl)
    return clean, safe_curl

def check_auth_evidence(headers, body):
    ev = []
    sess_pats = ["session", "token", "auth", "jwt", "sid", "phpsessid", "connect.sid"]
    for line in (headers or "").split("\n"):
        if "set-cookie:" in line.lower() and any(s in line.lower() for s in sess_pats):
            ev.append(f"Sessão criada: {line.strip()[:80]}")
    jwt_m = re.search(r'eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+', body or "")
    if jwt_m:
        ev.append(f"JWT: {jwt_m.group(0)[:40]}...")
    # Bearer token
    bearer_m = re.search(r'"(?:access_token|token)"\s*:\s*"([a-zA-Z0-9._\-]{20,})"', body or "")
    if bearer_m:
        ev.append(f"Bearer token: {bearer_m.group(1)[:40]}...")
    return ev

def double_check(cmd, interval=4):
    """
    Executa o mesmo comando duas vezes e verifica consistência.
    Retorna (consistente: bool, nota: str).
    """
    results = []
    for i in range(2):
        out, err = run_cmd(cmd, timeout=20, retries=1)
        if err:
            results.append({"status": "ERR", "body": ""})
        else:
            s, h, b = parse_http_response(out)
            results.append({"status": s, "body_len": len(b)})
        if i == 0:
            time.sleep(interval)

    s1, s2 = results[0]["status"], results[1]["status"]
    if s1 == s2 and s1 not in ("ERR", "???", "000"):
        return True, f"Consistente: HTTP {s1} em ambas execuções"
    if s1 != s2:
        return False, f"Instável: {s1} → {s2} (possível race condition ou cache)"
    return False, f"Ambas execuções com erro/timeout"

# ══════════════════════════════════════════════════════════════════
# CLASSIFICAÇÃO & VALIDAÇÃO
# ══════════════════════════════════════════════════════════════════

def classify_vuln(template_id, name, tags=""):
    tid = (template_id + " " + name + " " + tags).lower()
    if any(x in tid for x in ["sql", "sqli", "injection", "union"]):              return "sqli"
    if any(x in tid for x in ["xss", "cross-site-scripting", "cross site scr"]): return "xss"
    if any(x in tid for x in ["lfi", "path-traversal", "file-incl", "directory-traversal"]): return "lfi"
    if any(x in tid for x in ["ssrf", "server-side-request"]):                    return "ssrf"
    if any(x in tid for x in ["cors", "cross-origin"]):                           return "cors"
    if any(x in tid for x in ["jwt", "json-web", "token-bypass"]):               return "jwt"
    if any(x in tid for x in ["aws", "s3", "access-key", "secret-key"]):         return "secret_aws"
    if any(x in tid for x in ["default-login", "default-cred", "weak-cred",
                                "default-password"]):                              return "default_login"
    if any(x in tid for x in ["open-redirect", "unvalidated-redirect"]):         return "redirect"
    if any(x in tid for x in ["takeover", "subdomain-takeover"]):                return "takeover"
    if any(x in tid for x in ["exposure", "disclosure", "sensitive",
                                "leaked", "leak"]):                               return "exposure"
    if any(x in tid for x in ["middleware", "bypass", "auth-bypass",
                               "nextjs", "subrequest", "authorization-bypass",
                               "privilege-escalation", "idor"]):                  return "auth_bypass"
    if any(x in tid for x in ["hsts", "csp", "x-frame", "content-security",
                               "security-header", "missing-header",
                               "clickjacking", "x-content-type"]):               return "security_header"
    if any(x in tid for x in ["tls", "ssl", "certificate", "cipher",
                               "protocol", "heartbleed", "poodle", "beast",
                               "sweet32", "logjam"]):                             return "tls"
    if any(x in tid for x in ["spf", "dmarc", "dkim", "email", "mx"]):          return "email"
    return "generic"

def validate(vuln_type, url, resp_body, resp_headers, status,
             method_results=None, diff_changed=False, diff_conf=0,
             diff_note="", auth_ev=None, dc_result=None):
    """
    Valida uma vulnerabilidade e retorna (confirmed: bool, confidence: int, note: str).

    v3: thresholds mais rigorosos — especialmente para tipos que geravam FP:
        generic, exposure, redirect, auth_bypass, security_header, tls

    v8: dispatch via plug-in registry (lib/validators/*). Se o tipo está
    registrado, chama o plug-in; senão cai no if/elif legado.
    """
    p    = PATTERNS.get(vuln_type, {})
    b    = (resp_body    or "").lower()
    h    = (resp_headers or "").lower()
    auth = auth_ev or []

    # dc_bonus: +10 se double-check foi consistente, -15 se inconsistente
    if dc_result is not None:
        dc_bonus = 10 if dc_result[0] else -15
        dc_note  = dc_result[1]
    else:
        dc_bonus = 0
        dc_note  = ""

    # ── Plug-in registry: dispatch para validadores externos ─────
    try:
        import validators as _val_pkg
        _plugin = _val_pkg.get(vuln_type)
    except ImportError:
        _plugin = None
    if _plugin:
        ctx = {
            "url": url, "resp_body": resp_body, "resp_headers": resp_headers,
            "status": status, "patterns": p,
            "diff_changed": diff_changed, "diff_conf": diff_conf,
            "diff_note": diff_note, "auth_ev": auth,
            "dc_result": dc_result, "dc_bonus": dc_bonus,
            "method_results": method_results or {},
        }
        return _clamp_confidence(*_plugin(ctx))

    # ── SQLi ─────────────────────────────────────────────────────
    if vuln_type == "sqli":
        for pat in p.get("patterns", []):
            try:
                if re.search(pat, resp_body or "", re.IGNORECASE):
                    return _clamp_confidence(True, min(95 + dc_bonus, 99),
                                             f"Erro SQL: '{pat}'")
            except Exception:
                pass
        # Diff por mensagens de erro novas (diff_conf>=20) — sinal forte
        if diff_changed and diff_conf >= 20:
            return _clamp_confidence(True, 70 + dc_bonus + diff_conf,
                                     f"Payload disparou erro/anomalia: {diff_note}")
        # Diff só por tamanho (diff_conf~15) — sinal fraco. Só confirma se o
        # double-check corroborar (mesmo status nas 2 execuções). Conteúdo
        # dinâmico legítimo varia de tamanho e era a maior fonte de FP aqui.
        if diff_changed and diff_conf >= 15:
            if dc_result and dc_result[0]:
                return _clamp_confidence(True, 62 + dc_bonus,
                                         f"Diferença de tamanho corroborada por double-check: {diff_note}")
            return _clamp_confidence(False, 45,
                                     f"Diferença de tamanho sem corroboração (possível conteúdo dinâmico): {diff_note}")
        if status.startswith("5") and diff_changed:
            return _clamp_confidence(True, 65 + dc_bonus, "5xx + diff — possível crash SQLi")
        return _clamp_confidence(False, 30, "Sem indicador SQLi")

    # ── XSS ──────────────────────────────────────────────────────
    elif vuln_type == "xss":
        for pat in p.get("patterns", []):
            try:
                if re.search(pat, resp_body or "", re.IGNORECASE):
                    return _clamp_confidence(True, min(95 + dc_bonus, 99),
                                             f"XSS refletido: '{pat}'")
            except Exception:
                pass
        # XSS exige reflexão do payload; diff só por tamanho não confirma sozinho.
        if diff_changed and diff_conf >= 20:
            return _clamp_confidence(True, 68 + dc_bonus, f"Anomalia com payload: {diff_note}")
        if diff_changed and diff_conf >= 15:
            if dc_result and dc_result[0]:
                return _clamp_confidence(True, 60 + dc_bonus,
                                         f"Diferença de tamanho corroborada: {diff_note}")
            return _clamp_confidence(False, 40,
                                     f"Diferença de tamanho sem reflexão confirmada: {diff_note}")
        return _clamp_confidence(False, 20, "Payload não refletido ou encodado")

    # ── LFI ──────────────────────────────────────────────────────
    elif vuln_type == "lfi":
        for pat in p.get("patterns", []):
            try:
                if re.search(pat, resp_body or "", re.IGNORECASE):
                    return _clamp_confidence(True, min(97 + dc_bonus, 99),
                                             f"Conteúdo de sistema: '{pat}'")
            except Exception:
                pass
        if diff_changed and diff_conf >= 20:
            return _clamp_confidence(True, 72 + dc_bonus,
                                     f"Inclusão disparou anomalia: {diff_note}")
        if diff_changed and diff_conf >= 15:
            if dc_result and dc_result[0]:
                return _clamp_confidence(True, 62 + dc_bonus,
                                         f"Diferença de tamanho corroborada: {diff_note}")
            return _clamp_confidence(False, 42,
                                     f"Diferença de tamanho sem conteúdo de sistema: {diff_note}")
        return _clamp_confidence(False, 25, "Sem conteúdo de sistema no response")

    # ── SSRF ─────────────────────────────────────────────────────
    elif vuln_type == "ssrf":
        # SSRF é difícil de confirmar passivamente; exige OOB ou conteúdo interno
        for pat in p.get("oob_patterns", p.get("patterns", [])):
            try:
                if re.search(pat, resp_body or "", re.IGNORECASE):
                    return _clamp_confidence(True, min(93 + dc_bonus, 99),
                                             f"Resposta interna detectada: '{pat}'")
            except Exception:
                pass
        if diff_changed and diff_conf >= 20:
            return _clamp_confidence(True, 65 + dc_bonus,
                                     f"Diff com payload SSRF: {diff_note}")
        return _clamp_confidence(False, 25, "Sem evidência de SSRF (use interação OOB para confirmar)")

    # ── CORS ─────────────────────────────────────────────────────
    elif vuln_type == "cors":
        acao = next((l for l in (resp_headers or "").split("\n")
                     if "access-control-allow-origin" in l.lower()), "")
        acac = next((l for l in (resp_headers or "").split("\n")
                     if "access-control-allow-credentials" in l.lower()), "")
        cred_bonus = 20 if acac and "true" in acac.lower() else 0

        if acao and any(x in acao.lower() for x in ["evil.com", "null", "attacker"]):
            return _clamp_confidence(True, min(97 + cred_bonus, 99),
                                     f"CORS reflete origem controlável: {acao.strip()[:80]}")
        if acao and "*" in acao and cred_bonus:
            # Wildcard + credentials é o único caso realmente crítico com *
            return _clamp_confidence(True, 85,
                                     "CORS wildcard + credentials=true (misconfiguration real)")
        if acao and "*" in acao:
            return _clamp_confidence(False, 50,
                                     "CORS wildcard sem credentials — geralmente informacional")
        return _clamp_confidence(False, 15, "CORS não misconfigured")

    # ── Default Login ─────────────────────────────────────────────
    elif vuln_type == "default_login":
        if auth:
            return _clamp_confidence(True, min(97 + dc_bonus, 99),
                                     f"Auth confirmada: {auth[0]}")
        for pat in p.get("success_patterns", ["dashboard", "logout", "welcome",
                                               "logged in", "sign out"]):
            if pat.lower() in b:
                return _clamp_confidence(True, 88 + dc_bonus, f"Indicador pós-login: '{pat}'")
        if method_results:
            ps = (method_results.get("POST") or ("???",))[0]
            gs = (method_results.get("GET")  or ("???",))[0]
            # POST retorna 2xx enquanto GET não → indica autenticação bem-sucedida
            if ps.startswith("2") and not gs.startswith("2"):
                return _clamp_confidence(True, 78 + dc_bonus,
                                         f"POST autenticado ({ps}) vs GET sem auth ({gs})")
        return _clamp_confidence(False, 20, "Sem evidência de autenticação bem-sucedida")

    # ── Exposure ─────────────────────────────────────────────────
    elif vuln_type == "exposure":
        # v3: não confirmar apenas por acessibilidade HTTP 200 — exige padrão real
        cfg = p.get("config_pattern", "")
        if cfg:
            try:
                m = re.search(cfg, resp_body or "")
                if m:
                    return _clamp_confidence(True, 95,
                                             f"Credencial/dado sensível: '{m.group(0)[:60]}'")
            except Exception:
                pass
        for pat in p.get("high_confidence_patterns", []):
            try:
                if re.search(pat, resp_body or ""):
                    return _clamp_confidence(True, 94, f"Dado sensível: '{pat}'")
            except Exception:
                pass
        for pat in p.get("patterns", []):
            try:
                if re.search(pat, resp_body or "", re.IGNORECASE):
                    return _clamp_confidence(True, 80, f"Padrão de exposição: '{pat}'")
            except Exception:
                pass
        # HTTP 200 sem padrão = não confirmado (era fonte de FP)
        if status.startswith("2") and len(resp_body or "") > 500:
            return _clamp_confidence(False, 45,
                                     f"Recurso acessível ({len(resp_body or '')}B) mas sem dado sensível identificado")
        return _clamp_confidence(False, 25, "Sem dado sensível identificável")

    # ── Security Headers ─────────────────────────────────────────
    elif vuln_type == "security_header":
        # v3: headers ausentes são achados INFORMATIVOS confirmados, mas com
        # confiança moderada — não são exploits ativos
        required = {
            "content-security-policy":    "CSP",
            "strict-transport-security":  "HSTS",
            "x-frame-options":            "X-Frame-Options",
            "x-content-type-options":     "X-Content-Type-Options",
            "referrer-policy":            "Referrer-Policy",
            "permissions-policy":         "Permissions-Policy",
        }
        missing = [label for hdr, label in required.items() if hdr not in h]
        if not status.startswith("2") and status not in ("301", "302"):
            return _clamp_confidence(False, 15,
                                     f"Endpoint não retornou 2xx/3xx — verificação inválida")
        if missing:
            # Confirmado mas confiança limitada — é informacional
            return _clamp_confidence(True, 82,
                                     f"Headers ausentes verificados: {', '.join(missing)}")
        return _clamp_confidence(False, 15, "Todos os headers de segurança presentes")

    # ── TLS ──────────────────────────────────────────────────────
    elif vuln_type == "tls":
        # v3: já confirmado pelo testssl — verificar conectividade é necessário
        # mas não suficiente; a nota específica do testssl é o que importa
        if status.startswith("2") or status in ("301", "302", "403"):
            return _clamp_confidence(True, 82,
                                     f"TLS acessível (HTTP {status}) — issue de config confirmada via testssl")
        if status in ("000", "TIMEOUT", "ERR"):
            return _clamp_confidence(False, 20, f"Endpoint TLS inacessível — não é possível confirmar")
        return _clamp_confidence(False, 35, f"Endpoint retornou HTTP {status} — verificar manualmente")

    # ── Email / DNS ───────────────────────────────────────────────
    elif vuln_type == "email":
        # Confirmação já feita via dig em confirm_email()
        return _clamp_confidence(True, 95, "Configuração de email verificada via DNS")

    # ── Auth Bypass ──────────────────────────────────────────────
    elif vuln_type == "auth_bypass":
        # v3: exige diff ou evidência real — HTTP 200 sozinho não basta
        if diff_changed and diff_conf >= 15:
            return _clamp_confidence(True, min(88 + dc_bonus, 99),
                                     f"Bypass confirmado com diff: {diff_note}")
        if status.startswith("2") and diff_changed:
            return _clamp_confidence(True, 80 + dc_bonus,
                                     f"Acesso com header bypass (HTTP {status}) + diff")
        if auth:
            return _clamp_confidence(True, 85 + dc_bonus,
                                     f"Auth evidence com bypass: {auth[0]}")
        if status in ("401", "403"):
            return _clamp_confidence(False, 15, f"Bypass não funcionou (HTTP {status})")
        # HTTP 200 sem diff = não confirmado (era maior fonte de FP)
        if status.startswith("2"):
            return _clamp_confidence(False, 45,
                                     f"HTTP {status} com bypass mas sem diff — revisar manualmente")
        return _clamp_confidence(False, 15, f"HTTP {status} sem evidência de bypass")

    # ── Redirect ─────────────────────────────────────────────────
    elif vuln_type == "redirect":
        loc = next((l for l in (resp_headers or "").split("\n")
                    if "location:" in l.lower()), "")
        if not loc:
            return _clamp_confidence(False, 15, "Sem header Location — não há redirect")

        # v3: verificar se o destino é realmente externo/controlável
        malicious = p.get("malicious_destinations",
                          ["evil.com", "//evil", "@evil", "javascript:",
                           "//attacker", "//127.0.0.1", "//localhost"])
        for dest in malicious:
            if dest in loc:
                return _clamp_confidence(True, 94,
                                         f"Redirect externo confirmado: {loc.strip()[:100]}")

        # Verificar redirect para domínio diferente do original
        url_domain = re.search(r'https?://([^/]+)', url)
        loc_domain = re.search(r'location:\s*https?://([^/\s]+)', loc, re.IGNORECASE)
        if url_domain and loc_domain:
            if url_domain.group(1).lower() != loc_domain.group(1).lower():
                return _clamp_confidence(True, 78,
                                         f"Redirect para domínio externo: {loc.strip()[:100]}")

        # Redirect relativo ou para o mesmo domínio = não é open redirect
        return _clamp_confidence(False, 30,
                                  f"Redirect ({status}) para destino interno — provavelmente FP")

    # ── Takeover ─────────────────────────────────────────────────
    elif vuln_type == "takeover":
        for pat in p.get("patterns", []):
            try:
                if re.search(pat, resp_body or "", re.IGNORECASE):
                    return _clamp_confidence(True, 95, f"Serviço inativo: '{pat}'")
            except Exception:
                pass
        return _clamp_confidence(False, 25, "Sem indicador de serviço inativo")

    # ── JWT ──────────────────────────────────────────────────────
    elif vuln_type == "jwt":
        if auth:
            return _clamp_confidence(True, min(90 + dc_bonus, 99),
                                     f"JWT/token na resposta: {auth[0]}")
        if diff_changed and diff_conf >= 15:
            return _clamp_confidence(True, 75 + dc_bonus,
                                     f"Comportamento diferente com JWT modificado: {diff_note}")
        if status.startswith("2"):
            return _clamp_confidence(False, 40,
                                     "HTTP 200 mas sem JWT no response — confirmar manualmente")
        return _clamp_confidence(False, 20, f"HTTP {status} sem evidência JWT")

    # ── AWS Secrets ───────────────────────────────────────────────
    elif vuln_type == "secret_aws":
        aws_key_re = r'(?:AKIA|ASIA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}'
        aws_secret_re = r'[a-zA-Z0-9+/]{40}'
        if re.search(aws_key_re, resp_body or ""):
            return _clamp_confidence(True, 98, "AWS Access Key ID exposto")
        if re.search(aws_secret_re, resp_body or "") and re.search(aws_key_re, resp_body or ""):
            return _clamp_confidence(True, 99, "AWS Key + Secret expostos")
        for pat in p.get("patterns", []):
            try:
                if re.search(pat, resp_body or "", re.IGNORECASE):
                    return _clamp_confidence(True, 90, f"Padrão AWS: '{pat}'")
            except Exception:
                pass
        return _clamp_confidence(False, 20, "Sem credenciais AWS identificadas")

    # ── Generic ──────────────────────────────────────────────────
    else:
        # v3: muito mais conservador — evitar FP por HTTP 200 genérico
        if auth:
            return _clamp_confidence(True, 82, f"Auth evidence: {auth[0]}")
        if diff_changed and diff_conf >= 15:
            return _clamp_confidence(True, 65 + dc_bonus,
                                     f"Comportamento alterado: {diff_note}")
        # HTTP 200 sem diff → não confirmar (era maior fonte de FP)
        if status in ("401", "403"):
            return _clamp_confidence(False, 40, f"Endpoint existe (HTTP {status}) — sem bypass")
        if status.startswith("2") and diff_changed:
            return _clamp_confidence(False, 45,
                                     f"HTTP {status} mas sem evidência suficiente — revisar manualmente")
        return _clamp_confidence(False, 20, f"HTTP {status} sem evidência de vulnerabilidade")


def _clamp_confidence(confirmed, confidence, note=""):
    """
    Garante que achados 'confirmados' com confiança baixa sejam rebaixados.
    Aceita 2 ou 3 argumentos para compatibilidade com chamadas tuple-style.
    """
    if confirmed and confidence < MIN_CONFIRM_CONFIDENCE:
        confirmed = False
    return confirmed, min(int(confidence), 99), note

# ══════════════════════════════════════════════════════════════════
# CONFIRMAÇÃO POR FONTE
# ══════════════════════════════════════════════════════════════════

def confirm_nuclei(outdir):
    """Confirma achados Nuclei — curl sempre reconstruído de método+URL+body.
    SSRF/RCE/SSTI não confirmados por conteúdo recebem tentativa de confirmação
    OOB (interactsh) quando habilitado via INTERACTSH_SERVER."""
    nuclei_file = os.path.join(outdir, "raw", "nuclei.json")
    confirmations = []
    if not os.path.exists(nuclei_file):
        return confirmations

    profile   = os.environ.get("PROFILE", "lab")
    # OAuth: refresh inicial (se configurado) antes do loop
    _refresh_oauth_safe()
    oob       = OOBSession(out_dir=os.path.join(outdir, "raw")) if _OOB_AVAILABLE else None
    oob_ready = bool(oob and oob.start())
    if oob_ready:
        print(f"  [OOB] interactsh ativo ({oob.domain}) — confirmação cega habilitada")
    oob_pending = []   # [(idx_em_confirmations, token, oob_url)]
    # Cap por scan: limita o nº de findings que disparam OOB. Em scans com
    # 200+ findings SSRF/RCE/SSTI, isso evita stress no alvo. Default 25.
    OOB_MAX = max(0, int(os.environ.get("OOB_MAX_PAYLOADS", "25")))
    oob_fired_count = 0   # incrementa por finding disparado, não por payload

    with open(nuclei_file, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                data        = json.loads(line)
                severity    = data.get("info", {}).get("severity", "info")
                if severity.lower() not in ("critical", "high", "medium"):
                    continue
                template_id = data.get("template-id", "unknown")
                url         = data.get("matched-at", "")
                name        = data.get("info", {}).get("name", "")
                tags        = " ".join(data.get("info", {}).get("tags", []) or [])
                vuln_type   = classify_vuln(template_id, name, tags)

                # Reconstrói o curl SEMPRE a partir de método+URL+body, citados
                # com shlex.quote. O curl-command do Nuclei é deliberadamente
                # ignorado: ele deriva de respostas potencialmente hostis do alvo
                # e usá-lo direto — mesmo filtrado por denylist — abre injeção de
                # comando no shell do operador (o denylist não cobre & isolado,
                # | único, (), \, globs, redirecionamentos sem espaço, etc.).
                raw_req = data.get("request", "") or ""
                first_line = raw_req.split("\n")[0].strip() if raw_req else ""
                method = "GET"
                if first_line:
                    parts = first_line.split()
                    if parts and parts[0] in ("GET","POST","PUT","PATCH","DELETE","HEAD","OPTIONS"):
                        method = parts[0]
                # Extrair body do request raw se existir
                req_body = ""
                if "\r\n\r\n" in raw_req:
                    req_body = raw_req.split("\r\n\r\n", 1)[1].strip()
                elif "\n\n" in raw_req:
                    req_body = raw_req.split("\n\n", 1)[1].strip()
                curl_cmd = f"curl -sk -L -X {shlex.quote(method)} --max-time 15 {shlex.quote(url)}"
                if req_body and method in ("POST", "PUT", "PATCH"):
                    curl_cmd += f" --data {shlex.quote(req_body[:500])}"

                clean_curl, safe_curl = build_safe_baseline(curl_cmd, url)
                # OAuth: injeta Authorization Bearer no curl reconstruído
                clean_curl = _apply_oauth(clean_curl)
                safe_curl  = _apply_oauth(safe_curl)
                exec_cmd = (clean_curl
                            + " -D - -w '\\n===Stiglitz_STATUS:%{http_code}==='")

                print(f"  [Nuclei] {template_id} ({vuln_type}) → {url[:55]}...")
                raw_out, err = run_cmd(exec_cmd, timeout=20)
                # Retry em 401 com token refrescado (uma única vez)
                if err is None and "===Stiglitz_STATUS:401===" in raw_out and _refresh_oauth_safe():
                    clean_curl = _apply_oauth(clean_curl)
                    exec_cmd = clean_curl + " -D - -w '\\n===Stiglitz_STATUS:%{http_code}==='"
                    raw_out, err = run_cmd(exec_cmd, timeout=20)
                if err == "TIMEOUT":
                    confirmations.append(
                        _timeout_entry(template_id, url, severity, vuln_type,
                                       curl_cmd, clean_curl, "nuclei"))
                    continue

                status, resp_headers, resp_body = parse_http_response(raw_out)

                # Baseline com payload seguro
                base_exec = (safe_curl
                             + " -D - -w '\\n===Stiglitz_STATUS:%{http_code}==='")
                base_out, _ = run_cmd(base_exec, timeout=15, retries=1)
                _, _, base_body = parse_http_response(base_out or "")

                diff_changed, diff_conf, diff_note = response_diff(
                    normalize(base_body), normalize(resp_body))
                auth_ev = check_auth_evidence(resp_headers, resp_body)

                # Testar métodos adicionais
                method_results = {}
                for m in ["GET", "POST"]:
                    o, e = run_cmd(
                        f"curl -sk -L -X {m} --max-time 10 {shlex.quote(url)}"
                        f" -D - -w '\\n===Stiglitz_STATUS:%{{http_code}}==='",
                        timeout=12, retries=1)
                    if not e and o:
                        ms, mh, mb = parse_http_response(o)
                        if ms not in ("???", "000", "ERR"):
                            method_results[m] = (ms, mh, mb)

                # v3: double_check para critical E high
                dc = None
                if severity.lower() in ("critical", "high"):
                    ok, note = double_check(exec_cmd)
                    dc = (ok, note)
                    print(f"  [⟳] {note}")

                confirmed, confidence, poc_note = validate(
                    vuln_type, url, resp_body, resp_headers, status,
                    method_results=method_results,
                    diff_changed=diff_changed, diff_conf=diff_conf,
                    diff_note=diff_note, auth_ev=auth_ev, dc_result=dc)

                state = "CONFIRMADO" if confirmed else "NÃO CONFIRMADO"
                print(f"  [{state}] HTTP {status} | {confidence}% | {poc_note}")
                confirmations.append(_entry(
                    template_id, url, severity, vuln_type,
                    confirmed, confidence, poc_note, status,
                    resp_headers, resp_body, curl_cmd, clean_curl, safe_curl,
                    diff_changed, diff_note, method_results, auth_ev, dc, "nuclei"))

                # OOB: SSRF/RCE/SSTI não confirmados por conteúdo recebem
                # payload(s) únicos; o callback (assíncrono) é resolvido após
                # o loop. Para SSTI, vários payloads são disparados (uma engine
                # por payload); qualquer callback confirma o finding.
                # Gate de escopo: só injeta em hosts em escopo (evita disparar
                # payloads em URLs externas que vazaram para o output do scan).
                # Cap OOB_MAX_PAYLOADS: limita findings disparados por scan.
                if (oob_ready and not confirmed
                        and vuln_type in ("ssrf", "rce", "ssti")
                        and _url_in_scope(url)
                        and oob_fired_count < OOB_MAX):
                    token, oob_url = oob.new_payload(vuln_type)
                    cmds = inject_oob_url(url, oob_url, vuln_type, profile)
                    if cmds:
                        for inj in cmds:
                            run_cmd(inj, timeout=12, retries=1)
                        oob_pending.append((len(confirmations) - 1, token, oob_url))
                        oob_fired_count += 1
                        if oob_fired_count == OOB_MAX:
                            print(f"  [OOB] cap atingido ({OOB_MAX} findings) — próximos não injetam")

            except Exception as e:
                print(f"  [!] Nuclei parse error: {e}")

    # ── Resolução OOB: espera a janela de callback e eleva os confirmados ──
    if oob_ready and oob_pending:
        wait_s = int(os.environ.get("OOB_WAIT", "20"))
        print(f"  [OOB] Aguardando callbacks por {wait_s}s ({len(oob_pending)} payload(s))...")
        time.sleep(wait_s)
        # Cap de bytes da evidência OOB anexada (raw-request do callback).
        # Default 800 — suficiente pra header+body curto, sem inflar relatório.
        ev_cap = max(120, int(os.environ.get("OOB_EVIDENCE_BYTES", "800")))
        for idx, token, oob_url in oob_pending:
            hits = oob.matches(token)
            if not hits:
                continue
            proto = str(hits[0].get("protocol", "dns")).upper()
            src   = hits[0].get("remote-address", "?")
            entry = confirmations[idx]
            entry["confirmed"]     = True
            entry["confidence"]    = 98
            entry["oob_confirmed"] = True
            entry["poc_note"]      = f"OOB confirmado: callback {proto} de {src}"
            entry["response_snippet"] += (
                f"\n\n--- OOB CALLBACK ({proto}) via {oob_url} ---\n"
                + str(hits[0].get("raw-request", "(sem raw-request)"))[:ev_cap])
            print(f"  [CONFIRMADO-OOB] {entry['template_id']} ← {proto} de {src}")
    if oob:
        oob.stop()

    return confirmations


def confirm_zap(outdir):
    """Confirma alertas ZAP extraindo requests do XML."""
    xml_file  = os.path.join(outdir, "raw", "zap_evidencias.xml")
    json_file = os.path.join(outdir, "raw", "zap_alerts.json")
    confirmations = []

    # OAuth: refresh inicial (se configurado) antes do loop
    _refresh_oauth_safe()

    # URLs a ignorar — artefatos de redirect de autenticação
    SKIP_PATTERNS = [
        r'/securityRealm/', r'moLogin\?from=', r'j_spring_security',
        r'login\?from=%2F', r'login\?next=%2F', r'\?from=%2F',
        r'oauth/authorize\?', r'saml/login\?',
        r'/login$', r'/signin$',   # páginas de login puras geram FP em security headers
    ]
    def url_ok(u):
        return not any(re.search(p, u or "", re.IGNORECASE) for p in SKIP_PATTERNS)

    # Metadados de alerta do JSON
    alert_meta = {}
    try:
        zap_data = json.load(open(json_file, encoding="utf-8"))
        sev_map = {"high": "high", "medium": "medium", "low": "low", "informational": "info"}
        for a in zap_data.get("alerts", []):
            name = a.get("name", "")
            sev  = sev_map.get(a.get("risk", "").lower(), "info")
            if sev not in ("high", "medium", "critical"):
                continue
            alert_meta[name] = {
                "severity":    sev,
                "description": a.get("description", ""),
                "solution":    a.get("solution", ""),
                "cweid":       a.get("cweid", ""),
            }
    except Exception:
        pass

    if not os.path.exists(xml_file):
        return confirmations
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
    except Exception:
        return confirmations

    seen = set()
    for alert in root.iter("alertitem"):
        try:
            name     = (alert.findtext("alert") or alert.findtext("name") or "").strip()
            risk     = (alert.findtext("riskdesc") or alert.findtext("risk") or "").strip()
            url      = (alert.findtext("uri")      or alert.findtext("url")  or "").strip()
            req      = (alert.findtext("requestheader") or "").strip()
            req_body = (alert.findtext("requestbody")   or "").strip()

            # Filtro de severidade
            sev = "info"
            risk_low = risk.lower()
            if "high" in risk_low or "critical" in risk_low:
                sev = "high"
            elif "medium" in risk_low:
                sev = "medium"
            if sev not in ("high", "medium"):
                continue
            if not url_ok(url):
                continue

            key = f"{name}::{url}"
            if key in seen:
                continue
            seen.add(key)

            vuln_type = classify_vuln(name, name, "")
            meta      = alert_meta.get(name, {})

            curl_cmd  = _zap_request_to_curl(url, req, req_body)
            # OAuth: injeta Authorization Bearer (substituindo qualquer header já presente do XML)
            curl_cmd  = _apply_oauth(curl_cmd)
            exec_cmd  = curl_cmd + " -D - -w '\\n===Stiglitz_STATUS:%{http_code}==='"
            safe_curl = re.sub(r'^curl\s+', 'curl -sk -L --max-time 15 ', curl_cmd)

            print(f"  [ZAP]    {name[:45]} → {url[:45]}...")
            raw_out, err = run_cmd(exec_cmd, timeout=20)
            # Retry em 401 com token refrescado (uma única vez)
            if err is None and "===Stiglitz_STATUS:401===" in raw_out and _refresh_oauth_safe():
                curl_cmd = _apply_oauth(curl_cmd)
                exec_cmd = curl_cmd + " -D - -w '\\n===Stiglitz_STATUS:%{http_code}==='"
                raw_out, err = run_cmd(exec_cmd, timeout=20)
            if err == "TIMEOUT":
                confirmations.append(
                    _timeout_entry(name, url, sev, vuln_type, curl_cmd, curl_cmd, "zap"))
                continue

            status, resp_headers, resp_body = parse_http_response(raw_out)

            # Baseline GET limpo
            base_out, _ = run_cmd(
                f"curl -sk -L --max-time 15 '{url}'"
                f" -D - -w '\\n===Stiglitz_STATUS:%{{http_code}}==='",
                timeout=15, retries=1)
            _, _, base_body = parse_http_response(base_out or "")

            diff_changed, diff_conf, diff_note = response_diff(
                normalize(base_body), normalize(resp_body))
            auth_ev = check_auth_evidence(resp_headers, resp_body)

            confirmed, confidence, poc_note = validate(
                vuln_type, url, resp_body, resp_headers, status,
                diff_changed=diff_changed, diff_conf=diff_conf,
                diff_note=diff_note, auth_ev=auth_ev)

            state = "CONFIRMADO" if confirmed else "NÃO CONFIRMADO"
            print(f"  [{state}] HTTP {status} | {confidence}% | {poc_note}")
            confirmations.append(_entry(
                name, url, sev, vuln_type,
                confirmed, confidence, poc_note, status,
                resp_headers, resp_body, curl_cmd, curl_cmd, safe_curl,
                diff_changed, diff_note, {}, auth_ev, None, "zap"))

        except Exception as e:
            print(f"  [!] ZAP alert error: {e}")

    return confirmations


def _zap_request_to_curl(url, req_headers, req_body):
    """
    Reconstrói curl a partir dos headers de request do ZAP.
    v3: preserva cookies e Authorization header (contexto de autenticação).
    """
    method = "GET"
    headers_to_add = []
    if req_headers:
        lines = req_headers.split("\n")
        if lines:
            first = lines[0].strip()
            for verb in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"):
                if first.startswith(verb + " "):
                    method = verb
                    break
        for line in lines[1:]:
            line = line.strip()
            if not line:
                continue
            line_lower = line.lower()
            # Ignorar headers que curl gerencia ou que causam problemas
            if line_lower.startswith("host:"):
                continue
            if line_lower.startswith("content-length:"):
                continue
            if line_lower.startswith("transfer-encoding:"):
                continue
            if line_lower.startswith("connection:"):
                continue
            # Manter cookies e auth (importantes para contexto).
            # Citado com shlex.quote — o header vem do alvo (não confiável).
            headers_to_add.append(f"-H {shlex.quote(line)}")

    cmd = f"curl -sk -L -X {shlex.quote(method)} --max-time 15"
    if headers_to_add:
        # Limit para 12 headers (era 8) para preservar mais contexto
        cmd += " " + " ".join(headers_to_add[:12])
    if req_body and method in ("POST", "PUT", "PATCH"):
        cmd += f" --data {shlex.quote(req_body[:1000])}"
    cmd += f" {shlex.quote(url)}"
    return cmd


def confirm_tls(outdir, domain):
    """Confirma issues TLS usando openssl + curl."""
    tls_file = os.path.join(outdir, "raw", "testssl.json")
    confirmations = []
    if not os.path.exists(tls_file):
        return confirmations

    try:
        tls_data = json.load(open(tls_file, encoding="utf-8"))
        findings = tls_data if isinstance(tls_data, list) else tls_data.get("findings", [])
    except Exception:
        return confirmations

    # IDs do testssl que são metadados/operacionais, não vulnerabilidades —
    # nunca devem ser marcados como "exploit confirmado".
    NON_VULN_TLS_IDS = {"scantime", "service", "engine_problem", "pre_128cipher",
                        "clientsimulation", "grease", "ipv4_in_san", "drown_hint"}
    seen = set()
    for item in findings:
        sev = (item.get("severity") or "").lower()
        if sev not in ("critical", "high", "medium", "warn"):
            continue
        finding_id = item.get("id", "")
        label      = item.get("finding", "")[:80]
        # Pular metadados do testssl e erros operacionais (ex: "Scan interrupted")
        if finding_id.lower() in NON_VULN_TLS_IDS or "scan interrupt" in label.lower():
            continue
        key = f"tls::{finding_id}"
        if key in seen:
            continue
        seen.add(key)

        url = f"https://{domain}"
        print(f"  [TLS]    {finding_id}: {label[:50]}...")

        # Verificar conectividade básica
        raw_out, err = run_cmd(
            f"curl -sk --max-time 15 -D - -w '\\n===Stiglitz_STATUS:%{{http_code}}===' {shlex.quote(url)}",
            timeout=20, retries=1)
        if err == "TIMEOUT":
            confirmations.append(
                _timeout_entry(finding_id, url, "medium", "tls", "", "", "tls"))
            continue

        status, resp_headers, resp_body = parse_http_response(raw_out)

        # Default: sem reverificação ativa, o finding é "verificado pelo testssl"
        # (categoria hardening), não um exploit independentemente confirmado.
        # Endpoint precisa ao menos estar acessível para sustentar o finding.
        reachable  = status.startswith("2") or status in ("301", "302", "403")
        confirmed  = reachable
        confidence = 75 if reachable else 20
        poc_note   = (f"{label} (verificado via testssl; conectividade {status})"
                      if reachable else f"{label} — endpoint inacessível (HTTP {status})")

        # Verificações específicas por tipo
        if "hsts" in finding_id.lower():
            has_hsts = "strict-transport-security" in resp_headers.lower()
            confirmed  = not has_hsts
            confidence = 95 if confirmed else 15
            poc_note   = ("HSTS ausente — confirmado via curl -I"
                          if confirmed else "HSTS presente — issue corrigida ou FP")

        elif any(x in finding_id.lower() for x in ["certificate", "cert", "expired", "selfsigned"]):
            cert_out, _ = run_shell_pipe(
                f"echo | openssl s_client -connect {shlex.quote(domain)}:443 -servername {shlex.quote(domain)} 2>/dev/null"
                f" | openssl x509 -noout -dates 2>/dev/null",
                timeout=12, retries=1)
            if cert_out.strip():
                confirmed  = True
                confidence = 90
                poc_note   = f"Cert info: {cert_out.strip()[:120]}"
            else:
                confirmed  = False
                confidence = 25
                poc_note   = "Não foi possível obter info do certificado"

        elif any(x in finding_id.lower() for x in ["sslv2", "sslv3", "tls1_0", "tls10",
                                                     "rc4", "des", "3des", "export",
                                                     "null_cipher"]):
            # Verificar protocolo/cipher via openssl
            proto_map = {
                "sslv2": "-ssl2", "sslv3": "-ssl3",
                "tls1_0": "-tls1", "tls10": "-tls1",
            }
            proto_flag = next((v for k, v in proto_map.items()
                               if k in finding_id.lower()), "")
            if proto_flag:
                check_out, _ = run_shell_pipe(
                    f"echo | openssl s_client -connect {shlex.quote(domain)}:443 {proto_flag} 2>&1",
                    timeout=10, retries=1)
                if "handshake failure" in check_out.lower():
                    confirmed  = False
                    confidence = 20
                    poc_note   = f"Protocolo {proto_flag} não aceito — possível FP do testssl"
                else:
                    confirmed  = True
                    confidence = 93
                    poc_note   = f"Protocolo legado {proto_flag} aceito pelo servidor"

        elif not (status.startswith("2") or status in ("301", "302", "403")):
            # Endpoint inacessível — não confirmar
            confirmed  = False
            confidence = 20
            poc_note   = f"Endpoint inacessível (HTTP {status}) — não foi possível confirmar"

        confirmed, confidence = confirmed, min(confidence, 99)
        state = "CONFIRMADO" if confirmed else "NÃO CONFIRMADO"
        print(f"  [{state}] {confidence}% | {poc_note}")

        curl_cmd = f"curl -sk -D - -w '\\n===Stiglitz_STATUS:%{{http_code}}===' {shlex.quote(url)}"
        confirmations.append(_entry(
            finding_id, url, "medium", "tls",
            confirmed, confidence, poc_note, status,
            resp_headers, resp_body[:500], curl_cmd, curl_cmd, curl_cmd,
            False, "", {}, [], None, "tls"))

    return confirmations


def confirm_email(outdir, domain):
    """Confirma issues de email via re-query DNS."""
    email_file = os.path.join(outdir, "raw", "email_security.json")
    confirmations = []
    if not os.path.exists(email_file):
        return confirmations

    try:
        email_data = json.load(open(email_file, encoding="utf-8"))
    except Exception:
        return confirmations

    issues = email_data.get("issues", [])
    if not issues:
        return confirmations

    print(f"  [Email]  Re-verificando {len(issues)} issue(s) de email via DNS...")
    recheck = {}

    # SPF — argv-list direto; stderr é capturado pelo run_cmd, sem 2>/dev/null
    spf_out, _ = run_cmd(["dig", "TXT", domain, "+short"], timeout=10, retries=1)
    recheck["spf"] = "v=spf1" in spf_out.lower()

    # DMARC
    dmarc_out, _ = run_cmd(["dig", "TXT", f"_dmarc.{domain}", "+short"], timeout=10, retries=1)
    recheck["dmarc"] = "v=dmarc1" in dmarc_out.lower()

    # DKIM — seletores mais comuns
    dkim_found = False
    for sel in ["default", "google", "mail", "selector1", "selector2",
                 "k1", "smtp", "dkim", "email", "s1", "s2"]:
        dkim_out, _ = run_cmd(
            ["dig", "TXT", f"{sel}._domainkey.{domain}", "+short"],
            timeout=5, retries=1)
        if "v=dkim1" in dkim_out.lower():
            dkim_found = True
            break
    recheck["dkim"] = dkim_found

    label_map = {"spf": "SPF", "dmarc": "DMARC", "dkim": "DKIM"}
    for issue in issues:
        itype = issue.get("type", "").lower()
        for key in ["spf", "dmarc", "dkim"]:
            if key in itype:
                present    = recheck.get(key, False)
                confirmed  = not present   # ausente no DNS = confirmado
                confidence = 95 if confirmed else 20
                note = (f"{label_map.get(key, key)} ausente — confirmado via dig"
                        if confirmed
                        else f"{label_map.get(key, key)} presente — issue pode ter sido corrigida")
                state = "CONFIRMADO" if confirmed else "NÃO CONFIRMADO"
                print(f"  [{state}] {label_map.get(key, key)}: {note}")
                curl_cmd = f"dig TXT {'_dmarc.' if key == 'dmarc' else ''}{domain} +short"
                confirmations.append(_entry(
                    f"email-{key}", f"dns://{domain}", "medium", "email",
                    confirmed, confidence, note, "DNS", "", "",
                    curl_cmd, curl_cmd, curl_cmd,
                    False, "", {}, [], None, "email"))
                break

    return confirmations

# ══════════════════════════════════════════════════════════════════
# HELPER ENTRY BUILDERS
# ══════════════════════════════════════════════════════════════════

def _entry(tid, url, sev, vtype, confirmed, confidence, poc_note, status,
           resp_headers, resp_body, curl_cmd, curl_repr, safe_curl,
           diff_changed, diff_note, method_results, auth_ev, dc, source):
    ev = ""
    if resp_headers:
        ev += f"--- RESPONSE HEADERS ---\n{resp_headers}\n\n"
    if resp_body:
        ev += f"--- RESPONSE BODY ---\n{resp_body}"
    return {
        "template_id":       tid,
        "url":               url,
        "severity":          sev,
        "vuln_type":         vtype,
        "source":            source,
        "confirmed":         confirmed,
        "confidence":        confidence,
        "poc_note":          poc_note,
        "http_status":       status,
        "response_headers":  resp_headers,
        "response_body":     resp_body,
        "response_snippet":  ev,
        "curl_command":      curl_cmd,
        "curl_reproducible": curl_repr,
        "safe_baseline_curl": safe_curl,
        "diff_changed":      diff_changed,
        "diff_note":         diff_note,
        "methods_tested":    {m: r[0] for m, r in (method_results or {}).items()},
        "auth_evidence":     auth_ev or [],
        "double_checked":    dc is not None,
        "oob_confirmed":     False,
        "timestamp":         datetime.now(timezone.utc).isoformat(),
    }


def _timeout_entry(tid, url, sev, vtype, curl_cmd, curl_repr, source):
    return {
        "template_id":       tid,
        "url":               url,
        "severity":          sev,
        "vuln_type":         vtype,
        "source":            source,
        "confirmed":         False,
        "confidence":        0,
        "poc_note":          "Timeout após 2 tentativas",
        "http_status":       "TIMEOUT",
        "response_headers":  "",
        "response_body":     "",
        "response_snippet":  "",
        "curl_command":      curl_cmd,
        "curl_reproducible": curl_repr,
        "safe_baseline_curl": "",
        "diff_changed":      False,
        "diff_note":         "",
        "methods_tested":    {},
        "auth_evidence":     [],
        "double_checked":    False,
        "timestamp":         datetime.now(timezone.utc).isoformat(),
    }

# ══════════════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════════════

def run(outdir):
    domain = os.environ.get(
        "DOMAIN",
        outdir.split("scan_")[-1].split("_")[0] if "scan_" in outdir else "")
    all_confirmations = []

    print(f"\n  [PoC v3] Confirmação ativa — todas as fontes")
    print(f"  {'─' * 55}")

    # 1. Nuclei
    nuclei = confirm_nuclei(outdir)
    all_confirmations.extend(nuclei)
    print(f"  [Nuclei] {sum(1 for c in nuclei if c['confirmed'])}/{len(nuclei)} confirmados")

    # 2. ZAP
    zap = confirm_zap(outdir)
    all_confirmations.extend(zap)
    print(f"  [ZAP]    {sum(1 for c in zap if c['confirmed'])}/{len(zap)} confirmados")

    # 3. TLS
    if domain:
        tls = confirm_tls(outdir, domain)
        all_confirmations.extend(tls)
        print(f"  [TLS]    {sum(1 for c in tls if c['confirmed'])}/{len(tls)} confirmados")

    # 4. Email
    if domain:
        email = confirm_email(outdir, domain)
        all_confirmations.extend(email)
        print(f"  [Email]  {sum(1 for c in email if c['confirmed'])}/{len(email)} confirmados")

    confirm_file = os.path.join(outdir, "raw", "exploit_confirmations.json")
    with open(confirm_file, "w", encoding="utf-8") as f:
        json.dump(all_confirmations, f, ensure_ascii=False, indent=2)

    total     = len(all_confirmations)
    confirmed = sum(1 for c in all_confirmations if c["confirmed"])
    fp_reduction = total - confirmed
    print(f"\n  Resultado total: {confirmed}/{total} confirmados | "
          f"{fp_reduction} filtrados como não confirmados")
    return confirmed


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Uso: python3 lib/poc_validator.py <outdir>")
        sys.exit(1)
    run(sys.argv[1])

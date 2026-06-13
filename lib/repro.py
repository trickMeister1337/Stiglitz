#!/usr/bin/env python3
"""
repro.py — gera o bloco "How to Reproduce / Proof" por finding (item 6 fintech).

Núcleo puro (sem rede): decide se o finding entra (passes_gate), extrai/monta o
comando de reprodução (captura real do curl/HTTP request, senão template por classe),
sanitiza segredos vivos e PAN/PII por padrão, descreve o resultado esperado (prova) e
monta o HTML do painel. Texto do bloco em INGLÊS (deliverable); console/comentários PT-BR.

Uso (debug): python3 lib/repro.py <finding.json>
"""
import os
import re
import sys
import json
import html

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pan_scanner
import pii_detect


# ── Gate de alcance ───────────────────────────────────────────────────────────
_HIGH_SEVS = {"critical", "high"}
_CONFIRMED_CATS = {"exploit", "verified"}


def passes_gate(finding):
    """True se o finding deve receber o bloco: High/Critical OU confirmado."""
    sev = str(finding.get("severity", "")).strip().lower()
    if sev in _HIGH_SEVS:
        return True
    if str(finding.get("confirmed_category", "")).strip().lower() in _CONFIRMED_CATS:
        return True
    conf = finding.get("confirmed")
    if isinstance(conf, str):
        return conf.strip().lower() in {"true", "1", "yes", "confirmed"}
    return bool(conf)


# ── Sanitização ───────────────────────────────────────────────────────────────
# Política: redige segredos vivos (auth headers de qualquer esquema, cookies em
# header e em flags do curl, tokens em querystring e em corpo JSON) e mascara PAN
# (Luhn, tolerante a separadores) + CPF/CNPJ/email. Objetivo: nenhuma credencial
# viva nem PAN no deliverable (PCI/CDE). raw=True (em build_repro) pula tudo.
# Limitação conhecida: preferimos over-redact; formatos não cobertos (ex.: segredo
# embutido em corpo binário) podem escapar.

# Parâmetros sensíveis em querystring/corpo JSON (nome → valor redigido).
_SECRET_PARAMS = (
    "access_token", "refresh_token", "id_token", "client_secret", "client_id",
    "secret", "api_key", "apikey", "password", "passwd", "pwd", "auth", "jwt",
    "sid", "sessionid", "session", "signature", "code", "token")
_PARAM_ALT = "|".join(_SECRET_PARAMS)

# Authorization: Bearer (o `%` cobre tokens opacos url-encodados; `_` já incluso).
_BEARER_RE = re.compile(r"(?i)(authorization\s*:\s*bearer\s+)([A-Za-z0-9._~+/%\-]+=*)")
# Authorization com esquemas não-Bearer (Basic/Digest/Negotiate/NTLM).
_AUTH_OTHER_RE = re.compile(
    r"(?i)(authorization\s*:\s*(?:basic|digest|negotiate|ntlm)\s+)([^\s'\"\r\n]+)")
# Headers de segredo comuns em fintech/API (linha própria de header HTTP cru;
# valor até o fim da linha — cobre valor entre aspas, ex.: X-API-Key: "sk_...").
_SECRET_HDR_RE = re.compile(
    r"(?im)^((?:x-api-key|x-auth-token|api-key|apikey|x-amz-security-token|"
    r"proxy-authorization)\s*:\s*)([^\r\n]+)")
# Cookie em header HTTP cru (linha própria; valor até EOL — cobre Set-Cookie: jwt="...").
_COOKIE_RE = re.compile(r"(?im)^((?:set-)?cookie\s*:\s*)([^\r\n]+)")
# Headers sensíveis passados via flag do curl (-H/--header '<hdr>: <valor>'): o valor
# termina na aspa de fechamento (não engole o resto da linha/URL).
_CURL_HDR_RE = re.compile(
    r"(?i)((?:-H|--header)\s+['\"]\s*(?:set-cookie|cookie|x-api-key|x-auth-token|"
    r"api-key|apikey|proxy-authorization|x-amz-security-token)\s*:\s*)([^'\"]*)")
# Cookie em flags do curl (-b / --cookie).
_COOKIE_FLAG_RE = re.compile(r"(?i)(\s(?:-b|--cookie)\s+)('[^']*'|\"[^\"]*\"|[^\s]+)")
# Tokens em querystring.
_QS_TOKEN_RE = re.compile(r"(?i)\b(" + _PARAM_ALT + r")=([^&\s'\"]+)")
# Tokens em corpo JSON.
_JSON_TOKEN_RE = re.compile(r"(?i)(\"(?:" + _PARAM_ALT + r")\"\s*:\s*\")([^\"]+)(\")")
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_CPF_RE = re.compile(r"\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b")
_CNPJ_RE = re.compile(r"\b\d{2}\.?\d{3}\.?\d{3}/?\d{4}-?\d{2}\b")
# PAN tolerante a separadores (espaço/hífen/ponto entre grupos de dígitos).
_PAN_SEP_RE = re.compile(r"\b\d(?:[ \-.]?\d){12,18}\b")


def _mask_pans(text):
    hit = {"v": False}

    def _repl(m):
        raw = m.group(0)
        digits = re.sub(r"[ \-.]", "", raw)
        if 13 <= len(digits) <= 19 and pan_scanner.luhn(digits):
            hit["v"] = True
            return pan_scanner.mask(digits)
        return raw

    return _PAN_SEP_RE.sub(_repl, text), hit["v"]


def sanitize_text(text):
    """Redige segredos vivos e mascara PAN/PII. Retorna (texto, alterado?)."""
    if not text:
        return text, False
    changed = False
    for rx, repl in ((_BEARER_RE, r"\1<TOKEN_A>"),
                     (_AUTH_OTHER_RE, r"\1<TOKEN_A>"),
                     (_CURL_HDR_RE, r"\1<REDACTED>"),
                     (_SECRET_HDR_RE, r"\1<TOKEN_A>"),
                     (_COOKIE_RE, r"\1<SESSION>"),
                     (_COOKIE_FLAG_RE, r"\1<SESSION>"),
                     (_QS_TOKEN_RE, r"\1=<REDACTED>"),
                     (_JSON_TOKEN_RE, r"\1<REDACTED>\3")):
        new = rx.sub(repl, text)
        if new != text:
            changed = True
            text = new
    text, pan_changed = _mask_pans(text)
    changed = changed or pan_changed

    def _cpf_repl(m):
        if pii_detect.valid_cpf(m.group(0)):
            _cpf_repl.hit = True
            return "***.***.***-**"
        return m.group(0)
    _cpf_repl.hit = False
    text = _CPF_RE.sub(_cpf_repl, text)

    def _cnpj_repl(m):
        if pii_detect.valid_cnpj(m.group(0)):
            _cnpj_repl.hit = True
            return "**.***.***/****-**"
        return m.group(0)
    _cnpj_repl.hit = False
    text = _CNPJ_RE.sub(_cnpj_repl, text)

    def _email_repl(m):
        masked = pii_detect.mask_email(m.group(0))
        if masked != m.group(0):
            _email_repl.hit = True
        return masked
    _email_repl.hit = False
    text = _EMAIL_RE.sub(_email_repl, text)

    changed = changed or _cpf_repl.hit or _cnpj_repl.hit or _email_repl.hit
    return text, changed


def sanitize_command(text):
    """Mesma política de sanitize_text (alias semântico para comandos)."""
    return sanitize_text(text)


# ── Captura do comando real ───────────────────────────────────────────────────
_CURL_FIELDS = ("curl_command", "curl_reproducible", "curl-command", "curl")
# Sentinela "--- HTTP REQUEST ---": formato com que o relatório guarda a requisição
# capturada na evidence (ZAP/nuclei).
_REQ_BLOCK_RE = re.compile(
    r"---\s*HTTP REQUEST\s*---\s*\n(.*?)(?=\n---|\Z)", re.DOTALL | re.IGNORECASE)


def _command_from_curl_field(finding):
    """Primeiro campo de curl não-vazio do finding, ou None."""
    for k in _CURL_FIELDS:
        v = finding.get(k)
        if v and str(v).strip():
            return str(v).strip()
    return None


def _shq(s):
    """Escapa aspas simples para uso seguro dentro de '...' no shell."""
    return s.replace("'", "'\\''")


def _curl_from_request_block(evidence, url=""):
    """Monta um curl a partir do bloco '--- HTTP REQUEST ---' da evidence, ou None."""
    m = _REQ_BLOCK_RE.search(evidence or "")
    if not m:
        return None
    lines = m.group(1).strip().splitlines()
    if not lines:
        return None
    parts = lines[0].split()
    method = parts[0] if parts else "GET"
    path = parts[1] if len(parts) > 1 else "/"
    host = ""
    headers = []
    body_lines = []
    in_body = False
    for ln in lines[1:]:
        if not in_body and ln.strip() == "":
            in_body = True
            continue
        if in_body:
            body_lines.append(ln)
            continue
        if ":" in ln:
            hk, _, hv = ln.partition(":")
            if hk.strip().lower() == "host":
                host = hv.strip()
            else:
                headers.append((hk.strip(), hv.strip()))
    # path em absolute-form (ex.: "GET http://host/p HTTP/1.1") — ZAP/proxies usam isso.
    if path.startswith(("http://", "https://")):
        full_url = url or path
    else:
        full_url = url or (("https://" + host + path) if host else path)
    cmd = "curl -i -s -X %s '%s'" % (method, _shq(full_url))
    for hk, hv in headers:
        cmd += " \\\n  -H '%s: %s'" % (_shq(hk), _shq(hv))
    body = "\n".join(body_lines).strip()
    if body:
        cmd += " \\\n  --data '%s'" % _shq(body)
    return cmd


# ── Classificação e templates de fallback ─────────────────────────────────────
def _classify(finding):
    """Deriva a classe de reprodução a partir de cve/vuln_type/name/source/template."""
    blob = " ".join(str(finding.get(k, "")) for k in (
        "cve", "vuln_type", "type", "name", "other", "id", "source",
        "template_id")).lower()
    if "nosql" in blob:
        return "generic"
    if "sql" in blob:
        return "sqli"
    if "bola" in blob or "idor" in blob or "cwe-639" in blob:
        return "bola_idor"
    if "bfla" in blob or "function level" in blob:
        return "bfla"
    if "ssrf" in blob or "cwe-918" in blob:
        return "ssrf"
    if "ssti" in blob:
        return "ssti"
    if "xss" in blob or "cwe-79" in blob:
        return "xss"
    if "introspection" in blob or "graphql" in blob:
        return "graphql_introspection"
    if "redirect_uri" in blob or "open redirect" in blob or "cwe-601" in blob:
        return "oauth_redirect_uri"
    if "auth" in blob and ("bypass" in blob or "default" in blob):
        return "auth_bypass"
    if "header" in blob and ("missing" in blob or "security" in blob):
        return "missing_security_header"
    if "tls" in blob or "ssl" in blob or "cipher" in blob or "certificate" in blob:
        return "tls_weak"
    return "generic"


CLASS_TEMPLATES = {
    "bola_idor": {
        "prerequisites": "Two accounts (user A and user B); a valid session token for user A.",
        "steps": [
            "Authenticate as user A and capture a request returning an object you own (note the object id).",
            "Replace the object id in the path/parameter with an id belonging to user B.",
            "Replay the request using user A's token.",
        ],
        "command": "curl -i -s '<TARGET>/<endpoint>/<OTHER_USER_ID>' \\\n  -H 'Authorization: Bearer <TOKEN_A>'",
        "expected": "HTTP 200 returning user B's data with user A's token proves Broken Object Level Authorization (BOLA/IDOR).",
    },
    "bfla": {
        "prerequisites": "A low-privilege account token and the path of a privileged function.",
        "steps": [
            "Identify an administrative/privileged endpoint from the documentation or crawl.",
            "Call it using the low-privilege account token.",
        ],
        "command": "curl -i -s -X POST '<TARGET>/<admin_endpoint>' \\\n  -H 'Authorization: Bearer <LOW_PRIV_TOKEN>'",
        "expected": "The privileged action succeeds with a low-privilege token, proving Broken Function Level Authorization (BFLA).",
    },
    "sqli": {
        "prerequisites": "A parameter reachable by the captured request.",
        "steps": [
            "Send the parameter with a benign boolean payload (e.g. ' OR '1'='1).",
            "Compare the response with a false condition (e.g. ' OR '1'='2).",
        ],
        "command": "curl -i -s \"<TARGET>/<endpoint>?id=1'%20OR%20'1'='1\"",
        "expected": "A measurable, condition-dependent difference (rows, length, timing) between the true and false payloads proves SQL injection.",
    },
    "xss": {
        "prerequisites": "A reflected/stored parameter and a browser to render the response.",
        "steps": [
            "Inject a unique marker payload into the parameter.",
            "Render the response and confirm the marker executes as script.",
        ],
        "command": "curl -i -s \"<TARGET>/<endpoint>?q=<svg/onload=alert(1)>\"",
        "expected": "The payload is reflected unencoded in the response; rendering it in a browser executes the script, proving Cross-Site Scripting.",
    },
    "ssrf": {
        "prerequisites": "An out-of-band listener (e.g. interactsh/Collaborator URL).",
        "steps": [
            "Set the URL/host parameter to your OOB listener address.",
            "Send the request and watch the listener for an inbound callback.",
        ],
        "command": "curl -i -s '<TARGET>/<endpoint>?url=http://<OOB_LISTENER>/'",
        "expected": "An inbound request from the target to the OOB listener proves Server-Side Request Forgery.",
    },
    "ssti": {
        "prerequisites": "A parameter reflected into a server-side template.",
        "steps": [
            "Inject a template arithmetic payload into the parameter.",
            "Confirm the server evaluates it.",
        ],
        "command": "curl -i -s '<TARGET>/<endpoint>?name={{7*7}}'",
        "expected": "The response contains 49 (evaluated expression), proving Server-Side Template Injection.",
    },
    "oauth_redirect_uri": {
        "prerequisites": "A registered client_id for the authorization endpoint.",
        "steps": [
            "Build an authorization request with redirect_uri pointing to an attacker-controlled host.",
            "Open the URL and observe whether the server redirects there with a code/token.",
        ],
        "command": "curl -i -s '<TARGET>/authorize?client_id=<CLIENT_ID>&response_type=code&redirect_uri=https://attacker.example/cb'",
        "expected": "The server accepts the unregistered redirect_uri and forwards the authorization code, proving an open redirect / token leak (CWE-601).",
    },
    "graphql_introspection": {
        "prerequisites": "Network access to the GraphQL endpoint.",
        "steps": [
            "Send the introspection query to the GraphQL endpoint.",
            "Confirm the full schema (types/mutations) is returned.",
        ],
        "command": "curl -i -s '<TARGET>/graphql' \\\n  -H 'Content-Type: application/json' \\\n  --data '{\"query\":\"{ __schema { types { name } } }\"}'",
        "expected": "The endpoint returns the schema, exposing all types and mutations (introspection should be disabled in production).",
    },
    "auth_bypass": {
        "prerequisites": "The protected endpoint path.",
        "steps": [
            "Request the protected endpoint with no/invalid credentials, or with default credentials.",
            "Confirm access is granted.",
        ],
        "command": "curl -i -s '<TARGET>/<protected_endpoint>'",
        "expected": "The protected resource is served without valid authentication, proving an authentication bypass.",
    },
    "missing_security_header": {
        "prerequisites": "Network access to the target.",
        "steps": [
            "Request the resource and inspect the full set of response headers.",
            "Confirm the expected security header is not present.",
        ],
        "command": "curl -sI '<TARGET>'",
        "expected": "The response headers do not include the expected control (e.g. Strict-Transport-Security, Content-Security-Policy, or X-Frame-Options), confirming the security header is absent.",
    },
    "tls_weak": {
        "prerequisites": "openssl (or testssl.sh) available locally. <TARGET_HOST> is the hostname only (no scheme/path).",
        "steps": [
            "Negotiate the weak protocol/cipher against the host.",
            "Confirm the handshake succeeds.",
        ],
        "command": "echo | openssl s_client -connect <TARGET_HOST>:443 -tls1_1 2>/dev/null | grep -E 'Protocol|Cipher'",
        "expected": "The handshake completes with the weak protocol/cipher, proving an insecure TLS configuration.",
    },
    "generic": {
        "prerequisites": "Network access to the target and the captured request below.",
        "steps": [
            "Send the request shown in the Command field to the target.",
            "Compare the response against the Expected Result to confirm the issue.",
        ],
        "command": "curl -i -s '<TARGET>/<endpoint>'",
        "expected": "The response reproduces the vulnerable behavior described in this finding.",
    },
}

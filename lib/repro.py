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
_REQ_BLOCK_RE = re.compile(
    r"---\s*HTTP REQUEST\s*---\s*\n(.*?)(?=\n---|\Z)", re.DOTALL | re.IGNORECASE)


def _command_from_curl_field(finding):
    """Primeiro campo de curl não-vazio do finding, ou None."""
    for k in _CURL_FIELDS:
        v = finding.get(k)
        if v and str(v).strip():
            return str(v).strip()
    return None


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
    full_url = url or (("https://" + host + path) if host else path)
    cmd = "curl -i -s -X %s '%s'" % (method, full_url)
    for hk, hv in headers:
        cmd += " \\\n  -H '%s: %s'" % (hk, hv)
    body = "\n".join(body_lines).strip()
    if body:
        cmd += " \\\n  --data '%s'" % body.replace("'", "'\\''")
    return cmd

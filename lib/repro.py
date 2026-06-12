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
_BEARER_RE = re.compile(r"(?i)(authorization\s*:\s*bearer\s+)([A-Za-z0-9._~+/\-]+=*)")
_COOKIE_RE = re.compile(r"(?i)((?:set-)?cookie\s*:\s*)([^\r\n]+)")
_QS_TOKEN_RE = re.compile(
    r"(?i)\b(access_token|refresh_token|id_token|client_secret|code|token)=([^&\s'\"]+)")
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_CPF_RE = re.compile(r"\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b")
_CNPJ_RE = re.compile(r"\b\d{2}\.?\d{3}\.?\d{3}/?\d{4}-?\d{2}\b")


def _mask_pans(text):
    changed = {"v": False}

    def _repl(m):
        pan = m.group(0)
        if pan_scanner.luhn(pan):
            changed["v"] = True
            return pan_scanner.mask(pan)
        return pan

    return pan_scanner.PAN_RE.sub(_repl, text), changed["v"]


def sanitize_text(text):
    """Redige segredos vivos e mascara PAN/PII. Retorna (texto, alterado?)."""
    if not text:
        return text, False
    changed = False
    for rx, repl in ((_BEARER_RE, r"\1<TOKEN_A>"),
                     (_COOKIE_RE, r"\1<SESSION>"),
                     (_QS_TOKEN_RE, r"\1=<REDACTED>")):
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

# lib/active_probe.py
#!/usr/bin/env python3
"""
Stiglitz — Active Probe (par booleano + canário de reflexão).

Núcleo puro (sem rede) reusado pelos validators de injeção via poc_validator:
  - boolean_pair_verdict(): confirma SQLi blind boolean-based pelo diferencial
    true/false vs baseline.
  - canary_reflection(): confirma XSS refletido por marcador único + chars de quebra.
  - build_boolean_variants()/build_canary_variant(): montam as requests dos probes
    a partir de URL/method/body estruturados (shell-safety fica no orquestrador).

Espelha o padrão de lib/bola.py (veredito puro + reuso de normalize/response_diff
+ CLI). Sem domínio hardcoded, sem rede no núcleo.
"""
import os, re, sys, json, difflib
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode

# Reuso do normalize do poc_validator (remove tokens dinâmicos); fallback se
# importado fora do pacote. A comparação de CONTEÚDO usa difflib (não o
# response_diff, que é baseado em tamanho/erro e não distingue corpos de tamanho
# parecido com conteúdo diferente — exatamente o caso TRUE vs FALSE).
try:
    from poc_validator import normalize as _normalize
except Exception:
    def _normalize(t):
        return re.sub(r"\s+", " ", (t or "")).strip()

_SIMILAR_THRESHOLD = 0.95   # >= → corpos considerados "≈ iguais"


def _similar(a, b):
    """True se os corpos normalizados são ≈ iguais (ratio difflib >= threshold)."""
    a, b = _normalize(a), _normalize(b)
    if not a and not b:
        return True
    return difflib.SequenceMatcher(None, a, b).ratio() >= _SIMILAR_THRESHOLD


def boolean_pair_verdict(baseline_norm, true_norm, false_norm):
    """Confirma SQLi blind boolean-based pelo diferencial true/false.

    Retorna {confirmed, confidence, note}:
      TRUE≈baseline ∧ FALSE≠baseline ∧ TRUE≠FALSE → confirmed=True,  conf=88
      tudo ≈ igual (condição sem efeito)           → confirmed=False, conf=25
      sinal parcial (só um critério)               → confirmed=False, conf=40
      baseline pequeno (<50 chars normalizados)    → inconclusivo,    conf=20
    """
    if len(_normalize(baseline_norm)) < 50:
        return {"confirmed": False, "confidence": 20,
                "note": "Baseline pequeno demais para par booleano"}

    true_eq_base   = _similar(baseline_norm, true_norm)
    false_neq_base = not _similar(baseline_norm, false_norm)
    true_neq_false = not _similar(true_norm, false_norm)

    if true_eq_base and false_neq_base and true_neq_false:
        return {"confirmed": True, "confidence": 88,
                "note": "Par booleano: TRUE≈baseline, FALSE≠baseline"}
    if not false_neq_base and not true_neq_false:
        return {"confirmed": False, "confidence": 25,
                "note": "Condição sem efeito (true≈false≈baseline)"}
    return {"confirmed": False, "confidence": 40,
            "note": "Sinal parcial — diferencial booleano incompleto"}


PROBE_CHARS = '<">'   # quebra-de-contexto benigna anexada ao token do canário


def new_canary_token():
    """Marcador único 'stg' + 8 hex (os.urandom). Alfanumérico → busca inequívoca."""
    return "stg" + os.urandom(4).hex()


def canary_reflection(token, resp_body):
    """Detecta reflexão de `token` + PROBE_CHARS no corpo.

    Retorna {reflected, encoded, confidence, note}:
      token + PROBE_CHARS crus (< " >)  → reflected, !encoded, conf=90 (XSS provável)
      token + PROBE_CHARS HTML-escapados → reflected,  encoded, conf=35 (provável safe)
      token ausente                      → reflected=False,     conf=0
    """
    body = resp_body or ""
    if token not in body:
        return {"reflected": False, "encoded": False, "confidence": 0,
                "note": "Canário não refletido"}

    # Janela após cada ocorrência do token — procura PROBE_CHARS crus vs escapados.
    raw = False
    enc = False
    for m in re.finditer(re.escape(token), body):
        window = body[m.end():m.end() + 16]
        if any(c in window for c in PROBE_CHARS):
            raw = True
            break
        if re.search(r"&(?:lt|gt|quot|#x?\d+);", window):
            enc = True
    if raw:
        return {"reflected": True, "encoded": False, "confidence": 90,
                "note": "Canário refletido com chars de quebra crus (XSS provável)"}
    return {"reflected": True, "encoded": True, "confidence": 35,
            "note": "Canário refletido mas escapado/neutralizado (provável safe)"}


# Mesmas keywords SQL do build_safe_baseline (poc_validator).
_SQLI_KW = re.compile(
    r"(?:\bOR\b|\bAND\b|\bUNION\b|\bSELECT\b|\bDROP\b|\bINSERT\b|\bUPDATE\b"
    r"|\bDELETE\b|\bEXEC\b|\bCAST\b|\bSLEEP\b|\bWAITFOR\b|\bBENCHMARK\b|--|')",
    re.IGNORECASE)

# Chars que sinalizam um parâmetro carregando payload XSS.
_XSS_HINT = re.compile(r"[<>\"']|script|javascript:|onerror|onload", re.IGNORECASE)


def _rebuild_query(url, key, new_value):
    """Devolve `url` com o parâmetro `key` da query trocado por `new_value`
    (demais parâmetros preservados, na ordem)."""
    parts = urlsplit(url)
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    rebuilt = [(k, new_value if k == key else v) for k, v in pairs]
    return urlunsplit((parts.scheme, parts.netloc, parts.path,
                       urlencode(rebuilt), parts.fragment))


def _first_param(url, hint_re):
    """(key, value) do primeiro parâmetro de query cujo valor casa `hint_re`, ou None."""
    parts = urlsplit(url)
    for k, v in parse_qsl(parts.query, keep_blank_values=True):
        if hint_re.search(v or ""):
            return k, v
    return None


def build_boolean_variants(url, method="GET", body=""):
    """(true_req, false_req) | None — cada req é {"url","method","body"}.

    Detecta na query o parâmetro injetável (valor com keyword SQL) e troca o
    valor por `1' AND '1'='1` (true) / `1' AND '1'='2` (false). Só query string
    nesta fase. None se nenhum parâmetro injetável for achado."""
    hit = _first_param(url, _SQLI_KW)
    if not hit:
        return None
    key, _v = hit
    true_req = {"method": method, "body": body,
                "url": _rebuild_query(url, key, "1' AND '1'='1")}
    false_req = {"method": method, "body": body,
                 "url": _rebuild_query(url, key, "1' AND '1'='2")}
    return true_req, false_req


def build_canary_variant(url, token, method="GET", body=""):
    """canary_req | None — {"url","method","body"}.

    Detecta na query o parâmetro com payload XSS-ish e troca o valor por
    `token + PROBE_CHARS`. Só query string nesta fase. None se nada substituível."""
    hit = _first_param(url, _XSS_HINT)
    if not hit:
        return None
    key, _v = hit
    return {"method": method, "body": body,
            "url": _rebuild_query(url, key, token + PROBE_CHARS)}

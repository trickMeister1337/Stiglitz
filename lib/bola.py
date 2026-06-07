#!/usr/bin/env python3
"""
bola.py — detecção de BOLA/IDOR e BFLA (OWASP API #1) via replay multi-token (P1).

Reproduz requisições reais (gravadas pelo ZAP como token A/B) com a identidade do
outro usuário e confirma acesso indevido por tripla A/B/unauth + canário de corpo.
Lógica pura + CLI fina (replay de rede injetável p/ teste). Sem domínio hardcoded.
"""
import sys
import os
import re
import json
import urllib.parse

# Limiares ajustáveis (defaults conservadores — preferir FN a FP).
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
PRIVILEGED_PATH = re.compile(r"/(admin|internal|manage|console|root|sudo)\b", re.I)
_NUM_SEG = re.compile(r"/\d+(?=/|$)")
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)
_ID_PARAM = re.compile(r"(^|[?&])(id|user_id|account|uid|order|customer)=", re.I)
_EMAIL = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
_CPF = re.compile(r"\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b")


def _first_line(header):
    return (header or "").split("\r\n", 1)[0].split("\n", 1)[0]


def _status_of(resp_header):
    m = re.search(r"HTTP/\S+\s+(\d{3})", resp_header or "")
    return int(m.group(1)) if m else 0


def parse_zap_messages(json_text):
    """Lê o dump do core/view/messages do ZAP. Retorna lista de dicts
    {method, url, req_headers, req_body, status, resp_body}. Itens inválidos ignorados."""
    try:
        obj = json.loads(json_text or "")
    except Exception:
        return []
    msgs = obj.get("messages") if isinstance(obj, dict) else None
    if not isinstance(msgs, list):
        return []
    out = []
    for m in msgs:
        if not isinstance(m, dict):
            continue
        line = _first_line(m.get("requestHeader"))
        parts = line.split()
        if len(parts) < 2:
            continue
        method, target = parts[0].upper(), parts[1]
        out.append({
            "method": method,
            "url": target,
            "req_headers": m.get("requestHeader") or "",
            "req_body": m.get("requestBody") or "",
            "status": _status_of(m.get("responseHeader")),
            "resp_body": m.get("responseBody") or "",
        })
    return out


def is_safe_method(method):
    """Só métodos idempotentes read-only são reproduzidos (segurança/RoE)."""
    return (method or "").strip().upper() in SAFE_METHODS


def is_object_ref_request(req):
    """True se a URL carrega referência a objeto (id numérico em path, UUID,
    ou param id/user_id/account/...). Sem object-ref, replay é ruído."""
    url = req.get("url") or ""
    split = urllib.parse.urlsplit(url)
    path, query = split.path or url, split.query or ""
    if _NUM_SEG.search(path):
        return True
    if _UUID.search(url):
        return True
    if _ID_PARAM.search("?" + query):
        return True
    return False


def extract_canary(resp_body, content_type=""):
    """Extrai identificadores do objeto do dono (o que se procura no corpo do
    cross-replay): emails, CPFs, e valores de campos id/uuid em JSON. Retorna set."""
    body = resp_body or ""
    canary = set()
    canary.update(_EMAIL.findall(body))
    canary.update(_CPF.findall(body))
    canary.update(_UUID.findall(body))
    # valores de campos "id"/"..._id" em JSON: "id": 123  ou  "user_id":"abc"
    for m in re.finditer(r'"(?:\w*_)?id"\s*:\s*"?([\w-]{1,64})"?', body, re.I):
        canary.add(m.group(1))
    return {c for c in canary if c}


def canary_is_pii(canary):
    """True se algum item do canário é PII (email/CPF) — vira idor_read_pii."""
    return any(_EMAIL.fullmatch(c) or _CPF.fullmatch(c) for c in canary)


try:
    from poc_validator import normalize as _normalize, response_diff as _response_diff
except Exception:  # fallback se importado fora do pacote lib/
    def _normalize(t):
        return re.sub(r"\s+", " ", (t or "")).strip()

    def _response_diff(a, b):
        return (a != b, 0, "")


def _is_2xx(status):
    """True se status é 2xx (200-299)."""
    return 200 <= int(status or 0) < 300


def _bodies_match(a, b):
    """True se os dois corpos são ≈ iguais (response_diff.changed == False)."""
    changed, _score, _note = _response_diff(_normalize(a), _normalize(b))
    return not changed


def _canary_hit(canary, body):
    """True se algum item do canário aparece no corpo."""
    body = body or ""
    return any(c and c in body for c in canary)


def verdict(baseline, cross, unauth, canary):
    """Máquina de estados de confirmação. baseline/cross/unauth: {status, body}.

    Retorna {state, canary_hit, confidence}:
      PROTECTED    — cross negado (401/403): autorização funciona.
      PUBLIC       — unauth 2xx com corpo ≈ baseline: recurso público (não é achado).
      CONFIRMED    — cross 2xx + corpo ≈ baseline + canário bate + unauth negado.
      INCONCLUSIVE — cross 2xx mas corpo difere ou canário não bate (baixa confiança).
    """
    c_status = int(cross.get("status") or 0)
    if c_status in (401, 403):
        return {"state": "PROTECTED", "canary_hit": False, "confidence": 0}

    unauth_open = _is_2xx(unauth.get("status")) and _bodies_match(
        baseline.get("body"), unauth.get("body"))
    if unauth_open:
        return {"state": "PUBLIC", "canary_hit": False, "confidence": 0}

    if not _is_2xx(c_status):
        return {"state": "INCONCLUSIVE", "canary_hit": False, "confidence": 20}

    hit = _canary_hit(canary, cross.get("body"))
    same = _bodies_match(baseline.get("body"), cross.get("body"))
    if hit and same:
        return {"state": "CONFIRMED", "canary_hit": True, "confidence": 90}
    return {"state": "INCONCLUSIVE", "canary_hit": hit, "confidence": 50 if same else 30}


try:
    from fingerprint import fingerprint as _fingerprint
    from vuln_catalog import CATALOG as _CATALOG
except Exception:
    def _fingerprint(f):
        return "0" * 16
    _CATALOG = {}


def classify(req, canary):
    """Classe do finding: bfla (path privilegiado) > idor_read_pii (PII) > bola."""
    if PRIVILEGED_PATH.search(req.get("url") or ""):
        return "bfla"
    if canary_is_pii(canary):
        return "idor_read_pii"
    return "bola"


def build_findings(results):
    """Converte resultados CONFIRMED/INCONCLUSIVE em findings (schema findings.json).
    PROTECTED/PUBLIC são descartados. CONFIRMED → confirmed=True/severity high;
    INCONCLUSIVE → confirmed=False/severity info (triagem)."""
    findings = []
    for r in results:
        state = r["verdict"]["state"]
        if state not in ("CONFIRMED", "INCONCLUSIVE"):
            continue
        klass = classify(r["req"], r.get("canary") or set())
        cwe = _CATALOG.get(klass, {}).get("cwe", "")
        confirmed = state == "CONFIRMED"
        finding = {
            "type": klass,
            "cwe": cwe,
            "url": r["req"].get("url", ""),
            "param": "",
            "severity": "high" if confirmed else "info",
            "confirmed": confirmed,
            "confidence": r["verdict"].get("confidence", 0),
            "direction": r.get("direction", ""),
            "canary_hit": r["verdict"].get("canary_hit", False),
            "source": "bola",
            "poc_note": f"Access-control {state} via replay {r.get('direction','')}",
        }
        finding["fingerprint"] = _fingerprint(finding)
        findings.append(finding)
    return findings

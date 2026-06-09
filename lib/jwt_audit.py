#!/usr/bin/env python3
"""
jwt_audit.py — auditoria ATIVA de JWT (alg=none, weak HS256 secret, exp).

(#6/P0) O Stiglitz só DETECTAVA tokens (poc_validator.py) e os vetores
jwt_alg_none/jwt_weak_secret existiam no catálogo sem coletor. Aqui há a lógica
pura (forja alg=none, verificação/crack HS256, análise estática) — testável sem
rede. A confirmação ativa (replay do token forjado a um endpoint autenticado)
fica no runner que consome forge_alg_none() e compara a resposta.

Núcleo puro com stdlib (hmac/hashlib/base64) — sem dependências externas.
"""
import sys
import os
import json
import hmac
import hashlib
import base64


def b64url_decode(seg):
    seg = seg + "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg.encode())


def b64url_encode(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def decode_jwt(token):
    parts = token.split(".")
    if len(parts) < 2:
        raise ValueError("not a JWT")
    header = json.loads(b64url_decode(parts[0]))
    payload = json.loads(b64url_decode(parts[1]))
    return header, payload


def _signing_input(header, payload):
    h = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    return f"{h}.{p}"


def encode_hs256(header, payload, secret):
    si = _signing_input(header, payload)
    sig = hmac.new(secret.encode(), si.encode(), hashlib.sha256).digest()
    return f"{si}.{b64url_encode(sig)}"


def verify_hs256(token, secret):
    parts = token.split(".")
    if len(parts) != 3:
        return False
    si = f"{parts[0]}.{parts[1]}"
    expected = b64url_encode(hmac.new(secret.encode(), si.encode(), hashlib.sha256).digest())
    return hmac.compare_digest(expected, parts[2])


def forge_alg_none(token):
    """Reemite o token com alg=none e assinatura vazia (ataque de bypass clássico)."""
    header, payload = decode_jwt(token)
    header = dict(header)
    header["alg"] = "none"
    return _signing_input(header, payload) + "."


def forge_with_claims(token, overrides, alg="none"):
    """Reemite o token com claims sobrescritas (ex.: role=admin) e alg=none por padrão —
    primitiva do ataque ativo de impersonação (replay a endpoint protegido)."""
    header, payload = decode_jwt(token)
    header = dict(header)
    header["alg"] = alg
    payload = dict(payload)
    payload.update(overrides or {})
    return _signing_input(header, payload) + "."


def crack_hs256(token, wordlist):
    """Tenta quebrar o segredo HS256 com uma wordlist; retorna o segredo ou None."""
    try:
        header, _ = decode_jwt(token)
    except (ValueError, json.JSONDecodeError):
        return None
    if str(header.get("alg", "")).upper() != "HS256":
        return None
    for word in wordlist or []:
        if verify_hs256(token, word):
            return word
    return None


def exp_status(token, window_seconds, now_ts):
    """Classifica o exp do JWT contra uma janela de scan, SEM usar relógio (now_ts injetado).

    Retorna dict {"state", "exp", "remaining"}:
      "malformed"      — token não decodificável
      "no_exp"         — payload sem exp (ou exp não-numérico)
      "expired"        — exp <= now_ts
      "expires_within" — now_ts < exp <= now_ts + window_seconds
      "ok"             — exp > now_ts + window_seconds
    remaining = exp - now_ts (segundos) quando exp presente, senão None.
    now_ts e exp são truncados para int (epoch em segundos).
    """
    try:
        _, payload = decode_jwt(token)
    except (ValueError, json.JSONDecodeError):
        return {"state": "malformed", "exp": None, "remaining": None}
    exp = payload.get("exp")
    if not isinstance(exp, (int, float)) or isinstance(exp, bool):
        return {"state": "no_exp", "exp": None, "remaining": None}
    exp = int(exp)
    remaining = exp - int(now_ts)
    if remaining <= 0:
        state = "expired"
    elif remaining <= window_seconds:
        state = "expires_within"
    else:
        state = "ok"
    return {"state": state, "exp": exp, "remaining": remaining}


def _finding(ftype, name, sev, url, desc, remediation, evidence=""):
    return {
        "tool": "jwt_audit", "type": ftype, "source": "JWT Audit",
        "name": name, "url": url, "severity": sev,
        "description": desc, "remediation": remediation,
        "evidence": evidence, "cve": "CWE-347",
    }


def static_findings(token, target="", wordlist=None):
    """Findings derivados estaticamente do token (sem rede): segredo fraco, exp, alg=none."""
    findings = []
    try:
        header, payload = decode_jwt(token)
    except (ValueError, json.JSONDecodeError):
        return findings
    alg = str(header.get("alg", "")).lower()

    if alg == "hs256" and wordlist:
        secret = crack_hs256(token, wordlist)
        if secret is not None:
            findings.append(_finding(
                "jwt_weak_secret", "JWT signed with a weak/guessable HS256 secret",
                "critical", target,
                "The HS256 signing secret was recovered from a wordlist, allowing an "
                "attacker to forge arbitrary tokens (full authentication bypass).",
                "Use a high-entropy secret (>=256 bits) from a secrets manager; rotate the key.",
                evidence=f"Recovered secret: {secret}"))

    if alg == "none":
        findings.append(_finding(
            "jwt_alg_none", "JWT with alg=none (unsigned token)",
            "high", target,
            "Token uses alg=none, meaning no signature is verified — trivially forgeable.",
            "Reject alg=none server-side; pin the expected algorithm (e.g. RS256/HS256)."))

    if "exp" not in payload:
        findings.append(_finding(
            "jwt_missing_exp", "JWT without expiration (exp) claim",
            "low", target,
            "Token has no exp claim; a leaked token remains valid indefinitely.",
            "Add a short exp and validate it server-side."))

    return findings


def main(outdir, target, token=""):
    """Coletor: produz raw/jwt_findings.json a partir de um token (env STIGLITZ_JWT
    ou --token). A confirmação ativa de alg=none requer replay a um endpoint vivo;
    aqui emitimos os findings estáticos (weak-secret/exp/alg-none)."""
    token = token or os.environ.get("STIGLITZ_JWT", "")
    findings = []
    if token:
        wl_path = os.environ.get("STIGLITZ_JWT_WORDLIST", "")
        wordlist = []
        if wl_path and os.path.exists(wl_path):
            with open(wl_path, encoding="utf-8", errors="ignore") as fh:
                wordlist = [w.strip() for w in fh if w.strip()]
        findings = static_findings(token, target=target, wordlist=wordlist)
        for i, f in enumerate(findings, 1):
            f["id"] = f"JWT-{i:03d}"
    out = os.path.join(outdir, "raw", "jwt_findings.json")
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(findings, fh, indent=2, ensure_ascii=False)
    print(f"  [{'✓' if findings else '○'}] JWT audit: {len(findings)} finding(s) → jwt_findings.json")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else "",
         sys.argv[3] if len(sys.argv) > 3 else "")

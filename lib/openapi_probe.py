#!/usr/bin/env python3
"""openapi_probe.py — P0.1 (núcleo): OpenAPI/Swagger como motor de detecção de
broken-auth ZERO-credencial. Para cada operação documentada como protegida
(`security:`), faz uma requisição SEM credencial e confirma 'Missing Authentication'
(CWE-306) quando o endpoint responde 2xx com dados reais.

Lógica pura + fetch injetável + CLI. Reusa bola.extract_canary/is_safe_method e
openapi_seed._prefix. Só métodos seguros (GET/HEAD/OPTIONS) por padrão.
"""
import json
import os
import re
import sys
import urllib.request
import urllib.error

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from openapi_seed import _prefix as _spec_prefix
from bola import extract_canary, is_safe_method
import netproxy

_PARAM = re.compile(r"\{[^}]+\}")
_HTTP_METHODS = ("get", "put", "post", "delete", "options", "head", "patch", "trace")
_AUTH_ERR = re.compile(
    r"unauthor|forbidden|access\s+denied|not\s+authenticated|"
    r"missing\s+(?:token|auth)|invalid\s+token|token\s+(?:expired|missing)|"
    r"please\s+log\s*in|login\s+required",
    re.I,
)


def _as_dict(spec):
    if isinstance(spec, str):
        try:
            spec = json.loads(spec)
        except (ValueError, TypeError):
            return None
    return spec if isinstance(spec, dict) else None


def _op_requires_auth(spec, operation):
    """True se a operação exige auth. security:[] na operação remove a global."""
    op_sec = operation.get("security")
    if op_sec is not None:
        return bool(op_sec)
    return bool(spec.get("security"))


def documented_operations(spec):
    """Lista de {path, method(UPPER), requires_auth} para cada operação do spec."""
    spec = _as_dict(spec)
    if spec is None:
        return []
    paths = spec.get("paths")
    if not isinstance(paths, dict):
        return []
    out = []
    for raw, item in paths.items():
        if not isinstance(raw, str) or not raw.startswith("/") or not isinstance(item, dict):
            continue
        for method, operation in item.items():
            if method.lower() not in _HTTP_METHODS or not isinstance(operation, dict):
                continue
            out.append({
                "path": raw,
                "method": method.upper(),
                "requires_auth": _op_requires_auth(spec, operation),
            })
    return out


def op_url(spec, base_url, path, sample="1"):
    """URL absoluta: prefixo (basePath/servers) aplicado + {param} resolvido."""
    spec = _as_dict(spec) or {}
    prefix = _spec_prefix(spec)
    root = base_url.rstrip("/")
    full = path if (not prefix or path.startswith(prefix)) else prefix + path
    return _PARAM.sub(sample, root + full)


def unauth_verdict(status, body, content_type=""):
    """Veredito da resposta SEM credencial a um endpoint documentado como protegido.
      PROTECTED    — 401/403/3xx, ou 2xx cujo corpo é envelope de erro de auth.
      BROKEN_AUTH  — 2xx com dados reais (estruturado, canário, ou corpo substancial) → High.
      INCONCLUSIVE — 2xx vazio/curto, 404/405, 5xx.
    """
    s = int(status or 0)
    if s in (401, 403) or 300 <= s < 400:
        return {"state": "PROTECTED", "severity": "info", "confidence": 0}
    if not (200 <= s < 300):
        return {"state": "INCONCLUSIVE", "severity": "info", "confidence": 20}
    text = body or ""
    if not text.strip():
        return {"state": "INCONCLUSIVE", "severity": "info", "confidence": 25}
    if _AUTH_ERR.search(text[:512]):
        return {"state": "PROTECTED", "severity": "info", "confidence": 0}
    canary = extract_canary(text, content_type)
    ct = (content_type or "").lower()
    structured = ("json" in ct or "xml" in ct or text.lstrip()[:1] in ("{", "["))
    if canary:
        return {"state": "BROKEN_AUTH", "severity": "high", "confidence": 90}
    if structured or len(text) >= 64:
        return {"state": "BROKEN_AUTH", "severity": "high", "confidence": 70}
    return {"state": "INCONCLUSIVE", "severity": "info", "confidence": 40}


def build_finding(op, url, verdict_res, status):
    """Finding normalizado (texto EN — deliverable) para o broken-auth documentado."""
    return {
        "type": "broken_auth_documented",
        "name": "Missing Authentication on Documented-Protected Endpoint",
        "severity": verdict_res["severity"],
        "cwe": "CWE-306",
        "url": url,
        "method": op["method"],
        "confirmed": verdict_res["confidence"] >= 80,
        "confidence": verdict_res["confidence"],
        "source": "openapi_probe",
        "tool": "openapi_probe",
        "description": (
            "An endpoint documented in the OpenAPI/Swagger specification as requiring "
            "authentication (a security requirement is declared) returned HTTP %s with a "
            "data-bearing body in response to an UNAUTHENTICATED request. Authentication "
            "is not enforced at runtime, exposing the documented resource without credentials."
            % status
        ),
        "evidence": "Unauthenticated %s %s -> HTTP %s (verdict=%s, confidence=%s%%)" % (
            op["method"], url, status, verdict_res["state"], verdict_res["confidence"]),
    }


def probe(spec, base_url, fetch_fn, safe_only=True, sample="1"):
    """Sonda cada operação documentada-protegida SEM credencial. Retorna findings BROKEN_AUTH."""
    findings = []
    for op in documented_operations(spec):
        if not op["requires_auth"]:
            continue
        if safe_only and not is_safe_method(op["method"]):
            continue
        url = op_url(spec, base_url, op["path"], sample=sample)
        try:
            status, body, content_type = fetch_fn(url, op["method"])
        except Exception:
            continue
        v = unauth_verdict(status, body, content_type)
        if v["state"] == "BROKEN_AUTH":
            findings.append(build_finding(op, url, v, status))
    return findings


def _default_fetch(url, method, timeout=10):
    """Fetch real via netproxy (herda --proxy + mTLS). Retorna (status, body, content_type)."""
    req = urllib.request.Request(url, method=method,
                                 headers={"Accept": "application/json, */*"})
    try:
        with netproxy.urlopen(req, timeout=timeout) as resp:
            body = resp.read(65536).decode("utf-8", "replace")
            return resp.status, body, resp.headers.get("content-type", "")
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read(65536).decode("utf-8", "replace")
        except Exception:
            pass
        ct = e.headers.get("content-type", "") if getattr(e, "headers", None) else ""
        return e.code, body, ct


def run(spec_path, base_url, outdir, fetch_fn=_default_fetch):
    """Lê o spec, sonda, grava <outdir>/raw/openapi_authz.json. Retorna a contagem."""
    try:
        with open(spec_path, encoding="utf-8") as f:
            spec = json.load(f)
    except (OSError, ValueError):
        return 0
    findings = probe(spec, base_url, fetch_fn)
    raw = os.path.join(outdir, "raw")
    try:
        os.makedirs(raw, exist_ok=True)
        with open(os.path.join(raw, "openapi_authz.json"), "w", encoding="utf-8") as f:
            json.dump(findings, f, indent=2)
    except OSError:
        pass
    return len(findings)


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) < 2:
        print("uso: openapi_probe.py <spec.json> <base_url> [outdir]", file=sys.stderr)
        return 2
    outdir = argv[2] if len(argv) > 2 else "."
    print(run(argv[0], argv[1], outdir))
    return 0


if __name__ == "__main__":
    sys.exit(main())

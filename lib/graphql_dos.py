#!/usr/bin/env python3
"""graphql_dos.py — detecção de resource-exhaustion em GraphQL (batching/aliasing).

Probes não-destrutivos (leituras de __typename, request único, contagem limitada)
que detectam AUSÊNCIA de limite de complexidade/alias e de batching. Não requer
introspection (usa __typename). Em production, faz dry-run. Lógica pura + send_fn
injetável.
"""
import json
import os
import sys

ALIAS_N_DEFAULT = 100
BATCH_M_DEFAULT = 15


def _alias_n():
    try:
        return max(2, int(os.environ.get("STIGLITZ_GQL_ALIAS_N", ALIAS_N_DEFAULT)))
    except ValueError:
        return ALIAS_N_DEFAULT


def _batch_m():
    try:
        return max(2, int(os.environ.get("STIGLITZ_GQL_BATCH_M", BATCH_M_DEFAULT)))
    except ValueError:
        return BATCH_M_DEFAULT


def build_alias_probe(n):
    """Query com n aliases de __typename (meta-campo universal, sem args)."""
    aliases = " ".join(f"a{i}:__typename" for i in range(n))
    return {"query": "{ " + aliases + " }"}


def build_batch_probe(m):
    """Array JSON de m operações pequenas (batch)."""
    return [{"query": "{__typename}"} for _ in range(m)]


def _is_graphql_response(status, body):
    """True se body parece um envelope GraphQL (data/errors)."""
    try:
        obj = json.loads(body or "")
    except (ValueError, TypeError):
        return False
    if isinstance(obj, dict):
        return "data" in obj or "errors" in obj
    if isinstance(obj, list):
        return any(isinstance(x, dict) and ("data" in x or "errors" in x) for x in obj)
    return False


def classify_alias_response(status, body, n):
    """Finding quando 200 + os n aliases resolveram (sem errors de complexidade)."""
    if int(status or 0) != 200:
        return None
    try:
        obj = json.loads(body or "")
    except (ValueError, TypeError):
        return None
    if not isinstance(obj, dict) or obj.get("errors"):
        return None
    data = obj.get("data") or {}
    resolved = sum(1 for k in data if k.startswith("a"))
    if resolved < n:
        return None
    return {
        "tool": "graphql_dos", "type": "graphql_no_complexity_limit", "source": "GraphQL",
        "name": "GraphQL lacks query complexity/alias limiting",
        "severity": "medium", "cve": "CWE-770",
        "description": (f"The endpoint resolved a query with {n} aliased fields without "
                        "rejection, indicating no query-complexity/alias limiting — a "
                        "resource-exhaustion (DoS) amplification vector."),
        "remediation": "Enforce query complexity/depth/alias limits (e.g., a cost-analysis plugin).",
    }


def classify_batch_response(status, body, m):
    """Finding quando a resposta é um array de >= 2 resultados (batch processado)."""
    try:
        obj = json.loads(body or "")
    except (ValueError, TypeError):
        return None
    if isinstance(obj, list) and len(obj) >= 2:
        return {
            "tool": "graphql_dos", "type": "graphql_batching_enabled", "source": "GraphQL",
            "name": "GraphQL query batching enabled",
            "severity": "low", "cve": "CWE-770",
            "description": (f"The endpoint processed a batched array of {len(obj)} operations, "
                            "enabling request amplification (brute-force/DoS)."),
            "remediation": "Disable array-based query batching or bound the batch size.",
        }
    return None


def run(url, profile, send_fn, n=None, m=None):
    """Detecta o endpoint via {__typename}; roda probes de aliasing/batching.

    production → dry-run (não envia amplificação). Fail-soft. Retorna lista de findings.
    """
    n = n or _alias_n()
    m = m or _batch_m()
    findings = []
    try:
        det = send_fn(url, {"query": "{__typename}"})
    except Exception:
        return []
    if not _is_graphql_response(det.get("status"), det.get("body")):
        return []
    if (profile or "").lower() == "production":
        findings.append({
            "tool": "graphql_dos", "type": "graphql_dos_dryrun", "source": "GraphQL",
            "name": "GraphQL DoS probes skipped (production dry-run)",
            "severity": "info", "cve": "CWE-770", "url": url,
            "description": (f"GraphQL endpoint detected. Aliasing ({n} aliases) and batching "
                            f"({m} ops) probes were NOT sent (production profile). Re-run in a "
                            "staging window to confirm complexity/batch limiting."),
            "remediation": "Confirm query-complexity and batch limits in an approved window.",
        })
        return findings
    try:
        ar = send_fn(url, build_alias_probe(n))
        f = classify_alias_response(ar.get("status"), ar.get("body"), n)
        if f:
            f["url"] = url
            findings.append(f)
    except Exception:
        pass
    try:
        br = send_fn(url, build_batch_probe(m))
        f = classify_batch_response(br.get("status"), br.get("body"), m)
        if f:
            f["url"] = url
            findings.append(f)
    except Exception:
        pass
    return findings


def _send(url, payload):
    """POST default via netproxy/mtls (curl). Retorna {status, body}."""
    import subprocess
    import netproxy
    import mtls
    cmd = ["curl", *netproxy.curl_proxy_args(), *mtls.curl_cert_args(), "-s", "-S",
           "--max-time", "15", "-X", "POST", "-H", "Content-Type: application/json",
           "-o", "-", "-w", "\n__HTTP_STATUS__:%{http_code}",
           "-d", json.dumps(payload), "--", url]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        raw = p.stdout or ""
    except Exception:
        return {"status": 0, "body": ""}
    status, body = 0, raw
    marker = raw.rfind("__HTTP_STATUS__:")
    if marker != -1:
        body = raw[:marker].rstrip("\n")
        try:
            status = int(raw[marker + len("__HTTP_STATUS__:"):].strip())
        except ValueError:
            status = 0
    return {"status": status, "body": body}


def main(argv):
    outdir, url = argv[1], argv[2]
    profile = os.environ.get("STIGLITZ_PROFILE", "staging")
    findings = run(url, profile, _send)
    for i, f in enumerate(findings, 1):
        f["id"] = f"GQLDOS-{i:03d}"
    out = os.path.join(outdir, "raw", "graphql_dos.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(findings, fh, indent=2, ensure_ascii=False)
    print(f"  [{'✓' if findings else '○'}] GraphQL DoS: {len(findings)} finding(s) → graphql_dos.json")


if __name__ == "__main__":
    main(sys.argv)

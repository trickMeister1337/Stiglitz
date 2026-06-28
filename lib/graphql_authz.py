#!/usr/bin/env python3
"""graphql_authz.py — field-level authorization (BOLA/BFLA) em GraphQL.

Reusa o núcleo de confirmação do bola.py (verdict + extract_canary) sobre as
operações GraphQL reais capturadas no histórico do ZAP. Replaya cada operação
com token-a/token-b/unauth e confirma acesso indevido. Só queries por padrão;
mutations exigem mutate=True + profile != production. Lógica pura + replay_fn injetável.
"""
import json
import os
import sys
import urllib.parse

import bola
import graphql_audit

try:
    from fingerprint import fingerprint as _fingerprint
except Exception:
    def _fingerprint(f):
        return "0" * 16

_SENSITIVE = graphql_audit._SENSITIVE_RE


def select_graphql_messages(messages, endpoint_substr="graphql"):
    """POSTs ao endpoint GraphQL com corpo de operação, a partir do dump ZAP."""
    out = []
    for m in messages:
        if (m.get("method") or "").upper() != "POST":
            continue
        if endpoint_substr.lower() not in (m.get("url") or "").lower():
            continue
        body = m.get("req_body") or ""
        if '"query"' in body or '"mutation"' in body or "operationName" in body:
            out.append(m)
    return out


def _classify(req):
    """graphql_bfla se mutation ou nome sensível; senão graphql_bola."""
    body = req.get("req_body") or ""
    if graphql_audit.is_mutation(body) or _SENSITIVE.search(body):
        return "graphql_bfla"
    return "graphql_bola"


def _replay(req, token):
    """POST do corpo GraphQL trocando o Authorization. token=None → unauth.
    Retorna {status, body}. Reusa netproxy/mtls."""
    import subprocess
    import netproxy
    import mtls
    url = req.get("url") or ""
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return {"status": 0, "body": ""}
    auth_args = ["-H", f"Authorization: Bearer {token}"] if token else []
    cmd = ["curl", *netproxy.curl_proxy_args(), *mtls.curl_cert_args(), "-s", "-S",
           "--max-time", "15", "-X", "POST", "-H", "Content-Type: application/json",
           *auth_args,
           "-o", "-", "-w", "\n__HTTP_STATUS__:%{http_code}",
           "-d", req.get("req_body") or "", "--", url]
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


def run(messages, token_a, token_b, outdir, replay_fn=_replay, mutate=False, profile="staging"):
    """Replaya as operações GraphQL com 2 tokens; grava raw/graphql_authz.json.

    Só queries por padrão; mutations só com mutate=True E profile != production.

    Nota de contrato: o baseline (o "dado do dono") vem do próprio histórico do
    ZAP (`req["resp_body"]`, já capturado pelo spider autenticado com token_a) —
    não há replay ao vivo com token_a aqui. `token_a` permanece na assinatura por
    simetria com a guarda da CLI (`main` exige os 2 tokens) e como ponto de
    extensão futuro para um baseline ao vivo; hoje só `token_b`/unauth são enviados.
    """
    corpus = select_graphql_messages(messages)
    seen = set()
    findings = []
    prod = (profile or "").lower() == "production"
    for req in corpus:
        if graphql_audit.is_mutation(req.get("req_body") or "") and not (mutate and not prod):
            continue
        baseline = {"status": req.get("status"), "body": req.get("resp_body")}
        canary = bola.extract_canary(req.get("resp_body"), "")
        cross = replay_fn(req, token_b)
        unauth = replay_fn(req, None)
        v = bola.verdict(baseline, cross, unauth, canary)
        if v["state"] not in ("CONFIRMED", "INCONCLUSIVE"):
            continue
        klass = _classify(req)
        sp = urllib.parse.urlsplit(req.get("url") or "")
        key = (sp.netloc, sp.path, klass)
        if key in seen:
            continue
        seen.add(key)
        confirmed = v["state"] == "CONFIRMED"
        finding = {
            "type": klass,
            "cwe": "CWE-639" if klass == "graphql_bola" else "CWE-285",
            "url": req.get("url", ""), "param": "",
            "severity": "high" if confirmed else "info",
            "confirmed": confirmed, "confidence": v.get("confidence", 0),
            "canary_hit": v.get("canary_hit", False), "source": "graphql_authz",
            "poc_note": f"GraphQL access-control {v['state']} via token-B replay",
        }
        finding["fingerprint"] = _fingerprint(finding)
        findings.append(finding)
    out = os.path.join(outdir, "raw", "graphql_authz.json")
    try:
        os.makedirs(os.path.dirname(out), exist_ok=True)
        with open(out, "w", encoding="utf-8") as fh:
            json.dump(findings, fh, indent=2, ensure_ascii=False)
    except Exception as exc:
        print(f"aviso: não foi possível gravar graphql_authz.json: {exc}", file=sys.stderr)
    return findings


def main(argv):
    """uso: graphql_authz.py <zap_messages.json> <outdir> (tokens via env)."""
    if len(argv) < 3:
        print("uso: graphql_authz.py <zap_messages.json> <outdir>", file=sys.stderr)
        return 2
    with open(argv[1], encoding="utf-8") as fh:
        messages = bola.parse_zap_messages(fh.read())
    outdir = argv[2]
    tok_a = os.environ.get("BOLA_TOKEN_A", "")
    tok_b = os.environ.get("BOLA_TOKEN_B", "")
    if not tok_a or not tok_b:
        print("  [○] GraphQL authz: 2 tokens necessários — pulado")
        return 0
    if tok_a == tok_b:
        print("  [○] GraphQL authz: TOKEN_A == TOKEN_B — pulado", file=sys.stderr)
        return 0
    mutate = os.environ.get("STIGLITZ_GQL_MUTATE", "") == "1"
    profile = os.environ.get("STIGLITZ_PROFILE", "staging")
    findings = run(messages, tok_a, tok_b, outdir, mutate=mutate, profile=profile)
    print(f"  [{'✓' if findings else '○'}] GraphQL authz: {len(findings)} finding(s) → graphql_authz.json")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

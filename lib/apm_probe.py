#!/usr/bin/env python3
"""
apm_probe.py — detecção de Elastic APM Server com ingestão/config sem autenticação.

Gap coberto: o ZAP spider só acha a raiz `/` (APM Server é API pura, sem HTML),
o nuclei não tem template p/ "APM unauth ingestion" (exige POST NDJSON) e nenhuma
outra fase faz POST de probe no intake. Este módulo fecha esse buraco com um probe
DETERMINÍSTICO e NÃO-DESTRUTIVO.

Núcleo puro (fingerprint + classificadores, testável sem rede) + orquestração de
rede fina (curl via netproxy/mtls, injetável). Espelha oauth_audit.py / bola.py.
Findings em EN (deliverable); console/comentários PT-BR.

Prova sem poluir PROD: o POST usa NDJSON INVÁLIDO de propósito — o parser do APM
rejeita por schema (HTTP 400, `"accepted":0`) ANTES de indexar. A distinção
400/200-sem-auth vs 401-com-token-inválido é conclusiva sem enviar evento válido
(um evento válido seria 202 e seria indexado).

Uso (CLI): python3 lib/apm_probe.py <scan_dir> <target_url>
"""
import os
import sys
import json
import urllib.parse

import netproxy
import mtls

try:
    from fingerprint import fingerprint as _fingerprint
    from vuln_catalog import CATALOG as _CATALOG
except Exception:  # importado fora de lib/
    def _fingerprint(f):
        return "0" * 16
    _CATALOG = {}

# Caminhos fixos do Elastic APM Server.
INTAKE_PATH = "/intake/v2/events"
CONFIG_PATH = "/config/v1/agents?service.name=stiglitz-probe"
# NDJSON deliberadamente inválido (sem o objeto metadata completo): o parser do APM
# devolve 400 de validação ("accepted":0) sem indexar nada. NUNCA enviar evento válido.
INVALID_NDJSON = '{"metadata":{"stiglitz":"probe"}}\n'
_PROBE_TOKEN = "Bearer stiglitz-invalid-probe"


# ── Fingerprint do APM Server ─────────────────────────────────────────────────
def looks_like_apm(intake_status, intake_body, config_status):
    """True se as respostas do intake/config têm a assinatura de um Elastic APM Server."""
    b = (intake_body or "").lower()
    if "<html" in b:
        return False
    # corpo de validação característico do intake do APM
    if "accepted" in b or "validation error" in b:
        return True
    # 202 Accepted no intake
    if intake_status == 202:
        return True
    # caminho de auth do APM: intake e config exigem credencial
    if intake_status in (401, 403) and config_status in (401, 403):
        return True
    return False


# ── Classificadores (puros) ───────────────────────────────────────────────────
def classify_intake(noauth_status, noauth_body, badtoken_status):
    """Veredito sobre ingestão sem auth no /intake/v2/events.

    CONFIRMED  — sem credencial o servidor PROCESSA (200/202, ou 400 de schema do APM);
    REJECTED   — sem credencial recebe 401/403 (ingestão protegida);
    INCONCLUSIVE — sinal ambíguo (400 genérico, host fora do ar, etc.).
    """
    b = (noauth_body or "").lower()
    if noauth_status in (401, 403):
        return {"state": "REJECTED",
                "evidence": f"intake without auth -> HTTP {noauth_status} (authentication required)"}
    apm_processed = noauth_status in (200, 202) or (
        noauth_status == 400 and ("accepted" in b or "validation error" in b))
    if not apm_processed:
        return {"state": "INCONCLUSIVE",
                "evidence": f"intake without auth -> HTTP {noauth_status}"}
    if badtoken_status in (401, 403):
        return {"state": "CONFIRMED",
                "evidence": (f"intake without auth -> HTTP {noauth_status} (processed); "
                             f"with invalid bearer -> HTTP {badtoken_status} (anonymous ingestion enabled)")}
    return {"state": "CONFIRMED",
            "evidence": (f"intake without auth -> HTTP {noauth_status} (processed); "
                         "no authentication layer enforced")}


def classify_config(noauth_status, badtoken_status):
    """Veredito sobre o /config/v1/agents acessível sem auth (central config dos agentes)."""
    if noauth_status in (401, 403):
        return {"state": "REJECTED",
                "evidence": f"agent config without auth -> HTTP {noauth_status}"}
    if noauth_status == 200 and badtoken_status in (401, 403):
        return {"state": "CONFIRMED",
                "evidence": (f"agent config without auth -> HTTP 200; "
                             f"with invalid bearer -> HTTP {badtoken_status}")}
    return {"state": "INCONCLUSIVE",
            "evidence": f"agent config without auth -> HTTP {noauth_status}"}


# ── Findings ──────────────────────────────────────────────────────────────────
def _finding(klass, url, name, severity, description, remediation, evidence=""):
    """Schema do finding (igual oauth_audit + cwe + fingerprint). Texto em EN."""
    f = {
        "tool": "apm_probe", "type": klass, "source": "APM Probe",
        "name": name, "url": url, "severity": severity,
        "description": description, "remediation": remediation,
        "evidence": evidence, "cwe": _CATALOG.get(klass, {}).get("cwe", ""),
    }
    f["fingerprint"] = _fingerprint(f)
    return f


def _dedup(findings):
    seen, out = set(), []
    for f in findings:
        fp = f.get("fingerprint")
        if fp in seen:
            continue
        seen.add(fp)
        out.append(f)
    return out


def build_findings(intake_verdict, config_verdict, target):
    """Converte vereditos CONFIRMED em findings (EN). Não-CONFIRMED é descartado.

    Cada finding aponta para o endpoint exato afetado (intake vs config) — preciso
    no relatório e dá fingerprints distintos (mesmo CWE-306 no mesmo host)."""
    base = (target or "").rstrip("/")
    out = []
    if (intake_verdict or {}).get("state") == "CONFIRMED":
        out.append(_finding(
            "apm_unauth_ingestion", base + "/intake/v2/events",
            "APM Server accepts telemetry ingestion without authentication", "high",
            "The Elastic APM Server intake endpoint (/intake/v2/events) processes event "
            "payloads without requiring a secret token or API key: an unauthenticated request "
            "reaches schema validation instead of being rejected, while the same request with "
            "an invalid bearer token is rejected with HTTP 401 — confirming anonymous ingestion "
            "is enabled. Any unauthenticated client can submit forged telemetry, poisoning the "
            "dashboards and alerting the team relies on for incident detection, and can inflate "
            "Elasticsearch storage and cost with arbitrary event volume.",
            "Configure apm-server.auth.secret_token (or API keys) and require it for ingestion. "
            "Disable anonymous access (apm-server.auth.anonymous.enabled: false); if RUM needs "
            "anonymous access, restrict it with anonymous.allow_service and rate limits.",
            evidence=intake_verdict.get("evidence", "")))
    if (config_verdict or {}).get("state") == "CONFIRMED":
        out.append(_finding(
            "apm_central_config_exposed", base + "/config/v1/agents",
            "APM agent central configuration readable without authentication", "medium",
            "The APM Server agent central configuration endpoint (/config/v1/agents) returns "
            "HTTP 200 to unauthenticated requests while rejecting requests bearing an invalid "
            "token (HTTP 401). This serves agent/service configuration and enables enumeration "
            "of service names without credentials.",
            "Require authentication for the APM Server (secret_token/API key) and disable "
            "anonymous access so agent configuration is not served to unauthenticated clients.",
            evidence=config_verdict.get("evidence", "")))
    return _dedup(out)


# ── Rede (injetável) ──────────────────────────────────────────────────────────
def send_request(method, url, headers, data, timeout=15):
    """Envia uma requisição via curl (herda proxy/mTLS). Retorna (status, body).

    Não segue redirect; não verifica TLS (-k) — o alvo pode ter cert próprio.
    """
    import subprocess
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return (0, "")
    cmd = ["curl", *netproxy.curl_proxy_args(), *mtls.curl_cert_args(),
           "-sk", "-S", "--max-time", str(timeout),
           "-o", "-", "-w", "\n__HTTP_STATUS__:%{http_code}", "-X", method]
    for k, v in (headers or {}).items():
        cmd += ["-H", f"{k}: {v}"]
    if data is not None:
        cmd += ["--data-binary", data]
    cmd += ["--", url]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 5)
        raw = p.stdout or ""
    except Exception:
        return (0, "")
    status, body = 0, raw
    sm = raw.rfind("__HTTP_STATUS__:")
    if sm != -1:
        body = raw[:sm].rstrip("\n")
        try:
            status = int(raw[sm:].split(":", 1)[1].strip())
        except (ValueError, IndexError):
            status = 0
    return (status, body)


def probe_endpoints(base_url, send_fn=send_request, timeout=15):
    """Sonda intake e config (com e sem credencial). Retorna dict de (status, body)."""
    base = (base_url or "").rstrip("/")
    intake_url = base + INTAKE_PATH
    config_url = base + CONFIG_PATH
    ndjson = {"Content-Type": "application/x-ndjson"}
    ndjson_auth = dict(ndjson, **{"Authorization": _PROBE_TOKEN})
    return {
        "intake_noauth": send_fn("POST", intake_url, ndjson, INVALID_NDJSON, timeout),
        "intake_badtoken": send_fn("POST", intake_url, ndjson_auth, INVALID_NDJSON, timeout),
        "config_noauth": send_fn("GET", config_url, {}, None, timeout),
        "config_badtoken": send_fn("GET", config_url, {"Authorization": _PROBE_TOKEN}, None, timeout),
    }


# ── Orquestração ──────────────────────────────────────────────────────────────
def run(scan_dir, target, send_fn=send_request, timeout=15):
    """Roda o probe, grava raw/apm_probe.json (findings), retorna {findings, summary}.

    Fail-safe: só emite finding quando o host tem assinatura de APM Server E o
    veredito é CONFIRMED. Caso contrário é no-op silencioso.
    """
    r = probe_endpoints(target, send_fn=send_fn, timeout=timeout)
    intake_noauth_s, intake_noauth_b = r["intake_noauth"]
    intake_bad_s, _ = r["intake_badtoken"]
    config_noauth_s, _ = r["config_noauth"]
    config_bad_s, _ = r["config_badtoken"]

    is_apm = looks_like_apm(intake_noauth_s, intake_noauth_b, config_noauth_s)
    intake_v = {"state": "INCONCLUSIVE", "evidence": ""}
    config_v = {"state": "INCONCLUSIVE", "evidence": ""}
    findings = []
    if is_apm:
        intake_v = classify_intake(intake_noauth_s, intake_noauth_b, intake_bad_s)
        config_v = classify_config(config_noauth_s, config_bad_s)
        findings = build_findings(intake_v, config_v, target)

    summary = {"is_apm": is_apm, "intake": intake_v.get("state"),
               "config": config_v.get("state"), "total": len(findings)}

    raw_dir = os.path.join(scan_dir, "raw")
    try:
        os.makedirs(raw_dir, exist_ok=True)
        with open(os.path.join(raw_dir, "apm_probe.json"), "w", encoding="utf-8") as fh:
            json.dump(findings, fh, indent=2, ensure_ascii=False)
    except Exception as exc:
        print(f"  aviso: não foi possível gravar apm_probe.json: {exc}", file=sys.stderr)
    return {"findings": findings, "summary": summary}


# ── CLI ───────────────────────────────────────────────────────────────────────
def main(argv):
    if len(argv) >= 4 and argv[1] == "run":
        scan_dir, target = argv[2], argv[3]
    elif len(argv) >= 3:
        scan_dir, target = argv[1], argv[2]
    else:
        print("uso: apm_probe.py <scan_dir> <target_url>", file=sys.stderr)
        return 2
    res = run(scan_dir, target)
    s = res["summary"]
    if s["is_apm"]:
        print(f"  apm-probe: APM Server detectado | intake={s['intake']} "
              f"config={s['config']} → {s['total']} finding(s)")
    else:
        print("  apm-probe: alvo não parece um APM Server — nenhum probe aplicável")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

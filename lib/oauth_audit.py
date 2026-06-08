#!/usr/bin/env python3
"""
oauth_audit.py — auditoria ATIVA de OAuth 2.0 / OIDC (P1, fase P9.6).

Núcleo puro (parse de well-known/ZAP, análise de params, builders de probe,
classifiers de resposta) testável sem rede + orquestração de rede fina
(fetch well-known + envio de probe via curl, injetável). Espelha jwt_audit.py
e bola.py. Findings em EN, schema do jwt_audit + fingerprint.

Descoberta passiva roda sempre; probes ativos exigem flag --oauth-active e,
mesmo assim, viram dry-run sob STIGLITZ_PROFILE=production.
"""
import sys
import os
import re
import json
import urllib.parse

WELL_KNOWN_PATHS = (
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
)

try:
    from bola import parse_zap_messages
except Exception:  # importado fora de lib/
    def parse_zap_messages(_):
        return []

try:
    from fingerprint import fingerprint as _fingerprint
    from vuln_catalog import CATALOG as _CATALOG
except Exception:
    def _fingerprint(f):
        return "0" * 16
    _CATALOG = {}


_AUTHORIZE_HINT = re.compile(r'/(?:oauth2?/)?(?:authorize|auth)\b|[?&]response_type=', re.I)


def parse_well_known(json_text):
    """Normaliza o JSON do .well-known. JSON inválido/não-dict → {}."""
    try:
        d = json.loads(json_text or "")
    except Exception:
        return {}
    if not isinstance(d, dict):
        return {}

    def _list(k):
        v = d.get(k)
        return [str(x) for x in v] if isinstance(v, list) else []

    return {
        "authorization_endpoint": str(d.get("authorization_endpoint") or ""),
        "token_endpoint": str(d.get("token_endpoint") or ""),
        "response_types_supported": _list("response_types_supported"),
        "code_challenge_methods_supported": _list("code_challenge_methods_supported"),
        "grant_types_supported": _list("grant_types_supported"),
        "scopes_supported": _list("scopes_supported"),
    }


def parse_authorize_requests(zap_messages_text):
    """Extrai fluxos /authorize observados no dump do ZAP. Reusa bola.parse_zap_messages."""
    flows = []
    for r in parse_zap_messages(zap_messages_text):
        url = r.get("url") or ""
        if not _AUTHORIZE_HINT.search(url):
            continue
        q = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)

        def g(k):
            v = q.get(k)
            return v[0] if v else ""

        flows.append({
            "authorize_url": url,
            "client_id": g("client_id"),
            "redirect_uri": g("redirect_uri"),
            "response_type": g("response_type"),
            "state": g("state"),
            "nonce": g("nonce"),
            "code_challenge": g("code_challenge"),
            "code_challenge_method": g("code_challenge_method"),
            "scope": g("scope"),
        })
    return flows


def _finding(klass, url, name, severity, description, remediation, evidence=""):
    """Schema do finding (igual jwt_audit + cwe + fingerprint). Texto em EN."""
    f = {
        "tool": "oauth_audit", "type": klass, "source": "OAuth Audit",
        "name": name, "url": url, "severity": severity,
        "description": description, "remediation": remediation,
        "evidence": evidence, "cwe": _CATALOG.get(klass, {}).get("cwe", ""),
    }
    f["fingerprint"] = _fingerprint(f)
    return f


def _dedup(findings):
    """Remove duplicatas por fingerprint, preservando ordem."""
    seen, out = set(), []
    for f in findings:
        fp = f.get("fingerprint")
        if fp in seen:
            continue
        seen.add(fp)
        out.append(f)
    return out


def static_findings(wellknown, flows, target):
    """Findings derivados sem rede do well-known + fluxos observados."""
    out = []
    wk = wellknown or {}
    rts = [r.lower() for r in wk.get("response_types_supported", [])]
    ccm = [m.lower() for m in wk.get("code_challenge_methods_supported", [])]

    if any("token" in rt.split() for rt in rts):
        out.append(_finding(
            "oauth_implicit_flow", wk.get("authorization_endpoint") or target,
            "Implicit flow enabled (response_type=token advertised)", "medium",
            "The authorization server advertises the implicit grant (response_type=token), "
            "which returns the access_token in the URL fragment where it leaks via browser "
            "history, Referer headers and logs.",
            "Disable the implicit grant; use authorization code flow with PKCE."))

    if wk.get("authorization_endpoint"):
        if not ccm:
            out.append(_finding(
                "oauth_pkce_missing", wk.get("authorization_endpoint"),
                "PKCE not advertised by the authorization server", "high",
                "code_challenge_methods_supported is absent from the discovery document; "
                "the server likely does not enforce PKCE, exposing public clients to "
                "authorization code interception.",
                "Advertise and enforce PKCE with the S256 method for all clients."))
        elif ccm == ["plain"]:
            out.append(_finding(
                "oauth_pkce_downgrade", wk.get("authorization_endpoint"),
                "Only the 'plain' PKCE method is supported", "medium",
                "The server advertises only code_challenge_method=plain, which provides no "
                "protection if the authorization request is observed.",
                "Support and require the S256 PKCE method; reject 'plain'."))

    for f in flows:
        au = f.get("authorize_url") or target
        rt = (f.get("response_type") or "").lower().split()
        if "token" in rt:
            out.append(_finding(
                "oauth_implicit_flow", au,
                "Implicit flow observed in live request (response_type=token)", "medium",
                "An observed /authorize request uses response_type=token; the access_token "
                "is returned in the URL fragment and leaks via history/Referer/logs.",
                "Migrate the client to authorization code flow with PKCE.",
                evidence=f"response_type={f.get('response_type')}"))
        if "code" in rt and not f.get("code_challenge"):
            out.append(_finding(
                "oauth_pkce_missing", au,
                "Authorization code request without PKCE", "high",
                "An observed code-flow /authorize request carries no code_challenge, so the "
                "client is not protected against authorization code interception.",
                "Send and enforce a code_challenge (S256) on every code-flow request.",
                evidence="no code_challenge in request"))
        if (f.get("code_challenge_method") or "").lower() == "plain":
            out.append(_finding(
                "oauth_pkce_downgrade", au,
                "PKCE downgrade observed (code_challenge_method=plain)", "medium",
                "An observed request uses code_challenge_method=plain instead of S256.",
                "Use and require S256.", evidence="code_challenge_method=plain"))
        if rt and not f.get("state"):
            out.append(_finding(
                "oauth_missing_state", au,
                "OAuth request without state parameter", "medium",
                "An observed /authorize request omits the state parameter, exposing the flow "
                "to login CSRF / authorization response fixation.",
                "Send an unguessable state on every request and validate it on callback.",
                evidence="no state parameter"))
        if "openid" in (f.get("scope") or "").lower().split() and not f.get("nonce"):
            out.append(_finding(
                "oauth_missing_nonce", au,
                "OIDC request without nonce", "low",
                "An OpenID Connect request (scope=openid) omits nonce, allowing id_token replay.",
                "Send and validate a nonce for OIDC requests.", evidence="no nonce parameter"))
        if (f.get("redirect_uri") or "").startswith("http://"):
            out.append(_finding(
                "oauth_redirect_uri", au,
                "OAuth redirect_uri uses cleartext HTTP", "high",
                "An observed redirect_uri uses http://, so the authorization code/token can be "
                "intercepted on the network.",
                "Register and require https:// redirect URIs only.",
                evidence=f"redirect_uri={f.get('redirect_uri')}"))
    return _dedup(out)


def _with_query(url, params):
    """Reescreve a query da URL com params (descarta valores vazios)."""
    s = urllib.parse.urlsplit(url)
    q = urllib.parse.urlencode({k: v for k, v in params.items() if v != ""})
    return urllib.parse.urlunsplit((s.scheme, s.netloc, s.path, q, ""))


def build_redirect_uri_probes(authorize_url, params, canary):
    """Variações maliciosas de redirect_uri apontando ao host canary (sentinela)."""
    host = urllib.parse.urlsplit(canary).netloc or canary
    legit = params.get("redirect_uri", "")
    legit_host = urllib.parse.urlsplit(legit).netloc
    # Only variants whose real destination host IS the canary can be confirmed by the
    # Location-host classifier: external (destination = canary), subdomain_suffix
    # (destination = target.com.canary, a subdomain of canary), and userinfo
    # (https://target.com@canary → real host is canary via authority confusion).
    # path_traversal (/cb/../canary normalises back to target.com) and
    # open_redirect_param (?next=canary is second-order) never make the destination
    # the canary, so they are dropped to avoid noise.
    variants = {
        "external": canary,
        "subdomain_suffix": f"https://{legit_host}.{host}/cb" if legit_host else canary,
        "userinfo": f"https://{legit_host}@{host}/cb" if legit_host else canary,
    }
    probes = []
    for label, evil in variants.items():
        p = dict(params)
        p["redirect_uri"] = evil
        probes.append({"label": f"redirect_uri:{label}",
                       "url": _with_query(authorize_url, p),
                       "expected_marker": host, "kind": "redirect"})
    return probes


def build_pkce_missing_probe(authorize_url, params):
    """Code flow sem code_challenge — testa se o servidor aceita (PKCE não enforçado)."""
    p = dict(params)
    p["response_type"] = "code"
    p.pop("code_challenge", None)
    p.pop("code_challenge_method", None)
    return {"label": "pkce:missing", "url": _with_query(authorize_url, p), "kind": "pkce"}


def build_pkce_downgrade_probe(authorize_url, params):
    """Code flow com code_challenge_method=plain — testa downgrade."""
    p = dict(params)
    p["response_type"] = "code"
    p["code_challenge"] = p.get("code_challenge") or "plainchallenge"
    p["code_challenge_method"] = "plain"
    return {"label": "pkce:downgrade", "url": _with_query(authorize_url, p), "kind": "pkce"}


def _loc_host(location):
    # .hostname (não .netloc) — ignora userinfo/porta, então o probe
    # userinfo (https://target.com@canary/cb) resolve para o host real = canary.
    return urllib.parse.urlsplit(location or "").hostname or ""


def classify_redirect_response(status, location, canary_host):
    """CONFIRMED se o servidor redireciona para o host canary; REJECTED se nega; senão INCONCLUSIVE."""
    loc = location or ""
    host = _loc_host(loc)
    if host and (host == canary_host or host.endswith("." + canary_host)):
        return {"state": "CONFIRMED", "evidence": f"Location -> {loc[:120]}"}
    low = loc.lower()
    if status in (400, 401, 403) or "invalid_redirect" in low or "invalid_request" in low:
        return {"state": "REJECTED", "evidence": f"status={status} {loc[:80]}"}
    return {"state": "INCONCLUSIVE", "evidence": f"status={status} location={loc[:80]}"}


def classify_pkce_response(status, location, body):
    """CONFIRMED se um authorization code é emitido sem PKCE válido; REJECTED se o servidor exige PKCE."""
    loc = location or ""
    b = body or ""
    loc_qs = urllib.parse.parse_qs(urllib.parse.urlsplit(loc).query)
    if "code" in loc_qs or '"code"' in b or '"access_token"' in b:
        return {"state": "CONFIRMED", "evidence": f"code issued (status={status})"}
    low = (loc + " " + b).lower()
    if status in (400, 401, 403) or "code_challenge" in low or "pkce" in low:
        return {"state": "REJECTED", "evidence": f"status={status}"}
    return {"state": "INCONCLUSIVE", "evidence": f"status={status}"}


def active_findings(probe_verdicts, target):
    """Converte (probe, verdict) CONFIRMED em findings. Não-CONFIRMED é descartado."""
    out = []
    for probe, verdict in probe_verdicts:
        if verdict.get("state") != "CONFIRMED":
            continue
        kind = probe.get("kind")
        ev = verdict.get("evidence", "")
        if kind == "redirect":
            out.append(_finding(
                "oauth_redirect_uri", target,
                "redirect_uri validation bypass confirmed (open redirect / code theft)", "high",
                "The authorization server accepted an attacker-controlled redirect_uri and "
                "redirected to it. An attacker can steal the authorization code/token and take "
                "over the victim's account.",
                "Enforce exact-match allow-listing of registered redirect URIs; reject any "
                "unregistered value. No substring/subdomain/path matching.",
                evidence=f"{probe.get('label')} | {ev}"))
        elif kind == "pkce":
            klass = "oauth_pkce_missing" if probe.get("label") == "pkce:missing" else "oauth_pkce_downgrade"
            out.append(_finding(
                klass, target,
                "PKCE not enforced — authorization code issued without valid PKCE", "high",
                "The authorization server issued an authorization code for a request that "
                "lacked a valid S256 code_challenge, leaving public clients open to "
                "authorization code interception.",
                "Require and validate a S256 code_challenge for every authorization code "
                "request; reject 'plain' and missing challenges.",
                evidence=f"{probe.get('label')} | {ev}"))
    return _dedup(out)


def fetch_well_known(base_url, timeout=15):
    """GET nos paths .well-known. Retorna o primeiro corpo JSON não-vazio, ou ''."""
    import urllib.request
    base = base_url.rstrip("/")
    for path in WELL_KNOWN_PATHS:
        try:
            req = urllib.request.Request(base + path, headers={"Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read().decode("utf-8", errors="replace")
            if body.strip():
                return body
        except Exception:
            continue
    return ""


def send_probe(probe, timeout=15):
    """Envia o probe via curl SEM seguir redirect (lê o Location cru). Retorna (status, location, body)."""
    import subprocess
    url = probe.get("url") or ""
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return (0, "", "")
    cmd = ["curl", "-s", "-S", "--max-time", str(timeout), "-o", "-",
           "-w", "\n__HTTP_STATUS__:%{http_code}\n__LOCATION__:%{redirect_url}", "--", url]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 5)
        raw = p.stdout or ""
    except Exception:
        return (0, "", "")
    status, location, body = 0, "", raw
    sm = raw.rfind("__HTTP_STATUS__:")
    if sm != -1:
        body = raw[:sm].rstrip("\n")
        tail = raw[sm:]
        for line in tail.splitlines():
            if line.startswith("__HTTP_STATUS__:"):
                try:
                    status = int(line.split(":", 1)[1].strip())
                except ValueError:
                    status = 0
            elif line.startswith("__LOCATION__:"):
                location = line.split(":", 1)[1].strip()
    return (status, location, body)


def run(scan_dir, active=False, profile=None, well_known_text=None, zap_text=None,
        client_id="", authorize_url="", redirect_uri="", canary=None, target="",
        send_fn=send_probe):
    """Orquestra a fase P9.6. Passivo sempre; ativo só com active=True e profile!=production.
    well_known_text/zap_text injetáveis (testes); em produção real são lidos do disco/rede pelo caller."""
    canary = canary or os.environ.get("STIGLITZ_OAUTH_CANARY_URI") or "https://oauth-probe.invalid/cb"
    wk = parse_well_known(well_known_text or "")
    flows = parse_authorize_requests(zap_text or "")

    findings = static_findings(wk, flows, target or authorize_url)
    passive_n = len(findings)

    authorize_url = authorize_url or wk.get("authorization_endpoint") or ""
    if not client_id and flows:
        client_id = flows[0].get("client_id", "")
    if not redirect_uri and flows:
        redirect_uri = flows[0].get("redirect_uri", "")

    dry_run = active and (profile or "").lower() == "production"
    do_active = active and not dry_run and bool(authorize_url) and bool(client_id)

    params = {"client_id": client_id, "response_type": "code",
              "scope": (flows[0].get("scope") if flows else "") or "openid",
              "state": "stiglitz", "redirect_uri": redirect_uri}

    if active and not do_active and not dry_run:
        print("  [!] oauth-audit: probes ativos pulados (sem authorize_url/client_id)")

    if dry_run:
        print("  [i] oauth-audit: probes ativos em dry-run (STIGLITZ_PROFILE=production)")

    if do_active:
        probes = build_redirect_uri_probes(authorize_url, params, canary)
        pkce_missing = build_pkce_missing_probe(authorize_url, params)
        pkce_down = build_pkce_downgrade_probe(authorize_url, params)
        canary_host = urllib.parse.urlsplit(canary).netloc
        verdicts = []
        for pr in probes:
            status, loc, body = send_fn(pr)
            verdicts.append((pr, classify_redirect_response(status, loc, canary_host)))
        for pr in (pkce_missing, pkce_down):
            status, loc, body = send_fn(pr)
            verdicts.append((pr, classify_pkce_response(status, loc, body)))
        findings += active_findings(verdicts, target or authorize_url)
        findings = _dedup(findings)

    summary = {"passive": passive_n, "active": do_active, "dry_run": dry_run,
               "total": len(findings)}
    raw_dir = os.path.join(scan_dir, "raw")
    try:
        os.makedirs(raw_dir, exist_ok=True)
        with open(os.path.join(raw_dir, "oauth_findings.json"), "w", encoding="utf-8") as fh:
            json.dump(findings, fh, indent=2, ensure_ascii=False)
    except Exception as exc:
        print(f"  aviso: não foi possível gravar oauth_findings.json: {exc}", file=sys.stderr)
    return {"findings": findings, "summary": summary}


def _read(path):
    try:
        with open(path, encoding="utf-8", errors="ignore") as fh:
            return fh.read()
    except Exception:
        return ""


def main(argv):
    """CLI: oauth_audit.py run <scan_dir> [--well-known F] [--zap F] [--active]
    [--profile P] [--target URL] [--authorize-url URL]. Segredos via env STIGLITZ_OAUTH_*."""
    if len(argv) < 3 or argv[1] != "run":
        print("uso: oauth_audit.py run <scan_dir> [--well-known F] [--zap F] "
              "[--active] [--profile P] [--target URL] [--authorize-url URL]", file=sys.stderr)
        return 2
    scan_dir = argv[2]
    opts = {"--well-known": "", "--zap": "", "--profile": os.environ.get("STIGLITZ_PROFILE", ""),
            "--target": "", "--authorize-url": os.environ.get("STIGLITZ_OAUTH_AUTHORIZE_URL", "")}
    active = "--active" in argv
    i = 3
    while i < len(argv):
        if argv[i] in opts and i + 1 < len(argv):
            opts[argv[i]] = argv[i + 1]
            i += 2
        else:
            i += 1
    wk_text = _read(opts["--well-known"]) if opts["--well-known"] else ""
    if not wk_text and opts["--target"]:
        wk_text = fetch_well_known(opts["--target"])
    zap_text = _read(opts["--zap"]) if opts["--zap"] else ""
    res = run(scan_dir, active=active, profile=opts["--profile"] or None,
              well_known_text=wk_text, zap_text=zap_text,
              client_id=os.environ.get("STIGLITZ_OAUTH_CLIENT_ID", ""),
              authorize_url=opts["--authorize-url"],
              redirect_uri=os.environ.get("STIGLITZ_OAUTH_REDIRECT_URI", ""),
              target=opts["--target"])
    s = res["summary"]
    print(f"  oauth-audit: {s['total']} finding(s) ({s['passive']} passivo, "
          f"ativo={s['active']}, dry_run={s['dry_run']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

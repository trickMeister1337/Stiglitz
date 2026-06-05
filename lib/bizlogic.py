#!/usr/bin/env python3
"""
bizlogic.py — Detecções de lógica de negócio/authz (red team autorizado).

Spec-driven: lê um config (JSON nativo ou YAML opcional) com contas de teste e
endpoints-alvo, executa testes estruturados e seguros (IDOR read/write, privesc,
amount tampering, race/idempotency), e emite findings com vuln_class p/ o motor
de criticidade. Mutações são gated por profile + sentinela + RoE.

Console PT-BR; campos de evidência em EN (padrão deliverable do suite).
"""
import argparse
import json
import os
import re
import sys
import threading
import urllib.error
import urllib.request
from urllib.parse import urlparse

REQUIRED_TOP = ("base_url", "accounts", "endpoints")

# Mutação real só nestes profiles; production sempre dry-run.
_MUTATE_PROFILES = {"lab", "staging"}
_RACE_WORKERS = {"lab": 10, "staging": 5, "production": 1}

# Escopo ativo durante run() — validado por requisição (defesa-em-profundidade),
# além do pré-check em base_url. Também bloqueia redirects para hosts fora do escopo.
_ACTIVE_SCOPE = None


class _ScopedRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Não segue redirects para hosts fora do escopo ativo."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if _ACTIVE_SCOPE and not _in_scope(newurl, _ACTIVE_SCOPE):
            return None  # redirect off-scope → não seguir
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_OPENER = urllib.request.build_opener(_ScopedRedirectHandler())


def load_config(path):
    """Carrega config de .json (stdlib) ou .yaml/.yml (PyYAML, se instalado)."""
    with open(path, encoding="utf-8") as f:
        text = f.read()
    if path.endswith((".yaml", ".yml")):
        try:
            import yaml
        except ImportError:
            raise ValueError("Config YAML requer PyYAML; use .json ou instale PyYAML.")
        cfg = yaml.safe_load(text)
    else:
        cfg = json.loads(text)
    validate_config(cfg)
    return cfg


def validate_config(cfg):
    """Valida campos obrigatórios; levanta ValueError com mensagem clara."""
    if not isinstance(cfg, dict):
        raise ValueError("Config deve ser um objeto.")
    for k in REQUIRED_TOP:
        if k not in cfg:
            raise ValueError(f"Config sem campo obrigatório: {k}")
    if not isinstance(cfg["accounts"], dict) or not cfg["accounts"]:
        raise ValueError("Config precisa de 'accounts' como objeto não vazio (mapa nome→conta).")
    for _name, _acct in cfg["accounts"].items():
        if not isinstance(_acct, dict):
            raise ValueError(f"Conta '{_name}' deve ser um objeto.")
    if not isinstance(cfg["endpoints"], list) or not cfg["endpoints"]:
        raise ValueError("Config precisa de 'endpoints' (lista não vazia).")
    for ep in cfg["endpoints"]:
        for k in ("name", "method", "path", "tests"):
            if k not in ep:
                raise ValueError(f"Endpoint sem campo '{k}': {ep!r}")


def auth_headers(account):
    """Constrói os headers de autenticação de uma conta."""
    auth = account.get("auth", {})
    t = auth.get("type")
    if t == "bearer":
        return {"Authorization": f"Bearer {auth['token']}"}
    if t == "cookie":
        return {"Cookie": auth["cookie"]}
    if t == "header":
        return dict(auth.get("headers", {}))
    raise ValueError(f"Tipo de auth desconhecido: {t!r}")


class Response:
    """Resposta HTTP simplificada."""
    __slots__ = ("status", "body", "headers")

    def __init__(self, status, body, headers):
        self.status = status
        self.body = body
        self.headers = headers


def http_request(method, url, headers, body, timeout=15):
    """Faz uma requisição HTTP via urllib. Nunca levanta por status != 2xx.

    Reforça o escopo por requisição: se houver escopo ativo e a URL estiver fora,
    a requisição NÃO é enviada (Response status=0, body=__out_of_scope__).
    """
    if _ACTIVE_SCOPE and not _in_scope(url, _ACTIVE_SCOPE):
        return Response(0, "__out_of_scope__", {})
    data = None
    hdrs = dict(headers or {})
    if body is not None:
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        hdrs.setdefault("Content-Type", "application/json")
    req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
    try:
        with _OPENER.open(req, timeout=timeout) as resp:
            raw = resp.read().decode(errors="replace")
            return Response(resp.status, raw, dict(resp.headers))
    except urllib.error.HTTPError as e:
        raw = e.read().decode(errors="replace") if e.fp else ""
        return Response(e.code, raw, dict(e.headers or {}))
    except (urllib.error.URLError, OSError) as e:
        return Response(0, f"__error__:{e}", {})


# Campos dinâmicos que variam entre requisições e não indicam dados distintos.
_DYNAMIC_KEYS = re.compile(r"(ts|time|timestamp|date|req_id|request_id|trace|nonce|"
                           r"etag|expires|iat|exp)", re.IGNORECASE)


def _strip_dynamic(obj):
    """Remove recursivamente chaves dinâmicas de um objeto JSON decodificado."""
    if isinstance(obj, dict):
        return {k: _strip_dynamic(v) for k, v in sorted(obj.items())
                if not _DYNAMIC_KEYS.fullmatch(k)}
    if isinstance(obj, list):
        return [_strip_dynamic(v) for v in obj]
    return obj


def responses_equivalent(body_a, body_b):
    """True se dois corpos JSON representam os mesmos dados (ignora campos dinâmicos).

    Usado no IDOR read: se a conta B recebe um corpo equivalente ao baseline da
    conta A, houve exposição cross-user.
    """
    try:
        ja = _strip_dynamic(json.loads(body_a))
        jb = _strip_dynamic(json.loads(body_b))
        return ja == jb
    except (ValueError, TypeError):
        # Fallback não-JSON: comparação literal após strip de espaços.
        return body_a.strip() == body_b.strip()


def _resolve(template, values):
    """Resolve placeholders {k} recursivamente em strings dentro de dict/list/escalar."""
    if isinstance(template, dict):
        return {k: _resolve(v, values) for k, v in template.items()}
    if isinstance(template, list):
        return [_resolve(v, values) for v in template]
    if isinstance(template, str):
        for ph, val in values.items():
            template = template.replace("{" + ph + "}", str(val))
        return template
    return template


def _unresolved_placeholders(obj):
    """Lista placeholders {x} ainda não resolvidos em um body (recursivo)."""
    return re.findall(r"\{[A-Za-z_]\w*\}", json.dumps(obj, ensure_ascii=False))


def tamper_variations(base_body, money_params, sentinel):
    """Gera corpos com valores adulterados nos money_params (placeholders resolvidos)."""
    resolved = _resolve(base_body, sentinel)
    bad_values = ["-0.01", "0", "0.001", "abc", "1e9"]
    variations = []
    for p in money_params:
        for bad in bad_values:
            v = dict(resolved)
            v[p] = bad
            variations.append(v)
    return variations


def detect_double_spend(statuses, allowed=1):
    """True se mais respostas de sucesso (2xx) do que o permitido (double-spend).

    Tolera entradas None (worker que falhou) — contam como não-sucesso.
    """
    ok = sum(1 for s in statuses if s is not None and 200 <= s < 300)
    return ok > allowed


def _body_signals_error(body):
    """Heurística: True se o corpo (mesmo com HTTP 2xx) indica rejeição/erro.

    Muitas APIs devolvem 200 com {"error": ...} para validação de negócio. Usado
    no amount tampering para não confirmar adulteração que o servidor rejeitou no corpo.
    """
    try:
        j = json.loads(body)
    except (ValueError, TypeError):
        low = (body or "").lower()
        return any(m in low for m in ('"error"', "invalid", "denied", "rejected"))
    if isinstance(j, dict):
        for k in ("error", "errors", "message", "detail"):
            v = j.get(k)
            if v:  # campo de erro presente e não-vazio/não-falso
                return True
    return False


def _account(cfg, name):
    return cfg["accounts"][name]


def _url(cfg, ep, values):
    return cfg["base_url"].rstrip("/") + _resolve({"_": ep["path"]}, values)["_"]


def _finding(name, vuln_class, url, method, confirmed, evidence, severity="high"):
    return {"name": name, "vuln_class": vuln_class, "url": url, "method": method,
            "severity": severity, "confirmed": confirmed, "tool": "bizlogic",
            "evidence": evidence}


def test_idor_read(cfg, ep):
    """A pega o próprio recurso (baseline); B pede o MESMO recurso de A.
    Confirma se B recebe 2xx com corpo equivalente ao baseline."""
    owner = ep["object_of"]
    owner_id = _account(cfg, owner)["id"]
    url = _url(cfg, ep, {"id": owner_id, "owner": owner_id})

    base = http_request("GET", url, auth_headers(_account(cfg, owner)), None)
    if not (200 <= base.status < 300):
        return None  # baseline não acessível — nada a comparar

    other = "B" if owner != "B" else "A"
    victimless = http_request("GET", url, auth_headers(_account(cfg, other)), None)
    confirmed = (200 <= victimless.status < 300
                 and responses_equivalent(base.body, victimless.body))
    if not confirmed:
        return None
    return _finding(f"IDOR read: {ep['name']}", "idor_read_pii", url, "GET", True,
                    {"baseline_account": owner, "cross_account": other,
                     "baseline_status": base.status, "cross_status": victimless.status,
                     "response_excerpt": victimless.body[:400]})


def test_privesc(cfg, ep, actor="A", mutate_allowed=False, dry_run=True):
    """Ator não-privilegiado acessa endpoint privilegiado. 2xx → confirmado.

    GET é read-only (sempre executa). Métodos mutantes (POST/PUT/DELETE/PATCH)
    respeitam o gating: em dry_run ou sem permissão, emite finding potencial
    SEM enviar a requisição (mesmo padrão das demais famílias mutantes).
    """
    url = _url(cfg, ep, {"id": _account(cfg, actor).get("id", ""), "owner": ""})
    method = (ep["method"] or "GET").upper()
    if method != "GET" and (dry_run or not mutate_allowed):
        return _finding(f"Privilege escalation (dry-run): {ep['name']}", "priv_escalation",
                        url, ep["method"], False,
                        {"note": "dry-run — método mutante não enviado", "actor": actor,
                         "would_send": ep.get("body")})
    r = http_request(ep["method"], url, auth_headers(_account(cfg, actor)),
                     ep.get("body"))
    if not (200 <= r.status < 300):
        return None
    return _finding(f"Privilege escalation: {ep['name']}", "priv_escalation", url,
                    ep["method"], True,
                    {"actor": actor, "status": r.status, "response_excerpt": r.body[:400]})


def test_idor_write(cfg, ep, mutate_allowed, dry_run):
    """B muta o recurso de A. Mutating → respeita gating.
    Em dry_run: monta a request e marca como potencial (não envia a mutação)."""
    owner = ep["object_of"]
    owner_id = _account(cfg, owner)["id"]
    url = _url(cfg, ep, {"id": owner_id, "owner": owner_id})
    other = "B" if owner != "B" else "A"
    if dry_run or not mutate_allowed:
        return _finding(f"IDOR write (dry-run): {ep['name']}", "idor_write", url,
                        ep["method"], False,
                        {"note": "dry-run — mutação não enviada", "cross_account": other,
                         "would_send": ep.get("body")})
    # Baseline do dono (A) ANTES da escrita, para confirmar persistência da mutação.
    before = http_request("GET", url, auth_headers(_account(cfg, owner)), None)
    r = http_request(ep["method"], url, auth_headers(_account(cfg, other)), ep.get("body"))
    if not (200 <= r.status < 300):
        return None
    # Confirmação best-effort: re-lê o recurso como A; só confirma se o estado mudou.
    after = http_request("GET", url, auth_headers(_account(cfg, owner)), None)
    state_changed = (200 <= before.status < 300 and 200 <= after.status < 300
                     and not responses_equivalent(before.body, after.body))
    if not state_changed:
        # 2xx na escrita, mas a re-leitura do dono não confirmou mudança (no-op/escopo
        # silencioso/sem GET) → rebaixa para potencial, evitando falso positivo confirmado.
        return _finding(f"IDOR write (potencial): {ep['name']}", "idor_write", url,
                        ep["method"], False,
                        {"note": "escrita aceitou 2xx mas re-leitura do dono não confirmou mudança",
                         "cross_account": other, "write_status": r.status,
                         "owner_reread_status": after.status})
    return _finding(f"IDOR write: {ep['name']}", "idor_write", url, ep["method"], True,
                    {"cross_account": other, "write_status": r.status,
                     "owner_reread_status": after.status,
                     "response_excerpt": after.body[:400]})


def test_amount_tampering(cfg, ep, actor, mutate_allowed, dry_run):
    """Envia variações adulteradas de valor (sentinela). Aceito sem validação → confirma."""
    if "sentinel" not in cfg:
        raise ValueError("amount_tampering exige 'sentinel' no config.")
    url = _url(cfg, ep, {"owner": _account(cfg, actor).get("id", "")})
    variations = tamper_variations(ep.get("body", {}), ep.get("money_params", []),
                                   cfg["sentinel"])
    if dry_run or not mutate_allowed:
        return _finding(f"Amount tampering (dry-run): {ep['name']}", "amount_tampering",
                        url, ep["method"], False,
                        {"note": "dry-run — variações não enviadas",
                         "variations": variations[:5]})
    accepted = []
    for body in variations:
        r = http_request(ep["method"], url, auth_headers(_account(cfg, actor)), body)
        # Aceito de verdade só se 2xx E o corpo não sinaliza rejeição (200+{"error":...}).
        if 200 <= r.status < 300 and not _body_signals_error(r.body):
            accepted.append({"body": body, "status": r.status})
    if not accepted:
        return None
    return _finding(f"Amount tampering: {ep['name']}", "amount_tampering", url,
                    ep["method"], True,
                    {"accepted_variations": accepted[:5], "total_accepted": len(accepted)})


def test_race(cfg, ep, actor, workers, mutate_allowed, dry_run):
    """Dispara N requisições concorrentes da mesma operação sentinela.
    Mais de uma 2xx além do permitido → double-spend."""
    if "sentinel" not in cfg:
        raise ValueError("race exige 'sentinel'.")
    url = _url(cfg, ep, {"owner": _account(cfg, actor).get("id", "")})
    body = _resolve(ep.get("body", {}), cfg["sentinel"])
    if dry_run or not mutate_allowed:
        return _finding(f"Race condition (dry-run): {ep['name']}", "race_condition_funds",
                        url, ep["method"], False, {"note": "dry-run", "workers": workers})
    results = [0] * workers  # worker que falhar fica 0 (não-sucesso), nunca None
    hdrs = auth_headers(_account(cfg, actor))

    def worker(i):
        try:
            results[i] = http_request(ep["method"], url, hdrs, body).status
        except Exception:
            results[i] = 0

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(workers)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    if not detect_double_spend(results, allowed=1):
        return None
    return _finding(f"Race condition: {ep['name']}", "race_condition_funds", url,
                    ep["method"], True,
                    {"workers": workers, "statuses": results,
                     "success_count": sum(1 for s in results if 200 <= s < 300)})


def test_idempotency(cfg, ep, actor, mutate_allowed, dry_run):
    """Reenvia a mesma requisição com a MESMA Idempotency-Key. Processada 2× → falha."""
    if "sentinel" not in cfg:
        raise ValueError("idempotency exige 'sentinel'.")
    hdr_name = ep.get("idempotency_header", "Idempotency-Key")
    url = _url(cfg, ep, {"owner": _account(cfg, actor).get("id", "")})
    body = _resolve(ep.get("body", {}), cfg["sentinel"])
    if dry_run or not mutate_allowed:
        return _finding(f"Idempotency replay (dry-run): {ep['name']}",
                        "race_condition_funds", url, ep["method"], False,
                        {"note": "dry-run"})
    hdrs = dict(auth_headers(_account(cfg, actor)))
    hdrs[hdr_name] = "stiglitz-idem-canary-1"
    r1 = http_request(ep["method"], url, hdrs, body)
    r2 = http_request(ep["method"], url, hdrs, body)
    # Falha de idempotência: ambas processadas (2xx) em vez de a 2ª retornar 409/cacheado.
    if not (200 <= r1.status < 300 and 200 <= r2.status < 300):
        return None
    return _finding(f"Idempotency replay: {ep['name']}", "race_condition_funds", url,
                    ep["method"], True,
                    {"first_status": r1.status, "second_status": r2.status,
                     "idempotency_header": hdr_name})


def _in_scope(url, scope):
    if not scope:
        return True
    host = urlparse(url).hostname or ""
    return any(host == s or host.endswith("." + s) for s in scope)


def run(config, profile="staging", scope=None, outdir=None):
    """Executa os testes declarados, respeitando profile/escopo. Retorna findings.

    profile: lab/staging → mutação real (contra sentinela); production → dry-run.
    scope: lista de domínios permitidos; URLs fora são puladas.
    """
    validate_config(config)
    mutate_allowed = profile in _MUTATE_PROFILES
    dry_run = not mutate_allowed
    workers = _RACE_WORKERS.get(profile, 1)
    findings = []

    if not _in_scope(config["base_url"], scope):
        return findings

    global _ACTIVE_SCOPE
    _ACTIVE_SCOPE = scope  # reforço por requisição dentro de http_request
    try:
        for ep in config["endpoints"]:
            for test in ep.get("tests", []):
                try:
                    if test == "idor_read":
                        f = test_idor_read(config, ep)
                    elif test == "idor_write":
                        f = test_idor_write(config, ep, mutate_allowed, dry_run)
                    elif test == "privesc":
                        f = test_privesc(config, ep, mutate_allowed=mutate_allowed,
                                         dry_run=dry_run)
                    elif test == "amount_tampering":
                        f = test_amount_tampering(config, ep, "A", mutate_allowed, dry_run)
                    elif test == "race":
                        f = test_race(config, ep, "A", workers, mutate_allowed, dry_run)
                    elif test == "idempotency":
                        f = test_idempotency(config, ep, "A", mutate_allowed, dry_run)
                    else:
                        continue
                except (ValueError, KeyError, TypeError) as e:
                    print(f"  [!] bizlogic: teste {test} em {ep.get('name')} pulado: {e}")
                    continue
                if f:
                    findings.append(f)
    finally:
        _ACTIVE_SCOPE = None

    if outdir:
        os.makedirs(os.path.join(outdir, "raw"), exist_ok=True)
        with open(os.path.join(outdir, "raw", "bizlogic.json"), "w", encoding="utf-8") as fh:
            json.dump(findings, fh, ensure_ascii=False, indent=2)
    return findings


def roe_gate(assume_yes=False, interactive=None):
    """Confirma autorização antes de testes mutantes. Fail-safe sem TTY/consentimento."""
    if assume_yes:
        return True
    if interactive is None:
        interactive = sys.stdin.isatty()
    print("\n  [RoE] TESTES DE LÓGICA DE NEGÓCIO MUTANTES — uso autorizado apenas")
    if not interactive:
        print("  [RoE] Sem confirmação e sem terminal — abortando mutação.")
        return False
    try:
        return input("  [RoE] Digite EU AUTORIZO para confirmar: ").strip() == "EU AUTORIZO"
    except EOFError:
        return False


def parse_args(argv=None):
    p = argparse.ArgumentParser(description="Detecções de lógica de negócio/authz (red team autorizado).")
    p.add_argument("--config", required=True, help="bizlogic.yaml ou .json")
    p.add_argument("--profile", default="staging", choices=["lab", "staging", "production"])
    p.add_argument("--scope", default="", help="domínios permitidos (separados por vírgula)")
    p.add_argument("--outdir", default=None)
    p.add_argument("--roe-accept", action="store_true", help="auto-confirma o gate RoE (CI/RoE prévio)")
    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    cfg = load_config(args.config)
    scope = [s.strip() for s in args.scope.split(",") if s.strip()]

    # Gate só é exigido quando o profile permite mutação.
    if args.profile in _MUTATE_PROFILES:
        if not roe_gate(assume_yes=args.roe_accept):
            print("  [!] Autorização negada — abortando.")
            return 1

    findings = run(cfg, profile=args.profile, scope=scope, outdir=args.outdir)
    confirmed = sum(1 for f in findings if f["confirmed"])
    print(f"  [✓] bizlogic: {len(findings)} finding(s), {confirmed} confirmado(s).")
    return 0


if __name__ == "__main__":
    sys.exit(main())

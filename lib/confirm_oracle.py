#!/usr/bin/env python3
"""
confirm_oracle.py — oráculos de confirmação diferencial (red team autorizado).

Item #1 do ROADMAP-analyst-parity.md. Captura a técnica nº1 de um analista black-box:
NÃO confiar no veredito da ferramenta — rodar o experimento de controle e comparar.

Um finding candidato só é CONFIRMED quando um par diferencial mostra que o efeito é
atribuível à SEMÂNTICA do payload:
  - `ataque`  : requisição com o payload que DEVERIA disparar a vuln;
  - `controle`: requisição benigna do MESMO formato que NÃO deveria disparar.

Cláusula-de-controle (o coração): se ataque e controle produzem o MESMO efeito
(ambos 401/403, ambos a mesma página de bloqueio, ambos o mesmo erro genérico),
não há diferencial → REJECTED. Isso generaliza o insight do zap_authgate p/ qualquer
classe, sem precisar de um FP-reducer dedicado por classe.

Núcleo puro (decisão + detectores de efeito, testável sem rede) + orquestração fina
injetável (`send_fn`, padrão apm_probe.py/bola.py). Findings/evidence em EN (deliverable);
console/comentários PT-BR. Sem domínio hardcoded, sem rede no núcleo.

Uso (CLI): python3 lib/confirm_oracle.py redirect <base_url> <location>
           python3 lib/confirm_oracle.py db-error <body-file>
"""
import re
import sys
import json
from urllib.parse import urljoin, urlsplit


# ── Decisão central (cláusula-de-controle) ────────────────────────────────────
def differential_verdict(attack_signal, control_signal, cls):
    """Decide confirmação a partir do par (ataque, controle).

    Cada `*_signal` é um dict {"signal": bool, "detail": str}. Retorna
    {state, confidence, class, note, evidence}:
      efeito no ataque ∧ ausente no controle → CONFIRMED  (conf 85)
      efeito no ataque ∧ presente no controle → REJECTED  (conf 30) — gate/WAF/eco
      sem efeito no ataque                    → REJECTED  (conf 10)
    """
    a = bool(attack_signal.get("signal"))
    c = bool(control_signal.get("signal"))
    a_detail = attack_signal.get("detail", "")
    c_detail = control_signal.get("detail", "")
    if a and not c:
        return {"state": "CONFIRMED", "confidence": 85, "class": cls,
                "note": "Efeito no ataque, ausente no controle — atribuível ao payload",
                "evidence": f"attack: {a_detail}; control: {c_detail}"}
    if a and c:
        return {"state": "REJECTED", "confidence": 30, "class": cls,
                "note": ("Efeito também no controle (gate/WAF/eco genérico) — "
                         "não atribuível ao payload"),
                "evidence": f"attack: {a_detail}; control (same effect): {c_detail}"}
    return {"state": "REJECTED", "confidence": 10, "class": cls,
            "note": "Sem sinal diferencial no ataque",
            "evidence": f"attack: {a_detail}"}


# ── Open redirect: resolve o host efetivo e as evasões clássicas ──────────────
def redirect_effective_host(base_url, location):
    """Hostname que um browser realmente alcançaria ao seguir `location`, ou None.

    Cobre as evasões clássicas: protocol-relative (`//evil`), backslash na
    autoridade (`/\\evil` → `//evil`), userinfo (`target@evil` → host=evil),
    e resolução relativa a `base_url`. Path relativo same-site devolve o host base.
    """
    if not location:
        return None
    # Browsers tratam '\' como '/' na autoridade — normaliza antes de parsear.
    norm = location.replace("\\", "/")
    try:
        host = urlsplit(urljoin(base_url, norm)).hostname
    except ValueError:
        return None
    return host.lower() if host else None


def is_offsite_redirect(base_url, location, allow_hosts=()):
    """True se `location` leva a um host fora do host base (e seus subdomínios).

    `allow_hosts` amplia o conjunto same-site (host igual ou subdomínio de qualquer
    allow). Location vazio/irresolvível → False (fail-safe: não inventa finding).
    """
    host = redirect_effective_host(base_url, location)
    if not host:
        return False
    base_host = (urlsplit(base_url).hostname or "").lower()
    allowed = {base_host} | {h.lower() for h in allow_hosts if h}
    for a in allowed:
        if a and (host == a or host.endswith("." + a)):
            return False
    return True


# ── SQLi error-based: assinaturas de erro de DB (baixo-FP) ────────────────────
_DB_ERROR_PATTERNS = [
    ("MySQL", re.compile(
        r"you have an error in your sql syntax|warning:\s*mysql|mysql_fetch|"
        r"supplied argument is not a valid mysql|mysqli?_", re.I)),
    ("MSSQL", re.compile(
        r"unclosed quotation mark|microsoft ole db|incorrect syntax near|"
        r"microsoft sql server|\[sql server\]", re.I)),
    ("PostgreSQL", re.compile(
        r"pg_query|pg::|syntax error at or near|unterminated quoted string at or near",
        re.I)),
    ("Oracle", re.compile(
        r"\bora-\d{5}\b|quoted string not properly terminated|oracle error", re.I)),
    ("SQLite", re.compile(
        r"sqlite_error|sqlite3?::|unrecognized token", re.I)),
]


def db_error_signature(body):
    """Detecta assinatura de erro de banco no corpo. {"signal","engine","detail"}."""
    text = body or ""
    for engine, rx in _DB_ERROR_PATTERNS:
        m = rx.search(text)
        if m:
            return {"signal": True, "engine": engine,
                    "detail": f"{engine} error signature: {m.group(0)!r}"}
    return {"signal": False, "engine": None, "detail": "no DB error signature"}


# ── Adaptadores de efeito (resposta → {signal, detail}) ───────────────────────
def _header_get(headers, name):
    """Lookup case-insensitive de header; None se ausente."""
    if not headers:
        return None
    name_l = name.lower()
    for k, v in headers.items():
        if k.lower() == name_l:
            return v
    return None


def redirect_effect(resp, base_url, allow_hosts=()):
    """Sinal de open redirect: status 3xx + Location off-site.

    `resp` = {"status", "headers", "body"}. Só conta como sinal um redirect real
    (3xx) para host fora de escopo — 200 com Location ou redirect same-site não disparam.
    """
    status = int(resp.get("status") or 0)
    location = _header_get(resp.get("headers"), "Location")
    is_3xx = 300 <= status < 400
    offsite = bool(location) and is_offsite_redirect(base_url, location, allow_hosts)
    if is_3xx and offsite:
        host = redirect_effective_host(base_url, location)
        return {"signal": True, "detail": f"HTTP {status} Location -> {host} (offsite)"}
    return {"signal": False, "detail": f"HTTP {status}; no offsite redirect"}


def sqli_error_effect(resp):
    """Sinal de SQLi error-based: assinatura de erro de DB no corpo da resposta."""
    sig = db_error_signature(resp.get("body"))
    return {"signal": sig["signal"], "detail": sig["detail"]}


# ── Orquestração fina (send_fn injetável, testável sem rede) ──────────────────
def run_differential(base_url, attack_req, control_req, effect_fn, send_fn, cls):
    """Executa o par ataque/controle via `send_fn` e devolve o veredito diferencial.

    `send_fn(req) -> {"status","headers","body"}` é injetável (sem rede no núcleo).
    `effect_fn(resp) -> {"signal","detail"}` mapeia a resposta ao sinal da classe.
    `base_url` é a âncora de escopo (usada pelos detectores via closure do chamador).
    """
    _ = base_url  # âncora de escopo; consumida pelo effect_fn do chamador
    eff_a = effect_fn(send_fn(attack_req))
    eff_c = effect_fn(send_fn(control_req))
    return differential_verdict(eff_a, eff_c, cls)


# ── CLI ───────────────────────────────────────────────────────────────────────
def _main(argv):
    if len(argv) >= 4 and argv[1] == "redirect":
        base_url, location = argv[2], argv[3]
        print(json.dumps({"effective_host": redirect_effective_host(base_url, location),
                          "offsite": is_offsite_redirect(base_url, location)}))
        return 0
    if len(argv) >= 3 and argv[1] == "db-error":
        with open(argv[2], encoding="utf-8", errors="replace") as fh:
            print(json.dumps(db_error_signature(fh.read())))
        return 0
    sys.stderr.write(
        "uso: confirm_oracle.py redirect <base_url> <location>\n"
        "     confirm_oracle.py db-error <body-file>\n")
    return 2


if __name__ == "__main__":
    sys.exit(_main(sys.argv))

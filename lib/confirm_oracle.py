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
from urllib.parse import urljoin, urlsplit, urlunsplit, parse_qsl, urlencode


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


def parse_header_block(raw_headers):
    """Converte o bloco cru de headers do `curl -D -` em dict (última ocorrência vence).

    Ignora a status line (`HTTP/...`) e linhas de continuação (indentadas). Pareado
    com o `parse_http_response` do poc_validator, que devolve os headers como string.
    """
    out = {}
    for line in (raw_headers or "").splitlines():
        if not line or line[0] in " \t" or line.startswith("HTTP/") or ":" not in line:
            continue
        k, _, v = line.partition(":")
        out[k.strip()] = v.strip()
    return out


def _safe_int(value):
    """int tolerante — parse_http_response pode devolver '???'/'ERR'/'000'."""
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def redirect_effect(resp, base_url, allow_hosts=()):
    """Sinal de open redirect: status 3xx + Location off-site.

    `resp` = {"status", "headers", "body"}. Só conta como sinal um redirect real
    (3xx) para host fora de escopo — 200 com Location ou redirect same-site não disparam.
    Robusto a status não-numérico (string do parse_http_response) → tratado como 0.
    """
    status = _safe_int(resp.get("status"))
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


# ── Builder do probe de open redirect (monta ataque/controle) ────────────────
# Nomes convencionais de parâmetro que carregam destino de redirect.
_REDIRECT_PARAM_NAMES = {
    "next", "url", "redirect", "redirect_uri", "redirect_url", "redirecturl",
    "return", "return_url", "returnurl", "returnto", "return_to", "dest",
    "destination", "continue", "callback", "goto", "target", "rurl", "forward",
    "to", "u", "link", "checkout_url",
}


def _looks_like_redirect_value(v):
    """Heurística de formato: valor que parece um destino de navegação."""
    return (v or "").strip().startswith(("http://", "https://", "//", "/"))


def _pick_redirect_param(pairs):
    """Escolhe o parâmetro-alvo: nome convencional primeiro, senão valor com formato
    de destino. None se nenhum. Seleção errada é fail-safe: o ataque não vira offsite
    → oráculo devolve REJECTED (nunca inventa finding)."""
    for k, _v in pairs:
        if k.lower() in _REDIRECT_PARAM_NAMES:
            return k
    for k, v in pairs:
        if _looks_like_redirect_value(v):
            return k
    return None


def _rebuild_query(url, key, new_value):
    """`url` com o parâmetro `key` trocado por `new_value` (demais preservados)."""
    parts = urlsplit(url)
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    rebuilt = [(k, new_value if k == key else v) for k, v in pairs]
    return urlunsplit((parts.scheme, parts.netloc, parts.path,
                       urlencode(rebuilt), parts.fragment))


def build_redirect_variants(url, canary_host, method="GET", body=""):
    """(attack_req, control_req) | None — cada req é {"url","method","body"}.

    ataque   : parâmetro de redirect = `https://<canary_host>/` (destino externo);
    controle : mesmo parâmetro = `/` (path same-site, não deve virar offsite).
    O canary_host deve ser externo e inócuo (ex.: TLD reservado `.example`). None se
    nenhum parâmetro de redirect for identificado na query."""
    pairs = parse_qsl(urlsplit(url).query, keep_blank_values=True)
    key = _pick_redirect_param(pairs)
    if not key:
        return None
    attack = {"method": method, "body": body,
              "url": _rebuild_query(url, key, f"https://{canary_host}/")}
    control = {"method": method, "body": body,
               "url": _rebuild_query(url, key, "/")}
    return attack, control


# ── Builder do probe SQLi error-based (par ímpar/par de aspas) ────────────────
# Keywords que sinalizam o parâmetro que o nuclei já injetou com payload SQL.
_SQLI_KW = re.compile(
    r"(?:\bOR\b|\bAND\b|\bUNION\b|\bSELECT\b|\bWHERE\b|\bSLEEP\b|\bWAITFOR\b"
    r"|\bBENCHMARK\b|--|#|')", re.IGNORECASE)


def build_sqli_error_variants(url, method="GET", body=""):
    """(attack_req, control_req) | None — probe error-based diferencial.

    ataque   : valor-base + `'`  (nº ÍMPAR de aspas → quebra a sintaxe → erro de DB);
    controle : valor-base + `''` (nº PAR → aspas balanceadas → sem erro).
    Se o erro só aparece no ataque, é atribuível à injeção (não a página que sempre
    erra). Alvo: o parâmetro que carrega keyword SQL (payload do nuclei); senão o 1º.
    None se a query não tiver parâmetros."""
    pairs = parse_qsl(urlsplit(url).query, keep_blank_values=True)
    if not pairs:
        return None
    key, base = next(((k, v) for k, v in pairs if _SQLI_KW.search(v or "")), pairs[0])
    # Remove o payload que o nuclei já injetou (do 1º delimitador em diante).
    base_clean = re.sub(r"['\"].*$", "", base or "") or "1"
    attack = {"method": method, "body": body,
              "url": _rebuild_query(url, key, base_clean + "'")}
    control = {"method": method, "body": body,
               "url": _rebuild_query(url, key, base_clean + "''")}
    return attack, control


# ── LFI / path traversal: assinatura de arquivo de sistema (baixo-FP) ─────────
_LFI_PARAM_HINTS = ("../", "..\\", "%2e%2e", "/etc/", "passwd", "boot.ini", "win.ini")
_PASSWD_RX = re.compile(r"root:.*?:0:0:")
_WINI_RX = re.compile(r"\[extensions\]|for 16-bit app support|\[boot loader\]", re.I)
_LFI_DEPTH = "../" * 8


def passwd_signature(body):
    """Assinatura inequívoca de arquivo de sistema lido via traversal. {"signal","detail"}."""
    text = body or ""
    m = _PASSWD_RX.search(text)
    if m:
        return {"signal": True, "detail": f"unix passwd signature: {m.group(0)[:60]!r}"}
    m = _WINI_RX.search(text)
    if m:
        return {"signal": True, "detail": f"windows ini/boot signature: {m.group(0)[:60]!r}"}
    return {"signal": False, "detail": "no system-file signature"}


def lfi_effect(resp):
    """Sinal de LFI: assinatura de arquivo de sistema no corpo da resposta."""
    return passwd_signature(resp.get("body"))


def _pick_lfi_param(pairs):
    """Param cujo valor parece payload de traversal (do nuclei); senão o 1º."""
    for k, v in pairs:
        if any(h in (v or "").lower() for h in _LFI_PARAM_HINTS):
            return k
    return pairs[0][0] if pairs else None


def build_lfi_variants(url, method="GET", body=""):
    """(attack, control) | None — probe LFI diferencial.

    ataque : param = traversal profundo -> etc/passwd (arquivo real);
    controle: MESMA profundidade -> nome inexistente (etc/stiglitz_absent_zzz).
    Assinatura só-no-ataque é atribuível à leitura do arquivo real. None se a
    query não tiver parâmetros (fail-safe → oráculo ausente → fallback legado)."""
    pairs = parse_qsl(urlsplit(url).query, keep_blank_values=True)
    key = _pick_lfi_param(pairs)
    if not key:
        return None
    attack = {"method": method, "body": body,
              "url": _rebuild_query(url, key, _LFI_DEPTH + "etc/passwd")}
    control = {"method": method, "body": body,
               "url": _rebuild_query(url, key, _LFI_DEPTH + "etc/stiglitz_absent_zzz")}
    return attack, control


# ── SSTI: avaliação de template confirmada por aritmética (não-eco) ───────────
_SSTI_SYNTAXES = (("{{", "}}"), ("${", "}"), ("#{", "}"), ("<%=", "%>"))
_SSTI_A, _SSTI_B = 4111, 4093  # produto distinto e improvável: 16826323


def _detect_ssti_syntax(pairs):
    """(open, close) presente no valor de algum param (payload do nuclei); default {{ }}."""
    for _k, v in pairs:
        for op, cl in _SSTI_SYNTAXES:
            if op in (v or "") and cl in (v or ""):
                return op, cl
    return _SSTI_SYNTAXES[0]


def _pick_ssti_param(pairs):
    """Param cujo valor tem sintaxe de template; senão o 1º."""
    for k, v in pairs:
        for op, cl in _SSTI_SYNTAXES:
            if op in (v or "") and cl in (v or ""):
                return k
    return pairs[0][0] if pairs else None


def ssti_product_present(body, expected):
    """Sinal: produto aritmético presente no corpo (só se o template foi avaliado)."""
    text = body or ""
    if expected and expected in text:
        return {"signal": True, "detail": f"template evaluated: product {expected} present"}
    return {"signal": False, "detail": f"product {expected} absent"}


def ssti_effect(resp, expected):
    return ssti_product_present(resp.get("body"), expected)


def build_ssti_variants(url, method="GET", body=""):
    """(attack, control, expected) | None — probe SSTI diferencial.

    ataque : param = <op>A*B<cl> (templado) → corpo deve conter o produto A*B;
    controle: MESMA expressão A*B SEM delimitadores (literal, não avaliada).
    Motor de template → produto só no ataque. None se não houver parâmetro."""
    pairs = parse_qsl(urlsplit(url).query, keep_blank_values=True)
    key = _pick_ssti_param(pairs)
    if not key:
        return None
    op, cl = _detect_ssti_syntax(pairs)
    expr = f"{_SSTI_A}*{_SSTI_B}"
    expected = str(_SSTI_A * _SSTI_B)
    attack = {"method": method, "body": body,
              "url": _rebuild_query(url, key, f"{op}{expr}{cl}")}
    control = {"method": method, "body": body,
               "url": _rebuild_query(url, key, expr)}
    return attack, control, expected


# ── Command injection (in-band): resultado computado por `expr` (não-eco) ─────
# Unix. Windows (set /a) é follow-up anotado.
_CMDI_SEP = ";"
_CMDI_A, _CMDI_B = 1000000, 337  # resultado distinto: 1000337


def cmdi_result_present(body, expected):
    """Sinal: resultado aritmético presente no corpo (só se o comando executou)."""
    text = body or ""
    if expected and expected in text:
        return {"signal": True, "detail": f"command executed: result {expected} present"}
    return {"signal": False, "detail": f"result {expected} absent"}


def cmdi_effect(resp, expected):
    return cmdi_result_present(resp.get("body"), expected)


def _pick_cmdi_param(pairs):
    return pairs[0][0] if pairs else None


def build_cmdi_variants(url, method="GET", body=""):
    """(attack, control, expected) | None — probe cmd-injection diferencial (unix).

    ataque : param = <base>;expr A + B → corpo deve conter o resultado A+B;
    controle: <base>;expr A + (B-1) → resultado difere. Reflexão do payload
    mostraria 'expr A + B' (não o resultado) em ambos. None se não houver param."""
    pairs = parse_qsl(urlsplit(url).query, keep_blank_values=True)
    key = _pick_cmdi_param(pairs)
    if not key:
        return None
    base = next((v for k, v in pairs if k == key), "") or "1"
    base_clean = re.sub(r"[;&|`$].*$", "", base) or "1"
    expected = str(_CMDI_A + _CMDI_B)
    attack = {"method": method, "body": body,
              "url": _rebuild_query(url, key,
                                    f"{base_clean}{_CMDI_SEP}expr {_CMDI_A} + {_CMDI_B}")}
    control = {"method": method, "body": body,
               "url": _rebuild_query(url, key,
                                     f"{base_clean}{_CMDI_SEP}expr {_CMDI_A} + {_CMDI_B - 1}")}
    return attack, control, expected


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

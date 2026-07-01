# tests/test_confirm_oracle.py
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
import confirm_oracle as co


BASE = "https://app.target.com/login"
CANARY = "stg-redir-canary.example"


# ── differential_verdict: o coração (cláusula-de-controle) ────────────────────
def test_verdict_confirmed_when_attack_fires_and_control_silent():
    v = co.differential_verdict(
        {"signal": True, "detail": "Location -> evil.com (offsite)"},
        {"signal": False, "detail": "no offsite redirect"},
        "open_redirect")
    assert v["state"] == "CONFIRMED"
    assert v["confidence"] == 85
    assert v["class"] == "open_redirect"


def test_verdict_rejected_when_control_also_fires():
    # efeito presente no ataque E no controle → gate/WAF/eco genérico, não atribuível
    v = co.differential_verdict(
        {"signal": True, "detail": "DB error"},
        {"signal": True, "detail": "DB error"},
        "sqli_error")
    assert v["state"] == "REJECTED"
    assert v["confidence"] == 30
    assert "controle" in v["note"].lower()


def test_verdict_rejected_when_attack_silent():
    v = co.differential_verdict(
        {"signal": False, "detail": "no signal"},
        {"signal": False, "detail": "no signal"},
        "open_redirect")
    assert v["state"] == "REJECTED"
    assert v["confidence"] == 10


# ── redirect_effective_host: resolve as evasões clássicas ─────────────────────
def test_effective_host_protocol_relative():
    assert co.redirect_effective_host(BASE, "//evil.com/x") == "evil.com"


def test_effective_host_relative_path_is_same_site():
    assert co.redirect_effective_host(BASE, "/dashboard") == "app.target.com"


def test_effective_host_userinfo_trick():
    # o browser navega p/ o host DEPOIS do @ — evil.com, não target
    assert co.redirect_effective_host(BASE, "https://app.target.com@evil.com/") == "evil.com"


def test_effective_host_backslash_trick():
    # backslash é tratado como '/' na autoridade → //evil.com
    assert co.redirect_effective_host(BASE, "/\\evil.com") == "evil.com"


def test_effective_host_empty_is_none():
    assert co.redirect_effective_host(BASE, "") is None


# ── is_offsite_redirect ───────────────────────────────────────────────────────
def test_offsite_external_host_true():
    assert co.is_offsite_redirect(BASE, "//evil.com/x") is True


def test_offsite_relative_path_false():
    assert co.is_offsite_redirect(BASE, "/account") is False


def test_offsite_subdomain_of_base_false():
    assert co.is_offsite_redirect(BASE, "https://api.app.target.com/x") is False


def test_offsite_allow_hosts_suppresses():
    assert co.is_offsite_redirect(BASE, "//partner.com/x", allow_hosts=("partner.com",)) is False


# ── db_error_signature ────────────────────────────────────────────────────────
def test_db_error_mysql():
    s = co.db_error_signature("You have an error in your SQL syntax; check the manual")
    assert s["signal"] is True
    assert s["engine"] == "MySQL"


def test_db_error_mssql():
    s = co.db_error_signature("Unclosed quotation mark after the character string ''.")
    assert s["signal"] is True
    assert s["engine"] == "MSSQL"


def test_db_error_oracle():
    s = co.db_error_signature("ORA-00933: SQL command not properly ended")
    assert s["signal"] is True
    assert s["engine"] == "Oracle"


def test_db_error_absent():
    s = co.db_error_signature("<html><body>Welcome back</body></html>")
    assert s["signal"] is False
    assert s["engine"] is None


# ── redirect_effect (adaptador resposta→sinal) ────────────────────────────────
def test_redirect_effect_offsite_3xx_signals():
    resp = {"status": 302, "headers": {"Location": "https://evil.com/"}, "body": ""}
    eff = co.redirect_effect(resp, BASE)
    assert eff["signal"] is True


def test_redirect_effect_same_site_no_signal():
    resp = {"status": 302, "headers": {"location": "/dashboard"}, "body": ""}
    eff = co.redirect_effect(resp, BASE)
    assert eff["signal"] is False


def test_redirect_effect_non_3xx_no_signal():
    resp = {"status": 200, "headers": {"Location": "https://evil.com/"}, "body": ""}
    eff = co.redirect_effect(resp, BASE)
    assert eff["signal"] is False


# ── run_differential (orquestração fina, send_fn injetável) ───────────────────
def test_run_differential_confirms_open_redirect():
    def fake_send(req):
        if req["mark"] == "attack":
            return {"status": 302, "headers": {"Location": "https://evil.com/"}, "body": ""}
        return {"status": 302, "headers": {"Location": "/dashboard"}, "body": ""}

    v = co.run_differential(
        BASE,
        {"mark": "attack"}, {"mark": "control"},
        lambda r: co.redirect_effect(r, BASE),
        fake_send, "open_redirect")
    assert v["state"] == "CONFIRMED"


def test_run_differential_rejects_when_page_always_errors():
    # SQLi error-based FP: a página SEMPRE mostra erro de DB (ataque e controle)
    err = "You have an error in your SQL syntax"
    def fake_send(req):
        return {"status": 200, "headers": {}, "body": f"<html>{err}</html>"}

    v = co.run_differential(
        BASE,
        {"mark": "attack"}, {"mark": "control"},
        co.sqli_error_effect,
        fake_send, "sqli_error")
    assert v["state"] == "REJECTED"
    assert "controle" in v["note"].lower()


# ── build_redirect_variants (builder do probe de open redirect) ───────────────
def test_build_redirect_variants_named_param():
    v = co.build_redirect_variants("https://app.target.com/login?next=/home", CANARY)
    assert v is not None
    attack, control = v
    assert CANARY in attack["url"]
    assert CANARY not in control["url"]
    assert attack["url"] != control["url"]


def test_build_redirect_variants_value_shaped_param():
    # nome de param desconhecido, mas o valor é um path → detectado por formato
    v = co.build_redirect_variants("https://app.target.com/go?x=/dashboard", CANARY)
    assert v is not None
    attack, _control = v
    assert CANARY in attack["url"]


def test_build_redirect_variants_none_when_no_redirect_param():
    assert co.build_redirect_variants("https://app.target.com/search?q=hello", CANARY) is None


# ── parse_header_block (bloco cru do curl -D - → dict) ────────────────────────
def test_parse_header_block_extracts_location():
    raw = "HTTP/1.1 302 Found\r\nLocation: https://evil.com/\r\nContent-Length: 0"
    hd = co.parse_header_block(raw)
    assert hd["Location"] == "https://evil.com/"
    assert "302" not in hd            # a status line não vira header


# ── redirect_effect: robusto a status não-numérico do parse_http_response ─────
def test_redirect_effect_non_numeric_status_no_crash():
    resp = {"status": "???", "headers": {"Location": "https://evil.com/"}, "body": ""}
    eff = co.redirect_effect(resp, BASE)
    assert eff["signal"] is False


def test_run_differential_open_redirect_production_shape():
    # espelha o adapter do confirm_nuclei: status string + headers via parse_header_block
    def fake_send(req):
        if req["mark"] == "attack":
            raw = f"HTTP/1.1 302 Found\r\nLocation: https://{CANARY}/\r\n"
        else:
            raw = "HTTP/1.1 302 Found\r\nLocation: /dashboard\r\n"
        return {"status": "302", "headers": co.parse_header_block(raw), "body": ""}

    v = co.run_differential(
        BASE, {"mark": "attack"}, {"mark": "control"},
        lambda r: co.redirect_effect(r, BASE), fake_send, "open_redirect")
    assert v["state"] == "CONFIRMED"


# ── validators/redirect.py consumindo ctx["redir_oracle"] ─────────────────────
from validators.redirect import validate as _redir_validate


def _redir_ctx(**over):
    ctx = {"url": "https://app.target.com/login", "resp_body": "", "resp_headers": "",
           "status": "302", "patterns": {}, "redir_oracle": None}
    ctx.update(over)
    return ctx


def test_redirect_validator_confirms_on_oracle_confirmed():
    ctx = _redir_ctx(redir_oracle={"state": "CONFIRMED", "confidence": 85,
                                   "class": "open_redirect", "note": "x",
                                   "evidence": "Location -> evil (offsite)"})
    confirmed, conf, _note = _redir_validate(ctx)
    assert confirmed is True
    assert conf == 85


def test_redirect_validator_rejects_on_oracle_rejected():
    ctx = _redir_ctx(redir_oracle={"state": "REJECTED", "confidence": 30,
                                   "class": "open_redirect",
                                   "note": "efeito também no controle", "evidence": ""})
    confirmed, _conf, _note = _redir_validate(ctx)
    assert confirmed is False


def test_redirect_validator_legacy_fallback_without_oracle():
    # sem oráculo → lógica passiva legada (guarda de regressão)
    ctx = _redir_ctx(resp_headers="HTTP/1.1 302\nLocation: https://evil.com/x", redir_oracle=None)
    confirmed, _conf, _note = _redir_validate(ctx)
    assert confirmed is True

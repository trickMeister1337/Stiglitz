# tests/test_repro.py
import os, sys, json
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
import repro as R


def test_gate_high_and_critical_pass():
    assert R.passes_gate({"severity": "high"}) is True
    assert R.passes_gate({"severity": "critical"}) is True


def test_gate_confirmed_category_passes():
    assert R.passes_gate({"severity": "low", "confirmed_category": "exploit"}) is True
    assert R.passes_gate({"severity": "info", "confirmed_category": "verified"}) is True


def test_gate_confirmed_bool_passes():
    assert R.passes_gate({"severity": "low", "confirmed": True}) is True


def test_gate_info_low_without_confirmation_fail():
    assert R.passes_gate({"severity": "info"}) is False
    assert R.passes_gate({"severity": "low"}) is False


def test_gate_confirmed_false_does_not_pass():
    assert R.passes_gate({"severity": "low", "confirmed": False}) is False
    assert R.passes_gate({"severity": "info", "confirmed": "false"}) is False


def test_gate_confirmed_string_true_passes():
    assert R.passes_gate({"severity": "low", "confirmed": "true"}) is True


def test_sanitize_redacts_bearer():
    out, changed = R.sanitize_text("curl -H 'Authorization: Bearer eyJabc.def-123'")
    assert "eyJabc.def-123" not in out
    assert "<TOKEN_A>" in out
    assert changed is True


def test_sanitize_redacts_cookie():
    out, changed = R.sanitize_text("Cookie: session=deadbeef; other=1")
    assert "deadbeef" not in out
    assert "<SESSION>" in out
    assert changed is True


def test_sanitize_redacts_querystring_token():
    out, _ = R.sanitize_text("https://t/cb?code=SECRETCODE&state=x")
    assert "SECRETCODE" not in out


def test_sanitize_masks_valid_pan():
    out, changed = R.sanitize_text("card 4111111111111111 here")
    assert "4111111111111111" not in out
    assert "411111******1111" in out
    assert changed is True


def test_sanitize_masks_valid_cpf():
    out, changed = R.sanitize_text("cpf 529.982.247-25")
    assert "529.982.247-25" not in out
    assert changed is True


def test_sanitize_masks_email():
    out, changed = R.sanitize_text("contact joao.silva@acme.com now")
    assert "joao.silva@acme.com" not in out
    assert "@acme.com" in out
    assert changed is True


def test_sanitize_noop_returns_unchanged():
    out, changed = R.sanitize_text("nothing sensitive here")
    assert out == "nothing sensitive here"
    assert changed is False


def test_sanitize_redacts_basic_auth():
    out, changed = R.sanitize_text("Authorization: Basic dXNlcjpwYXNz")
    assert "dXNlcjpwYXNz" not in out
    assert changed is True


def test_sanitize_redacts_api_key_header():
    out, changed = R.sanitize_text("X-API-Key: sk_live_abc123DEF")
    assert "sk_live_abc123DEF" not in out
    assert changed is True


def test_sanitize_redacts_curl_cookie_flag():
    out, changed = R.sanitize_text("curl -b 'sid=deadbeef' https://t/")
    assert "deadbeef" not in out
    assert "<SESSION>" in out
    assert changed is True


def test_sanitize_redacts_querystring_password_and_apikey():
    out, _ = R.sanitize_text("https://t/login?password=hunter2&api_key=KEY123")
    assert "hunter2" not in out
    assert "KEY123" not in out


def test_sanitize_redacts_json_body_secret():
    out, changed = R.sanitize_text('{"client_secret":"shhh-very-secret","grant_type":"x"}')
    assert "shhh-very-secret" not in out
    assert "grant_type" in out
    assert changed is True


def test_sanitize_masks_pan_with_spaces():
    out, changed = R.sanitize_text("PAN 4111 1111 1111 1111 captured")
    assert "4111 1111 1111 1111" not in out
    assert "411111******1111" in out
    assert changed is True


def test_sanitize_masks_pan_with_hyphens():
    out, changed = R.sanitize_text("4111-1111-1111-1111")
    assert "4111-1111-1111-1111" not in out
    assert "411111******1111" in out


def test_sanitize_bearer_with_percent_does_not_leak_tail():
    out, _ = R.sanitize_text("Authorization: Bearer eyJ%41AA.bbb-ccc")
    assert "%41AA" not in out
    assert "bbb-ccc" not in out

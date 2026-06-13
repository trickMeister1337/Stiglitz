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


def test_sanitize_redacts_quoted_cookie_value_raw_header():
    out, changed = R.sanitize_text('Set-Cookie: jwt="eyJhbGciOiJ.xxx"; HttpOnly')
    assert "eyJhbGciOiJ.xxx" not in out
    assert changed is True


def test_sanitize_redacts_quoted_api_key_value():
    out, changed = R.sanitize_text('X-API-Key: "sk_live_abc"')
    assert "sk_live_abc" not in out
    assert changed is True


def test_sanitize_curl_header_flag_preserves_url():
    out, changed = R.sanitize_text("curl -H 'Cookie: session=abc' https://t/api")
    assert "session=abc" not in out
    assert "https://t/api" in out
    assert changed is True


def test_command_from_curl_field_priority():
    assert R._command_from_curl_field({"curl_command": "A", "curl": "B"}) == "A"
    assert R._command_from_curl_field({"curl": "B"}) == "B"
    assert R._command_from_curl_field({}) is None


def test_curl_from_request_block_parses():
    ev = "--- HTTP REQUEST ---\nGET /api/v1/users/123 HTTP/1.1\nHost: t.com\nAccept: */*\n\n"
    cmd = R._curl_from_request_block(ev, "")
    assert "curl" in cmd and "-X GET" in cmd
    assert "https://t.com/api/v1/users/123" in cmd
    assert "Accept: */*" in cmd


def test_curl_from_request_block_none_when_absent():
    assert R._curl_from_request_block("no block here", "") is None


def test_curl_from_request_block_absolute_form():
    ev = "--- HTTP REQUEST ---\nGET http://t.com/api/users HTTP/1.1\nHost: t.com\n\n"
    cmd = R._curl_from_request_block(ev, "")
    assert "http://t.com/api/users" in cmd
    assert "t.comhttp" not in cmd


def test_curl_from_request_block_with_body():
    ev = ('--- HTTP REQUEST ---\nPOST /login HTTP/1.1\nHost: t.com\n'
          'Content-Type: application/json\n\n{"user":"a","pass":"b"}')
    cmd = R._curl_from_request_block(ev, "")
    assert "-X POST" in cmd
    assert "--data '{\"user\":\"a\",\"pass\":\"b\"}'" in cmd


def test_curl_from_request_block_escapes_single_quote_in_path():
    ev = "--- HTTP REQUEST ---\nGET /search?q=it's HTTP/1.1\nHost: t.com\n\n"
    cmd = R._curl_from_request_block(ev, "")
    assert "'\\''" in cmd

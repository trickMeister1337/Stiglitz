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

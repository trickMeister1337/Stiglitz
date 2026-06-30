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


def test_classify_known_classes():
    assert R._classify({"vuln_type": "sqli"}) == "sqli"
    assert R._classify({"cve": "CWE-639", "name": "IDOR"}) == "bola_idor"
    assert R._classify({"name": "GraphQL introspection enabled"}) == "graphql_introspection"


def test_classify_unknown_is_generic():
    assert R._classify({"vuln_type": "zzz-unmapped"}) == "generic"


def test_class_templates_have_required_keys():
    for cls, tpl in R.CLASS_TEMPLATES.items():
        assert set(tpl) >= {"prerequisites", "steps", "command", "expected"}
        assert tpl["steps"] and tpl["command"] and tpl["expected"]


def test_classify_nosql_not_sqli():
    assert R._classify({"vuln_type": "nosql_injection"}) == "generic"
    assert R._classify({"template_id": "nosql-injection-mongodb"}) == "generic"


def test_classify_remaining_classes():
    assert R._classify({"name": "BFLA - broken function level authorization"}) == "bfla"
    assert R._classify({"cve": "CWE-918", "name": "SSRF"}) == "ssrf"
    assert R._classify({"vuln_type": "ssti"}) == "ssti"
    assert R._classify({"name": "Reflected XSS"}) == "xss"
    assert R._classify({"name": "OAuth redirect_uri not validated"}) == "oauth_redirect_uri"
    assert R._classify({"name": "Default login auth bypass"}) == "auth_bypass"
    assert R._classify({"name": "Missing security header: CSP"}) == "missing_security_header"
    assert R._classify({"name": "Weak TLS cipher"}) == "tls_weak"


def test_safe_note_for_money_url():
    note = R.safe_note({"url": "https://t/api/transfer", "name": "BOLA"}, "")
    assert note != ""


def test_safe_note_for_mutating_method():
    note = R.safe_note({"url": "https://t/api/x"}, "curl -i -s -X POST '<TARGET>'")
    assert note != ""


def test_no_safe_note_for_readonly_get():
    note = R.safe_note({"url": "https://t/api/profile", "name": "Missing header"},
                       "curl -sI '<TARGET>'")
    assert note == ""


def test_build_repro_none_when_gate_fails():
    assert R.build_repro({"severity": "info"}) is None


def test_build_repro_uses_captured_curl():
    f = {"severity": "high", "curl_command": "curl -i 'https://t/api'"}
    d = R.build_repro(f, raw=True)
    assert d["command"] == "curl -i 'https://t/api'"
    assert d["sanitized"] is False


def test_build_repro_builds_curl_from_request_block():
    ev = "--- HTTP REQUEST ---\nGET /api/v1/users/123 HTTP/1.1\nHost: t.com\n\n"
    d = R.build_repro({"severity": "high", "evidence": ev}, raw=True)
    assert "/api/v1/users/123" in d["command"]
    assert "t.com" in d["command"]


def test_build_repro_template_fallback():
    d = R.build_repro({"severity": "high", "vuln_type": "sqli"}, raw=True)
    assert d["command"] == R.CLASS_TEMPLATES["sqli"]["command"]
    assert d["expected"] == R.CLASS_TEMPLATES["sqli"]["expected"]
    assert d["steps"] == R.CLASS_TEMPLATES["sqli"]["steps"]


def test_build_repro_sanitizes_by_default():
    f = {"severity": "high", "curl_command": "curl -H 'Authorization: Bearer eyJsecret'"}
    d = R.build_repro(f)  # raw=False
    assert "eyJsecret" not in d["command"]
    assert d["sanitized"] is True


def test_build_repro_safe_note_on_money_endpoint():
    f = {"severity": "high", "url": "https://t/api/transfer", "vuln_type": "bola_idor"}
    d = R.build_repro(f, raw=True)
    assert d["safe_note"] != ""


def test_render_panel_empty_when_gate_fails():
    assert R.render_panel_html({"severity": "info"}, raw=True) == ""


def test_render_panel_contains_sections():
    out = R.render_panel_html({"severity": "high", "vuln_type": "sqli"}, raw=True)
    assert "How to Reproduce / Proof" in out
    assert "Expected Result" in out
    assert "<pre" in out
    assert "<ol" in out


def test_render_panel_sanitized_badge_and_no_leak():
    f = {"severity": "high", "curl_command": "curl -H 'Authorization: Bearer eyJsecret'"}
    out = R.render_panel_html(f, raw=False)
    assert "values sanitized" in out
    assert "eyJsecret" not in out


def test_cli_outputs_json(tmp_path):
    import subprocess
    p = tmp_path / "f.json"
    p.write_text(json.dumps({"severity": "high", "vuln_type": "sqli"}))
    repro_py = os.path.join(os.path.dirname(__file__), "..", "lib", "repro.py")
    r = subprocess.run([sys.executable, repro_py, str(p)],
                       capture_output=True, text=True)
    assert r.returncode == 0
    data = json.loads(r.stdout)
    assert data["expected"]


def test_render_panel_escapes_html_in_command():
    f = {"severity": "high",
         "curl_command": "curl 'https://t/?q=<script>alert(1)</script>'"}
    out = R.render_panel_html(f, raw=True)
    assert "<script>alert(1)</script>" not in out
    assert "&lt;script&gt;" in out


def test_cli_raw_env_disables_sanitization(tmp_path):
    import subprocess
    p = tmp_path / "f.json"
    p.write_text(json.dumps({"severity": "high",
                             "curl_command": "curl -H 'Authorization: Bearer eyJsecret'"}))
    repro_py = os.path.join(os.path.dirname(__file__), "..", "lib", "repro.py")
    env = dict(os.environ, STIGLITZ_REPRO_RAW="1")
    r = subprocess.run([sys.executable, repro_py, str(p)],
                       capture_output=True, text=True, env=env)
    assert r.returncode == 0
    assert "eyJsecret" in r.stdout


def test_cli_no_arg_exits_2():
    import subprocess
    repro_py = os.path.join(os.path.dirname(__file__), "..", "lib", "repro.py")
    r = subprocess.run([sys.executable, repro_py], capture_output=True, text=True)
    assert r.returncode == 2


# ── APM unauth ingestion ──────────────────────────────────────────────────────
def test_classify_apm_unauth_ingestion():
    f = {"type": "apm_unauth_ingestion",
         "name": "APM Server accepts telemetry ingestion without authentication"}
    assert R._classify(f) == "apm_unauth"


def test_repro_apm_uses_intake_post_template():
    f = {"type": "apm_unauth_ingestion", "severity": "high",
         "name": "APM Server accepts telemetry ingestion without authentication",
         "url": "https://apm.example.com/intake/v2/events"}
    data = R.build_repro(f)
    assert data is not None
    assert "/intake/v2/events" in data["command"]
    assert "POST" in data["command"].upper()
    # a prova é a distinção 400-sem-auth vs 401-com-token
    assert "401" in data["expected"]

import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
import poc_validator as pv  # noqa: E402
import validators  # noqa: E402


def test_template_injection_routes_to_ssti():
    assert pv.classify_vuln("ssti-detect", "Server-Side Template Injection", "ssti") == "ssti"
    assert pv.classify_vuln("x", "Template Injection", "template-injection") == "ssti"


def test_command_injection_routes_to_cmdi():
    assert pv.classify_vuln("cmd-inj", "OS Command Injection", "command-injection") == "cmdi"
    assert pv.classify_vuln("rce-x", "Remote Code Execution", "rce") == "cmdi"


def test_sqli_still_routes_to_sqli():
    assert pv.classify_vuln("sqli-error", "SQL Injection", "sqli") == "sqli"
    assert pv.classify_vuln("x", "UNION based", "union") == "sqli"


def test_ssti_and_cmdi_have_plugins():
    assert validators.get("ssti") is not None
    assert validators.get("cmdi") is not None


def _oracle_ctx(**over):
    ctx = {"url": "u", "resp_body": "", "resp_headers": "", "status": 200,
           "patterns": {}, "diff_changed": False, "diff_conf": 0, "diff_note": "",
           "auth_ev": [], "dc_result": None, "dc_bonus": 0, "method_results": {},
           "bool_pair": None, "canary": None, "redir_oracle": None,
           "sqli_oracle": None, "lfi_oracle": None,
           "ssti_oracle": None, "cmdi_oracle": None}
    ctx.update(over)
    return ctx


def test_ssti_validator_confirms_on_oracle():
    ok, conf, note = validators.get("ssti")(_oracle_ctx(
        ssti_oracle={"state": "CONFIRMED", "confidence": 90, "evidence": "product 16826323"}))
    assert ok is True and "oracle" in note.lower()


def test_cmdi_validator_confirms_on_oracle():
    ok, conf, note = validators.get("cmdi")(_oracle_ctx(
        cmdi_oracle={"state": "CONFIRMED", "confidence": 90, "evidence": "result 1000337"}))
    assert ok is True and "oracle" in note.lower()


def test_ssti_validator_falls_back_without_oracle():
    ok, _, _ = validators.get("ssti")(_oracle_ctx())
    assert ok is False

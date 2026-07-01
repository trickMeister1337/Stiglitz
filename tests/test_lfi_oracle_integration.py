import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
import validators  # noqa: E402
import poc_validator as pv  # noqa: E402


def _base_ctx(**over):
    ctx = {"url": "https://app.target.com/download?file=x", "resp_body": "",
           "resp_headers": "", "status": 200, "patterns": {},
           "diff_changed": False, "diff_conf": 0, "diff_note": "", "auth_ev": [],
           "dc_result": None, "dc_bonus": 0, "method_results": {},
           "bool_pair": None, "canary": None, "redir_oracle": None,
           "sqli_oracle": None, "lfi_oracle": None}
    ctx.update(over)
    return ctx


def test_lfi_validator_confirms_on_oracle():
    plugin = validators.get("lfi")
    ok, conf, note = plugin(_base_ctx(
        lfi_oracle={"state": "CONFIRMED", "confidence": 90,
                    "evidence": "attack: unix passwd signature; control: no signature"}))
    assert ok is True and conf >= 85 and "oracle" in note.lower()


def test_lfi_validator_falls_back_when_oracle_rejected():
    plugin = validators.get("lfi")
    # oráculo REJECTED + sem assinatura no corpo → fallback legado decide (False)
    ok, conf, _ = plugin(_base_ctx(
        lfi_oracle={"state": "REJECTED", "confidence": 30, "note": "no diff"},
        resp_body="<html>ok</html>"))
    assert ok is False


def test_lfi_validator_legacy_signature_still_works_without_oracle():
    plugin = validators.get("lfi")
    ctx = _base_ctx(resp_body="root:x:0:0:root:/root:/bin/bash",
                    patterns={"patterns": [r"root:.*:0:0:"]})
    ok, _, _ = plugin(ctx)
    assert ok is True


def test_validate_forwards_lfi_oracle_to_plugin():
    # prova o caminho validate() -> ctx -> plugin
    ok, _conf, note = pv.validate(
        "lfi", "https://app.target.com/download?file=x", "", "", 200,
        lfi_oracle={"state": "CONFIRMED", "confidence": 90, "evidence": "unix passwd signature"})
    assert ok is True and "oracle" in note.lower()

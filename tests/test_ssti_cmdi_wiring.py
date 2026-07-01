import inspect, os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
import poc_validator as pv  # noqa: E402


def test_validate_accepts_ssti_and_cmdi_oracle_kwargs():
    params = inspect.signature(pv.validate).parameters
    assert "ssti_oracle" in params and "cmdi_oracle" in params


def test_validate_passes_ssti_oracle_to_plugin():
    # oráculo CONFIRMED chega ao validador ssti via ctx
    ok, conf, note = pv.validate(
        "ssti", "https://app.target.com/greet?name=x", "", "", 200,
        ssti_oracle={"state": "CONFIRMED", "confidence": 90, "evidence": "product 16826323"})
    assert ok is True and "oracle" in note.lower()


def test_validate_cmdi_oracle_rejected_falls_back():
    ok, _, _ = pv.validate(
        "cmdi", "https://app.target.com/ping?host=x", "", "", 200,
        cmdi_oracle={"state": "REJECTED", "confidence": 30, "note": "no diff"})
    assert ok is False

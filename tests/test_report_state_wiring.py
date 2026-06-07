import os, sys, datetime
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
import finding_state as S

def test_report_helper_enriches_and_persists(tmp_path):
    findings = [{"fingerprint": "aaa", "severity": "high", "name": "X",
                 "url": "http://t/a"}]
    summary = S.apply_state(findings, target="ex.com", scan_id="scan_x",
                            today=datetime.date(2026, 6, 1), state_dir=str(tmp_path))
    assert findings[0]["state"]["status"] == "open"
    assert summary["open_total"] == 1
    assert S.load_store("ex.com", state_dir=str(tmp_path))["aaa"]["status"] == "open"

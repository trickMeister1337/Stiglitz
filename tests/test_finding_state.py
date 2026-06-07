import os, sys, datetime, json, tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
import finding_state as S

D = datetime.date

def _f(fp, sev="high", name="X", url="http://t/a"):
    return {"fingerprint": fp, "severity": sev, "name": name, "url": url}

def test_reconcile_new_finding_creates_open_entry():
    store, trans = S.reconcile({}, [_f("aaa")], today=D(2026, 6, 1), scan_id="s1")
    e = store["aaa"]
    assert e["status"] == "open"
    assert e["first_seen"] == "2026-06-01"
    assert e["last_seen"] == "2026-06-01"
    assert e["reopened_count"] == 0
    assert e["resolved_at"] is None
    assert e["history"][-1]["event"] == "new"
    assert {"fingerprint": "aaa", "event": "new", "severity": "high"} in trans

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

def test_reconcile_persistent_advances_last_seen_keeps_first():
    s1, _ = S.reconcile({}, [_f("aaa")], today=D(2026, 6, 1), scan_id="s1")
    s2, trans = S.reconcile(s1, [_f("aaa")], today=D(2026, 6, 5), scan_id="s2")
    assert s2["aaa"]["first_seen"] == "2026-06-01"
    assert s2["aaa"]["last_seen"] == "2026-06-05"
    assert s2["aaa"]["status"] == "open"
    assert trans[0]["event"] == "persistent"

def test_reconcile_missing_finding_becomes_resolved():
    s1, _ = S.reconcile({}, [_f("aaa")], today=D(2026, 6, 1), scan_id="s1")
    s2, trans = S.reconcile(s1, [], today=D(2026, 6, 10), scan_id="s2")
    assert s2["aaa"]["status"] == "resolved"
    assert s2["aaa"]["resolved_at"] == "2026-06-10"
    assert {"fingerprint": "aaa", "event": "resolved", "severity": "high"} in trans

def test_reconcile_resolved_reappears_reopens():
    s1, _ = S.reconcile({}, [_f("aaa")], today=D(2026, 6, 1), scan_id="s1")
    s2, _ = S.reconcile(s1, [], today=D(2026, 6, 10), scan_id="s2")
    s3, trans = S.reconcile(s2, [_f("aaa")], today=D(2026, 6, 20), scan_id="s3")
    assert s3["aaa"]["status"] == "open"
    assert s3["aaa"]["resolved_at"] is None
    assert s3["aaa"]["reopened_count"] == 1
    assert trans[0]["event"] == "reopened"

def test_reconcile_ignores_findings_without_fingerprint():
    store, trans = S.reconcile({}, [{"severity": "low", "name": "no-fp"}],
                               today=D(2026, 6, 1), scan_id="s1")
    assert store == {}
    assert trans == []

def test_load_save_roundtrip(tmp_path):
    d = str(tmp_path)
    store, _ = S.reconcile({}, [_f("aaa")], today=D(2026, 6, 1), scan_id="s1")
    p = S.save_store("ex.com", store, state_dir=d)
    assert os.path.exists(p)
    loaded = S.load_store("ex.com", state_dir=d)
    assert loaded["aaa"]["first_seen"] == "2026-06-01"

def test_load_missing_store_returns_empty(tmp_path):
    assert S.load_store("never.com", state_dir=str(tmp_path)) == {}

def test_save_sanitizes_target_into_filename(tmp_path):
    d = str(tmp_path)
    p = S.save_store("https://a.b.com/x", {}, state_dir=d)
    assert os.path.dirname(p) == d
    assert "/" not in os.path.basename(p).replace(".json", "")

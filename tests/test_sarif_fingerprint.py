import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
from report.sarif import build_sarif

def test_each_result_carries_fingerprint_as_partial_fingerprint():
    findings = [
        {"name": "SQLi", "severity": "high", "url": "http://t/a",
         "fingerprint": "deadbeef0001", "cve": ""},
        {"name": "XSS", "severity": "medium", "url": "http://t/b",
         "fingerprint": "deadbeef0002", "cve": ""},
    ]
    doc = build_sarif(findings, "http://t")
    results = doc["runs"][0]["results"]
    fps = [r["partialFingerprints"]["stiglitzFingerprint/v1"] for r in results]
    assert "deadbeef0001" in fps and "deadbeef0002" in fps

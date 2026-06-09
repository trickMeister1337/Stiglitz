# tests/test_dedup.py
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
import dedup as D


def test_exact_cross_tool_merge():
    fs = [
        {"name": "Reflected XSS", "cwe": "CWE-79", "url": "http://t/s", "param": "q",
         "severity": "high", "tool": "nuclei", "count": 1},
        {"name": "Cross Site Scripting", "cwe": "CWE-79", "url": "http://t/s", "param": "q",
         "severity": "medium", "tool": "zap", "count": 1},
    ]
    out = D.dedupe(fs)
    assert len(out) == 1
    assert out[0]["severity"] == "high"            # severidade máxima
    assert out[0]["count"] == 2                     # soma
    assert set(out[0]["sources"]) == {"nuclei", "zap"}
    assert len(out[0]["merged_from"]) == 1          # mesmo fingerprint
    assert out[0]["merge_score"] == 1.0             # bucket exato


def test_path_variant_collapse():
    fs = [{"cwe": "CWE-89", "url": f"http://t/user/{i}/orders", "param": "id",
           "name": "SQLi", "severity": "high", "tool": "nuclei"} for i in (1, 2, 3)]
    out = D.dedupe(fs)
    assert len(out) == 1
    assert len(out[0]["endpoints"]) == 3            # /user/1, /user/2, /user/3 unidos


def test_red_target_form():
    fs = [
        {"type": "xss", "target": "http://t/p", "sev": "Medium", "tool": "zap", "count": 1},
        {"type": "xss", "target": "http://t/p", "sev": "High", "tool": "nuclei", "count": 1},
    ]
    out = D.dedupe(fs)
    assert len(out) == 1
    assert out[0]["count"] == 2


def test_singleton_passes_through_unchanged():
    f = {"cwe": "CWE-79", "url": "http://t/a", "param": "q", "name": "x", "tool": "nuclei"}
    out = D.dedupe([f])
    assert len(out) == 1
    assert out[0] is f                              # não muta nem copia singleton


def test_degrade_on_malformed():
    out = D.dedupe([{"name": "x"}, {}, {"url": "http://t/a", "cwe": "CWE-79"}])
    assert isinstance(out, list)                    # não levanta
    assert len(out) == 3                             # fingerprints distintos → nenhum merge

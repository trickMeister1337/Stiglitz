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


def test_fuzzy_merge_shared_cve():
    fs = [
        {"name": "Apache RCE", "cve": "CVE-2021-41773", "cwe": "CWE-22",
         "url": "http://t/", "severity": "critical", "tool": "nuclei"},
        {"name": "Path traversal Apache", "cve": "CVE-2021-41773", "cwe": "CWE-98",
         "url": "http://t/", "severity": "high", "tool": "nmap"},
    ]
    out = D.dedupe(fs)
    assert len(out) == 1                            # CVE igual -> merge mesmo c/ CWE divergente
    assert out[0]["severity"] == "critical"
    assert len(out[0]["merged_from"]) == 2          # 2 fingerprints distintos


def test_fuzzy_title_above_threshold_merges():
    # mesmo host + mesma classe, paths diferentes (fingerprints diferentes),
    # título/evidência quase idênticos -> score acima do threshold.
    fs = [
        {"name": "Server version disclosure in header", "cwe": "CWE-200",
         "url": "http://t/login", "severity": "low", "tool": "nuclei",
         "evidence": "Server: nginx disclosed"},
        {"name": "Server version disclosure in header", "cwe": "CWE-200",
         "url": "http://t/admin", "severity": "low", "tool": "zap",
         "evidence": "Server: nginx disclosed"},
    ]
    out = D.dedupe(fs)
    assert len(out) == 1


def test_fuzzy_below_threshold_kept_separate():
    # mesma classe + host, mas títulos/evidência divergentes -> score < threshold.
    fs = [
        {"name": "SQL injection in search", "cwe": "CWE-89", "url": "http://t/search",
         "severity": "high", "tool": "nuclei", "evidence": "error-based payload"},
        {"name": "Open redirect on logout", "cwe": "CWE-89", "url": "http://t/logout",
         "severity": "high", "tool": "zap", "evidence": "location header attacker"},
    ]
    out = D.dedupe(fs)
    assert len(out) == 2


def test_distinct_host_never_merges():
    # CVE igual mas hosts distintos -> fingerprint difere e fuzzy é blocado por host.
    fs = [
        {"name": "X", "cve": "CVE-2021-1234", "url": "http://a/p", "severity": "high", "tool": "nuclei"},
        {"name": "X", "cve": "CVE-2021-1234", "url": "http://b/p", "severity": "high", "tool": "nuclei"},
    ]
    out = D.dedupe(fs)
    assert len(out) == 2

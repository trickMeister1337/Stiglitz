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


def _js_lib(component, version, sev, url, cve=""):
    return {"source": "retire.js", "tool": "retire.js", "type": "vulnerable_js_library",
            "cwe": "CWE-1395", "component": component, "version": version,
            "name": f"Vulnerable JS library: {component} {version}", "severity": sev,
            "cve": cve, "url": url,
            "evidence": f"retire.js flagged {component} {version} as vulnerable"}


def test_distinct_vulnerable_libraries_not_merged():
    # axios/pdf.js/quill são componentes DISTINTOS — não podem colapsar num só
    # (mesmo com CWE-1395 compartilhado + títulos templatizados). Antes do fix,
    # o dedup os fundia e pdf.js/quill sumiam do relatório.
    fs = [
        _js_lib("axios", "0.21.4", "critical", "https://h/static/js/958.a6.js", "CVE-2023-45857"),
        _js_lib("pdf.js", "2.16.105", "high", "https://h/static/js/311.b0.js", "CVE-2024-4367"),
        _js_lib("quill", "1.3.7", "medium", "https://h/static/js/55.bd.js", "CVE-2021-3163"),
    ]
    out = D.dedupe(fs)
    names = sorted(f["component"] for f in out)
    assert names == ["axios", "pdf.js", "quill"], f"esperava 3 libs, veio {names}"


def test_distinct_libraries_in_same_chunk_not_merged():
    # Caso real: retire atribui axios E pdf.js ao MESMO chunk → mesma URL. Sem
    # componente na identidade, o estágio-1 (fingerprint) os colapsava.
    url = "https://h/static/js/958.a697a0dc.js"
    out = D.dedupe([
        _js_lib("axios", "0.21.4", "critical", url, "CVE-2023-45857"),
        _js_lib("pdf.js", "2.16.105", "high", url, "CVE-2024-4367"),
    ])
    assert len(out) == 2


def test_same_library_across_chunks_still_merges():
    # A MESMA lib/versão em dois arquivos é uma duplicata legítima → colapsa em 1,
    # agregando as localizações (não regredir o dedup correto).
    out = D.dedupe([
        _js_lib("axios", "0.21.4", "high", "https://h/static/js/958.a6.js", "CVE-2023-45857"),
        _js_lib("axios", "0.21.4", "high", "https://h/static/js/311.b0.js", "CVE-2023-45857"),
    ])
    assert len(out) == 1
    assert len(out[0]["endpoints"]) == 2


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
    # CVE igual mas hosts distintos -> by_host isola os índices; _score nunca é chamado cross-host.
    fs = [
        {"name": "X", "cve": "CVE-2021-1234", "url": "http://a/p", "severity": "high", "tool": "nuclei"},
        {"name": "X", "cve": "CVE-2021-1234", "url": "http://b/p", "severity": "high", "tool": "nuclei"},
    ]
    out = D.dedupe(fs)
    assert len(out) == 2


def test_summary_string():
    fs = [{"cwe": "CWE-79", "url": "http://t/s", "param": "q", "name": "x", "tool": "nuclei"},
          {"cwe": "CWE-79", "url": "http://t/s", "param": "q", "name": "x", "tool": "zap"}]
    out = D.dedupe(fs)
    s = D._summary(fs, out)
    assert "2 findings" in s and "1" in s           # 2 -> 1 (1 merge)


def test_evidence_legacy_dedup_fallback():
    import importlib
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
    ev = importlib.import_module("evidence")
    fs = [{"tool": "zap", "type": "xss", "target": "http://t/p"},
          {"tool": "zap", "type": "xss", "target": "http://t/p"},
          {"tool": "nuclei", "type": "sqli", "target": "http://t/q"}]
    out = ev._legacy_dedup(fs)
    assert len(out) == 2                            # colapsa a duplicata exata zap/xss


def test_dedupe_tolerates_non_string_url():
    # url/target não-string não deve abortar o estágio 2 (degrada como malformado).
    out = D.dedupe([{"cwe": "CWE-89", "url": 12345, "name": "x", "tool": "nuclei"},
                    {"cwe": "CWE-79", "url": ["weird"], "name": "y", "tool": "zap"}])
    assert isinstance(out, list) and len(out) == 2


def test_legacy_dedup_tolerates_none_target():
    import importlib
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
    ev = importlib.import_module("evidence")
    out = ev._legacy_dedup([{"tool": "zap", "type": "xss", "target": None},
                            {"tool": "nuclei", "type": "sqli"}])   # target ausente/None
    assert isinstance(out, list) and len(out) == 2


def test_distinct_explicit_types_same_cwe_not_merged():
    # apm_unauth_ingestion vs apm_central_config_exposed: mesmo CWE-306, mesmo host,
    # títulos similares e evidência parecida — mas são vulnerabilidades distintas em
    # endpoints distintos. Não devem ser fundidas (perder o config exposed é pior).
    fs = [
        {"type": "apm_unauth_ingestion", "cwe": "CWE-306", "severity": "high",
         "tool": "apm_probe", "url": "https://apm.t/intake/v2/events",
         "name": "APM Server accepts telemetry ingestion without authentication",
         "evidence": "noauth=400 badtoken=401"},
        {"type": "apm_central_config_exposed", "cwe": "CWE-306", "severity": "medium",
         "tool": "apm_probe", "url": "https://apm.t/config/v1/agents",
         "name": "APM agent central configuration readable without authentication",
         "evidence": "noauth=200 badtoken=401"},
    ]
    out = D.dedupe(fs)
    types = {f.get("type") for f in out}
    assert len(out) == 2, f"types distintos não deveriam fundir, veio {len(out)}"
    assert types == {"apm_unauth_ingestion", "apm_central_config_exposed"}


def test_shared_cve_still_merges_across_distinct_types():
    # guarda de type NÃO deve impedir merge legítimo quando há CVE compartilhada
    # (ex.: nuclei e zap classificam a mesma CVE com 'type' diferente).
    fs = [
        {"type": "nuclei-cve", "cve": "CVE-2021-44228", "url": "http://t/x",
         "severity": "critical", "tool": "nuclei", "name": "Log4Shell"},
        {"type": "rce", "cve": "CVE-2021-44228", "url": "http://t/x",
         "severity": "high", "tool": "zap", "name": "Remote Code Execution"},
    ]
    out = D.dedupe(fs)
    assert len(out) == 1, "CVE compartilhada deveria fundir mesmo com types distintos"

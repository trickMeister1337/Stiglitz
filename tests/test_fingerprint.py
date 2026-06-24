import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
import fingerprint as F


def test_normalize_path_replaces_numeric_and_uuid_segments():
    assert F.normalize_path("http://t/user/123/profile") == "/user/{id}/profile"
    assert F.normalize_path("http://t/o/550e8400-e29b-41d4-a716-446655440000") == "/o/{id}"
    assert F.normalize_path("http://t/search") == "/search"


def test_fingerprint_stable_across_id_values():
    a = {"cwe": "CWE-639", "url": "http://t/user/1/orders", "param": "id"}
    b = {"cwe": "CWE-639", "url": "http://t/user/2/orders", "param": "id"}
    assert F.fingerprint(a) == F.fingerprint(b)  # mesmo endpoint-template + classe + param


def test_fingerprint_differs_by_class():
    a = {"cwe": "CWE-79", "url": "http://t/x", "param": "q"}
    b = {"cwe": "CWE-89", "url": "http://t/x", "param": "q"}
    assert F.fingerprint(a) != F.fingerprint(b)


def test_fingerprint_differs_by_host():
    a = {"cwe": "CWE-79", "url": "http://a.t/x"}
    b = {"cwe": "CWE-79", "url": "http://b.t/x"}
    assert F.fingerprint(a) != F.fingerprint(b)


def test_fingerprint_uses_cwe_from_cve_field_when_no_cwe():
    a = {"url": "http://t/x", "cve": "CWE-79"}
    b = {"cwe": "CWE-79", "url": "http://t/x"}
    assert F.fingerprint(a) == F.fingerprint(b)


def test_fingerprint_distinguishes_vulnerable_components():
    # Duas libs vulneráveis distintas no MESMO arquivo (mesma classe CWE-1395,
    # mesmo host/path) têm identidades diferentes — senão o dedup as funde e uma
    # some do relatório. O componente entra no fingerprint quando presente.
    base = {"cwe": "CWE-1395", "type": "vulnerable_js_library",
            "url": "https://h/static/js/958.abc.js"}
    axios = {**base, "component": "axios", "version": "0.21.4"}
    pdfjs = {**base, "component": "pdf.js", "version": "2.16.105"}
    assert F.fingerprint(axios) != F.fingerprint(pdfjs)
    # mesma lib/versão no mesmo lugar → mesma identidade (dedup correto)
    assert F.fingerprint(axios) == F.fingerprint(
        {**base, "component": "axios", "version": "0.21.4"})


def test_fingerprint_unchanged_when_no_component():
    # Sem campo component (findings não-SCA), o fingerprint é exatamente o de
    # antes — a mudança não afeta o corpus geral nem o state cross-scan.
    import hashlib, urllib.parse
    f = {"cwe": "CWE-89", "url": "https://h/login", "param": "user"}
    host = urllib.parse.urlsplit(f["url"]).netloc
    key = "|".join([F.vuln_class(f), host, F.normalize_path(f["url"]), "user"])
    assert F.fingerprint(f) == hashlib.sha1(key.encode()).hexdigest()[:16]


def test_fingerprint_is_short_hex():
    fp = F.fingerprint({"name": "X", "url": "http://t/x"})
    assert len(fp) == 16 and all(c in "0123456789abcdef" for c in fp)

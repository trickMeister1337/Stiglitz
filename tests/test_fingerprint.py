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


def test_fingerprint_is_short_hex():
    fp = F.fingerprint({"name": "X", "url": "http://t/x"})
    assert len(fp) == 16 and all(c in "0123456789abcdef" for c in fp)

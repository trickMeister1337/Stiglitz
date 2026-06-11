import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
import scope as S


def test_in_scope_exact_and_subdomain():
    assert S.in_scope("https://a.com/x", ["a.com"]) is True
    assert S.in_scope("https://api.a.com/x", ["a.com"]) is True


def test_out_of_scope():
    assert S.in_scope("https://evil.com/?redirect=a.com", ["a.com"]) is False
    assert S.in_scope("https://nota.com/x", ["a.com"]) is False


def test_no_scope_is_fail_open():
    assert S.in_scope("https://anything.com/x", []) is True


def test_malformed_url_with_scope_is_out():
    assert S.in_scope("not a url", ["a.com"]) is False
    assert S.in_scope("", ["a.com"]) is False


def test_filter_lines():
    lines = ["https://a.com/1", "https://evil.com/2", "https://api.a.com/3"]
    assert S.filter_in_scope(lines, ["a.com"]) == ["https://a.com/1", "https://api.a.com/3"]

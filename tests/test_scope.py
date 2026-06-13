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


def test_filter_preserves_scored_format():
    # targets_scored.txt é 'score|url'; o filtro deve checar a URL e PRESERVAR a linha.
    lines = ["5|https://a.com/x?id=1", "3|https://evil.com/y", "9|https://api.a.com/z"]
    out = S.filter_in_scope(lines, ["a.com"])
    assert out == ["5|https://a.com/x?id=1", "9|https://api.a.com/z"]   # linhas originais preservadas


def test_url_of_strips_score_prefix_only():
    assert S._url_of("5|https://a.com/x") == "https://a.com/x"
    assert S._url_of("https://a.com/x") == "https://a.com/x"          # sem prefixo: inalterado
    assert S._url_of("https://a.com/x?a=1|2") == "https://a.com/x?a=1|2"  # '|' embutido preservado

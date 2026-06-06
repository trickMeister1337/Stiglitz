import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
import dast_prep as D


def test_has_query_params():
    assert D.has_query_params("http://t/s?q=1") is True
    assert D.has_query_params("http://t/s") is False


def test_parameterized_urls_filters_and_dedups_by_param_set():
    urls = [
        "http://t/search?q=abc",
        "http://t/search?q=xyz",   # mesmo endpoint+param → dedup
        "http://t/item?id=1",
        "http://t/static.js",      # sem params → fora
        "http://t/item?id=2",      # dedup com id=1
    ]
    out = D.parameterized_urls(urls)
    assert "http://t/search?q=abc" in out
    assert "http://t/item?id=1" in out
    assert "http://t/static.js" not in out
    assert len(out) == 2  # search(q) + item(id)


def test_parameterized_urls_respects_cap():
    urls = [f"http://t/p{i}?x=1" for i in range(10)]
    assert len(D.parameterized_urls(urls, cap=3)) == 3


def test_inject_params_appends_query():
    u = D.inject_params("http://t/api/user", ["id", "role"])
    from urllib.parse import urlsplit, parse_qs
    q = parse_qs(urlsplit(u).query)
    assert set(q.keys()) == {"id", "role"}


def test_parse_arjun_extracts_params_per_url():
    data = {"http://t/api/user": {"method": "GET", "params": ["id", "admin"]}}
    assert D.parse_arjun(data) == {"http://t/api/user": ["id", "admin"]}


def test_arjun_fuzz_urls_builds_parameterized():
    data = {"http://t/api/user": {"params": ["id"]}}
    urls = D.arjun_fuzz_urls(data)
    assert urls and "id=" in urls[0] and urls[0].startswith("http://t/api/user?")


def test_arjun_fuzz_urls_skips_empty_params():
    assert D.arjun_fuzz_urls({"http://t/x": {"params": []}}) == []

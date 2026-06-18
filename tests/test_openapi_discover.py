import os, sys, json
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
import openapi_discover as D

SPEC = {
    "swagger": "2.0", "basePath": "/api",
    "paths": {"/users/{id}": {"get": {}}, "/orders": {"get": {}}},
}


def _fetch_map(mapping):
    """fetch_fn falso: retorna o corpo mapeado por URL, senão None."""
    return lambda url, timeout=8: mapping.get(url)


def test_discover_host_finds_spec_and_extracts_urls():
    base = "https://api.example.com"
    fetch = _fetch_map({base + "/swagger/v1/swagger.json": json.dumps(SPEC)})
    spec_url, urls = D.discover_host(base, fetch)
    assert spec_url == base + "/swagger/v1/swagger.json"
    assert base + "/api/users/1" in urls          # placeholder {id} → 1, prefixo /api
    assert base + "/api/orders" in urls


def test_discover_host_ignores_non_spec_and_404():
    base = "https://x.example.com"
    fetch = _fetch_map({base + "/swagger.json": "<html>swagger-ui</html>",
                        base + "/openapi.json": json.dumps({"no": "paths"})})
    assert D.discover_host(base, fetch) == (None, [])


def test_discover_all_aggregates_only_hosts_with_spec():
    a, b, c = "https://a.ex", "https://b.ex", "https://c.ex"
    fetch = _fetch_map({
        a + "/swagger.json": json.dumps(SPEC),
        c + "/openapi.json": json.dumps(SPEC),
        # b não expõe nada
    })
    found = D.discover_all([a, b, c], fetch, max_workers=3)
    assert set(found) == {a, c}
    assert b not in found


def test_aggregate_urls_dedups_preserving_order():
    found = {"https://a.ex": ("u", ["https://a.ex/api/x", "https://a.ex/api/y"]),
             "https://b.ex": ("u", ["https://b.ex/api/x", "https://a.ex/api/x"])}
    urls = D.aggregate_urls(found)
    assert urls.count("https://a.ex/api/x") == 1
    assert len(urls) == 3


def test_main_writes_openapi_urls(tmp_path):
    raw = tmp_path / "raw"; raw.mkdir()
    (raw / "httpx_results.txt").write_text(
        "https://api.example.com [200] [Kestrel]\nhttps://blank.example.com [404]\n")
    fetch = _fetch_map({"https://api.example.com/swagger/v1/swagger.json": json.dumps(SPEC)})
    found = D.main(str(tmp_path), "example.com", fetch_fn=fetch)
    assert "https://api.example.com" in found
    written = (raw / "openapi_urls.txt").read_text()
    assert "https://api.example.com/api/orders" in written
    assert "/home/" not in written           # só URLs, nunca paths locais


def test_hosts_from_httpx_takes_first_column():
    raw_path = "/nonexistent"
    assert D._hosts_from_httpx(raw_path) == []   # arquivo ausente → vazio, sem erro

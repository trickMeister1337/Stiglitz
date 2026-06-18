#!/usr/bin/env python3
"""openapi_discover.py — Descoberta multi-host de specs OpenAPI/Swagger (Fase 4).

`discover_openapi_urls` (stiglitz.sh) só sondava o alvo-raiz. Aqui sondamos os paths
de spec em CADA host vivo (raw/httpx_results.txt) concorrentemente; para cada spec
válido, extraímos as URLs concretas (openapi_seed.spec_to_urls) e as agregamos em
raw/openapi_urls.txt — o mesmo arquivo que o feed do Nuclei consome.

Motivação: as APIs (.NET/Kestrel) dão 404 na raiz, então o Nuclei varrendo só a raiz
não casa nada ≥ low. Os specs OpenAPI expõem os endpoints REAIS — alimentá-los dá ao
Nuclei a superfície de fato testável.

Orquestração + CLI. A sondagem HTTP é injetável (fetch_fn) p/ testar sem rede.
Respeita escopo: processa apenas os hosts que o chamador fornece (já in-scope).
"""
import os
import sys
import json
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import openapi_seed  # noqa: E402

# Paths de spec mais comuns (Swagger 2 / OpenAPI 3 — .NET/Express/Spring).
SPEC_PATHS = (
    "/swagger/v1/swagger.json", "/swagger.json", "/openapi.json",
    "/v1/swagger.json", "/v2/swagger.json", "/v3/swagger.json",
    "/api/swagger.json", "/api/openapi.json", "/api-docs", "/api-docs/v1",
)

_MAX_BODY = 3_000_000


def _default_fetch(url, timeout=8):
    """GET respeitando STIGLITZ_PROXY (netproxy) com fallback p/ urllib. Fail-soft."""
    try:
        import netproxy
        opener = netproxy.make_opener()
        with opener.open(url, timeout=timeout) as r:
            return r.read(_MAX_BODY).decode("utf-8", "ignore")
    except ImportError:
        import urllib.request
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.read(_MAX_BODY).decode("utf-8", "ignore")
        except Exception:
            return None
    except Exception:
        return None


def _looks_like_spec(spec):
    return (isinstance(spec, dict) and isinstance(spec.get("paths"), dict)
            and bool(spec.get("paths")))


def discover_host(base, fetch_fn, paths=SPEC_PATHS):
    """Sonda os paths de spec num host; retorna (spec_url, [urls]) do 1º válido."""
    base = base.rstrip("/")
    for p in paths:
        url = base + p
        body = fetch_fn(url)
        if not body:
            continue
        try:
            spec = json.loads(body)
        except (ValueError, TypeError):
            continue
        if not _looks_like_spec(spec):
            continue
        urls = openapi_seed.spec_to_urls(spec, base)
        if urls:
            return url, urls
    return None, []


def discover_all(hosts, fetch_fn=None, max_workers=12):
    """{host: (spec_url, [urls])} para os hosts que expõem um spec utilizável."""
    fetch_fn = fetch_fn or _default_fetch
    found = {}
    hosts = list(hosts or [])
    if not hosts:
        return found
    with ThreadPoolExecutor(max_workers=min(max_workers, len(hosts))) as ex:
        futs = {ex.submit(discover_host, h, fetch_fn): h for h in hosts}
        for fu in as_completed(futs):
            h = futs[fu]
            try:
                spec_url, urls = fu.result()
            except Exception:
                spec_url, urls = None, []
            if urls:
                found[h] = (spec_url, urls)
    return found


def _hosts_from_httpx(path):
    """URLs-raiz (1ª coluna) do httpx_results.txt."""
    out, seen = [], set()
    try:
        with open(path, encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                parts = line.split()
                u = parts[0] if parts else ""
                if u.startswith("http") and u not in seen:
                    seen.add(u)
                    out.append(u)
    except OSError:
        pass
    return out


def aggregate_urls(found):
    """Achata {host: (spec_url, urls)} numa lista de URLs deduplicada, ordem estável."""
    out, seen = [], set()
    for _h, (_spec, urls) in found.items():
        for u in urls:
            if u not in seen:
                seen.add(u)
                out.append(u)
    return out


def main(outdir, domain="", fetch_fn=None):
    raw = os.path.join(outdir, "raw")
    hosts = _hosts_from_httpx(os.path.join(raw, "httpx_results.txt"))
    found = discover_all(hosts, fetch_fn)
    all_urls = aggregate_urls(found)
    if all_urls:
        # Mesmo arquivo que o feed do Nuclei lê; append preserva o que o
        # discover single-host tenha gravado. sort -u a jusante deduplica.
        with open(os.path.join(raw, "openapi_urls.txt"), "a", encoding="utf-8") as fh:
            fh.write("\n".join(all_urls) + "\n")
    print(f"  [{'✓' if found else '○'}] OpenAPI multi-host: {len(found)} host(s) com "
          f"spec, {len(all_urls)} endpoint(s) reais agregados ao feed do Nuclei")
    return found


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else "")

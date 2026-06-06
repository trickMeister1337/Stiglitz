#!/usr/bin/env python3
"""
dast_prep.py — prepara a lista de URLs para o fuzzing ativo do Nuclei (#1/#5).

Seleciona URLs parametrizadas (candidatas a injeção) do crawl e mescla os
parâmetros ocultos descobertos pelo arjun, deduplicando por (endpoint, conjunto
de params) para não fuzzar /search?q=1 e /search?q=2 como alvos distintos.
O stiglitz.sh alimenta `nuclei -dast` com o resultado.

Funções puras (urllib) — testáveis sem rede.
"""
import sys
import os
import json
import urllib.parse


def has_query_params(url):
    return bool(urllib.parse.urlsplit(url).query)


def _dedup_key(url):
    sp = urllib.parse.urlsplit(url)
    params = tuple(sorted(k for k, _ in urllib.parse.parse_qsl(sp.query)))
    return (sp.scheme, sp.netloc, sp.path, params)


def parameterized_urls(urls, cap=None):
    """URLs com query string, deduplicadas por (endpoint, nomes de parâmetros)."""
    seen = set()
    out = []
    for u in urls:
        u = (u or "").strip()
        if not u or not has_query_params(u):
            continue
        key = _dedup_key(u)
        if key in seen:
            continue
        seen.add(key)
        out.append(u)
        if cap and len(out) >= cap:
            break
    return out


def inject_params(base_url, params, placeholder="1"):
    """Anexa parâmetros descobertos a um endpoint sem query (valor placeholder)."""
    sp = urllib.parse.urlsplit(base_url)
    q = urllib.parse.urlencode({p: placeholder for p in params})
    return urllib.parse.urlunsplit((sp.scheme, sp.netloc, sp.path, q, ""))


def parse_arjun(data):
    """Normaliza o JSON do arjun (-oJ) → {url: [params]}."""
    out = {}
    for url, meta in (data or {}).items():
        params = (meta or {}).get("params", []) if isinstance(meta, dict) else []
        if params:
            out[url] = list(params)
    return out


def arjun_fuzz_urls(data):
    """Constrói URLs parametrizadas a partir da saída do arjun."""
    urls = []
    for url, params in parse_arjun(data).items():
        if params:
            urls.append(inject_params(url, params))
    return urls


def build_list(crawl_urls, arjun_data=None, cap=300):
    """Lista final p/ o nuclei -dast: URLs parametrizadas do crawl + as do arjun."""
    candidates = list(crawl_urls or [])
    if arjun_data:
        candidates += arjun_fuzz_urls(arjun_data)
    return parameterized_urls(candidates, cap=cap)


def main(crawl_file, out_file, arjun_file=""):
    crawl = []
    if os.path.exists(crawl_file):
        with open(crawl_file, encoding="utf-8", errors="ignore") as fh:
            crawl = [ln.strip() for ln in fh if ln.strip()]
    arjun_data = None
    if arjun_file and os.path.exists(arjun_file):
        try:
            with open(arjun_file, encoding="utf-8", errors="ignore") as fh:
                arjun_data = json.load(fh)
        except ValueError:
            arjun_data = None
    urls = build_list(crawl, arjun_data)
    with open(out_file, "w", encoding="utf-8") as fh:
        fh.write("\n".join(urls) + ("\n" if urls else ""))
    print(len(urls))


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else "")

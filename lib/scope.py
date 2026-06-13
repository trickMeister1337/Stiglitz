#!/usr/bin/env python3
"""scope.py — escopo de engajamento: in_scope(url, scope_domains).

Fail-open só quando scope_domains vazio (operador não delimitou). Com escopo,
in-scope = host igual a um domínio do escopo ou subdomínio real dele. URL
malformada com escopo definido => fora de escopo. Puro, sem rede. CLI filtra
stdin → stdout. Ponto único de verdade reusado por ingest/brute/sqli/xss.
"""
import re
import sys
import urllib.parse

_SCORE_PREFIX = re.compile(r"^\d+\|")


def _url_of(line):
    """Extrai a URL de uma linha. Tolera o formato 'score|url' (prefixo numérico
    do targets_scored.txt); deixa intactas URLs com '|' embutido no meio."""
    return _SCORE_PREFIX.sub("", line.strip(), count=1)


def _norm(domains):
    return [d.strip().lower().lstrip("*.") for d in domains if d and d.strip()]


def in_scope(url, scope_domains):
    sd = _norm(scope_domains)
    if not sd:                       # sem escopo: fail-open (operador não delimitou)
        return True
    try:
        host = (urllib.parse.urlsplit(url).hostname or "").lower()
    except (ValueError, AttributeError):
        return False
    if not host:
        return False
    return any(host == d or host.endswith("." + d) for d in sd)


def filter_in_scope(lines, scope_domains):
    out = []
    for line in lines:
        s = line.strip()
        if s and in_scope(_url_of(s), scope_domains):
            out.append(s)
    return out


def _main(argv):
    # uso: scope.py <dom1> [dom2 ...]  (lê URLs do stdin, imprime as in-scope)
    for u in filter_in_scope(sys.stdin.read().splitlines(), argv):
        print(u)
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))

#!/usr/bin/env python3
"""openapi_seed.py — Extrai URLs concretas de um spec OpenAPI/Swagger para semear
no contexto ZAP (fase P9) quando o import nativo do ZAP falha (ex.: nomes de schema
.NET com backtick que violam o validador do ZAP). Lógica pura + CLI.

Resolve placeholders de path ({id}) com um valor de amostra, aplica o prefixo
(basePath do Swagger 2 / path do servers[] do OpenAPI 3) sem duplicar, e deduplica.
"""
import json
import re
import sys
import urllib.parse

_PARAM = re.compile(r"\{[^}]+\}")


def _prefix(spec):
    """Prefixo de path do spec: basePath (Swagger 2) ou path do servers[0] (OpenAPI 3)."""
    bp = spec.get("basePath")
    if isinstance(bp, str) and bp:
        return bp.rstrip("/")
    servers = spec.get("servers")
    if isinstance(servers, list) and servers and isinstance(servers[0], dict):
        url = servers[0].get("url") or ""
        path = urllib.parse.urlsplit(url).path if "://" in url else url
        path = (path or "").rstrip("/")
        return path if path not in ("", "/") else ""
    return ""


def spec_to_urls(spec, base_url, sample="1"):
    """Lista de URLs absolutas (uma por path), placeholders resolvidos, deduplicadas.
    `spec` pode ser dict ou texto JSON. Retorna [] se inviável."""
    if isinstance(spec, str):
        try:
            spec = json.loads(spec)
        except (ValueError, TypeError):
            return []
    if not isinstance(spec, dict):
        return []
    paths = spec.get("paths")
    if not isinstance(paths, dict):
        return []

    prefix = _prefix(spec)
    root = base_url.rstrip("/")
    out, seen = [], set()
    for raw in paths:
        if not isinstance(raw, str) or not raw.startswith("/"):
            continue
        full = raw if (not prefix or raw.startswith(prefix)) else prefix + raw
        url = _PARAM.sub(sample, root + full)
        if url not in seen:
            seen.add(url)
            out.append(url)
    return out


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) < 2:
        print("uso: openapi_seed.py <spec.json> <base_url> [sample]", file=sys.stderr)
        return 2
    spec_path, base_url = argv[0], argv[1]
    sample = argv[2] if len(argv) > 2 else "1"
    try:
        with open(spec_path, encoding="utf-8") as f:
            spec = f.read()
    except OSError as e:
        print(f"erro lendo spec: {e}", file=sys.stderr)
        return 1
    for url in spec_to_urls(spec, base_url, sample=sample):
        print(url)
    return 0


if __name__ == "__main__":
    sys.exit(main())

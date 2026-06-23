#!/usr/bin/env python3
"""Testes de lib/httpx_parse.py — parsing estruturado da saída JSON do httpx.

Bug #1: o tech_profile parseava os colchetes do output TEXTO do httpx e tratava
QUALQUER token (título HTTP, flag HSTS) como "tecnologia". A saída -json separa
title/tech/webserver — estes testes fixam esse contrato.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
import httpx_parse as hp  # noqa: E402


def test_parse_jsonl_skips_invalid_lines():
    text = '{"url":"https://a.com","tech":["Nginx"]}\nGARBAGE\n\n{"url":"https://b.com"}\n'
    recs = hp.parse_jsonl(text)
    assert len(recs) == 2
    assert recs[0]["url"] == "https://a.com"


def test_tech_inventory_excludes_title():
    # Antes do fix, "Not Found" (título) virava tecnologia high-confidence.
    recs = [{"url": "https://x.com", "title": "Not Found", "tech": ["Django", "Nginx"]}]
    inv = hp.tech_inventory(recs)
    assert "Not Found" not in inv
    assert "Django" in inv
    assert "Nginx" in inv


def test_tech_inventory_detects_django_from_tech_array():
    recs = [{"url": "https://x.com", "tech": ["Django"]}]
    inv = hp.tech_inventory(recs)
    assert inv["Django"]["source"] == "httpx"
    assert inv["Django"]["confidence"] == "high"


def test_tech_inventory_includes_webserver():
    recs = [{"url": "https://x.com", "webserver": "nginx", "tech": []}]
    inv = hp.tech_inventory(recs)
    assert "nginx" in inv


def test_tech_inventory_extracts_version():
    recs = [{"url": "https://x.com", "tech": ["Swagger UI:3.1.6"]}]
    inv = hp.tech_inventory(recs)
    assert inv["Swagger UI"]["version"] == "3.1.6"


def test_tech_inventory_never_includes_hsts_flag():
    # A saída -json nunca traz HSTS no array tech (é header, não tecnologia).
    recs = [{"url": "https://x.com", "tech": ["Nginx"], "webserver": "nginx"}]
    inv = hp.tech_inventory(recs)
    assert "HSTS" not in inv


def test_tech_inventory_dedups_case_insensitively():
    # "Cloudflare" (tech) + "cloudflare" (webserver) é a MESMA tecnologia.
    recs = [{"url": "https://x.com", "tech": ["Nginx"], "webserver": "nginx"}]
    inv = hp.tech_inventory(recs)
    assert len(inv) == 1
    assert "Nginx" in inv  # a forma do array tech (capitalizada) vence


def test_to_legacy_line_url_first_column():
    rec = {"url": "https://x.com", "status_code": 200, "title": "Hi",
           "tech": ["Nginx"], "webserver": "nginx"}
    line = hp.to_legacy_line(rec)
    assert line.split()[0] == "https://x.com"


def test_to_legacy_line_preserves_edge_tokens_for_grep():
    # O grep de edge do stiglitz.sh detecta LB/CDN gerenciado no texto.
    rec = {"url": "https://x.com", "status_code": 200,
           "tech": ["Amazon ALB"], "cdn_name": "cloudfront"}
    line = hp.to_legacy_line(rec).lower()
    assert "amazon alb" in line
    assert "cloudfront" in line


def test_to_legacy_text_round_trips_lines():
    text = '{"url":"https://a.com","status_code":200,"tech":["Nginx"]}\n' \
           '{"url":"https://b.com","status_code":403}\n'
    out = hp.to_legacy_text(text)
    lines = [l for l in out.splitlines() if l.strip()]
    assert len(lines) == 2
    assert lines[0].split()[0] == "https://a.com"

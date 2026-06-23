# tests/test_js_chunks.py
"""Cobertura de lib/js_chunks.py — descoberta de lazy chunks webpack +
guarda anti-FP de catch-all SPA.

Cenário: um scanner reporta "secret em <chunk>.js" (ex.: hash confundido com
PAT). O chunk pode nem existir — uma SPA com catch-all devolve index.html
(HTTP 200, text/html) para qualquer path, e varrer esse HTML como JS gera
falso positivo. Além disso, varrer só o entry bundle ignora o código real
(lazy chunks). Estas funções fecham os dois gaps: resolver os chunks reais a
partir do manifest webpack (i.u) e nunca tratar HTML como JS.
"""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
import js_chunks as J

# Runtime webpack típico de SPA (função i.u = template de nome de chunk) + i.p
# (public path). Domínio fictício; estrutura idêntica à de um build real.
ENTRY_URL = "https://app.example.com/static/js/index.ec42d45b.js"
ENTRY_JS = (
    'i.p="/",'
    'i.u=e=>"static/js/"+({200:"css",547:"bootstrap",601:"index2",881:"jquery"}[e]||e)'
    '+"."+{82:"efdd6985",200:"f1cb05bf",427:"0d0009b6",494:"32d67407",547:"65728515",'
    '553:"0400dab2",601:"0c8e35f3",799:"5c185cea",808:"f6a3d6ce",881:"073694c2",'
    '941:"e785c15e",945:"c3e487fa",958:"a697a0dc"}[e]+".js"'
)


def test_webpack_chunk_urls_resolves_real_manifest():
    urls = set(J.webpack_chunk_urls(ENTRY_JS, ENTRY_URL))
    base = "https://app.example.com/static/js/"
    expected = {
        base + "82.efdd6985.js",
        base + "css.f1cb05bf.js",        # id 200 tem nome "css"
        base + "427.0d0009b6.js",
        base + "494.32d67407.js",
        base + "bootstrap.65728515.js",  # id 547 -> "bootstrap"
        base + "553.0400dab2.js",
        base + "index2.0c8e35f3.js",     # id 601 -> "index2"
        base + "799.5c185cea.js",
        base + "808.f6a3d6ce.js",
        base + "jquery.073694c2.js",     # id 881 -> "jquery"
        base + "941.e785c15e.js",
        base + "945.c3e487fa.js",
        base + "958.a697a0dc.js",
    }
    assert urls == expected


def test_webpack_chunk_urls_excludes_nonexistent_chunk():
    # um chunk inexistente (fora do manifest) nunca deve ser gerado
    urls = J.webpack_chunk_urls(ENTRY_JS, ENTRY_URL)
    assert not any("337.95900432" in u for u in urls)


def test_webpack_chunk_urls_empty_for_non_webpack():
    assert J.webpack_chunk_urls("console.log('ola');var x=1;", ENTRY_URL) == []
    assert J.webpack_chunk_urls("", ENTRY_URL) == []


def test_is_js_payload_rejects_spa_catch_all_html():
    html = '<!doctype html><html lang="pt"><head><title>Example App</title></head></html>'
    assert J.is_js_payload("text/html; charset=utf-8", html) is False


def test_is_js_payload_rejects_html_even_without_content_type():
    # servidores podem devolver Content-Type vazio/errado; o sniff do corpo decide
    assert J.is_js_payload("", "  \n<!DOCTYPE html><html></html>") is False


def test_is_js_payload_accepts_real_javascript():
    assert J.is_js_payload("application/javascript; charset=utf-8", "(()=>{var e=1;})()") is True
    assert J.is_js_payload("", "var x=1;function f(){}") is True

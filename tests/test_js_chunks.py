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


# ── Descoberta determinística de JS (discover_js_urls) ───────────────────
# Bug original: o crawl de descoberta em js_analysis.py usava um `set` como
# fronteira e `set.pop()` (ordem dependente do PYTHONHASHSEED, que varia por
# processo). Combinado com o teto MAX_PAGES, cada execução varria um subconjunto
# DIFERENTE de páginas → entry bundles/lazy-chunks diferentes → findings de SCA
# (retire.js) divergentes entre dois scans do mesmo alvo. A fronteira agora é
# uma LISTA (ordem de inserção), tornando a seleção sob o teto reprodutível.

def _make_fetch(pages):
    """fetch_fn de teste (sem rede): url -> (corpo, status, content-type)."""
    def fetch(u):
        return (pages.get(u, ""), 200, "text/html")
    return fetch


def test_discovery_seeds_have_fixed_order():
    seeds = J.discovery_seeds("https://t.io")
    assert seeds == [
        "https://t.io",
        "https://t.io/",
        "https://t.io/login",
        "https://t.io/app",
        "https://t.io/dashboard",
        "https://t.io/api/docs/",
        "https://t.io/swagger-ui/",
    ]


def test_discover_visits_bfs_prefix_under_cap_not_arbitrary_set_order():
    # Cada semente serve um <script src> único → o conjunto de JS descoberto
    # revela QUAIS páginas foram visitadas. Sob o teto, deve visitar as N
    # PRIMEIRAS sementes (ordem BFS), nunca N quaisquer (como faria set.pop).
    target = "https://t.io"
    seeds = J.discovery_seeds(target)
    pages = {s: f'<script src="/static/{i}.js"></script>' for i, s in enumerate(seeds)}
    got = J.discover_js_urls(target, "t.io", _make_fetch(pages), max_pages=3)
    assert got == sorted(f"https://t.io/static/{i}.js" for i in range(3))


def test_discovered_links_follow_document_order_under_cap():
    # 7 sementes; a 1a injeta 2 links (/z antes de /a em ordem de documento).
    # Com teto 8, exatamente 1 link descoberto é visitado: o 1o do documento (/z).
    target = "https://t.io"
    seeds = J.discovery_seeds(target)
    pages = {s: "" for s in seeds}
    pages[seeds[0]] = '<a href="/z"></a><a href="/a"></a>'
    pages["https://t.io/z"] = '<script src="/static/z.js"></script>'
    pages["https://t.io/a"] = '<script src="/static/a.js"></script>'
    got = J.discover_js_urls(target, "t.io", _make_fetch(pages), max_pages=8)
    assert "https://t.io/static/z.js" in got
    assert "https://t.io/static/a.js" not in got


def test_discover_is_stable_across_repeated_calls():
    target = "https://t.io"
    seeds = J.discovery_seeds(target)
    pages = {s: f'<script src="/static/{i}.js"></script><a href="/x{i}"></a>'
             for i, s in enumerate(seeds)}
    fetch = _make_fetch(pages)
    r1 = J.discover_js_urls(target, "t.io", fetch, max_pages=5)
    r2 = J.discover_js_urls(target, "t.io", fetch, max_pages=5)
    assert r1 == r2 and r1  # determinístico e não-vazio


def test_discover_filters_out_of_scope_and_returns_sorted():
    target = "https://t.io"
    pages = {"https://t.io": (
        '<script src="https://t.io/static/b.js"></script>'
        '<script src="https://t.io/static/a.js"></script>'
        '<script src="https://evil.com/x.js"></script>'  # fora do domínio
    )}
    got = J.discover_js_urls(target, "t.io", _make_fetch(pages), max_pages=8)
    assert got == ["https://t.io/static/a.js", "https://t.io/static/b.js"]
    assert all("evil.com" not in u for u in got)

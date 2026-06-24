#!/usr/bin/env python3
"""
js_chunks.py — Helpers puros p/ análise de bundles JS (consumidos por js_analysis.py).

Dois gaps fechados (motivados por SPAs webpack servidas atrás de catch-all):

1. webpack_chunk_urls() — SPAs webpack carregam o código real em *lazy chunks*
   montados em runtime pela função `i.u` dentro do entry bundle; eles nunca
   aparecem como <script src> no HTML, então o crawl não os descobre. Aqui
   resolvemos o manifest (id->hash, id->nome, prefixo, public path) e geramos
   as URLs reais dos chunks para varredura de secrets.

2. is_js_payload() — guarda anti-FP de catch-all: SPAs devolvem index.html
   (HTTP 200, text/html) para qualquer path inexistente. Sem esta checagem,
   um `.js` que cai no catch-all é varrido como se fosse JS — origem de falsos
   positivos de "secret em JS bundle" (ex.: hash SRI confundido com PAT).

Lógica pura (sem rede) + CLI (`chunks <entry.js> <entry_url>`).
"""
import re
import sys
from urllib.parse import urljoin, urlparse

# Objeto literal "achatado" (sem aninhamento) — chunk maps do webpack são planos.
_FLAT_OBJ = re.compile(r"\{[^{}]*\}")
# Par chave-inteiro: valor-string (chaves sem aspas, formato JS minificado).
_INT_STR_PAIR = re.compile(r'(\d+)\s*:\s*"([^"]*)"')
# Função i.u (arrow): `.u=e=>"static/js/"+(...)+"."+{...}[e]+".js"`.
_IU_ARROW = re.compile(r'\.u\s*=\s*\w+\s*=>\s*("(?:[^"\\]|\\.)*".*?\.js")', re.DOTALL)
# Variante function: `.u=function(e){return "static/js/"+...+".js"}`.
_IU_FUNC = re.compile(
    r'\.u\s*=\s*function\s*\([^)]*\)\s*\{[^}]*?return\s+("(?:[^"\\]|\\.)*".*?\.js")',
    re.DOTALL,
)
# Public path: `i.p="/"`.
_PUBLIC_PATH = re.compile(r'\.p\s*=\s*"([^"]*)"')


def _parse_int_str_map(obj_src):
    """'{82:"efdd6985",200:"f1cb05bf"}' -> {82:'efdd6985',200:'f1cb05bf'}."""
    return {int(k): v for k, v in _INT_STR_PAIR.findall(obj_src)}


def webpack_chunk_urls(entry_js, entry_url):
    """Resolve as URLs dos lazy chunks a partir do runtime webpack do entry bundle.

    Retorna [] quando o conteúdo não é um runtime webpack reconhecível.
    """
    if not entry_js:
        return []
    m = _IU_ARROW.search(entry_js) or _IU_FUNC.search(entry_js)
    if not m:
        return []
    region = m.group(1)

    # Prefixo de caminho: 1º literal de string da região (ex.: "static/js/").
    pm = re.search(r'"([^"]*)"', region)
    prefix = pm.group(1) if pm else ""

    # Mapas {int:"str"} na região: o de mais entradas é o de hashes (todo chunk
    # tem hash); o(s) menor(es), se houver, é(são) o(s) de nomes (subconjunto).
    maps = [mp for mp in (_parse_int_str_map(o) for o in _FLAT_OBJ.findall(region)) if mp]
    if not maps:
        return []
    hash_map = max(maps, key=len)
    name_map = {}
    for mp in maps:
        if mp is not hash_map:
            name_map.update(mp)

    pp = _PUBLIC_PATH.search(entry_js)
    public_path = pp.group(1) if pp else "/"
    if public_path in ("", "auto"):
        public_path = "/"
    if not public_path.endswith("/"):
        public_path += "/"
    base = urljoin(entry_url, public_path)

    urls = []
    for cid in sorted(hash_map):
        name = name_map.get(cid, str(cid))
        urls.append(urljoin(base, f"{prefix}{name}.{hash_map[cid]}.js"))
    return urls


def is_js_payload(content_type, body):
    """True se a resposta deve ser tratada como JS; False p/ catch-all HTML.

    Anti-FP: rejeita qualquer corpo que comece como documento HTML/XML (o
    index.html do catch-all) e qualquer resposta tipada explicitamente como
    text/html. JS real (content-type application/javascript, corpo começando
    em `(`, `var`, `function`, etc.) passa.
    """
    head = (body or "").lstrip()[:256].lower()
    if head.startswith(("<!doctype", "<html", "<head", "<?xml", "<svg")):
        return False
    if "text/html" in (content_type or "").lower():
        return False
    return True


# ── Descoberta de arquivos JS (crawl determinístico) ────────────────────
# Paths-semente fixos varridos além do próprio alvo (rotas comuns de SPA onde
# o entry bundle costuma ser referenciado).
_SEED_PATHS = ("/", "/login", "/app", "/dashboard", "/api/docs/", "/swagger-ui/")
_SCRIPT_SRC = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)
# Referência a *.js / *.chunk.js embutida no HTML (webpack as injeta como string).
_JS_REF = re.compile(r'["\']([^"\']*\.(?:js|chunk\.js)(?:\?[^"\']*)?)["\']')
_HREF = re.compile(r'<a[^>]+href=["\']([^"\']+)["\']', re.IGNORECASE)
_NON_PAGE_EXT = (".js", ".css", ".png", ".jpg", ".ico")


def _normalize(url, base):
    """Resolve uma URL relativa/protocolo-relativa contra `base` (ou None)."""
    if not url or url.startswith(("data:", "javascript:", "mailto:", "#")):
        return None
    if url.startswith("//"):
        return base.split("://")[0] + ":" + url
    if url.startswith("/"):
        p = urlparse(base)
        return f"{p.scheme}://{p.netloc}{url}"
    if not url.startswith("http"):
        return urljoin(base, url)
    return url


def discovery_seeds(target):
    """Páginas-semente do crawl em ordem FIXA (target + rotas comuns de SPA).

    Dedup preservando ordem de inserção — base de uma seleção reprodutível.
    """
    p = urlparse(target)
    base = f"{p.scheme}://{p.netloc}"
    seeds, seen = [], set()
    for u in [target] + [base + path for path in _SEED_PATHS]:
        if u not in seen:
            seen.add(u)
            seeds.append(u)
    return seeds


def discover_js_urls(target, domain, fetch_fn, max_pages=8):
    """Crawl de descoberta de arquivos JS — determinístico e sem rede própria.

    `fetch_fn(url) -> (corpo|None, status, content_type)` é injetado (o chamador
    decide como buscar; testável sem rede). A fronteira é uma LISTA (fila FIFO
    por ordem de inserção), NUNCA um `set`: `set.pop()` tem ordem dependente do
    PYTHONHASHSEED (varia por processo) e, sob o teto `max_pages`, fazia cada
    execução varrer páginas diferentes → entry bundles/lazy-chunks diferentes →
    findings de SCA (retire.js) divergentes entre scans do mesmo alvo.

    Retorna a lista de URLs de JS no domínio, ordenada (`sorted`) — entrada
    estável para o worklist a jusante.
    """
    queue = discovery_seeds(target)
    queued = set(queue)
    crawled, js_urls = set(), set()
    count = 0
    qi = 0
    while qi < len(queue) and count < max_pages:
        url = queue[qi]
        qi += 1
        if url in crawled:
            continue
        crawled.add(url)
        count += 1
        content, _status, _ct = fetch_fn(url)
        if not content:
            continue
        for m in _SCRIPT_SRC.finditer(content):
            u = _normalize(m.group(1), url)
            if u and domain in u:
                js_urls.add(u)
        for m in _JS_REF.finditer(content):
            u = _normalize(m.group(1), url)
            if u and domain in u:
                js_urls.add(u)
        for m in _HREF.finditer(content):
            u = _normalize(m.group(1), url)
            if u and domain in u and not u.endswith(_NON_PAGE_EXT):
                pu = urlparse(u)
                nxt = f"{pu.scheme}://{pu.netloc}{pu.path}"
                if nxt not in queued:
                    queued.add(nxt)
                    queue.append(nxt)
    return sorted(js_urls)


if __name__ == "__main__":
    if len(sys.argv) >= 3 and sys.argv[1] == "chunks":
        with open(sys.argv[2], encoding="utf-8", errors="replace") as fh:
            data = fh.read()
        for u in webpack_chunk_urls(data, sys.argv[3] if len(sys.argv) > 3 else ""):
            print(u)
    else:
        print("uso: js_chunks.py chunks <entry.js> <entry_url>", file=sys.stderr)
        sys.exit(2)

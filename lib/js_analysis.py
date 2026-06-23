#!/usr/bin/env python3
"""
js_analysis.py — Análise de JS (secrets, endpoints, frameworks) → js_*.json

Extraído de stiglitz.sh (heredoc PYJS). Recebe argumentos posicionais
via sys.argv, idêntico à invocação original do stiglitz.sh.
"""
import urllib.request, urllib.parse, urllib.error, re, os, sys, json, ssl, hashlib, time
import http.client
import netproxy
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pii_detect import extract_pii, build_pii_findings
import finding_quality as fq
import js_chunks

OUTDIR, TARGET, DOMAIN = sys.argv[1], sys.argv[2], sys.argv[3]
os.makedirs(os.path.join(OUTDIR,"raw","js_files"), exist_ok=True)

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
HEADERS = {"User-Agent":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0"}

def fetch(url, timeout=15):
    try:
        req = urllib.request.Request(url, headers=HEADERS)
        with netproxy.urlopen(req, timeout=timeout, context=ctx) as r:
            return (r.read().decode("utf-8", errors="replace"), r.status,
                    r.headers.get("Content-Type", ""))
    except Exception as e:
        return None, str(e), ""

def normalize(url, base):
    if not url or url.startswith(("data:","javascript:","mailto:","#")): return None
    if url.startswith("//"): return base.split("://")[0] + ":" + url
    if url.startswith("/"):
        p = urllib.parse.urlparse(base)
        return f"{p.scheme}://{p.netloc}{url}"
    if not url.startswith("http"): return urllib.parse.urljoin(base, url)
    return url

# ── Fase 8a: Descoberta de arquivos JS ───────────────────────────
pages = {TARGET}
extra = ["/","/login","/app","/dashboard","/api/docs/","/swagger-ui/"]
parsed = urllib.parse.urlparse(TARGET)
for path in extra:
    pages.add(f"{parsed.scheme}://{parsed.netloc}{path}")

crawled, js_urls = set(), set()
MAX_PAGES = 8
count = 0

while pages and count < MAX_PAGES:
    url = pages.pop()
    if url in crawled: continue
    crawled.add(url); count += 1
    content, status, _ct = fetch(url)
    if not content: continue
    # Extract <script src>
    for m in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', content, re.IGNORECASE):
        u = normalize(m.group(1), url)
        if u and DOMAIN in u: js_urls.add(u)
    # Webpack chunks
    for m in re.finditer(r'["\']([^"\']*\.(?:js|chunk\.js)(?:\?[^"\']*)?)["\']', content):
        u = normalize(m.group(1), url)
        if u and DOMAIN in u: js_urls.add(u)
    # Links for next pages
    for m in re.finditer(r'<a[^>]+href=["\']([^"\']+)["\']', content, re.IGNORECASE):
        u = normalize(m.group(1), url)
        if u and DOMAIN in u and not u.endswith((".js",".css",".png",".jpg",".ico")):
            pu = urllib.parse.urlparse(u)
            pages.add(f"{pu.scheme}://{pu.netloc}{pu.path}")

js_list = sorted(js_urls)
with open(os.path.join(OUTDIR,"raw","js_urls.txt"),"w") as f:
    f.write("\n".join(js_list))
print(f"  [✓] {len(js_list)} arquivo(s) JS descoberto(s)")

# ── Fase 8b: Download e detecção de secrets ──────────────────────
SECRET_PATTERNS = [
    (r'(?i)(?:api[_\-\.]?key|apikey|access[_-]?key)\s*[:=]\s*["\']([A-Za-z0-9_\-]{20,})["\']', "API Key"),
    (r'AKIA[0-9A-Z]{16}', "AWS Access Key"),
    (r'(?i)aws[_\-]?secret[_\-]?(?:access[_\-]?)?key\s*[:=]\s*["\']([A-Za-z0-9/+]{40})["\']', "AWS Secret"),
    (r'arn:aws:[a-zA-Z0-9\-]+:[a-z0-9\-]*:[0-9]{12}:[^\s"\']+', "AWS ARN"),
    (r'AIza[0-9A-Za-z\-_]{33,}', "Google API Key"),
    (r'ghp_[A-Za-z0-9]{36}', "GitHub Token"),
    (r'glpat-[A-Za-z0-9_\-]{20}', "GitLab PAT"),
    (r'sk-proj-[A-Za-z0-9_\-]{20,}', "OpenAI Key"),
    (r'sk-ant-[A-Za-z0-9_\-]{20,}', "Anthropic Key"),
    (r'sk-[A-Za-z0-9]{48}', "OpenAI Legacy"),
    (r'eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}', "JWT Token"),
    (r'sk_live_[A-Za-z0-9]{24,}', "Stripe Live Key"),
    (r'["\']AIzaSy[A-Za-z0-9_\-]{33}["\']', "Firebase Key"),
    (r'(?i)(?:mongodb|postgres|mysql|redis|amqp)://[^\s"\'<>]{10,}', "DB Connection String"),
    (r'(?i)(?:password|passwd|pwd)\s*[:=]\s*["\']([^"\']{8,64})["\']', "Hardcoded Password"),
    (r'(?i)(?:secret[_\-]?key|client[_-]?secret)\s*[:=]\s*["\']([A-Za-z0-9_\-]{16,})["\']', "Secret Key"),
    (r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----[A-Za-z0-9+/=\s]{40,5000}-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----', "Private Key"),
    (r'xox[baprs]-[A-Za-z0-9\-]{10,}', "Slack Token"),
    (r'https?://(?:localhost|127\.0\.0\.1|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})[^\s"\'<>]*', "URL Rede Interna"),
    (r'https?://[a-zA-Z0-9\-\.]+\.(?:internal|local|corp|lan|intranet|dev|staging|hml)[^\s"\'<>]*', "Domínio Interno"),
]
ENDPOINT_PATTERNS = [
    r'(?:fetch|axios|http\.(?:get|post|put|delete|patch))\s*\(["\']([^"\']+)["\']',
    r'(?:url|endpoint|baseUrl|apiUrl|API_URL)\s*[:=]\s*["\']([^"\']{5,})["\']',
    r'["\']/(api|v\d+|graphql|rest|admin|auth|user|users|token|tokens|upload|webhook)[^"\'<>\s]{0,100}["\']',
]
FRAMEWORK_PATTERNS = [
    (r'[Rr]eact["\s\.]+[vV]?ersion["\s:]+["\']?(\d+\.\d+[\.\d]*)', "React"),
    (r'[Aa]ngular["\s\.]+[vV]?ersion["\s:]+["\']?(\d+\.\d+[\.\d]*)', "Angular"),
    (r'[Vv]ue(?:\.js)?["\s\.]+[vV]?ersion["\s:]+["\']?(\d+\.\d+[\.\d]*)', "Vue.js"),
    (r'jquery["\s]+v?(\d+\.\d+[\.\d]*)', "jQuery"),
    (r'axios["\s\/]+(\d+\.\d+[\.\d]*)', "Axios"),
    (r'next(?:js)?["\s\.]+[vV]?ersion["\s:]+["\']?(\d+\.\d+[\.\d]*)', "Next.js"),
]
VULN_VERSIONS = {
    "jQuery": [("< 3.5.0", lambda v: tuple(int(x) for x in v.split(".")[:3]) < (3,5,0), "XSS via HTML parsing", "CVE-2020-11022")],
    "React":  [("< 16.13.0", lambda v: tuple(int(x) for x in v.split(".")[:2]) < (16,13), "SSR XSS", "CVE-2018-6341")],
}
FP_WORDS = {"example","placeholder","your-key","your_key","xxx","dummy","test","sample","foo","bar","changeme"}

# Vocabulário de UI/i18n que aparece após "password:" mas NÃO é credencial
# (ex: 'password:"Password input field"', placeholders, labels, validações).
_PWD_UI_WORDS = {"input","field","label","placeholder","enter","confirm","required",
                 "invalid","forgot","reset","change","current","again","match","hint",
                 "show","hide","toggle","strength","minimum","maximum","characters",
                 "must","least","contain","empty","wrong","incorrect","new","old","please"}

def _looks_like_password(v):
    """Heurística de precisão: credenciais reais não têm espaços nem
    vocabulário de UI. Reduz falsos-positivos de labels/placeholders."""
    v = (v or "").strip()
    if not v or " " in v:
        return False
    low = v.lower()
    if any(w in low for w in _PWD_UI_WORDS):
        return False
    return True

all_secrets, all_endpoints, all_frameworks, all_comments, js_stats = [], set(), [], [], []

# PII (e-mail corporativo, CPF/CNPJ, telefone BR) — domínio(s) corporativo(s)
# derivado(s) do alvo; extra via STIGLITZ_CORP_DOMAINS (CSV) p/ orgs multi-domínio.
pii_agg = {"emails_corporate": set(), "emails_external": set(),
           "cpf": set(), "cnpj": set(), "phones": set()}
pii_source = None
_corp_domains = [DOMAIN] + [d.strip() for d in
                 os.environ.get("STIGLITZ_CORP_DOMAINS", "").split(",") if d.strip()]

# Worklist (fila) em vez de iterar js_list direto: permite enfileirar os lazy
# chunks webpack descobertos no entry bundle durante a varredura.
worklist = list(js_list)
seen_js = set()
chunks_added = 0
wi = 0
while wi < len(worklist):
    js_url = worklist[wi]; wi += 1
    if js_url in seen_js: continue
    seen_js.add(js_url)
    print(f"  [>] {js_url[:80]}")
    content, status, ctype = fetch(js_url)
    if not content: continue
    # Anti-FP: SPA com catch-all devolve index.html (200, text/html) p/ path
    # inexistente; não tratar HTML como JS (origem de falso "secret em bundle").
    if not js_chunks.is_js_payload(ctype, content):
        print(f"  [skip não-JS] {js_url[:70]} (Content-Type={ctype or '?'})")
        continue
    fname = hashlib.md5(js_url.encode()).hexdigest()[:8] + ".js"
    fpath = os.path.join(OUTDIR,"raw","js_files",fname)
    with open(fpath,"w",encoding="utf-8") as f: f.write(content)
    js_stats.append({"url":js_url,"size_kb":len(content)//1024,"file":fname})

    # Lazy chunks webpack (i.u): não aparecem como <script src>; resolve e enfileira.
    for cu in js_chunks.webpack_chunk_urls(content, js_url):
        if DOMAIN in cu and cu not in seen_js and cu not in worklist:
            worklist.append(cu); chunks_added += 1

    for pattern, label in SECRET_PATTERNS:
        for m in re.finditer(pattern, content, re.IGNORECASE|re.MULTILINE):
            val = m.group(0)
            if any(fp in val.lower() for fp in FP_WORDS): continue
            # Validação de precisão por tipo — descarta labels/placeholders de UI
            if label == "Hardcoded Password" and not _looks_like_password(
                    m.group(1) if m.lastindex else val):
                continue
            line_start = content.rfind("\n", 0, m.start())+1
            line_end = content.find("\n", m.end()); line_end = len(content) if line_end==-1 else line_end
            snippet = content[line_start:line_end].strip()[:200]
            all_secrets.append({"url":js_url,"file":fname,"type":label,"value":val,"context":snippet})

    for pat in ENDPOINT_PATTERNS:
        for m in re.finditer(pat, content, re.IGNORECASE):
            ep = (m.group(1) if m.lastindex else m.group(0)).strip("\"'")
            if len(ep) > 3: all_endpoints.add(ep)

    for pat, name in FRAMEWORK_PATTERNS:
        m = re.search(pat, content, re.IGNORECASE)
        if m:
            ver = m.group(1) if m.lastindex else "?"
            vulns = []
            for vrange, checker, detail, cve in VULN_VERSIONS.get(name,[]):
                try:
                    if checker(ver): vulns.append({"range":vrange,"detail":detail,"cve":cve})
                except (ValueError, TypeError, AttributeError, IndexError): pass
            all_frameworks.append({"framework":name,"version":ver,"url":js_url,"vulnerable":bool(vulns),"vulns":vulns})

    for cp in [r'//.*(?:TODO|FIXME|password|secret|api.?key|credential|token)[^\n]*',
               r'/\*[^*]*(?:password|secret|credential)[^*]*\*/']:
        for m in re.finditer(cp, content, re.IGNORECASE):
            all_comments.append({"url":js_url,"comment":m.group(0).strip()[:200]})

    _pii = extract_pii(content, _corp_domains)
    for _k in pii_agg:
        pii_agg[_k].update(_pii.get(_k, []))
    if pii_source is None and (_pii["emails_corporate"] or _pii["cpf"] or _pii["cnpj"]):
        pii_source = js_url

    time.sleep(0.2)

# ── Fase 8c: Verificação de endpoints ────────────────────────────
parsed_t = urllib.parse.urlparse(TARGET)
base = f"{parsed_t.scheme}://{parsed_t.netloc}"
probed = []
for ep in list(all_endpoints)[:30]:
    url = (base + ep) if ep.startswith("/") else (base+"/"+ep if not ep.startswith("http") else ep)
    try:
        req = urllib.request.Request(url, headers=HEADERS, method="GET")
        req.add_unredirected_header("Accept","application/json,text/html,*/*")
        with netproxy.urlopen(req, timeout=8, context=ctx) as r:
            st = r.status; ct = r.headers.get("Content-Type","")
            body = r.read(512).decode("utf-8",errors="replace")
    except urllib.error.HTTPError as e:
        st = e.code; ct = ""; body = ""
    except (urllib.error.URLError, OSError, http.client.HTTPException): st = 0; ct = ""; body = ""
    probed.append({"endpoint":ep,"url":url,"status":st,"content_type":ct[:80],
        "is_json":"json" in ct,"body_preview":body[:200] if st==200 else ""})
    time.sleep(0.1)

# ── Fase 8d: PII (e-mail corporativo, CPF/CNPJ, telefone BR) ──────
pii = {k: sorted(v) for k, v in pii_agg.items()}
# Descarta e-mails placeholder/exemplo de UI (fulano@empresa.com, seu.email@…) —
# não são PII real e geravam "Employee PII hardcoded" (medium) como FP.
pii["emails_corporate"] = fq.filter_placeholder_emails(pii.get("emails_corporate", []))
pii["emails_external"] = fq.filter_placeholder_emails(pii.get("emails_external", []))
pii_findings = build_pii_findings(pii, TARGET, pii_source or "")
with open(os.path.join(OUTDIR,"raw","pii_findings.json"),"w",encoding="utf-8") as f:
    json.dump(pii_findings, f, ensure_ascii=False, indent=2)

results = {"target":TARGET,"domain":DOMAIN,"js_files":js_stats,
    "secrets":all_secrets,"endpoints":sorted(all_endpoints),
    "frameworks":all_frameworks,"sensitive_comments":all_comments[:30],
    "endpoint_probes":probed,"pii":pii}
with open(os.path.join(OUTDIR,"raw","js_analysis.json"),"w",encoding="utf-8") as f:
    json.dump(results, f, ensure_ascii=False, indent=2)

print(f"  [✓] {len(js_stats)} JS varrido(s) (+{chunks_added} chunk webpack) | "
      f"{len(all_secrets)} secret(s) | {len(all_endpoints)} endpoint(s) | {len(all_frameworks)} framework(s)")
print(f"  [✓] PII: {len(pii['emails_corporate'])} e-mail corp | {len(pii['cpf'])} CPF | "
      f"{len(pii['cnpj'])} CNPJ | {len(pii['phones'])} tel → {len(pii_findings)} finding(s)")
print(f"  [✓] {len(probed)} endpoint(s) verificado(s)")

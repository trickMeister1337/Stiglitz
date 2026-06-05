# PCI DSS CDE Coverage — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Adicionar ao Stiglitz, somente nas URLs declaradas como CDE, detecção de PAN exposto, integridade de scripts de checkout (anti-Magecart) e tags `pci_req` no relatório.

**Architecture:** Quatro módulos Python em `lib/` seguindo o padrão dos coletores (fetch próprio, gravam `raw/*_findings.json`, agregados pelo `stiglitz_report.py`). Um helper de escopo lê `cde_targets.txt` (gitignored) e restringe todas as detecções dedicadas e tags PCI às URLs declaradas. Reusa `asset_classifier`/`criticality` para boost CDE.

**Tech Stack:** Python 3 (stdlib: `re`, `json`, `hashlib`, `urllib`, `ssl`), pytest, bash (`stiglitz.sh`). Sem novas dependências externas.

> ⚠️ **Segurança:** nenhum dado real de escopo entra em código/teste. Use sempre `example.com` e números de cartão de teste públicos (`4111111111111111` Visa, `5500000000000004` MC). `cde_targets.txt` é gitignored e lido em runtime.

---

## File Structure

- Create: `lib/cde_scope.py` — parse de `cde_targets.txt`; `in_cde_scope`/`cde_class`/`is_checkout`.
- Create: `lib/pan_scanner.py` — detector de PAN (Luhn + contexto + máscara) → `raw/pan_findings.json`.
- Create: `lib/payment_page_monitor.py` — inventário/integridade de scripts → `raw/payment_findings.json` + baseline.
- Create: `lib/pci_verdicts.py` — anota `pci_req` em findings já existentes (TLS/serviços/cookies) quando o ativo é CDE.
- Modify: `stiglitz_report.py` — agregar `pan_findings.json`/`payment_findings.json`; seção "PCI DSS CDE Coverage".
- Modify: `stiglitz.sh` — chamar os módulos na Fase 3, guardados por `cde_targets` presente.
- Create: `tests/test_cde_scope.py`, `tests/test_pan_scanner.py`, `tests/test_payment_monitor.py`, `tests/test_pci_verdicts.py`.

---

## Task 1: `lib/cde_scope.py` — fonte de escopo CDE

**Files:**
- Create: `lib/cde_scope.py`
- Test: `tests/test_cde_scope.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_cde_scope.py
import os, sys, tempfile, textwrap
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
import cde_scope

SAMPLE = textwrap.dedent("""
    # comentário
    web    https://checkout.example.com   checkout-app   checkout=true
    web    https://api.example.com
    infra  10.0.0.5                       db-node
    both   https://gateway.example.com
""")

def _write(tmp_path, content):
    p = os.path.join(tmp_path, "cde_targets.txt")
    with open(p, "w") as f:
        f.write(content)
    return p

def test_parse_types_and_checkout(tmp_path):
    t = cde_scope.load_targets(_write(tmp_path, SAMPLE))
    assert "https://checkout.example.com" in t["web"]
    assert "https://gateway.example.com" in t["web"]      # both → web
    assert "https://gateway.example.com" in t["infra"]    # both → infra
    assert "10.0.0.5" in t["infra"]
    assert "https://checkout.example.com" in t["checkout"]
    assert "https://api.example.com" not in t["checkout"]

def test_in_cde_scope_by_host(tmp_path):
    t = cde_scope.load_targets(_write(tmp_path, SAMPLE))
    assert cde_scope.in_cde_scope("https://api.example.com/v1/users", t)
    assert cde_scope.in_cde_scope("https://checkout.example.com/pay", t)
    assert not cde_scope.in_cde_scope("https://www.other.com/", t)

def test_is_checkout(tmp_path):
    t = cde_scope.load_targets(_write(tmp_path, SAMPLE))
    assert cde_scope.is_checkout("https://checkout.example.com/step1", t)
    assert not cde_scope.is_checkout("https://api.example.com/x", t)

def test_missing_file_returns_empty():
    t = cde_scope.load_targets("/nonexistent/cde_targets.txt")
    assert t["web"] == [] and t["infra"] == [] and t["checkout"] == []
    assert not cde_scope.in_cde_scope("https://anything.example.com", t)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_cde_scope.py -q`
Expected: FAIL with `ModuleNotFoundError: No module named 'cde_scope'`

- [ ] **Step 3: Write minimal implementation**

```python
# lib/cde_scope.py
"""
cde_scope.py — fonte de escopo CDE (Cardholder Data Environment).

Lê cde_targets.txt (gitignored) no formato `tipo alvo [label] [checkout=true]`
(tipos: web|infra|both; `#` comentário). Restringe as detecções PCI dedicadas
às URLs declaradas. Nunca contém dados reais — o arquivo é lido em runtime.
"""
import os
from urllib.parse import urlsplit


def _host(url):
    s = urlsplit(url if "://" in url else "//" + url)
    return (s.hostname or url).lower()


def default_path():
    env = os.environ.get("STIGLITZ_CDE_TARGETS")
    if env:
        return env
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(here, "cde_targets.txt")


def load_targets(path=None):
    path = path or default_path()
    out = {"web": [], "infra": [], "checkout": [], "labels": {}}
    if not path or not os.path.exists(path):
        return out
    with open(path, encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            typ, target = parts[0].lower(), parts[1]
            label = parts[2] if len(parts) >= 3 and "=" not in parts[2] else target
            out["labels"][target] = label
            if typ == "web":
                out["web"].append(target)
            elif typ == "infra":
                out["infra"].append(target)
            elif typ == "both":
                out["web"].append(target)
                out["infra"].append(target)
            else:
                (out["web"] if "://" in target else out["infra"]).append(target)
            if any(p == "checkout=true" for p in parts[2:]):
                out["checkout"].append(target)
    return out


def _hosts(targets, keys):
    hs = set()
    for k in keys:
        for t in targets.get(k, []):
            hs.add(_host(t))
    return hs


def in_cde_scope(url, targets):
    return _host(url) in _hosts(targets, ("web", "infra"))


def cde_class(url, targets):
    return "cde" if in_cde_scope(url, targets) else None


def is_checkout(url, targets):
    return _host(url) in _hosts(targets, ("checkout",))
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_cde_scope.py -q`
Expected: PASS (4 passed)

- [ ] **Step 5: Commit**

```bash
git add lib/cde_scope.py tests/test_cde_scope.py
git commit -m "feat(pci): cde_scope — lê cde_targets e restringe escopo CDE"
```

---

## Task 2: `lib/pan_scanner.py` — exposição de PAN (Req 3.5.1)

**Files:**
- Create: `lib/pan_scanner.py`
- Test: `tests/test_pan_scanner.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_pan_scanner.py
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
import pan_scanner as ps

def test_luhn_valid_and_invalid():
    assert ps.luhn("4111111111111111")       # cartão de teste Visa
    assert ps.luhn("5500000000000004")       # cartão de teste MC
    assert not ps.luhn("4111111111111112")   # dígito quebrado

def test_mask_keeps_bin_and_last4():
    assert ps.mask("4111111111111111") == "411111******1111"

def test_scan_text_detects_pan_with_context():
    body = "erro ao salvar card=4111111111111111 cvv=123"
    hits = ps.scan_text(body)
    assert hits == ["411111******1111"]

def test_scan_text_ignores_random_long_number():
    # 16 dígitos que NÃO passam Luhn e sem contexto de cartão
    body = "order id 1234567890123456 timestamp 9999999999999999"
    assert ps.scan_text(body) == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_pan_scanner.py -q`
Expected: FAIL with `ModuleNotFoundError: No module named 'pan_scanner'`

- [ ] **Step 3: Write minimal implementation**

```python
# lib/pan_scanner.py
"""
pan_scanner.py — detecta PAN exposto (Req PCI DSS 3.5.1) em respostas/JS do CDE.

Pipeline: candidatos por bandeira → validação Luhn → filtro de contexto
(palavras card/cvv/pan/expiry por perto) → mascaramento obrigatório (BIN…last4).
Nunca persiste o PAN inteiro. Roda apenas em URLs in-scope do CDE.

Uso: python3 pan_scanner.py <outdir> <target>
"""
import os, sys, re, json, ssl, urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cde_scope

PAN_RE = re.compile(
    r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b'
)
CTX_RE = re.compile(r'card|cvv|cvc|pan|cardnumber|card_number|expiry|validade', re.I)
_CTX = ctx = None


def luhn(n):
    s, alt = 0, False
    for d in reversed(n):
        d = int(d)
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        s += d
        alt = not alt
    return s % 10 == 0


def mask(pan):
    return pan[:6] + "*" * (len(pan) - 10) + pan[-4:]


def scan_text(body):
    """Retorna lista de PANs mascarados com Luhn-válido E contexto de cartão."""
    out = []
    for m in PAN_RE.finditer(body):
        pan = m.group(0)
        if not luhn(pan):
            continue
        window = body[max(0, m.start() - 40): m.end() + 40]
        if not CTX_RE.search(window):
            continue
        masked = mask(pan)
        if masked not in out:
            out.append(masked)
    return out


def _fetch(url, timeout=10):
    ctx_ssl = ssl.create_default_context()
    ctx_ssl.check_hostname = False
    ctx_ssl.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=timeout, context=ctx_ssl) as r:
        return r.read(2_000_000).decode("utf-8", "ignore")


def main(outdir, target):
    targets = cde_scope.load_targets()
    urls = [target]
    katana = os.path.join(outdir, "raw", "katana_urls.txt")
    if os.path.exists(katana):
        urls += [l.strip() for l in open(katana, errors="replace") if l.strip()]
    findings, seen, idx = [], set(), 0
    for url in urls:
        if url in seen or not cde_scope.in_cde_scope(url, targets):
            continue
        seen.add(url)
        try:
            body = _fetch(url)
        except Exception:
            continue
        masked = scan_text(body)
        if masked:
            idx += 1
            findings.append({
                "id": f"PAN-{idx:03d}", "tool": "pan-detector",
                "type": "pan_exposure", "source": "PCI PAN",
                "name": "Possível PAN exposto em resposta HTTP", "url": url,
                "severity": "critical", "pci_req": "3.5.1",
                "description": f"{len(masked)} string(s) Luhn-válidas com contexto de cartão.",
                "evidence": "PAN(s) mascarado(s): " + ", ".join(masked),
                "remediation": "PAN nunca deve ser exposto. Aplicar truncation/tokenização (Req 3.5.1).",
                "cve": "CWE-359",
            })
    out = os.path.join(outdir, "raw", "pan_findings.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(findings, f, indent=2, ensure_ascii=False)
    print(f"  [✓] PAN scanner: {len(findings)} achado(s) em ativos CDE → pan_findings.json"
          if findings else "  [○] PAN scanner: nenhum PAN exposto em ativos CDE")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2].rstrip("/"))
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_pan_scanner.py -q`
Expected: PASS (4 passed)

- [ ] **Step 5: Commit**

```bash
git add lib/pan_scanner.py tests/test_pan_scanner.py
git commit -m "feat(pci): pan_scanner — PAN com Luhn+contexto+máscara (Req 3.5.1)"
```

---

## Task 3: `lib/payment_page_monitor.py` — integridade de checkout (Req 6.4.3 / 11.6.1)

**Files:**
- Create: `lib/payment_page_monitor.py`
- Test: `tests/test_payment_monitor.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_payment_monitor.py
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
import payment_page_monitor as ppm

HTML = '''
<html><head>
<script src="https://checkout.example.com/app.js" integrity="sha384-abc"></script>
<script src="https://cdn.thirdparty.com/track.js"></script>
</head></html>
'''

def test_extract_scripts_classifies_and_flags_sri():
    items = ppm.extract_scripts(HTML, "https://checkout.example.com/pay")
    by_src = {i["src"]: i for i in items}
    assert by_src["https://checkout.example.com/app.js"]["third_party"] is False
    assert by_src["https://checkout.example.com/app.js"]["has_sri"] is True
    tp = by_src["https://cdn.thirdparty.com/track.js"]
    assert tp["third_party"] is True
    assert tp["has_sri"] is False

def test_diff_detects_new_script():
    prev = [{"src": "https://checkout.example.com/app.js", "sha384": "h1"}]
    curr = [{"src": "https://checkout.example.com/app.js", "sha384": "h1"},
            {"src": "https://cdn.evil.com/skim.js", "sha384": "h2"}]
    new, changed = ppm.diff_scripts(prev, curr)
    assert "https://cdn.evil.com/skim.js" in new
    assert changed == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_payment_monitor.py -q`
Expected: FAIL with `ModuleNotFoundError: No module named 'payment_page_monitor'`

- [ ] **Step 3: Write minimal implementation**

```python
# lib/payment_page_monitor.py
"""
payment_page_monitor.py — integridade de scripts em páginas de checkout
(Req PCI DSS 6.4.3 + 11.6.1). Inventaria <script src>, classifica 1ª/3ª parte,
checa SRI e CSP, calcula SHA-384 e compara com baseline anterior (Magecart).
Roda apenas em URLs marcadas checkout=true no cde_targets.

Uso: python3 payment_page_monitor.py <outdir> <target> [previous_outdir]
"""
import os, sys, re, json, ssl, hashlib, urllib.request
from urllib.parse import urlsplit

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cde_scope

SCRIPT_RE = re.compile(r'<script[^>]*\bsrc=["\']([^"\']+)["\'][^>]*>', re.I)
SRI_RE = re.compile(r'integrity=', re.I)


def _abs(src, base):
    return src if src.startswith("http") else base.rstrip("/") + "/" + src.lstrip("/")


def extract_scripts(html, page_url):
    base_host = (urlsplit(page_url).hostname or "").lower()
    items = []
    for m in re.finditer(r'<script[^>]*\bsrc=["\']([^"\']+)["\'][^>]*>', html, re.I):
        tag, src = m.group(0), m.group(1)
        full = _abs(src, page_url)
        host = (urlsplit(full).hostname or "").lower()
        items.append({
            "src": full,
            "third_party": bool(host) and host != base_host,
            "has_sri": bool(SRI_RE.search(tag)),
        })
    return items


def diff_scripts(prev, curr):
    prev_map = {s["src"]: s.get("sha384") for s in prev}
    new, changed = [], []
    for s in curr:
        if s["src"] not in prev_map:
            new.append(s["src"])
        elif prev_map[s["src"]] != s.get("sha384"):
            changed.append(s["src"])
    return new, changed


def _ssl_ctx():
    c = ssl.create_default_context()
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    return c


def _fetch(url, timeout=12, limit=None):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=timeout, context=_ssl_ctx()) as r:
        data = r.read(limit) if limit else r.read()
        csp = r.headers.get("Content-Security-Policy", "")
        return data, csp


def main(outdir, target, previous=None):
    targets = cde_scope.load_targets()
    base_dir = os.path.join(outdir, "raw", "payment_baseline")
    os.makedirs(base_dir, exist_ok=True)
    findings, idx = [], 0
    for url in [target] + targets.get("checkout", []):
        if not cde_scope.is_checkout(url, targets):
            continue
        try:
            raw, csp = _fetch(url, limit=2_000_000)
            html = raw.decode("utf-8", "ignore")
        except Exception:
            continue
        items = extract_scripts(html, url)
        for it in items:
            try:
                sb, _ = _fetch(it["src"], timeout=10)
                it["sha384"] = hashlib.sha384(sb).hexdigest()
            except Exception:
                it["sha384"] = None
            if it["third_party"] and not it["has_sri"]:
                idx += 1
                findings.append({
                    "id": f"PAY-{idx:03d}", "tool": "payment-monitor",
                    "type": "script_integrity", "source": "PCI Payment Page",
                    "name": f"Script de 3ª parte sem SRI em checkout: {it['src'][:70]}",
                    "url": url, "severity": "high", "pci_req": "6.4.3, 11.6.1",
                    "description": "Script de terceiro sem Subresource Integrity em página de pagamento.",
                    "evidence": f"src={it['src']}",
                    "remediation": "Adicionar SRI (integrity=) e CSP script-src restritiva; autorizar e monitorar (Req 6.4.3).",
                    "cve": "",
                })
        if not csp:
            idx += 1
            findings.append({
                "id": f"PAY-{idx:03d}", "tool": "payment-monitor",
                "type": "script_integrity", "source": "PCI Payment Page",
                "name": "CSP ausente em página de checkout", "url": url,
                "severity": "medium", "pci_req": "6.4.3",
                "description": "Página de pagamento sem Content-Security-Policy.",
                "evidence": "Header Content-Security-Policy ausente.",
                "remediation": "Definir CSP com script-src restritiva (Req 6.4.3).",
                "cve": "",
            })
        safe = re.sub(r'[^A-Za-z0-9]', "_", url)
        with open(os.path.join(base_dir, safe + ".json"), "w") as f:
            json.dump({"url": url, "scripts": items}, f, indent=2)
        if previous:
            prev_file = os.path.join(previous, "raw", "payment_baseline", safe + ".json")
            if os.path.isfile(prev_file):
                prev = json.load(open(prev_file)).get("scripts", [])
                new, changed = diff_scripts(prev, items)
                for src in new + changed:
                    idx += 1
                    findings.append({
                        "id": f"PAY-{idx:03d}", "tool": "payment-monitor",
                        "type": "script_integrity", "source": "PCI Payment Page",
                        "name": f"Script novo/alterado em checkout: {src[:60]}", "url": url,
                        "severity": "high", "pci_req": "11.6.1",
                        "description": "Script mudou desde o último scan (possível Magecart/skimmer).",
                        "evidence": f"src={src}",
                        "remediation": "Investigar alteração não autorizada (Req 11.6.1).",
                        "cve": "",
                    })
    out = os.path.join(outdir, "raw", "payment_findings.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(findings, f, indent=2, ensure_ascii=False)
    print(f"  [✓] Payment monitor: {len(findings)} achado(s) → payment_findings.json"
          if findings else "  [○] Payment monitor: checkout íntegro / sem alvos checkout")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2].rstrip("/"), sys.argv[3] if len(sys.argv) > 3 else None)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_payment_monitor.py -q`
Expected: PASS (2 passed)

- [ ] **Step 5: Commit**

```bash
git add lib/payment_page_monitor.py tests/test_payment_monitor.py
git commit -m "feat(pci): payment_page_monitor — SRI/CSP/baseline anti-Magecart (Req 6.4.3/11.6.1)"
```

---

## Task 4: `lib/pci_verdicts.py` — anota `pci_req` em findings existentes

**Files:**
- Create: `lib/pci_verdicts.py`
- Test: `tests/test_pci_verdicts.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_pci_verdicts.py
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
import pci_verdicts as pv

TARGETS = {"web": ["https://api.example.com"], "infra": [], "checkout": [], "labels": {}}

def test_tags_tls_finding_in_cde():
    f = {"source": "testssl.sh", "name": "TLS 1.0 (obsoleto)",
         "url": "https://api.example.com", "severity": "high"}
    pv.tag_finding(f, TARGETS)
    assert f.get("pci_req") == "4.2.1"

def test_tags_service_finding_in_cde():
    f = {"source": "Service Version", "name": "ftp exposto",
         "url": "api.example.com:21/tcp", "severity": "high"}
    pv.tag_finding(f, TARGETS)
    assert f.get("pci_req") == "2.2.5"

def test_no_tag_outside_cde():
    f = {"source": "testssl.sh", "name": "TLS 1.0", "url": "https://other.com", "severity": "high"}
    pv.tag_finding(f, TARGETS)
    assert "pci_req" not in f
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_pci_verdicts.py -q`
Expected: FAIL with `ModuleNotFoundError: No module named 'pci_verdicts'`

- [ ] **Step 3: Write minimal implementation**

```python
# lib/pci_verdicts.py
"""
pci_verdicts.py — anota pci_req em findings já existentes quando o ativo é CDE.
Mapeia categorias já coletadas (TLS, serviços, cookies/cache) ao requisito PCI.
Não cria findings novos; apenas etiqueta os do escopo CDE declarado.
"""
import os, sys, re
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cde_scope

_TLS_RE = re.compile(r'tls|ssl|cipher|certificad|cert\b', re.I)
_SVC_RE = re.compile(r'telnet|ftp|snmp|smb|rdp|mysql|postgres|mongo|redis|exposto', re.I)
_COOKIE_RE = re.compile(r'cookie|cache-control|httponly|samesite|secure flag', re.I)


def _url_of(f):
    return f.get("url") or f.get("target") or f.get("matched_at") or ""


def tag_finding(f, targets):
    """Anota f['pci_req'] in-place se o ativo for CDE e a categoria casar."""
    if not cde_scope.in_cde_scope(_url_of(f), targets):
        return f
    src = (f.get("source") or "")
    name = (f.get("name") or "")
    if src == "testssl.sh" or _TLS_RE.search(name):
        f["pci_req"] = "4.2.1"
    elif src == "Service Version" or _SVC_RE.search(name):
        f["pci_req"] = "2.2.5"
    elif _COOKIE_RE.search(name):
        f["pci_req"] = "3.2"
    return f


def tag_all(findings, targets=None):
    targets = targets or cde_scope.load_targets()
    for f in findings:
        if "pci_req" not in f:
            tag_finding(f, targets)
    return findings
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_pci_verdicts.py -q`
Expected: PASS (3 passed)

- [ ] **Step 5: Commit**

```bash
git add lib/pci_verdicts.py tests/test_pci_verdicts.py
git commit -m "feat(pci): pci_verdicts — tag pci_req em findings de ativos CDE"
```

---

## Task 5: `stiglitz_report.py` — agregar findings PCI + seção CDE

**Files:**
- Modify: `stiglitz_report.py` (loop de agregação de `*_findings.json`; nova seção)

- [ ] **Step 1: Adicionar os novos arquivos ao loop de agregação**

Localizar o loop que lê `service_findings.json` (introduzido antes) e acrescentar as duas linhas:

```python
    ('service_findings.json',    'service_findings'),
    ('pan_findings.json',        'pan_findings'),
    ('payment_findings.json',    'payment_findings'),
]:
```

- [ ] **Step 2: Aplicar tags PCI antes do cálculo de stats**

Logo após `all_f = sorted(... )`, inserir:

```python
import sys as _sys, os as _os
_sys.path.insert(0, _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "lib"))
import cde_scope as _cde, pci_verdicts as _pv
_cde_targets = _cde.load_targets()
_pv.tag_all(all_f, _cde_targets)
```

- [ ] **Step 3: Registrar cores das novas sources**

Em `src_cls` e no dict `_src_color`, acrescentar (seguindo o padrão de `Service Version`):

```python
    src_cls = ('source-nuclei'  if _src == 'Nuclei'              else
               'source-headers' if _src == 'Security Headers'    else
               'source-version' if _src in ('Version Fingerprint', 'Service Version',
                                            'PCI PAN', 'PCI Payment Page') else
               'source-zap')
```
```python
        "Service Version":     "#c0622e",
        "PCI PAN":             "#7a0000",
        "PCI Payment Page":    "#8e44ad",
    }
```

- [ ] **Step 4: Adicionar a seção "PCI DSS CDE Coverage"**

Antes da montagem final do HTML, construir a seção (findings com `pci_req`, agrupados por requisito):

```python
_pci_findings = [f for f in all_f if f.get("pci_req")]
pci_section_html = ""
if _pci_findings:
    by_req = {}
    for f in _pci_findings:
        by_req.setdefault(f["pci_req"], []).append(f)
    rows = ""
    for req in sorted(by_req):
        for f in by_req[req]:
            rows += (f"<tr><td>{html.escape(req)}</td>"
                     f"<td>{badge(f['severity'])}</td>"
                     f"<td style='font-size:12px'>{html.escape(f.get('name',''))}</td>"
                     f"<td style='font-size:11px'>{html.escape(_url_of_report(f))}</td></tr>")
    pci_section_html = (
        "<h2>PCI DSS CDE Coverage</h2>"
        "<p>Achados em ativos declarados no escopo CDE, por requisito PCI DSS 4.0.1.</p>"
        "<table><tr><th>Req</th><th>Sev</th><th>Achado</th><th>Ativo</th></tr>"
        + rows + "</table>")
```

Onde `_url_of_report(f)` é um helper local: `return f.get('url') or f.get('target') or ''`. Definir junto das demais funções de render se não existir.

- [ ] **Step 5: Inserir a seção no corpo do relatório**

Adicionar `{pci_section_html}` no template HTML final, logo após a tabela de findings principais.

- [ ] **Step 6: Validar o relatório standalone**

Run:
```bash
T=/tmp/pci_report_test; rm -rf "$T"; mkdir -p "$T/raw"
printf '[{"id":"PAN-001","source":"PCI PAN","name":"Possível PAN exposto","url":"https://api.example.com","severity":"critical","pci_req":"3.5.1","description":"x","remediation":"y","cve":"CWE-359"}]' > "$T/raw/pan_findings.json"
printf 'web https://api.example.com\n' > "$T/cde_targets.txt"
STIGLITZ_CDE_TARGETS="$T/cde_targets.txt" OUTDIR="$T" TARGET=https://api.example.com DOMAIN=api.example.com python3 stiglitz_report.py
grep -c "PCI DSS CDE Coverage" "$T/stiglitz_report.html"
```
Expected: relatório gerado; `grep` retorna `1`.

- [ ] **Step 7: Commit**

```bash
git add stiglitz_report.py
git commit -m "feat(pci): relatório agrega PAN/payment findings + seção PCI DSS CDE Coverage"
```

---

## Task 6: `stiglitz.sh` — wiring dos coletores PCI na Fase 3

**Files:**
- Modify: `stiglitz.sh` (Fase 3, junto a security_headers/secscan)

- [ ] **Step 1: Adicionar a chamada condicional ao escopo CDE**

Após a chamada do `secscan.py` na Fase 3, inserir:

```bash
# ── PCI/CDE: detecções dedicadas apenas se houver escopo CDE declarado ──
_cde_file="${STIGLITZ_CDE_TARGETS:-$SCRIPT_DIR/cde_targets.txt}"
if [ -s "$_cde_file" ]; then
    echo -e "  ${BLUE}[…]${NC} PCI/CDE: escopo declarado detectado — rodando detecções dedicadas..."
    python3 "$SCRIPT_DIR/lib/pan_scanner.py" "$OUTDIR" "$TARGET" || true
    python3 "$SCRIPT_DIR/lib/payment_page_monitor.py" "$OUTDIR" "$TARGET" || true
else
    echo -e "  ${YELLOW}[○]${NC} PCI/CDE: sem cde_targets.txt — detecções PCI dedicadas puladas"
fi
unset _cde_file
```

- [ ] **Step 2: Validar sintaxe**

Run: `bash -n stiglitz.sh && shellcheck --severity=warning stiglitz.sh`
Expected: sem erros.

- [ ] **Step 3: Dry-run não deve quebrar**

Run: `bash stiglitz.sh https://example.com --dry-run`
Expected: plano impresso, exit 0, nenhum diretório criado.

- [ ] **Step 4: Commit**

```bash
git add stiglitz.sh
git commit -m "feat(pci): wiring dos coletores PCI na Fase 3 (guardado por cde_targets)"
```

---

## Task 7: Validação final e CLAUDE.md

**Files:**
- Modify: `CLAUDE.md` (tabela `lib/`) — nota: CLAUDE.md é gitignored localmente; atualizar mesmo assim para referência.

- [ ] **Step 1: Suíte completa**

Run:
```bash
bash -n stiglitz.sh && shellcheck --severity=warning stiglitz.sh
python3 -m py_compile lib/cde_scope.py lib/pan_scanner.py lib/payment_page_monitor.py lib/pci_verdicts.py stiglitz_report.py
python3 -m pytest tests/test_cde_scope.py tests/test_pan_scanner.py tests/test_payment_monitor.py tests/test_pci_verdicts.py tests/test_lib.py tests/test_stiglitz_modules.py tests/test_criticality.py -q
```
Expected: tudo verde.

- [ ] **Step 2: Auditoria de segurança (sem dados reais)**

Run (substitua `<CLIENT_TERMS>` pelos termos sensíveis do cliente — **não versione essa lista**; mantenha-a fora do repo, p.ex. em `$STIGLITZ_SENSITIVE_TERMS`):
`git grep -icE "$STIGLITZ_SENSITIVE_TERMS" -- ':!swarm-pci' | grep -v ':0' || echo CLEAN`
Expected: `CLEAN`.

- [ ] **Step 3: Registrar módulos no CLAUDE.md** (linha na tabela `lib/`):

```
| `cde_scope.py`, `pan_scanner.py`, `payment_page_monitor.py`, `pci_verdicts.py` | Cobertura PCI DSS restrita ao CDE (cde_targets): PAN (3.5.1), Magecart (6.4.3/11.6.1), tag pci_req |
```

- [ ] **Step 4: Commit**

```bash
git add CLAUDE.md
git commit -m "docs(pci): registra módulos PCI/CDE no CLAUDE.md"
```

---

## Self-Review

**Spec coverage:**
- §4 cde_scope → Task 1 ✓
- §5 PAN → Task 2 ✓
- §6 Magecart → Task 3 ✓
- §7 vereditos pci_req → Task 4; seção relatório → Task 5 ✓
- §8 wiring fases → Task 6 ✓
- §9 segurança → Task 7 Step 2 (auditoria) + dados fictícios em todos os testes ✓
- §10 testes → um por módulo ✓

**Placeholders:** nenhum TBD/TODO; todo código presente. (Task 5 referencia trechos existentes do `stiglitz_report.py` por âncora textual — intencional, é modificação de arquivo grande existente.)

**Type consistency:** `load_targets`/`in_cde_scope`/`is_checkout`/`cde_class` usados de forma consistente entre Tasks 1–6; `scan_text`/`mask`/`luhn` em Task 2; `extract_scripts`/`diff_scripts` em Task 3; `tag_finding`/`tag_all` em Task 4. Sources `"PCI PAN"`/`"PCI Payment Page"` consistentes entre Tasks 2,3,5. Campo `pci_req` consistente entre 2,3,4,5.

**Limpeza temporária:** Task 5 Step 6 e qualquer `/tmp/*test*` devem ser removidos ao final (não versionados).

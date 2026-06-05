"""
payment_page_monitor.py — integridade de scripts em páginas de checkout
(Req PCI DSS 6.4.3 + 11.6.1). Inventaria <script src>, classifica 1ª/3ª parte,
checa SRI e CSP, calcula SHA-384 e compara com baseline anterior (Magecart).
Roda apenas em URLs marcadas checkout=true no cde_targets.

Uso: python3 payment_page_monitor.py <outdir> <target> [previous_outdir]
"""
import os, sys, re, json, ssl, hashlib, urllib.request
from urllib.parse import urlsplit, urljoin

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cde_scope

SRI_RE = re.compile(r'(?<![\w-])integrity\s*=\s*["\']\s*(?:sha256|sha384|sha512)-', re.I)


def _abs(src, base):
    return urljoin(base, src)


def extract_scripts(html, page_url):
    base_host = (urlsplit(page_url).hostname or "").lower()
    items = []
    for m in re.finditer(r'<script[^>]*?(?<![\w-])src\s*=\s*["\']([^"\']+)["\'][^>]*>', html, re.I):
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
    target = target.rstrip("/")
    targets = cde_scope.load_targets()
    base_dir = os.path.join(outdir, "raw", "payment_baseline")
    os.makedirs(base_dir, exist_ok=True)
    findings, idx = [], 0
    for url in dict.fromkeys([target] + targets.get("checkout", [])):
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
                    "name": f"Third-party script without SRI on checkout: {it['src'][:70]}",
                    "url": url, "severity": "high", "pci_req": "6.4.3, 11.6.1",
                    "description": "Third-party script without Subresource Integrity on a payment page.",
                    "evidence": f"src={it['src']}",
                    "remediation": "Add SRI (integrity=) and a restrictive CSP script-src; authorize and monitor (Req 6.4.3).",
                    "cve": "",
                })
        if not csp:
            idx += 1
            findings.append({
                "id": f"PAY-{idx:03d}", "tool": "payment-monitor",
                "type": "script_integrity", "source": "PCI Payment Page",
                "name": "CSP missing on checkout page", "url": url,
                "severity": "medium", "pci_req": "6.4.3",
                "description": "Payment page without Content-Security-Policy.",
                "evidence": "Content-Security-Policy header absent.",
                "remediation": "Define a CSP with a restrictive script-src (Req 6.4.3).",
                "cve": "",
            })
        safe = re.sub(r'[^A-Za-z0-9]', "_", url)[:150] + "_" + hashlib.md5(url.encode()).hexdigest()[:8]
        with open(os.path.join(base_dir, safe + ".json"), "w") as f:
            json.dump({"url": url, "scripts": items}, f, indent=2)
        if previous:
            prev_file = os.path.join(previous, "raw", "payment_baseline", safe + ".json")
            if os.path.isfile(prev_file):
                with open(prev_file) as fh:
                    prev_scripts = json.load(fh).get("scripts", [])
                new, changed = diff_scripts(prev_scripts, items)
                for src, kind in [(s, "new") for s in new] + [(s, "changed") for s in changed]:
                    idx += 1
                    findings.append({
                        "id": f"PAY-{idx:03d}", "tool": "payment-monitor",
                        "type": "script_integrity", "source": "PCI Payment Page",
                        "name": f"Script {kind} on checkout: {src[:60]}", "url": url,
                        "severity": "high", "pci_req": "11.6.1",
                        "description": f"Script {kind} since last scan (possible Magecart/skimmer).",
                        "evidence": f"src={src}",
                        "remediation": "Investigate unauthorized change (Req 11.6.1).",
                        "cve": "",
                    })
    out = os.path.join(outdir, "raw", "payment_findings.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(findings, f, indent=2, ensure_ascii=False)
    print(f"  [✓] Payment monitor: {len(findings)} achado(s) → payment_findings.json"
          if findings else "  [○] Payment monitor: checkout íntegro / sem alvos checkout")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2].rstrip("/"), sys.argv[3] if len(sys.argv) > 3 else None)

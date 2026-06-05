"""
pan_scanner.py — detecta PAN exposto (Req PCI DSS 3.5.1) em respostas/JS do CDE.

Pipeline: candidatos por bandeira → validação Luhn → filtro de contexto
(palavras card/cvv/pan/expiry por perto) → mascaramento obrigatório (BIN…last4).
Nunca persiste o PAN inteiro. Roda apenas em URLs in-scope do CDE.

Uso: python3 pan_scanner.py <outdir> <target>
Limitação conhecida: detecta apenas PANs em dígitos contíguos; números com espaços/hífens (ex.: "4111 1111 1111 1111") não são casados.
"""
import os, sys, re, json, ssl, urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cde_scope

PAN_RE = re.compile(
    r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b'
)
CTX_RE = re.compile(r'card|cvv|cvc|pan|cardnumber|card_number|expiry|validade', re.I)


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
    out, seen = [], set()
    for m in PAN_RE.finditer(body):
        pan = m.group(0)
        if not luhn(pan):
            continue
        window = body[max(0, m.start() - 40): m.end() + 40]
        if not CTX_RE.search(window):
            continue
        masked = mask(pan)
        if masked not in seen:
            seen.add(masked)
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
        with open(katana, errors="replace") as fh:
            urls += [l.strip() for l in fh if l.strip()]
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
                "name": "Potential PAN exposed in HTTP response", "url": url,
                "severity": "critical", "pci_req": "3.5.1",
                "description": f"{len(masked)} Luhn-valid string(s) with card context.",
                "evidence": "Masked PAN(s): " + ", ".join(masked),
                "remediation": "PAN must never be exposed. Apply truncation/tokenization (Req 3.5.1).",
                "cve": "CWE-359",
            })
    out = os.path.join(outdir, "raw", "pan_findings.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(findings, f, indent=2, ensure_ascii=False)
    print(f"  [✓] PAN scanner: {len(findings)} achado(s) em ativos CDE → pan_findings.json"
          if findings else "  [○] PAN scanner: nenhum PAN exposto em ativos CDE")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2].rstrip("/"))

#!/usr/bin/env python3
"""
stiglitz_report.py — Gerador de relatório HTML do Stiglitz.

Lê os artefatos em $OUTDIR/raw/ e gera:
  - stiglitz_report.html   (relatório técnico completo)
  - executive_summary.html (sumário executivo)
  - findings.json          (achados estruturados)

Entrada via variáveis de ambiente (exportadas pelo stiglitz.sh):
  OUTDIR, TARGET, DOMAIN, SCAN_START_TS, OPEN_PORTS, ACTIVE_COUNT,
  SUB_COUNT, IS_SUBDOMAIN, OPENAPI_FOUND, TLS_ISSUES, CONFIRMED_COUNT,
  JS_SECRETS, JS_ENDPOINTS, JS_FRAMEWORKS, JS_FILES, KATANA_URLS,
  WAF_DETECTED, WAF_NAME, EMAIL_ISSUES, SMUGGLER_FOUND, FFUF_FOUND,
  TRUFFLEHOG_FOUND, AUTH_TOKEN, AUTH_HEADER, WPSCAN_VULNS

Uso direto (regenerar relatório de um scan existente):
  OUTDIR=scan_dir TARGET=https://alvo DOMAIN=alvo python3 stiglitz_report.py
"""
import json, os, html, re, sys
from datetime import datetime, timezone

# Permite importar módulos de lib/ quando rodado como script standalone
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))
from risk_score import compute_risk, HIGH_JS_TYPES  # noqa: E402
from report.cwe_data import (  # noqa: E402
    CWE_CVSS_TABLE, IMPACT_MAP, REMEDIATION_MAP, cwe_enrich, cvss_to_sev,
)
from report.sarif import build_sarif  # noqa: E402
from report.exec_summary import build_exec_summary  # noqa: E402
from report_helpers import inject_cve_signals  # noqa: E402

# Tabelas CWE → CVSS sintético, impacto, remediação + helpers cwe_enrich/
# cvss_to_sev estão em lib/report/cwe_data.py (importado acima).

OUTDIR          = os.environ.get('OUTDIR','scan_output')

def _derive_domain_from_outdir(outdir):
    """Extrai o domínio do padrão scan_<domain>_YYYYMMDD_HHMMSS."""
    base = os.path.basename(outdir.rstrip('/'))
    m = re.match(r'^scan_(.+)_\d{8}_\d{6}$', base)
    if m:
        return m.group(1)
    # fallback: strip prefixo scan_ se existir
    if base.startswith('scan_'):
        return base[5:]
    return None

def _derive_domain_from_files(outdir):
    """Tenta extrair o domínio do primeiro subdomínio ou URL nos arquivos raw."""
    for fname in ('subdomains.txt', 'nuclei_urls.txt', 'katana_urls.txt'):
        fpath = os.path.join(outdir, 'raw', fname)
        try:
            with open(fpath, encoding='utf-8') as _f:
                for line in _f:
                    line = line.strip()
                    if not line:
                        continue
                    # linha pode ser URL ou hostname puro
                    if line.startswith('http'):
                        from urllib.parse import urlparse
                        h = urlparse(line).hostname or ''
                    else:
                        h = line.split('/')[0]
                    if h and '.' in h:
                        return h
        except OSError:
            continue
    return None

_env_target = os.environ.get('TARGET', '')
_env_domain = os.environ.get('DOMAIN', '')
if not _env_domain:
    _env_domain = _derive_domain_from_outdir(OUTDIR) or _derive_domain_from_files(OUTDIR) or 'example.com'
TARGET = _env_target if _env_target else f'https://{_env_domain}'
DOMAIN = _env_domain

# ── KPIs: a env var tem precedência (preserva o run monolítico byte-a-byte);
#    na ausência, deriva dos arquivos em raw/. Isso permite que a fase de
#    relatório (P11) rode standalone — `stiglitz.sh --only-phase P11 --outdir X` —
#    sob o orquestrador pipeline.py, sem depender de variáveis em memória.
def _raw(name): return os.path.join(OUTDIR, "raw", name)

def _count_lines(name):
    try:
        with open(_raw(name), encoding="utf-8", errors="ignore") as f:
            return sum(1 for ln in f if ln.strip())
    except OSError:
        return 0

def _json_load(name):
    try:
        with open(_raw(name), encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None

def _derive_tls():
    d = _json_load("testssl.json")
    if d is None: return 0
    fnd = d if isinstance(d, list) else d.get("scanResult",[{}])[0].get("findings",[])
    return len([f for f in fnd if f.get("severity","") in ("WARN","HIGH","CRITICAL","LOW")])

def _derive_confirmed():
    d = _json_load("exploit_confirmations.json")
    return sum(1 for c in d if c.get("confirmed")) if isinstance(d, list) else 0

def _derive_js(key):
    d = _json_load("js_analysis.json")
    return len(d.get(key, [])) if isinstance(d, dict) else 0

def _derive_ffuf():
    d = _json_load("ffuf.json")
    return len(d.get("results", [])) if isinstance(d, dict) else 0

def _derive_email():
    d = _json_load("email_security.json")
    if not isinstance(d, dict): return 0
    return sum(1 for v in d.values() if isinstance(v, dict) and v.get("severity","") in ("high","medium"))

def _derive_smuggler():
    try:
        txt = open(_raw("smuggler.txt"), encoding="utf-8", errors="ignore").read()
    except OSError:
        return 0
    return 1 if re.search(r"vulnerable|CL\.TE|TE\.CL|CL\.0|desync", txt, re.I) else 0

def _derive_open_ports():
    try:
        ports = [m.group(1) for ln in open(_raw("nmap.txt"), encoding="utf-8", errors="ignore")
                 if (m := re.match(r"^(\d+/tcp)\s+open", ln))]
    except OSError:
        return "N/A"
    return " ".join(ports) if ports else "nenhuma"

def _derive_waf_name():
    try:
        n = open(_raw("waf_name.txt"), encoding="utf-8").read().strip()
        if n: return n
    except OSError:
        pass
    d = _json_load("waf.json")
    results = d if isinstance(d, list) else (d.get("results", []) if isinstance(d, dict) else [])
    for r in results:
        if isinstance(r, dict):
            fw = r.get("firewall","") or r.get("waf","")
            if fw and fw.lower() not in ("none","generic",""):
                return fw
    return ""

def _env_or(name, derived):
    """Retorna a env var se definida (mesmo '0'/''), senão o valor derivado."""
    v = os.environ.get(name)
    return v if v is not None and v != "" else derived

_d_waf_name = _derive_waf_name()

OPEN_PORTS      = _env_or('OPEN_PORTS', _derive_open_ports())
ACTIVE_COUNT    = _env_or('ACTIVE_COUNT', str(_count_lines("httpx_results.txt")))
SUB_COUNT       = _env_or('SUB_COUNT', str(_count_lines("subdomains.txt")))
OPENAPI_FOUND   = (os.environ.get('OPENAPI_FOUND','0') == '1') if 'OPENAPI_FOUND' in os.environ \
                  else os.path.exists(_raw("openapi_spec.json"))
TLS_ISSUES      = int(_env_or('TLS_ISSUES', _derive_tls()))
CONFIRMED_COUNT = int(_env_or('CONFIRMED_COUNT', _derive_confirmed()))
SCAN_START_TS   = int(os.environ.get('SCAN_START_TS','0'))

# Carregar tempos por fase
phase_times = {}
_ptf = os.path.join(OUTDIR,'raw','.phase_times')
if os.path.exists(_ptf):
    try:
        for _line in open(_ptf):
            _parts = _line.strip().split(':')
            if len(_parts) >= 5 and _parts[1] == 'end':
                phase_times[_parts[0]] = int(_parts[4])
    except: pass
JS_SECRETS      = int(_env_or('JS_SECRETS', _derive_js("secrets")))
JS_ENDPOINTS    = int(_env_or('JS_ENDPOINTS', _derive_js("endpoints")))
JS_FRAMEWORKS   = int(_env_or('JS_FRAMEWORKS', _derive_js("frameworks")))
JS_FILES        = int(_env_or('JS_FILES', _derive_js("js_files")))
KATANA_URLS      = int(_env_or('KATANA_URLS', _count_lines("katana_urls.txt")))
SMUGGLER_FOUND   = int(_env_or('SMUGGLER_FOUND', _derive_smuggler()))
FFUF_FOUND       = int(_env_or('FFUF_FOUND', _derive_ffuf()))
TRUFFLEHOG_FOUND = int(_env_or('TRUFFLEHOG_FOUND', _count_lines("trufflehog.json")))
WAF_DETECTED    = (os.environ.get('WAF_DETECTED','') == '1') if 'WAF_DETECTED' in os.environ \
                  else bool(_d_waf_name)
WAF_NAME        = os.environ.get('WAF_NAME') if os.environ.get('WAF_NAME') is not None else _d_waf_name
EMAIL_ISSUES    = int(_env_or('EMAIL_ISSUES', _derive_email()))
errors = []

# Nuclei
findings = []
_seen_nuclei = set()  # dedup: (template-id, host) — info-pass + main pass podem duplicar
nuclei_file = os.path.join(OUTDIR,"raw","nuclei.json")
if os.path.exists(nuclei_file) and os.path.getsize(nuclei_file) > 0:
    with open(nuclei_file,"r",encoding="utf-8") as f:
        for ln, line in enumerate(f,1):
            line = line.strip()
            if not line: continue
            try:
                data = json.loads(line)
                info = data.get("info",{})
                sev  = info.get("severity","info").lower()
                cl   = info.get("classification",{}) or {}
                cves = cl.get("cve-id",[]) or []

                # Dedup por (template-id, host): mesma vulnerabilidade no mesmo host
                # aparece uma vez só, mesmo se bater em vários paths/matchers.
                _tid = data.get("template-id","")
                _host = data.get("host", "")
                _dedup_key = (_tid, _host)
                if _dedup_key in _seen_nuclei:
                    continue
                _seen_nuclei.add(_dedup_key)

                # Evidência: montar a partir de request/response/matcher do nuclei
                ev_parts = []
                if data.get("request"): ev_parts.append("REQUEST:\n" + str(data["request"]))
                if data.get("response"): ev_parts.append("RESPONSE:\n" + str(data["response"]))
                if data.get("extracted-results"): ev_parts.append("EXTRACTED: " + str(data["extracted-results"]))
                if data.get("curl-command"): ev_parts.append("CURL:\n" + str(data["curl-command"]))
                ev = "\n\n".join(ev_parts)  # sem truncagem — evidência completa
                meta = data.get("meta",{}) or {}
                findings.append({"source":"Nuclei","name":info.get("name","Vuln"),
                    "severity":sev,"description":(info.get("description","N/A") or "N/A"),
                    "cve":", ".join(cves) if cves else "N/A","url":data.get("matched-at",TARGET),
                    "remediation":info.get("remediation","Revisar.") or "Revisar.",
                    "evidence":ev,
                    "param":str(meta.get("username","") or meta.get("param","") or ""),
                    "attack":str(meta.get("password","") or ""),
                    "other":_tid})
            except json.JSONDecodeError as e: errors.append(f"Nuclei L{ln}: {e}")
            except Exception as e: errors.append(f"Nuclei L{ln}: {type(e).__name__}: {e}")

# ZAP — com deduplicação de alertas repetidos e filtro de confiança
zap_findings = []
zap_low_groups = {}  # Low/Info: tabela compacta
zap_dedup      = {}  # Critical/High/Medium: card único por tipo
# Carregar request/response do XML ZAP para evidência completa
_zap_xml_evidence = {}  # name -> {request, response}
_zap_xml_path = os.path.join(OUTDIR,"raw","zap_evidencias.xml")
if os.path.exists(_zap_xml_path):
    try:
        import xml.etree.ElementTree as ET
        _xtree = ET.parse(_zap_xml_path)
        for _xalert in _xtree.findall(".//alertitem"):
            _xname = (_xalert.findtext("alert") or "").strip()
            if _xname and _xname not in _zap_xml_evidence:
                _xreq  = (_xalert.findtext("requestheader") or "").strip()
                _xreqb = (_xalert.findtext("requestbody") or "").strip()
                _xres  = (_xalert.findtext("responseheader") or "").strip()
                _xresb = (_xalert.findtext("responsebody") or "").strip()
                _xfull_req = _xreq + ("\n\n" + _xreqb if _xreqb else "")
                _xfull_res = _xres + ("\n\n" + _xresb if _xresb else "")  # evidência completa sem truncagem
                _zap_xml_evidence[_xname] = {
                    "request":  _xfull_req,
                    "response": _xfull_res
                }
    except Exception as _xe: errors.append(f"ZAP XML: {_xe}")

zap_file = os.path.join(OUTDIR,"raw","zap_alerts.json")
if os.path.exists(zap_file) and os.path.getsize(zap_file) > 0:
    try:
        zap_data = json.load(open(zap_file,"r",encoding="utf-8"))
        rmap = {"high":"high","medium":"medium","low":"low","informational":"info"}
        SKIP_CONFIDENCE = {"false positive"}

        # ── Padrões de URLs geradas pelo spider que não representam recursos reais ──
        # Redirects de autenticação (Jenkins, Jira, Confluence, etc.)
        # e URLs com parâmetros de redirect injetados pelo scanner
        URL_SKIP_PATTERNS = [
            r'/securityRealm/',          # Jenkins auth redirect
            r'moLogin\?from=',           # Jenkins login redirect
            r'j_spring_security',        # Spring Security login
            r'login\?from=%2F',          # Generic auth redirect
            r'login\?next=%2F',          # Django/Flask auth redirect
            r'signin\?returnUrl=',       # Generic signin redirect
            r'auth\?redirect=',          # Generic auth redirect
            r'\?from=%2F',              # ZAP-injected redirect param
            r'\?from=%2Fsitemap',        # sitemap redirect artifact
            r'\?from=%2Fstatic',         # static asset redirect artifact
            r'/j_acegi_security',        # Legacy Spring Security
            r'oauth/authorize\?',        # OAuth artifacts
            r'saml/login\?',             # SAML redirect artifacts
        ]

        def url_is_real(url):
            """Retorna False se a URL é claramente um artefato de redirect/scanner."""
            if not url:
                return True
            for pattern in URL_SKIP_PATTERNS:
                if re.search(pattern, url, re.IGNORECASE):
                    return False
            return True

        for i,a in enumerate(zap_data.get("alerts",[])):
            try:
                sev_orig = rmap.get(a.get("risk","info").lower(),"info")
                conf = a.get("confidence","").lower()
                if conf in SKIP_CONFIDENCE:
                    continue

                # ── Filtrar URLs que não representam recursos reais ──────────
                alert_url = a.get("url","")
                if not url_is_real(alert_url):
                    errors.append(f"ZAP URL filtrada (redirect artefato): {alert_url[:80]}")
                    continue
                # Reclassificar severidade via CVSS do CWE (Opção C — tabela sintética)
                _cweid = str(a.get("cweid","") or "")
                _cwe_data = cwe_enrich(_cweid)
                sev_reclassified = False
                if _cwe_data:
                    sev_from_cvss = cvss_to_sev(_cwe_data["cvss"])
                    if sev_from_cvss and sev_from_cvss != sev_orig:
                        sev = sev_from_cvss
                        sev_reclassified = True
                    else:
                        sev = sev_orig
                else:
                    sev = sev_orig
                # Evidência completa: campos JSON + request/response do XML ZAP
                ev_parts_zap = []
                _alert_name = a.get("name","")
                _xml_ev = _zap_xml_evidence.get(_alert_name, {})
                if a.get("param",""):      ev_parts_zap.append(f"Parameter: {a['param']}")
                if a.get("attack",""):     ev_parts_zap.append(f"Attack Vector:\n{a['attack']}")
                if a.get("evidence",""):   ev_parts_zap.append(f"Evidence:\n{a['evidence']}")
                if _xml_ev.get("request"): ev_parts_zap.append(f"--- HTTP REQUEST ---\n{_xml_ev['request']}")
                if _xml_ev.get("response"):ev_parts_zap.append(f"--- HTTP RESPONSE ---\n{_xml_ev['response']}")
                if a.get("other",""):      ev_parts_zap.append(f"Additional detail:\n{a['other']}")
                ev = "\n\n".join(ev_parts_zap)  # sem truncagem — evidência completa
                # Extrair CVE do campo reference; fallback para CWE
                _refs = a.get("reference","") or ""
                _cves = re.findall(r"CVE-\d{4}-\d{4,7}", _refs, re.IGNORECASE)
                _cve_str = ", ".join(sorted(set(c.upper() for c in _cves))) if _cves \
                    else f"CWE-{a.get('cweid','N/A')}"
                f_entry = {"source":"OWASP ZAP","name":a.get("name","Alerta"),
                    "severity":sev,
                    "severity_orig":sev_orig,
                    "severity_reclassified":sev_reclassified,
                    "cvss_synthetic":_cwe_data["cvss"] if _cwe_data else None,
                    "description":(a.get("description","N/A") or "N/A"),
                    "cve": f"{_cve_str} | Conf: {a.get('confidence','?')}",
                    "url":a.get("url",TARGET),
                    "remediation":a.get("solution","Revisar.") or "Revisar.",
                    "evidence":ev,
                    "param":(a.get("param","") or ""),
                    "attack":(a.get("attack","") or ""),
                    "other":(a.get("other","") or "")}
                # Estratégia de deduplicação por severidade:
                # Critical/High → card único por nome (melhor evidência + lista de URLs)
                # Medium        → card único por nome (melhor evidência + lista de URLs)
                # Low/Info      → tabela compacta agrupada
                name = a.get("name","Alerta")
                url  = a.get("url","")
                if sev in ("low","info"):
                    if name not in zap_low_groups:
                        zap_low_groups[name] = {"count":0,"urls":[],"finding":f_entry,
                            "cve": _cve_str, "conf":a.get("confidence","?"),
                            "sev": sev}
                    zap_low_groups[name]["count"] += 1
                    if url and url not in zap_low_groups[name]["urls"]:
                        zap_low_groups[name]["urls"].append(url)
                else:
                    # Deduplicar Medium/High/Critical por nome
                    # Manter o finding com maior evidência; acumular URLs distintas
                    if name not in zap_dedup:
                        zap_dedup[name] = {"finding": f_entry, "urls": [], "count": 0, "sev": sev}
                    # Promover para maior severidade encontrada
                    sev_order = {"critical":0,"high":1,"medium":2,"low":3,"info":4}
                    if sev_order.get(sev,5) < sev_order.get(zap_dedup[name]["sev"],5):
                        zap_dedup[name]["finding"] = f_entry
                        zap_dedup[name]["sev"] = sev
                    # Preferir finding com evidência real
                    if f_entry.get("evidence") and not zap_dedup[name]["finding"].get("evidence"):
                        zap_dedup[name]["finding"] = f_entry
                    zap_dedup[name]["count"] += 1
                    if url and url not in zap_dedup[name]["urls"]:
                        zap_dedup[name]["urls"].append(url)
            except Exception as e: errors.append(f"ZAP alerta {i}: {e}")
    except json.JSONDecodeError as e: errors.append(f"ZAP JSON malformado: {e}")
    except Exception as e: errors.append(f"ZAP: {e}")

# Converter zap_dedup em zap_findings, injetando lista de URLs afetadas
for name, grp in zap_dedup.items():
    f = dict(grp["finding"])  # cópia
    affected = grp["urls"]
    f["severity"] = grp["sev"]  # severidade mais alta encontrada
    f["affected_count"] = grp["count"]
    f["affected_urls"] = affected
    # Se mais de uma URL, adicionar lista às outras informações do card
    if len(affected) > 1:
        extra = f"\n\n[{len(affected)} URLs afetadas]\n" + "\n".join(f"  • {u}" for u in affected[:20])
        if len(affected) > 20:
            extra += f"\n  ... e mais {len(affected)-20} URL(s)"
        f["other"] = (f.get("other","") + extra).strip()
    zap_findings.append(f)

# httpx / nmap
httpx_lines = []
hf = os.path.join(OUTDIR,"raw","httpx_results.txt")
if os.path.exists(hf):
    try: httpx_lines = [l.strip() for l in open(hf) if l.strip()]
    except Exception as e: errors.append(f"httpx: {e}")

nmap_lines = []
nf = os.path.join(OUTDIR,"raw","nmap.txt")
if os.path.exists(nf):
    try: nmap_lines = [l.strip() for l in open(nf) if "open" in l and "/tcp" in l]
    except Exception as e: errors.append(f"nmap: {e}")

# ── testssl ───────────────────────────────────────────────────
# Mapeamento de IDs testssl → nome legível, descrição e remediação
TLS_ID_INFO = {
    "cipherlist_NULL": {
        "name": "NULL Cipher Suites Enabled (No Encryption)",
        "desc": "The server accepts NULL cipher suites, which apply no encryption to traffic. Any attacker with network access can read and modify data in transit without barriers.",
        "rem":  "Disable all NULL cipher suites in the server's TLS configuration. Nginx: ssl_ciphers 'HIGH:!NULL:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5'; Apache: SSLCipherSuite HIGH:!NULL:!aNULL. Restart the server after the change.",
    },
    "cipherlist_aNULL": {
        "name": "Anonymous Cipher Suites Enabled (No Authentication)",
        "desc": "The server accepts anonymous cipher suites (aNULL/anonymous DH), which do not authenticate the server. This enables Man-in-the-Middle attacks where an attacker impersonates the legitimate server without the client noticing.",
        "rem":  "Disable aNULL and anonymous DH cipher suites. Nginx: ssl_ciphers 'HIGH:!aNULL:!NULL:!eNULL'; Apache: SSLCipherSuite HIGH:!aNULL:!NULL. Also remove EXPORT, DES and RC4 ciphers from the configuration.",
    },
    "cipherlist_EXPORT": {
        "name": "EXPORT Cipher Suites Enabled (Weak Encryption — FREAK/LogJam)",
        "desc": "The server accepts export-grade cipher suites (40-56 bits), created in the 1990s to bypass US export regulations. They are vulnerable to the FREAK (CVE-2015-0204) and LOGJAM attacks.",
        "rem":  "Remove EXPORT cipher suites: ssl_ciphers '!EXPORT' (Nginx) / SSLCipherSuite !EXPORT (Apache). Upgrade to TLS 1.2+ with modern ciphers (AES-256-GCM, CHACHA20).",
    },
    "cipherlist_LOW": {
        "name": "Low-Security Cipher Suites Enabled",
        "desc": "The server accepts cipher suites with weak encryption (DES, RC2, 56-bit). These ciphers can be brute-forced with modern hardware.",
        "rem":  "Remove all LOW and MEDIUM ciphers: ssl_ciphers 'HIGH:!LOW:!MEDIUM:!EXPORT:!aNULL:!NULL' (Nginx). Keep only AES-128-GCM, AES-256-GCM and CHACHA20-POLY1305.",
    },
    "cipherlist_3DES_IDEA": {
        "name": "3DES/IDEA Enabled (Vulnerable to SWEET32)",
        "desc": "The server accepts 3DES or IDEA, vulnerable to the SWEET32 attack (CVE-2016-2183) which allows decrypting long sessions after ~768 GB of data exchanged.",
        "rem":  "Disable 3DES and IDEA: add '!3DES:!IDEA' to the ssl_ciphers directive. Prioritize AES-GCM and CHACHA20.",
    },
    "cipherlist_OBSOLETED": {
        "name": "Obsolete Cipher Suites Enabled",
        "desc": "The server accepts cipher suites considered obsolete (RC4, DES, IDEA, SEED or similar). These ciphers have known weaknesses and should not be used in production environments.",
        "rem":  "Restrict the server to modern cipher suites: TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256 (TLS 1.3) and ECDHE-ECDSA-AES256-GCM-SHA384, ECDHE-RSA-AES256-GCM-SHA384 (TLS 1.2).",
    },
    "cipherlist_STRONG_NOFS": {
        "name": "Lack of Forward Secrecy in Strong Ciphers",
        "desc": "Strong cipher suites without Perfect Forward Secrecy (PFS) are enabled. If the server's private key is compromised in the future, recorded past sessions can be decrypted retroactively.",
        "rem":  "Prioritize ECDHE/DHE cipher suites: ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305'. Disable static RSA key exchange.",
    },
    "fallback_SCSV": {
        "name": "TLS Fallback SCSV Not Supported (Vulnerable to Downgrade)",
        "desc": "The server does not support TLS Fallback SCSV (RFC 7507), a mechanism that prevents protocol downgrade attacks. Without it, a MITM attacker can force the connection to use an older, less secure TLS version.",
        "rem":  "Update the server's TLS library (OpenSSL 1.0.1j+, NSS 3.17.1+). SCSV support is automatic in modern versions. Also disable TLS 1.0 and 1.1 to eliminate the downgrade vector.",
    },
    "BEAST": {
        "name": "BEAST Vulnerability (CVE-2011-3389)",
        "desc": "The server is vulnerable to the BEAST attack via CBC in TLS 1.0. A MITM attacker can inject plaintext and perform a chosen-plaintext attack to recover portions of the traffic.",
        "rem":  "Disable TLS 1.0: ssl_protocols TLSv1.2 TLSv1.3 (Nginx). Prioritizing RC4 ciphers was once suggested as mitigation, but RC4 is also weak — the correct fix is to disable TLS 1.0.",
    },
    "LUCKY13": {
        "name": "LUCKY13 Vulnerability (CVE-2013-0169)",
        "desc": "The server is potentially vulnerable to LUCKY13, a timing attack against CBC in TLS/DTLS that may allow partial plaintext recovery.",
        "rem":  "Prioritize GCM (AEAD) ciphers over CBC: ssl_ciphers 'ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:!CBC'. In TLS 1.3, LUCKY13 does not apply.",
    },
    "POODLE_SSL": {
        "name": "POODLE Vulnerability (CVE-2014-3566) — SSLv3",
        "desc": "The server supports SSLv3, vulnerable to the POODLE attack which allows recovering individual plaintext bytes in HTTPS sessions through padding oracle attacks.",
        "rem":  "Disable SSLv3 immediately: ssl_protocols TLSv1.2 TLSv1.3 (Nginx) / SSLProtocol TLSv1.2 TLSv1.3 (Apache). SSLv3 must not be used in any production scenario.",
    },
    "POODLE_TLS": {
        "name": "POODLE-TLS Vulnerability — Padding Oracle in TLS",
        "desc": "TLS implementation vulnerable to POODLE via a padding oracle in TLS (not only SSLv3). Some TLS stacks accept invalid padding without reporting an error, enabling an attack similar to the original POODLE.",
        "rem":  "Update the server/TLS library to a version that fixes the padding oracle. Enable only TLS 1.2 and 1.3, which are resistant to this attack.",
    },
    "DROWN": {
        "name": "DROWN Vulnerability (CVE-2016-0800)",
        "desc": "The server, or a server sharing the same private key, supports SSLv2, vulnerable to DROWN. An attacker can decrypt modern TLS sessions using the SSLv2 oracle.",
        "rem":  "Disable SSLv2 on all servers sharing the private key. Revoke and reissue certificates if the key was exposed. Never reuse the same private key across services with different TLS configurations.",
    },
    "LOGJAM": {
        "name": "LOGJAM Vulnerability — Weak DH (CVE-2015-4000)",
        "desc": "The server accepts Diffie-Hellman parameters of insufficient size (< 2048 bits), vulnerable to the LOGJAM attack which allows downgrade to export-grade DH and offline decryption.",
        "rem":  "Generate strong DH parameters: openssl dhparam -out dhparam.pem 2048. Configure ssl_dhparam /etc/nginx/dhparam.pem. Prefer ECDHE over DHE to eliminate this vector.",
    },
    "SWEET32": {
        "name": "SWEET32 Vulnerability (CVE-2016-2183)",
        "desc": "The server supports 64-bit block ciphers (3DES, DES, IDEA, Blowfish), vulnerable to SWEET32. After ~768 GB of data with the same session key, block collisions allow partial plaintext recovery.",
        "rem":  "Disable 3DES, DES, IDEA and Blowfish: add '!3DES:!DES:!IDEA' to ssl_ciphers. Limit TLS session duration (ssl_session_timeout 1h) as additional mitigation.",
    },
    "ROBOT": {
        "name": "ROBOT Vulnerability — Return of Bleichenbacher Oracle Threat",
        "desc": "The server is vulnerable to ROBOT, a variation of the 1998 Bleichenbacher attack that allows decrypting RSA sessions and forging RSA signatures using RSA PKCS#1 v1.5.",
        "rem":  "Disable static RSA key exchange: remove non-ECDHE RSA ciphers. Enable only forward-secrecy ciphers (ECDHE). Update the TLS library if the vendor released a specific patch.",
    },
    "HEARTBLEED": {
        "name": "Heartbleed Vulnerability (CVE-2014-0160) — CRITICAL",
        "desc": "The server is vulnerable to Heartbleed, a critical OpenSSL flaw that allows reading up to 64 KB of process memory per request. Data such as private keys, passwords and session tokens can be extracted remotely without authentication.",
        "rem":  "Update OpenSSL to 1.0.1g+ / 1.0.2+ IMMEDIATELY. Revoke all certificates and generate new ones after patching. Invalidate all active sessions and force user password resets.",
    },
    "CCS": {
        "name": "OpenSSL CCS Injection (CVE-2014-0224)",
        "desc": "The server is vulnerable to OpenSSL's ChangeCipherSpec injection. It allows a MITM attacker to inject a null session key, decrypting and modifying TLS traffic in real time.",
        "rem":  "Update OpenSSL to version 0.9.8za, 1.0.0m or 1.0.1h and above. This vulnerability requires a library patch — there is no configuration workaround.",
    },
    "CRIME_TLS": {
        "name": "CRIME Vulnerability (CVE-2012-4929) — TLS Compression",
        "desc": "The server supports TLS compression, vulnerable to CRIME. An attacker injecting text into the traffic can infer session cookies and tokens by analyzing variation in compressed size.",
        "rem":  "Disable TLS compression: ssl_comp_add_compression_method() must not be called; in OpenSSL, compile with -DOPENSSL_NO_COMP. In modern Nginx, TLS compression is already disabled by default.",
    },
    "BREACH": {
        "name": "BREACH Vulnerability — HTTP Compression",
        "desc": "The server uses HTTP compression (gzip) on responses that contain secrets (CSRF tokens, session data), vulnerable to BREACH. Similar to CRIME but exploiting compression at the HTTP layer.",
        "rem":  "Disable compression on responses containing secrets: do not compress endpoints with CSRF tokens or sensitive data. Implement per-request variable CSRF tokens (masked tokens). General HTTP compression can be kept on static assets.",
    },
    "TICKETBLEED": {
        "name": "Ticketbleed Vulnerability (CVE-2016-9244)",
        "desc": "The F5/Citrix server is vulnerable to Ticketbleed, a flaw in TLS session tickets that leaks up to 31 bytes of uninitialized memory per connection.",
        "rem":  "Apply the vendor patch (F5 BIG-IP, Citrix). Disable TLS session tickets as a temporary mitigation: ssl_session_tickets off (Nginx).",
    },
    "TLS1": {
        "name": "TLS 1.0 Enabled (Deprecated Protocol)",
        "desc": "The server supports TLS 1.0, deprecated by the IETF (RFC 8996) and prohibited by PCI DSS since 2018. It is subject to multiple attacks (BEAST, POODLE, CRIME) and uses weak hash functions (MD5/SHA-1).",
        "rem":  "Disable TLS 1.0 and 1.1: ssl_protocols TLSv1.2 TLSv1.3 (Nginx) / SSLProtocol -all +TLSv1.2 +TLSv1.3 (Apache). Verify compatibility with legitimate clients before applying.",
    },
    "TLS1_1": {
        "name": "TLS 1.1 Enabled (Deprecated Protocol)",
        "desc": "The server supports TLS 1.1, deprecated by the IETF (RFC 8996) along with TLS 1.0. It does not support AEAD cipher suites and uses legacy MAC constructions vulnerable to timing attacks.",
        "rem":  "Disable TLS 1.1: ssl_protocols TLSv1.2 TLSv1.3 (Nginx). Keep only TLS 1.2 (with GCM ciphers) and TLS 1.3.",
    },
    "SSLv2": {
        "name": "SSLv2 Enabled (Severely Vulnerable Protocol)",
        "desc": "The server supports SSLv2, a completely broken protocol using 40-bit encryption, with no replay protection and vulnerable to DROWN. It must be disabled in any environment.",
        "rem":  "Disable SSLv2 immediately: ssl_protocols TLSv1.2 TLSv1.3 (Nginx). If the server does not allow disabling SSLv2, replace the server/TLS library.",
    },
    "SSLv3": {
        "name": "SSLv3 Enabled (Vulnerable to POODLE)",
        "desc": "The server supports SSLv3, vulnerable to POODLE (CVE-2014-3566) and lacking TLS extensions support. All SSLv3 communications can be decrypted by a MITM attacker.",
        "rem":  "Disable SSLv3: ssl_protocols TLSv1.2 TLSv1.3 (Nginx) / SSLProtocol -SSLv3 (Apache). There is no legitimate use for SSLv3 in 2024+.",
    },
    "HSTS": {
        "name": "HTTP Strict Transport Security (HSTS) Missing",
        "desc": "The server does not send the Strict-Transport-Security header, allowing unencrypted HTTP connections to be accepted and SSL stripping downgrade attacks to redirect users to HTTP.",
        "rem":  "Add the HSTS header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload (Nginx: add_header Strict-Transport-Security). Once stable, submit the domain to the HSTS preload list.",
    },
    "OCSP_stapling": {
        "name": "OCSP Stapling Not Configured",
        "desc": "The server does not use OCSP stapling, causing browsers to query the CA's OCSP server to check certificate revocation — which can leak the user's IP to the CA and add latency.",
        "rem":  "Enable OCSP stapling: ssl_stapling on; ssl_stapling_verify on; resolver 8.8.8.8 (Nginx). Verify that the CA supports OCSP and the certificate has the OCSP URL extension.",
    },
    "DNS_CAArecord": {
        "name": "CAA DNS Record Missing",
        "desc": "The domain has no CAA (Certification Authority Authorization) record, which restricts which CAs may issue certificates for the domain. Without CAA, any CA in the world can issue certificates, increasing the risk of fraudulent certificates.",
        "rem":  "Add a CAA record in DNS: example for Let's Encrypt: 0 issue letsencrypt.org; 0 issuewild letsencrypt.org; 0 iodef mailto:security@domain.com. Verify with: dig CAA domain.com",
    },
    "cert_expired": {
        "name": "Expired TLS Certificate",
        "desc": "The server's TLS certificate is expired. Browsers will show a security error to all users, potentially making the application inaccessible.",
        "rem":  "Renew the certificate immediately. Implement automatic renewal via Let's Encrypt (certbot renew) or expiration monitoring with alerts 30+ days in advance.",
    },
    "cert_notYetValid": {
        "name": "TLS Certificate Not Yet Valid",
        "desc": "The TLS certificate has a start date (NotBefore) in the future. The server is presenting an invalid certificate to all clients.",
        "rem":  "Verify that the system clock is synchronized (NTP). Reissue the certificate with correct dates from the CA.",
    },
    "cert_chain_of_trust": {
        "name": "Invalid or Incomplete Certificate Chain",
        "desc": "The server does not present the full chain of intermediate certificates, preventing clients from validating the certificate correctly. This may cause SSL errors in some clients.",
        "rem":  "Configure the server to send the intermediate certificates (chain): ssl_certificate /path/to/fullchain.pem (Nginx). The fullchain.pem file must contain: server certificate + intermediate(s) + root (optional).",
    },
}

tls_findings = []
tf = os.path.join(OUTDIR,"raw","testssl.json")
if os.path.exists(tf) and os.path.getsize(tf) > 0:
    try:
        tdata = json.load(open(tf,"r",encoding="utf-8"))
        findings_raw = tdata if isinstance(tdata,list) else \
            tdata.get("scanResult",[{}])[0].get("findings",[])
        SEV_MAP = {"CRITICAL":"critical","HIGH":"high","WARN":"medium","LOW":"low","OK":"info","INFO":"info"}
        _tls_seen_ids = set()  # dedup: testssl escaneia múltiplos IPs → mesmo id duplicado
        for item in findings_raw:
            sev_raw = item.get("severity","INFO")
            sev = SEV_MAP.get(sev_raw.upper(),"info")
            _tls_id = item.get("id","")
            # scanTime é metadado do testssl (duração do scan), não uma vulnerabilidade
            # "not supported by local OpenSSL" = limitação do scanner local, não vulnerabilidade do servidor
            _tls_raw_pre = item.get("finding","")
            if sev_raw.upper() in ("CRITICAL","HIGH","WARN","LOW") and _tls_id != "scanTime" \
                    and _tls_id not in _tls_seen_ids \
                    and "not supported by local openssl" not in _tls_raw_pre.lower():
                _tls_raw  = _tls_raw_pre  # resultado bruto do teste (ex: "offered")
                _cve_raw  = item.get("cve","") or item.get("cwe","")
                _info     = TLS_ID_INFO.get(_tls_id, {})
                _name     = _info.get("name") or f"TLS/SSL: {_tls_id}" if _tls_id else "TLS/SSL Issue"
                _desc     = _info.get("desc") or f"testssl.sh reported '{_tls_raw}' for the '{_tls_id}' test."
                _rem      = _info.get("rem") or "Consult the server documentation to disable this insecure TLS feature."
                _evidence = f"testssl.sh · test: {_tls_id} · result: {_tls_raw}" if _tls_raw else f"testssl.sh · test: {_tls_id}"
                _tls_seen_ids.add(_tls_id)
                tls_findings.append({
                    "id":       _tls_id,
                    "name":     _name,
                    "severity": sev, "severity_orig": sev, "severity_reclassified": False,
                    "sev":      sev,
                    "sev_raw":  sev_raw,
                    "source":   "testssl.sh",
                    "url":      TARGET,
                    "cve":      _cve_raw, "cve_ids": [],
                    "finding":  _tls_raw,
                    "description": _desc,
                    "remediation": _rem,
                    "evidence": _evidence,
                    "param": "", "attack": "", "other": "",
                })
    except Exception as e: errors.append(f"testssl: {e}")

# ── exploit confirmations ─────────────────────────────────────
confirmations = []
cf = os.path.join(OUTDIR,"raw","exploit_confirmations.json")
if os.path.exists(cf) and os.path.getsize(cf) > 0:
    try: confirmations = json.load(open(cf,"r",encoding="utf-8"))
    except Exception as e: errors.append(f"confirmations: {e}")

# Normalização defensiva (igual ao stiglitz_report.py externo)
def _norm_sev_inline(v, default="info"):
    if not v: return default
    s = str(v).strip().lower()
    if s in ("crit","critical"): return "critical"
    if s in ("hi","high"): return "high"
    if s in ("med","medium","moderate"): return "medium"
    if s in ("lo","low"): return "low"
    if s in ("informational","information","info","none","unknown"): return "info"
    return s if s in ("critical","high","medium","low","info") else default

_nc = []
for _c in (confirmations if isinstance(confirmations, list) else []):
    if not isinstance(_c, dict): continue
    _sev_raw = (_c.get("severity") or (_c.get("info") or {}).get("severity")
                or _c.get("sev") or _c.get("risk"))
    if not _sev_raw:
        _cl = str(_c.get("confidence_level","")).lower()
        if "oob" in _cl or "rce" in _cl: _sev_raw = "critical"
        elif "reflected" in _cl or "sqli" in _cl: _sev_raw = "high"
        elif "version" in _cl: _sev_raw = "medium"
        elif "probable" in _cl: _sev_raw = "low"
        else: _sev_raw = "info"
    _c["severity"] = _norm_sev_inline(_sev_raw, "info")
    _c.setdefault("confirmed", False)
    _c.setdefault("template_id", _c.get("id") or _c.get("template-id") or "—")
    _c.setdefault("url", _c.get("matched-at") or _c.get("host") or _c.get("target") or "—")
    _c.setdefault("http_status", str(_c.get("status_code") or _c.get("status") or "—"))
    _c.setdefault("confidence", _c.get("confidence_score") or 0)
    try: _c["confidence"] = int(_c["confidence"])
    except Exception: _c["confidence"] = 0
    _c.setdefault("vuln_type", _c.get("type") or _c.get("confidence_level") or "")
    _c.setdefault("poc_note", _c.get("note") or _c.get("reason") or "—")
    _c.setdefault("response_headers", _c.get("headers") or "")
    _c.setdefault("response_body", _c.get("body") or _c.get("evidence") or "")
    _c.setdefault("curl_reproducible", _c.get("curl") or "")
    _c.setdefault("curl_command", _c.get("curl") or "")
    _url_v = str(_c.get("url","")).strip()
    _tid_v = str(_c.get("template_id","")).strip()
    if (not _url_v or _url_v == "—") and (not _tid_v or _tid_v == "—"):
        continue
    _nc.append(_c)
confirmations = _nc

# Classificar cada confirmação: "exploit" (abusável diretamente) vs
# "verified" (config/hardening apenas verificado). Evita rotular header
# ausente ou config TLS como "exploit confirmado".
_EXPLOIT_VULN_TYPES = ("sqli", "rce", "command_injection", "cmdi", "auth_bypass",
                       "default_login", "default-login", "ssrf", "lfi", "rfi",
                       "xss", "deserialization", "xxe", "ssti", "idor", "path_traversal")
_TLS_EXPLOIT_KW = ("null", "anull", "rc4", "export", "des", "3des", "sweet32",
                   "logjam", "drown", "beast", "poodle", "heartbleed", "ccs",
                   "robot", "ticketbleed", "crime", "cipherlist", "obsoleted")

def _confirmation_category(c):
    """exploit = vulnerabilidade abusável; verified = apenas verificado."""
    vt   = str(c.get("vuln_type", "")).lower()
    tid  = str(c.get("template_id", "")).lower()
    blob = vt + " " + tid
    if any(t in blob for t in _EXPLOIT_VULN_TYPES):
        return "exploit"
    if "default" in tid and "login" in tid:
        return "exploit"
    if vt == "tls" or any(x in tid for x in ("tls", "ssl", "cipher")):
        return "exploit" if any(x in tid for x in _TLS_EXPLOIT_KW) else "verified"
    return "verified"

for _c in confirmations:
    _c["category"] = _confirmation_category(_c)

# Mapa: identificador confirmado (template_id / id testssl) → categoria.
# Usado para marcar os cards/linhas correspondentes.
_confirmed_cat = {}
for _c in confirmations:
    if _c.get("confirmed"):
        _k = str(_c.get("template_id", "")).strip().lower()
        if _k and _k != "—":
            _confirmed_cat[_k] = _c["category"]

def _confirmed_category(f):
    """Retorna 'exploit'/'verified' se o finding tem confirmação correspondente,
    senão None. Nuclei guarda o template-id em f['other']; testssl em f['id']."""
    cands = []
    if f.get("source") == "Nuclei":
        cands.append(f.get("other", ""))
    cands.append(f.get("id", ""))
    for c in cands:
        ck = str(c).strip().lower()
        if ck and ck in _confirmed_cat:
            return _confirmed_cat[ck]
    return None

def _is_confirmed(f):
    return _confirmed_category(f) is not None

# ── WAF & Email Security ───────────────────────────────────
email_security = {}
_esf = os.path.join(OUTDIR,'raw','email_security.json')
if os.path.exists(_esf):
    try: email_security = json.load(open(_esf))
    except Exception as e: errors.append(f'email_security: {e}')

# Converter email_security dict em lista de findings para stats/risk
email_findings = []
if email_security:
    _EMAIL_CWE   = {'spf':'CWE-349','dmarc':'CWE-349','dkim':'CWE-345'}
    _EMAIL_NAMES = {
        'spf':   'SPF Missing — Domain Vulnerable to Email Spoofing',
        'dmarc': 'DMARC Missing — No Anti-Spoofing Protection',
        'dkim':  'DKIM Not Detected — Email Authenticity Compromised',
    }
    for _proto, _edata in email_security.items():
        _esev = _edata.get('severity','info')
        if _esev not in ('critical','high','medium','low'): continue
        email_findings.append({
            "id":       f"email-{_proto}",
            "name":     _EMAIL_NAMES.get(_proto, _proto.upper()),
            "severity": _esev, "severity_orig": _esev, "severity_reclassified": False,
            "source":   "Email Security",
            "url":      TARGET,
            "cve":      _EMAIL_CWE.get(_proto,''), "cve_ids": [],
            "description": _edata.get('detail',''),
            "remediation": _edata.get('recommendation',''),
            "evidence": "", "param": "", "attack": "", "other": "",
        })

# ── Scan metadata (comportamento + evasão) ───────────────────
scan_meta = {}
_smf = os.path.join(OUTDIR,'raw','scan_metadata.json')
if os.path.exists(_smf):
    try: scan_meta = json.load(open(_smf))
    except Exception as e: errors.append(f'scan_metadata: {e}')

# ── Security headers data ─────────────────────────────────────
security_headers_data = []
_shf = os.path.join(OUTDIR,'raw','security_headers.json')
if os.path.exists(_shf):
    try: security_headers_data = json.load(open(_shf))
    except Exception as e: errors.append(f'security_headers: {e}')

# Convert missing security headers into pseudo-findings so they are counted
# in stats/risk_score and rendered as cards in the HTML report.
_HDR_CWE = {
    "content-security-policy":  ("CWE-693", "critical"),
    "strict-transport-security":("CWE-319", "high"),
    "x-frame-options":          ("CWE-1021","medium"),
    "x-content-type-options":   ("CWE-693", "medium"),
    "referrer-policy":          ("CWE-200", "low"),
    "permissions-policy":       ("CWE-693", "low"),
    "x-xss-protection":         ("CWE-693", "info"),
}
_HDR_REM = {
    "content-security-policy":   "Add: Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' — adjust to the application stack.",
    "strict-transport-security": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
    "x-frame-options":           "Add: X-Frame-Options: SAMEORIGIN (or DENY if there are no legitimate iframes)",
    "x-content-type-options":    "Add: X-Content-Type-Options: nosniff",
    "referrer-policy":           "Add: Referrer-Policy: strict-origin-when-cross-origin",
    "permissions-policy":        "Add: Permissions-Policy: camera=(), microphone=(), geolocation=()",
    "x-xss-protection":          "Remove or replace with Content-Security-Policy — X-XSS-Protection is legacy and ignored by modern browsers.",
}
header_findings = []
_seen_subdir = set()  # dedup subdirective issues por (header, description)
for _shd in security_headers_data:
    _url = _shd.get("url", TARGET)
    for _hdr, _hinfo in _shd.get("missing", {}).items():
        _cwe, _sev_default = _HDR_CWE.get(_hdr, ("CWE-693", "info"))
        _sev = _hinfo.get("severity", _sev_default)
        header_findings.append({
            "id":   f"missing-header-{_hdr}",
            "name": f"Missing Security Header: {_hdr}",
            "severity": _sev, "severity_orig": _sev, "severity_reclassified": False,
            "source": "Security Headers",
            "url": _url,
            "cve": _cwe, "cve_ids": [],
            "description": _hinfo.get("description", f"Header {_hdr} missing"),
            "remediation": _HDR_REM.get(_hdr, f"Configure the {_hdr} header on the web server or reverse proxy."),
            "evidence": "", "param": "", "attack": "", "other": "",
        })

    # Validações de subdiretivas (HSTS preload, CSP unsafe-inline, etc.)
    for _sub in _shd.get("subdirective_issues", []):
        _hdr = _sub.get("header", "")
        _desc = _sub.get("description", "")
        _dedup_key = (_hdr, _desc)
        if _dedup_key in _seen_subdir:
            continue
        _seen_subdir.add(_dedup_key)
        header_findings.append({
            "id":   f"weak-{_hdr}-{abs(hash(_desc)) % 10000}",
            "name": f"Weak {_hdr}: {_desc.split(' — ')[0] if ' — ' in _desc else _desc[:60]}",
            "severity": _sub.get("severity", "low"),
            "severity_orig": _sub.get("severity", "low"),
            "severity_reclassified": False,
            "source": "Security Headers",
            "url": _url,
            "cve": _HDR_CWE.get(_hdr, ("CWE-693", "info"))[0],
            "cve_ids": [],
            "description": _desc,
            "remediation": _HDR_REM.get(_hdr, f"Revise as subdiretivas do header {_hdr}."),
            "evidence": f"{_hdr}: {_sub.get('value','')[:200]}",
            "param": "", "attack": "", "other": "",
        })

# ── CORS Findings (preflight OPTIONS via lib/cors_check.py) ─────
_cors_path = os.path.join(OUTDIR, 'raw', 'cors_findings.json')
if os.path.exists(_cors_path):
    try:
        for _cf in json.load(open(_cors_path)):
            header_findings.append({
                "id": f"cors-{abs(hash(_cf.get('url','')+_cf.get('name',''))) % 100000}",
                "name": _cf.get("name", "CORS Misconfiguration"),
                "severity": _cf.get("severity", "medium"),
                "severity_orig": _cf.get("severity", "medium"),
                "severity_reclassified": False,
                "source": "CORS Check",
                "url": _cf.get("url", TARGET),
                "cve": "CWE-942",  # Permissive Cross-domain Policy
                "cve_ids": [],
                "description": _cf.get("description", ""),
                "remediation": (
                    "1. Substituir wildcard '*' por allowlist explícita de origens confiáveis. "
                    "2. Validar Origin contra um conjunto fixo antes de ecoar. "
                    "3. Nunca combinar Access-Control-Allow-Origin reflexivo com "
                    "Access-Control-Allow-Credentials: true. "
                    "Exemplo nginx: map $http_origin $cors_origin { default ''; "
                    "'~^https://(app|admin)\\.exemplo\\.com$' $http_origin; }"
                ),
                "evidence": _cf.get("evidence", ""),
                "param": "", "attack": "", "other": "",
            })
    except Exception as e:
        errors.append(f"cors_findings: {e}")

# ── Tech Profile ─────────────────────────────────────────────
tech_profile  = {}
tech_detected = {}
tech_categories = {}
_tp_file = os.path.join(OUTDIR, "raw", "tech_profile.json")
if os.path.exists(_tp_file) and os.path.getsize(_tp_file) > 0:
    try:
        tech_profile    = json.load(open(_tp_file, "r", encoding="utf-8"))
        tech_detected   = tech_profile.get("detected", {})
        tech_categories = tech_profile.get("categories", {})
    except Exception as e:
        errors.append(f"tech_profile: {e}")

# ── Version Fingerprint + Monitoring + Rate Limit findings ───
version_findings = []
for _vf_file, _vf_label in [
    ('version_findings.json',    'version_findings'),
    ('monitoring_findings.json', 'monitoring_findings'),
    ('ratelimit_findings.json',  'ratelimit_findings'),
    ('secscan_findings.json',    'secscan_findings'),
    ('service_findings.json',    'service_findings'),
    ('pan_findings.json',        'pan_findings'),
    ('payment_findings.json',    'payment_findings'),
]:
    _vff = os.path.join(OUTDIR, 'raw', _vf_file)
    if os.path.exists(_vff):
        try:
            _vf_raw = json.load(open(_vff))
            for _vf in _vf_raw:
                _vf.setdefault("severity_orig", _vf.get("severity","info"))
                _vf.setdefault("severity_reclassified", False)
                _vf.setdefault("cve_ids", [])
                version_findings.append(_vf)
        except Exception as e:
            errors.append(f'{_vf_label}: {e}')

# ── JS Analysis ──────────────────────────────────────────────
js_analysis = {}
js_file = os.path.join(OUTDIR,"raw","js_analysis.json")
if os.path.exists(js_file) and os.path.getsize(js_file) > 0:
    try: js_analysis = json.load(open(js_file,"r",encoding="utf-8"))
    except Exception as e: errors.append(f"js_analysis: {e}")
js_secrets    = js_analysis.get("secrets",[])
js_endpoints  = js_analysis.get("endpoints",[])
js_frameworks = js_analysis.get("frameworks",[])
js_files_list = js_analysis.get("js_files",[])
js_probes     = js_analysis.get("endpoint_probes",[])
js_comments   = js_analysis.get("sensitive_comments",[])

# Enriquecer tech_profile com frameworks JS detectados pelo PYJS
if js_frameworks:
    for fw in js_frameworks:
        fw_name = fw.get("framework","")
        fw_ver  = fw.get("version","")
        if fw_name and fw_name not in tech_detected:
            tech_detected[fw_name] = {
                "version":    fw_ver,
                "source":     "js_analysis",
                "confidence": "high",
                "vulnerable": fw.get("vulnerable", False),
            }

# ── CVE enrichment (NVD + EPSS) ──────────────────────────────
cve_enrichment = {}
cve_db_file = os.path.join(OUTDIR,"raw","cve_enrichment.json")
if os.path.exists(cve_db_file) and os.path.getsize(cve_db_file) > 0:
    try: cve_enrichment = json.load(open(cve_db_file,"r",encoding="utf-8"))
    except Exception as e: errors.append(f"cve_enrichment: {e}")

# KEV matches — CVEs encontrados no catálogo CISA
kev_matches = {}
_kev_f = os.path.join(OUTDIR,"raw","kev_matches.json")
if os.path.exists(_kev_f):
    try: kev_matches = json.load(open(_kev_f,"r",encoding="utf-8"))
    except Exception as e: errors.append(f"kev_matches: {e}")
kev_count = len(kev_matches)

# Reclassificar achados Nuclei usando CVSS real do NVD quando disponível
# e injetar sinais KEV/EPSS/cvss_vector_nvd para o motor de criticidade
for f in findings:
    # Injetar in_kev, epss_score, cvss_vector_nvd a partir do cve_enrichment
    inject_cve_signals(f, cve_enrichment)

    cve_field = f.get('cve','')
    cve_ids_f = re.findall(r'CVE-\d{4}-\d{4,7}', cve_field, re.IGNORECASE)
    best_cvss = None
    for cid in [c.upper() for c in cve_ids_f]:
        ev = cve_enrichment.get(cid,{})
        cvss_val = ev.get('cvss_v3') or ev.get('cvss_v2')
        if cvss_val and (best_cvss is None or float(cvss_val) > best_cvss):
            best_cvss = float(cvss_val)
    if best_cvss is not None:
        new_sev = cvss_to_sev(best_cvss)
        if new_sev and new_sev != f['severity']:
            f['severity_orig'] = f['severity']
            f['severity'] = new_sev
            f['severity_reclassified'] = True
            f['cvss_real'] = best_cvss
        else:
            f.setdefault('severity_orig', f['severity'])
            f.setdefault('severity_reclassified', False)
    else:
        f.setdefault('severity_orig', f['severity'])
        f.setdefault('severity_reclassified', False)


# Montar lista combinada (todos os tipos) antes de enriquecer com criticidade
_all_f_raw = findings + zap_findings + header_findings + version_findings + tls_findings + email_findings

# ── Enriquecimento de criticidade CVSS 3.1 (Environmental + Temporal KEV/EPSS)
# Chamado AQUI — após injeção de sinais CVE nos findings Nuclei — para que
# todos os tipos de finding recebam cvss_vector, cvss_environmental, severity_tool,
# score_source e asset_class antes de calcular as stats e o risk score.
try:
    import criticality as _criticality
    _ov = _criticality.load_asset_overrides(os.path.dirname(os.path.abspath(__file__)))
    _criticality.enrich_findings(_all_f_raw, overrides=_ov)
except Exception as _e_crit:
    print(f"  [!] criticality: enrich falhou ({_e_crit}) — mantendo severidade da ferramenta")

# Stats — contagem de CARDS únicos por severidade (padrão relatórios profissionais)
# Cada tipo de vulnerabilidade = 1, independente de quantas URLs afeta.
# NOTA: f["severity"] é a banda FINAL (Environmental) já reescrita por
# criticality.enrich_findings acima. O campo f["severity_tool"] guarda
# a severidade original da ferramenta.
all_f = sorted(_all_f_raw, key=lambda x: {"critical":0,"high":1,"medium":2,"low":3,"info":4}.get(x["severity"],5))

# ── PCI DSS CDE tagging ───────────────────────────────────────
import cde_scope as _cde, pci_verdicts as _pv
_cde_targets = _cde.load_targets()
_pv.tag_all(all_f, _cde_targets)

stats = {"critical":0,"high":0,"medium":0,"low":0,"info":0}
for f in all_f:
    if f.get("source") == "Email Security": continue
    if f["severity"] in stats: stats[f["severity"]] += 1
# Low/Info: cada grupo = 1 card (tipo único)
for grp in zap_low_groups.values():
    sev = grp["finding"]["severity"]
    if sev in stats: stats[sev] += 1
total = sum(stats.values())

# Ocorrências reais — usadas apenas para o risk score (reflete severidade total do ambiente)
occurrences = dict(stats)
for grp in zap_low_groups.values():
    sev = grp["finding"]["severity"]
    if sev in occurrences: occurrences[sev] += (grp["count"] - 1)
for grp in zap_dedup.values():
    sev = grp["sev"]
    if sev in occurrences: occurrences[sev] += (grp["count"] - 1)

# ── Risk score: KEV > EPSS > CVSS (metodologia 2026) ───────────
# Lógica em lib/risk_score.py (extraída para teste em isolamento).
_r = compute_risk(stats, cve_enrichment, js_secrets, js_frameworks)
base_risk  = _r["base_risk"]
kev_bonus  = _r["kev_bonus"]
kev_count  = _r["kev_count"]
epss_bonus = _r["epss_bonus"]
js_high    = _r["js_high"]
js_medium  = _r["js_medium"]
js_vuln_fw = _r["js_vuln_fw"]
js_bonus   = _r["js_bonus"]
risk       = _r["risk"]
# Classificação baseada no risk score (KEV+EPSS+CVSS) — não apenas contagem
# Faixas: 70-100=CRÍTICO, 40-69=ALTO, 15-39=MÉDIO, 0-14=BAIXO
if risk >= 70:
    stxt, scol = "CRITICAL — Immediate Action",   "#7a2e2e"
elif risk >= 40:
    stxt, scol = "HIGH — Urgent Attention",       "#b34e4e"
elif risk >= 15:
    stxt, scol = "MEDIUM — Planned Remediation",  "#d4833a"
else:
    stxt, scol = "LOW — Monitoring",              "#4a7c8c"
import time as _time
# Janela real do scan a partir de raw/.phase_times (estável mesmo se o
# relatório for regerado depois — não usa a hora de geração do relatório).
_ph_starts, _ph_ends = [], []
_ptf2 = os.path.join(OUTDIR, "raw", ".phase_times")
if os.path.exists(_ptf2):
    for _l in open(_ptf2):
        _p = _l.strip().split(":")
        if len(_p) >= 3 and _p[1] == "start":
            try: _ph_starts.append(int(_p[2]))
            except Exception: pass
        elif len(_p) >= 3 and _p[1] == "end":
            try: _ph_ends.append(int(_p[2]))
            except Exception: pass
_scan_start = min(_ph_starts) if _ph_starts else SCAN_START_TS
_scan_end   = max(_ph_ends) if _ph_ends else (int(_time.time()) if SCAN_START_TS else 0)
duration_secs = (_scan_end - _scan_start) if (_scan_start and _scan_end > _scan_start) else 0
duration_str = (f"{duration_secs//3600}h {(duration_secs%3600)//60}m {duration_secs%60}s"
                if duration_secs > 0 else "N/A")
# Data do scan = início real do scan (não a hora de geração do relatório)
rdate = (datetime.fromtimestamp(_scan_start).strftime("%Y-%m-%d %H:%M")
         if _scan_start else datetime.now().strftime("%Y-%m-%d %H:%M"))

def badge(sev):
    labels = {"critical":"CRITICAL","high":"HIGH","medium":"MEDIUM","low":"LOW","info":"INFO"}
    c={"critical":"#7a2e2e","high":"#b34e4e","medium":"#d4833a","low":"#4a7c8c","info":"#6e8f72"}.get(sev,"#999")
    return f'<span style="background:{c};color:white;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:bold">{labels.get(sev, labels.get(sev.lower(), sev.upper()))}</span>'

def trows(items,empty="No results"):
    if not items: return f'<tr><td style="color:#999;font-style:italic">{empty}</td></tr>'
    return "".join(f'<tr><td style="font-family:monospace;font-size:12px">{html.escape(i)}</td></tr>' for i in items[:50])

def _decode_cvss_vector(vec):
    """Decodifica os campos mais decisivos do vetor CVSS (exploitabilidade)."""
    if not vec:
        return ""
    parts = dict(p.split(":") for p in vec.split("/") if p.count(":") == 1)
    av = {"N":"Network","A":"Adjacent","L":"Local","P":"Physical"}.get(parts.get("AV",""), "")
    ac = {"L":"Low","H":"High"}.get(parts.get("AC",""), "")
    pr = {"N":"None","L":"Low","H":"High"}.get(parts.get("PR",""), "")
    ui = {"N":"None","R":"Required"}.get(parts.get("UI",""), "")
    bits = []
    if av: bits.append(f"Vector: {av}")
    if ac: bits.append(f"Complexity: {ac}")
    if pr: bits.append(f"Privileges: {pr}")
    if ui: bits.append(f"Interaction: {ui}")
    return " · ".join(bits)

def render_finding(f):
    # Enriquecer CVE com dados NVD/EPSS se disponível
    cve_val = f.get('cve','N/A')
    enrich_rows = ''
    # Extrair CVE IDs do campo cve
    cve_ids = re.findall(r'CVE-\d{4}-\d{4,7}', cve_val, re.IGNORECASE)
    for cve_id in [c.upper() for c in cve_ids]:
        ev = cve_enrichment.get(cve_id, {})
        if ev:
            cvss = ev.get('cvss_v3') or ev.get('cvss_v2')
            epss = ev.get('epss_score')
            epss_pct = ev.get('epss_percentile')
            sev = ev.get('severity','')
            desc_nvd = ev.get('description','')
            cvss_color = '#7a2e2e' if cvss and cvss>=9 else '#b34e4e' if cvss and cvss>=7 else '#d4833a' if cvss and cvss>=4 else '#27ae60'
            epss_color = '#7a2e2e' if epss and epss>=0.5 else '#d4833a' if epss and epss>=0.1 else '#27ae60'
            enrich_rows += f'<tr><th>{html.escape(cve_id)}</th><td>'
            _SEV_PT = {"CRITICAL":"CRÍTICO","HIGH":"ALTO","MEDIUM":"MÉDIO","LOW":"BAIXO"}
            sev_pt = _SEV_PT.get(str(sev).upper(), sev)
            # KEV badge — máxima prioridade, exibido antes de CVSS/EPSS
            in_kev = ev.get("in_kev", False)
            kev_info = ev.get("kev", {})
            if in_kev:
                kev_due = kev_info.get("due_date","")
                kev_added = kev_info.get("date_added","")
                kev_prod = f"{kev_info.get('vendor','')} {kev_info.get('product','')}".strip()
                enrich_rows += (f'<span style="background:#7a0000;color:white;padding:2px 10px;'
                    f'border-radius:4px;font-size:12px;font-weight:bold;'
                    f'border:2px solid #ff4444;letter-spacing:.3px">'
                    f'🔴 ACTIVE EXPLOITATION — CISA KEV</span> ')
                if kev_due: enrich_rows += f'<span style="background:#b34e4e;color:white;padding:1px 6px;border-radius:3px;font-size:11px">CISA Due: {html.escape(kev_due)}</span> '
                if kev_prod: enrich_rows += f'<br><small style="color:#7a0000;font-weight:bold">Added to KEV on {html.escape(kev_added)} — {html.escape(kev_prod)}</small> '
            if cvss: enrich_rows += f'<span style="background:{cvss_color};color:white;padding:1px 6px;border-radius:3px;font-size:12px;font-weight:bold">CVSS {cvss} {html.escape(sev_pt)}</span> '
            if epss is not None:
                if epss_pct is not None:
                    enrich_rows += f'<span style="background:{epss_color};color:white;padding:1px 6px;border-radius:3px;font-size:12px">EPSS {epss:.4f} ({epss_pct*100:.1f}th percentile)</span> '
                else:
                    enrich_rows += f'<span style="background:{epss_color};color:white;padding:1px 6px;border-radius:3px;font-size:12px">EPSS {epss:.4f}</span> '
            # Vetor CVSS — exibe a string e decodifica os campos de exploitabilidade
            _vec = ev.get("cvss_vector", "")
            if _vec:
                _dec = _decode_cvss_vector(_vec)
                enrich_rows += (f'<br><code style="font-size:10px;color:#666">{html.escape(_vec)}</code>'
                    + (f' <span style="font-size:10px;color:#888">({html.escape(_dec)})</span>' if _dec else ''))
            # Link direto para advisory NVD
            enrich_rows += (f'<a href="https://nvd.nist.gov/vuln/detail/{html.escape(cve_id)}" '
                f'target="_blank" style="font-size:11px;color:#388bfd;margin-left:6px">'
                f'Ver no NVD ↗</a> ')
            if desc_nvd: enrich_rows += f'<br><small style="color:#555">{html.escape(desc_nvd)}</small>'
            enrich_rows += '</td></tr>'
    # Fallback CWE sintético — quando não há CVE NVD disponível
    if not cve_ids or not enrich_rows:
        cwe_match = re.search(r'CWE-?(\d+)', cve_val, re.IGNORECASE)
        if cwe_match:
            cwe_data = cwe_enrich(cwe_match.group(1))
            if cwe_data:
                cvss = cwe_data["cvss"]
                _SEV_PT = {"CRITICAL":"CRÍTICO","HIGH":"ALTO","MEDIUM":"MÉDIO","LOW":"BAIXO"}
                sev_label = _SEV_PT.get(cwe_data["sev"], cwe_data["sev"])
                cwe_name = cwe_data["name"]
                cvss_color = '#7a2e2e' if cvss>=9 else '#b34e4e' if cvss>=7 else '#d4833a' if cvss>=4 else '#27ae60'
                enrich_rows += (f'<tr><th>CWE-{cwe_match.group(1)}</th><td>'
                    f'<span style="background:{cvss_color};color:white;padding:1px 6px;border-radius:3px;font-size:12px;font-weight:bold">CVSS ~{cvss} {sev_label}</span> '
                    f'<span style="background:#636e72;color:white;padding:1px 6px;border-radius:3px;font-size:11px">CWE-based estimate</span>'
                    f'<br><small style="color:#555">{html.escape(cwe_name)}</small>'
                    f'</td></tr>')
    # Badge de reclassificação — mostrar quando severidade original difere da atual
    sev_orig = f.get('severity_orig', f.get('severity',''))
    was_reclassified = f.get('severity_reclassified', False)
    reclassify_badge = ''
    if was_reclassified and sev_orig and sev_orig != f.get('severity',''):
        labels = {'critical':'CRITICAL','high':'HIGH','medium':'MEDIUM','low':'LOW','info':'INFO'}
        orig_label = labels.get(sev_orig, sev_orig.upper())
        reclassify_badge = (f'<span style="background:#2d3436;color:#dfe6e9;'
            f'padding:2px 7px;border-radius:4px;font-size:10px;margin-left:6px">'
            f'↑ Reclassified from {orig_label} (CVE/CWE)</span>')

    rows = f"""
    <tr><th style="width:120px">CVE/CWE</th><td>{html.escape(str(f.get('cve','N/A')))}</td></tr>
    {enrich_rows}
    <tr><th>URL</th><td><code>{html.escape(f.get('url',''))}</code></td></tr>
    <tr><th>Description</th><td>{html.escape(f.get('description',''))}</td></tr>"""
    # Impacto prático — extrair CWE do campo cve para lookup no IMPACT_MAP
    _cwe_for_impact = re.search(r'CWE-?(\d+)', f.get("cve",""), re.IGNORECASE)
    _impact = IMPACT_MAP.get(_cwe_for_impact.group(1), "") if _cwe_for_impact else ""
    _remediation_specific = REMEDIATION_MAP.get(_cwe_for_impact.group(1), "") if _cwe_for_impact else ""
    if _impact:
        rows += (f'\n    <tr><th style="background:#fff3cd;color:#856404">⚠ Impact</th>'
            f'<td style="background:#fff3cd;color:#856404;font-weight:500">{html.escape(_impact)}</td></tr>')
    if _remediation_specific:
        rows += (f'\n    <tr><th style="background:#d4edda;color:#155724">✓ How to Fix</th>'
            f'<td style="background:#d4edda;color:#155724">{html.escape(_remediation_specific)}</td></tr>')
    if f.get('param'):
        rows += f"\n    <tr><th>Parameter</th><td><code>{html.escape(f['param'])}</code></td></tr>"
    if f.get('attack'):
        rows += f"\n    <tr><th>Attack</th><td><code>{html.escape(f['attack'])}</code></td></tr>"
    # Exibir evidência dividida em blocos legíveis
    _ev_full = f.get("evidence","")
    if _ev_full:
        _req_match  = re.search(r"--- HTTP REQUEST ---\n(.*?)(?=---|$)", _ev_full, re.DOTALL)
        _res_match  = re.search(r"--- HTTP RESPONSE ---\n(.*?)(?=---|$)", _ev_full, re.DOTALL)
        _ev_other   = re.sub(r"--- HTTP (REQUEST|RESPONSE) ---\n.*?(?=---|$)", "", _ev_full, flags=re.DOTALL).strip()
        if _ev_other:
            rows += f'\n    <tr><th>Evidence</th><td><div class="evidence-box">{html.escape(_ev_other)}</div></td></tr>'
        if _req_match:
            rows += f'\n    <tr><th>HTTP Request</th><td><div class="evidence-box">{html.escape(_req_match.group(1).strip())}</div></td></tr>'
        if _res_match:
            rows += f'\n    <tr><th>HTTP Response</th><td><div class="evidence-box">{html.escape(_res_match.group(1).strip())}</div></td></tr>'
    if f.get('affected_count', 0) > 1:
        n = f['affected_count']
        urls_sample = f.get('affected_urls', [])
        url_list = ''.join(f'<li><code>{html.escape(u)}</code></li>' for u in urls_sample)
        rows += (f'\n    <tr><th>Affected URLs</th>'
            f'<td><strong>{n} occurrence(s)</strong> of the same alert type:<ul style="margin:6px 0 0;padding-left:18px">{url_list}</ul></td></tr>')
    other_val = f.get('other','')
    if other_val and '[URLs afetadas]' not in other_val:
        rows += f"\n    <tr><th>Detail</th><td>{html.escape(other_val)}</td></tr>"
    # Criticidade CVSS 3.1 (Environmental) — campos injetados por criticality.enrich_findings.
    if f.get('cvss_vector'):
        _cvss_src = f.get('score_source', '')
        _est_note = ' <em style="color:#e67e22">(estimado)</em>' if _cvss_src == 'estimated' else ''
        _env_score = f.get('cvss_environmental', '')
        _asset_cls = html.escape(str(f.get('asset_class', '')))
        _src_label  = html.escape(str(_cvss_src))
        rows += (f'\n    <tr><th>CVSS (Environmental)</th>'
                 f'<td><code style="font-size:11px">{html.escape(f["cvss_vector"])}</code> '
                 f'— <strong>{_env_score}</strong> '
                 f'[{_asset_cls} · {_src_label}]{_est_note}</td></tr>')
    rows += f"\n    <tr><th>Recommendation</th><td>{html.escape(f.get('remediation',''))}</td></tr>"
    _src = f.get('source','')
    src_cls = ('source-nuclei'  if _src == 'Nuclei'              else
               'source-headers' if _src == 'Security Headers'    else
               'source-version' if _src in ('Version Fingerprint', 'Service Version',
                                            'PCI PAN', 'PCI Payment Page') else
               'source-zap')
    confirmed_badge = ''
    _cat = _confirmed_category(f)
    if _cat == "exploit":
        confirmed_badge = ('<span style="background:#7a0000;color:white;padding:2px 8px;'
            'border-radius:4px;font-size:10px;font-weight:bold;margin-left:6px;'
            'border:1px solid #ff4444">✓ EXPLOIT CONFIRMED</span>')
    elif _cat == "verified":
        confirmed_badge = ('<span style="background:#1b5e20;color:white;padding:2px 8px;'
            'border-radius:4px;font-size:10px;font-weight:bold;margin-left:6px;'
            'border:1px solid #2e7d32">✓ VERIFIED</span>')
    return f'''<div class="vuln {f['severity']}">
  <h3>{html.escape(f.get('name',''))} <span class="source-badge {src_cls}">{f.get('source','')}</span> {badge(f['severity'])}{reclassify_badge}{confirmed_badge}</h3>
  <table>{rows}
  </table></div>'''

# Email Security: apenas na tabela dedicada, sem cards.
# testssl.sh: critical/high viram cards; medium/low/info ficam só na tabela TLS.
_EMAIL_ONLY_TABLE = {"Email Security"}
_DEDICATED_SOURCES = {"testssl.sh", "Email Security"}
_main_findings = [
    f for f in all_f
    if f["severity"] in ("critical","high","medium")
    and f.get("source") not in _EMAIL_ONLY_TABLE
    and (f.get("source") != "testssl.sh" or f["severity"] in ("critical","high"))
]
vhtml = (
    '<div class="info-box"><p>✅ No vulnerabilities found within the analyzed scope.</p></div>'
    if not _main_findings
    else "".join(render_finding(f) for f in _main_findings)
)

# ── Consolidated Low / Info table (all sources) ───────────────
# Collect low/info items from every source: Nuclei, Security Headers,
# Version Fingerprint, and ZAP low_groups (already grouped by name).
_low_info_findings = [f for f in all_f if f["severity"] in ("low","info") and f.get("source") not in _DEDICATED_SOURCES]

low_table_html = ""
if _low_info_findings or zap_low_groups:
    _src_color = {
        "Nuclei":              "#3498db",
        "ZAP":                 "#e74c3c",
        "Security Headers":    "#7d3c98",
        "Version Fingerprint": "#d35400",
        "Service Version":     "#c0622e",
        "PCI PAN":             "#7a0000",
        "PCI Payment Page":    "#8e44ad",
    }
    rows_low = ""
    # Rows from all_f (low/info)
    for f in sorted(_low_info_findings, key=lambda x: ({"low":0,"info":1}.get(x["severity"],2), x.get("source",""), x.get("name",""))):
        src = f.get("source","")
        src_col = _src_color.get(src, "#636e72")
        rows_low += (
            f'<tr>'
            f'<td style="font-size:12px">{html.escape(f.get("name",""))}</td>'
            f'<td style="text-align:center">{badge(f["severity"])}</td>'
            f'<td style="text-align:center"><span style="background:{src_col};color:white;'
            f'padding:2px 7px;border-radius:4px;font-size:10px;font-weight:bold">'
            f'{html.escape(src)}</span></td>'
            f'<td style="font-size:11px">{html.escape(f.get("cve","—") or "—")}</td>'
            f'<td style="font-size:11px;color:#555">{html.escape(f.get("description","") or "")}</td>'
            f'<td style="font-size:11px">{html.escape(f.get("remediation","") or "")}</td>'
            f'</tr>'
        )
    # Rows from ZAP low_groups (deduplicated ZAP low/info)
    for name, grp in sorted(zap_low_groups.items()):
        src_col = _src_color.get("ZAP","#e74c3c")
        urls_str = ", ".join(grp["urls"][:3])
        if len(grp["urls"]) > 3:
            urls_str += f" (+{len(grp['urls'])-3})"
        # span de URLs montado fora do f-string (sem barra invertida em {} — compat. Python 3.11)
        _urls_span = (f'<br><span style="font-size:10px;color:#888">{html.escape(urls_str)}</span>'
                      if urls_str else "")
        rows_low += (
            f'<tr>'
            f'<td style="font-size:12px">{html.escape(name)}{_urls_span}</td>'
            f'<td style="text-align:center">{badge(grp.get("sev","low"))}</td>'
            f'<td style="text-align:center"><span style="background:{src_col};color:white;'
            f'padding:2px 7px;border-radius:4px;font-size:10px;font-weight:bold">ZAP</span></td>'
            f'<td style="font-size:11px">{html.escape(grp.get("cve","—") or "—")}</td>'
            f'<td style="font-size:11px;color:#555">{grp["count"]} occurrence(s) — confidence: {html.escape(grp.get("conf","?"))}</td>'
            f'<td style="font-size:11px">{html.escape((grp["finding"].get("remediation") or ""))}</td>'
            f'</tr>'
        )
    _total_low = len(_low_info_findings) + len(zap_low_groups)
    low_table_html = f'''<h2>4. Low / Informational Findings ({_total_low} item(s))</h2>
    <p style="color:#666;font-size:13px">Consolidated low/info priority items. Validate and address after the critical fixes.</p>
    <table>
      <tr style="background:#f5f5f5">
        <th>Finding</th><th style="width:80px">Sev</th><th style="width:120px">Source</th>
        <th style="width:130px">CVE / CWE</th><th>Description</th><th>Recommendation</th>
      </tr>
      {rows_low}
    </table>'''

# ── Gerar HTML: WAF & Email Security ────────────────────────
waf_email_html = ''

# WAF banner
if WAF_DETECTED and WAF_NAME:
    waf_email_html += (f'<div style="background:#fff3cd;border-left:5px solid #d4833a;'
        f'padding:14px 16px;border-radius:4px;margin:16px 0">'
        f'<strong style="color:#856404">🛡 WAF Detected: {html.escape(WAF_NAME)}</strong>'
        f'<p style="margin:6px 0 0;font-size:13px;color:#555">'
        f'The target is protected by a Web Application Firewall. Active scan findings '
        f'may have false negatives — injection vulnerabilities may have been blocked '
        f'during the scan without being detected.</p></div>')

# Email security
if email_security:
    sev_color = {'high':'#b34e4e','medium':'#d4833a','low':'#4a7c8c','none':'#27ae60'}
    sev_label = {'high':'HIGH','medium':'MEDIUM','low':'LOW','none':'OK','NOT_FOUND':'INFO'}
    email_rows = ''
    for proto, data in [('SPF', email_security.get('spf',{})),
                         ('DMARC', email_security.get('dmarc',{})),
                         ('DKIM',  email_security.get('dkim',{}))]:
        sev  = data.get('severity','none')
        stat = data.get('status','?')
        det  = data.get('detail','')
        rec  = data.get('recommendation','')
        val  = data.get('value','')
        sc   = sev_color.get(sev,'#999')
        sl   = sev_label.get(stat, sev_label.get(sev,'?'))
        email_rows += (f'<tr>'
            f'<td style="font-weight:bold;width:80px">{proto}</td>'
            f'<td style="text-align:center"><span style="background:{sc};color:white;'
            f'padding:2px 8px;border-radius:4px;font-size:11px;font-weight:bold">{sl}</span></td>'
            f'<td>{html.escape(det)}</td>'
            f'<td style="font-size:11px;color:#555">{html.escape(rec) if rec else ("<code>"+html.escape(val)+"</code>" if val else "—")}</td>'
            f'</tr>')
    waf_email_html += (f'<h3>Email Security — {html.escape(DOMAIN)}</h3>'
        '<table><tr style="background:#f5f5f5">'
        '<th>Protocol</th><th>Status</th><th>Detail</th><th>Recommendation / Value</th></tr>'
        + email_rows + '</table>')

if waf_email_html:
    waf_email_html = f'<h2>Infrastructure & DNS Security</h2>' + waf_email_html

# ── Gerar HTML: Comportamento do Scan ─────────────────────────
scan_behavior_html = ""
if scan_meta:
    evasion_active = scan_meta.get("evasion_active", False)
    waf_n          = scan_meta.get("waf_name", "")
    techniques     = scan_meta.get("evasion_techniques", [])
    rl             = scan_meta.get("nuclei_rate_limit", 50)
    conc           = scan_meta.get("nuclei_concurrency", 10)
    delay          = scan_meta.get("nuclei_delay")
    ua             = scan_meta.get("user_agent", "")
    nuc_count      = scan_meta.get("nuclei_results_after_evasion")
    zap_count      = scan_meta.get("zap_results_after_evasion")

    TECH_LABELS = {
        "rate_limit_reduced":     ("🐢", "Rate limit reduced",      f"Nuclei: {rl} req/s with random delay — mimics human traffic"),
        "user_agent_rotation":    ("🔄", "User-Agent rotation",     f"Real browser UA: {ua[:60]}..." if len(ua)>60 else f"UA: {ua}"),
        "origin_spoofing":        ("🎭", "Origin spoofing",         "X-Forwarded-For: 127.0.0.1 + X-Real-IP: 127.0.0.1 injected"),
        "payload_alterations":    ("🔀", "Payload alterations",     "Nuclei automatically tested encoding variations (-pa)"),
        "waf_response_bypass":    ("⏭", "WAF response bypass",     "403/406/429 responses ignored — scan does not stop on blocks"),
        "zap_threads_reduced":    ("🧵", "ZAP threads reduced",     "Active scan with 2 threads — reduces automated-scan signature"),
    }

    if evasion_active:
        tech_rows = "".join(
            f'<tr>'
            f'<td style="font-size:18px;text-align:center;width:36px">{icon}</td>'
            f'<td style="font-weight:600;width:180px">{label}</td>'
            f'<td style="color:#555;font-size:13px">{desc}</td>'
            f'<td style="text-align:center"><span style="background:#27ae60;color:white;'
            f'padding:2px 8px;border-radius:4px;font-size:11px;font-weight:bold">ACTIVE</span></td>'
            f'</tr>'
            for t in techniques for icon, label, desc in [TECH_LABELS.get(t, ("","",""))]
            if label
        )

        results_row = ""
        if nuc_count is not None:
            results_row += (f'<div style="display:inline-block;background:#f0f7ff;'
                f'border:1px solid #388bfd;border-radius:8px;padding:12px 20px;margin:6px 8px 6px 0">'
                f'<div style="font-size:28px;font-weight:bold;color:#1a3a4f">{nuc_count}</div>'
                f'<div style="font-size:12px;color:#555">Nuclei findings\nwith evasion</div></div>')
        if zap_count is not None:
            results_row += (f'<div style="display:inline-block;background:#f0f7ff;'
                f'border:1px solid #388bfd;border-radius:8px;padding:12px 20px;margin:6px 8px 6px 0">'
                f'<div style="font-size:28px;font-weight:bold;color:#1a3a4f">{zap_count}</div>'
                f'<div style="font-size:12px;color:#555">ZAP alerts\nwith evasion</div></div>')

        scan_behavior_html = (
            f'<h2>🔬 Scan Behavior & Passive Evasion</h2>'
            f'<div style="background:#fff8e6;border-left:5px solid #d4833a;'
            f'padding:16px;border-radius:4px;margin-bottom:16px">'
            f'<strong style="color:#856404">⚠ WAF Detected: {html.escape(waf_n)}</strong>'
            f'<p style="margin:6px 0 0;font-size:13px;color:#555">'
            f'The scanner detected a WAF and automatically enabled passive evasion mode. '
            f'The techniques below were applied to maximize coverage and reduce false negatives.</p></div>'
            f'<h3 style="color:#1a3a4f;margin-bottom:8px">Passive Evasion Techniques Applied</h3>'
            f'<table style="margin-bottom:16px"><tr style="background:#f5f5f5">'
            f'<th></th><th style="text-align:left">Technique</th>'
            f'<th style="text-align:left">Detail</th><th>Status</th></tr>'
            + tech_rows +
            f'</table>'
            + (f'<h3 style="color:#1a3a4f;margin-bottom:8px">Results with Active Evasion</h3>'
               f'<div style="margin-bottom:8px">{results_row}</div>'
               f'<p style="font-size:12px;color:#888;margin:4px 0">Results obtained after applying the evasion techniques. '
               f'Comparing with non-evasion scans is not applicable since the WAF would have blocked earlier requests.</p>'
               if results_row else "")
        )
    else:
        # Sem WAF — registrar que scan foi direto
        scan_behavior_html = (
            f'<h2>🔬 Scan Behavior</h2>'
            f'<div style="background:#f0fff4;border-left:5px solid #27ae60;'
            f'padding:14px 16px;border-radius:4px">'
            f'<strong style="color:#1a7a4a">✓ No WAF Detected — Direct Scan</strong>'
            f'<p style="margin:6px 0 0;font-size:13px;color:#555">'
            f'The target has no identified WAF. The scan ran with default settings '
            f'(Nuclei {rl} req/s, concurrency {conc}). '
            f'Results have high confidence — no intermediate filters.</p></div>'
        )

errsec = "" if not errors else \
    '<h2>⚠ Processing Warnings</h2><div class="info-box" style="border-left-color:#d4833a"><ul>' + \
    "".join(f"<li><code>{html.escape(e)}</code></li>" for e in errors) + "</ul></div>"

# ── Gerar HTML: Análise JS ───────────────────────────────────
js_html = ""
if js_analysis:
    HIGH_JS_TYPES = {"AWS Access Key","AWS Secret","Private Key","Stripe Live Key",
        "GitHub Token","GitLab PAT","OpenAI Key","Anthropic Key","Hardcoded Password",
        "DB Connection String","Firebase Key","Slack Token"}
    def js_sev(t): return "high" if t in HIGH_JS_TYPES else "medium"
    def js_sev_color(s): return {"high":"#b34e4e","medium":"#d4833a"}.get(s,"#4a7c8c")
    def js_badge(t):
        s=js_sev(t); c=js_sev_color(s)
        lbl={"high":"ALTO","medium":"MÉDIO"}.get(s,"BAIXO")
        return f'<span style="background:{c};color:white;padding:1px 6px;border-radius:3px;font-size:11px;font-weight:bold">{lbl}</span>'

    # Stat bar JS
    js_accessible = [p for p in js_probes if p.get("status")==200]
    js_exposed_api = [p for p in js_probes if p.get("status")==200 and p.get("is_json")]
    js_vuln_fw = [f for f in js_frameworks if f.get("vulnerable")]
    js_html = f'''<h2>JS / Frontend — Security Analysis</h2>
    <div class="info-box">
      <table>
        <tr><th style="width:200px">JS files analyzed</th><td>{len(js_files_list)}</td></tr>
        <tr><th>Secrets / credentials</th><td><span style="color:#b34e4e;font-weight:bold">{sum(1 for s in js_secrets if js_sev(s["type"])=="high")}</span> high &nbsp;|&nbsp; <span style="color:#d4833a">{sum(1 for s in js_secrets if js_sev(s["type"])=="medium")}</span> medium</td></tr>
        <tr><th>Endpoints discovered</th><td>{len(js_endpoints)} &nbsp;|&nbsp; {len(js_accessible)} accessible without authentication</td></tr>
        <tr><th>Frameworks detected</th><td>{len(js_frameworks)} ({len(js_vuln_fw)} with known CVE)</td></tr>
        <tr><th>Sensitive comments</th><td>{len(js_comments)}</td></tr>
      </table>
    </div>'''

    # Secrets
    if js_secrets:
        from collections import defaultdict
        by_type = defaultdict(list)
        for s in js_secrets: by_type[s["type"]].append(s)
        js_html += "<h3>Detected Secrets and Credentials</h3>"
        for stype, items in sorted(by_type.items(), key=lambda x: 0 if js_sev(x[0])=="high" else 1):
            c = js_sev_color(js_sev(stype))
            js_html += (f'<div style="border-left:5px solid {c};padding:14px 16px;margin:12px 0;'
                f'background:#ffffff;border-radius:6px;border:1px solid #e0e0e0;box-shadow:0 1px 3px rgba(0,0,0,.06)">'
                f'<div style="margin-bottom:10px">'
                f'<strong style="font-size:14px">{html.escape(stype)}</strong> {js_badge(stype)}'
                f' <span style="color:#888;font-size:12px;margin-left:6px">({len(items)} occurrence(s))</span>'
                f'</div>'
                f'<table style="width:100%;border-collapse:collapse">'
                f'<tr>'
                f'<th style="background:#f5f5f5;color:#1a3a4f;font-weight:700;font-size:12px;'
                f'padding:8px 12px;text-align:left;border:1px solid #ddd;width:35%">Value / Pattern</th>'
                f'<th style="background:#f5f5f5;color:#1a3a4f;font-weight:700;font-size:12px;'
                f'padding:8px 12px;text-align:left;border:1px solid #ddd">Context in Code</th>'
                f'</tr>')
            for item in items:
                v    = item["value"]
                ctx  = item.get("context", "")
                furl = item.get("url", "")
                js_html += (
                    f'<tr>'
                    f'<td style="padding:8px 12px;border:1px solid #eee;vertical-align:top;background:#fafafa">'
                    f'<code style="font-size:11px;color:#c0392b;background:#fff5f5;padding:3px 6px;'
                    f'border-radius:3px;word-break:break-all;display:block">{html.escape(v)}</code>'
                    + (f'<div style="font-size:10px;color:#888;margin-top:5px">📄 {html.escape(furl)}</div>' if furl else "")
                    + f'</td>'
                    f'<td style="padding:8px 12px;border:1px solid #eee;vertical-align:top">'
                    f'<pre style="margin:0;font-size:10px;font-family:monospace;background:#f8f9fa;'
                    f'color:#333;padding:6px 8px;border-radius:3px;white-space:pre-wrap;'
                    f'word-break:break-all;border:1px solid #e0e0e0;max-height:160px;'
                    f'overflow-y:auto">{html.escape(ctx) if ctx else "—"}</pre>'
                    + f'</td></tr>')
            js_html += "</table></div>"

    # Frameworks
    if js_frameworks:
        seen_fw = {}
        fw_rows = ""
        for fw in js_frameworks:
            k = (fw["framework"],fw["version"])
            if k in seen_fw: continue
            seen_fw[k]=True
            vuln_html = ('<span style="color:#b34e4e;font-weight:bold">⚠ ' +
                ', '.join(v["cve"] for v in fw.get("vulns",[])) + '</span>')\
                if fw.get("vulnerable") else '<span style="color:#27ae60">✓ OK</span>'
            fw_rows += (f'<tr><td><strong>{html.escape(fw["framework"])}</strong></td>'
                f'<td><code>{html.escape(fw["version"])}</code></td>'
                f'<td>{vuln_html}</td></tr>')
        js_html += ('<h3>Detected Frameworks</h3>'
            '<table><tr style="background:#f5f5f5"><th>Framework</th><th>Version</th><th>Status</th></tr>'
            + fw_rows + '</table>')

    # Endpoints acessíveis
    if js_accessible:
        ep_rows = "".join(
            f'<tr><td><code style="font-size:11px;word-break:break-all">{html.escape(p["url"])}</code></td>'
            f'<td style="text-align:center"><span style="background:#27ae60;color:white;'
            f'padding:1px 6px;border-radius:3px;font-size:11px">{p["status"]}</span></td>'
            f'<td style="font-size:11px">{"JSON API" if p.get("is_json") else "HTML"}</td></tr>'
            for p in js_accessible[:15])
        js_html += ('<h3>Endpoints Accessible Without Authentication</h3>'
            '<table><tr style="background:#f5f5f5"><th>URL</th><th>HTTP</th><th>Type</th></tr>'
            + ep_rows + '</table>')

    # Comentários sensíveis
    if js_comments:
        comm_rows = "".join(
            f'<tr><td style="padding:6px 10px;border-bottom:1px solid #eee">'
            f'<code style="font-size:11px;background:#f8f9fa;color:#c0392b;'
            f'padding:3px 6px;border-radius:3px;display:block;white-space:pre-wrap;'
            f'word-break:break-all;border:1px solid #e0e0e0">{html.escape(c["comment"])}</code>'
            f'<div style="font-size:10px;color:#888;margin-top:3px">📄 {html.escape(c.get("url",""))}</div>'
            f'</td></tr>'
            for c in js_comments[:10])
        js_html += ('<h3>Sensitive Comments in Code</h3>'
            '<table style="width:100%;border-collapse:collapse;border:1px solid #eee;border-radius:6px">'
            + comm_rows + '</table>')

# ── Gerar HTML: TLS ─────────────────────────────────────────
SEV_TLS_CLASS = {"critical":"tls-critical","high":"tls-high","medium":"tls-warn","low":"tls-warn","info":"tls-ok"}
if tls_findings:
    TLS_SEV_PT = {"CRITICAL":"CRÍTICO","HIGH":"ALTO","WARN":"AVISO","LOW":"BAIXO","OK":"OK","INFO":"INFO"}
    def _tls_problem_cell(f):
        cell = html.escape(f.get("name", f.get("finding", "")))
        _c = _confirmed_category(f)
        if _c == "exploit":
            cell += ('  <span style="background:#7a0000;color:white;padding:1px 6px;'
                'border-radius:3px;font-size:10px;font-weight:bold">✓ EXPLOITABLE</span>')
        elif _c == "verified":
            cell += ('  <span style="background:#1b5e20;color:white;padding:1px 6px;'
                'border-radius:3px;font-size:10px;font-weight:bold">✓ VERIFIED</span>')
        return cell
    tls_rows = "".join(
        f'<tr><td style="font-family:monospace;font-size:12px">{html.escape(f["id"])}</td>'
        f'<td class="{SEV_TLS_CLASS.get(f["sev"],"tls-ok")}">{html.escape(TLS_SEV_PT.get(f["sev_raw"].upper(),f["sev_raw"]))}</td>'
        f'<td>{_tls_problem_cell(f)}</td>'
        f'<td>{html.escape(f["cve"] or "—")}</td></tr>'
        for f in tls_findings
    )
    tls_html = f'''<h2>TLS / SSL — {len(tls_findings)} issue(s) identified</h2>
    <table>
      <tr style="background:#f5f5f5"><th>Identifier</th><th>Severity</th><th>Issue</th><th>CVE/CWE</th></tr>
      {tls_rows}
    </table>'''
else:
    tls_html = ""

# ── Gerar HTML: Confirmação Ativa (Exploits vs Verificações) ─────────
def _conf_row(c):
    status_color = "#27ae60" if c.get("confirmed") else "#b34e4e"
    status_label = "✓ CONFIRMED" if c.get("confirmed") else "✗ NOT CONFIRMED"
    sev_colors = {"critical":"#7a2e2e","high":"#b34e4e","medium":"#d4833a","low":"#4a7c8c","info":"#888"}
    sev_c = sev_colors.get(c.get("severity","info"),"#888")

    evidence_html = ""
    if c.get("response_headers"):
        evidence_html += (
            f'<div style="font-size:11px;font-weight:600;color:#555;margin-bottom:3px">Response Headers</div>'
            f'<div class="evidence-box" style="margin-bottom:8px">{html.escape(str(c.get("response_headers","")))}</div>'
        )
    if c.get("response_body"):
        evidence_html += (
            f'<div style="font-size:11px;font-weight:600;color:#555;margin-bottom:3px">Response Body</div>'
            f'<div class="evidence-box">{html.escape(str(c.get("response_body","")))}</div>'
        )
    if not evidence_html:
        evidence_html = '<span style="color:#888">—</span>'

    curl_repr = c.get("curl_reproducible") or c.get("curl_command","")
    curl_html = (
        f'<div style="font-size:11px;font-weight:600;color:#555;margin-bottom:3px">Reproduce:</div>'
        f'<div class="evidence-box" style="background:#1e3a4f;color:#a8d8ea;font-size:11px">'
        f'{html.escape(curl_repr)}</div>'
    ) if curl_repr else ""

    conf = c.get("confidence", 0)
    vt   = c.get("vuln_type", "")
    return (
        f'<tr>'
        f'<td style="vertical-align:top">'
        f'  <code style="font-size:12px">{html.escape(str(c.get("template_id","—")))}</code><br>'
        f'  <span style="background:{sev_c};color:white;padding:1px 6px;border-radius:3px;font-size:10px">'
        f'  {str(c.get("severity","info")).upper()}</span>'
        f'</td>'
        f'<td style="vertical-align:top"><code style="font-size:11px;word-break:break-all">{html.escape(str(c.get("url","—")))}</code></td>'
        f'<td style="text-align:center;vertical-align:top">'
        f'  <span style="background:{status_color};color:white;padding:3px 8px;border-radius:4px;'
        f'  font-size:11px;font-weight:bold;white-space:nowrap">{status_label}</span><br>'
        f'  <code style="font-size:13px;font-weight:bold;color:{status_color}">{html.escape(str(c.get("http_status","—")))}</code>'
        f'</td>'
        f'<td style="text-align:center;vertical-align:top">'
        f'<div style="font-size:24px;font-weight:bold;color:{"#27ae60" if conf>=80 else ("#d4833a" if conf>=50 else "#b34e4e")}">{conf}%</div>'
        f'<div style="font-size:10px;color:#888;margin-top:2px">{html.escape(vt)}</div>'
        f'</td>'
        f'<td style="vertical-align:top">'
        f'<div style="background:#f0f7ff;border-left:3px solid #388bfd;padding:6px 10px;border-radius:3px;font-size:12px;margin-bottom:8px">'
        f'<strong>Note:</strong> {html.escape(c.get("poc_note","—"))}</div>'
        f'{evidence_html}{curl_html}'
        f'</td>'
        f'</tr>'
    )

def _conf_table(title, subtitle, items):
    rows = "".join(_conf_row(c) for c in items)
    return (
        f'<h3>{title} ({len(items)})</h3>'
        f'<p style="color:#666;font-size:13px">{subtitle}</p>'
        f'<table><tr style="background:#f5f5f5">'
        f'<th style="width:160px">Template</th><th>URL</th>'
        f'<th style="width:110px">Status</th><th style="width:80px">Confidence</th>'
        f'<th>Evidence & PoC Note</th></tr>' + rows + f'</table>'
    )

if confirmations:
    _exploits = [c for c in confirmations if c.get("confirmed") and c.get("category") == "exploit"]
    _verified = [c for c in confirmations if c.get("confirmed") and c.get("category") == "verified"]
    _notconf  = [c for c in confirmations if not c.get("confirmed")]
    confirm_html = (
        f'<h2>Active Confirmation — {len(_exploits)} exploit(s) · {len(_verified)} verification(s)</h2>'
        f'<p style="color:#666;font-size:13px">Each finding was re-executed. '
        f'<strong>Exploits</strong> are directly abusable vulnerabilities; '
        f'<strong>verifications</strong> confirm configuration/hardening issues (e.g. missing header, '
        f'TLS config) — relevant, but not exploitable on their own.</p>'
    )
    if _exploits:
        confirm_html += _conf_table(
            "🔴 Confirmed Exploits",
            "Abusable vulnerabilities with a reproducible PoC.", _exploits)
    if _verified:
        confirm_html += _conf_table(
            "🔵 Active Verifications",
            "Configuration/hardening issues confirmed via re-execution.", _verified)
    if _notconf:
        confirm_html += _conf_table(
            "⚪ Not Confirmed",
            "Findings that could not be confirmed on re-execution.", _notconf)
else:
    confirm_html = (
        f'<h2>Active Exploit Confirmation</h2>'
        f'<div style="background:#f5f5f5;border-left:4px solid #888;padding:14px 16px;'
        f'border-radius:4px;color:#666;font-size:13px">'
        f'<strong>No findings eligible for active confirmation.</strong><br>'
        f'Active confirmation only runs on Nuclei findings of '
        f'Critical, High or Medium severity that include a curl-command. '
        f'If the scan used only ZAP, the findings appear in the '
        f'Identified Vulnerabilities section with full request/response evidence.'
        f'</div>'
    )


# ── Gerar HTML: Plano de Ação Priorizado ─────────────────────────
SEV_ORDER = {"critical":0,"high":1,"medium":2,"low":3,"info":4}

# Coletar todos os achados acionáveis por prazo
# Email Security fica apenas na tabela — excluir do plano de ação para não duplicar
imediato  = [f for f in all_f if f["severity"] in ("critical","high") and f.get("source") not in _EMAIL_ONLY_TABLE]
sprint    = [f for f in all_f if f["severity"] == "medium" and f.get("source") not in _DEDICATED_SOURCES]
backlog   = [f for f in zap_low_groups.values() if f["sev"] in ("low","info")]

def action_card(title, icon, color, bg, items, prazo, descricao):
    if not items: return ""
    rows = ""
    seen_names = set()
    for item in items[:10]:
        name = item.get("name","") if isinstance(item,dict) and "name" in item else item.get("finding",{}).get("name","")
        if name in seen_names: continue
        seen_names.add(name)
        count = item.get("affected_count",1) if isinstance(item,dict) and "affected_count" in item else item.get("count",1)
        sev_f = item.get("severity","") if "severity" in item else item.get("sev","")
        count_str = f" <span style='color:#666;font-size:11px'>({count} occurrence(s))</span>" if count > 1 else ""
        rows += f"<li style='margin:4px 0'><strong>{html.escape(name)}</strong>{count_str}</li>"
    return f"""<div style="border-left:5px solid {color};padding:16px;margin:12px 0;background:{bg};border-radius:4px">
  <h3 style="margin:0 0 6px;color:{color}">{icon} {html.escape(title)} <span style="font-size:12px;font-weight:normal;color:#666">— Timeframe: {prazo}</span></h3>
  <p style="margin:0 0 10px;font-size:13px;color:#555">{descricao}</p>
  <ul style="margin:0;padding-left:20px;font-size:13px">{rows}</ul>
</div>"""

plan_parts = []
plan_parts.append(action_card(
    "Immediate Action","🔴","#7a2e2e","#fff0f0",
    imediato,"this week",
    "Critical and high vulnerabilities with direct compromise potential. Halt deployment if necessary."
))
plan_parts.append(action_card(
    "Next Sprint","🟡","#d4833a","#fff8f0",
    sprint,"next 2 weeks",
    "Medium findings that reduce the attack surface. Include in the team's upcoming stories."
))
plan_parts.append(action_card(
    "Security Backlog","🔵","#4a7c8c","#f0f8ff",
    backlog,"next 30 days",
    "Hardening and header improvements. Schedule as security technical debt."
))

action_plan_html = ""
if any(plan_parts):
    action_plan_html = f"""<h2>Action Plan for the Team</h2>
<div class="info-box">
  <p>Prioritization based on CVSS + EPSS. Findings with higher active-exploitation probability were prioritized.</p>
</div>
{"".join(plan_parts)}"""

# ── Matriz Esforço × Impacto (priorização estilo Big4) ───────────
def _estimate_effort(f):
    """Esforço de correção: baixo (config/infra) / médio / alto (código/arquitetura)."""
    cve  = str(f.get("cve", "")).upper()
    name = str(f.get("name", "")).lower()
    src  = f.get("source", "")
    _m   = re.search(r'CWE-?(\d+)', cve)
    cwe  = _m.group(1) if _m else ""
    HIGH_CWE = {"89","78","77","94","502","611","918","22","23","287","306",
                "352","384","843","917","98","434"}
    if cwe in HIGH_CWE: return "alto"
    if any(k in name for k in ("sql injection","sqli","command inject","rce",
            "remote code","deserial","ssrf","xxe","path traversal","authentication",
            "authorization","bypass","csrf","ssti","file upload","lfi")):
        return "alto"
    LOW_CWE = {"693","1021","319","614","1004","532","16"}
    if cwe in LOW_CWE: return "baixo"
    if src in ("Email Security", "testssl.sh"): return "baixo"
    if any(k in name for k in ("header","hsts","spf","dmarc","dkim","cipher","tls/ssl",
            "ssl","cookie","clickjacking","security.txt","caa","ocsp","rate limit")):
        return "baixo"
    return "médio"

def _impact_tier(sev):
    return "alto" if sev in ("critical","high") else "médio" if sev == "medium" else "baixo"

_matrix = {}
_seen_m = set()
for f in all_f:
    sev = f.get("severity", "")
    if sev not in ("critical","high","medium","low"): continue
    nm = f.get("name", "")
    if not nm or nm in _seen_m: continue
    _seen_m.add(nm)
    _matrix.setdefault((_impact_tier(sev), _estimate_effort(f)), []).append((nm, sev))

def _matrix_cell(imp, eff, highlight=False):
    items = sorted(_matrix.get((imp, eff), []), key=lambda x: SEV_ORDER.get(x[1], 9))
    if not items:
        body = '<span style="color:#ccc">—</span>'
    else:
        body = "<br>".join(f'{badge(s)} {html.escape(n[:46])}' for n, s in items[:7])
        if len(items) > 7:
            body += f'<br><span style="color:#888;font-size:11px">+{len(items)-7} more</span>'
    bg = "#eafaf1" if highlight else "#fff"
    tag = ('<div style="font-size:10px;font-weight:bold;color:#1b5e20;margin-bottom:4px">★ QUICK WINS</div>'
           if highlight else "")
    return f'<td style="vertical-align:top;background:{bg};padding:8px;font-size:12px;border:1px solid #e0e0e0">{tag}{body}</td>'

priority_matrix_html = ""
if _seen_m:
    priority_matrix_html = f"""<h2>Prioritization Matrix — Effort × Impact</h2>
<div class="info-box"><p style="font-size:13px">Cross-references <strong>impact</strong> (severity)
with the estimated <strong>remediation effort</strong>. The <strong>high impact + low
effort</strong> quadrant are the <strong>quick wins</strong> — top execution priority.</p></div>
<table style="border-collapse:collapse;width:100%">
<tr>
  <th style="padding:8px;width:90px;background:#1a3a4f;color:white"></th>
  <th style="padding:8px;background:#1a3a4f;color:white">Low Effort<br><span style="font-weight:normal;font-size:11px;color:#cdd8e3">config / infra</span></th>
  <th style="padding:8px;background:#1a3a4f;color:white">Medium Effort<br><span style="font-weight:normal;font-size:11px;color:#cdd8e3">upgrade / tuning</span></th>
  <th style="padding:8px;background:#1a3a4f;color:white">High Effort<br><span style="font-weight:normal;font-size:11px;color:#cdd8e3">code / architecture</span></th>
</tr>
<tr><th style="background:#7a2e2e;color:white;padding:8px">High<br>Impact</th>
  {_matrix_cell("alto","baixo",highlight=True)}{_matrix_cell("alto","médio")}{_matrix_cell("alto","alto")}</tr>
<tr><th style="background:#d4833a;color:white;padding:8px">Medium<br>Impact</th>
  {_matrix_cell("médio","baixo")}{_matrix_cell("médio","médio")}{_matrix_cell("médio","alto")}</tr>
<tr><th style="background:#4a7c8c;color:white;padding:8px">Low<br>Impact</th>
  {_matrix_cell("baixo","baixo")}{_matrix_cell("baixo","médio")}{_matrix_cell("baixo","alto")}</tr>
</table>"""

# ── Gerar HTML: Inventário de Tecnologias Detectadas ─────────
tech_inventory_html = ""
if tech_detected:
    # Coletar techs desatualizadas a partir do version_findings
    outdated_names = set()
    for _vf in version_findings:
        if _vf.get("is_outdated"):
            _m = re.match(r'^([A-Za-z][A-Za-z0-9\s\-/]+?)\s+v?[0-9]', _vf.get("name",""))
            if _m:
                outdated_names.add(_m.group(1).strip().lower())

    # Mapa de CVEs por tecnologia (de version_findings)
    tech_cve_map = {}
    for _vf in version_findings:
        _m = re.match(r'^([A-Za-z][A-Za-z0-9\s\-/]+?)\s+v?[0-9]', _vf.get("name",""))
        if _m:
            _tn = _m.group(1).strip()
            tech_cve_map[_tn.lower()] = re.sub(r'CWE-[0-9]+\s*[—-]\s*','', _vf.get("cve",""))[:80]

    rows = ""
    for _tech_name, _info in sorted(tech_detected.items(), key=lambda x: x[0].lower()):
        _version    = _info.get("version","") or "—"
        _source     = _info.get("source","")
        _confidence = _info.get("confidence","medium")
        _is_outdated = _tech_name.lower() in outdated_names or _info.get("outdated", False)
        _is_vuln_fw  = _info.get("vulnerable", False)

        if _is_outdated:
            _sbg, _slbl = "#b34e4e", "⚠ OUTDATED"
        elif _is_vuln_fw:
            _sbg, _slbl = "#d4833a", "⚠ VULNERABLE"
        elif _confidence == "confirmed":
            _sbg, _slbl = "#27ae60", "✓ CONFIRMED"
        else:
            _sbg, _slbl = "#6e8f72", "✓ DETECTED"

        _cves = tech_cve_map.get(_tech_name.lower(), "")
        _src_labels = {"httpx":"httpx","probe":"probe","path_fingerprint":"path","js_analysis":"JS"}
        _src_label = _src_labels.get(_source, _source)

        rows += (
            f'<tr>'
            f'<td style="font-weight:600">{html.escape(_tech_name)}</td>'
            f'<td><code style="font-size:12px">{html.escape(str(_version))}</code></td>'
            f'<td style="text-align:center">'
            f'<span style="background:{_sbg};color:white;padding:2px 8px;border-radius:4px;'
            f'font-size:11px;font-weight:bold;white-space:nowrap">{_slbl}</span></td>'
            f'<td style="font-size:11px;color:#555">{html.escape(_cves) if _cves else "—"}</td>'
            f'<td style="text-align:center">'
            f'<span style="background:#eee;padding:1px 6px;border-radius:3px;font-size:11px">'
            f'{html.escape(_src_label)}</span></td>'
            f'</tr>'
        )

    _outdated_count = len(outdated_names)
    _total_tech     = len(tech_detected)

    # Badges de categoria
    _cat_labels_pt = {
        "cms":"CMS","webserver":"Web Server","language":"Language","framework":"Framework",
        "database":"Database","cdn":"CDN","cloud":"Cloud",
        "monitoring":"Monitoring","devops":"DevOps","security":"Security"
    }
    _cat_badges = "".join(
        f'<span style="background:#e8f4f8;border:1px solid #1a3a4f;padding:3px 10px;'
        f'border-radius:12px;font-size:12px;margin:3px;display:inline-block">'
        f'<strong>{_cat_labels_pt.get(_cat,_cat)}:</strong> {", ".join(_items)}</span>'
        for _cat, _items in tech_categories.items()
    )
    _cat_html = f'<div style="margin:10px 0 14px">{_cat_badges}</div>' if _cat_badges else ""

    _outdated_badge = (
        f' — <span style="color:#b34e4e;font-weight:bold">{_outdated_count} outdated</span>'
        if _outdated_count else " — up-to-date stack"
    )
    tech_inventory_html = (
        f'<h2>2.5. Detected Technology Inventory</h2>'
        f'<div class="info-box">'
        f'<p><strong>{_total_tech} component(s) identified</strong>{_outdated_badge}. '
        f'Detected via httpx tech-detect, JS analysis and endpoint fingerprinting.</p>'
        + _cat_html +
        f'</div>'
        f'<table><tr style="background:#f5f5f5">'
        f'<th style="width:170px">Component</th>'
        f'<th style="width:130px">Version</th>'
        f'<th style="width:150px">Status</th>'
        f'<th>Known CVEs</th>'
        f'<th style="width:70px">Source</th>'
        f'</tr>' + rows + f'</table>'
    )

# ── Big4: Escopo & Metodologia (seção 1.1) ───────────────────
_auth_token  = os.environ.get("AUTH_TOKEN", "")
_auth_header = os.environ.get("AUTH_HEADER", "")
_scan_type   = ("Authenticated (token/header provided)"
                if (_auth_token or _auth_header)
                else "Unauthenticated (black-box)")

# Canonical pipeline — status derived from raw/.phase_times + artifacts
_PIPELINE = [
    ("P1",   "Subdomain discovery",        "subfinder + httpx + katana"),
    ("P2",   "Surface mapping",            "httpx + nmap + katana"),
    ("P2_5", "WAF & header detection",     "wafw00f + security headers"),
    ("P3",   "TLS/SSL analysis",           "testssl.sh"),
    ("P4",   "Vulnerability scanning",     "Nuclei (adaptive tags)"),
    ("P5",   "Active exploit confirmation","poc_validator (re-execution)"),
    ("P6",   "CVE enrichment",             "NVD + EPSS + CISA KEV"),
    ("P8",   "Email security",             "SPF / DMARC / DKIM"),
    ("P9",   "Dynamic scan",               "OWASP ZAP (spider + active)"),
    ("P10",  "JavaScript analysis",        "secrets + endpoints + libs"),
    ("P10_5","Supplementary fuzzing",      "ffuf + CMS scanners"),
    ("P11",  "Report generation",          "stiglitz_report.py"),
]
_phase_artifact = {"P3": "testssl.json"}  # phases that run without recording 'end' in .phase_times
_method_rows = ""
for _pid, _pname, _ptools in _PIPELINE:
    if _pid in phase_times:
        _d = phase_times[_pid]
        if _d > 0:
            _label, _dur, _color = "✓ Executed", f"{_d//60}m {_d%60:02d}s", "#1b5e20"
        else:
            _label, _dur, _color = "✓ Executed", "no applicable work", "#4a7c8c"
    elif _pid == "P11":
        _label, _dur, _color = "✓ Executed", "—", "#1b5e20"
    elif _pid in _phase_artifact and os.path.exists(os.path.join(OUTDIR, "raw", _phase_artifact[_pid])):
        _label, _dur, _color = "✓ Executed", "—", "#1b5e20"
    else:
        _label, _dur, _color = "○ Not executed", "—", "#888"
    _method_rows += (f'<tr><td style="font-family:monospace">{_pid.replace("_",".")}</td>'
        f'<td>{html.escape(_pname)}</td>'
        f'<td style="font-size:12px;color:#555">{html.escape(_ptools)}</td>'
        f'<td style="color:{_color};font-weight:600;white-space:nowrap">{_label}</td>'
        f'<td style="white-space:nowrap">{_dur}</td></tr>')

# Risk score derivation narrative
_total_occ = sum(occurrences.values())
_risk_narr = (f"The score <strong>{risk}/100</strong> uses a base tier from the highest severity "
    f"present (critical→70, high→40, medium→15, low→5) plus a quantity bonus with "
    f"diminishing returns over <strong>{total}</strong> unique finding type(s)")
if _total_occ > total:
    _risk_narr += f" ({_total_occ} total occurrences, counted once per type to avoid saturation)"
if kev_bonus:  _risk_narr += f", adds <strong>+{kev_bonus}</strong> for CVE(s) under active exploitation (CISA KEV)"
if epss_bonus: _risk_narr += f", <strong>+{epss_bonus}</strong> for exploitation probability (EPSS)"
if js_bonus:   _risk_narr += f", <strong>+{js_bonus}</strong> for JavaScript exposures"
_risk_narr += f". Final classification: <strong style='color:{scol}'>{html.escape(stxt)}</strong>."

_waf_limit = (f' The target is protected by a WAF ({html.escape(WAF_NAME)}): the active scan may contain '
    f'false negatives.' if WAF_DETECTED and WAF_NAME else '')

methodology_html = f'''<h2>1.1. Scope &amp; Methodology</h2>
<table>
<tr><th style="width:220px">Target</th><td><code>{html.escape(TARGET)}</code></td></tr>
<tr><th>Domain</th><td>{html.escape(DOMAIN)}</td></tr>
<tr><th>Scan date</th><td>{rdate}</td></tr>
<tr><th>Total duration</th><td>{duration_str}</td></tr>
<tr><th>Assessment type</th><td>{_scan_type}</td></tr>
<tr><th>Authorization</th><td>Execution restricted to environments with a signed Rules of Engagement (RoE).</td></tr>
</table>
<div class="info-box" style="margin-top:10px">
<p><strong>Risk derivation:</strong> {_risk_narr}</p>
</div>
<h3>Executed Pipeline</h3>
<table>
<tr style="background:#f5f5f5"><th style="width:60px">Phase</th><th>Activity</th><th>Tools</th><th style="width:150px">Status</th><th style="width:120px">Duration</th></tr>
{_method_rows}
</table>
<div class="info-box" style="margin-top:10px;font-size:12px">
<p><strong>Limitations:</strong> this is an automated assessment and does not replace a manual penetration test.{_waf_limit} Critical/high severity findings must be manually validated before remediation.</p>
</div>'''

# ── Diff com scan anterior do mesmo domínio ──────────────────
def _find_prev_scan(outdir, domain):
    """Diretório de scan anterior mais recente (mesmo domínio) que tenha
    findings.json — pula scans antigos sem dados estruturados."""
    import glob
    base = os.path.dirname(os.path.abspath(outdir)) or "."
    cur  = os.path.basename(os.path.abspath(outdir))
    cands = [c for c in sorted(glob.glob(os.path.join(base, f"scan_{domain}_*")), reverse=True)
             if os.path.isdir(c) and os.path.basename(c) < cur]
    for c in cands:
        if os.path.exists(os.path.join(c, "findings.json")):
            return c
    return None

diff_html = ""
_prev_dir = _find_prev_scan(OUTDIR, DOMAIN)
if _prev_dir:
    _prev_fj = os.path.join(_prev_dir, "findings.json")
    _prev_findings = None
    try: _prev_findings = json.load(open(_prev_fj, encoding="utf-8")).get("findings", [])
    except Exception: _prev_findings = None
    if _prev_findings is not None:
        def _fkey(n): return re.sub(r'\s+', ' ', str(n).strip().lower())
        _ACT = ("critical", "high", "medium", "low")
        _cur_map  = {_fkey(f.get("name","")): (f.get("name",""), f.get("severity",""))
                     for f in all_f if f.get("severity") in _ACT and f.get("name")}
        _prev_map = {_fkey(f.get("name","")): (f.get("name",""), f.get("severity",""))
                     for f in _prev_findings if f.get("severity") in _ACT and f.get("name")}
        _novos      = set(_cur_map)  - set(_prev_map)
        _corrigidos = set(_prev_map) - set(_cur_map)
        _persist    = set(_cur_map)  & set(_prev_map)
        # timestamp do scan anterior (do nome do diretório scan_<dom>_YYYYMMDD_HHMMSS)
        _pm = re.search(r'_(\d{8})_(\d{6})$', os.path.basename(_prev_dir))
        if _pm:
            _d, _t = _pm.group(1), _pm.group(2)
            _prev_label = f"{_d[0:4]}-{_d[4:6]}-{_d[6:8]} {_t[0:2]}:{_t[2:4]}"
        else:
            _prev_label = os.path.basename(_prev_dir)

        def _diff_group(icon, title, color, keys, src_map):
            if not keys:
                return (f'<div style="flex:1;min-width:200px"><h4 style="color:{color};margin:0 0 6px">'
                        f'{icon} {title} (0)</h4><p style="color:#999;font-size:12px;margin:0">None</p></div>')
            rows = "".join(
                f'<li style="margin:3px 0;font-size:12px">{badge(src_map[k][1])} {html.escape(src_map[k][0][:48])}</li>'
                for k in sorted(keys, key=lambda k: SEV_ORDER.get(src_map[k][1], 9))[:12])
            extra = f'<li style="color:#888;font-size:11px">+{len(keys)-12} more</li>' if len(keys) > 12 else ""
            return (f'<div style="flex:1;min-width:200px"><h4 style="color:{color};margin:0 0 6px">'
                    f'{icon} {title} ({len(keys)})</h4><ul style="margin:0;padding-left:18px">{rows}{extra}</ul></div>')

        diff_html = (
            f'<h2>1.2. Evolution Since Last Scan</h2>'
            f'<div class="info-box"><p style="font-size:13px">Compared with the scan from '
            f'<strong>{_prev_label}</strong> (by finding type). '
            f'<span style="color:#27ae60">{len(_corrigidos)} fixed</span> · '
            f'<span style="color:#b34e4e">{len(_novos)} new</span> · '
            f'<span style="color:#888">{len(_persist)} persistent</span>.</p></div>'
            f'<div style="display:flex;gap:20px;flex-wrap:wrap;margin:10px 0">'
            + _diff_group("🆕", "New", "#b34e4e", _novos, _cur_map)
            + _diff_group("✅", "Fixed", "#27ae60", _corrigidos, _prev_map)
            + _diff_group("➡️", "Persistent", "#888", _persist, _cur_map)
            + '</div>'
        )

# ── PCI DSS CDE Coverage section ─────────────────────────────
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
                     f"<td style='font-size:11px'>{html.escape(_pv._url_of(f))}</td></tr>")
    pci_section_html = (
        "<h2>PCI DSS CDE Coverage</h2>"
        "<p>Findings on assets declared in the CDE scope, by PCI DSS 4.0.1 requirement.</p>"
        "<table><tr><th>Req</th><th>Sev</th><th>Finding</th><th>Asset</th></tr>"
        + rows + "</table>")

page = f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<title>Security Report — {html.escape(DOMAIN)}</title><style>
body{{font-family:'Segoe UI',Arial,sans-serif;margin:0;padding:20px;background:#f0f2f5}}
.container{{max-width:1200px;margin:0 auto;background:white;border-radius:10px;overflow:hidden;box-shadow:0 2px 10px rgba(0,0,0,.1)}}
.header{{background:#1a3a4f;color:white;padding:30px;text-align:center}}.header h1{{margin:0 0 10px}}
.content{{padding:30px}}
.stats{{display:flex;gap:15px;margin:20px 0;flex-wrap:wrap}}
.stat-card{{flex:1;padding:20px;text-align:center;color:white;border-radius:8px;min-width:100px}}
.stat-card.critical{{background:#7a2e2e}}.stat-card.high{{background:#b34e4e}}
.stat-card.medium{{background:#d4833a}}.stat-card.low{{background:#4a7c8c}}.stat-card.info{{background:#6e8f72}}
.stat-card .number{{font-size:36px;font-weight:bold}}
.info-box{{background:#e8f4f8;padding:15px;border-radius:8px;margin:20px 0;border-left:4px solid #1a3a4f}}
.vuln{{border:1px solid #ddd;margin:20px 0;padding:20px;border-radius:8px;background:#fafafa}}
.vuln.critical{{border-left:10px solid #7a2e2e}}.vuln.high{{border-left:10px solid #b34e4e}}
.vuln.medium{{border-left:10px solid #d4833a}}.vuln.low{{border-left:10px solid #4a7c8c}}.vuln.info{{border-left:10px solid #6e8f72}}
.vuln h3{{margin-top:0}}.source-badge{{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:bold;margin-left:8px}}
.source-nuclei{{background:#3498db;color:white}}.source-zap{{background:#e74c3c;color:white}}.source-headers{{background:#7d3c98;color:white}}.source-version{{background:#d35400;color:white}}
.footer{{background:#f5f5f5;padding:20px;text-align:center;font-size:12px;color:#666}}
table{{width:100%;border-collapse:collapse;margin:10px 0}}th,td{{border:1px solid #ddd;padding:10px;text-align:left;vertical-align:top}}
th{{background:#f5f5f5;font-weight:600}}h2{{color:#1a3a4f;border-bottom:2px solid #e0e0e0;padding-bottom:8px}}
.risk-bar-wrap{{background:#e0e0e0;border-radius:4px;height:12px;margin:8px 0}}
.risk-bar{{background:{scol};height:12px;border-radius:4px;width:{risk}%}}
code{{background:#f4f4f4;padding:1px 4px;border-radius:3px;font-size:12px}}
    .evidence-box{{background:#2d3436;color:#dfe6e9;padding:10px 14px;font-family:monospace;font-size:12px;border-radius:4px;overflow-x:auto;white-space:pre-wrap;word-break:break-all}}
    .tls-ok{{color:#27ae60;font-weight:bold}}.tls-warn{{color:#d4833a;font-weight:bold}}
    .tls-high{{color:#b34e4e;font-weight:bold}}.tls-critical{{color:#7a2e2e;font-weight:bold}}
    .confirm-yes{{background:#27ae60;color:white;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:bold}}
    .confirm-no{{background:#95a5a6;color:white;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:bold}}
</style></head><body><div class="container">
<div class="header"><h1>Security Report</h1>
<p>Target: <strong>{html.escape(TARGET)}</strong> | Domain: {html.escape(DOMAIN)}</p>
<p>Date: {rdate} &nbsp;|&nbsp; Duration: {duration_str} &nbsp;|&nbsp; <strong>CONFIDENTIAL</strong></p></div>
<div class="content">
<h2>1. Executive Summary</h2>
<div class="stats">
{f'<div class="stat-card" style="background:#7a0000;border:2px solid #ff4444"><div class="number">{kev_count}</div><div>🔴 KEV</div></div>' if kev_count > 0 else ""}
<div class="stat-card critical"><div class="number">{stats['critical']}</div><div>CRITICAL</div></div>
<div class="stat-card high"><div class="number">{stats['high']}</div><div>HIGH</div></div>
<div class="stat-card medium"><div class="number">{stats['medium']}</div><div>MEDIUM</div></div>
<div class="stat-card low"><div class="number">{stats['low']}</div><div>LOW</div></div>
<div class="stat-card info"><div class="number">{stats['info']}</div><div>INFO</div></div></div>
{f'<div style="background:#7a0000;color:white;padding:14px 18px;border-radius:6px;margin:12px 0;border-left:6px solid #ff4444"><strong style="font-size:14px">🔴 {kev_count} CVE(S) WITH CONFIRMED ACTIVE EXPLOITATION — CISA KEV</strong><br><span style="font-size:12px;opacity:.9">These CVEs are in the CISA Known Exploited Vulnerabilities catalog. Regardless of CVSS score, they require immediate action: ' + ", ".join(f"<code style='background:rgba(255,255,255,.15);padding:1px 4px;border-radius:3px'>{html.escape(cid)}</code>" for cid in list(kev_matches.keys())[:10]) + (f" and {len(kev_matches)-10} more" if len(kev_matches)>10 else "") + "</span></div>" if kev_count > 0 else ""}
<div class="info-box">
<p><strong>Risk Score (0–100):</strong> {risk} <small style="color:#888;font-size:11px">(methodology: KEV + EPSS + CVSS + JS)</small></p>
<div class="risk-bar-wrap"><div class="risk-bar"></div></div>
<p><strong>Total Findings:</strong> {total} &nbsp;|&nbsp; <strong>Status:</strong> <span style="color:{scol};font-weight:bold">{stxt}</span></p>
<p><strong>Total scan duration:</strong> {duration_str}</p>
<p><strong>Tools:</strong> Nuclei + OWASP ZAP{"+ wafw00f" if WAF_DETECTED or os.path.exists(os.path.join(OUTDIR,"raw","waf.json")) else ""}{"+ Katana" if KATANA_URLS > 0 else ""}{"+ JS/Secrets" if js_analysis else ""}{"+ testssl" if TLS_ISSUES >= 0 and os.path.exists(os.path.join(OUTDIR,"raw","testssl.json")) else ""}{"+ OpenAPI" if OPENAPI_FOUND else ""}</p>
<p><strong>Actively verified exploits:</strong> {CONFIRMED_COUNT} re-executed with captured response</p>
{'<p style="background:#fff3cd;padding:8px 12px;border-radius:4px;margin:8px 0;font-size:13px"><strong style="color:#856404">🛡 WAF: '+html.escape(WAF_NAME)+'</strong> — active scan may have false negatives.</p>' if WAF_DETECTED and WAF_NAME else ""}
{'<p style="color:#b34e4e;font-size:13px">⚠ <strong>'+str(EMAIL_ISSUES)+' email security issue(s)</strong> detected.</p>' if EMAIL_ISSUES > 0 else ""}
</div>
{methodology_html}
{diff_html}
<h2>2. Attack Surface</h2>
<table>
<tr><th style="width:220px">Subdomains discovered</th><td>{SUB_COUNT}</td></tr>
<tr><th>Active subdomains (HTTP)</th><td>{ACTIVE_COUNT}</td></tr>
<tr><th>Open ports</th><td><code>{html.escape(OPEN_PORTS)}</code></td></tr>
{f'<tr><th>URLs (Katana JS crawl)</th><td>{KATANA_URLS} URL(s) discovered with JS rendering</td></tr>' if KATANA_URLS > 0 else ""}</table>
<h3>Live Hosts (httpx)</h3><table><tr><th>Result</th></tr>{trows(httpx_lines,"httpx not run or no results detected")}</table>
<h3>Open Ports and Services (nmap)</h3><table><tr><th>Port / Service</th></tr>{trows(nmap_lines,"nmap not run or no open ports")}</table>
{tech_inventory_html}
<h2>3. Identified Vulnerabilities</h2>{vhtml}
{pci_section_html}

<!-- Scan Behavior -->
{scan_behavior_html}

<!-- WAF + Email Security -->
{waf_email_html}

<!-- TLS Section -->
{tls_html}

<!-- Exploit Confirmations -->
{confirm_html}


<!-- JS Analysis -->
{js_html}
{errsec}
{low_table_html}

<!-- Action Plan -->
{action_plan_html}

<!-- Effort x Impact Prioritization Matrix -->
{priority_matrix_html}
<h2>5. Evidence Files</h2><div class="info-box"><ul>
<li><code>raw/subdomains.txt</code> — Discovered subdomains</li>
<li><code>raw/httpx_results.txt</code> — Live HTTP hosts and technologies</li>
<li><code>raw/nmap.txt</code> — Port and service scan</li>
<li><code>raw/nuclei.json</code> — Nuclei findings (raw JSONL)</li>
<li><code>raw/zap_alerts.json</code> — OWASP ZAP alerts (raw JSON)</li>
<li><code>raw/zap_evidencias.xml</code> — Full ZAP report (XML)</li>
{"<li><code>raw/testssl.json</code> — TLS/SSL analysis (testssl)</li>" if os.path.exists(os.path.join(OUTDIR,"raw","testssl.json")) else ""}
{"<li><code>raw/kev_matches.json</code> — CVEs with confirmed active exploitation (CISA KEV)</li>" if kev_matches else ""}
{"<li><code>raw/cve_enrichment.json</code> — CVE data (CVSS + EPSS) from NVD/FIRST</li>" if cve_enrichment else ""}
{"<li><code>raw/exploit_confirmations.json</code> — Active exploit confirmation results</li>" if confirmations else ""}
{"<li><code>raw/openapi_spec.json</code> — Imported OpenAPI/Swagger spec</li>" if OPENAPI_FOUND else ""}
{"<li><code>raw/scan_metadata.json</code> — Scan behavior and evasion configuration</li>" if scan_meta else ""}
{"<li><code>raw/waf.json</code> — WAF detection (wafw00f)</li>" if os.path.exists(os.path.join(OUTDIR,"raw","waf.json")) else ""}
{"<li><code>raw/email_security.json</code> — SPF/DMARC/DKIM</li>" if email_security else ""}
{"<li><code>raw/katana_urls.txt</code> — URLs discovered by Katana (JS crawl)</li>" if KATANA_URLS > 0 else ""}
{"<li><code>raw/ffuf.json</code> — Endpoints discovered by fuzzing (ffuf)</li>" if FFUF_FOUND > 0 else ""}
{"<li><code>raw/smuggler.txt</code> — HTTP Request Smuggling analysis</li>" if SMUGGLER_FOUND else ""}
{"<li><code>raw/trufflehog.json</code> — High-confidence secrets (trufflehog)</li>" if TRUFFLEHOG_FOUND > 0 else ""}
{"<li><code>raw/js_analysis.json</code> — Full JS/Secrets analysis</li>" if js_analysis else ""}
{"<li><code>raw/js_files/</code> — JS files for forensic analysis</li>" if js_files_list else ""}
{"<li><code>raw/tech_profile.json</code> — Detected technology inventory (httpx + JS + probes)</li>" if tech_detected else ""}
{"<li><code>raw/wpscan.json</code> — WordPress scanner (wpscan)</li>" if os.path.exists(os.path.join(OUTDIR,"raw","wpscan.json")) else ""}
{"<li><code>raw/joomscan.txt</code> — Joomla scanner (joomscan)</li>" if os.path.exists(os.path.join(OUTDIR,"raw","joomscan.txt")) else ""}
{"<li><code>raw/droopescan.txt</code> — Drupal scanner (droopescan)</li>" if os.path.exists(os.path.join(OUTDIR,"raw","droopescan.txt")) else ""}
</ul>
<p><strong>Note:</strong> All findings must be manually validated before reporting to the client or development team.</p></div></div>
<div class="footer"><p><strong>CONFIDENTIAL — INTERNAL USE</strong></p>
<p>Security Assessment &nbsp;·&nbsp; CONFIDENTIAL</p></div></div></body></html>"""

out = os.path.join(OUTDIR,"stiglitz_report.html")
open(out,"w",encoding="utf-8").write(page)
print(f"[✓] Report: {out}")
print(f"[✓] {total} vulnerability(ies) | C={stats['critical']} H={stats['high']} M={stats['medium']} L={stats['low']} I={stats['info']}")
if errors: print(f"[!] {len(errors)} warning(s) — see report")

# ── findings.json ─────────────────────────────────────────────────
try:
    risk_level = stxt.split(" — ")[0] if " — " in stxt else stxt
    findings_out = {
        "schema_version": "1.0",
        "scan": {
            "target": TARGET, "domain": DOMAIN,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "risk_score": risk, "risk_level": risk_level,
            "waf_detected": WAF_DETECTED, "waf_name": WAF_NAME,
            "phase_times": phase_times,
        },
        "summary": {
            "total": total,
            "critical": stats["critical"], "high": stats["high"],
            "medium": stats["medium"], "low": stats["low"],
            "info": stats["info"], "kev_count": kev_count,
            "confirmed": sum(1 for c in confirmations if c.get("confirmed")),
        },
        "findings": [
            {k: v for k, v in {
                "id": f.get("id",""), "name": f.get("name",""),
                "severity": f.get("severity",""), "source": f.get("source",""),
                "url": f.get("url",""), "cve_ids": f.get("cve_ids",[]),
                # "cvss" e "epss" são campos legados nullable-obrigatórios: sempre
                # presentes no JSON de saída (mesmo que None) para não quebrar
                # consumers existentes (DefectDojo, CI parsers, stiglitz_diff.py)
                # que dependem da presença da chave. Novos consumers devem
                # preferir cvss_environmental/epss_score respectivamente.
                "cvss": f.get("cvss"), "epss": f.get("epss_score"),
                "in_kev": f.get("in_kev",False),
                "description": f.get("description",""),
                "remediation": f.get("remediation",""),
                "risk_score": f.get("risk_score",0),
                # Campos de criticidade (presentes após enrich_findings)
                "cvss_vector": f.get("cvss_vector"),
                "cvss_base": f.get("cvss_base"),
                "cvss_temporal": f.get("cvss_temporal"),
                "cvss_environmental": f.get("cvss_environmental"),
                "severity_tool": f.get("severity_tool"),
                "score_source": f.get("score_source"),
                "asset_class": f.get("asset_class"),
                "requirements": f.get("requirements"),
            }.items() if v is not None or k in ("id","name","severity","source","url",
                                                  "cve_ids","cvss","in_kev","description",
                                                  "remediation","risk_score","epss")}
            for f in all_f
        ],
        "confirmations": [
            {"template_id": c.get("template_id",""), "url": c.get("url",""),
             "severity": c.get("severity",""), "confirmed": c.get("confirmed",False),
             "confidence": c.get("confidence",0), "poc_note": c.get("poc_note",""),
             "http_status": c.get("http_status",""),
             "curl_reproducible": c.get("curl_reproducible","")}
            for c in confirmations
        ],
        "security_headers": security_headers_data,
    }
    fj = os.path.join(OUTDIR,"findings.json")
    json.dump(findings_out, open(fj,"w",encoding="utf-8"), ensure_ascii=False, indent=2, default=str)
    print(f"[✓] Structured JSON: {fj}")
except Exception as _e:
    print(f"[!] findings.json: {_e}")

# ── findings.sarif (SARIF 2.1.0 — GitHub Security / DefectDojo / CI) ──
# Lógica em lib/report/sarif.py (extraída para teste em isolamento).
try:
    sarif_out = build_sarif(all_f, TARGET)
    sf = os.path.join(OUTDIR, "findings.sarif")
    json.dump(sarif_out, open(sf, "w", encoding="utf-8"),
              ensure_ascii=False, indent=2, default=str)
    print(f"[✓] SARIF 2.1.0: {sf}")
except Exception as _e:
    print(f"[!] findings.sarif: {_e}")

# ── executive_summary.html ────────────────────────────────────────
# Lógica em lib/report/exec_summary.py (extraída para teste em isolamento).
try:
    exec_html = build_exec_summary(
        target=TARGET, domain=DOMAIN,
        risk=risk, risk_label=stxt, timestamp=rdate,
        stats=stats, findings=all_f,
        kev_matches=kev_matches, phase_times=phase_times,
    )
    ef = os.path.join(OUTDIR, "executive_summary.html")
    open(ef, "w", encoding="utf-8").write(exec_html)
    print(f"[✓] Executive summary: {ef}")
except Exception as _e:
    print(f"[!] executive_summary: {_e}")


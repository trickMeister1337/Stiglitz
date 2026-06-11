#!/usr/bin/env python3
"""
cve_enrich.py — Enriquecimento NVD/EPSS/KEV dos CVEs encontrados

Extraído de stiglitz.sh (heredoc PYCVE). Recebe argumentos posicionais
via sys.argv, idêntico à invocação original do stiglitz.sh.
"""
import json, sys, os, re, urllib.request, urllib.parse, time, csv, io

outdir = sys.argv[1]
nuclei_file = os.path.join(outdir, "raw", "nuclei.json")
cve_db_file = os.path.join(outdir, "raw", "cve_enrichment.json")

# ── Carregar catálogo KEV com cache diário ───────────────────────
kev_set = set()
kev_meta = {}  # cve_id -> {date_added, due_date, vendor, product, notes}
import tempfile, time as _time
_cache_dir = os.path.join(os.path.expanduser("~"), ".cache", "stiglitz")
os.makedirs(_cache_dir, exist_ok=True)
_kev_cache = os.path.join(_cache_dir, "kev_cache.json")
_kev_max_age = 86400  # 24 horas em segundos
_kev_cached = False

# Verificar se cache existe e ainda é válido
if os.path.exists(_kev_cache):
    _cache_age = _time.time() - os.path.getmtime(_kev_cache)
    if _cache_age < _kev_max_age:
        try:
            _cached = json.load(open(_kev_cache))
            kev_set  = set(_cached.get("kev_set", []))
            kev_meta = _cached.get("kev_meta", {})
            _kev_cached = True
            _cache_mins = int(_cache_age // 60)
            print(f"  [✓] KEV: {len(kev_set)} CVEs carregados do cache "
                  f"({_cache_mins}min atrás)")
        except (json.JSONDecodeError, ValueError, OSError, KeyError): pass

if not _kev_cached:
    try:
        kev_url = "https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv"
        req_kev = urllib.request.Request(kev_url, headers={"User-Agent": "Stiglitz/1.0"})
        with urllib.request.urlopen(req_kev, timeout=15) as r:
            raw = r.read().decode("utf-8")
        reader = csv.DictReader(io.StringIO(raw))
        for row in reader:
            cid = row.get("cveID","").strip().upper()
            if cid:
                kev_set.add(cid)
                kev_meta[cid] = {
                    "date_added": row.get("dateAdded",""),
                    "due_date":   row.get("dueDate",""),
                    "vendor":     row.get("vendorProject",""),
                    "product":    row.get("product",""),
                    "notes":      row.get("notes","")[:200]
                }
        # Salvar cache
        json.dump({"kev_set": list(kev_set), "kev_meta": kev_meta,
                   "cached_at": _time.time()}, open(_kev_cache, "w"))
        print(f"  [✓] KEV: {len(kev_set)} CVEs baixados e salvos em cache")
    except Exception as e:
        print(f"  [!] KEV: falha no download ({e}) — continuando sem KEV")

del _kev_cache, _kev_max_age, _kev_cached

# Coletar CVEs únicos dos achados Nuclei
cves = set()
if os.path.exists(nuclei_file):
    with open(nuclei_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line: continue
            try:
                data = json.loads(line)
                cl = data.get("info", {}).get("classification", {}) or {}
                for cve in (cl.get("cve-id", []) or []):
                    if cve and cve.upper().startswith("CVE-"):
                        cves.add(cve.upper())
            except (json.JSONDecodeError, ValueError, AttributeError, TypeError):
                pass

# Coletar CVEs dos serviços de rede (nmap --script vulners → service_findings.json)
_svc_file = os.path.join(outdir, "raw", "service_findings.json")
if os.path.exists(_svc_file):
    try:
        for _sf in (json.load(open(_svc_file, encoding="utf-8")) or []):
            for _cve in re.findall(r'CVE-\d{4}-\d{4,7}', _sf.get("cve", ""), re.IGNORECASE):
                cves.add(_cve.upper())
    except Exception as _e:
        print(f"  [!] cve_enrich: falha ao ler service_findings.json ({_e})")

if not cves:
    print("  [○] Nenhum CVE encontrado nos achados (Nuclei/serviços)")
    sys.exit(0)

print(f"  [*] Consultando {len(cves)} CVE(s)...")
enriched = {}

for cve_id in sorted(cves):
    in_kev = cve_id in kev_set
    kev_info = kev_meta.get(cve_id, {})
    entry = {"cve_id": cve_id, "cvss_v3": None, "cvss_v2": None, "cvss_vector": "",
             "description": "", "epss_score": None, "epss_percentile": None,
             "severity": "", "in_kev": in_kev, "kev": kev_info}
    if in_kev:
        print(f"  [🔴] KEV: {cve_id} está no catálogo de explorações ativas! "
              f"(adicionado: {kev_info.get('date_added','?')} | prazo CISA: {kev_info.get('due_date','?')})")
    # NVD API v2 — com retry e backoff exponencial
    def nvd_fetch(cve_id, max_retries=3):
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={urllib.parse.quote(cve_id)}"
        for attempt in range(max_retries):
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "Stiglitz/1.0"})
                with urllib.request.urlopen(req, timeout=12) as r:
                    if r.status == 200:
                        return json.loads(r.read())
            except urllib.error.HTTPError as e:
                if e.code == 403 or e.code == 429:  # rate limited
                    wait = (2 ** attempt) * 6  # 6, 12, 24s
                    print(f"  [!] NVD rate limit ({e.code}) — aguardando {wait}s...")
                    time.sleep(wait)
                    continue
                print(f"  [!] NVD HTTP {e.code} para {cve_id}")
                return None
            except Exception as e:
                print(f"  [!] NVD erro para {cve_id}: {e}")
                return None
        return None

    nvd_data = nvd_fetch(cve_id)
    if nvd_data:
        vulns = nvd_data.get("vulnerabilities", [])
        if vulns:
            cve_data = vulns[0].get("cve", {})
            for d in cve_data.get("descriptions", []):
                if d.get("lang") == "en":
                    entry["description"] = d.get("value", "")[:300]
                    break
            metrics = cve_data.get("metrics", {})
            cvss3 = metrics.get("cvssMetricV31", metrics.get("cvssMetricV30", []))
            if cvss3:
                _cd = cvss3[0].get("cvssData", {})
                entry["cvss_v3"] = _cd.get("baseScore")
                entry["severity"] = _cd.get("baseSeverity", "")
                entry["cvss_vector"] = _cd.get("vectorString", "")
            cvss2 = metrics.get("cvssMetricV2", [])
            if cvss2:
                _cd2 = cvss2[0].get("cvssData", {})
                entry["cvss_v2"] = _cd2.get("baseScore")
                if not entry["cvss_vector"]:
                    entry["cvss_vector"] = _cd2.get("vectorString", "")
        print(f"  [✓] NVD: {cve_id} — CVSS {entry.get('cvss_v3','?')} {entry.get('severity','')}")
    time.sleep(6)  # NVD rate limit: 5 req/30s sem API key — mínimo 6s entre chamadas

    # EPSS API (FIRST.org)
    try:
        epss_url = f"https://api.first.org/data/v1/epss?cve={urllib.parse.quote(cve_id)}"
        req2 = urllib.request.Request(epss_url, headers={"User-Agent": "Stiglitz/1.0"})
        with urllib.request.urlopen(req2, timeout=10) as r2:
            epss_data = json.loads(r2.read())
        epss_list = epss_data.get("data", [])
        if epss_list:
            entry["epss_score"] = float(epss_list[0].get("epss", 0))
            entry["epss_percentile"] = float(epss_list[0].get("percentile", 0))
            print(f"  [✓] EPSS: {cve_id} — {entry['epss_score']:.4f} ({entry['epss_percentile']*100:.1f}° percentil)")
    except Exception as e:
        print(f"  [!] EPSS erro para {cve_id}: {e}")
    time.sleep(0.3)

    enriched[cve_id] = entry

# Adicionar entradas KEV para CVEs que não passaram pelo NVD mas estão no KEV
for cve_id in cves:
    if cve_id not in enriched and cve_id in kev_set:
        kev_info = kev_meta.get(cve_id, {})
        enriched[cve_id] = {
            "cve_id": cve_id, "cvss_v3": None, "cvss_v2": None,
            "description": f"Exploração ativa confirmada ({kev_info.get('vendor','')} {kev_info.get('product','')})",
            "epss_score": None, "epss_percentile": None,
            "severity": "", "in_kev": True, "kev": kev_info
        }
        print(f"  [🔴] KEV sem NVD: {cve_id} — adicionado pelo catálogo CISA")

# Salvar também CVEs do KEV que não foram encontrados pelo Nuclei mas podem estar em templates
kev_file = os.path.join(outdir, "raw", "kev_matches.json")
kev_hits = {cid: kev_meta[cid] for cid in cves if cid in kev_set}
with open(kev_file, "w", encoding="utf-8") as f:
    json.dump(kev_hits, f, ensure_ascii=False, indent=2)
if kev_hits:
    print(f"  [🔴] {len(kev_hits)} CVE(s) encontrado(s) no catálogo KEV — exploração ativa confirmada!")

with open(cve_db_file, "w", encoding="utf-8") as f:
    json.dump(enriched, f, ensure_ascii=False, indent=2)
print(f"  [✓] Enriquecimento salvo: {cve_db_file}")

#!/usr/bin/env python3
"""
Stiglitz RED — Ingestão e priorização de findings do Stiglitz.

Lê a saída do Stiglitz (findings.json + raw/) e produz listas priorizadas
para cada fase de exploração. Só promove URLs/CVEs que têm evidência real.

Uso: python3 ingest.py <scan_dir> <outdir>
"""
import json
import os
import re
import sys
from pathlib import Path


def _load_json(path):
    try:
        return json.loads(Path(path).read_text())
    except Exception:
        return None


def _load_jsonl(path):
    results = []
    try:
        for line in Path(path).read_text().splitlines():
            line = line.strip()
            if line:
                try:
                    results.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    except Exception:
        pass
    return results


def _write_lines(path, lines):
    Path(path).write_text("\n".join(lines) + "\n" if lines else "")


# ── Detecção de URL injetável ──────────────────────────────────────────────────

INJECTABLE_PARAMS = re.compile(
    r'[?&](id|user|username|uid|account|token|key|query|q|search|s|page|'
    r'file|path|url|redirect|next|return|ref|cat|category|type|action|'
    r'cmd|exec|order|sort|filter|lang|locale|format|name|email|pass|'
    r'password|hash|code|session|auth|api_key|secret|data|input|value|'
    r'param|field|table|db|database|view|template|module|component)=',
    re.IGNORECASE
)

def _has_injectable_param(url: str) -> bool:
    return bool(INJECTABLE_PARAMS.search(url))

def _url_score(url: str) -> int:
    """Score de prioridade para SQLi: maior = mais promissor."""
    score = 0
    if "?" in url and "=" in url:
        score += 2
    if _has_injectable_param(url):
        score += 5
    if re.search(r'/api/', url, re.I):
        score += 2
    if re.search(r'/admin|/login|/auth|/user|/account', url, re.I):
        score += 3
    # mais parâmetros = mais superfície
    score += min(url.count("="), 4)
    return score


# ── Parsers ────────────────────────────────────────────────────────────────────

def parse_findings(scan_dir: str) -> list:
    """Lê findings.json do Stiglitz — fonte primária."""
    path = os.path.join(scan_dir, "findings.json")
    data = _load_json(path)
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        return data.get("findings", [])
    return []


def parse_bizlogic(scan_dir: str) -> list:
    """Lê raw/bizlogic.json (findings de lógica de negócio/authz)."""
    data = _load_json(os.path.join(scan_dir, "raw", "bizlogic.json"))
    return data if isinstance(data, list) else []


def parse_confirmations(scan_dir: str) -> dict:
    """
    Lê exploit_confirmations.json do Stiglitz.
    Retorna dict {url: confidence} para achados confirmados.
    """
    path = os.path.join(scan_dir, "raw", "exploit_confirmations.json")
    data = _load_json(path)
    if not data:
        return {}
    confirmed = {}
    for item in (data if isinstance(data, list) else []):
        if item.get("confirmed"):
            url = item.get("url") or item.get("matched_at") or ""
            if url:
                confirmed[url] = item.get("confidence", 60)
    return confirmed


def parse_nuclei(scan_dir: str) -> list:
    """Lê nuclei.json do Stiglitz."""
    for name in ("nuclei.json", "nuclei_results.jsonl", "nuclei_all.json"):
        path = os.path.join(scan_dir, "raw", name)
        if os.path.exists(path):
            return _load_jsonl(path) or (_load_json(path) or [])
    return []


def parse_zap(scan_dir: str) -> list:
    """Lê zap_alerts.json do Stiglitz."""
    path = os.path.join(scan_dir, "raw", "zap_alerts.json")
    data = _load_json(path)
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        return data.get("alerts", [])
    return []


def parse_nmap(scan_dir: str) -> list:
    """
    Lê nmap.txt do Stiglitz e extrai serviços abertos.
    Retorna lista de dicts {port, protocol, service, version, host}.
    """
    services = []
    target = _extract_target(scan_dir)

    for name in ("nmap.txt", "nmap_results.txt"):
        path = os.path.join(scan_dir, "raw", name)
        if not os.path.exists(path):
            continue
        current_host = target
        for line in Path(path).read_text().splitlines():
            host_match = re.search(r'Nmap scan report for (.+)', line)
            if host_match:
                current_host = host_match.group(1).strip()
            port_match = re.match(
                r'^(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)', line
            )
            if port_match:
                services.append({
                    "host":     current_host,
                    "port":     int(port_match.group(1)),
                    "protocol": port_match.group(2),
                    "service":  port_match.group(3),
                    "version":  port_match.group(4).strip(),
                })
    return services


def parse_cves(scan_dir: str) -> list:
    """Coleta CVEs únicos de todas as fontes."""
    cves = set()

    # De findings.json
    for f in parse_findings(scan_dir):
        for cve in f.get("cve", []):
            if re.match(r'CVE-\d{4}-\d+', cve, re.I):
                cves.add(cve.upper())

    # De nuclei
    for item in parse_nuclei(scan_dir):
        classification = item.get("info", {}).get("classification", {})
        raw = classification.get("cve-id") or classification.get("cve") or []
        if isinstance(raw, str):
            raw = [raw]
        for cve in raw:
            if cve and re.match(r'CVE-\d{4}-\d+', cve, re.I):
                cves.add(cve.upper())

    # De cve_enrichment.json
    enrich = _load_json(os.path.join(scan_dir, "raw", "cve_enrichment.json"))
    if isinstance(enrich, dict):
        cves.update(k.upper() for k in enrich if re.match(r'CVE-\d{4}-\d+', k, re.I))

    return sorted(cves)


def _extract_target(scan_dir: str) -> str:
    """Tenta extrair o domínio do nome do diretório."""
    base = os.path.basename(scan_dir.rstrip("/"))
    m = re.match(r'^scan_(.+)_\d{8}_\d{6}$', base)
    return m.group(1) if m else base


# ── Priorização ────────────────────────────────────────────────────────────────

def build_sqli_targets(scan_dir: str, confirmed: dict) -> list:
    """
    Retorna lista de URLs ordenada por prioridade para SQLi.

    Prioridade (score):
      +20  URL confirmada como SQLi pelo poc_validator do Stiglitz
      +10  URL em achado ZAP de SQLi (High/Critical)
      +5   parâmetro com nome suspeito (id, user, token, etc.)
      +2   tem query string
      +2   endpoint de API
      +3   endpoint admin/auth/login
    """
    candidates: dict[str, int] = {}  # url -> score

    def add(url: str, extra: int = 0):
        if url and "?" in url:
            s = _url_score(url) + extra
            candidates[url] = max(candidates.get(url, 0), s)

    # Confirmações do Stiglitz (mais alta prioridade)
    for url, conf in confirmed.items():
        add(url, extra=20)

    # Nuclei findings com SQLi ou injection
    for item in parse_nuclei(scan_dir):
        tags = item.get("info", {}).get("tags", [])
        name = (item.get("info", {}).get("name") or "").lower()
        url  = item.get("matched-at") or item.get("host") or ""
        if any(t in ["sqli", "injection", "sql"] for t in tags) or "sql" in name:
            add(url, extra=15)
        else:
            add(url)

    # ZAP alerts de SQLi
    for alert in parse_zap(scan_dir):
        name = (alert.get("alert") or alert.get("name") or "").lower()
        risk = int(alert.get("riskcode") or alert.get("risk") or 0)
        url  = alert.get("url") or ""
        if "sql" in name or "inject" in name:
            add(url, extra=10 + risk * 2)
        elif risk >= 2:
            add(url, extra=risk)

    return sorted(candidates, key=lambda u: candidates[u], reverse=True)


def build_brute_targets(services: list) -> list:
    """
    Filtra serviços que fazem sentido para brute force.
    Retorna lista de dicts com host/port/service para o Hydra.
    """
    BRUTABLE = {
        "ssh": 22, "ftp": 21, "telnet": 23,
        "mysql": 3306, "postgresql": 5432, "mssql": 1433,
        "rdp": 3389, "smb": 445, "smtp": 25,
        "http": 80, "https": 443,
    }
    targets = []
    seen = set()

    for svc in services:
        name = svc["service"].lower()
        port = svc["port"]

        # Normalizar nomes comuns
        if name in ("ms-sql-s", "ms-wbt-server"):
            name = "mssql" if "sql" in name else "rdp"
        if name.startswith("http"):
            name = "https" if port in (443, 8443) else "http"

        if name in BRUTABLE:
            key = (svc["host"], port)
            if key not in seen:
                seen.add(key)
                targets.append({
                    "host":    svc["host"],
                    "port":    port,
                    "service": name,
                    "version": svc.get("version", ""),
                })

    return targets


# ── Entry point ────────────────────────────────────────────────────────────────

def ingest(scan_dir: str, outdir: str) -> dict:
    os.makedirs(outdir, exist_ok=True)

    confirmed  = parse_confirmations(scan_dir)
    sqli_urls  = build_sqli_targets(scan_dir, confirmed)
    services   = parse_nmap(scan_dir)
    brute_tgts = build_brute_targets(services)
    cves       = parse_cves(scan_dir)
    target     = _extract_target(scan_dir)

    # Salvar outputs para as fases
    _write_lines(os.path.join(outdir, "sqli_targets.txt"), sqli_urls)
    _write_lines(os.path.join(outdir, "cves_found.txt"), cves)

    svc_lines = [f"{s['host']}:{s['port']}:{s['service']}" for s in services]
    _write_lines(os.path.join(outdir, "open_services.txt"), svc_lines)

    brute_lines = [f"{b['host']}:{b['port']}:{b['service']}" for b in brute_tgts]
    _write_lines(os.path.join(outdir, "brute_targets.txt"), brute_lines)

    summary = {
        "target":        target,
        "sqli_urls":     len(sqli_urls),
        "confirmed_urls": len(confirmed),
        "cves":          len(cves),
        "services":      len(services),
        "brute_targets": len(brute_tgts),
    }
    Path(os.path.join(outdir, "ingest_summary.json")).write_text(
        json.dumps(summary, indent=2)
    )

    return summary


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(f"Uso: {sys.argv[0]} <scan_dir> <outdir>")
        sys.exit(1)
    s = ingest(sys.argv[1], sys.argv[2])
    print(f"[ingest] target={s['target']} sqli={s['sqli_urls']} "
          f"cves={s['cves']} brute={s['brute_targets']}")

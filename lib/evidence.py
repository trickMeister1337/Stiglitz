#!/usr/bin/env python3
"""
Stiglitz RED v7.0 — Extração de evidências e consolidação de findings.

Lê resultados de sqlmap, dalfox, hydra, metasploit e nikto.
Consolida findings deduplicados para o relatório HTML.
"""
import sys
import os
import json
import re
import glob
import csv
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse


def extract_sqlmap_evidence(log_content: str, log_dir: str) -> Dict[str, Any]:
    """Extrai evidência estruturada de um log do sqlmap."""
    info: Dict[str, Any] = {
        "target_url": "", "parameter": "", "place": "", "techniques": [],
        "dbms": "", "current_user": "", "current_db": "", "banner": "",
        "tables": [], "csv_data": [], "injectable": False,
    }

    for line in log_content.split("\n"):
        l = line.strip()
        ll = l.lower()
        clean = re.sub(r"\[\d{2}:\d{2}:\d{2}\]\s*\[\w+\]\s*", "", l)

        if "parameter '" in ll and ("is vulnerable" in ll or "injectable" in ll) \
                and "not injectable" not in ll and "might not be injectable" not in ll:
            info["injectable"] = True
            m = re.search(r"parameter '([^']+)'", l)
            if m: info["parameter"] = m.group(1)

        if "place:" in ll and not info["place"]:
            m = re.search(r"Place:\s*(\w+)", l, re.I)
            if m: info["place"] = m.group(1)

        if "type:" in ll and any(
            t in ll for t in ["boolean", "time", "union", "error", "stacked", "inline"]
        ):
            tech = re.sub(r"^.*Type:\s*", "", clean, flags=re.I).strip()
            if tech and tech not in info["techniques"] and "testing" not in ll:
                info["techniques"].append(tech)

        if "back-end dbms:" in ll:       info["dbms"]         = clean.split(":", 1)[-1].strip()
        if "current user:" in ll:        info["current_user"] = clean.split(":", 1)[-1].strip().strip("'\"")
        if "current database:" in ll:    info["current_db"]   = clean.split(":", 1)[-1].strip().strip("'\"")
        if "banner:" in ll:              info["banner"]        = clean.split(":", 1)[-1].strip().strip("'\"")

        if re.match(r"^\[\*\]\s+\w", l) and not any(
            kw in ll for kw in ("starting", "shutting", "ending", "fetched", "retrieved",
                                "maximum", "available", "used", "resumed", "cached")
        ):
            val = l.lstrip("[*] ").strip()
            # Rejeitar linhas que parecem timestamps ou mensagens de status
            if val and len(val) < 60 and not re.match(r"\w+ @ \d{2}:\d{2}:\d{2}", val) \
                    and val not in info["tables"]:
                info["tables"].append(val)

        m = re.search(r"testing URL '([^']+)'", l)
        if m: info["target_url"] = m.group(1)
        m = re.search(r"target URL:\s*(\S+)", l, re.I)
        if m: info["target_url"] = m.group(1)

    # CSV results
    csv_paths: List[str] = []
    for pattern in [f"{log_dir}/results-*.csv", f"{log_dir}/*/results-*.csv"]:
        csv_paths.extend(glob.glob(pattern))
    for d in glob.glob(f"{log_dir}/*/"):
        csv_paths.extend(glob.glob(f"{d}results-*.csv"))
    csv_paths = list(set(csv_paths))

    for cp in csv_paths[:3]:
        try:
            with open(cp) as f:
                rows = list(csv.reader(f))
            if len(rows) > 1:
                info["csv_data"].append(
                    {"file": os.path.basename(cp), "header": rows[0], "rows": rows[1:10]}
                )
        except Exception:
            pass

    for dp in glob.glob(f"{log_dir}/dump/**/*.csv", recursive=True)[:3]:
        try:
            with open(dp) as f:
                rows = list(csv.reader(f))
            if rows:
                tname = os.path.basename(dp).replace(".csv", "")
                info["csv_data"].append(
                    {"file": f"dump/{tname}", "header": rows[0] if rows else [], "rows": rows[1:10]}
                )
        except Exception:
            pass

    return info


def format_sqlmap_evidence(info: Dict[str, Any]) -> Optional[str]:
    parts: List[str] = []
    if info["parameter"]:
        line = f"Parâmetro vulnerável: {info['parameter']}"
        if info["place"]: line += f" ({info['place']})"
        parts.append(line)
    if info["techniques"]:
        parts.append("Técnica(s) de injeção:")
        for t in info["techniques"][:5]: parts.append(f"  • {t}")
    if info["dbms"]:         parts.append(f"DBMS: {info['dbms']}")
    if info["banner"]:       parts.append(f"Banner: {info['banner']}")
    if info["current_user"]: parts.append(f"Usuário: {info['current_user']}")
    if info["current_db"]:   parts.append(f"Base de dados: {info['current_db']}")
    if info["tables"]:
        parts.append("Tabelas:")
        for t in info["tables"][:10]: parts.append(f"  • {t}")
    if info["csv_data"]:
        for csv_info in info["csv_data"][:2]:
            parts.append(f"\nDados extraídos ({csv_info['file']}):")
            if csv_info["header"]:
                parts.append("  " + " | ".join(str(h) for h in csv_info["header"]))
            for row in csv_info["rows"][:5]:
                parts.append("  " + " | ".join(str(c) for c in row))
    return "\n".join(parts[:25]) if parts else None


# backwards-compat alias
format_evidence = format_sqlmap_evidence


_ANSI_RE = re.compile(r"\033\[[0-9;]*[mKHFABCDJsu]")


def strip_ansi(text: str) -> str:
    """Remove sequências de escape ANSI de texto terminal."""
    return _ANSI_RE.sub("", text)


def is_valid_url(url: str) -> bool:
    """Retorna True se url tem scheme http/https e hostname real (não vazio, não filename)."""
    if not url:
        return False
    try:
        p = urlparse(url)
    except Exception:
        return False
    if p.scheme not in ("http", "https"):
        return False
    host = p.netloc or p.path
    if not host or "." not in host:
        return False
    # Rejeita paths que parecem filenames (sem ponto de domínio no netloc)
    if not p.netloc:
        return False
    return True


def collect_and_consolidate(outdir: str) -> Dict[str, Any]:
    """Coleta dados de todas as fontes e consolida findings deduplicados."""

    def _rf(p: str, lim: Optional[int] = None) -> str:
        try:
            with open(p) as f:
                c = f.read()
                return c[-lim:] if lim else c
        except Exception:
            return ""

    def _rl(p: str) -> List[str]:
        try:
            with open(p) as f:
                return [ll.strip() for ll in f if ll.strip()]
        except Exception:
            return []

    def _rj(p: str):
        try:
            with open(p) as f:
                return json.load(f)
        except Exception:
            return []

    # ── SQLi ─────────────────────────────────────────────────────────────────
    sqli_results = []
    for f in sorted(glob.glob(f"{outdir}/sqlmap/*_output.log")):
        with open(f) as fh:
            c = fh.read()
        cl = c.lower()
        vuln = (
            "is vulnerable" in cl
            or "identified the following injection" in cl
            or (
                "injectable" in cl
                and "not injectable" not in cl
                and "might not be injectable" not in cl
            )
        )
        info = extract_sqlmap_evidence(c, os.path.dirname(f))
        info["injectable"] = info["injectable"] or vuln
        evidence = format_sqlmap_evidence(info)
        target_url = info["target_url"]
        if not target_url:
            m = re.search(r"testing URL '([^']+)'", c) or re.search(r"-u ['\"]?([^\s'\"]+)", c)
            target_url = m.group(1) if m else os.path.basename(f)
        sqli_results.append({
            "file": os.path.basename(f), "vulnerable": info["injectable"],
            "evidence": evidence, "target_url": target_url, "info": info
        })

    # ── XSS (dalfox) ─────────────────────────────────────────────────────────
    xss_results = []
    for xss_path in [f"{outdir}/xss/xss_all_results.json"]:
        if os.path.exists(xss_path):
            try:
                data = json.load(open(xss_path))
                if isinstance(data, list):
                    xss_results = data
            except Exception:
                pass

    xss_confirmed_lines = _rl(f"{outdir}/xss/xss_confirmed.txt")

    # ── Other sources ─────────────────────────────────────────────────────────
    msf_log = _rf(f"{outdir}/metasploit/msf_output.log", 4000)

    hydra_results = []
    for f in glob.glob(f"{outdir}/hydra/*.log"):
        c = _rf(f).strip()
        if c and ("login:" in c.lower() or "host:" in c.lower()):
            hydra_results.append({
                "service": os.path.basename(f).replace(".log", ""), "content": c
            })

    nikto_findings = []
    for nf_path in [f"{outdir}/nikto/nikto_filtered.json",
                    f"{outdir}/nikto/nikto_report.json"]:
        nd = _rj(nf_path)
        if nd:
            if isinstance(nd, list):
                nikto_findings = [x for x in nd if isinstance(x, dict)]
            elif isinstance(nd, dict):
                nikto_findings = nd.get("vulnerabilities", [])
            break

    cves      = _rl(f"{outdir}/data/cves_found.txt")
    services  = _rl(f"{outdir}/data/open_services.txt")
    log_content = _rf(f"{outdir}/stiglitz_red.log", 3000)

    zap_hc = []
    for line in _rl(f"{outdir}/data/zap_high_crit.txt"):
        p = line.split("|")
        if len(p) >= 3:
            zap_hc.append({"risk": p[0], "alert": p[1], "url": p[2]})

    ssd: Dict = {}
    for f in glob.glob(f"{outdir}/searchsploit/CVE-*.json"):
        cv = os.path.basename(f).replace(".json", "")
        d = _rj(f)
        if isinstance(d, dict):
            ex = d.get("RESULTS_EXPLOIT", [])
            if ex: ssd[cv] = ex

    subdomains = _rl(f"{outdir}/recon/subdomains.txt")

    # ── Confirmed CSV ─────────────────────────────────────────────────────────
    confirmed_all = []
    for line in _rl(f"{outdir}/exploits_confirmed.csv"):
        p = line.split("|")
        if len(p) >= 3:
            confirmed_all.append({
                "type": p[0], "sev": p[1] if len(p) > 1 else "HIGH",
                "target": p[2], "detail": "|".join(p[3:]) if len(p) > 3 else ""
            })

    # ── Build findings ────────────────────────────────────────────────────────
    findings: List[Dict] = []

    # SQLi from confirmed CSV
    confirmed_sqli = [c for c in confirmed_all if c["type"] in ("SQLI", "SQL_INJECT")]
    cg: Dict = {}
    for c in confirmed_sqli:
        base = re.sub(r"\?.*$", "", c["target"]).rstrip("/")
        path = re.sub(r"https?://[^/]+", "", base)
        key = ("sqlmap", path)
        if key not in cg: cg[key] = {"urls": []}
        cg[key]["urls"].append(c["target"])

    for key, grp in cg.items():
        urls = grp["urls"]; n = len(urls)
        best_ev = next(
            (r["evidence"] for r in sqli_results if r["vulnerable"] and r["evidence"]), None
        )
        ev_parts = []
        if best_ev: ev_parts.append(best_ev)
        ev_parts.append(f"\nEndpoints afetados ({n}):")
        for u in urls[:20]: ev_parts.append(f"  • {u}")
        if n > 20: ev_parts.append(f"  ... e mais {n - 20}")
        findings.append({
            "sev": "Critical",
            "title": f"SQL Injection ({n} endpoint{'s' if n>1 else ''})",
            "target": urls[0] if n == 1 else f"{n} endpoints em {urlparse(urls[0]).netloc}",
            "tool": "sqlmap", "detail": "\n".join(ev_parts), "type": "sqli",
            "count": n, "endpoints": urls
        })

    confirmed_urls_sqli = set(u for grp in cg.values() for u in grp["urls"])
    for r in sqli_results:
        if r["vulnerable"] and r["target_url"] not in confirmed_urls_sqli:
            findings.append({
                "sev": "High", "title": "SQL Injection Confirmada",
                "target": r["target_url"], "tool": "sqlmap",
                "detail": r["evidence"] or "Confirmada via sqlmap",
                "type": "sqli", "count": 1, "endpoints": [r["target_url"]]
            })

    # XSS from confirmed CSV
    confirmed_xss = [c for c in confirmed_all if c["type"] == "XSS"]
    if confirmed_xss:
        xss_urls = [c["target"] for c in confirmed_xss]
        findings.append({
            "sev": "High",
            "title": f"Cross-Site Scripting ({len(xss_urls)} endpoint{'s' if len(xss_urls)>1 else ''})",
            "target": xss_urls[0] if len(xss_urls) == 1 else f"{len(xss_urls)} endpoints",
            "tool": "dalfox",
            "detail": "\n".join(
                f"• {c['target']} | {c.get('detail','')}" for c in confirmed_xss[:20]
            ),
            "type": "xss", "count": len(xss_urls), "endpoints": xss_urls
        })
    elif xss_results:
        xss_vulns = [f for f in xss_results if f.get("payload") or f.get("type")]
        if xss_vulns:
            findings.append({
                "sev": "High",
                "title": f"Cross-Site Scripting ({len(xss_vulns)} finding{'s' if len(xss_vulns)>1 else ''})",
                "target": xss_vulns[0].get("url", "?"), "tool": "dalfox",
                "detail": "\n".join(
                    f"• {f.get('url','')} param={f.get('parameter','')} "
                    f"payload={str(f.get('payload',''))[:80]}" for f in xss_vulns[:20]
                ),
                "type": "xss", "count": len(xss_vulns),
                "endpoints": [f.get("url", "") for f in xss_vulns]
            })

    # Brute force
    confirmed_brute = [c for c in confirmed_all if c["type"] in ("BRUTE", "CREDENTIAL")]
    for r in confirmed_brute:
        findings.append({
            "sev": "High", "title": f"Credenciais Fracas — {r['target']}",
            "target": r["target"], "tool": "hydra",
            "detail": r.get("detail", "Credenciais padrão aceitas"),
            "type": "bruteforce", "count": 1, "endpoints": []
        })
    for r in hydra_results:
        if not any(f["tool"] == "hydra" and r["service"] in f.get("target", "") for f in findings):
            findings.append({
                "sev": "High", "title": f"Credenciais Fracas — {r['service'].upper()}",
                "target": r["service"], "tool": "hydra",
                "detail": r["content"][:400], "type": "bruteforce", "count": 1, "endpoints": []
            })

    # Lógica de negócio / Authz (bizlogic) — raw/bizlogic.json
    bizlogic_findings = []
    try:
        from ingest import parse_bizlogic
        bizlogic_findings = parse_bizlogic(outdir)
    except ImportError as _e:
        print(f"  [!] bizlogic: import de parse_bizlogic falhou ({_e}) — "
              f"findings de authz não serão incluídos")
    except Exception as _e:
        print(f"  [!] bizlogic: parse falhou ({_e}) — findings de authz não serão incluídos")
    for bf in bizlogic_findings:
        url = bf.get("url", "")
        ev = bf.get("evidence", {})
        detail = (json.dumps(ev, ensure_ascii=False, indent=2)
                  if isinstance(ev, (dict, list)) else str(ev))
        if not bf.get("confirmed", False):
            detail = "[NÃO CONFIRMADO — dry-run/potencial]\n" + detail
        findings.append({
            "sev": str(bf.get("severity", "high")).capitalize(),
            "title": bf.get("name", "Business logic / authz finding"),
            "target": url, "tool": bf.get("tool", "bizlogic"), "detail": detail,
            "type": bf.get("vuln_class", "bizlogic"), "count": 1,
            "endpoints": [url] if url else [],
            # Campos lidos pelo motor de criticidade (vuln_class via catálogo, confirmed→E:H).
            "url": url, "vuln_class": bf.get("vuln_class"),
            "confirmed": bf.get("confirmed", False),
        })

    # Dedup
    seen: set = set()
    deduped = []
    for f in findings:
        key = (f["tool"], f["type"], f.get("target", "")[:60])
        if key not in seen:
            seen.add(key); deduped.append(f)

    # Criticidade CVSS 3.1 por finding (Base+Temporal+Environmental).
    # enrich_findings lê confirmed/in_kev/epss de cada finding e infere a
    # classe do ativo do campo target/url. Falhas não interrompem o scan.
    try:
        import criticality as _criticality
        _ov = _criticality.load_asset_overrides(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        )
        # Normalizar os campos para que enrich_findings leia corretamente:
        # evidence.py usa 'target' como URL; criticality._host_path lê 'url'|'matched_at'|'host'.
        for _f in deduped:
            if "url" not in _f and "target" in _f:
                _f["url"] = _f["target"]
        _criticality.enrich_findings(deduped, overrides=_ov)
    except Exception as _e:
        print(f"  [!] criticality: enrich falhou ({_e}) — mantendo severidade da ferramenta")

    return {
        "findings": deduped,
        "sqli_results": sqli_results,
        "xss_results": xss_results,
        "xss_confirmed": xss_confirmed_lines,
        "msf_log": msf_log,
        "hydra_results": hydra_results,
        "nikto_findings": nikto_findings,
        "confirmed": confirmed_all,
        "cves": cves,
        "services": services,
        "log_content": log_content,
        "zap_hc": zap_hc,
        "searchsploit": ssd,
        "subdomains": subdomains,
    }


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    result = collect_and_consolidate(sys.argv[1])
    print(json.dumps({
        "findings_count": len(result["findings"]),
        "sqli_vulnerable": len([r for r in result["sqli_results"] if r["vulnerable"]]),
        "xss_count": len(result["xss_results"]),
        "cves": len(result["cves"]),
        "services": len(result["services"]),
        "subdomains": len(result["subdomains"]),
    }, indent=2))

#!/usr/bin/env python3
"""
Stiglitz RED v7.0 — Gerador de Relatório Red Team (Big4 Style).

Uso: python3 report_generator.py <outdir> <target> <profile> <total> <success> <failed> <version> [--scan-dir <scan_dir>]

Lê dados consolidados de evidence.py e gera stiglitz_red_report.html.
--scan-dir: integra findings.json do Stiglitz scan de origem no relatório.
"""
import sys
import os
import json
import html as H
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from evidence import collect_and_consolidate
from poc_generator import collect_pocs, generate_verify_script

esc = lambda s: H.escape(str(s)) if s else ""


def _load_scan_findings(scan_dir: str) -> list:
    """Load and convert findings.json from a Stiglitz scan directory."""
    fpath = os.path.join(scan_dir, "findings.json")
    if not os.path.exists(fpath):
        return []
    try:
        with open(fpath, encoding="utf-8") as f:
            data = json.load(f)
        raw = data.get("findings", []) if isinstance(data, dict) else data
    except Exception:
        return []

    sev_map = {"critical": "Critical", "high": "High", "medium": "Medium",
               "low": "Low", "info": "Info"}
    converted = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        sev = sev_map.get(str(item.get("severity", "info")).lower(), "Info")
        cves_str = ", ".join(item.get("cve_ids", [])) if item.get("cve_ids") else ""
        detail_parts = []
        if item.get("description"):
            detail_parts.append(item["description"])
        if cves_str:
            detail_parts.append(f"CVEs: {cves_str}")
        if item.get("cvss"):
            detail_parts.append(f"CVSS: {item['cvss']}")
        if item.get("epss"):
            detail_parts.append(f"EPSS: {item['epss']:.4f}")
        if item.get("in_kev"):
            detail_parts.append("⚠ CISA KEV")
        if item.get("remediation"):
            detail_parts.append(f"\nRemediation: {item['remediation']}")
        converted.append({
            "sev":    sev,
            "tool":   "stiglitz",
            "title":  item.get("name", item.get("id", "Stiglitz Finding")),
            "target": item.get("url", ""),
            "type":   "stiglitz",
            "detail": "\n".join(detail_parts),
            "count":  1,
            "endpoints": [item.get("url", "")] if item.get("url") else [],
            "source": item.get("source", "Stiglitz"),
        })
    return converted


def generate_report(
    outdir: str, target: str, profile: str,
    total: int, success: int, failed: int, version: str,
    scan_dir: str = ""
) -> str:
    now = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    data = collect_and_consolidate(outdir)

    pocs = collect_pocs(outdir)
    if pocs:
        generate_verify_script(outdir, pocs, target)

    findings      = data["findings"]
    sqli_results  = data["sqli_results"]
    xss_results   = data["xss_results"]
    msf_log       = data["msf_log"]
    hydra_results = data["hydra_results"]
    nikto_findings= data["nikto_findings"]
    cves          = data["cves"]
    services      = data["services"]
    log_content   = data["log_content"]
    zap_hc        = data["zap_hc"]
    ssd           = data["searchsploit"]
    subdomains    = data["subdomains"]

    # Merge Stiglitz findings when scan directory is provided
    scan_findings = []
    if scan_dir and os.path.isdir(scan_dir):
        scan_findings = _load_scan_findings(scan_dir)
        # Append after RED findings so they render in their own block
        findings = findings + scan_findings

    st = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for f in findings:
        if f["sev"] in st: st[f["sev"]] += 1
    tf = sum(st.values())
    rs = min(100, st["Critical"] * 30 + st["High"] * 15 + st["Medium"] * 5 + st["Low"])

    if rs >= 70:   rl_, rc_ = "CRITICAL", "#7a2e2e"
    elif rs >= 40: rl_, rc_ = "HIGH",    "#b34e4e"
    elif rs >= 15: rl_, rc_ = "MEDIUM",  "#d4833a"
    else:          rl_, rc_ = "LOW",     "#4a7c8c"

    pl = {"staging": "Staging/QA", "lab": "Lab", "production": "Production"}
    sqli_vc       = len([r for r in sqli_results if r["vulnerable"]])
    xss_vc        = len([f for f in findings if f.get("type") == "xss"])
    msf_sess      = msf_log.lower().count("session") if msf_log else 0
    total_endpoints = sum(f.get("count", 1) for f in findings)

    # Detect mode from existence of recon dir
    mode = "BLACKBOX" if os.path.isdir(f"{outdir}/recon") and subdomains else "Stiglitz"

    html = _build_html(
        target=target, profile=profile, version=version, now=now, mode=mode,
        total=total, success=success, st=st, tf=tf, rs=rs, rl_=rl_, rc_=rc_,
        pl=pl, sqli_vc=sqli_vc, xss_vc=xss_vc, msf_sess=msf_sess,
        total_endpoints=total_endpoints,
        findings=findings, scan_findings=scan_findings,
        sqli_results=sqli_results, xss_results=xss_results,
        msf_log=msf_log, hydra_results=hydra_results, nikto_findings=nikto_findings,
        cves=cves, services=services, log_content=log_content,
        zap_hc=zap_hc, ssd=ssd, outdir=outdir, pocs=pocs, subdomains=subdomains,
    )

    report_path = f"{outdir}/stiglitz_red_report.html"
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(html)
    return report_path


def _build_html(**k) -> str:
    CSS = """
body{font-family:'Segoe UI',Arial,sans-serif;margin:0;padding:20px;background:#f0f2f5}
.ctn{max-width:1200px;margin:0 auto;background:#fff;border-radius:10px;overflow:hidden;box-shadow:0 2px 10px rgba(0,0,0,.1)}
.hdr{background:#1a3a4f;color:#fff;padding:40px 30px;text-align:center}
.hdr h1{margin:0 0 5px;font-size:1.6em;letter-spacing:2px;text-transform:uppercase}
.hdr .sub{font-size:1.1em;opacity:.9;margin:5px 0}.hdr .meta{font-size:.85em;opacity:.7}
.hdr .cls{display:inline-block;border:2px solid #e74c3c;color:#e74c3c;padding:4px 16px;border-radius:4px;font-weight:700;font-size:.8em;margin-top:12px;letter-spacing:1px}
.cnt{padding:30px}
h2{color:#1a3a4f;border-bottom:2px solid #e0e0e0;padding-bottom:8px;margin-top:30px}
h3{color:#2c3e50;margin-top:20px}
.sts{display:flex;gap:12px;margin:20px 0;flex-wrap:wrap}
.sc{flex:1;padding:18px;text-align:center;color:#fff;border-radius:8px;min-width:85px}
.sc .n{font-size:32px;font-weight:bold}.sc .l{font-size:.75em;text-transform:uppercase;letter-spacing:.5px;opacity:.9}
.s-cr{background:#7a2e2e}.s-hi{background:#b34e4e}.s-me{background:#d4833a}.s-lo{background:#4a7c8c}.s-in{background:#6e8f72}.s-te{background:#2c3e50}
.ib{background:#e8f4f8;padding:15px 20px;border-radius:8px;margin:15px 0;border-left:4px solid #1a3a4f}
.ib.n{border-left-color:#2c3e50;background:#f9f9f9}.ib.g{border-left-color:#27ae60;background:#f0faf4}
table{width:100%;border-collapse:collapse;margin:10px 0}
th,td{border:1px solid #ddd;padding:10px;text-align:left;vertical-align:top}
th{background:#f5f5f5;font-weight:600;font-size:.85em}
.fd{border:1px solid #ddd;margin:18px 0;padding:20px;border-radius:8px;background:#fafafa}
.fd.Critical{border-left:10px solid #7a2e2e}.fd.High{border-left:10px solid #b34e4e}
.fd.Medium{border-left:10px solid #d4833a}.fd.Low{border-left:10px solid #4a7c8c}
.fd h3{margin-top:0}
.sb{display:inline-block;padding:3px 10px;border-radius:4px;font-size:.75em;font-weight:700;color:#fff}
.sb-cr{background:#7a2e2e}.sb-hi{background:#b34e4e}.sb-me{background:#d4833a}.sb-lo{background:#4a7c8c}.sb-in{background:#6e8f72}
.tb{display:inline-block;padding:2px 8px;border-radius:4px;font-size:.7em;font-weight:700;margin-left:6px;color:#fff}
.t-sq{background:#e67e22}.t-ms{background:#2980b9}.t-hy{background:#8e44ad}.t-nk{background:#27ae60}.t-df{background:#c0392b}.t-sw{background:#1a3a4f}
.ev{background:#2d3436;color:#dfe6e9;padding:14px;border-radius:6px;font-family:'Cascadia Code',monospace;font-size:.82em;overflow-x:auto;white-space:pre-wrap;word-break:break-all;max-height:400px;margin:8px 0;line-height:1.5}
.rb{background:#e0e0e0;border-radius:4px;height:14px;margin:8px 0}.ri{height:14px;border-radius:4px}
code{background:#f4f4f4;padding:1px 4px;border-radius:3px;font-size:.85em}
.ft{background:#f5f5f5;padding:20px;text-align:center;font-size:.8em;color:#666}
.toc{background:#f8f9fa;padding:15px 20px;border-radius:8px;margin:15px 0}.toc a{color:#1a3a4f;text-decoration:none}.toc a:hover{text-decoration:underline}.toc li{margin:4px 0}
.pt{display:inline-block;background:#1a3a4f;color:#fff;padding:2px 8px;border-radius:3px;font-size:.7em;margin-right:6px}
.tl{border-left:3px solid #1a3a4f;margin:15px 0;padding:0}
.ti{padding:10px 20px;position:relative;margin-left:15px}
.ti::before{content:'';position:absolute;left:-24px;top:15px;width:12px;height:12px;border-radius:50%;background:#1a3a4f}
.ti.ok::before{background:#27ae60}.ti.no::before{background:#95a5a6}
.cnt-badge{background:#555;color:#fff;padding:2px 10px;border-radius:10px;font-size:.7em;font-weight:700}
.ep-list{background:#f8f9fa;border:1px solid #e0e0e0;border-radius:6px;padding:10px 14px;margin:8px 0;font-size:.85em;max-height:200px;overflow-y:auto}
.ep-list li{margin:2px 0;font-family:monospace;font-size:.9em}
.mode-badge{display:inline-block;background:#27ae60;color:#fff;padding:3px 12px;border-radius:4px;font-size:.75em;font-weight:700;margin-left:10px}
"""
    h = f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Stiglitz RED — {esc(k['target'])}</title><style>{CSS}</style></head>
<body><div class="ctn">
<div class="hdr">
<h1>Stiglitz RED — Red Team Engagement Report
<span class="mode-badge">{k['mode']}</span></h1>
<div class="sub">{esc(k['target'])}</div>
<div class="meta">Date: {k['now']} | Profile: {k['profile'].upper()} ({k['pl'].get(k['profile'],k['profile'])}) | v{k['version']}</div>
<div class="cls">CONFIDENTIAL — RED TEAM — RESTRICTED DISTRIBUTION</div></div>
<div class="cnt">
<div class="toc"><strong>Contents</strong><ol>
<li><a href="#s1">Executive Summary</a></li><li><a href="#s2">Scope &amp; Methodology</a></li>
<li><a href="#s3">Attack Surface</a></li><li><a href="#s4">Attack Narrative</a></li>
<li><a href="#s5">Findings &amp; Vulnerabilities</a></li><li><a href="#s6">Recommendations</a></li>
<li><a href="#s7">Conclusion</a></li><li><a href="#s8">Proofs of Concept (PoC)</a></li>
<li><a href="#s9">Appendices</a></li></ol></div>"""

    h += _section_exec_summary(**k)
    h += _section_scope(**k)
    h += _section_surface(**k)
    h += _section_narrative(**k)
    h += _section_findings(**k)
    h += _section_recommendations(**k)
    h += _section_conclusion(**k)
    h += _section_poc(**k)
    h += _section_appendix(**k)

    h += f'</div><div class="ft">Stiglitz RED v{k["version"]} — Red Team Report | {k["now"]} | <strong>CONFIDENTIAL</strong></div></div></body></html>'
    return h


def _section_exec_summary(**k) -> str:
    h = f"""<h2 id="s1">1. Executive Summary</h2>
<div class="sts">
<div class="sc s-te"><div class="n">{k['total']}</div><div class="l">Tests</div></div>
<div class="sc s-cr"><div class="n">{k['st']['Critical']}</div><div class="l">Critical</div></div>
<div class="sc s-hi"><div class="n">{k['st']['High']}</div><div class="l">High</div></div>
<div class="sc s-me"><div class="n">{k['st']['Medium']}</div><div class="l">Medium</div></div>
<div class="sc s-lo"><div class="n">{k['st']['Low']}</div><div class="l">Low</div></div>
<div class="sc s-in"><div class="n">{k['st']['Info']}</div><div class="l">Info</div></div></div>
<div class="ib"><p><strong>Risk:</strong> {k['rs']}/100 — <span style="color:{k['rc_']};font-weight:bold">{k['rl_']}</span></p>
<div class="rb"><div class="ri" style="background:{k['rc_']};width:{k['rs']}%"></div></div></div>
<div class="ib n">
<p>Stiglitz RED ran a Red Team engagement against <strong>{esc(k['target'])}</strong>
(mode: {k['mode']}, profile: {k['pl'].get(k['profile'], k['profile'])}), running {k['total']} test(s).</p>"""
    if k['success'] > 0:
        h += f'\n<p><strong style="color:#7a2e2e">Confirmed {k["success"]} exploit(s)</strong> affecting {k["total_endpoints"]} endpoint(s).</p>'
    else:
        h += '\n<p>No exploits confirmed. Controls withstood the applied techniques.</p>'
    if k['findings']:
        parts = []
        if k['st']['Critical']: parts.append(f'{k["st"]["Critical"]} critical')
        if k['st']['High']:     parts.append(f'{k["st"]["High"]} high')
        if k['st']['Medium']:   parts.append(f'{k["st"]["Medium"]} medium')
        h += f'\n<p><strong>{k["tf"]} finding(s):</strong> {", ".join(parts) or "none"}.</p>'
    h += '\n<p>Recommendations in section 6.</p></div>\n'
    return h


def _section_scope(**k) -> str:
    mode = k.get("mode", "Stiglitz")
    approach = "Black-box — no prior knowledge of the target" if mode == "BLACKBOX" else "Grey-box — data from the Stiglitz scan"
    h = f'''<h2 id="s2">2. Scope &amp; Methodology</h2>
<div class="ib"><p><strong>Target:</strong> <code>{esc(k['target'])}</code> | <strong>Approach:</strong> {approach} | <strong>Methodology:</strong> PTES + OWASP Testing Guide + MITRE ATT&CK</p></div>
<table><tr><th>Tool</th><th>MITRE Tactic</th><th>Purpose</th></tr>
<tr><td><strong>subfinder + httpx</strong></td><td><span class="pt">T1590</span></td><td>Reconnaissance — subdomain and surface discovery</td></tr>
<tr><td><strong>nmap</strong></td><td><span class="pt">T1046</span></td><td>Network and service mapping</td></tr>
<tr><td><strong>katana + ffuf</strong></td><td><span class="pt">T1083</span></td><td>Endpoint crawling and fuzzing</td></tr>
<tr><td><strong>sqlmap</strong></td><td><span class="pt">T1190</span></td><td>SQL Injection — crawl, forms, parameters</td></tr>
<tr><td><strong>dalfox</strong></td><td><span class="pt">T1059.007</span></td><td>Cross-Site Scripting (XSS) — reflected, stored, DOM</td></tr>
<tr><td><strong>Hydra</strong></td><td><span class="pt">T1110</span></td><td>Brute force — SSH, FTP, MySQL, PostgreSQL, HTTP</td></tr>
<tr><td><strong>Metasploit</strong></td><td><span class="pt">T1210</span></td><td>Exploitation of confirmed CVEs</td></tr>
<tr><td><strong>Nikto</strong></td><td><span class="pt">T1046</span></td><td>Web misconfigurations and default files</td></tr>
<tr><td><strong>SearchSploit</strong></td><td><span class="pt">T1588.005</span></td><td>Public exploits for CVEs</td></tr></table>'''
    return h


def _section_surface(**k) -> str:
    h = '<h2 id="s3">3. Attack Surface</h2>\n'

    # Subdomains (blackbox recon)
    if k.get("subdomains"):
        h += f'<h3>Discovered Subdomains ({len(k["subdomains"])})</h3>\n'
        h += '<div class="ep-list"><ul>\n'
        for s in k["subdomains"][:50]:
            h += f'<li>{esc(s)}</li>\n'
        if len(k["subdomains"]) > 50:
            h += f'<li><em>... and {len(k["subdomains"]) - 50} more</em></li>\n'
        h += '</ul></div>\n'

    # Services
    if k["services"]:
        h += '<h3>Open Services</h3>\n'
        h += '<table><tr><th>Port</th><th>Service</th><th>Version</th></tr>\n'
        for s in k["services"]:
            p = s.split()
            h += f'<tr><td><code>{esc(p[0] if p else "?")}</code></td><td>{esc(p[1] if len(p)>1 else "?")}</td><td>{esc(" ".join(p[2:]) if len(p)>2 else "")}</td></tr>\n'
        h += '</table>\n'

    # CVEs
    if k["cves"]:
        h += f'<h3>Identified CVEs ({len(k["cves"])})</h3>\n'
        h += '<table><tr><th>CVE</th><th>Public Exploits</th></tr>\n'
        for cv in k["cves"]:
            ex = k["ssd"].get(cv, [])
            if ex:
                h += f'<tr><td><strong style="color:#7a2e2e">{esc(cv)}</strong></td><td>{", ".join(esc(e.get("Title","")[:50]) for e in ex[:3])}</td></tr>\n'
            else:
                h += f'<tr><td><code>{esc(cv)}</code></td><td style="color:#999">—</td></tr>\n'
        h += '</table>\n'

    if not k["services"] and not k["cves"] and not k.get("subdomains"):
        h += '<div class="ib n"><p>No surface data collected.</p></div>\n'

    return h


def _section_narrative(**k) -> str:
    mode = k.get("mode", "Stiglitz")
    h = '<h2 id="s4">4. Attack Narrative</h2><div class="tl">\n'

    if mode == "BLACKBOX":
        n_subs = len(k.get("subdomains", []))
        h += f'<div class="ti {"ok" if n_subs>1 else "no"}"><strong>Phase 1 — Reconnaissance</strong><br>'
        h += f'{n_subs} subdomain(s) discovered.</div>\n'
    else:
        h += f'<div class="ti ok"><strong>Phase 1 — Stiglitz Ingestion</strong><br>{len(k["services"])} service(s), {len(k["cves"])} CVE(s).</div>\n'

    h += f'<div class="ti {"ok" if k["sqli_vc"]>0 else "no"}"><strong>Phase SQLi (sqlmap)</strong><br>'
    if k["sqli_vc"] > 0: h += f'{k["sqli_vc"]} vulnerable endpoint(s).'
    elif k["sqli_results"]: h += f'{len(k["sqli_results"])} tested — none vulnerable.'
    else: h += 'Discovery mode.'
    h += '</div>\n'

    h += f'<div class="ti {"ok" if k["xss_vc"]>0 else "no"}"><strong>Phase XSS (dalfox)</strong><br>'
    if k["xss_vc"] > 0: h += f'{k["xss_vc"]} XSS confirmed.'
    elif k.get("xss_results"): h += f'{len(k["xss_results"])} tested — none vulnerable.'
    else: h += 'Not run or no results.'
    h += '</div>\n'

    h += f'<div class="ti {"ok" if k["msf_sess"]>0 else "no"}"><strong>Phase Metasploit</strong><br>'
    if k["msf_sess"] > 0: h += f'{k["msf_sess"]} session(s) opened.'
    elif k["msf_log"]: h += 'Modules executed.'
    else: h += 'Not run.'
    h += '</div>\n'

    h += f'<div class="ti {"ok" if k["hydra_results"] else "no"}"><strong>Phase Brute Force (Hydra)</strong><br>'
    if k["hydra_results"]: h += f'Credentials on {len(k["hydra_results"])} service(s).'
    else: h += 'No weak credentials identified.'
    h += '</div>\n'

    h += f'<div class="ti {"ok" if k["nikto_findings"] else "no"}"><strong>Phase Web (Nikto)</strong><br>'
    if k["nikto_findings"]: h += f'{len(k["nikto_findings"])} misconfiguration finding(s).'
    else: h += 'No misconfiguration findings.'
    h += '</div>\n'

    h += f'<div class="ti ok"><strong>Consolidation</strong><br>{len(k["cves"])} CVE(s), {len(k["ssd"])} with public exploit(s).</div>\n</div>\n'
    return h


def _render_finding_card(i: int, f: dict, prefix: str = "RED") -> str:
    sv, tl = f["sev"], f["tool"]
    tc = {"sqlmap": "t-sq", "metasploit": "t-ms", "hydra": "t-hy",
          "nikto": "t-nk", "dalfox": "t-df", "stiglitz": "t-sw"}.get(tl, "t-sq")
    sc = {"Critical": "sb-cr", "High": "sb-hi", "Medium": "sb-me", "Low": "sb-lo"}.get(sv, "sb-in")
    cnt = f.get("count", 1)
    cnt_html = f' <span class="cnt-badge">{cnt} endpoint{"s" if cnt>1 else ""}</span>' if cnt > 1 else ""

    mitre = {
        "sqli":        "T1190 — Exploit Public-Facing Application",
        "xss":         "T1059.007 — JavaScript Execution",
        "bruteforce":  "T1110 — Brute Force",
        "exploit":     "T1210 — Exploitation of Remote Services",
        "stiglitz":    "T1046/T1190 — Recon + Vulnerability Scan",
    }
    impact = {
        "sqli":       "Read, modify or delete data. Possible escalation to RCE.",
        "xss":        "Session theft, defacement, phishing, data exfiltration via JS.",
        "bruteforce": "Unauthorized access. Possible lateral movement.",
        "exploit":    "Remote code execution or privileged access.",
        "stiglitz":   "Identified by the automated Stiglitz scan — requires analysis and remediation.",
    }

    source_label = esc(f.get("source", tl) if tl == "stiglitz" else tl)
    h  = f'<div class="fd {sv}"><h3>{prefix}-{i:03d}: {esc(f["title"])}{cnt_html} <span class="sb {sc}">{sv.upper()}</span> <span class="tb {tc}">{source_label}</span></h3>\n'
    h += f'<table><tr><th style="width:130px">Target</th><td><code>{esc(f["target"][:200])}</code></td></tr>\n'
    h += f'<tr><th>MITRE ATT&CK</th><td>{mitre.get(f.get("type",""), "T1210")}</td></tr>\n'
    h += f'<tr><th>Impact</th><td>{impact.get(f.get("type",""), "System compromise")}</td></tr>\n'
    if f.get("cvss_vector"):
        _src = f.get("score_source", "")
        _est = " <em>(estimado)</em>" if _src == "estimated" else ""
        h += (f'<tr><th>CVSS</th><td><code>{esc(f["cvss_vector"])}</code> '
              f'— <strong>{f.get("cvss_environmental", "")}</strong> '
              f'[{esc(f.get("asset_class", ""))} · {esc(_src)}]{_est}</td></tr>\n')
    h += '</table>\n'

    eps = f.get("endpoints", [])
    if eps and len(eps) > 1:
        h += f'<p><strong>Affected endpoints ({len(eps)}):</strong></p>\n<div class="ep-list"><ol>\n'
        for ep in eps[:30]: h += f'<li>{esc(ep)}</li>\n'
        if len(eps) > 30: h += f'<li><em>... and {len(eps)-30} more</em></li>\n'
        h += '</ol></div>\n'

    det = f.get("detail", "")
    if det and det.strip():
        h += f'<p><strong>Technical evidence:</strong></p>\n<div class="ev">{esc(det)}</div>\n'
    h += '</div>\n'
    return h


def _section_findings(**k) -> str:
    all_findings    = k["findings"]
    scan_findings   = k.get("scan_findings", [])
    # RED findings are those that are NOT from the merged Stiglitz list
    red_findings    = [f for f in all_findings if f not in scan_findings]

    h = '<h2 id="s5">5. Findings &amp; Vulnerabilities</h2>\n'
    if not all_findings:
        return h + '<div class="ib g"><p><strong>No exploits confirmed.</strong></p></div>\n'

    total_ep = sum(f.get("count", 1) for f in all_findings)
    h += f'<div class="ib"><p><strong>{len(all_findings)} finding(s)</strong> representing {total_ep} endpoint(s).</p></div>\n'

    # ── RED findings ──
    if red_findings:
        h += f'<h3>Red Team — Active Exploitation ({len(red_findings)})</h3>\n'
        for i, f in enumerate(red_findings, 1):
            h += _render_finding_card(i, f, prefix="RED")
    else:
        h += '<div class="ib g"><p>No exploits confirmed by the Red Team in this phase.</p></div>\n'

    # ── Stiglitz findings ──
    if scan_findings:
        h += f'<h3>Stiglitz Context — Source Scan ({len(scan_findings)})</h3>\n'
        h += '<div class="ib n"><p>Vulnerabilities identified by the Stiglitz scan preceding this engagement. '
        h += 'Included for context and remediation prioritization.</p></div>\n'
        for i, f in enumerate(scan_findings, 1):
            h += _render_finding_card(i, f, prefix="STG")

    # ── Nikto ──
    if k["nikto_findings"]:
        h += '<h3>Nikto — Misconfigurations</h3><table><tr><th>Severity</th><th>Finding</th><th>URL</th></tr>\n'
        for nf in k["nikto_findings"][:30]:
            if isinstance(nf, dict):
                sev_c = {"HIGH": "#7a2e2e", "MEDIUM": "#d4833a", "INFO": "#6e8f72"}.get(
                    nf.get("sev", "INFO"), "#6e8f72")
                h += f'<tr><td><strong style="color:{sev_c}">{esc(nf.get("sev","INFO"))}</strong></td>'
                h += f'<td>{esc(nf.get("msg",""))}</td><td><code>{esc(nf.get("url",""))}</code></td></tr>\n'
        h += '</table>\n'

    # ── MSF log ──
    if k["msf_log"]:
        h += '<h3>Metasploit Log</h3>\n<div class="ev">' + esc(k["msf_log"][-2000:]) + '</div>\n'

    # ── ZAP ──
    zap_hi = [z for z in k["zap_hc"] if z.get("risk") in ("Critical","High")]
    zap_show = zap_hi or [z for z in k["zap_hc"] if z.get("risk") == "Medium"]
    if zap_show:
        title = "OWASP ZAP — High/Critical" if zap_hi else "OWASP ZAP — Medium"
        h += f'<h3>{title}</h3><table><tr><th>Risk</th><th>Alert</th><th>URL</th></tr>\n'
        for z in zap_show:
            c = {"Critical": "#7a2e2e", "High": "#b34e4e", "Medium": "#d4833a"}.get(z.get("risk",""), "#555")
            h += f'<tr><td><strong style="color:{c}">{esc(z["risk"])}</strong></td><td>{esc(z["alert"])}</td><td><code>{esc(z["url"][:80])}</code></td></tr>\n'
        h += '</table>\n'

    return h


def _section_recommendations(**k) -> str:
    h = '<h2 id="s6">6. Recommendations</h2>\n'
    obs = []

    if k["sqli_vc"] > 0:
        obs.append(("SQL Injection", "Endpoints accept unsanitized input.",
            "1. Prepared statements in ALL queries\n2. WAF with SQLi rules\n3. Input validation (whitelist)\n4. Least privilege on the database\n5. Urgent code review", "Immediate (0-7 days)"))

    if k["xss_vc"] > 0:
        obs.append(("Cross-Site Scripting (XSS)", "Parameters reflect input without sanitization.",
            "1. Output encoding in ALL contexts (HTML, JS, URL, CSS)\n2. Restrictive Content Security Policy (CSP)\n3. HttpOnly + Secure on session cookies\n4. X-XSS-Protection: 1; mode=block\n5. DOMPurify for client-side sanitization", "Immediate (0-7 days)"))

    if k["hydra_results"]:
        obs.append(("Weak Credentials", "Default or weak passwords accepted.",
            "1. Rotate ALL default passwords immediately\n2. Min 14 chars, complexity, 90d rotation\n3. MFA on ALL exposed services\n4. Account lockout (5 attempts)\n5. SIEM monitoring for brute force", "Immediate (0-7 days)"))

    if k["msf_sess"] > 0:
        obs.append(("Confirmed Remote Exploitation", "Known exploits worked.",
            "1. Emergency patch management\n2. Network segmentation (micro-segmentation)\n3. EDR/XDR on all endpoints\n4. Hardening of exposed services\n5. Immediate incident response", "Immediate (0-3 days)"))

    if k["cves"]:
        obs.append(("CVEs with Public Exploits", f"{len(k['cves'])} CVE(s), {len(k['ssd'])} with exploits.",
            "1. Prioritized patching (CISA KEV first)\n2. Continuous vulnerability management\n3. Compensating controls until patch is applied\n4. Virtual patching via WAF", "Short term (0-30 days)"))

    if not obs:
        obs.append(("Posture Maintenance", "Current controls held.",
            "1. Continuous patching\n2. Quarterly red team\n3. Expand test scope\n4. Bug bounty program", "Continuous"))

    for title, detail, rec, prazo in obs:
        h += f'<div class="fd Medium"><h3>{esc(title)}</h3><table>\n'
        h += f'<tr><th style="width:130px">Observation</th><td>{esc(detail)}</td></tr>\n'
        h += f'<tr><th>Actions</th><td><pre style="margin:0;background:transparent;border:none;font-size:.9em">{esc(rec)}</pre></td></tr>\n'
        h += f'<tr><th>Timeframe</th><td><strong>{esc(prazo)}</strong></td></tr></table></div>\n'
    return h


def _section_conclusion(**k) -> str:
    h = '<h2 id="s7">7. Conclusion</h2><div class="ib n">\n'
    if k["success"] > 0:
        h += f'<p><strong style="color:#7a2e2e">Confirmed {k["success"]} exploit(s)</strong> against {esc(k["target"])}, affecting {k["total_endpoints"]} endpoint(s). Immediate remediation recommended.</p>'
    else:
        h += f'<p>The controls of {esc(k["target"])} withstood {k["total"]} test(s) in {k["mode"]} mode. Expand scope in future engagements.</p>'
    return h + '</div>\n'


def _section_poc(**k) -> str:
    pocs = k.get("pocs", [])
    h = '<h2 id="s8">8. Proofs of Concept (PoC)</h2>\n'

    has_verify = os.path.exists(f"{k['outdir']}/poc/verify.sh")
    if has_verify:
        h += ('<div class="ib g"><p><strong>Verification script:</strong> '
              '<code>poc/verify.sh</code> — run before and after remediation.</p>'
              '<pre style="background:#1e1e1e;color:#d4d4d4;padding:10px;border-radius:6px;'
              'font-size:.85em;margin:8px 0">bash poc/verify.sh</pre></div>\n')

    if not pocs:
        h += '<div class="ib n"><p>No vulnerabilities confirmed via PoC.</p></div>\n'
        return h

    h += f'<div class="ib"><p>{len(pocs)} proof(s) of concept generated.</p></div>\n'

    for poc in pocs:
        color_map = {"sqli_time": "#7a2e2e", "sqli_bool": "#7a2e2e", "cors": "#b34e4e", "header_missing": "#4a7c8c"}
        border = color_map.get(poc["type"], "#d4833a")
        h += (f'<div class="fd" style="border-left:8px solid {border};margin:18px 0;padding:20px;border-radius:8px;background:#fafafa">\n'
              f'<h3 style="margin-top:0">{esc(poc["id"])}: {esc(poc["title"])}</h3>\n')
        if poc.get("sqlmap_title"):
            h += f'<p><strong>Technique:</strong> <code>{esc(poc["sqlmap_title"])}</code></p>\n'
        h += f'<p><strong>Target:</strong> <code>{esc(poc["url"])}</code></p>\n'
        h += '<p><strong>How to reproduce:</strong></p>\n'
        h += f'<div class="ev">{esc(poc["curl"])}</div>\n'
        if poc.get("remediation"):
            h += (f'<details style="margin-top:12px"><summary style="cursor:pointer;font-weight:600">Remediation</summary>'
                  f'<pre style="background:#f4f4f4;padding:10px;border-radius:4px;font-size:.85em">{esc(poc["remediation"])}</pre></details>\n')
        h += '</div>\n'

    return h


def _section_appendix(**k) -> str:
    h = '<h2 id="s9">9. Appendices</h2>\n<h3>A. Activity Log</h3>\n'
    h += '<div class="ev">' + esc(k["log_content"]) + '</div>\n'
    h += '<h3>B. Artifacts</h3><table><tr><th>File</th><th>Description</th></tr>\n'
    artifacts = [
        ("exploits_confirmed.csv", "Confirmed exploits"),
        ("data/cves_found.txt", "Identified CVEs"),
        ("data/open_services.txt", "Open services"),
        ("recon/subdomains.txt", "Subdomains (recon)"),
        ("crawl/katana_urls.txt", "URLs (katana)"),
        ("stiglitz_red.log", "Activity log"),
        ("sqlmap/", "sqlmap results"),
        ("xss/xss_confirmed.txt", "Confirmed XSS"),
        ("poc/verify.sh", "PoC verification script"),
        ("metasploit/stiglitz_red.rc", "Metasploit RC"),
        ("hydra/", "Brute force"),
        ("nikto/nikto_report.json", "Nikto"),
        ("searchsploit/", "SearchSploit"),
    ]
    for fn, ds in artifacts:
        ex = "✓" if os.path.exists(f"{k['outdir']}/{fn}") else "—"
        h += f'<tr><td><code>{ex} {esc(fn)}</code></td><td>{esc(ds)}</td></tr>\n'
    h += '</table>\n'
    return h


if __name__ == "__main__":
    if len(sys.argv) < 8:
        print(__doc__)
        sys.exit(1)

    # Parse optional --scan-dir <path>
    args = sys.argv[8:]
    scan_dir_arg = ""
    i = 0
    while i < len(args):
        if args[i] == "--scan-dir" and i + 1 < len(args):
            scan_dir_arg = args[i + 1]
            i += 2
        else:
            i += 1

    path = generate_report(
        outdir=sys.argv[1], target=sys.argv[2], profile=sys.argv[3],
        total=int(sys.argv[4]), success=int(sys.argv[5]),
        failed=int(sys.argv[6]), version=sys.argv[7],
        scan_dir=scan_dir_arg,
    )
    print(f"REPORT_OK:{path}")

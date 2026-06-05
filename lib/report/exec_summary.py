#!/usr/bin/env python3
"""
exec_summary.py — Geração do executive_summary.html.

Pure function: recebe os componentes já computados (risk score, stats,
top findings, KEV matches, etc.) e devolve a string HTML. Sem IO.
"""
import html


def build_exec_summary(
    *,
    target,
    domain,
    risk,
    risk_label,                # ex.: "CRITICAL — Immediate Action"
    timestamp,                 # já formatada
    stats,                     # {"critical": N, "high": N, ...}
    findings,                  # lista de findings (filtra top critical/high)
    kev_matches=None,          # dict CVE→info ou None
    phase_times=None,          # dict {"P1": seconds, ...} ou None
):
    """Constrói o HTML do executive summary.

    Args: ver assinatura. Todos os valores devem estar prontos —
    a função não calcula, apenas renderiza.

    Returns:
        str: HTML completo do executive_summary.html.
    """
    kev_matches = kev_matches or {}
    phase_times = phase_times or {}

    rc = ("#7a2e2e" if risk >= 70
          else "#b34e4e" if risk >= 40
          else "#d4833a" if risk >= 15
          else "#27ae60")
    kev_count = len(kev_matches)
    kev_str = ", ".join(list(kev_matches.keys())[:5]) if kev_matches else "None"

    # Top findings table (critical + high, primeiros 8)
    sev_bg = {"critical": "#7a2e2e", "high": "#b34e4e"}
    sev_lb = {"critical": "CRITICAL", "high": "HIGH"}
    top_f = [f for f in findings if f.get("severity") in ("critical", "high")][:8]
    top_rows = ""
    for f in top_f:
        sc = sev_bg.get(f.get("severity", ""), "#888")
        sl = sev_lb.get(f.get("severity", ""), "?")
        name = html.escape(f.get("name", ""))
        impact = html.escape(f.get("impact", "") or "See technical report")
        rem = html.escape((f.get("remediation", "") or "")[:60])
        top_rows += (f'<tr><td><span style="background:{sc};color:white;padding:2px 8px;'
                     f'border-radius:4px;font-size:11px">{sl}</span></td>'
                     f'<td style="font-weight:600">{name}</td>'
                     f'<td style="color:#555;font-size:12px">{impact}</td>'
                     f'<td style="font-size:11px">{rem}</td></tr>')
    if not top_rows:
        top_rows = ('<tr><td colspan="4" style="text-align:center;color:#888">'
                    'No critical or high findings</td></tr>')

    # Phase timing
    phase_map = {"P1": "Discovery", "P2": "Surface", "P3": "TLS", "P4": "Nuclei",
                 "P5": "Confirmation", "P6": "CVE/EPSS", "P7": "WAF", "P8": "Email",
                 "P9": "ZAP", "P10": "JS/Secrets", "P10_5": "Supplementary", "P11": "Report"}
    phase_rows = ""
    for pid, dur in phase_times.items():
        pname = phase_map.get(pid, pid)
        phase_rows += f'<tr><td>{pname}</td><td>{int(dur)//60}m {int(dur)%60:02d}s</td></tr>'
    phase_section = ""
    if phase_rows:
        phase_section = (f'<h2>Time per Phase</h2>'
                         f'<table><tr><th>Phase</th><th>Duration</th></tr>'
                         f'{phase_rows}</table>')

    # Recommendations
    recs = []
    if kev_count > 0:
        recs.append(f"<li><strong>URGENT:</strong> Remediate {kev_count} CVE(s) "
                    f"under active exploitation: {html.escape(kev_str)}</li>")
    if stats.get("critical", 0) > 0:
        recs.append(f"<li>Fix {stats['critical']} critical finding(s) — immediate</li>")
    if stats.get("high", 0) > 0:
        recs.append(f"<li>Plan {stats['high']} high finding(s) — this sprint</li>")
    if stats.get("medium", 0) > 0:
        recs.append(f"<li>Schedule {stats['medium']} medium finding(s) — next sprint</li>")
    recs.append("<li>See the technical report for detailed evidence</li>")
    recs_html = "\n".join(recs)

    kev_alert = ""
    if kev_count > 0:
        kev_alert = (f'<p style="background:#fff0f0;padding:10px;border-radius:6px;'
                     f'border-left:4px solid #7a0000;font-size:12px">'
                     f'<strong>⚠ Active Exploitation (CISA KEV):</strong> '
                     f'{html.escape(kev_str)}</p>')

    kev_kpi = ""
    if kev_count > 0:
        kev_kpi = (f'<div class="kpi"><div class="n" style="color:#7a0000">{kev_count}</div>'
                   f'<div class="l">🔴 KEV</div></div>')

    target_esc = html.escape(target)
    domain_esc = html.escape(domain)
    label_esc  = html.escape(risk_label)

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<title>Executive Summary — {domain_esc}</title>
<style>
body{{font-family:"Segoe UI",sans-serif;max-width:850px;margin:0 auto;padding:30px;color:#333}}
h1{{color:#1a3a4f;font-size:22px;border-bottom:3px solid #1a3a4f;padding-bottom:8px}}
h2{{color:#1a3a4f;font-size:15px;margin-top:24px}}
.kpi{{display:inline-block;text-align:center;margin:0 10px;padding:10px 18px;background:#f5f5f5;border-radius:8px}}
.kpi .n{{font-size:26px;font-weight:bold}}
.kpi .l{{font-size:11px;color:#888}}
table{{width:100%;border-collapse:collapse;margin:8px 0}}
th{{background:#1a3a4f;color:white;padding:8px;text-align:left;font-size:12px}}
td{{border:1px solid #eee;padding:8px;font-size:12px}}
.footer{{color:#aaa;font-size:10px;text-align:center;margin-top:32px;border-top:1px solid #eee;padding-top:8px}}
@media print{{body{{padding:0}}}}
</style></head><body>
<div style="background:#1a3a4f;color:white;padding:18px;border-radius:8px;margin-bottom:20px">
<h1 style="color:white;border:none;margin:0 0 4px">Security Executive Summary</h1>
<p style="margin:0;opacity:.8;font-size:13px">{target_esc} &nbsp;·&nbsp; {timestamp} &nbsp;·&nbsp; CONFIDENTIAL</p>
</div>
<h2>Risk Score</h2>
<div style="margin:8px 0">
<span style="background:{rc};color:white;font-size:32px;font-weight:bold;padding:10px 22px;border-radius:6px">{risk}/100</span>
<span style="margin-left:14px;font-size:15px;font-weight:600;color:{rc}">{label_esc}</span>
</div>
<h2>Findings</h2>
<div style="margin:8px 0">
<div class="kpi"><div class="n" style="color:#7a2e2e">{stats.get("critical",0)}</div><div class="l">CRITICAL</div></div>
<div class="kpi"><div class="n" style="color:#b34e4e">{stats.get("high",0)}</div><div class="l">HIGH</div></div>
<div class="kpi"><div class="n" style="color:#d4833a">{stats.get("medium",0)}</div><div class="l">MEDIUM</div></div>
<div class="kpi"><div class="n" style="color:#4a7c8c">{stats.get("low",0)}</div><div class="l">LOW</div></div>
{kev_kpi}
</div>
{kev_alert}
<h2>Top Vulnerabilities</h2>
<table><tr><th>Severity</th><th>Vulnerability</th><th>Impact</th><th>Fix</th></tr>
{top_rows}
</table>
<h2>Recommendations</h2>
<ol style="font-size:13px;line-height:2">{recs_html}</ol>
{phase_section}
<div class="footer">Security Assessment · Restricted to authorized security teams · CONFIDENTIAL</div>
</body></html>"""

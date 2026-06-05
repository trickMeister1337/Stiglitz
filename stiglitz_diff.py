#!/usr/bin/env python3
"""
Stiglitz Diff — Comparação entre dois scans
Uso: python3 stiglitz_diff.py <scan_anterior/> <scan_novo/>
     python3 stiglitz_diff.py <scan_anterior/> <scan_novo/> --html

Identifica vulnerabilidades: novas, corrigidas e persistentes.
"""
import sys, json, os, re, html as _html
from datetime import datetime

RED   = "\033[0;31m"; GREEN  = "\033[0;32m"; YELLOW = "\033[1;33m"
CYAN  = "\033[0;36m"; BOLD   = "\033[1m";    NC     = "\033[0m"

def usage():
    print(f"\n  {BOLD}Stiglitz Diff — Comparação de Scans{NC}")
    print(f"  Uso: python3 stiglitz_diff.py <anterior/> <novo/> [--html]\n")
    sys.exit(1)

if len(sys.argv) < 3:
    usage()

DIR_OLD   = sys.argv[1].rstrip("/")
DIR_NEW   = sys.argv[2].rstrip("/")
HTML_OUT  = "--html" in sys.argv

for d in [DIR_OLD, DIR_NEW]:
    if not os.path.isdir(d):
        print(f"{RED}[✗] Diretório não encontrado: {d}{NC}")
        sys.exit(1)

# ── Carregar achados de um diretório ─────────────────────────────
def load_findings(scan_dir):
    findings = {}  # key = (name, severity) -> dict

    # Nuclei findings
    nuc_f = os.path.join(scan_dir, "raw", "nuclei.json")
    if os.path.exists(nuc_f):
        for line in open(nuc_f, encoding="utf-8", errors="replace"):
            line = line.strip()
            if not line: continue
            try:
                d = json.loads(line)
                name = d.get("info", {}).get("name", "")
                sev  = d.get("info", {}).get("severity", "info").lower()
                url  = d.get("matched-at", "")
                # Chave NÃO inclui severidade: ela pode mudar entre scans
                # (atualização de template) e geraria falso new/fixed do mesmo finding.
                key  = f"nuclei::{name}"
                if key not in findings:
                    findings[key] = {"name": name, "severity": sev,
                                     "source": "Nuclei", "urls": set()}
                findings[key]["urls"].add(url)
            except: pass

    # ZAP findings
    zap_f = os.path.join(scan_dir, "raw", "zap_alerts.json")
    if os.path.exists(zap_f):
        try:
            data = json.load(open(zap_f, encoding="utf-8", errors="replace"))
            sev_map = {"high":"high","medium":"medium","low":"low","informational":"info"}
            for a in data.get("alerts", []):
                name = a.get("name", "")
                sev  = sev_map.get(a.get("risk","").lower(), "info")
                url  = a.get("url", "")
                key  = f"zap::{name}"
                if key not in findings:
                    findings[key] = {"name": name, "severity": sev,
                                     "source": "ZAP", "urls": set()}
                findings[key]["urls"].add(url)
        except: pass

    # Convert url sets to lists
    for k in findings:
        findings[k]["urls"] = sorted(findings[k]["urls"])

    return findings

def load_risk(scan_dir):
    """Try to extract risk score and metadata from the HTML report."""
    rep = os.path.join(scan_dir, "stiglitz_report.html")
    if not os.path.exists(rep): return None, None
    content = open(rep, encoding="utf-8", errors="replace").read()
    # Suporta o rótulo atual ("Risk Score") e o antigo PT ("Índice de Risco")
    m = re.search(r'(?:Risk Score|Índice de Risco)[^0-9]*?(\d+)', content[:6000])
    score = int(m.group(1)) if m else None
    ts_m = re.search(r'(\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2})', content[:3000])
    ts = ts_m.group(1) if ts_m else "?"
    return score, ts

print(f"\n{CYAN}{BOLD}══════════════════════════════════════════════════════════════{NC}")
print(f"{CYAN}{BOLD}  Stiglitz DIFF — Análise Comparativa de Scans{NC}")
print(f"{CYAN}{BOLD}══════════════════════════════════════════════════════════════{NC}\n")

print(f"  {BOLD}Anterior:{NC} {DIR_OLD}")
print(f"  {BOLD}Novo:    {NC} {DIR_NEW}\n")

old_f = load_findings(DIR_OLD)
new_f = load_findings(DIR_NEW)

old_risk, old_ts = load_risk(DIR_OLD)
new_risk, new_ts = load_risk(DIR_NEW)

old_keys = set(old_f.keys())
new_keys = set(new_f.keys())

fixed    = old_keys - new_keys   # estava antes, não está mais → CORRIGIDO
appeared = new_keys - old_keys   # não estava antes, está agora → NOVO
persist  = old_keys & new_keys   # estava e continua → PERSISTENTE

sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
sev_color = {"critical": RED, "high": "\033[0;31m", "medium": YELLOW,
             "low": CYAN, "info": "\033[0;37m"}

def sev_label(s):
    return {"critical":"CRÍTICO","high":"ALTO","medium":"MÉDIO",
            "low":"BAIXO","info":"INFO"}.get(s, s.upper())

def print_group(label, color, keys, findings_dict):
    if not keys: return
    sorted_keys = sorted(keys, key=lambda k: sev_order.get(findings_dict[k]["severity"], 9))
    print(f"  {color}{BOLD}{label} ({len(keys)}){NC}")
    for k in sorted_keys:
        f = findings_dict[k]
        sc = sev_color.get(f["severity"], "")
        print(f"    {sc}[{sev_label(f['severity'])}]{NC}  {f['name']}  {CYAN}({f['source']}){NC}")
        for url in f["urls"][:3]:
            if url: print(f"          {url}")
        if len(f["urls"]) > 3:
            print(f"          ... e mais {len(f['urls'])-3} URL(s)")
    print()

# ── Risk score comparison ─────────────────────────────────────────
if old_risk is not None and new_risk is not None:
    delta = new_risk - old_risk
    delta_str = f"+{delta}" if delta > 0 else str(delta)
    delta_col = RED if delta > 0 else (GREEN if delta < 0 else NC)
    print(f"  {BOLD}Risk Score:{NC}  {old_risk} → {new_risk}  "
          f"{delta_col}({delta_str}){NC}\n")

# ── Summary ───────────────────────────────────────────────────────
print(f"  {GREEN}{BOLD}✓ Corrigidos    : {len(fixed)}{NC}")
print(f"  {RED}{BOLD}✗ Novos         : {len(appeared)}{NC}")
print(f"  {YELLOW}{BOLD}~ Persistentes  : {len(persist)}{NC}")
print()

print_group("✗ NOVOS — apareceram neste scan",     RED,    appeared, new_f)
print_group("✓ CORRIGIDOS — resolvidos desde antes", GREEN,  fixed,    old_f)
print_group("~ PERSISTENTES — ainda presentes",    YELLOW, persist,  new_f)

# ── HTML report ───────────────────────────────────────────────────
if HTML_OUT:
    def sev_badge(s):
        colors = {"critical":"#7a2e2e","high":"#b34e4e","medium":"#d4833a",
                  "low":"#4a7c8c","info":"#888"}
        c = colors.get(s,"#888")
        return (f'<span style="background:{c};color:white;padding:2px 8px;'
                f'border-radius:4px;font-size:11px;font-weight:bold">'
                f'{sev_label(s)}</span>')

    def build_rows(keys, fd, color, icon):
        if not keys: return f'<tr><td colspan="4" style="color:#888;text-align:center">Nenhum</td></tr>'
        rows = ""
        for k in sorted(keys, key=lambda k: sev_order.get(fd[k]["severity"],9)):
            f = fd[k]
            urls_html = "<br>".join(f'<code style="font-size:11px">{_html.escape(u)}</code>'
                                    for u in f["urls"][:5])
            if len(f["urls"]) > 5:
                urls_html += f'<br><span style="color:#888">... +{len(f["urls"])-5}</span>'
            rows += (f'<tr><td>{sev_badge(f["severity"])}</td>'
                     f'<td><strong>{_html.escape(f["name"])}</strong></td>'
                     f'<td style="font-size:12px;color:#666">{_html.escape(f["source"])}</td>'
                     f'<td style="font-size:11px">{urls_html}</td></tr>')
        return rows

    risk_html = ""
    if old_risk is not None and new_risk is not None:
        delta = new_risk - old_risk
        dc = "#b34e4e" if delta > 0 else ("#27ae60" if delta < 0 else "#888")
        risk_html = (f'<div style="background:#f5f5f5;padding:16px;border-radius:8px;margin:16px 0">'
                     f'<strong>Risk Score:</strong> {old_risk} → <strong>{new_risk}</strong> '
                     f'<span style="color:{dc};font-weight:bold">({("+" if delta>0 else "")}{delta})</span>'
                     f'</div>')

    page = f"""<!DOCTYPE html><html lang="pt-br"><head><meta charset="UTF-8">
<title>Stiglitz Diff — {_html.escape(os.path.basename(DIR_OLD))} vs {_html.escape(os.path.basename(DIR_NEW))}</title>
<style>
body{{font-family:'Segoe UI',sans-serif;margin:0;padding:20px;background:#f0f2f5}}
.container{{max-width:1100px;margin:0 auto;background:white;border-radius:12px;
  overflow:hidden;box-shadow:0 4px 20px rgba(0,0,0,.12)}}
.header{{background:linear-gradient(135deg,#1a3a4f,#0f2a3d);color:white;padding:30px;text-align:center}}
.header h1{{margin:0 0 8px;font-size:22px}}
.content{{padding:28px}}
h2{{color:#1a3a4f;border-bottom:3px solid #e0e0e0;padding-bottom:8px}}
table{{width:100%;border-collapse:collapse;margin:8px 0 20px}}
th{{background:#1a3a4f;color:white;padding:10px;text-align:left;font-size:13px}}
td{{border:1px solid #eee;padding:10px;vertical-align:top}}
tr:nth-child(even) td{{background:#fafafa}}
.kpi{{display:flex;gap:14px;margin:16px 0}}
.kpi-card{{flex:1;padding:18px;text-align:center;color:white;border-radius:8px}}
.kpi-card .num{{font-size:36px;font-weight:bold}}
.kpi-card .lbl{{font-size:12px;margin-top:4px}}
.footer{{background:#f5f5f5;padding:16px;text-align:center;font-size:12px;color:#888}}
</style></head><body><div class="container">
<div class="header">
  <h1>Stiglitz — Análise Comparativa de Scans</h1>
  <p>Anterior: <strong>{_html.escape(os.path.basename(DIR_OLD))}</strong>
     &nbsp;→&nbsp;
     Novo: <strong>{_html.escape(os.path.basename(DIR_NEW))}</strong></p>
  <p>Gerado em: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')} &nbsp;·&nbsp; CONFIDENCIAL</p>
</div>
<div class="content">
{risk_html}
<div class="kpi">
  <div class="kpi-card" style="background:#b34e4e">
    <div class="num">{len(appeared)}</div><div class="lbl">Novas</div>
  </div>
  <div class="kpi-card" style="background:#27ae60">
    <div class="num">{len(fixed)}</div><div class="lbl">Corrigidas</div>
  </div>
  <div class="kpi-card" style="background:#d4833a">
    <div class="num">{len(persist)}</div><div class="lbl">Persistentes</div>
  </div>
</div>

<h2>✗ Novas Vulnerabilidades</h2>
<table><tr><th>Severidade</th><th>Nome</th><th>Fonte</th><th>URLs</th></tr>
{build_rows(appeared, new_f, "#b34e4e", "✗")}
</table>

<h2>✓ Vulnerabilidades Corrigidas</h2>
<table><tr><th>Severidade</th><th>Nome</th><th>Fonte</th><th>URLs (anterior)</th></tr>
{build_rows(fixed, old_f, "#27ae60", "✓")}
</table>

<h2>~ Vulnerabilidades Persistentes</h2>
<table><tr><th>Severidade</th><th>Nome</th><th>Fonte</th><th>URLs</th></tr>
{build_rows(persist, new_f, "#d4833a", "~")}
</table>
</div>
<div class="footer">Stiglitz — Scanner Automatizado de Segurança · CONFIDENCIAL</div>
</div></body></html>"""

    out_name = f"stiglitz_diff_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    with open(out_name, "w", encoding="utf-8") as f:
        f.write(page)
    print(f"\n  {GREEN}[✓] Relatório HTML: {out_name}{NC}")

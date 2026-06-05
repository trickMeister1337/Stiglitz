#!/usr/bin/env python3
"""
Stiglitz Trend — Análise longitudinal cross-engagement.

Aceita N scan directories (ordenados por timestamp) e produz um HTML com:
- Linha de tendência do Risk Score por scan.
- Tabela de contagem de findings por severidade ao longo do tempo.
- Delta entre o primeiro e o último scan.

Uso:
    python3 stiglitz_trend.py scan_target_2026Q1/ scan_target_2026Q2/ scan_target_2026Q3/
    python3 stiglitz_trend.py scan_target_*/    # via glob shell
    python3 stiglitz_trend.py --out trend.html scan_*/

Útil para tracking trimestral / engagement-over-engagement.
"""
import glob
import html as _html
import json
import os
import re
import sys
from datetime import datetime


def _err(msg):
    print(f"[✗] {msg}", file=sys.stderr)
    sys.exit(1)


def _extract_timestamp(scan_dir):
    """Extrai timestamp do nome (scan_<domain>_YYYYMMDD_HHMMSS/) ou do mtime."""
    base = os.path.basename(scan_dir.rstrip("/"))
    m = re.search(r"_(\d{8})_(\d{6})$", base)
    if m:
        try:
            return datetime.strptime(m.group(1) + m.group(2), "%Y%m%d%H%M%S")
        except ValueError:
            pass
    try:
        return datetime.fromtimestamp(os.path.getmtime(scan_dir))
    except OSError:
        return datetime.now()


def _extract_domain(scan_dir):
    base = os.path.basename(scan_dir.rstrip("/"))
    m = re.match(r"^scan_(.+?)_\d{8}_\d{6}$", base)
    return m.group(1) if m else base


def _extract_risk(scan_dir):
    """Lê risk score do HTML report (mesma heurística do stiglitz_diff)."""
    rep = os.path.join(scan_dir, "stiglitz_report.html")
    if not os.path.exists(rep):
        return None
    try:
        content = open(rep, encoding="utf-8", errors="replace").read()
    except OSError:
        return None
    m = re.search(r"(?:Risk Score|Índice de Risco)[^0-9]*?(\d+)", content[:6000])
    return int(m.group(1)) if m else None


def _extract_stats(scan_dir):
    """Conta findings por severidade a partir de findings.json."""
    fj = os.path.join(scan_dir, "findings.json")
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    if not os.path.exists(fj):
        return counts
    try:
        data = json.load(open(fj, encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return counts
    # findings.json layout: dict com "findings": [...] ou lista direta
    items = data.get("findings", data) if isinstance(data, dict) else data
    if not isinstance(items, list):
        return counts
    for f in items:
        if not isinstance(f, dict):
            continue
        sev = (f.get("severity") or "info").lower()
        if sev in counts:
            counts[sev] += 1
    return counts


def collect(scan_dirs):
    """Retorna lista de dicts ordenada por timestamp ascendente."""
    rows = []
    for d in scan_dirs:
        if not os.path.isdir(d):
            print(f"[!] não é diretório, pulando: {d}", file=sys.stderr)
            continue
        rows.append({
            "dir":       d,
            "domain":    _extract_domain(d),
            "timestamp": _extract_timestamp(d),
            "risk":      _extract_risk(d),
            "stats":     _extract_stats(d),
        })
    rows.sort(key=lambda r: r["timestamp"])
    return rows


def _sparkline_svg(scores, width=600, height=120, pad=24):
    """SVG simples — linha + pontos das pontuações de risco."""
    pts = [s if s is not None else 0 for s in scores]
    if not pts:
        return "<svg></svg>"
    n = len(pts)
    if n == 1:
        # Um único ponto — desenha como bola
        cx, cy = width // 2, height // 2
        return (f'<svg width="{width}" height="{height}" xmlns="http://www.w3.org/2000/svg">'
                f'<circle cx="{cx}" cy="{cy}" r="6" fill="#1a3a4f"/></svg>')
    max_y = 100
    inner_w = width - 2 * pad
    inner_h = height - 2 * pad
    coords = []
    for i, v in enumerate(pts):
        x = pad + (inner_w * i // (n - 1))
        y = pad + inner_h - (inner_h * v // max_y)
        coords.append((x, y, v))
    path = "M " + " L ".join(f"{x},{y}" for x, y, _ in coords)
    dots = "".join(
        f'<circle cx="{x}" cy="{y}" r="4" fill="#1a3a4f"/>'
        f'<text x="{x}" y="{y - 8}" font-size="10" text-anchor="middle" fill="#555">{v}</text>'
        for x, y, v in coords
    )
    # Linhas-guia (bandas 70/40/15)
    bands = ""
    for band, color in [(70, "#7a2e2e"), (40, "#b34e4e"), (15, "#d4833a")]:
        y = pad + inner_h - (inner_h * band // max_y)
        bands += (f'<line x1="{pad}" y1="{y}" x2="{width - pad}" y2="{y}" '
                  f'stroke="{color}" stroke-width="0.5" stroke-dasharray="3,3"/>'
                  f'<text x="{width - pad + 4}" y="{y + 3}" font-size="9" '
                  f'fill="{color}">{band}</text>')
    return (f'<svg width="{width + 28}" height="{height}" '
            f'xmlns="http://www.w3.org/2000/svg" style="background:#fafafa;'
            f'border:1px solid #eee;border-radius:6px">'
            f'{bands}<path d="{path}" stroke="#1a3a4f" stroke-width="2" fill="none"/>'
            f'{dots}</svg>')


def render_html(rows, out_path):
    if not rows:
        _err("nenhum scan válido para gerar trend")
    domain = rows[0]["domain"]
    scores = [r["risk"] for r in rows]
    first, last = rows[0], rows[-1]
    first_risk = first["risk"] if first["risk"] is not None else 0
    last_risk  = last["risk"]  if last["risk"]  is not None else 0
    delta = last_risk - first_risk
    delta_color = "#27ae60" if delta < 0 else "#b34e4e" if delta > 0 else "#888"
    delta_sign = "+" if delta > 0 else ""

    rows_html = ""
    for r in rows:
        ts = r["timestamp"].strftime("%d/%m/%Y %H:%M")
        risk_disp = r["risk"] if r["risk"] is not None else "?"
        s = r["stats"]
        rows_html += (f'<tr><td>{ts}</td>'
                      f'<td style="font-family:monospace;font-size:11px">{_html.escape(os.path.basename(r["dir"].rstrip("/")))}</td>'
                      f'<td style="text-align:center;font-weight:600">{risk_disp}</td>'
                      f'<td style="color:#7a2e2e">{s["critical"]}</td>'
                      f'<td style="color:#b34e4e">{s["high"]}</td>'
                      f'<td style="color:#d4833a">{s["medium"]}</td>'
                      f'<td style="color:#4a7c8c">{s["low"]}</td></tr>')

    spark = _sparkline_svg(scores)

    out = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<title>Stiglitz Trend — {_html.escape(domain)}</title>
<style>
body{{font-family:"Segoe UI",sans-serif;max-width:1000px;margin:0 auto;padding:30px;color:#333}}
h1{{color:#1a3a4f;border-bottom:3px solid #1a3a4f;padding-bottom:8px;font-size:22px}}
h2{{color:#1a3a4f;font-size:15px;margin-top:24px}}
table{{width:100%;border-collapse:collapse;margin:12px 0;font-size:12px}}
th{{background:#1a3a4f;color:white;padding:8px;text-align:left}}
td{{border:1px solid #eee;padding:8px}}
.summary{{display:flex;gap:16px;margin:16px 0}}
.kpi{{flex:1;background:#f5f5f5;padding:12px 18px;border-radius:8px;text-align:center}}
.kpi .n{{font-size:24px;font-weight:bold}}
.kpi .l{{font-size:11px;color:#888}}
.footer{{color:#aaa;font-size:10px;text-align:center;margin-top:32px;border-top:1px solid #eee;padding-top:8px}}
</style></head><body>
<h1>📈 Stiglitz Trend — {_html.escape(domain)}</h1>
<p style="color:#666">Análise longitudinal de {len(rows)} scan(s) — {first["timestamp"].strftime("%d/%m/%Y")} a {last["timestamp"].strftime("%d/%m/%Y")}</p>

<h2>Risk Score over Time</h2>
{spark}

<div class="summary">
  <div class="kpi"><div class="n">{first_risk}</div><div class="l">First scan</div></div>
  <div class="kpi"><div class="n">{last_risk}</div><div class="l">Latest scan</div></div>
  <div class="kpi"><div class="n" style="color:{delta_color}">{delta_sign}{delta}</div><div class="l">Δ Delta</div></div>
  <div class="kpi"><div class="n">{len(rows)}</div><div class="l">Scans</div></div>
</div>

<h2>Per-scan breakdown</h2>
<table>
<tr><th>Date</th><th>Scan</th><th>Risk</th><th>Critical</th><th>High</th><th>Medium</th><th>Low</th></tr>
{rows_html}
</table>

<div class="footer">Stiglitz Trend · Restricted to authorized security teams · CONFIDENTIAL</div>
</body></html>"""

    with open(out_path, "w", encoding="utf-8") as f:
        f.write(out)


def main():
    args = sys.argv[1:]
    out_path = None
    if "--out" in args:
        i = args.index("--out")
        out_path = args[i + 1]
        args = args[:i] + args[i + 2:]
    if "-h" in args or "--help" in args or not args:
        print(__doc__, file=sys.stderr)
        sys.exit(0 if not args else 2)

    # Expansão de globs (caso o shell não tenha expandido)
    expanded = []
    for a in args:
        if any(c in a for c in "*?["):
            expanded.extend(sorted(glob.glob(a)))
        else:
            expanded.append(a)
    if not expanded:
        _err("nenhum diretório encontrado")

    rows = collect(expanded)
    if not rows:
        _err("nenhum scan válido")

    if not out_path:
        domain = rows[0]["domain"].replace("/", "_")
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_path = f"stiglitz_trend_{domain}_{ts}.html"

    render_html(rows, out_path)
    print(f"[✓] Trend gerado: {out_path}")
    print(f"    {len(rows)} scan(s) | {rows[0]['timestamp']:%Y-%m-%d} → {rows[-1]['timestamp']:%Y-%m-%d}")
    if rows[0]["risk"] is not None and rows[-1]["risk"] is not None:
        delta = rows[-1]["risk"] - rows[0]["risk"]
        sign = "+" if delta > 0 else ""
        print(f"    Δ risk: {sign}{delta}  ({rows[0]['risk']} → {rows[-1]['risk']})")


if __name__ == "__main__":
    main()

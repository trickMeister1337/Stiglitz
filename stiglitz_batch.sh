#!/bin/bash
# ==============================================================================
# Stiglitz BATCH — Orquestrador de múltiplos alvos
# Executa stiglitz.sh com suporte a paralelização via semáforo FIFO
# Uso: bash stiglitz_batch.sh targets.txt [--delay N] [--workers N]
#      bash stiglitz_batch.sh targets.txt --workers 5   (5 scans em paralelo)
#      bash stiglitz_batch.sh targets.txt --delay 30    (sequencial, 30s delay)
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
Stiglitz="$SCRIPT_DIR/stiglitz.sh"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

# ── Argumentos ───────────────────────────────────────────────────────────────
TARGETS_FILE=""
DELAY_BETWEEN=15
WORKERS=1

while [[ $# -gt 0 ]]; do
    case "$1" in
        --delay)   DELAY_BETWEEN="$2"; shift 2 ;;
        --workers) WORKERS="$2";       shift 2 ;;
        -*)        echo -e "${RED}Opção desconhecida: $1${NC}" >&2; shift ;;
        *)         [[ -z "$TARGETS_FILE" ]] && TARGETS_FILE="$1"; shift ;;
    esac
done

if [ -z "$TARGETS_FILE" ]; then
    echo -e "${RED}Uso: $0 <targets.txt> [--delay N] [--workers N]${NC}"
    echo -e "${YELLOW}Exemplos:${NC}"
    echo -e "  $0 targets.txt"
    echo -e "  $0 targets.txt --workers 5"
    echo -e "  $0 targets.txt --delay 30"
    exit 1
fi

[ ! -f "$TARGETS_FILE" ] && echo -e "${RED}[✗] Arquivo não encontrado: $TARGETS_FILE${NC}" && exit 1
[ ! -f "$Stiglitz" ]        && echo -e "${RED}[✗] stiglitz.sh não encontrado em: $Stiglitz${NC}" && exit 1

# ── Validar --workers ─────────────────────────────────────────────────────────
if ! [[ "$WORKERS" =~ ^[0-9]+$ ]] || [ "$WORKERS" -lt 1 ]; then
    echo -e "${RED}[✗] --workers deve ser um inteiro >= 1${NC}"; exit 1
fi
[ "$WORKERS" -gt 10 ] && echo -e "${YELLOW}[!] Mais de 10 workers pode sobrecarregar o sistema${NC}"

# ── Ler alvos ─────────────────────────────────────────────────────────────────
mapfile -t TARGETS < <(
    grep -v '^\s*#' "$TARGETS_FILE" \
    | grep -v '^\s*$' \
    | sed 's/\s*#.*//' \
    | sed $'s/\r//' \
    | sed 's/[[:space:]]//g' \
    | awk '{ if ($0 !~ /^https?:\/\//) print "https://" $0; else print $0 }' \
    | grep -v '^$'
)

TOTAL=${#TARGETS[@]}
if [ "$TOTAL" -eq 0 ]; then
    echo -e "${RED}[✗] Nenhum alvo válido em $TARGETS_FILE${NC}"; exit 1
fi

# Limitar workers ao número de alvos
[ "$WORKERS" -gt "$TOTAL" ] && WORKERS=$TOTAL

# ── Diretório de batch ────────────────────────────────────────────────────────
BATCH_TS=$(date +%Y%m%d_%H%M%S)
BATCH_DIR="$SCRIPT_DIR/scan_batch_${BATCH_TS}"
mkdir -p "$BATCH_DIR/logs"
STATE_FILE="$BATCH_DIR/.state"

BATCH_START=$(date +%s)

# ── Banner ────────────────────────────────────────────────────────────────────
clear 2>/dev/null || true
echo -e "${GREEN}${BOLD}"
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║               Stiglitz — MODO BATCH                            ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"
echo -e "${GREEN}[+] Arquivo   : $TARGETS_FILE${NC}"
echo -e "${GREEN}[+] Alvos     : $TOTAL${NC}"
echo -e "${GREEN}[+] Workers   : $WORKERS${NC}"
if [ "$WORKERS" -eq 1 ]; then
    echo -e "${GREEN}[+] Delay     : ${DELAY_BETWEEN}s entre scans (aguarda ZAP encerrar)${NC}"
else
    _ports=""
    for ((i=0; i<WORKERS; i++)); do _ports+="$((8080 + i * 10)) "; done
    echo -e "${GREEN}[+] Portas ZAP: ${_ports}${NC}"
fi
echo -e "${GREEN}[+] Output    : $BATCH_DIR/${NC}"
echo -e "${GREEN}[+] Iniciado  : $(date '+%d/%m/%Y %H:%M:%S')${NC}"
echo ""
echo -e "${CYAN}Alvos enfileirados:${NC}"
for i in "${!TARGETS[@]}"; do
    printf "  %2d. %s\n" "$((i+1))" "${TARGETS[$i]}"
done
echo ""
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

# ── Barra de progresso ────────────────────────────────────────────────────────
print_progress() {
    local current=$1 total=$2
    local pct=$(( current * 100 / total ))
    local filled=$(( current * 40 / total ))
    local bar=""
    for ((i=0; i<filled; i++));   do bar+="█"; done
    for ((i=filled; i<40; i++)); do bar+="░"; done
    echo -ne "\r  [${bar}] ${pct}% (${current}/${total})"
}

# ── Modo sequencial ───────────────────────────────────────────────────────────
run_sequential() {
    local IDX=0
    for TARGET_URL in "${TARGETS[@]}"; do
        IDX=$((IDX + 1))

        echo ""
        echo -e "${CYAN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "${CYAN}${BOLD}  SCAN $IDX/$TOTAL: $TARGET_URL${NC}"
        echo -e "${CYAN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "${BLUE}[*] Iniciado em: $(date '+%d/%m/%Y %H:%M:%S')${NC}"

        local SCAN_START
        SCAN_START=$(date +%s)
        local _domain
        _domain=$(echo "$TARGET_URL" | sed -E 's|https?://||' | cut -d/ -f1 | cut -d: -f1)
        local _log="$BATCH_DIR/logs/${_domain}.log"

        # Garantir que ZAP da rodada anterior foi encerrado
        if pgrep -f "zaproxy\|zap-.*jar" > /dev/null 2>&1; then
            echo -e "${YELLOW}[!] ZAP ainda rodando — aguardando encerramento...${NC}"
            pkill -f "zaproxy" 2>/dev/null; pkill -f "zap-.*jar" 2>/dev/null
            sleep "$DELAY_BETWEEN"
            rm -f ~/.ZAP/zap.lock 2>/dev/null
        fi

        local SCAN_EXIT=0
        set -o pipefail
        STIGLITZ_BATCH=1 bash "$Stiglitz" "$TARGET_URL" 2>&1 | tee "$_log" || SCAN_EXIT=$?
        set +o pipefail

        local SCAN_END
        SCAN_END=$(date +%s)
        local SCAN_DUR=$(( SCAN_END - SCAN_START ))
        local DUR_STR="${SCAN_DUR}s"
        [ "$SCAN_DUR" -ge 60 ] && DUR_STR="$(( SCAN_DUR/60 ))m $(( SCAN_DUR%60 ))s"

        local _outdir
        _outdir=$(ls -td "$SCRIPT_DIR/scan_${_domain}_"* 2>/dev/null | head -1)
        if [ -n "$_outdir" ] && [ -d "$_outdir" ]; then
            mv "$_outdir" "$BATCH_DIR/" 2>/dev/null || true
            _outdir="$BATCH_DIR/$(basename "$_outdir")"
        fi

        if [ "$SCAN_EXIT" -eq 0 ] && [ -n "$_outdir" ]; then
            echo "OK|$TARGET_URL|$_outdir|$SCAN_DUR" >> "$STATE_FILE"
            echo -e "${GREEN}[✓] Concluído em $DUR_STR → $(basename "$_outdir")${NC}"
        else
            echo "FAIL|$TARGET_URL||$SCAN_DUR" >> "$STATE_FILE"
            echo -e "${RED}[✗] Falhou (exit $SCAN_EXIT) — log: $_log${NC}"
        fi

        echo ""; print_progress "$IDX" "$TOTAL"; echo ""

        if [ "$IDX" -lt "$TOTAL" ]; then
            echo -e "${BLUE}[*] Aguardando ${DELAY_BETWEEN}s antes do próximo scan...${NC}"
            for ((s=DELAY_BETWEEN; s>0; s--)); do
                echo -ne "\r    ${s}s restantes...   "; sleep 1
            done
            echo -ne "\r                        \r"
            pkill -f "zaproxy" 2>/dev/null; pkill -f "zap-.*jar" 2>/dev/null; true
            rm -f ~/.ZAP/zap.lock 2>/dev/null
        fi
    done
}

# ── Modo paralelo ─────────────────────────────────────────────────────────────
run_parallel() {
    echo -e "${YELLOW}[*] Modo paralelo — ${WORKERS} workers simultâneos${NC}"
    echo ""

    # Semáforo baseado em FIFO — cada token é uma porta ZAP disponível
    # Ler token = adquirir slot; escrever token de volta = liberar slot
    local SEM_FIFO
    SEM_FIFO=$(mktemp -u "$BATCH_DIR/.semXXXXXX")
    mkfifo "$SEM_FIFO"
    exec 3<>"$SEM_FIFO"
    rm -f "$SEM_FIFO"  # desvincula nome; fd 3 permanece aberto

    for ((i=0; i<WORKERS; i++)); do
        printf "%d\n" "$((8080 + i * 10))" >&3
    done

    local IDX=0
    for TARGET_URL in "${TARGETS[@]}"; do
        IDX=$((IDX + 1))

        # Adquirir semáforo — bloqueia até haver worker livre
        local WORKER_ZAP_PORT
        read -u 3 WORKER_ZAP_PORT

        local _domain
        _domain=$(echo "$TARGET_URL" | sed -E 's|https?://||' | cut -d/ -f1 | cut -d: -f1)
        local _log="$BATCH_DIR/logs/${_domain}.log"
        local _IDX_SNAP=$IDX

        echo -e "${CYAN}[>>] Worker ZAP:${WORKER_ZAP_PORT} — SCAN ${_IDX_SNAP}/${TOTAL}: $TARGET_URL${NC}"

        # Capturar variáveis no escopo do subshell
        (
            local SCAN_START
            SCAN_START=$(date +%s)

            # Matar ZAP nesta porta se ainda estiver rodando
            pkill -f "port ${WORKER_ZAP_PORT}" 2>/dev/null || true
            sleep 2

            local SCAN_EXIT=0
            ZAP_PORT=$WORKER_ZAP_PORT STIGLITZ_BATCH=1 \
                bash "$Stiglitz" "$TARGET_URL" > "$_log" 2>&1 || SCAN_EXIT=$?

            local SCAN_END
            SCAN_END=$(date +%s)
            local SCAN_DUR=$(( SCAN_END - SCAN_START ))
            local DUR_STR="${SCAN_DUR}s"
            [ "$SCAN_DUR" -ge 60 ] && DUR_STR="$(( SCAN_DUR/60 ))m $(( SCAN_DUR%60 ))s"

            local _outdir
            _outdir=$(ls -td "$SCRIPT_DIR/scan_${_domain}_"* 2>/dev/null | head -1)
            if [ -n "$_outdir" ] && [ -d "$_outdir" ]; then
                mv "$_outdir" "$BATCH_DIR/" 2>/dev/null || true
                _outdir="$BATCH_DIR/$(basename "$_outdir")"
            fi

            if [ "$SCAN_EXIT" -eq 0 ] && [ -n "$_outdir" ]; then
                # echo para STATE_FILE é atômico para linhas < PIPE_BUF
                echo "OK|$TARGET_URL|$_outdir|$SCAN_DUR" >> "$STATE_FILE"
                echo -e "${GREEN}[✓] ZAP:${WORKER_ZAP_PORT} — ${_domain} — $DUR_STR → $(basename "$_outdir")${NC}"
            else
                echo "FAIL|$TARGET_URL||$SCAN_DUR" >> "$STATE_FILE"
                echo -e "${RED}[✗] ZAP:${WORKER_ZAP_PORT} — ${_domain} — falhou (exit $SCAN_EXIT) — log: $_log${NC}"
            fi

            # Liberar semáforo devolvendo a porta
            printf "%d\n" "$WORKER_ZAP_PORT" >&3
        ) &

        # Pequeno delay entre lançamentos para evitar race no startup do ZAP
        sleep 5
    done

    echo ""
    echo -e "${BLUE}[*] Aguardando conclusão de todos os workers...${NC}"
    wait
    echo -e "${GREEN}[✓] Todos os workers finalizados.${NC}"

    exec 3>&-
}

# ── Execução ──────────────────────────────────────────────────────────────────
if [ "$WORKERS" -eq 1 ]; then
    run_sequential
else
    run_parallel
fi

# ── Contadores finais via state file ─────────────────────────────────────────
PASSED=0; FAILED=0
if [ -f "$STATE_FILE" ]; then
    PASSED=$(grep -c "^OK|" "$STATE_FILE" 2>/dev/null || echo 0)
    FAILED=$(grep -c "^FAIL|" "$STATE_FILE" 2>/dev/null || echo 0)
fi

# ── Relatório consolidado ─────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${CYAN}${BOLD}  GERANDO RELATÓRIO CONSOLIDADO${NC}"
echo -e "${CYAN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

BATCH_END=$(date +%s)
BATCH_DUR=$(( BATCH_END - BATCH_START ))

python3 - "$BATCH_DIR" "$BATCH_TS" "$BATCH_DUR" "$TOTAL" "$PASSED" "$FAILED" << 'PYREPORT'
import sys, json, os, html
from datetime import datetime

batch_dir   = sys.argv[1]
batch_ts    = sys.argv[2]
batch_dur   = int(sys.argv[3])
total       = int(sys.argv[4])
passed      = int(sys.argv[5])
failed      = int(sys.argv[6])
state_file  = os.path.join(batch_dir, ".state")

# Ler resultados do state file
results = []
if os.path.exists(state_file):
    for line in open(state_file):
        line = line.strip()
        if not line: continue
        parts = line.split("|")
        if len(parts) >= 4:
            results.append({
                "status": parts[0],
                "url":    parts[1],
                "outdir": parts[2],
                "dur":    int(parts[3]) if parts[3].isdigit() else 0
            })

def read_stats(outdir):
    stats = {"critical":0,"high":0,"medium":0,"low":0,"info":0}
    if not outdir or not os.path.exists(outdir): return stats, 0
    # Ler do findings.json gerado pelo stiglitz_report.py — agrega TLS, Email, ZAP, Nuclei
    fj = os.path.join(outdir, "findings.json")
    if os.path.exists(fj):
        try:
            data = json.load(open(fj))
            summary = data.get("summary", {})
            for k in stats:
                stats[k] = int(summary.get(k, 0))
            risk = data.get("scan", {}).get("risk_score", 0)
            return stats, risk
        except: pass
    # Fallback: ler diretamente de nuclei.json + zap_alerts.json (sem TLS/Email)
    sev_map = {"high":"high","medium":"medium","low":"low","informational":"info"}
    seen_names = {}
    nuc_f = os.path.join(outdir,"raw","nuclei.json")
    zap_f = os.path.join(outdir,"raw","zap_alerts.json")
    if os.path.exists(nuc_f):
        try:
            for line in open(nuc_f):
                line = line.strip()
                if not line: continue
                d = json.loads(line)
                s = d.get("info",{}).get("severity","info").lower()
                n = d.get("info",{}).get("name","")
                if n not in seen_names: seen_names[n] = s; stats[s] = stats.get(s,0)+1
        except: pass
    if os.path.exists(zap_f):
        try:
            data = json.load(open(zap_f))
            for a in data.get("alerts",[]):
                s = sev_map.get(a.get("risk","").lower(),"info")
                n = a.get("name","")
                if n not in seen_names: seen_names[n] = s; stats[s] = stats.get(s,0)+1
        except: pass
    risk = min(stats["critical"]*10+stats["high"]*5+stats["medium"]*2+stats["low"],100)
    return stats, risk

def rc(r):
    if r>=70: return "#7a2e2e"
    if r>=40: return "#b34e4e"
    if r>=15: return "#d4833a"
    return "#27ae60"

def rl(r):
    if r>=70: return "CRÍTICO"
    if r>=40: return "ALTO"
    if r>=15: return "MÉDIO"
    return "BAIXO"

def fmt_dur(s):
    if s>=3600: return f"{s//3600}h {(s%3600)//60}m"
    if s>=60:   return f"{s//60}m {s%60}s"
    return f"{s}s"

rdate = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
dur_str = fmt_dur(batch_dur)

# Build rows
rows_html = ""
all_risks = []
total_crit = total_high = total_med = 0

for r in results:
    stats, risk = read_stats(r["outdir"])
    all_risks.append(risk)
    total_crit += stats["critical"]
    total_high += stats["high"]
    total_med  += stats["medium"]

    report_path = os.path.join(r["outdir"], "stiglitz_report.html") if r["outdir"] else ""
    rel_path = os.path.join(os.path.basename(r["outdir"]), "stiglitz_report.html") if r["outdir"] else ""
    report_link = (f'<a href="{html.escape(rel_path)}" target="_blank" '
                   f'style="color:#388bfd;font-weight:500">📄 Abrir</a>') \
                   if os.path.exists(report_path) else \
                   '<span style="color:#e74c3c">✗ falhou</span>'

    status_icon = "✓" if r["status"]=="OK" else "✗"
    status_col  = "#27ae60" if r["status"]=="OK" else "#e74c3c"
    risk_c = rc(risk)

    rows_html += f"""<tr>
      <td style="font-weight:500">{html.escape(r['url'])}</td>
      <td style="text-align:center;color:{status_col};font-weight:bold">{status_icon}</td>
      <td style="text-align:center">
        <span style="background:{risk_c};color:white;padding:2px 10px;
          border-radius:12px;font-size:12px;font-weight:bold">{risk}</span>
        <div style="font-size:10px;color:{risk_c};font-weight:bold;margin-top:2px">{rl(risk)}</div>
      </td>
      <td style="text-align:center;color:#7a2e2e;font-weight:bold;font-size:16px">{stats['critical']}</td>
      <td style="text-align:center;color:#b34e4e;font-weight:bold;font-size:16px">{stats['high']}</td>
      <td style="text-align:center;color:#d4833a;font-size:15px">{stats['medium']}</td>
      <td style="text-align:center;color:#4a7c8c;font-size:13px">{stats['low']}</td>
      <td style="text-align:center;color:#888;font-size:13px">{stats['info']}</td>
      <td style="text-align:center;color:#666;font-size:12px">{fmt_dur(r['dur'])}</td>
      <td style="text-align:center">{report_link}</td>
    </tr>"""

max_risk = max(all_risks) if all_risks else 0
avg_risk = int(sum(all_risks)/len(all_risks)) if all_risks else 0

# Sort results by risk desc for summary insight
sorted_results = sorted(zip(all_risks, results), key=lambda x: -x[0])
top_risks = sorted_results[:3]
insight_html = ""
if top_risks:
    insight_html = '<h3 style="color:#1a3a4f;margin-bottom:8px">⚠ Atenção prioritária</h3><ul>'
    for r_val, r_item in top_risks:
        if r_val > 0:
            insight_html += f'<li><strong>{html.escape(r_item["url"])}</strong> — Risco {r_val} ({rl(r_val)})</li>'
    insight_html += "</ul>"

page = f"""<!DOCTYPE html><html lang="pt-br"><head><meta charset="UTF-8">
<title>Stiglitz — Relatório Consolidado {html.escape(batch_ts)}</title>
<style>
*{{box-sizing:border-box}}
body{{font-family:'Segoe UI',Arial,sans-serif;margin:0;padding:20px;background:#f0f2f5;color:#333}}
.container{{max-width:1280px;margin:0 auto;background:white;border-radius:12px;
  overflow:hidden;box-shadow:0 4px 20px rgba(0,0,0,.12)}}
.header{{background:linear-gradient(135deg,#1a3a4f,#0f2a3d);color:white;padding:36px;text-align:center}}
.header h1{{margin:0 0 10px;font-size:24px;letter-spacing:.5px}}
.header p{{margin:4px 0;opacity:.85;font-size:14px}}
.content{{padding:32px}}
.kpi-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:14px;margin:20px 0 28px}}
.kpi{{padding:20px;text-align:center;color:white;border-radius:10px}}
.kpi .num{{font-size:36px;font-weight:bold;line-height:1}}
.kpi .lbl{{font-size:12px;margin-top:6px;opacity:.9}}
h2{{color:#1a3a4f;border-bottom:3px solid #e0e0e0;padding-bottom:10px;font-size:18px}}
h3{{color:#1a3a4f}}
table{{width:100%;border-collapse:collapse;margin:12px 0;font-size:13px}}
th{{background:#1a3a4f;color:white;padding:12px 10px;text-align:center;font-weight:600;font-size:12px}}
th:first-child{{text-align:left}}
td{{border:1px solid #e8e8e8;padding:12px 10px;vertical-align:middle}}
tr:nth-child(even) td{{background:#fafafa}}
tr:hover td{{background:#f0f7ff}}
.info-box{{background:#e8f4f8;padding:16px;border-radius:8px;margin:16px 0;border-left:4px solid #1a3a4f;font-size:13px}}
.footer{{background:#f5f5f5;padding:20px;text-align:center;font-size:12px;color:#888;
  border-top:1px solid #e0e0e0}}
a{{color:#388bfd;text-decoration:none}}a:hover{{text-decoration:underline}}
</style></head>
<body><div class="container">
<div class="header">
  <h1>🕷️ Stiglitz — Relatório Consolidado de Segurança</h1>
  <p>Batch: {html.escape(batch_ts)} &nbsp;·&nbsp; {passed}/{total} scans concluídos &nbsp;·&nbsp; Duração total: {dur_str}</p>
  <p>Gerado em: {rdate} &nbsp;·&nbsp; <strong>CONFIDENCIAL — USO INTERNO</strong></p>
</div>
<div class="content">

<h2>Visão Geral</h2>
<div class="kpi-grid">
  <div class="kpi" style="background:#1a3a4f">
    <div class="num">{total}</div><div class="lbl">Alvos escaneados</div>
  </div>
  <div class="kpi" style="background:#27ae60">
    <div class="num">{passed}</div><div class="lbl">Concluídos</div>
  </div>
  {'<div class="kpi" style="background:#e74c3c"><div class="num">'+str(failed)+'</div><div class="lbl">Falharam</div></div>' if failed else ''}
  <div class="kpi" style="background:#7a2e2e">
    <div class="num">{total_crit}</div><div class="lbl">CRÍTICO (total)</div>
  </div>
  <div class="kpi" style="background:#b34e4e">
    <div class="num">{total_high}</div><div class="lbl">ALTO (total)</div>
  </div>
  <div class="kpi" style="background:#d4833a">
    <div class="num">{total_med}</div><div class="lbl">MÉDIO (total)</div>
  </div>
</div>

{'<div class="info-box">' + insight_html + '</div>' if insight_html else ''}

<h2>Resultados por Alvo</h2>
<table>
  <tr>
    <th style="text-align:left;min-width:220px">Alvo</th>
    <th>Status</th>
    <th>Risco</th>
    <th style="background:#7a2e2e">C</th>
    <th style="background:#b34e4e">A</th>
    <th style="background:#d4833a">M</th>
    <th style="background:#4a7c8c">B</th>
    <th style="background:#6e8f72">I</th>
    <th>Duração</th>
    <th>Relatório</th>
  </tr>
  {rows_html}
</table>

<div class="info-box">
  <strong>Legenda:</strong> C=Crítico &nbsp;A=Alto &nbsp;M=Médio &nbsp;B=Baixo &nbsp;I=Info
  &nbsp;·&nbsp; Contadores exibem tipos únicos de vulnerabilidade (não ocorrências brutas).
  &nbsp;·&nbsp; Clique em "📄 Abrir" para acessar o relatório completo de cada alvo.
  Os relatórios ficam nas subpastas deste diretório.
</div>

</div>
<div class="footer">
  <p>Stiglitz — Scanner Automatizado de Segurança &nbsp;·&nbsp; CONFIDENCIAL</p>
</div>
</div></body></html>"""

out = os.path.join(batch_dir, "relatorio_consolidado.html")
with open(out,"w",encoding="utf-8") as f:
    f.write(page)
print(f"[✓] Relatório consolidado: {out}")
PYREPORT

# ── Resumo final ──────────────────────────────────────────────────────────────
BATCH_DUR_TOTAL=$(( $(date +%s) - BATCH_START ))
DUR_STR="${BATCH_DUR_TOTAL}s"
[ "$BATCH_DUR_TOTAL" -ge 60 ] && DUR_STR="$(( BATCH_DUR_TOTAL/60 ))m $(( BATCH_DUR_TOTAL%60 ))s"

echo ""
echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}${BOLD}║  BATCH CONCLUÍDO — $(date '+%d/%m/%Y %H:%M:%S')               ${NC}"
echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${GREEN}✓ Concluídos : $PASSED/$TOTAL${NC}"
[ "$FAILED" -gt 0 ] && echo -e "  ${RED}✗ Falharam   : $FAILED/$TOTAL${NC}"
echo -e "  ${CYAN}⏱ Duração    : $DUR_STR${NC}"
echo ""
echo -e "  ${CYAN}📁 Batch      : $BATCH_DIR/${NC}"
echo -e "  ${CYAN}📊 Consolidado: $BATCH_DIR/relatorio_consolidado.html${NC}"
echo -e "  ${CYAN}📋 Logs       : $BATCH_DIR/logs/${NC}"
echo ""

[ -n "$DISPLAY" ] && command -v xdg-open &>/dev/null && \
    xdg-open "$BATCH_DIR/relatorio_consolidado.html" 2>/dev/null || \
    command -v wslview &>/dev/null && \
    wslview "$BATCH_DIR/relatorio_consolidado.html" 2>/dev/null || true

exit 0

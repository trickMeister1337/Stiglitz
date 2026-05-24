#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
#  Stiglitz FULL — Orquestrador completo da suite Stiglitz
# ═══════════════════════════════════════════════════════════════════════════════
#
#  Executa o pipeline completo em sequência:
#    osint.sh → stiglitz.sh → stiglitz_red.sh
#  e gera um índice HTML consolidando todos os relatórios.
#
#  Uso:
#    bash stiglitz_full.sh -t https://alvo.com
#    bash stiglitz_full.sh -t https://alvo.com -p staging
#    bash stiglitz_full.sh -t https://alvo.com --skip-osint --skip-red
# ═══════════════════════════════════════════════════════════════════════════════
set -uo pipefail

readonly VERSION="1.0"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; readonly SCRIPT_DIR

trap 'echo; echo "[!] Interrompido pelo usuário — abortando."; exit 130' INT TERM

# ── Cores ──────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[1;33m'; CYN='\033[0;36m'
BLD='\033[1m'; DIM='\033[2m'; RST='\033[0m'

# ── Defaults ───────────────────────────────────────────────────────────────────
TARGET=""
DOMAIN=""
PROFILE="staging"
SCOPE_FILE=""
AUTH_COOKIE=""
AUTH_HEADER=""
SKIP_OSINT=false
SKIP_SCAN=false
SKIP_RED=false
DRY_RUN=false
OUTDIR_OVERRIDE=""
# shellcheck disable=SC2034  # reservado p/ args extras
EXTRA_ARGS=()

# Diretórios capturados de cada fase
OSINT_DIR=""
SCAN_DIR=""
RED_DIR=""
FULL_DIR=""
LOG=""

# Métricas por fase
OSINT_SUBDOMAINS=0; OSINT_LEAKS=0
# shellcheck disable=SC2034  # OSINT_CVES_SHODAN reservado p/ relatório
OSINT_CVES_SHODAN=0
SCAN_FINDINGS=0;    SCAN_CVES=0;   SCAN_CONFIRMED=0
RED_SQLI=0;         RED_XSS=0;     RED_BRUTE=0

# Tempos de execução
T_OSINT=0; T_SCAN=0; T_RED=0; T_START=0

info()  { echo -e "${GRN}[✓]${RST} $*"; }
warn()  { echo -e "${YLW}[!]${RST} $*"; }
fail()  { echo -e "${RED}[✗]${RST} $*"; }
phase() { echo -e "\n${CYN}══════════════════════════════════════════════════${RST}"; \
          echo -e "${CYN}  $*${RST}"; \
          echo -e "${CYN}══════════════════════════════════════════════════${RST}"; }
log()   { echo "[$(date +%H:%M:%S)] $*" | tee -a "$LOG" 2>/dev/null || true; }
elapsed() { echo $(( $(date +%s) - $1 )); }
fmt_time() { local s=$1; printf "%dm%02ds" $(( s/60 )) $(( s%60 )); }

usage() {
    cat << 'EOF'

Stiglitz FULL v1.0 — Orquestrador completo da suite

MODO:
  bash stiglitz_full.sh -t https://alvo.com [opções]

OPÇÕES PRINCIPAIS:
  -t, --target URL        URL do alvo (obrigatório)
  -p, --profile PROFILE   lab | staging | production  (padrão: staging)
  --scope-file FILE       Arquivo com domínios/IPs em escopo
  --auth-cookie COOKIE    Cookie de autenticação
  --auth-header HEADER    Header de autenticação

CONTROLE DE FASES:
  --skip-osint            Pular fase OSINT
  --skip-scan             Pular fase Stiglitz (recon + varredura)
  --skip-red              Pular fase Stiglitz RED (exploração)

OPÇÕES GERAIS:
  --dry-run               Simular sem executar ferramentas
  --output-dir DIR        Diretório base customizado
  -h, --help              Exibir ajuda

EXEMPLOS:
  bash stiglitz_full.sh -t https://alvo.com
  bash stiglitz_full.sh -t https://alvo.com -p production --skip-red
  bash stiglitz_full.sh -t https://alvo.com -p lab --dry-run
  bash stiglitz_full.sh -t https://alvo.com --skip-osint --scope-file escopo.txt

EOF
    exit 0
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -t|--target)      TARGET="$2";          shift 2 ;;
            -p|--profile)     PROFILE="$2";          shift 2 ;;
            --scope-file)     SCOPE_FILE="$2";       shift 2 ;;
            --auth-cookie)    AUTH_COOKIE="$2";      shift 2 ;;
            --auth-header)    AUTH_HEADER="$2";      shift 2 ;;
            --skip-osint)     SKIP_OSINT=true;       shift ;;
            --skip-scan)      SKIP_SCAN=true;        shift ;;
            --skip-red)       SKIP_RED=true;         shift ;;
            --dry-run)        DRY_RUN=true;          shift ;;
            --output-dir)     OUTDIR_OVERRIDE="$2";  shift 2 ;;
            -h|--help)        usage ;;
            *) warn "Argumento desconhecido: $1"; shift ;;
        esac
    done
}

validate() {
    [ -z "$TARGET" ] && { fail "Informe o alvo com -t <url>"; echo "  bash stiglitz_full.sh --help"; exit 1; }

    DOMAIN=$(echo "$TARGET" | sed 's|https\?://||' | cut -d'/' -f1 | cut -d':' -f1)
    [ -z "$DOMAIN" ] && { fail "Não foi possível extrair o domínio de '$TARGET'"; exit 1; }

    case "$PROFILE" in
        lab|staging|production) ;;
        *) fail "Perfil inválido: '$PROFILE'. Use: lab|staging|production"; exit 1 ;;
    esac

    [ -n "$SCOPE_FILE" ] && [ ! -f "$SCOPE_FILE" ] && \
        { fail "scope-file não encontrado: $SCOPE_FILE"; exit 1; }
}

banner() {
    echo -e "${RED}"
    cat << 'BANNER'
   _____ _       _____    ____  __  ___   ________________  __   __
  / ___/| |     / /   |  / __ \/  |/  /  / ____/ ____/  / / /  / /
  \__ \ | | /| / / /| | / /_/ / /|_/ /  / /_  / /   / / / /  / /
 ___/ / | |/ |/ / ___ |/ _, _/ /  / /  / __/ / /___/ /_/ /  / /___
/____/  |__/|__/_/  |_/_/ |_/_/  /_/  /_/    \____/\____/  /_____/
BANNER
    echo -e "${RST}"
    echo -e "  ${YLW}${BLD}v${VERSION}${RST} — Orquestrador completo da suite Stiglitz"
    echo -e "  ${DIM}Alvo: ${TARGET} | Perfil: ${PROFILE^^}${RST}"
    [ "$DRY_RUN" = true ] && echo -e "  ${YLW}[DRY-RUN MODE — nenhum teste real será executado]${RST}"
    echo ""
}

authorization_gate() {
    echo ""
    echo -e "${YLW}╔══════════════════════════════════════════════════════════╗${RST}"
    echo -e "${YLW}║           GATE DE AUTORIZAÇÃO — Stiglitz FULL v${VERSION}        ║${RST}"
    echo -e "${YLW}╚══════════════════════════════════════════════════════════╝${RST}"
    echo ""
    echo -e "  ${BLD}Alvo:${RST}    ${TARGET}"
    echo -e "  ${BLD}Domínio:${RST} ${DOMAIN}"
    echo -e "  ${BLD}Perfil:${RST}  ${PROFILE^^}"
    echo ""

    local fases="OSINT"
    [ "$SKIP_OSINT" = true ] && fases="(OSINT pulado)"
    [ "$SKIP_SCAN"  = false ] && fases="$fases → Stiglitz"  || fases="$fases → (Stiglitz pulado)"
    [ "$SKIP_RED"   = false ] && fases="$fases → Stiglitz RED" || fases="$fases → (RED pulado)"
    echo -e "  ${BLD}Pipeline:${RST} $fases"
    echo ""
    echo -e "  ${RED}${BLD}AVISO:${RST} Este pipeline executa reconhecimento e testes ativos."
    echo -e "  Use SOMENTE em sistemas com autorização formal documentada."
    echo -e "  Uso não autorizado é crime (Art. 154-A CP / CFAA)."
    echo ""

    if [ "$DRY_RUN" = true ]; then
        warn "[DRY-RUN] Autorização simulada."
        export Stiglitz_AUTHORIZED=1
        return 0
    fi

    echo -e "  Digite ${BLD}EU AUTORIZO${RST} para confirmar e iniciar o pipeline:"
    read -r _auth_input
    if [[ "$_auth_input" != "EU AUTORIZO" ]]; then
        fail "Autorização não confirmada. Abortando."
        exit 1
    fi

    # Propagar autorização para os scripts filhos (evita prompts redundantes)
    export Stiglitz_AUTHORIZED=1
    log "AUTORIZADO. Pipeline completo. Alvo=${TARGET} Perfil=${PROFILE}"
}

# ── Captura do diretório criado por um script filho ───────────────────────────
_latest_dir() {
    # $1 = padrão glob, ex: "osint_alvo.com_*"
    ls -dt ${1} 2>/dev/null | head -1
}

# ═══════════════════════════════════════════════════════════════════════════════
#  FASE 1 — OSINT
# ═══════════════════════════════════════════════════════════════════════════════
run_osint() {
    if [ "$SKIP_OSINT" = true ]; then
        warn "OSINT: pulado (--skip-osint)"
        return 0
    fi

    phase "FASE 1 — OSINT (osint.sh)"
    [ ! -f "$SCRIPT_DIR/osint.sh" ] && { warn "osint.sh não encontrado — pulando"; return 0; }

    local _before; _before=$(_latest_dir "osint_${DOMAIN}_*")
    local _t0; _t0=$(date +%s)

    local osint_args=("$DOMAIN" "--no-roe")
    [ "$DRY_RUN" = true ] && osint_args+=("--dry-run")
    [ -n "$SCOPE_FILE" ] && osint_args+=("--scope-file" "$SCOPE_FILE")

    bash "$SCRIPT_DIR/osint.sh" "${osint_args[@]}" 2>&1 | tee -a "$LOG" || \
        warn "osint.sh terminou com erro (não crítico — continuando pipeline)"

    T_OSINT=$(elapsed $_t0)
    local _after; _after=$(_latest_dir "osint_${DOMAIN}_*")
    [ "$_after" != "$_before" ] && [ -n "$_after" ] && OSINT_DIR="$_after"

    if [ -n "$OSINT_DIR" ]; then
        # Extrair métricas do osint_summary.json se existir
        local summary="$OSINT_DIR/osint_summary.json"
        if [ -f "$summary" ]; then
            OSINT_SUBDOMAINS=$(python3 -c "import json; d=json.load(open('$summary')); print(d.get('subdomains_live',d.get('subdomains',0)))" 2>/dev/null || echo 0)
            OSINT_LEAKS=$(python3 -c "import json; d=json.load(open('$summary')); print(d.get('leaked_accounts',0))" 2>/dev/null || echo 0)
        fi
        info "OSINT: ${DOMAIN} — ${OSINT_SUBDOMAINS} subdomínios | ${OSINT_LEAKS} vazamentos | $(fmt_time $T_OSINT)"
        log "OSINT_DIR=$OSINT_DIR"
    else
        warn "OSINT: diretório de saída não localizado"
    fi
}

# ═══════════════════════════════════════════════════════════════════════════════
#  FASE 2 — Stiglitz (recon + varredura)
# ═══════════════════════════════════════════════════════════════════════════════
run_scan() {
    if [ "$SKIP_SCAN" = true ]; then
        warn "Stiglitz: pulado (--skip-scan)"
        return 0
    fi

    phase "FASE 2 — Stiglitz (recon + varredura)"
    [ ! -f "$SCRIPT_DIR/stiglitz.sh" ] && { warn "stiglitz.sh não encontrado — pulando"; return 0; }

    local _before; _before=$(_latest_dir "scan_${DOMAIN}_*")
    local _t0; _t0=$(date +%s)

    local scan_args=("$TARGET")
    [ -n "$OSINT_DIR" ] && scan_args+=("--osint-dir" "$OSINT_DIR")
    [ "$DRY_RUN" = true ] && scan_args+=("--dry-run")
    [ -n "$AUTH_COOKIE" ] && scan_args+=("--cookie" "$AUTH_COOKIE")
    [ -n "$AUTH_HEADER" ] && scan_args+=("--header" "$AUTH_HEADER")
    [ -n "$SCOPE_FILE" ] && scan_args+=("--scope-file" "$SCOPE_FILE")

    bash "$SCRIPT_DIR/stiglitz.sh" "${scan_args[@]}" 2>&1 | tee -a "$LOG" || \
        warn "stiglitz.sh terminou com erro (não crítico — continuando pipeline)"

    T_SCAN=$(elapsed $_t0)
    local _after; _after=$(_latest_dir "scan_${DOMAIN}_*")
    [ "$_after" != "$_before" ] && [ -n "$_after" ] && SCAN_DIR="$_after"

    if [ -n "$SCAN_DIR" ]; then
        local fj="$SCAN_DIR/findings.json"
        if [ -f "$fj" ]; then
            SCAN_FINDINGS=$(python3 -c "
import json
try:
    d = json.load(open('$fj'))
    findings = d if isinstance(d, list) else d.get('findings', [])
    print(len(findings))
except: print(0)
" 2>/dev/null || echo 0)
            SCAN_CONFIRMED=$(python3 -c "
import json, os
cf = '$SCAN_DIR/raw/exploit_confirmations.json'
try:
    data = json.load(open(cf))
    print(sum(1 for c in data if c.get('confirmed')))
except: print(0)
" 2>/dev/null || echo 0)
        fi
        SCAN_CVES=$(wc -l < "$SCAN_DIR/raw/cves_found.txt" 2>/dev/null || echo 0)
        info "Stiglitz: ${SCAN_FINDINGS} findings | ${SCAN_CONFIRMED} confirmados | ${SCAN_CVES} CVEs | $(fmt_time $T_SCAN)"
        log "SCAN_DIR=$SCAN_DIR"
    else
        warn "Stiglitz: diretório de saída não localizado"
    fi
}

# ═══════════════════════════════════════════════════════════════════════════════
#  FASE 3 — Stiglitz RED (exploração)
# ═══════════════════════════════════════════════════════════════════════════════
run_red() {
    if [ "$SKIP_RED" = true ]; then
        warn "Stiglitz RED: pulado (--skip-red)"
        return 0
    fi

    phase "FASE 3 — Stiglitz RED (exploração)"
    [ ! -f "$SCRIPT_DIR/stiglitz_red.sh" ] && { warn "stiglitz_red.sh não encontrado — pulando"; return 0; }

    local _before; _before=$(_latest_dir "stiglitz_red_${DOMAIN//./_}_*")
    local _t0; _t0=$(date +%s)

    local red_args=("-p" "$PROFILE")
    if [ -n "$SCAN_DIR" ]; then
        red_args+=("-d" "$SCAN_DIR")
    else
        red_args+=("-t" "$TARGET")
    fi
    [ "$DRY_RUN" = true ]   && red_args+=("--dry-run")
    [ -n "$AUTH_COOKIE" ]   && red_args+=("--auth-cookie" "$AUTH_COOKIE")
    [ -n "$AUTH_HEADER" ]   && red_args+=("--auth-header" "$AUTH_HEADER")
    [ -n "$SCOPE_FILE" ]    && red_args+=("--scope-file"  "$SCOPE_FILE")

    bash "$SCRIPT_DIR/stiglitz_red.sh" "${red_args[@]}" 2>&1 | tee -a "$LOG" || \
        warn "stiglitz_red.sh terminou com erro (não crítico)"

    T_RED=$(elapsed $_t0)
    local domain_safe="${DOMAIN//./_}"
    local _after; _after=$(_latest_dir "stiglitz_red_${domain_safe}_*")
    [ "$_after" != "$_before" ] && [ -n "$_after" ] && RED_DIR="$_after"

    if [ -n "$RED_DIR" ] && [ -f "$RED_DIR/exploits_confirmed.csv" ]; then
        RED_SQLI=$(grep -c "SQLI\|SQL_INJECT" "$RED_DIR/exploits_confirmed.csv" 2>/dev/null || echo 0)
        RED_XSS=$(grep -c "XSS" "$RED_DIR/exploits_confirmed.csv" 2>/dev/null || echo 0)
        RED_BRUTE=$(grep -c "BRUTE\|CREDENTIAL" "$RED_DIR/exploits_confirmed.csv" 2>/dev/null || echo 0)
        local total=$(( RED_SQLI + RED_XSS + RED_BRUTE ))
        info "Stiglitz RED: ${total} finding(s) (SQLi:${RED_SQLI} XSS:${RED_XSS} Brute:${RED_BRUTE}) | $(fmt_time $T_RED)"
        log "RED_DIR=$RED_DIR"
    else
        warn "Stiglitz RED: diretório de saída não localizado ou sem findings"
    fi
}

# ═══════════════════════════════════════════════════════════════════════════════
#  ÍNDICE HTML CONSOLIDADO
# ═══════════════════════════════════════════════════════════════════════════════
generate_index() {
    phase "RELATÓRIO — Índice consolidado"

    local total_elapsed; total_elapsed=$(elapsed "$T_START")
    local ts_str; ts_str=$(date '+%d/%m/%Y %H:%M')
    local total_red=$(( RED_SQLI + RED_XSS + RED_BRUTE ))

    python3 - << PYEOF
import html, os

domain      = "${DOMAIN}"
target      = "${TARGET}"
profile     = "${PROFILE}"
ts_str      = "${ts_str}"
total_time  = "$(fmt_time $total_elapsed)"
version     = "${VERSION}"
full_dir    = "${FULL_DIR}"

osint_dir   = "${OSINT_DIR}"
scan_dir    = "${SCAN_DIR}"
red_dir     = "${RED_DIR}"
osint_sub   = ${OSINT_SUBDOMAINS}
osint_leaks = ${OSINT_LEAKS}
scan_find   = ${SCAN_FINDINGS}
scan_conf   = ${SCAN_CONFIRMED}
scan_cves   = ${SCAN_CVES}
red_sqli    = ${RED_SQLI}
red_xss     = ${RED_XSS}
red_brute   = ${RED_BRUTE}
red_total   = ${total_red}

def rpath(d, filename):
    """Caminho relativo de full_dir até filename em d."""
    if not d: return ""
    p = os.path.join(d, filename)
    if os.path.exists(p):
        return os.path.relpath(p, full_dir)
    return ""

osint_report = rpath(osint_dir, "osint_report.html")
scan_report  = rpath(scan_dir,  "stiglitz_report.html")
red_report   = rpath(red_dir,   "stiglitz_red_report.html")

def link(path, label):
    if path:
        return f'<a href="{html.escape(path)}" target="_blank" style="color:#1a6fb5;font-weight:600">{label}</a>'
    return f'<span style="color:#aaa">{label}</span>'

def status_badge(ran, issues=None):
    if not ran:
        return '<span style="background:#e0e0e0;color:#888;padding:2px 8px;border-radius:4px;font-size:11px">PULADO</span>'
    if issues and issues > 0:
        return f'<span style="background:#b34e4e;color:white;padding:2px 8px;border-radius:4px;font-size:11px">⚠ {issues} finding(s)</span>'
    return '<span style="background:#2e7d32;color:white;padding:2px 8px;border-radius:4px;font-size:11px">✓ OK</span>'

rows = [
    ("🔍 OSINT", osint_dir, status_badge(bool(osint_dir), osint_sub),
     f"{osint_sub} subdomínios · {osint_leaks} vazamentos", link(osint_report, "Relatório OSINT")),
    ("📡 Stiglitz", scan_dir, status_badge(bool(scan_dir), scan_find),
     f"{scan_find} findings · {scan_conf} confirmados · {scan_cves} CVEs", link(scan_report, "Relatório Stiglitz")),
    ("⚔ Stiglitz RED", red_dir, status_badge(bool(red_dir), red_total),
     f"SQLi:{red_sqli} · XSS:{red_xss} · Brute:{red_brute}", link(red_report, "Relatório RED")),
]

rows_html = ""
for name, d, badge, summary, lnk in rows:
    dir_name = os.path.basename(d) if d else "—"
    rows_html += f"""
    <tr>
      <td style="font-weight:600;padding:10px 14px">{html.escape(name)}</td>
      <td style="padding:10px 14px">{badge}</td>
      <td style="padding:10px 14px;color:#555;font-size:12px">{html.escape(summary)}</td>
      <td style="padding:10px 14px">{lnk}</td>
      <td style="padding:10px 14px;font-size:11px;color:#999">{html.escape(dir_name)}</td>
    </tr>"""

index_html = f"""<!DOCTYPE html>
<html lang="pt-br"><head><meta charset="UTF-8">
<title>Stiglitz FULL — {html.escape(domain)}</title>
<style>
  *{{box-sizing:border-box}}
  body{{font-family:"Segoe UI",sans-serif;margin:0;background:#f0f2f5;color:#333}}
  .header{{background:#1a3a4f;color:white;padding:24px 36px}}
  .header h1{{margin:0 0 4px;font-size:22px}}
  .header p{{margin:0;opacity:.75;font-size:13px}}
  .container{{max-width:1100px;margin:24px auto;padding:0 24px}}
  .kpis{{display:flex;gap:16px;flex-wrap:wrap;margin-bottom:24px}}
  .kpi{{background:white;border-radius:8px;padding:16px 24px;flex:1;min-width:140px;
        box-shadow:0 1px 3px rgba(0,0,0,.08);text-align:center}}
  .kpi .n{{font-size:28px;font-weight:700;color:#1a3a4f}}
  .kpi .l{{font-size:11px;color:#888;margin-top:2px}}
  .card{{background:white;border-radius:8px;box-shadow:0 1px 3px rgba(0,0,0,.08);
         margin-bottom:20px;overflow:hidden}}
  .card-title{{background:#1a3a4f;color:white;padding:10px 18px;font-size:13px;font-weight:600}}
  table{{width:100%;border-collapse:collapse}}
  th{{background:#f5f7fa;padding:10px 14px;text-align:left;font-size:11px;
      color:#666;border-bottom:1px solid #e8e8e8}}
  tr:not(:last-child) td{{border-bottom:1px solid #f0f0f0}}
  .footer{{text-align:center;color:#aaa;font-size:11px;padding:20px;margin-top:12px}}
  .badge-run{{background:#1a3a4f;color:white;padding:2px 8px;border-radius:4px;font-size:11px}}
  @media print{{body{{background:white}}.header{{-webkit-print-color-adjust:exact}}}}
</style></head><body>
<div class="header">
  <h1>🎯 Stiglitz FULL — Relatório Consolidado</h1>
  <p>{html.escape(target)} &nbsp;·&nbsp; Perfil: {html.escape(profile.upper())} &nbsp;·&nbsp; {ts_str} &nbsp;·&nbsp; Duração total: {total_time} &nbsp;·&nbsp; CONFIDENCIAL</p>
</div>
<div class="container">
  <div class="kpis">
    <div class="kpi"><div class="n">{osint_sub}</div><div class="l">Subdomínios</div></div>
    <div class="kpi"><div class="n">{scan_find}</div><div class="l">Findings Scan</div></div>
    <div class="kpi"><div class="n" style="color:{'#b34e4e' if red_total>0 else '#2e7d32'}">{red_total}</div><div class="l">Exploits Confirmados</div></div>
    <div class="kpi"><div class="n">{scan_cves}</div><div class="l">CVEs Detectados</div></div>
    <div class="kpi"><div class="n">{osint_leaks}</div><div class="l">Credenciais Vazadas</div></div>
  </div>
  <div class="card">
    <div class="card-title">Pipeline de Execução</div>
    <table>
      <thead><tr>
        <th>Fase</th><th>Status</th><th>Resumo</th><th>Relatório</th><th>Diretório</th>
      </tr></thead>
      <tbody>{rows_html}</tbody>
    </table>
  </div>
</div>
<div class="footer">
  Gerado por Stiglitz FULL v{html.escape(version)} · {ts_str} · Uso restrito a equipes autorizadas · CONFIDENCIAL
</div>
</body></html>"""

out = os.path.join(full_dir, "index.html")
open(out, "w", encoding="utf-8").write(index_html)
print(f"INDEX_OK:{out}")
PYEOF
}

# ── Notificação final ─────────────────────────────────────────────────────────
send_notification() {
    local message="$1"
    local token="${STIGLITZ_TELEGRAM_TOKEN:-}"
    local chat="${STIGLITZ_TELEGRAM_CHAT:-}"
    local webhook="${STIGLITZ_NOTIFY_WEBHOOK:-}"
    local teams="${STIGLITZ_TEAMS_WEBHOOK:-}"

    if [ -n "$token" ] && [ -n "$chat" ]; then
        curl -s -X POST "https://api.telegram.org/bot${token}/sendMessage" \
            -d "chat_id=${chat}" --data-urlencode "text=${message}" \
            -d "parse_mode=HTML" --max-time 10 >/dev/null 2>&1 || true
    fi
    if [ -n "$teams" ]; then
        local escaped; escaped=$(echo "$message" | sed 's/"/\\"/g' | sed 's/$/\\n/' | tr -d '\n')
        curl -s -X POST "$teams" -H "Content-Type: application/json" \
            -d "{\"@type\":\"MessageCard\",\"@context\":\"https://schema.org/extensions\",\"themeColor\":\"1a3a4f\",\"summary\":\"Stiglitz FULL concluído\",\"sections\":[{\"activityTitle\":\"🎯 Stiglitz FULL v${VERSION}\",\"activityText\":\"${escaped}\"}]}" \
            --max-time 10 >/dev/null 2>&1 || true
    fi
    if [ -n "$webhook" ]; then
        curl -s -X POST "$webhook" -H "Content-Type: application/json" \
            -d "{\"text\":\"$(echo "$message" | sed 's/"/\\"/g')\"}" \
            --max-time 10 >/dev/null 2>&1 || true
    fi
}

# ── Sumário final ─────────────────────────────────────────────────────────────
print_summary() {
    local total_elapsed; total_elapsed=$(elapsed "$T_START")
    local total_red=$(( RED_SQLI + RED_XSS + RED_BRUTE ))

    echo ""
    echo -e "${CYN}══════════════════════════════════════════════════════════${RST}"
    echo -e "${CYN}  SUMÁRIO FINAL — Stiglitz FULL v${VERSION}${RST}"
    echo -e "${CYN}══════════════════════════════════════════════════════════${RST}"
    echo ""
    printf "  %-18s %s\n" "Alvo:"     "$TARGET"
    printf "  %-18s %s\n" "Domínio:"  "$DOMAIN"
    printf "  %-18s %s\n" "Perfil:"   "${PROFILE^^}"
    printf "  %-18s %s\n" "Duração:"  "$(fmt_time $total_elapsed)"
    echo ""
    printf "  %-18s %d subdomínios · %d vazamentos\n" "OSINT:"     "$OSINT_SUBDOMAINS" "$OSINT_LEAKS"
    printf "  %-18s %d findings · %d confirmados · %d CVEs\n" "Stiglitz:" "$SCAN_FINDINGS" "$SCAN_CONFIRMED" "$SCAN_CVES"
    printf "  %-18s SQLi:%d XSS:%d Brute:%d\n" "Stiglitz RED:"  "$RED_SQLI" "$RED_XSS" "$RED_BRUTE"
    echo ""

    if [ "$total_red" -gt 0 ]; then
        echo -e "  ${RED}${BLD}⚠  $total_red exploit(s) confirmado(s) — revisar relatório RED imediatamente${RST}"
    else
        echo -e "  ${GRN}${BLD}✓  Nenhum exploit crítico confirmado${RST}"
    fi

    echo ""
    echo -e "  ${DIM}Índice:${RST}    ${FULL_DIR}/index.html"
    [ -n "$OSINT_DIR" ] && echo -e "  ${DIM}OSINT:${RST}     ${OSINT_DIR}/osint_report.html"
    [ -n "$SCAN_DIR"  ] && echo -e "  ${DIM}Stiglitz:${RST}     ${SCAN_DIR}/stiglitz_report.html"
    [ -n "$RED_DIR"   ] && echo -e "  ${DIM}Stiglitz RED:${RST} ${RED_DIR}/stiglitz_red_report.html"
    echo ""
}

# ═══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════════════════════
main() {
    parse_args "$@"
    validate

    T_START=$(date +%s)
    local ts; ts=$(date +%Y%m%d_%H%M%S)
    local domain_safe="${DOMAIN//./_}"

    if [ -n "$OUTDIR_OVERRIDE" ]; then
        FULL_DIR="$OUTDIR_OVERRIDE"
    else
        FULL_DIR="full_${domain_safe}_${ts}"
    fi
    mkdir -p "$FULL_DIR"
    LOG="$FULL_DIR/swarm_full.log"

    banner
    log "Stiglitz FULL v${VERSION} iniciado — Alvo=${TARGET} Perfil=${PROFILE}"

    authorization_gate

    run_osint
    run_scan
    run_red

    local idx_out
    idx_out=$(generate_index 2>&1)
    if echo "$idx_out" | grep -q "INDEX_OK:"; then
        local idx_file; idx_file=$(echo "$idx_out" | grep "INDEX_OK:" | sed 's/INDEX_OK://')
        info "Índice HTML: $idx_file"
    else
        warn "Índice HTML: falhou ($idx_out)"
    fi

    print_summary
    log "Stiglitz FULL concluído — $(fmt_time "$(elapsed "$T_START")") — Output: $FULL_DIR"

    local total_red=$(( RED_SQLI + RED_XSS + RED_BRUTE ))
    send_notification "[Stiglitz FULL v${VERSION}] Pipeline concluído
Alvo: ${TARGET}
OSINT: ${OSINT_SUBDOMAINS} subdomínios · ${OSINT_LEAKS} vazamentos
Stiglitz: ${SCAN_FINDINGS} findings · ${SCAN_CVES} CVEs
RED: SQLi:${RED_SQLI} XSS:${RED_XSS} Brute:${RED_BRUTE}
Duração: $(fmt_time "$(elapsed "$T_START")")
Índice: ${FULL_DIR}/index.html"
}

main "$@"

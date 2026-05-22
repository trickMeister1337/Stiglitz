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
    echo -e "  ${BLUE}[…] Gerando relatório (swarm_report.py)${NC}"
    if ! python3 "$_report_py"; then
        echo -e "  ${RED}[✗] swarm_report.py falhou — relatório HTML não gerado${NC}"
    fi
else
    echo -e "  ${RED}[✗] swarm_report.py não encontrado — relatório HTML não gerado${NC}"
    echo -e "  ${YELLOW}    Esperado em: $(dirname "$0")/swarm_report.py${NC}"
fi
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

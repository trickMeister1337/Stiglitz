#!/bin/bash
set -o pipefail

# ==============================================================================
# Stiglitz - CONSULTANT EDITION
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
        _found=$(find "$HOME" /usr/local /snap \
            -name "$_tool" -type f -perm /111 2>/dev/null | head -1)
        if [ -n "$_found" ]; then
            _found_dir=$(dirname "$_found")
            [[ ":$PATH:" != *":$_found_dir:"* ]] && export PATH="$PATH:$_found_dir"
        fi
    fi
done
unset _tool _found _found_dir

# ── httpx: resolver colisão de nome com a CLI do pacote Python httpx ───────────
# O pip instala um console-script "httpx" (ex.: ~/.local/bin/httpx) que pode
# sombrear o httpx da ProjectDiscovery quando ~/.local/bin precede ~/go/bin no
# PATH. O da PD lê hosts via stdin e entende -silent; a CLI Python rejeita as
# flags e o mapeamento de superfície (Fase 2) falha silenciosamente. Se o httpx
# do PATH não entender -silent, prioriza o binário da ProjectDiscovery.
if command -v httpx &>/dev/null && ! printf '' | httpx -silent >/dev/null 2>&1; then
    _pd_httpx=""
    while IFS= read -r _cand; do
        if printf '' | "$_cand" -silent >/dev/null 2>&1; then _pd_httpx="$_cand"; break; fi
    done < <(type -aP httpx 2>/dev/null)
    [ -z "$_pd_httpx" ] && [ -x "$HOME/go/bin/httpx" ] && _pd_httpx="$HOME/go/bin/httpx"
    if [ -n "$_pd_httpx" ]; then
        _pd_dir="$(dirname "$_pd_httpx")"
        export PATH="$_pd_dir:$PATH"
    fi
    unset _pd_httpx _pd_dir _cand
fi

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

# Diretório do script — usado para localizar lib/ e stiglitz_report.py
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# OAST (#2): por padrão -no-interactsh (sem callbacks externos — evita vazar para
# servidores públicos). Se INTERACTSH_SERVER estiver setado (interactsh self-hosted,
# ver lib/oob.py), liga o OAST do Nuclei para CONFIRMAR SSRF/RCE/SSTI/XXE CEGOS.
if [ -n "${INTERACTSH_SERVER:-}" ]; then
    NUCLEI_OAST_FLAGS=(-interactsh-server "$INTERACTSH_SERVER")
else
    NUCLEI_OAST_FLAGS=(-no-interactsh)
fi

ZAP_PORT=${ZAP_PORT:-8080}
ZAP_HOST="127.0.0.1"
ZAP_STARTED_BY_SCRIPT=0
# Em modo paralelo (STIGLITZ_BATCH=1), cada worker usa dir ZAP isolado para evitar conflito de lock/config
if [ "${STIGLITZ_BATCH:-0}" -eq 1 ]; then
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

# urlencode de UMA string (helper p/ a API do ZAP)
_url_quote() { python3 -c "import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1],safe=''))" "$1"; }

# ── ZAP Context com autenticação form/JSON + loggedInIndicator (#3) ──────────
# Opt-in via STIGLITZ_AUTH_LOGIN_URL + STIGLITZ_AUTH_USER (+ _PASS). Cria contexto,
# coloca o alvo no escopo, configura jsonBasedAuthentication com re-login automático
# (forced user) e exporta ZAP_CONTEXT_ID/ZAP_USER_ID para o spider/ascan rodarem
# AUTENTICADOS. Sequência validada ao vivo contra ZAP 2.17 + OWASP Juice Shop.
ZAP_CONTEXT_ID=""; ZAP_USER_ID=""
zap_setup_auth_context() {
    [ -z "${STIGLITZ_AUTH_LOGIN_URL:-}" ] && return 0
    [ -z "${STIGLITZ_AUTH_USER:-}" ] && return 0
    echo -e "  ${BLUE}[…] ZAP Context: configurando scan autenticado (JSON login + re-login)...${NC}"
    local uf="${STIGLITZ_AUTH_USER_FIELD:-email}" pf="${STIGLITZ_AUTH_PASS_FIELD:-password}"
    local indicator="${STIGLITZ_AUTH_INDICATOR:-\"token\"}"
    local ctx uid login_data auth_cfg creds
    ctx=$(zap_api_call "context/action/newContext" "contextName=stiglitz-auth" \
          | python3 -c "import sys,json;print(json.load(sys.stdin).get('contextId',''))" 2>/dev/null)
    [ -z "$ctx" ] && { echo -e "  ${YELLOW}[○] ZAP newContext falhou — seguindo sem auth${NC}"; return 0; }
    zap_api_call "context/action/includeInContext" \
        "contextName=stiglitz-auth&regex=$(_url_quote "${TARGET}.*")" >/dev/null
    login_data=$(python3 "$SCRIPT_DIR/lib/zap_auth.py" login-data "$uf" "$pf")
    auth_cfg=$(python3 "$SCRIPT_DIR/lib/zap_auth.py" json-auth "$STIGLITZ_AUTH_LOGIN_URL" "$login_data")
    zap_api_call "authentication/action/setAuthenticationMethod" \
        "contextId=${ctx}&authMethodName=jsonBasedAuthentication&authMethodConfigParams=$(_url_quote "$auth_cfg")" >/dev/null
    zap_api_call "authentication/action/setLoggedInIndicator" \
        "contextId=${ctx}&loggedInIndicatorRegex=$(_url_quote "$indicator")" >/dev/null
    uid=$(zap_api_call "users/action/newUser" "contextId=${ctx}&name=stiglitz" \
          | python3 -c "import sys,json;print(json.load(sys.stdin).get('userId',''))" 2>/dev/null)
    [ -z "$uid" ] && { echo -e "  ${YELLOW}[○] ZAP newUser falhou — seguindo sem auth${NC}"; return 0; }
    creds=$(python3 "$SCRIPT_DIR/lib/zap_auth.py" creds "$STIGLITZ_AUTH_USER" "${STIGLITZ_AUTH_PASS:-}")
    zap_api_call "users/action/setAuthenticationCredentials" \
        "contextId=${ctx}&userId=${uid}&authCredentialsConfigParams=$(_url_quote "$creds")" >/dev/null
    zap_api_call "users/action/setUserEnabled" "contextId=${ctx}&userId=${uid}&enabled=true" >/dev/null
    zap_api_call "forcedUser/action/setForcedUser" "contextId=${ctx}&userId=${uid}" >/dev/null
    zap_api_call "forcedUser/action/setForcedUserModeEnabled" "boolean=true" >/dev/null
    ZAP_CONTEXT_ID="$ctx"; ZAP_USER_ID="$uid"
    echo -e "  ${GREEN}[✓] ZAP Context autenticado (ctx=${ctx} user=${uid}) — spider/ascan rodarão logados${NC}"
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
# shellcheck disable=SC2034  # knob de config reservado
TARGETS_FILE=""
TARGET=""

# shellcheck disable=SC2034  # knob de config reservado
PARALLEL_JOBS=1
AUTH_TOKEN=""      # Bearer token para scan autenticado
TOKEN_A=""         # token primário (BOLA/BFLA) — também alimenta AUTH_TOKEN
TOKEN_B=""         # token secundário (BOLA/BFLA)
AUTH_HEADER=""     # Header customizado (ex: "Cookie: session=abc")
OSINT_DIR=""       # Diretório de output do osint.sh (reaproveita descoberta)
OUTDIR_OVERRIDE="" # Reutiliza um diretório de scan fixo (orquestrador pipeline.py)
ONLY_PHASES=""     # Lista de fases a executar (ex: "P4"); vazio = todas
DRY_RUN=false      # Simular: imprime o plano e sai sem executar ferramentas

# Parse args: suporta --token, --header, --osint-dir, --outdir, --only-phase, --dry-run
_args=("$@")
for _i in "${!_args[@]}"; do
    case "${_args[$_i]}" in
        --token|-t)          AUTH_TOKEN="${_args[$((${_i}+1))]}" ;;
        --token-a)           TOKEN_A="${_args[$((${_i}+1))]}" ;;
        --token-b)           TOKEN_B="${_args[$((${_i}+1))]}" ;;
        --header|-H)         AUTH_HEADER="${_args[$((${_i}+1))]}" ;;
        --osint-dir|--osint) OSINT_DIR="${_args[$((${_i}+1))]}" ;;
        --outdir)            OUTDIR_OVERRIDE="${_args[$((${_i}+1))]}" ;;
        --only-phase)        ONLY_PHASES="${_args[$((${_i}+1))]}" ;;
        --dry-run)           DRY_RUN=true ;;
    esac
done

# --token/-t é apelido de --token-a; AUTH_TOKEN (usado pela P9/nuclei) reflete o token A
[ -z "$TOKEN_A" ] && [ -n "$AUTH_TOKEN" ] && TOKEN_A="$AUTH_TOKEN"
[ -n "$TOKEN_A" ] && AUTH_TOKEN="$TOKEN_A"

# Atribuir alvo se não for flag
if [ -n "$1" ] && ! echo "$1" | grep -q '^-'; then
    TARGET="$1"
fi
unset _args _i

if [ "$1" = "-f" ] || [ "$1" = "--file" ] || [ "$1" = "--f" ]; then
    echo -e "${CYAN}[*] Modo multi-target — use stiglitz_batch.sh para múltiplos alvos:${NC}"
    echo -e "${YELLOW}    bash stiglitz_batch.sh targets.txt${NC}"
    echo ""
    # Redirecionar automaticamente para stiglitz_batch.sh se disponível
    _batch="$(dirname "$0")/stiglitz_batch.sh"
    if [ -f "$_batch" ]; then
        echo -e "  ${BLUE}[…] Redirecionando para stiglitz_batch.sh...${NC}"
        exec bash "$_batch" "${@:2}"
    else
        echo -e "  ${RED}[✗] stiglitz_batch.sh não encontrado em: $_batch${NC}"
        exit 1
    fi
fi

# ── Sem argumento: mostrar uso ──────────────────────────────────────
if [ -z "$TARGET" ]; then
    echo -e "${RED}Uso:${NC}"
    echo -e "  ${YELLOW}bash stiglitz.sh https://target.com${NC}                  — scan único"
    echo -e "  ${YELLOW}bash stiglitz.sh -f targets.txt${NC}                      — múltiplos alvos (via stiglitz_batch.sh)"
    echo -e "  ${YELLOW}bash stiglitz.sh target.com --osint-dir osint_*/${NC}     — reaproveita descoberta do osint.sh"
    echo -e "  ${YELLOW}bash stiglitz.sh target.com --token <jwt>${NC}            — scan autenticado"
    echo ""
    echo -e "  ${YELLOW}Exemplo: bash stiglitz.sh https://app.exemplo.com${NC}"
    exit 1
fi

# ── Modo single-target: continua normalmente ─────────────────────
# Normalizar scheme — alvos sem http(s):// assumem https://
if ! echo "$TARGET" | grep -qE '^https?://'; then
    TARGET="https://$TARGET"
fi
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
if [ -n "$OUTDIR_OVERRIDE" ]; then
    # Restringir a um charset seguro — OUTDIR é interpolado em heredocs Python
    if ! echo "$OUTDIR_OVERRIDE" | grep -qE '^[A-Za-z0-9._/-]+$'; then
        echo -e "${RED}[✗] --outdir contém caracteres inválidos: ${OUTDIR_OVERRIDE}${NC}"
        echo -e "${YELLOW}    Permitido: letras, números, . _ - /${NC}"
        exit 1
    fi
    OUTDIR="$OUTDIR_OVERRIDE"   # diretório fixo reutilizado entre fases (orquestrador)
else
    OUTDIR="scan_${DOMAIN}_${TIMESTAMP}"
    # Convenção local: se STIGLITZ_OUTDIR_BASE estiver setado, ancora a saída fora do
    # repo (organizada por host). Sem a env, mantém o comportamento padrão (CWD).
    if [ -n "${STIGLITZ_OUTDIR_BASE:-}" ]; then
        OUTDIR="${STIGLITZ_OUTDIR_BASE%/}/${DOMAIN}/${OUTDIR}"
    fi
fi
# ── DRY-RUN: imprime o plano e sai sem executar nenhuma ferramenta ──
# Avaliado ANTES de criar qualquer diretório — dry-run não deve tocar o disco.
if [ "$DRY_RUN" = true ]; then
    echo -e "${YELLOW}[DRY-RUN] Nenhuma ferramenta será executada.${NC}"
    echo -e "  Alvo:    ${TARGET}"
    echo -e "  Domínio: ${DOMAIN}"
    echo -e "  Output:  ${OUTDIR}"
    echo -e "  Fases:   P1 subdomains → P2 surface → P3 TLS → P4 nuclei → P5 confirm →"
    echo -e "           P6 CVE/EPSS → P7 WAF → P8 email → P9 ZAP → P10 JS → P10.5 extra → P11 report → P12 tracker"
    [ -n "$ONLY_PHASES" ] && echo -e "  Apenas:  ${ONLY_PHASES}"
    [ -n "$OSINT_DIR" ]   && echo -e "  OSINT:   ${OSINT_DIR}"
    echo -e "${GREEN}[DRY-RUN] Plano impresso — encerrando.${NC}"
    exit 0
fi

# Criação do diretório de output só após passar pelo gate de dry-run
mkdir -p "$OUTDIR/raw"

# ── Lockfile: evitar execuções simultâneas no mesmo diretório ────
LOCKFILE="$OUTDIR/raw/.stiglitz.lock"
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
STIGLITZ_STATE="$OUTDIR/raw/.stiglitz_state"
touch "$STIGLITZ_STATE" 2>/dev/null

# ── Timing por fase ─────────────────────────────────────────────
PHASE_TIMES_FILE="$OUTDIR/raw/.phase_times"
touch "$PHASE_TIMES_FILE"

phase_start() {
    echo "$1:start:$(date +%s)" >> "$PHASE_TIMES_FILE"
}

phase_end() {
    local _s; _s=$(grep "^$1:start:" "$PHASE_TIMES_FILE" 2>/dev/null | tail -1 | cut -d: -f3)
    local _e; _e=$(date +%s)
    local _dur=$(( _e - ${_s:-_e} ))
    echo "$1:end:$_e:dur:$_dur" >> "$PHASE_TIMES_FILE"
    printf "  ${BLUE}[⏱] Duração da fase: %dm%02ds${NC}\n" $(( _dur/60 )) $(( _dur%60 ))
}
if [ -s "$STIGLITZ_STATE" ]; then
    _done_phases=$(grep "=done:" "$STIGLITZ_STATE" | cut -d= -f1 | tr "\n" " ")
    echo -e "  ${YELLOW}[!] Retomando scan — fases já concluídas: ${_done_phases}${NC}"
    echo -e "  ${YELLOW}    Para reiniciar do zero: rm -rf $OUTDIR${NC}"
    unset _done_phases
fi

phase_done() {
    # Marca fase como concluída: phase_done "FASE_1"
    echo "$1=done:$(date +%s)" >> "$STIGLITZ_STATE"
}

phase_skip() {
    # Retorna 0 (skip) se fase já concluída, 1 (run) se não
    grep -q "^$1=done:" "$STIGLITZ_STATE" 2>/dev/null
}

_filter_inscope_urls() {
    # Lê URLs de $1 e imprime só as in-scope, comparando o HOST da URL com $DOMAIN
    # (igual ou subdomínio real). Filtrar por substring deixaria escapar URLs como
    # "https://externo.com/?redirect_uri=alvo.com", comuns em fluxos OAuth/SSO.
    [ -s "$1" ] || return 0
    python3 -c '
import sys, urllib.parse as u
dom = sys.argv[1].lower()
for line in sys.stdin:
    url = line.strip()
    if not url:
        continue
    host = (u.urlsplit(url).hostname or "").lower()
    if host == dom or host.endswith("." + dom):
        print(url)
' "$DOMAIN" < "$1" 2>/dev/null || true
}

_phase_enabled() {
    # Retorna 0 se a fase deve rodar. Sem --only-phase, todas rodam (comportamento padrão).
    # Com --only-phase "P4 P9", apenas as listadas (match por palavra) rodam.
    [ -z "$ONLY_PHASES" ] && return 0
    case " $ONLY_PHASES " in *" $1 "*) return 0 ;; *) return 1 ;; esac
}

_needs_network() {
    # Retorna 0 se alguma fase habilitada precisa de acesso de rede ao alvo.
    # Fases offline (P11 = geração de relatório) não requerem conectividade.
    for _np in P1 P2 P2_5 P3 P4 P5 P6 P8 P9 P9_5 P10 P10_5; do
        _phase_enabled "$_np" && return 0
    done
    return 1
}

# ── Banner ASCII ──────────────────────────────────────────────────────────────
clear 2>/dev/null || true
echo -e "${CYAN}"
cat << 'ASCIIART'
  ███████╗████████╗██╗ ██████╗ ██╗     ██╗████████╗███████╗
  ██╔════╝╚══██╔══╝██║██╔════╝ ██║     ██║╚══██╔══╝╚══███╔╝
  ███████╗   ██║   ██║██║  ███╗██║     ██║   ██║     ███╔╝ 
  ╚════██║   ██║   ██║██║   ██║██║     ██║   ██║    ███╔╝  
  ███████║   ██║   ██║╚██████╔╝███████╗██║   ██║   ███████╗
  ╚══════╝   ╚═╝   ╚═╝ ╚═════╝ ╚══════╝╚═╝   ╚═╝   ╚══════╝
ASCIIART
echo -e "${NC}"
echo -e "  ${BOLD}Stiglitz — All-in-One Offensive Security Pipeline${NC}"
echo -e "  ${BLUE}Methodology: KEV + EPSS + CVSS · 12-phase pipeline${NC}"
echo ""
echo -e "  ${GREEN}▸${NC} Alvo     ${BOLD}$TARGET${NC}"
echo -e "  ${GREEN}▸${NC} Domínio  ${BOLD}$DOMAIN${NC}"
echo -e "  ${GREEN}▸${NC} Output   ${BOLD}$OUTDIR/${NC}"
echo -e "  ${GREEN}▸${NC} Iniciado ${BOLD}$(date '+%d/%m/%Y %H:%M:%S')${NC}"
echo ""
echo -e "  ${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# ── Verificação de acesso ao alvo ─────────────────────────────────────────────
if _needs_network; then
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
        echo -e "  ${YELLOW}    Tente especificar a porta: bash stiglitz.sh https://$DOMAIN:8080${NC}"
    else
        echo -e "  ${RED}[✗]${NC} DNS não resolve — verifique o domínio"
    fi
    unset _dns
    [ "${STIGLITZ_BATCH:-0}" = "1" ] && exit 1
    exit 1
fi
echo -e "\r  ${GREEN}[✓]${NC} Alvo acessível ${GREEN}(HTTP ${HTTP_CODE})${NC}"
echo ""
fi # _needs_network

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
        _loc=$(find "$HOME" /usr/local /usr/bin /snap \
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
# TLDs compostos: empresa.com.br tem 3 partes mas é raiz (não subdomínio)
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
    # empresa.com.br = 3 → raiz → rodar subfinder
    # api.empresa.com.br = 4 → subdomínio → pular
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


if _phase_enabled "P1"; then
phase_start "P1"
phase_banner "FASE 1/11: DESCOBERTA DE SUBDOMÍNIOS"

# ── Integração OSINT: validar diretório fornecido ─────────────────
if [ -n "$OSINT_DIR" ]; then
    OSINT_DIR="${OSINT_DIR%/}"   # remover barra final
    if [ ! -d "$OSINT_DIR" ]; then
        echo -e "  ${YELLOW}[!] --osint-dir '${OSINT_DIR}' não encontrado — seguindo com descoberta normal${NC}"
        OSINT_DIR=""
    elif [ ! -s "$OSINT_DIR/targets_enriched.txt" ]; then
        echo -e "  ${YELLOW}[!] OSINT dir sem targets_enriched.txt — descoberta normal${NC}"
    else
        echo -e "  ${GREEN}[✓] Integração OSINT ativa: ${OSINT_DIR}${NC}"
    fi
fi

SUB_COUNT=0
if [ -n "$OSINT_DIR" ] && [ -s "$OSINT_DIR/targets_enriched.txt" ]; then
    # Reaproveitar descoberta do osint.sh — não rodar subfinder de novo.
    # targets_enriched.txt traz "https://host"; subdomains.txt espera hostnames.
    # O alvo explícito (DOMAIN) é sempre incluído — nunca descartar o TARGET passado.
    {
        sed -E 's#^https?://##' "$OSINT_DIR/targets_enriched.txt" | cut -d/ -f1
        echo "$DOMAIN"
    } | sed '/^$/d' | sort -u > "$OUTDIR/raw/subdomains.txt"
    SUB_COUNT=$(wc -l < "$OUTDIR/raw/subdomains.txt" | tr -d ' ')
    echo -e "  ${GREEN}[✓] Reaproveitando ${SUB_COUNT} alvo(s) do OSINT (alvo explícito garantido) — subfinder ignorado${NC}"
elif [ "$IS_SUBDOMAIN" -eq 1 ]; then
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

fi  # fim P1
if _phase_enabled "P2"; then
phase_start "P2"
phase_banner "FASE 2/11: MAPEAMENTO DE SUPERFÍCIE"

ACTIVE_COUNT=0
if command -v httpx &>/dev/null; then
    cat "$OUTDIR/raw/subdomains.txt" | \
        httpx -silent -status-code -title -tech-detect -timeout 5 \
              -o "$OUTDIR/raw/httpx_results.txt" 2>"$OUTDIR/raw/httpx_error.log"
    [ -f "$OUTDIR/raw/httpx_results.txt" ] && \
        ACTIVE_COUNT=$(grep -c . "$OUTDIR/raw/httpx_results.txt" 2>/dev/null); ACTIVE_COUNT=${ACTIVE_COUNT:-0}
    echo -e "  ${GREEN}[✓] $ACTIVE_COUNT subdomínio(s) ativo(s) detectado(s)${NC}"
else
    echo -e "  ${YELLOW}[○] httpx não disponível — pulando mapeamento HTTP${NC}"
fi

OPEN_PORTS="N/A"
if command -v nmap &>/dev/null; then
    # Full TCP scan (-p-) + fingerprint de versão + mapeamento de CVEs por banner.
    # --script vulners consulta vulners.com e lista CVEs conhecidos da versão de cada
    # serviço (ex.: OpenSSH 7.4 → CVE-...), sinalizando software desatualizado —
    # cobrindo serviços de rede (SSH/FTP/SMTP/RDP) além das portas web.
    # --version-intensity 7: fingerprint mais preciso (evita rótulos errados como
    # "ssl/rtsp"). -p- é abrangente porém lento: NMAP_TIMEOUT (default 30min) protege
    # o pipeline. -oX gera XML estruturado consumido por lib/service_versions.py.
    echo -e "  ${BLUE}[…] Executando nmap (full TCP scan + vulners — pode levar vários minutos)...${NC}"
    timeout "${NMAP_TIMEOUT:-1800}" nmap -p- \
         -T4 -sV --version-intensity 7 --open \
         --script vulners \
         "$DOMAIN" -oN "$OUTDIR/raw/nmap.txt" -oX "$OUTDIR/raw/nmap.xml" > /dev/null 2>&1
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
    # Extrai versões de serviço + CVEs (vulners) do XML → service_findings.json
    if [ -f "$OUTDIR/raw/nmap.xml" ]; then
        python3 "$SCRIPT_DIR/lib/service_versions.py" "$OUTDIR" "$TARGET" || true
    fi
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
fi  # fim P2
if _phase_enabled "P2_5"; then
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

python3 "$SCRIPT_DIR/lib/scan_metadata.py" "$OUTDIR" "$WAF_DETECTED" "$WAF_NAME" \
    "$NUCLEI_RATE_LIMIT" "$NUCLEI_CONCURRENCY" "${NUCLEI_DELAY:-none}" \
    "$RANDOM_UA"

phase_end "P2_5"
phase_done "FASE_2_5"

# ====================== FASES 3+4: TESTSSL + NUCLEI (paralelo) ======================

fi  # fim P2_5
if _phase_enabled "P3"; then
phase_start "P3"
# ── Verificação de headers de segurança ─────────────────────────
echo -e "  ${BLUE}[…] Verificando headers de segurança HTTP...${NC}"
python3 "$SCRIPT_DIR/lib/security_headers.py" "$OUTDIR"
echo -e "  ${GREEN}[✓] Headers de segurança verificados${NC}"
export SECURITY_HEADERS_FILE="$OUTDIR/raw/security_headers.json"

# ── Technology Version Fingerprinting ────────────────────────────
# Probes well-known unauthenticated version-disclosure endpoints.
# Detects outdated installations and maps them to known CVEs.
# Output: raw/version_findings.json
echo -e "  ${BLUE}[…] Fingerprinting de versão de aplicações...${NC}"
python3 "$SCRIPT_DIR/lib/version_fingerprint.py" "$OUTDIR" "$TARGET"
export VERSION_FINDINGS_FILE="$OUTDIR/raw/version_findings.json"

# ── Tech Profile Builder: agrega httpx tech-detect + katana paths + PROBES ───
# Gera tech_profile.json usado pelas Fases 4 (Nuclei), 10.5 (ffuf) e 11 (relatório)
echo -e "  ${BLUE}[…]${NC} Construindo perfil tecnológico do alvo..."
python3 "$SCRIPT_DIR/lib/tech_profile.py" "$OUTDIR" "$TARGET"

# ── Monitoring Endpoint Exposure Check ───────────────────────────────────────
# Checks /metrics, /actuator/*, /-/metrics for unauthenticated access.
# Extracts datasource names, alert names, PCI-sensitive labels.
python3 "$SCRIPT_DIR/lib/monitoring_check.py" "$OUTDIR" "$TARGET"

# ── PYSECSCAN: security.txt (RFC-9116) + internal IP exposure ────
echo -e "  ${BLUE}[…]${NC} Verificando security.txt e exposição de IPs internos..."
python3 "$SCRIPT_DIR/lib/secscan.py" "$OUTDIR" "$TARGET" "$DOMAIN"

# ── PCI/CDE: detecções dedicadas apenas se houver escopo CDE declarado ──
_cde_file="${STIGLITZ_CDE_TARGETS:-$SCRIPT_DIR/cde_targets.txt}"
if [ -s "$_cde_file" ]; then
    echo -e "  ${BLUE}[…]${NC} PCI/CDE: escopo declarado detectado — rodando detecções dedicadas..."
    python3 "$SCRIPT_DIR/lib/pan_scanner.py" "$OUTDIR" "$TARGET" || true
    # Detecta o scan anterior do mesmo domínio para o diff de scripts (Req 11.6.1)
    _prev_scan=$(ls -dt scan_"${DOMAIN}"_*/ 2>/dev/null | sed 's#/$##' | grep -vx "$OUTDIR" | head -1)
    python3 "$SCRIPT_DIR/lib/payment_page_monitor.py" "$OUTDIR" "$TARGET" ${_prev_scan:+"$_prev_scan"} || true
    unset _prev_scan
else
    echo -e "  ${YELLOW}[○]${NC} PCI/CDE: sem cde_targets.txt — detecções PCI dedicadas puladas"
fi
unset _cde_file

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
fi  # fim P3
if _phase_enabled "P4"; then
phase_start "P4"
phase_banner "FASE 4/11: SCAN DE VULNERABILIDADES (NUCLEI) — paralelo com testssl"

NUCLEI_COUNT=0
if command -v nuclei &>/dev/null; then
    echo -e "  ${YELLOW}[!] Scan pode levar 5-10 minutos (rate-limit: ${NUCLEI_RATE_LIMIT} req/s)...${NC}"
    # Construir flags de evasão baseado em WAF detectado
    # Arrays bash preservam os limites de cada argumento (headers com espaços)
    # sem precisar de eval na invocação do nuclei.
    NUCLEI_EVASION_FLAGS=()
    # Injetar token de autenticação no Nuclei se fornecido
    if [ -n "$AUTH_TOKEN" ]; then
        NUCLEI_EVASION_FLAGS+=(-H "Authorization: Bearer ${AUTH_TOKEN}")
        echo -e "  ${GREEN}[✓]${NC} Nuclei: Authorization header configurado"
    fi
    if [ -n "$AUTH_HEADER" ]; then
        NUCLEI_EVASION_FLAGS+=(-H "${AUTH_HEADER}")
        echo -e "  ${GREEN}[✓]${NC} Nuclei: header customizado configurado"
    fi
    if [ "${WAF_DETECTED}" = "1" ]; then
        # User-Agent de browser real + headers que imitam tráfego legítimo
        # (reset intencional: comportamento idêntico ao original)
        NUCLEI_EVASION_FLAGS=(-H "User-Agent: ${RANDOM_UA}")
        NUCLEI_EVASION_FLAGS+=(-H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
        NUCLEI_EVASION_FLAGS+=(-H "Accept-Language: pt-BR,pt;q=0.9,en;q=0.8")
        NUCLEI_EVASION_FLAGS+=(-H "X-Forwarded-For: 127.0.0.1")
        NUCLEI_EVASION_FLAGS+=(-H "X-Real-IP: 127.0.0.1")
        # Ignorar respostas de bloqueio do WAF (403/406/429) e continuar
        # shellcheck disable=SC2054  # nuclei -hc espera lista comma-separated num único arg
        NUCLEI_EVASION_FLAGS+=(-hc 403,406,429)
        # Payload alterations — testa variações de encoding automaticamente
        NUCLEI_EVASION_FLAGS+=(-pa)
        [ -n "$NUCLEI_DELAY" ] && NUCLEI_EVASION_FLAGS+=(-rl-duration "$NUCLEI_DELAY")
        echo -e "  ${BLUE}[…] Evasão passiva ativada: UA rotation + origin spoofing + payload alterations${NC}"
    fi

    # Atualização de templates do Nuclei com cache diário (24h).
    # A adaptação por tags só é tão boa quanto os templates instalados — manter
    # frescos garante cobertura de CVEs novos. Cacheado para não baixar a cada scan.
    _nuc_tpl_marker="$HOME/.cache/stiglitz/nuclei_templates_updated"
    mkdir -p "$(dirname "$_nuc_tpl_marker")" 2>/dev/null
    _nuc_tpl_age=$(( $(date +%s) - $(stat -c %Y "$_nuc_tpl_marker" 2>/dev/null || echo 0) ))
    if [ "$_nuc_tpl_age" -gt 86400 ]; then
        echo -e "  ${BLUE}[…] Atualizando templates do Nuclei (cache diário)...${NC}"
        if timeout 120 nuclei -update-templates -silent 2>/dev/null; then
            touch "$_nuc_tpl_marker"
            echo -e "  ${GREEN}[✓] Templates do Nuclei atualizados${NC}"
        else
            echo -e "  ${YELLOW}[!] Falha/timeout ao atualizar templates — usando os instalados${NC}"
        fi
    else
        echo -e "  ${GREEN}[✓] Templates do Nuclei atualizados há $(( _nuc_tpl_age/3600 ))h (cache)${NC}"
    fi
    unset _nuc_tpl_marker _nuc_tpl_age

    # Always include custom templates directory if it exists
    NUCLEI_TEMPLATES_FLAGS=()
    _custom_tpl_dir="$(dirname "$0")/nuclei-custom-templates"
    [ -d "$_custom_tpl_dir" ] && NUCLEI_TEMPLATES_FLAGS+=(-t "$_custom_tpl_dir")

    # Tags adaptativas: base + extras por stack tecnológica detectada no tech profile
    # (#1/#5) sqli,xss,rce,ssti,xxe,nosqli agora nas base tags (antes só no fallback) —
    # injeção ativa em todo scan, não só quando o RED roda.
    _nuclei_base_tags="cve,tech,detect,exposure,default-login,misconfig,takeover,cors,lfi,ssrf,redirect,sqli,xss,rce,ssti,xxe,nosqli"
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

    # Preparar lista de URLs: domínio raiz + URLs do Katana + endpoints OSINT
    _nuclei_list="$OUTDIR/raw/nuclei_urls.txt"
    echo "$TARGET" > "$_nuclei_list"
    # Apenas URLs in-scope do Katana alimentam o Nuclei — o crawl em -d 5 segue
    # links/redirects para domínios externos (SSO, refs em JS) que NÃO podem
    # receber probes. Filtro por host (não substring); mesmo critério no feed ZAP.
    _filter_inscope_urls "$OUTDIR/raw/katana_urls.txt" >> "$_nuclei_list"
    # Endpoints históricos do OSINT (wayback/gau) alimentam a varredura
    if [ -n "$OSINT_DIR" ] && [ -s "$OSINT_DIR/endpoints_historical.txt" ]; then
        cat "$OSINT_DIR/endpoints_historical.txt" >> "$_nuclei_list"
        echo -e "  ${GREEN}[✓]${NC} Nuclei: $(wc -l < "$OSINT_DIR/endpoints_historical.txt" | tr -d ' ') endpoint(s) históricos do OSINT incluídos"
    fi
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
            timeout "$NUCLEI_BATCH_TIMEOUT" nuclei -l "$_batch" \
                -tags "$_nuclei_base_tags" \
                -severity critical,high,medium,low \
                -rate-limit "$NUCLEI_RATE_LIMIT" -concurrency "$NUCLEI_CONCURRENCY" \
                -timeout 10 "${NUCLEI_OAST_FLAGS[@]}" \
                "${NUCLEI_TEMPLATES_FLAGS[@]}" "${NUCLEI_EVASION_FLAGS[@]}" \
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
        _nuclei_input=(-l "$_nuclei_list")
        _nuclei_skip=0
    fi

    [ "${_nuclei_skip:-0}" = "1" ] || timeout "$NUCLEI_TIMEOUT" nuclei "${_nuclei_input[@]}" \
           -tags "$_nuclei_base_tags" \
           -severity critical,high,medium,low \
           -rate-limit "$NUCLEI_RATE_LIMIT" -concurrency "$NUCLEI_CONCURRENCY" \
           -timeout 10 "${NUCLEI_OAST_FLAGS[@]}" \
           "${NUCLEI_TEMPLATES_FLAGS[@]}" "${NUCLEI_EVASION_FLAGS[@]}" \
           -jsonl -o "$OUTDIR/raw/nuclei.json" \
           > /dev/null 2>"$OUTDIR/raw/nuclei_error.log"

    if [ -s "$OUTDIR/raw/nuclei.json" ]; then
        NUCLEI_COUNT=$(grep -c . "$OUTDIR/raw/nuclei.json" 2>/dev/null); NUCLEI_COUNT=${NUCLEI_COUNT:-0}
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
        # Reaproveita a lista completa de URLs (Katana/OSINT) e mantém as flags de
        # evasão (inclui -H Authorization do --token) e templates custom — senão o
        # fallback varreria apenas a raiz e perderia o token em scans autenticados.
        timeout "$NUCLEI_TIMEOUT" nuclei -l "$_nuclei_list" \
               -tags cve,exposure,misconfig,default-login,takeover,xss,sqli \
               -severity critical,high,medium \
               -rate-limit "$NUCLEI_RATE_LIMIT" -concurrency "$NUCLEI_CONCURRENCY" \
               -timeout 10 "${NUCLEI_OAST_FLAGS[@]}" \
               "${NUCLEI_TEMPLATES_FLAGS[@]}" "${NUCLEI_EVASION_FLAGS[@]}" \
               -jsonl -o "$OUTDIR/raw/nuclei.json" \
               > /dev/null 2>>"$OUTDIR/raw/nuclei_error.log"
        NUCLEI_COUNT=$(grep -c . "$OUTDIR/raw/nuclei.json" 2>/dev/null); NUCLEI_COUNT=${NUCLEI_COUNT:-0}
        echo -e "  ${GREEN}[✓] $NUCLEI_COUNT vulnerabilidade(s) encontrada(s)${NC}"
    fi

    # ── DAST fuzzing ativo (#1/#5): nuclei -dast sobre parâmetros ──────────────
    # Injeção ATIVA (SQLi/XSS/SSTI/redirect/prototype-pollution) em parâmetros — o
    # que o scan por-template não pega em app custom. arjun (se presente) descobre
    # params ocultos; dast_prep.py monta a lista parametrizada (dedupe por endpoint+
    # params); os hits anexam ao nuclei.json e fluem pela agregação existente.
    _dast_tpl_ok=0
    { [ -d "$HOME/nuclei-templates/dast" ] || [ -d "/root/nuclei-templates/dast" ]; } && _dast_tpl_ok=1
    if [ "${STIGLITZ_DAST:-1}" = "1" ] && [ "$_dast_tpl_ok" = "1" ]; then
        _arjun_out=""
        if command -v arjun &>/dev/null && [ -s "$OUTDIR/raw/katana_inscope.txt" ]; then
            echo -e "  ${BLUE}[…] arjun: descobrindo parâmetros ocultos...${NC}"
            arjun -i "$OUTDIR/raw/katana_inscope.txt" -oJ "$OUTDIR/raw/arjun.json" -t 10 \
                  >/dev/null 2>&1 || true
            [ -s "$OUTDIR/raw/arjun.json" ] && _arjun_out="$OUTDIR/raw/arjun.json"
        fi
        _dast_n=$(python3 "$SCRIPT_DIR/lib/dast_prep.py" "$OUTDIR/raw/katana_urls.txt" \
                  "$OUTDIR/raw/dast_urls.txt" "$_arjun_out" 2>/dev/null || echo 0)
        if [ "${_dast_n:-0}" -gt 0 ]; then
            echo -e "  ${BLUE}[…] nuclei -dast: fuzzing ativo em ${_dast_n} endpoint(s) parametrizado(s)...${NC}"
            timeout "$NUCLEI_TIMEOUT" nuclei -l "$OUTDIR/raw/dast_urls.txt" -dast -silent \
                   -rate-limit "$NUCLEI_RATE_LIMIT" -concurrency "$NUCLEI_CONCURRENCY" \
                   -timeout 10 "${NUCLEI_OAST_FLAGS[@]}" "${NUCLEI_EVASION_FLAGS[@]}" \
                   -jsonl -o "$OUTDIR/raw/nuclei_dast.json" \
                   > /dev/null 2>>"$OUTDIR/raw/nuclei_error.log" || true
            if [ -s "$OUTDIR/raw/nuclei_dast.json" ]; then
                _dast_hits=$(grep -c . "$OUTDIR/raw/nuclei_dast.json" 2>/dev/null); _dast_hits=${_dast_hits:-0}
                cat "$OUTDIR/raw/nuclei_dast.json" >> "$OUTDIR/raw/nuclei.json"
                NUCLEI_COUNT=$(( ${NUCLEI_COUNT:-0} + _dast_hits ))
                echo -e "  ${GREEN}[✓] DAST fuzzing: ${_dast_hits} finding(s) ativo(s) (injeção em parâmetros)${NC}"
            else
                echo -e "  ${YELLOW}[○] DAST fuzzing: sem injeção confirmada nos parâmetros${NC}"
            fi
            unset _dast_hits
        else
            echo -e "  ${YELLOW}[○] DAST fuzzing: sem endpoints parametrizados para fuzzar${NC}"
        fi
        unset _arjun_out _dast_n
    fi
    unset _dast_tpl_ok
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
    echo -e "  ${YELLOW}    Verifique conectividade com o alvo e considere re-executar deletando FASE_4 do .stiglitz_state${NC}"
fi
phase_end "P4"
phase_done "FASE_4"

# ====================== FASE 5: CONFIRMAÇÃO DE EXPLOITS ======================

fi  # fim P4
if _phase_enabled "P5"; then
phase_start "P5"
phase_banner "FASE 5/11: CONFIRMAÇÃO ATIVA DE EXPLOITS (Nuclei)"

CONFIRMED_COUNT=0
export DOMAIN OUTDIR TARGET   # necessário para poc_validator.py resolver domínio e caminhos
# Escopo para o poc_validator (usado pelo gate OOB para não injetar fora de escopo)
export STIGLITZ_SCOPE_DOMAINS="$DOMAIN"
if [ -s "$OUTDIR/raw/nuclei.json" ]; then
    echo -e "  ${BLUE}[…] Re-executando curl de cada achado para confirmar...${NC}"
    # Usar poc_validator.py — tentar múltiplos caminhos possíveis
    _poc_lib=""
    for _candidate in \
        "$(dirname "$0")/lib/poc_validator.py" \
        "$(cd "$(dirname "$0")" && pwd)/lib/poc_validator.py" \
        "$(dirname "$(readlink -f "$0")")/lib/poc_validator.py" \
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
else
    echo -e "  ${YELLOW}[○] Nenhum achado Nuclei para confirmar${NC}"
fi
# Marcar fase concluída SEMPRE (fora do if) — senão o checkpoint do pipeline.py
# re-executa a P5 a cada resume quando não há achados Nuclei para confirmar.
phase_end "P5"
phase_done "FASE_5"

# ====================== FASE 10: ENRIQUECIMENTO CVE/EPSS ======================

fi  # fim P5
if _phase_enabled "P6"; then
phase_start "P6"
phase_banner "FASE 6/11: ENRIQUECIMENTO CVE / EPSS (NVD + FIRST.org)"

if [ -s "$OUTDIR/raw/nuclei.json" ] || [ -s "$OUTDIR/raw/service_findings.json" ]; then
    echo -e "  ${BLUE}[…] Consultando NVD e EPSS para CVEs encontrados...${NC}"
    python3 "$SCRIPT_DIR/lib/cve_enrich.py" "$OUTDIR"
else
    echo -e "  ${YELLOW}[○] Sem CVEs (Nuclei/serviços) para enriquecer${NC}"
fi
phase_end "P6"
phase_done "FASE_6"

# ====================== FASE 7: EMAIL SECURITY ======================

fi  # fim P6
if _phase_enabled "P8"; then
phase_start "P8"
phase_banner "FASE 8/11: SEGURANÇA DE EMAIL (SPF / DMARC / DKIM)"

EMAIL_ISSUES=0
if command -v dig &>/dev/null; then
    echo -e "  ${BLUE}[…] Verificando registros DNS de segurança de email...${NC}"
    python3 "$SCRIPT_DIR/lib/email_security.py" "$DOMAIN" "$OUTDIR"

    EMAIL_ISSUES=$(python3 -c "
import json, os
try:
    d = json.load(open('$OUTDIR/raw/email_security.json'))
    print(sum(1 for v in d.values() if v.get('severity','') in ('high','medium')))
except: print(0)" 2>/dev/null || echo 0)
    echo -e "  ${GREEN}[✓] Análise de email concluída — $EMAIL_ISSUES problema(s) encontrado(s)${NC}"

    # Hint de PoC: se o From: exato é spoofável (DMARC ausente ou p=none), sugere
    # o email_spoof_poc.py. Apenas sugestão — não envia nada automaticamente.
    EMAIL_SPOOFABLE=$(python3 -c "
import json
try:
    d = json.load(open('$OUTDIR/raw/email_security.json'))
    dm = d.get('dmarc', {})
    print('1' if dm.get('status') == 'MISSING' or dm.get('policy') == 'none' else '0')
except: print('0')" 2>/dev/null || echo 0)
    if [ "$EMAIL_SPOOFABLE" = "1" ]; then
        echo -e "  ${YELLOW}[!] From: exato spoofável (DMARC ausente ou p=none).${NC}"
        echo -e "  ${BLUE}      PoC: python3 $SCRIPT_DIR/email_spoof_poc.py $DOMAIN --dry-run --to <alvo@org>${NC}"
        echo -e "  ${BLUE}      Envio real exige --send + gate RoE (\"EU AUTORIZO\").${NC}"
    fi
else
    echo -e "  ${YELLOW}[○] dig não disponível — pulando análise de email${NC}"
fi

export EMAIL_ISSUES
phase_end "P8"
phase_done "FASE_8"

# ====================== FASE 9: ZAP ======================

fi  # fim P8
if _phase_enabled "P9"; then
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
            cp "$ZAP_CONFIG" "${ZAP_CONFIG}.stiglitz_backup" 2>/dev/null
            python3 "$SCRIPT_DIR/lib/zap_config_fix.py" "$ZAP_CONFIG"
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
            [ -f "${ZAP_CONFIG}.stiglitz_backup" ] && \
                mv "${ZAP_CONFIG}.stiglitz_backup" "$ZAP_CONFIG" 2>/dev/null
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
        _oa_spec_seen=0
        OPENAPI_PATHS=("/swagger.json" "/swagger/v1/swagger.json" "/openapi.json"
                       "/api/swagger.json" "/api/openapi.json" "/api-docs"
                       "/v1/swagger.json" "/v2/swagger.json" "/v3/swagger.json"
                       "/swagger-ui/swagger.json" "/docs/swagger.json")
        for _oapath in "${OPENAPI_PATHS[@]}"; do
            _oa_url="${TARGET%/}${_oapath}"
            _oa_resp=$(curl -s --max-time 8 -w "%{http_code}" -o "$OUTDIR/raw/oa_check.tmp" "$_oa_url" 2>/dev/null)
            if echo "$_oa_resp" | grep -q "^2"; then
                # Validar que é um spec OpenAPI/Swagger REAL (JSON com chave de topo
                # openapi/swagger), não uma página HTML/JS que apenas contém a palavra.
                if python3 -c "import json,sys; d=json.load(open(sys.argv[1])); sys.exit(0 if isinstance(d,dict) and ('openapi' in d or 'swagger' in d) else 1)" \
                        "$OUTDIR/raw/oa_check.tmp" 2>/dev/null; then
                    _oa_spec_seen=1
                    echo -e "  ${GREEN}[✓] OpenAPI spec encontrado: $_oapath${NC}"
                    cp "$OUTDIR/raw/oa_check.tmp" "$OUTDIR/raw/openapi_spec.json"
                    # Importar spec no ZAP via API
                    _oa_encoded=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1],safe=''))" "$_oa_url")
                    _oa_result=$(zap_api_call "openapi/action/importUrl" "url=${_oa_encoded}&targetUrl=${ENCODED_URL}")
                    if echo "$_oa_result" | grep -q "OK\|Result"; then
                        echo -e "  ${GREEN}[✓] OpenAPI importado no ZAP — endpoints adicionados ao scan${NC}"
                        OPENAPI_FOUND=1
                    else
                        echo -e "  ${YELLOW}[!] Spec OpenAPI encontrado mas o import no ZAP falhou: $_oa_result${NC}"
                    fi
                    break
                fi
            fi
        done
        rm -f "$OUTDIR/raw/oa_check.tmp"
        if [ "$OPENAPI_FOUND" -eq 0 ] && [ "$_oa_spec_seen" -eq 0 ]; then
            echo -e "  ${YELLOW}[○] Nenhum endpoint OpenAPI/Swagger encontrado${NC}"
        fi

        # ── JWT audit (#6): testa o token fornecido (alg=none/weak-secret/exp) ──
        if [ -n "${AUTH_TOKEN:-}" ]; then
            echo -e "  ${BLUE}[…]${NC} JWT audit: analisando token autenticado..."
            python3 "$SCRIPT_DIR/lib/jwt_audit.py" "$OUTDIR" "$TARGET" "$AUTH_TOKEN" || true
        fi

        # ── GraphQL audit (#7): introspection nos endpoints /graphql conhecidos ──
        _gql_q='{"query":"query IntrospectionQuery { __schema { queryType { name } mutationType { name } types { name fields { name } } } }"}'
        for _gql in "$TARGET/graphql" "$TARGET/api/graphql" "$TARGET/v1/graphql" "$TARGET/query"; do
            _gql_resp=$(curl -s -m 10 -X POST -H "Content-Type: application/json" \
                ${AUTH_TOKEN:+-H "Authorization: Bearer $AUTH_TOKEN"} \
                -d "$_gql_q" "$_gql" 2>/dev/null)
            if echo "$_gql_resp" | grep -q '"__schema"'; then
                echo -e "  ${GREEN}[✓]${NC} GraphQL introspection respondeu em ${_gql}"
                echo "$_gql_resp" > "$OUTDIR/raw/graphql_resp.json"
                python3 "$SCRIPT_DIR/lib/graphql_audit.py" "$OUTDIR" "$_gql" || true
                break
            fi
        done
        unset _gql_q _gql _gql_resp

        # ── Katana: injetar URLs descobertas em P2 no contexto ZAP ───────
        # (o crawl já foi feito na Fase 2 para alimentar o Nuclei)
        if [ -s "$OUTDIR/raw/katana_urls.txt" ]; then
            # Mesmo filtro host-based do feed Nuclei — só URLs in-scope vão ao ZAP.
            _filter_inscope_urls "$OUTDIR/raw/katana_urls.txt" > "$OUTDIR/raw/katana_inscope.txt"
            KATANA_URLS=$(wc -l < "$OUTDIR/raw/katana_inscope.txt" | tr -d " ")
            echo -e "  ${BLUE}[…] Injetando ${KATANA_URLS} URL(s) in-scope do Katana no contexto ZAP...${NC}"
            _injected=0
            while IFS= read -r _k_url; do
                [ -z "$_k_url" ] && continue
                _k_enc=$(python3 -c \
                    "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1],safe=''))" \
                    "$_k_url" 2>/dev/null)
                zap_api_call "core/action/accessUrl" "url=${_k_enc}" > /dev/null 2>&1
                _injected=$((_injected + 1))
            done < "$OUTDIR/raw/katana_inscope.txt"
            echo -e "  ${GREEN}[✓] $_injected URL(s) injetadas no contexto ZAP${NC}"
            sleep 2
        else
            echo -e "  ${YELLOW}[○] Sem URLs do Katana para injetar — ZAP usará spider próprio${NC}"
        fi

        # ── ZAP Context autenticado (#3): configura scan logado se STIGLITZ_AUTH_* setado
        zap_setup_auth_context

        # ── ZAP Spider: complementa o Katana ou age sozinho ────────────
        echo -e "  ${BLUE}[…] Iniciando ZAP Spider (complementa crawl)...${NC}"
        if [ -n "$ZAP_CONTEXT_ID" ]; then
            SPIDER_ID=$(zap_api_call "spider/action/scanAsUser" \
                        "contextId=${ZAP_CONTEXT_ID}&userId=${ZAP_USER_ID}&url=${ENCODED_URL}&recurse=true" \
                        | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('scanAsUser', d.get('scan','0')))" 2>/dev/null)
        else
            SPIDER_ID=$(zap_api_call "spider/action/scan" "url=${ENCODED_URL}" \
                        | python3 -c "import sys,json; print(json.load(sys.stdin).get('scan','0'))" 2>/dev/null)
        fi
        wait_for_zap_progress "spider/view/status" "${SPIDER_ID:-0}" "$ZAP_SPIDER_TIMEOUT" "Spider"

        # ── AJAX Spider (#4): crawl headless para SPAs (React/Vue/Angular) ──
        # O spider clássico não executa JS pós-carga; o AJAX Spider navega via
        # browser headless e descobre rotas client-side/XHR invisíveis ao spider.
        if [ "${STIGLITZ_AJAX_SPIDER:-1}" = "1" ]; then
            echo -e "  ${BLUE}[…] AJAX Spider (SPA crawl headless)...${NC}"
            # inScope=true exige escopo definido (senão internal_error — validado);
            # com contexto autenticado usamos scanAsUser+inScope, senão inScope=false.
            if [ -n "$ZAP_CONTEXT_ID" ]; then
                _ajax_start=$(zap_api_call "ajaxSpider/action/scanAsUser" "contextId=${ZAP_CONTEXT_ID}&userId=${ZAP_USER_ID}&url=${ENCODED_URL}&inScope=true" 2>/dev/null)
            else
                _ajax_start=$(zap_api_call "ajaxSpider/action/scan" "url=${ENCODED_URL}&inScope=false" 2>/dev/null)
            fi
            if echo "$_ajax_start" | grep -q "OK"; then
                _ajax_waited=0
                while [ "$_ajax_waited" -lt "${ZAP_AJAX_TIMEOUT:-180}" ]; do
                    _ajax_st=$(zap_api_call "ajaxSpider/view/status" "" 2>/dev/null \
                        | python3 -c "import sys,json; print(json.load(sys.stdin).get('status',''))" 2>/dev/null)
                    [ "$_ajax_st" = "stopped" ] && break
                    sleep 5; _ajax_waited=$((_ajax_waited+5))
                done
                _ajax_n=$(zap_api_call "ajaxSpider/view/numberOfResults" "" 2>/dev/null \
                    | python3 -c "import sys,json; print(json.load(sys.stdin).get('numberOfResults','0'))" 2>/dev/null || echo 0)
                echo -e "  ${GREEN}[✓] AJAX Spider: ${_ajax_n:-0} rota(s) client-side descoberta(s)${NC}"
            else
                echo -e "  ${YELLOW}[○] AJAX Spider indisponível (add-on/browser ausente) — seguindo${NC}"
            fi
            unset _ajax_start _ajax_st _ajax_waited _ajax_n
        fi

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

        if [ -n "$ZAP_CONTEXT_ID" ]; then
            SCAN_RESPONSE=$(zap_api_call "ascan/action/scanAsUser" "url=${_scan_url}&contextId=${ZAP_CONTEXT_ID}&userId=${ZAP_USER_ID}&recurse=true" 2>/dev/null)
        else
            SCAN_RESPONSE=$(zap_api_call "ascan/action/scan" "url=${_scan_url}&recurse=true" 2>/dev/null)
        fi
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
    echo -e "  ${YELLOW}    Verifique se o ZAP spider completou e considere re-executar deletando FASE_9 do .stiglitz_state${NC}"
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

fi  # fim P9

# ====================== FASE 9.5: ACCESS CONTROL (BOLA/BFLA) ======================
if _phase_enabled "P9_5" && [ -n "$TOKEN_A" ] && [ -n "$TOKEN_B" ]; then
phase_start "P9_5"
phase_banner "FASE 9.5/11: ACCESS CONTROL (BOLA/BFLA)"

_zap_msgs_a="$OUTDIR/raw/zap_messages_a.json"
_zap_msgs_b="$OUTDIR/raw/zap_messages_b.json"
_zap_msgs_full="$OUTDIR/raw/zap_messages_full.json"
echo '{"messages":[]}' > "$_zap_msgs_b"   # default vazio → degrada p/ só direção B→A

if zap_api_call "core/view/version" "" 2>/dev/null | grep -q "version"; then
    # Corpus de A: histórico já gravado pelo crawl autenticado da P9 (token A)
    zap_api_call "core/view/messages" "" > "$_zap_msgs_a" 2>/dev/null || true
    _n_a=$(python3 -c "import json,sys
try:
    d=json.load(open(sys.argv[1])); print(len(d.get('messages',[])) if isinstance(d,dict) else 0)
except Exception:
    print(0)" "$_zap_msgs_a" 2>/dev/null || echo 0)

    # Corpus de B: spider-only leve com token B (sem active scan)
    _tb_enc=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1],safe=''))" "Bearer ${TOKEN_B}" 2>/dev/null)
    zap_api_call "replacer/action/removeRule" "description=AuthToken" >/dev/null 2>&1 || true
    zap_api_call "replacer/action/addRule" \
        "description=AuthToken&enabled=true&matchType=REQ_HEADER&matchString=Authorization&replacement=${_tb_enc}" \
        >/dev/null 2>&1
    _tgt_enc=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1],safe=''))" "$TARGET" 2>/dev/null)
    zap_api_call "spider/action/scan" "url=${_tgt_enc}&maxChildren=10" >/dev/null 2>&1
    sleep 20
    # Dump cumulativo e fatia só as mensagens novas (de B) — evita A no corpus_b (FP)
    zap_api_call "core/view/messages" "" > "$_zap_msgs_full" 2>/dev/null || true
    python3 -c "import json,sys
try:
    d=json.load(open(sys.argv[1])); msgs=d.get('messages',[]) if isinstance(d,dict) else []
except Exception:
    msgs=[]
n=int(sys.argv[2])
json.dump({'messages':msgs[n:]}, open(sys.argv[3],'w'))" \
        "$_zap_msgs_full" "$_n_a" "$_zap_msgs_b" 2>/dev/null || echo '{"messages":[]}' > "$_zap_msgs_b"
else
    echo -e "  ${YELLOW}[!] ZAP indisponível — corpus de B vazio (só direção B→A)${NC}"
fi

if [ ! -s "$_zap_msgs_a" ]; then
    echo -e "  ${YELLOW}[!] access-control: sem corpus do ZAP (P9 não rodou?) — BOLA/BFLA pulado${NC}"
else
    if BOLA_TOKEN_A="$TOKEN_A" BOLA_TOKEN_B="$TOKEN_B" \
            python3 "$SCRIPT_DIR/lib/bola.py" run "$_zap_msgs_a" "$_zap_msgs_b" "$OUTDIR"; then
        echo -e "  ${GREEN}[✓] Access Control concluído → access_control.json + raw/access_findings.json${NC}"
    else
        echo -e "  ${YELLOW}[!] access-control: motor BOLA retornou erro${NC}"
    fi
fi
phase_end "P9_5"
phase_done "FASE_9_5"
fi  # fim P9.5

if _phase_enabled "P10"; then
phase_start "P10"
phase_banner "FASE 10/11: ANÁLISE DE JAVASCRIPT & SECRETS"

JS_SECRETS=0
JS_ENDPOINTS=0
JS_FRAMEWORKS=0
JS_FILES=0

python3 "$SCRIPT_DIR/lib/js_analysis.py" "$OUTDIR" "$TARGET" "$DOMAIN"

# Coletar contadores para o relatório
if [ -f "$OUTDIR/raw/js_analysis.json" ]; then
    JS_SECRETS=$(python3 -c "import json; d=json.load(open('$OUTDIR/raw/js_analysis.json')); print(len(d.get('secrets',[])))" 2>/dev/null); JS_SECRETS=${JS_SECRETS:-0}
    JS_ENDPOINTS=$(python3 -c "import json; d=json.load(open('$OUTDIR/raw/js_analysis.json')); print(len(d.get('endpoints',[])))" 2>/dev/null); JS_ENDPOINTS=${JS_ENDPOINTS:-0}
    JS_FRAMEWORKS=$(python3 -c "import json; d=json.load(open('$OUTDIR/raw/js_analysis.json')); print(len(d.get('frameworks',[])))" 2>/dev/null); JS_FRAMEWORKS=${JS_FRAMEWORKS:-0}
    JS_FILES=$(python3 -c "import json; d=json.load(open('$OUTDIR/raw/js_analysis.json')); print(len(d.get('js_files',[])))" 2>/dev/null); JS_FILES=${JS_FILES:-0}
    echo -e "  ${GREEN}[✓] JS: $JS_FILES arquivo(s) | $JS_SECRETS secret(s) | $JS_ENDPOINTS endpoint(s) | $JS_FRAMEWORKS framework(s)${NC}"
fi
# Marcar fase concluída SEMPRE (fora do if) — senão o checkpoint re-executa a P10
# a cada resume quando js_analysis.json não é gerado.
phase_end "P10"
phase_done "FASE_10"

export JS_SECRETS JS_ENDPOINTS JS_FRAMEWORKS JS_FILES


# ====================== FASE 10.5: SMUGGLER + FFUF + TRUFFLEHOG ======================
fi  # fim P10
if _phase_enabled "P10_5"; then
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
    keycloak)
        echo -e "  ${GREEN}[✓]${NC} ffuf: wordlist Keycloak adicionada"
        cat >> "$_custom_wl" << 'KEYCLOAK_PATHS'
realms/master
realms/master/.well-known/openid-configuration
realms/master/protocol/openid-connect/auth
realms/master/protocol/openid-connect/token
realms/master/protocol/openid-connect/userinfo
realms/master/protocol/openid-connect/certs
realms/master/account
realms/master/clients-registrations/openid-connect
admin/
admin/master/console/
admin/realms
admin/serverinfo
metrics
health
health/ready
health/live
.well-known/openid-configuration
KEYCLOAK_PATHS
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
            _joom_items=$(grep -c "^\[!" "$OUTDIR/raw/joomscan.txt" 2>/dev/null); _joom_items=${_joom_items:-0}
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

# Estrutura a saída dos scanners de CMS (wpscan/joomscan/droopescan) em
# cms_findings.json para o relatório agregar — senão só vira link de artefato.
python3 "$SCRIPT_DIR/lib/cms_findings.py" "$OUTDIR" "$TARGET" || true

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

# ── retire.js: bibliotecas JS vulneráveis (SCA client-side, P1) ──
if command -v retire &>/dev/null; then
    if [ -d "$OUTDIR/raw/js_files" ] && \
       [ "$(find "$OUTDIR/raw/js_files" -name "*.js" 2>/dev/null | wc -l)" -gt 0 ]; then
        echo -e "  ${BLUE}[…]${NC} retire.js: verificando libs JS vulneráveis..."
        timeout 60 retire --jspath "$OUTDIR/raw/js_files" --outputformat json \
            --outputpath "$OUTDIR/raw/retire_raw.json" 2>/dev/null || true
        python3 "$SCRIPT_DIR/lib/retire_parse.py" "$OUTDIR" "$TARGET" || true
    else
        echo -e "  ${YELLOW}[○]${NC} retire.js: sem arquivos JS coletados"
    fi
else
    echo -e "  ${YELLOW}[○]${NC} retire.js não instalado — pulando SCA client-side"
    echo -e "  ${YELLOW}    Instale: npm install -g retire${NC}"
fi

# ── Rate Limiting Check ──────────────────────────────────────────
# Sends 20 rapid login attempts and checks for 429 / Retry-After / delays.
# Tests common login paths: /login, /api/login, /api/auth/login, /auth/login.
echo -e "  ${BLUE}[…]${NC} Testando rate limiting em endpoints de login..."
python3 "$SCRIPT_DIR/lib/ratelimit_check.py" "$OUTDIR" "$TARGET"

# ── CORS Preflight Check ─────────────────────────────────────────
# Testa OPTIONS preflight contra TARGET + paths /api e URLs descobertas pelo
# ffuf/katana. Detecta Access-Control-Allow-Origin: * ou eco da origem —
# que o template nuclei cors-misconfig (GET-only) não pega em ASP.NET/Express.
echo -e "  ${BLUE}[…]${NC} Testando CORS via OPTIONS preflight..."
python3 "$SCRIPT_DIR/lib/cors_check.py" "$OUTDIR" "$TARGET"

# ── Nuclei targeted info pass (descoberta passiva alto valor) ────
# Roda templates info-severity de alto sinal contra URLs descobertas pelo
# ffuf + katana. Cobre swagger/openapi expostos, debug endpoints, config
# files e exposures que ficaram fora do filtro severity da fase 4.
if command -v nuclei &>/dev/null; then
    _info_urls="$OUTDIR/raw/nuclei_info_targets.txt"
    : > "$_info_urls"

    # 1. URL raiz sempre incluída
    echo "$TARGET" >> "$_info_urls"

    # 2. Endpoints descobertos pelo ffuf (paths que retornaram 200/301/401/403)
    if [ -s "$OUTDIR/raw/ffuf.json" ]; then
        python3 -c "
import json
try:
    d = json.load(open('$OUTDIR/raw/ffuf.json'))
    for r in d.get('results', []):
        url = r.get('url', '').strip()
        if url.startswith('http'):
            print(url)
except: pass
" >> "$_info_urls" 2>/dev/null || true
    fi

    # 3. URLs do katana (até 50 mais relevantes — limita custo)
    if [ -s "$OUTDIR/raw/katana_urls.txt" ]; then
        head -50 "$OUTDIR/raw/katana_urls.txt" >> "$_info_urls" 2>/dev/null || true
    fi

    sort -u "$_info_urls" -o "$_info_urls"
    _info_url_count=$(wc -l < "$_info_urls" | tr -d ' ')

    if [ "$_info_url_count" -gt 0 ]; then
        echo -e "  ${BLUE}[…]${NC} Nuclei info-pass: ${_info_url_count} URL(s) · tags: exposure,api,debug,config,technologies,backup"
        # Tags focadas em info-severity de alto sinal — evita ruído de banner/lang
        _info_tags="exposure,api,debug,config,technologies,backup,disclosure"
        # NÃO usar NUCLEI_TEMPLATES_FLAGS aqui: passar -t direciona o nuclei a
        # carregar APENAS aquele diretório (desativa auto-load do default). O
        # diretório custom tem poucos templates que não casam com nossos tags.
        timeout 300 nuclei -l "$_info_urls" \
            -tags "$_info_tags" \
            -severity info \
            -rate-limit "$NUCLEI_RATE_LIMIT" -concurrency "$NUCLEI_CONCURRENCY" \
            -timeout 10 "${NUCLEI_OAST_FLAGS[@]}" \
            -jsonl -o "$OUTDIR/raw/nuclei_info.json" \
            > /dev/null 2>>"$OUTDIR/raw/nuclei_error.log" || true

        if [ -s "$OUTDIR/raw/nuclei_info.json" ]; then
            _info_count=$(grep -c . "$OUTDIR/raw/nuclei_info.json" 2>/dev/null); _info_count=${_info_count:-0}
            echo -e "  ${GREEN}[✓]${NC} Nuclei info-pass: ${_info_count} achado(s) extra"
            # Anexar ao nuclei.json principal (mantém compatibilidade do pipeline)
            cat "$OUTDIR/raw/nuclei_info.json" >> "$OUTDIR/raw/nuclei.json"
        else
            echo -e "  ${BLUE}[○]${NC} Nuclei info-pass: nenhum achado adicional"
        fi
        unset _info_count _info_tags
    fi
    unset _info_urls _info_url_count
fi

export SMUGGLER_FOUND FFUF_FOUND TRUFFLEHOG_FOUND AUTH_TOKEN AUTH_HEADER
phase_end "P10_5"
phase_done "FASE_10_5"

# ====================== FASE 11: RELATÓRIO ======================

fi  # fim P10_5
if _phase_enabled "P11"; then
phase_start "P11"
phase_banner "FASE 11/11: GERAÇÃO DE RELATÓRIO"

# Vars sempre válidas (derivadas dos args / disponíveis em qualquer invocação)
AUTH_TOKEN="${AUTH_TOKEN:-}";     AUTH_HEADER="${AUTH_HEADER:-}"
export OUTDIR TARGET DOMAIN SCAN_START_TS IS_SUBDOMAIN AUTH_TOKEN AUTH_HEADER

if [ -z "$ONLY_PHASES" ]; then
    # Run monolítico: os contadores foram calculados em memória pelas fases anteriores.
    # Sanitizar (evita ValueError no Python se vierem como "") e exportar.
    JS_SECRETS="${JS_SECRETS:-0}";    JS_ENDPOINTS="${JS_ENDPOINTS:-0}"
    JS_FRAMEWORKS="${JS_FRAMEWORKS:-0}"; JS_FILES="${JS_FILES:-0}"
    KATANA_URLS="${KATANA_URLS:-0}";  SMUGGLER_FOUND="${SMUGGLER_FOUND:-0}"
    FFUF_FOUND="${FFUF_FOUND:-0}";    TRUFFLEHOG_FOUND="${TRUFFLEHOG_FOUND:-0}"
    ACTIVE_COUNT="${ACTIVE_COUNT:-0}"; SUB_COUNT="${SUB_COUNT:-0}"
    TLS_ISSUES="${TLS_ISSUES:-0}";    CONFIRMED_COUNT="${CONFIRMED_COUNT:-0}"
    EMAIL_ISSUES="${EMAIL_ISSUES:-0}"; OPENAPI_FOUND="${OPENAPI_FOUND:-0}"
    WAF_DETECTED="${WAF_DETECTED:-false}"; WAF_NAME="${WAF_NAME:-}"
    WPSCAN_VULNS="${WPSCAN_VULNS:-0}"
    export OPEN_PORTS ACTIVE_COUNT SUB_COUNT OPENAPI_FOUND TLS_ISSUES CONFIRMED_COUNT \
           JS_SECRETS JS_ENDPOINTS JS_FRAMEWORKS JS_FILES KATANA_URLS WAF_DETECTED WAF_NAME \
           EMAIL_ISSUES SMUGGLER_FOUND FFUF_FOUND TRUFFLEHOG_FOUND WPSCAN_VULNS
fi
# Em modo --only-phase (orquestrador pipeline.py), os contadores NÃO são exportados
# de propósito — o stiglitz_report.py os deriva de raw/* (ver _env_or / _derive_*).

# Usar stiglitz_report.py externo se disponível (manutenção mais fácil)
_report_py="$(dirname "$0")/stiglitz_report.py"
if [ ! -f "$_report_py" ]; then
    _report_py="$(cd "$(dirname "$0")" && pwd)/stiglitz_report.py"
fi

if [ -f "$_report_py" ]; then
    echo -e "  ${BLUE}[…] Gerando relatório (stiglitz_report.py)${NC}"
    if ! python3 "$_report_py"; then
        echo -e "  ${RED}[✗] stiglitz_report.py falhou — relatório HTML não gerado${NC}"
    fi
else
    echo -e "  ${RED}[✗] stiglitz_report.py não encontrado — relatório HTML não gerado${NC}"
    echo -e "  ${YELLOW}    Esperado em: $(dirname "$0")/stiglitz_report.py${NC}"
fi
fi  # fim P11

# ====================== FASE 12: TRACKER SYNC (DefectDojo) ======================

if _phase_enabled "P12"; then
phase_start "P12"
phase_banner "FASE 12: SINCRONIZAÇÃO COM TRACKER (DefectDojo)"

if [[ -n "${DEFECTDOJO_URL:-}" && -n "${DEFECTDOJO_TOKEN:-}" ]]; then
    echo -e "  ${BLUE}[…] Enviando findings para DefectDojo: ${DEFECTDOJO_URL}${NC}"
    if ! python3 "$SCRIPT_DIR/stiglitz_track.py" "$OUTDIR"; then
        echo -e "  ${YELLOW}[!] stiglitz_track.py retornou erro — sync com tracker falhou (não-fatal)${NC}"
    else
        echo -e "  ${GREEN}[✓] Sync com tracker concluído${NC}"
    fi
else
    echo -e "  ${YELLOW}[○] nenhum tracker configurado — pulando (defina DEFECTDOJO_URL e DEFECTDOJO_TOKEN).${NC}"
fi

phase_end "P12"
phase_done "FASE_12"
fi  # fim P12

# ====================== RESUMO FINAL ======================
echo -e "\n${GREEN}════════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  PROCESSO CONCLUÍDO — $(date '+%d/%m/%Y %H:%M:%S')${NC}"
echo -e "${GREEN}════════════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}📁 Resultados  : ${OUTDIR}/${NC}"
echo -e "${CYAN}📄 Relatório   : ${OUTDIR}/stiglitz_report.html${NC}"
echo -e "${CYAN}📊 Exec Summary: ${OUTDIR}/executive_summary.html${NC}"
echo -e "${CYAN}📦 JSON Export : ${OUTDIR}/findings.json${NC}"
echo -e "${CYAN}📦 Dados brutos: ${OUTDIR}/raw/${NC}"
echo ""

# Abrir relatório apenas em modo single-target (batch abre o consolidado no final).
# Destacado em subshell com & para nunca bloquear o término do scan — em WSL/WSLg
# o xdg-open/wslview pode travar em foreground (ex.: execução headless/automação).
[ "${STIGLITZ_BATCH:-0}" = "0" ] && \
    [ -n "$DISPLAY" ] && command -v xdg-open &>/dev/null && \
    ( xdg-open "$OUTDIR/stiglitz_report.html" >/dev/null 2>&1 & )

# ── Notificação ao finalizar ──────────────────────────────────────────────────
# Telegram:      export STIGLITZ_TELEGRAM_TOKEN=<token> STIGLITZ_TELEGRAM_CHAT=<chat_id>
# Slack/generic: export STIGLITZ_NOTIFY_WEBHOOK=https://hooks.slack.com/...
# Teams:         export STIGLITZ_TEAMS_WEBHOOK=https://outlook.office.com/webhook/...
#                (ou URL do Power Automate Workflow)
_stiglitz_notify() {
    local msg="$1"
    local token="${STIGLITZ_TELEGRAM_TOKEN:-}"
    local chat="${STIGLITZ_TELEGRAM_CHAT:-}"
    local webhook="${STIGLITZ_NOTIFY_WEBHOOK:-}"
    local teams="${STIGLITZ_TEAMS_WEBHOOK:-}"

    if [ -n "$token" ] && [ -n "$chat" ]; then
        curl -s -X POST "https://api.telegram.org/bot${token}/sendMessage" \
            -d "chat_id=${chat}" --data-urlencode "text=${msg}" \
            -d "parse_mode=HTML" --max-time 10 >/dev/null 2>&1 || true
    fi

    if [ -n "$teams" ]; then
        local escaped
        escaped=$(echo "$msg" | sed 's/"/\\"/g' | sed 's/$/\\n/' | tr -d '\n')
        curl -s -X POST "$teams" -H "Content-Type: application/json" \
            -d "{\"@type\":\"MessageCard\",\"@context\":\"https://schema.org/extensions\",\"themeColor\":\"0078D4\",\"summary\":\"Stiglitz scan concluído\",\"sections\":[{\"activityTitle\":\"🔍 Stiglitz\",\"activityText\":\"${escaped}\"}]}" \
            --max-time 10 >/dev/null 2>&1 || true
    fi

    if [ -n "$webhook" ]; then
        curl -s -X POST "$webhook" -H "Content-Type: application/json" \
            -d "{\"text\":\"$(echo "$msg" | sed 's/"/\\"/g')\"}" \
            --max-time 10 >/dev/null 2>&1 || true
    fi
}

_n_findings=$(grep -c '"severity":\s*"\(critical\|high\)"' "${OUTDIR}/findings.json" 2>/dev/null); _n_findings=${_n_findings:-0}
_stiglitz_notify "[Stiglitz] Scan concluído
Alvo: ${TARGET:-${DOMAIN}}
Findings críticos/altos: ${_n_findings}
Relatório: ${OUTDIR}/stiglitz_report.html"

exit 0

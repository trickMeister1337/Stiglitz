#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
#  Stiglitz RED — Instalador Universal (Linux / WSL)
# ═══════════════════════════════════════════════════════════════════════════════
#  Instala TODAS as dependências automaticamente. Zero passos manuais.
#  Detecta distro (apt/dnf/pacman/zypper) e WSL automaticamente.
#
#  Uso: bash setup.sh [--force]
#
#  O flag --force reinstala tudo mesmo se já presente.
#  Log completo: ~/.stiglitz-install.log
# ═══════════════════════════════════════════════════════════════════════════════
set -uo pipefail

readonly LOGFILE="$HOME/.stiglitz-install.log"
readonly VENV_DIR="$HOME/.stiglitz-venv"
FORCE=false
[[ "${1:-}" == "--force" ]] && FORCE=true

# Cores
RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[1;33m'; CYN='\033[0;36m'
BLD='\033[1m'; DIM='\033[2m'; RST='\033[0m'

# Contadores
INSTALLED=0; SKIPPED=0; FAILED=0; TOTAL=0

# ═══════════════════════════════════════════════════════════════════════════════
#  LOGGING
# ═══════════════════════════════════════════════════════════════════════════════
exec > >(tee -a "$LOGFILE") 2>&1
echo "════════════════════════════════════════" >> "$LOGFILE"
echo "Stiglitz RED Installer — $(date)" >> "$LOGFILE"
echo "════════════════════════════════════════" >> "$LOGFILE"

banner() {
    echo -e "${RED}"
    cat << 'EOF'
   _____ _       _____    ____  __  ___   ____  __________
  / ___/| |     / /   |  / __ \/  |/  /  / __ \/ ____/ __ \
  \__ \ | | /| / / /| | / /_/ / /|_/ /  / /_/ / __/ / / / /
 ___/ / | |/ |/ / ___ |/ _, _/ /  / /  / _, _/ /___/ /_/ /
/____/  |__/|__/_/  |_/_/ |_/_/  /_/  /_/ |_/_____/_____/
EOF
    echo -e "${RST}"
    echo -e "  ${YLW}Instalador Universal — Linux / WSL${RST}"
    echo -e "  ${DIM}Log: $LOGFILE${RST}"
    echo ""
}

info()  { echo -e "  ${GRN}[✓]${RST} $*"; }
warn()  { echo -e "  ${YLW}[!]${RST} $*"; }
fail()  { echo -e "  ${RED}[✗]${RST} $*"; }
step()  { echo -e "\n${CYN}─── $* ───${RST}"; }
has()   { command -v "$1" &>/dev/null; }

track_result() {
    local name="$1" result="$2"
    ((TOTAL++))
    if [ "$result" = "ok" ]; then
        info "$name instalado com sucesso"
        ((INSTALLED++))
    elif [ "$result" = "skip" ]; then
        info "$name já instalado"
        ((SKIPPED++))
    else
        fail "$name — falha na instalação"
        ((FAILED++))
    fi
}

# ═══════════════════════════════════════════════════════════════════════════════
#  DETECÇÃO DE SISTEMA
# ═══════════════════════════════════════════════════════════════════════════════
DISTRO_ID="unknown"; DISTRO_NAME="Unknown"; PKG_FAMILY="unknown"; IS_WSL=false

detect_system() {
    step "Detectando sistema"

    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO_ID="${ID:-unknown}"
        DISTRO_NAME="${PRETTY_NAME:-unknown}"
    elif has lsb_release; then
        DISTRO_ID=$(lsb_release -si | tr '[:upper:]' '[:lower:]')
        DISTRO_NAME=$(lsb_release -sd)
    fi

    case "$DISTRO_ID" in
        ubuntu|debian|kali|linuxmint|pop|parrot|raspbian|zorin|elementary)
            PKG_FAMILY="apt" ;;
        fedora|rhel|centos|rocky|alma|ol|amzn)
            PKG_FAMILY="dnf"
            has dnf || PKG_FAMILY="yum"
            ;;
        arch|manjaro|endeavouros|garuda)
            PKG_FAMILY="pacman" ;;
        opensuse*|sles)
            PKG_FAMILY="zypper" ;;
        *)
            has apt-get && PKG_FAMILY="apt"
            has dnf     && PKG_FAMILY="dnf"
            has yum     && PKG_FAMILY="yum"
            has pacman  && PKG_FAMILY="pacman"
            has zypper  && PKG_FAMILY="zypper"
            ;;
    esac

    grep -qiE "(microsoft|wsl)" /proc/version 2>/dev/null && IS_WSL=true

    info "Distro:  $DISTRO_NAME ($DISTRO_ID)"
    info "Pacotes: $PKG_FAMILY"
    info "WSL:     $IS_WSL"

    if [ "$PKG_FAMILY" = "unknown" ]; then
        fail "Gerenciador de pacotes não detectado."
        fail "Instale manualmente: python3, curl, git, nmap, jq, nikto, hydra"
        exit 1
    fi
}

# ═══════════════════════════════════════════════════════════════════════════════
#  INSTALADORES BASE
# ═══════════════════════════════════════════════════════════════════════════════

# Verificar se sudo funciona (primeiro passo crítico)
check_sudo() {
    step "Verificando permissões"
    if [ "$(id -u)" -eq 0 ]; then
        info "Executando como root"
        # Criar alias de sudo para root
        sudo() { "$@"; }
        export -f sudo 2>/dev/null || true
        return 0
    fi

    if ! has sudo; then
        fail "sudo não encontrado e não está rodando como root"
        fail "Execute: su -c 'apt-get install sudo' e adicione seu usuário ao grupo sudo"
        exit 1
    fi

    # Testar se sudo funciona sem senha (ou pedir uma vez)
    if ! sudo -n true 2>/dev/null; then
        warn "sudo requer senha — digite sua senha abaixo:"
        if ! sudo true; then
            fail "Falha na autenticação sudo"
            fail "Verifique se seu usuário está no grupo sudo: groups $(whoami)"
            exit 1
        fi
    fi
    info "sudo disponível para $(whoami)"
}

# Esperar apt lock ser liberado (problema comum no WSL quando outro processo trava)
_wait_apt_lock() {
    local max_wait=60 waited=0
    while fuser /var/lib/dpkg/lock-frontend &>/dev/null 2>&1 || \
          fuser /var/lib/apt/lists/lock &>/dev/null 2>&1 || \
          fuser /var/cache/apt/archives/lock &>/dev/null 2>&1; do
        if [ "$waited" -eq 0 ]; then
            warn "Esperando apt lock ser liberado (outro processo usando apt)..."
        fi
        sleep 2
        ((waited+=2))
        if [ "$waited" -ge "$max_wait" ]; then
            warn "Timeout esperando apt lock — tentando forçar..."
            sudo rm -f /var/lib/dpkg/lock-frontend /var/lib/apt/lists/lock /var/cache/apt/archives/lock 2>/dev/null
            sudo dpkg --configure -a 2>/dev/null || true
            break
        fi
    done
}

pkg_update() {
    step "Atualizando índice de pacotes"

    local success=false
    local attempt=0
    local max_attempts=3

    while [ "$attempt" -lt "$max_attempts" ] && [ "$success" = false ]; do
        ((attempt++))
        [ "$attempt" -gt 1 ] && warn "Tentativa $attempt/$max_attempts..."

        case "$PKG_FAMILY" in
            apt)
                _wait_apt_lock
                if sudo apt-get update -qq 2>&1 | tee -a "$LOGFILE"; then
                    success=true
                else
                    local err=$?
                    # Diagnóstico
                    if [ "$err" -eq 100 ]; then
                        warn "Erro de repositório — tentando fix..."
                        # Tentar com --fix-missing
                        sudo apt-get update --fix-missing -qq 2>&1 | tee -a "$LOGFILE" && success=true
                    fi
                fi
                ;;
            dnf)    sudo dnf check-update -q 2>&1 | tee -a "$LOGFILE"; success=true ;;
            yum)    sudo yum check-update -q 2>&1 | tee -a "$LOGFILE"; success=true ;;
            pacman) sudo pacman -Sy --noconfirm 2>&1 | tee -a "$LOGFILE" && success=true ;;
            zypper) sudo zypper refresh -q 2>&1 | tee -a "$LOGFILE" && success=true ;;
        esac

        [ "$success" = false ] && sleep 3
    done

    if [ "$success" = true ]; then
        info "Índice atualizado"
    else
        warn "Falha ao atualizar índice — continuando com cache existente"
    fi
}

pkg_install() {
    local retval=0
    case "$PKG_FAMILY" in
        apt)
            _wait_apt_lock
            sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@" 2>&1 | tee -a "$LOGFILE"
            retval=${PIPESTATUS[0]}
            # Se falhou, tentar fix
            if [ "$retval" -ne 0 ]; then
                warn "apt install falhou — tentando --fix-broken..."
                sudo apt-get install -y --fix-broken 2>&1 | tee -a "$LOGFILE"
                sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@" 2>&1 | tee -a "$LOGFILE"
                retval=${PIPESTATUS[0]}
            fi
            ;;
        dnf)    sudo dnf install -y -q "$@" 2>&1 | tee -a "$LOGFILE"; retval=${PIPESTATUS[0]} ;;
        yum)    sudo yum install -y -q "$@" 2>&1 | tee -a "$LOGFILE"; retval=${PIPESTATUS[0]} ;;
        pacman) sudo pacman -S --noconfirm --needed "$@" 2>&1 | tee -a "$LOGFILE"; retval=${PIPESTATUS[0]} ;;
        zypper) sudo zypper install -y -n "$@" 2>&1 | tee -a "$LOGFILE"; retval=${PIPESTATUS[0]} ;;
    esac
    return $retval
}

pkg_install_any() {
    local names=("$@")
    for name in "${names[@]}"; do
        pkg_install "$name" 2>/dev/null && return 0
    done
    return 1
}

# Clone via git OU download via curl/wget (funciona sem git)
clone_or_download() {
    local url="$1" dest="$2"
    sudo rm -rf "$dest" 2>/dev/null

    # Tentativa 1: git clone
    if has git; then
        if sudo git clone --depth 1 "$url" "$dest" 2>&1 | tee -a "$LOGFILE"; then
            return 0
        fi
    fi

    # Tentativa 2: download do archive via curl
    local archive_url=""
    if echo "$url" | grep -q "github.com"; then
        # GitHub: https://github.com/user/repo → https://github.com/user/repo/archive/refs/heads/master.tar.gz
        archive_url="${url}/archive/refs/heads/master.tar.gz"
        # Alguns repos usam 'main' ao invés de 'master'
    elif echo "$url" | grep -q "gitlab.com"; then
        # GitLab: https://gitlab.com/group/repo → https://gitlab.com/group/repo/-/archive/main/repo-main.tar.gz
        local repo_name
        repo_name=$(basename "$url")
        archive_url="${url}/-/archive/main/${repo_name}-main.tar.gz"
    fi

    if [ -n "$archive_url" ] && has curl; then
        warn "  git indisponível — baixando archive via curl..."
        local tmpfile="/tmp/clone_download_$$.tar.gz"
        local tmpdir="/tmp/clone_extract_$$"

        # Tentar master, depois main
        for branch in master main; do
            local try_url
            if echo "$url" | grep -q "github.com"; then
                try_url="${url}/archive/refs/heads/${branch}.tar.gz"
            elif echo "$url" | grep -q "gitlab.com"; then
                local rn; rn=$(basename "$url")
                try_url="${url}/-/archive/${branch}/${rn}-${branch}.tar.gz"
            fi

            if curl -fsSL -o "$tmpfile" "$try_url" 2>/dev/null; then
                mkdir -p "$tmpdir"
                tar xzf "$tmpfile" -C "$tmpdir" 2>/dev/null
                # Mover o conteúdo extraído (geralmente repo-branch/) para o destino
                local extracted_dir
                extracted_dir=$(find "$tmpdir" -mindepth 1 -maxdepth 1 -type d | head -1)
                if [ -n "$extracted_dir" ] && [ -d "$extracted_dir" ]; then
                    sudo mv "$extracted_dir" "$dest"
                    rm -rf "$tmpfile" "$tmpdir"
                    info "  Baixado e extraído em $dest"
                    return 0
                fi
            fi
        done
        rm -rf "$tmpfile" "$tmpdir"
    fi

    # Tentativa 3: wget
    if [ -n "$archive_url" ] && has wget; then
        warn "  curl falhou — tentando wget..."
        local tmpfile="/tmp/clone_download_$$.tar.gz"
        wget -q -O "$tmpfile" "${archive_url}" 2>/dev/null
        if [ -f "$tmpfile" ] && [ -s "$tmpfile" ]; then
            local tmpdir="/tmp/clone_extract_$$"
            mkdir -p "$tmpdir"
            tar xzf "$tmpfile" -C "$tmpdir" 2>/dev/null
            local extracted_dir
            extracted_dir=$(find "$tmpdir" -mindepth 1 -maxdepth 1 -type d | head -1)
            if [ -n "$extracted_dir" ]; then
                sudo mv "$extracted_dir" "$dest"
                rm -rf "$tmpfile" "$tmpdir"
                return 0
            fi
        fi
        rm -rf "$tmpfile" "/tmp/clone_extract_$$"
    fi

    fail "  Não conseguiu clonar/baixar: $url"
    return 1
}

# ═══════════════════════════════════════════════════════════════════════════════
#  FERRAMENTAS BASE
# ═══════════════════════════════════════════════════════════════════════════════
install_base_tools() {
    step "Ferramentas base"

    local base_pkgs=()
    case "$PKG_FAMILY" in
        apt)     base_pkgs=(git curl jq wget whois dnsutils python3 python3-pip python3-venv build-essential libffi-dev) ;;
        dnf|yum) base_pkgs=(git curl jq wget whois bind-utils python3 python3-pip gcc libffi-devel) ;;
        pacman)  base_pkgs=(git curl jq wget whois bind python python-pip base-devel) ;;
        zypper)  base_pkgs=(git curl jq wget whois bind-utils python3 python3-pip gcc libffi-devel) ;;
    esac

    # Instalar tudo de uma vez primeiro (mais rápido)
    warn "Instalando pacotes base..."
    pkg_install "${base_pkgs[@]}" || true

    # Verificar cada ferramenta individualmente e tentar fix se falhou
    local critical_tools=(git curl python3)
    local optional_tools=(jq wget)

    for tool in "${critical_tools[@]}"; do
        if has "$tool"; then
            track_result "$tool" "skip"
        else
            warn "$tool não instalou — tentando individualmente..."
            # Tentativa individual
            pkg_install "$tool" || true

            if ! has "$tool"; then
                # Diagnóstico
                fail "$tool FALHOU — diagnóstico:"
                case "$PKG_FAMILY" in
                    apt)
                        echo "    Verificando..." | tee -a "$LOGFILE"
                        apt-cache show "$tool" 2>&1 | head -3 | tee -a "$LOGFILE"
                        sudo apt-get install -y "$tool" 2>&1 | tail -5 | tee -a "$LOGFILE"
                        ;;
                esac

                # Se é git, tentar alternativas
                if [ "$tool" = "git" ]; then
                    warn "Tentando instalar git por métodos alternativos..."

                    # Método 1: software-properties + PPA
                    if [ "$PKG_FAMILY" = "apt" ]; then
                        pkg_install software-properties-common || true
                        sudo add-apt-repository -y ppa:git-core/ppa 2>/dev/null || true
                        sudo apt-get update -qq 2>/dev/null || true
                        pkg_install git || true
                    fi

                    # Método 2: compilar do source (último recurso)
                    if ! has git; then
                        warn "Compilando git do source..."
                        pkg_install make gcc libssl-dev libcurl4-gnutls-dev libexpat1-dev gettext zlib1g-dev 2>/dev/null || true
                        (
                            cd /tmp
                            curl -fsSL "https://mirrors.edge.kernel.org/pub/software/scm/git/git-2.44.0.tar.gz" -o git.tar.gz 2>/dev/null
                            tar xzf git.tar.gz 2>/dev/null
                            cd git-2.44.0 2>/dev/null
                            make prefix=/usr/local -j"$(nproc)" 2>/dev/null
                            sudo make prefix=/usr/local install 2>/dev/null
                            cd /tmp && rm -rf git-2.44.0 git.tar.gz
                        ) 2>&1 | tee -a "$LOGFILE" || true
                    fi

                    # Método 3: binário estático
                    if ! has git; then
                        warn "Baixando binário estático do git..."
                        local arch
                        arch=$(uname -m)
                        case "$arch" in
                            x86_64)  arch="amd64" ;;
                            aarch64) arch="arm64" ;;
                        esac
                        curl -fsSL "https://github.com/git/git/releases/latest" -o /dev/null 2>/dev/null || true
                        # conda/mamba fallback
                        if has conda; then
                            conda install -y git 2>/dev/null || true
                        fi
                    fi
                fi

                has "$tool" && track_result "$tool" "ok" || track_result "$tool" "fail"
            else
                track_result "$tool" "ok"
            fi
        fi
    done

    for tool in "${optional_tools[@]}"; do
        if has "$tool"; then
            track_result "$tool" "skip"
        else
            pkg_install "$tool" 2>/dev/null || true
            has "$tool" && track_result "$tool" "ok" || track_result "$tool" "fail"
        fi
    done
}

# ═══════════════════════════════════════════════════════════════════════════════
#  PYTHON VENV
# ═══════════════════════════════════════════════════════════════════════════════
install_python_env() {
    step "Python venv + dependências"

    if [ -f "$VENV_DIR/bin/python3" ] && [ "$FORCE" = false ]; then
        track_result "python-venv" "skip"
    else
        if ! python3 -m venv --help &>/dev/null; then
            case "$PKG_FAMILY" in
                apt) pkg_install python3-venv ;;
                *)   : ;;
            esac
        fi

        rm -rf "$VENV_DIR"
        python3 -m venv "$VENV_DIR"

        if [ -f "$VENV_DIR/bin/python3" ]; then
            track_result "python-venv" "ok"
        else
            track_result "python-venv" "fail"
            return 1
        fi
    fi

    warn "Instalando pacotes Python no venv..."
    "$VENV_DIR/bin/pip" install --quiet --upgrade pip 2>/dev/null
    "$VENV_DIR/bin/pip" install --quiet \
        requests jinja2 python-docx pdfminer.six colorama 2>/dev/null

    if "$VENV_DIR/bin/python3" -c "import requests, jinja2, docx, pdfminer, colorama" 2>/dev/null; then
        info "Pacotes Python: requests, jinja2, python-docx, pdfminer, colorama"
    else
        fail "Alguns pacotes Python não instalaram corretamente"
    fi
}

# ═══════════════════════════════════════════════════════════════════════════════
#  NMAP
# ═══════════════════════════════════════════════════════════════════════════════
install_nmap() {
    step "Nmap"
    if has nmap && [ "$FORCE" = false ]; then
        track_result "nmap" "skip"; return 0
    fi
    pkg_install nmap
    has nmap && track_result "nmap" "ok" || track_result "nmap" "fail"
}

# ═══════════════════════════════════════════════════════════════════════════════
#  SQLMAP (3 tentativas: pacote → git clone → pip)
# ═══════════════════════════════════════════════════════════════════════════════
install_sqlmap() {
    step "sqlmap"
    if has sqlmap && [ "$FORCE" = false ]; then
        track_result "sqlmap" "skip"; return 0
    fi

    # Tentativa 1: pacote do sistema
    pkg_install sqlmap 2>/dev/null

    # Tentativa 2: clone/download do GitHub
    if ! has sqlmap; then
        warn "Pacote não disponível — obtendo do GitHub..."
        if clone_or_download "https://github.com/sqlmapproject/sqlmap" "/opt/sqlmap"; then
            sudo chmod +x /opt/sqlmap/sqlmap.py
            sudo ln -sf /opt/sqlmap/sqlmap.py /usr/local/bin/sqlmap
        fi
    fi

    # Tentativa 3: pip
    if ! has sqlmap; then
        warn "Clone falhou — tentando via pip..."
        "$VENV_DIR/bin/pip" install sqlmap --quiet 2>/dev/null
        [ -f "$VENV_DIR/bin/sqlmap" ] && sudo ln -sf "$VENV_DIR/bin/sqlmap" /usr/local/bin/sqlmap 2>/dev/null || true
    fi

    has sqlmap && track_result "sqlmap" "ok" || track_result "sqlmap" "fail"
}

# ═══════════════════════════════════════════════════════════════════════════════
#  HYDRA (3 tentativas: pacote → pacote alt → compilar)
# ═══════════════════════════════════════════════════════════════════════════════
install_hydra() {
    step "Hydra"
    if has hydra && [ "$FORCE" = false ]; then
        track_result "hydra" "skip"; return 0
    fi

    # Tentativa 1: pacote
    pkg_install_any hydra thc-hydra 2>/dev/null

    # Tentativa 2: compilar
    if ! has hydra; then
        warn "Pacote não disponível — compilando do source..."
        local build_dir="/tmp/hydra-build-$$"
        (
            set -e
            case "$PKG_FAMILY" in
                apt)     pkg_install libssl-dev libssh-dev libidn11-dev libpcre3-dev libmysqlclient-dev libpq-dev 2>/dev/null || true ;;
                dnf|yum) pkg_install openssl-devel libssh-devel libidn-devel pcre-devel mysql-devel postgresql-devel 2>/dev/null || true ;;
                pacman)  pkg_install openssl libssh libidn pcre mariadb-libs postgresql-libs 2>/dev/null || true ;;
            esac
            clone_or_download "https://github.com/vanhauser-thc/thc-hydra" "$build_dir"
            cd "$build_dir"
            ./configure --prefix=/usr/local 2>/dev/null
            make -j"$(nproc)" 2>/dev/null
            sudo make install 2>/dev/null
        ) 2>&1 | tee -a "$LOGFILE" || true
        rm -rf "$build_dir"
    fi

    has hydra && track_result "hydra" "ok" || track_result "hydra" "fail"
}

# ═══════════════════════════════════════════════════════════════════════════════
#  NIKTO (2 tentativas: pacote → git clone)
# ═══════════════════════════════════════════════════════════════════════════════
install_nikto() {
    step "Nikto"
    if has nikto && [ "$FORCE" = false ]; then
        track_result "nikto" "skip"; return 0
    fi

    # Tentativa 1: pacote
    pkg_install nikto 2>/dev/null

    # Tentativa 2: clone/download
    if ! has nikto; then
        warn "Pacote não disponível — obtendo do GitHub..."
        has perl || pkg_install_any perl perl-base 2>/dev/null || true
        if clone_or_download "https://github.com/sullo/nikto" "/opt/nikto"; then
            if [ -f /opt/nikto/program/nikto.pl ]; then
                sudo chmod +x /opt/nikto/program/nikto.pl
                sudo ln -sf /opt/nikto/program/nikto.pl /usr/local/bin/nikto
            fi
        fi
    fi

    has nikto && track_result "nikto" "ok" || track_result "nikto" "fail"
}

# ═══════════════════════════════════════════════════════════════════════════════
#  SEARCHSPLOIT (3 tentativas: pacote → git clone + config → wrapper API)
# ═══════════════════════════════════════════════════════════════════════════════
install_searchsploit() {
    step "searchsploit (ExploitDB)"
    if has searchsploit && [ "$FORCE" = false ]; then
        track_result "searchsploit" "skip"; return 0
    fi

    # Tentativa 1: pacote do sistema (Kali/Parrot/Debian)
    if [ "$DISTRO_ID" = "kali" ] || [ "$DISTRO_ID" = "parrot" ]; then
        pkg_install exploitdb 2>/dev/null
    else
        pkg_install_any exploitdb exploit-db 2>/dev/null || true
    fi

    # Tentativa 2: clone/download do repositório oficial
    if ! has searchsploit; then
        warn "Pacote não disponível — obtendo ExploitDB..."

        local EXPLOITDB_DIR="/opt/exploitdb"
        if clone_or_download "https://gitlab.com/exploit-database/exploitdb" "$EXPLOITDB_DIR"; then
            if [ -f "$EXPLOITDB_DIR/searchsploit" ]; then
                sudo chmod +x "$EXPLOITDB_DIR/searchsploit"
                sudo ln -sf "$EXPLOITDB_DIR/searchsploit" /usr/local/bin/searchsploit
            fi

            # Configurar .searchsploit_rc
            cat > "$HOME/.searchsploit_rc" << RCEOF
## searchsploit — gerado por Stiglitz RED setup.sh
package_array=()
package_array+=("exploitdb")
path_array=()
path_array+=("${EXPLOITDB_DIR}")
colour_tag_2="blue"
colour_tag_1="red"
colour_id="cyan"
colour_results="white"
colour_title="green"
colour_default="reset"
RCEOF
            info "Configuração criada: $HOME/.searchsploit_rc"
        fi
    fi

    # Tentativa 3: wrapper Python que busca via ExploitDB web
    if ! has searchsploit; then
        warn "Clone falhou — criando wrapper com busca ExploitDB web..."

        sudo tee /usr/local/bin/searchsploit > /dev/null << 'WRAPPER'
#!/usr/bin/env python3
"""searchsploit wrapper — busca ExploitDB via web (fallback Stiglitz RED)"""
import sys, json, re, urllib.request, urllib.parse

def search(query):
    encoded = urllib.parse.quote_plus(query)

    # Tentar JSON output via site
    url = f"https://www.exploit-db.com/search?q={encoded}"
    headers = {"User-Agent": "searchsploit-stiglitz/1.0", "Accept": "application/json"}

    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=15) as resp:
            html = resp.read().decode("utf-8", errors="ignore")

        # Parsear resultados
        titles = re.findall(
            r'href="/exploits/(\d+)"[^>]*>\s*([^<]+)', html
        )

        if "--json" in sys.argv:
            results = [{"id": eid, "Title": title.strip()} for eid, title in titles[:30]]
            json.dump({"RESULTS_EXPLOIT": results}, sys.stdout, indent=2)
            print()
        elif titles:
            print(f"\n  Exploit DB — {len(titles)} resultado(s) para: {query}\n")
            print(f"  {'EDB-ID':>10}  |  {'Título'}")
            print(f"  {'-'*10}  |  {'-'*55}")
            for eid, title in titles[:30]:
                print(f"  {eid:>10}  |  {title.strip()[:55]}")
            print(f"\n  Detalhes: https://www.exploit-db.com/search?q={encoded}")
        else:
            print(f"  Nenhum exploit encontrado para: {query}")

    except Exception as e:
        if "--json" in sys.argv:
            json.dump({"RESULTS_EXPLOIT": [], "error": str(e)}, sys.stdout)
            print()
        else:
            print(f"  Erro na busca: {e}")
            print(f"  Busque manualmente: https://www.exploit-db.com/search?q={encoded}")

if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if not args:
        print("Uso: searchsploit <termo> [--json]")
        sys.exit(1)
    search(" ".join(args))
WRAPPER
        sudo chmod +x /usr/local/bin/searchsploit
        info "Wrapper searchsploit criado em /usr/local/bin/searchsploit"
    fi

    has searchsploit && track_result "searchsploit" "ok" || track_result "searchsploit" "fail"
}

# ═══════════════════════════════════════════════════════════════════════════════
#  SECLISTS (wordlists para brute force)
# ═══════════════════════════════════════════════════════════════════════════════
install_seclists() {
    step "SecLists (wordlists)"

    if [ -d "/usr/share/seclists" ] || [ -d "/opt/SecLists" ]; then
        if [ "$FORCE" = false ]; then
            track_result "seclists" "skip"; return 0
        fi
    fi

    # Tentativa 1: pacote (Kali/Parrot)
    pkg_install seclists 2>/dev/null

    # Tentativa 2: clone/download do GitHub
    if [ ! -d "/usr/share/seclists" ] && [ ! -d "/opt/SecLists" ]; then
        warn "Pacote não disponível — obtendo SecLists do GitHub..."
        warn "  (download ~400MB — necessário para wordlists de brute force)"
        clone_or_download "https://github.com/danielmiessler/SecLists" "/opt/SecLists" || true
    fi

    # Descompactar rockyou.txt.gz se presente
    local rockyou="/usr/share/wordlists/rockyou.txt"
    if [ -f "${rockyou}.gz" ] && [ ! -f "$rockyou" ]; then
        warn "Descompactando rockyou.txt.gz..."
        sudo gunzip -k "${rockyou}.gz" 2>/dev/null || true
    fi

    if [ -d "/usr/share/seclists" ] || [ -d "/opt/SecLists" ]; then
        track_result "seclists" "ok"
    else
        warn "SecLists não instalado — wordlists embutidas serão usadas como fallback"
        track_result "seclists" "fail"
    fi
}

# ═══════════════════════════════════════════════════════════════════════════════
#  POSTGRESQL (dependência Metasploit DB)
# ═══════════════════════════════════════════════════════════════════════════════
install_postgresql() {
    step "PostgreSQL (para Metasploit DB)"
    if has psql && [ "$FORCE" = false ]; then
        track_result "postgresql" "skip"
    else
        case "$PKG_FAMILY" in
            apt)     pkg_install postgresql postgresql-client 2>/dev/null ;;
            dnf|yum) pkg_install postgresql-server postgresql 2>/dev/null ;;
            pacman)  pkg_install postgresql 2>/dev/null ;;
            zypper)  pkg_install postgresql postgresql-server 2>/dev/null ;;
        esac
        has psql && track_result "postgresql" "ok" || track_result "postgresql" "fail"
    fi

    # Garantir que está rodando
    if has psql; then
        if [ "$IS_WSL" = true ]; then
            sudo service postgresql start 2>/dev/null \
                || sudo /etc/init.d/postgresql start 2>/dev/null \
                || true
        else
            sudo systemctl enable postgresql 2>/dev/null || true
            sudo systemctl start postgresql 2>/dev/null \
                || sudo service postgresql start 2>/dev/null \
                || true
        fi
    fi
}

# ═══════════════════════════════════════════════════════════════════════════════
#  METASPLOIT (3 tentativas: pacote → Rapid7 installer → snap)
# ═══════════════════════════════════════════════════════════════════════════════
install_metasploit() {
    step "Metasploit Framework"
    if has msfconsole && [ "$FORCE" = false ]; then
        track_result "metasploit" "skip"; return 0
    fi

    # Tentativa 1: pacote (Kali/Parrot)
    if [ "$DISTRO_ID" = "kali" ] || [ "$DISTRO_ID" = "parrot" ]; then
        pkg_install metasploit-framework 2>/dev/null
    fi

    # Tentativa 2: instalador oficial Rapid7
    if ! has msfconsole; then
        warn "Instalando via script oficial Rapid7..."
        local installer="/tmp/msfinstall_$$"
        if curl -fsSL -o "$installer" \
            "https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb" 2>/dev/null; then
            chmod 755 "$installer"
            sudo "$installer" 2>/dev/null || true
            rm -f "$installer"
        fi

        # Adicionar ao PATH se instalou em /opt
        if [ -f /opt/metasploit-framework/bin/msfconsole ]; then
            export PATH="/opt/metasploit-framework/bin:$PATH"
        fi
    fi

    # Tentativa 3: snap
    if ! has msfconsole && has snap; then
        warn "Tentando via snap..."
        sudo snap install metasploit-framework 2>/dev/null || true
    fi

    if has msfconsole; then
        track_result "metasploit" "ok"
        # Inicializar DB
        if has msfdb; then
            warn "Inicializando banco do Metasploit..."
            if [ "$IS_WSL" = true ]; then
                # WSL precisa que PostgreSQL esteja rodando
                if has pg_isready && ! pg_isready -q 2>/dev/null; then
                    sudo service postgresql start 2>/dev/null || true
                    sleep 2
                fi
            fi
            sudo msfdb init 2>/dev/null || true
            info "Banco do Metasploit inicializado"
        fi
    else
        track_result "metasploit" "fail"
    fi
}

# ═══════════════════════════════════════════════════════════════════════════════
#  GO + FERRAMENTAS GO (subfinder, httpx, katana, ffuf, dalfox, waybackurls)
# ═══════════════════════════════════════════════════════════════════════════════
install_go() {
    step "Go (runtime para ferramentas ProjectDiscovery)"

    if has go && [ "$FORCE" = false ]; then
        track_result "go" "skip"; return 0
    fi

    # Tentativa 1: pacote do sistema
    pkg_install_any golang golang-go 2>/dev/null

    # Tentativa 2: binário oficial do golang.org
    if ! has go; then
        warn "Instalando Go via binário oficial..."
        local arch="amd64"
        [ "$(uname -m)" = "aarch64" ] && arch="arm64"
        local go_ver="1.22.2"
        local go_tar="/tmp/go${go_ver}.linux-${arch}.tar.gz"
        curl -fsSL -o "$go_tar" \
            "https://go.dev/dl/go${go_ver}.linux-${arch}.tar.gz" 2>/dev/null || true

        if [ -f "$go_tar" ] && [ -s "$go_tar" ]; then
            sudo rm -rf /usr/local/go
            sudo tar -C /usr/local -xzf "$go_tar" 2>/dev/null
            export PATH="/usr/local/go/bin:$PATH"
            rm -f "$go_tar"
        fi
    fi

    has go && track_result "go" "ok" || track_result "go" "fail"

    # Garantir GOPATH e ~/go/bin no PATH imediato
    export GOPATH="${GOPATH:-$HOME/go}"
    export PATH="$GOPATH/bin:/usr/local/go/bin:$PATH"
    mkdir -p "$GOPATH/bin"
}

_go_install() {
    local name="$1" pkg="$2"
    has go || { warn "$name: go não disponível"; track_result "$name" "fail"; return 1; }
    if has "$name" && [ "$FORCE" = false ]; then
        track_result "$name" "skip"; return 0
    fi
    warn "Instalando $name via go install..."
    go install "$pkg" 2>&1 | tee -a "$LOGFILE" || true
    has "$name" && track_result "$name" "ok" || track_result "$name" "fail"
}

install_go_tools() {
    step "Ferramentas Go (ProjectDiscovery + dalfox + ffuf)"

    install_go

    # ProjectDiscovery
    _go_install subfinder     "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    _go_install httpx          "github.com/projectdiscovery/httpx/cmd/httpx@latest"
    _go_install katana         "github.com/projectdiscovery/katana/cmd/katana@latest"
    _go_install nuclei         "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    _go_install waybackurls    "github.com/tomnomnom/waybackurls@latest"

    # ffuf
    _go_install ffuf           "github.com/ffuf/ffuf/v2@latest"

    # dalfox (XSS scanner)
    _go_install dalfox         "github.com/hahwul/dalfox/v2@latest"

    info "Ferramentas Go instaladas"
}

install_arjun() {
    step "Arjun (descoberta de parâmetros)"
    if has arjun && [ "$FORCE" = false ]; then
        track_result "arjun" "skip"; return 0
    fi
    # Tentativa 1: pip3 com --break-system-packages (Debian/Ubuntu moderno)
    pip3 install arjun --break-system-packages --quiet 2>/dev/null \
        || pip3 install arjun --quiet 2>/dev/null \
        || pip install arjun --quiet 2>/dev/null \
        || true

    # Garantir ~/.local/bin no PATH
    export PATH="$HOME/.local/bin:$PATH"

    has arjun && track_result "arjun" "ok" || track_result "arjun" "fail"
}

# ═══════════════════════════════════════════════════════════════════════════════
#  PATH + WSL CONFIG
# ═══════════════════════════════════════════════════════════════════════════════
configure_path() {
    step "Configurando PATH"
    local extra_paths=(
        "/opt/metasploit-framework/bin"
        "/opt/exploitdb"
        "$HOME/go/bin"
        "$HOME/.local/bin"
        "/usr/local/bin"
    )

    local shell_rc="$HOME/.bashrc"
    [ -f "$HOME/.zshrc" ] && shell_rc="$HOME/.zshrc"

    local added=0
    for p in "${extra_paths[@]}"; do
        if [ -d "$p" ] && ! grep -qF "$p" "$shell_rc" 2>/dev/null; then
            echo "export PATH=\"$p:\$PATH\"" >> "$shell_rc"
            export PATH="$p:$PATH"
            ((added++))
        fi
    done

    [ "$added" -gt 0 ] && info "$added path(s) adicionado(s) em $shell_rc" || info "PATH já configurado"
}

configure_wsl() {
    [ "$IS_WSL" = false ] && return 0
    step "Configuração específica WSL"

    local shell_rc="$HOME/.bashrc"
    [ -f "$HOME/.zshrc" ] && shell_rc="$HOME/.zshrc"

    if ! grep -q "JAVA_TOOL_OPTIONS" "$shell_rc" 2>/dev/null; then
        cat >> "$shell_rc" << 'ENVEOF'

# Stiglitz RED — Headless config para WSL
export JAVA_TOOL_OPTIONS="-Djava.awt.headless=true"
ENVEOF
        info "Variáveis headless configuradas"
    fi

    if [ -f /run/systemd/system ]; then
        info "systemd ativo no WSL"
    else
        warn "systemd não detectado — configurando automaticamente..."

        # Auto-habilitar systemd no WSL
        local wsl_conf="/etc/wsl.conf"
        if [ ! -f "$wsl_conf" ] || ! grep -q "systemd" "$wsl_conf" 2>/dev/null; then
            sudo tee -a "$wsl_conf" > /dev/null << 'WSLEOF'

[boot]
systemd=true
WSLEOF
            info "systemd habilitado em /etc/wsl.conf"
            warn "Para ativar, feche o WSL e execute no PowerShell:"
            warn "  wsl --shutdown"
            warn "Depois abra o WSL novamente e rode: bash setup.sh"
        else
            warn "systemd já configurado em /etc/wsl.conf mas não ativo"
            warn "Execute no PowerShell: wsl --shutdown (e abra novamente)"
        fi

        # Enquanto systemd não está ativo, iniciar serviços manualmente
        if has pg_isready && ! pg_isready -q 2>/dev/null; then
            warn "Iniciando PostgreSQL manualmente..."
            sudo service postgresql start 2>/dev/null \
                || sudo /etc/init.d/postgresql start 2>/dev/null \
                || true
        fi
    fi
}

# ═══════════════════════════════════════════════════════════════════════════════
#  VERIFICAÇÃO FINAL
# ═══════════════════════════════════════════════════════════════════════════════
verify_install() {
    echo ""
    echo -e "${CYN}═══════════════════════════════════════════════════════════════${RST}"
    echo -e "${CYN}  VERIFICAÇÃO FINAL${RST}"
    echo -e "${CYN}═══════════════════════════════════════════════════════════════${RST}"
    echo ""

    local tools=(
        "python3:Obrigatório"
        "curl:Obrigatório"
        "git:Obrigatório"
        "nmap:Port scanning"
        "sqlmap:SQL Injection"
        "dalfox:XSS scanning"
        "subfinder:Recon subdomínios"
        "httpx:HTTP probe"
        "katana:Crawler"
        "ffuf:Fuzzing"
        "arjun:Parâmetros"
        "hydra:Brute force"
        "nikto:Web scanner"
        "msfconsole:Metasploit"
        "searchsploit:ExploitDB"
        "jq:JSON processing"
    )

    local ok=0 missing=0

    for entry in "${tools[@]}"; do
        local tool="${entry%%:*}"
        local desc="${entry##*:}"

        if has "$tool"; then
            local path ver=""
            path=$(which "$tool" 2>/dev/null)
            case "$tool" in
                python3)    ver="$(python3 --version 2>/dev/null)" ;;
                msfconsole) ver="$(msfconsole --version 2>/dev/null | head -1)" ;;
                nmap)       ver="$(nmap --version 2>/dev/null | head -1 | grep -oP 'Nmap \S+' || true)" ;;
                jq)         ver="$(jq --version 2>/dev/null)" ;;
            esac
            echo -e "  ${GRN}[✓]${RST} ${BLD}$tool${RST}  ${DIM}($desc)${RST}  →  $path ${DIM}$ver${RST}"
            ((ok++))
        else
            echo -e "  ${RED}[✗]${RST} ${BLD}$tool${RST}  ${DIM}($desc)${RST}  →  NÃO ENCONTRADO"
            ((missing++))
        fi
    done

    echo ""
    if [ -f "$VENV_DIR/bin/python3" ]; then
        local pip_count
        pip_count=$("$VENV_DIR/bin/pip" list 2>/dev/null | wc -l)
        echo -e "  ${GRN}[✓]${RST} ${BLD}Python venv${RST}  →  $VENV_DIR  ${DIM}($pip_count pacotes)${RST}"
    else
        echo -e "  ${RED}[✗]${RST} ${BLD}Python venv${RST}  →  NÃO ENCONTRADO"
        ((missing++))
    fi

    echo ""
    echo -e "${CYN}═══════════════════════════════════════════════════════════════${RST}"
    echo -e "  ${GRN}Instalados: $ok${RST}  |  ${RED}Faltando: $missing${RST}  |  Total: $((ok + missing))"
    echo -e "${CYN}═══════════════════════════════════════════════════════════════${RST}"
    echo ""

    if [ "$missing" -eq 0 ]; then
        echo -e "  ${GRN}${BLD}✅ Instalação completa!${RST}"
    elif [ "$missing" -le 2 ]; then
        echo -e "  ${YLW}${BLD}⚠  Quase completo — $missing ferramenta(s) faltando${RST}"
        echo -e "  ${DIM}O Stiglitz RED funciona sem elas (fases correspondentes desabilitadas)${RST}"
    else
        echo -e "  ${RED}${BLD}❌ $missing ferramentas faltando${RST}"
        echo -e "  ${DIM}Verifique o log: $LOGFILE${RST}"
    fi

    echo ""
    echo -e "  ${DIM}Próximo passo:${RST}  ${BLD}bash stiglitz_red.sh --help${RST}"
    echo -e "  ${DIM}Testar:${RST}         ${BLD}bash tests/test_stiglitz_red.sh${RST}"
    echo -e "  ${DIM}Integração:${RST}     ${BLD}python3 -m pytest tests/test_integration.py${RST}"
    echo ""
}

# ═══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════════════════════
main() {
    banner
    detect_system

    [ "$FORCE" = true ] && warn "Modo --force: reinstalando tudo" && echo ""

    check_sudo
    pkg_update
    install_base_tools
    install_python_env
    install_nmap
    install_sqlmap
    install_hydra
    install_nikto
    install_searchsploit
    install_seclists
    install_postgresql
    install_metasploit
    install_go_tools
    install_arjun
    configure_path
    configure_wsl
    verify_install
}

main "$@"

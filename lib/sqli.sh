#!/usr/bin/env bash
# Stiglitz RED — Fase SQLi (sqlmap)
# Detecção real de SQLi — sem falsos positivos.
# Chamado por: stiglitz_red.sh run_sqli()

set -uo pipefail

# ── Detecção real de injeção ──────────────────────────────────────────────────
# Só marca VULNERABLE com confirmação explícita do sqlmap.
_sqli_confirmed() {
    local log="$1"
    grep -qiE \
        "identified the following injection point|Parameter:.+appears to be.+injectable|Type: (Boolean|Error|Time|Union|Stacked)" \
        "$log" 2>/dev/null
}

_sqli_get_dbms() {
    grep -oiE "back-end DBMS is [^\n]+" "$1" 2>/dev/null | head -1 \
        | sed 's/back-end DBMS is //'
}

_sqli_get_type() {
    grep -oiE "Type: [^\n]+" "$1" 2>/dev/null \
        | awk '{print $2}' | sort -u | tr '\n' ',' | sed 's/,$//'
}

# ── Tamper adaptativo por WAF detectado ──────────────────────────────────────
_tamper_for_waf() {
    case "${WAF_NAME:-none}" in
        *[Cc]loudflare*)   echo "between,randomcase,space2comment,charunicodeencode" ;;
        *[Mm]od[Ss]ecurity*|*[Oo][Ww][Aa][Ss][Pp]*) echo "space2morehash,between,percentage,charencode" ;;
        *[Aa][Ww][Ss]*|*[Cc]loud[Ff]ront*)           echo "space2comment,between,randomcase,charunicodeencode" ;;
        *[Aa]kamai*)       echo "between,space2comment,charunicodeencode,randomcase" ;;
        *[Ii]mperva*|*[Ii]ncapsula*) echo "space2comment,between,charunicodeencode,equaltolike" ;;
        *[Ff]5*|*[Bb]ig[Ii][Pp]*)   echo "space2comment,between,percentage,charencode" ;;
        *)                 echo "space2comment,between" ;;
    esac
}

# ── Runner principal ──────────────────────────────────────────────────────────
# Assinatura nova: run_sqli_phase(scored_file, sqlmap_dir, confirmed_csv,
#                                  level, risk, threads, max, timeout,
#                                  auth_cookie, auth_header)
run_sqli_phase() {
    local scored_file="$1"
    local sqlmap_dir="$2"
    local confirmed_csv="$3"
    local level="${4:-1}"
    local risk="${5:-1}"
    local threads="${6:-1}"
    local max="${7:-10}"
    local timeout_url="${8:-120}"
    local auth_cookie="${9:-}"
    local auth_header="${10:-}"

    mkdir -p "$sqlmap_dir"

    if [ ! -f "$scored_file" ] || [ ! -s "$scored_file" ]; then
        echo "[sqli] Sem URLs para testar"
        return 0
    fi

    # Filtrar URLs com parâmetros (score > 0 e tem '?')
    local sqli_targets="$sqlmap_dir/sqli_targets.txt"
    awk -F'|' '$2 ~ /[?&]/ {print $2}' "$scored_file" | head -"$max" > "$sqli_targets" || true

    local n_targets
    n_targets=$(wc -l < "$sqli_targets" 2>/dev/null || echo 0)
    echo "[sqli] $n_targets URL(s) com parâmetros | level=$level risk=$risk threads=$threads"

    if [ "$n_targets" -eq 0 ]; then
        echo "[sqli] Sem URLs com parâmetros — nada a testar"
        return 0
    fi

    local tamper; tamper=$(_tamper_for_waf)
    # Técnica por perfil: production NUNCA usa Stacked queries (S),
    # que permitem INSERT/UPDATE/DROP. Só técnicas read-only de confirmação.
    local technique
    case "${PROFILE:-lab}" in
        production) technique="BEU" ;;     # boolean, error, union — somente leitura
        staging)    technique="BEUT" ;;    # + time-based, sem stacked
        *)          technique="BEUSTQ" ;;  # lab — todas as técnicas
    esac
    local tested=0 vuln=0

    while IFS= read -r url; do
        [ -z "$url" ] && continue
        ((tested++))

        local hash; hash=$(printf '%s' "$url" | md5sum | cut -c1-8)
        local log_file="$sqlmap_dir/${hash}_output.log"
        local out_dir="$sqlmap_dir/${hash}"

        echo "[sqli] [$tested/$n_targets] $url"

        if [ "${DRY_RUN:-false}" = true ]; then
            echo "[sqli]   [DRY-RUN] sqlmap -u '$url'"
            continue
        fi

        local sqlmap_args=(
            -u "$url"
            --batch
            --level="$level"
            --risk="$risk"
            --threads="$threads"
            --output-dir="$out_dir"
            --random-agent
            --flush-session
            --technique="$technique"
            --tamper="$tamper"
            --timeout=30
            --retries=1
        )

        # Auth cookie
        [ -n "$auth_cookie" ] && sqlmap_args+=(--cookie "$auth_cookie")
        [ -n "$auth_header" ] && sqlmap_args+=(--headers "$auth_header")

        # Dump apenas em lab/staging (não production)
        case "${PROFILE:-lab}" in
            lab|staging) sqlmap_args+=(--banner --current-db --current-user) ;;
            production)  : ;;
        esac

        timeout "$timeout_url" sqlmap "${sqlmap_args[@]}" > "$log_file" 2>&1 || true

        if _sqli_confirmed "$log_file"; then
            local dbms; dbms=$(_sqli_get_dbms "$log_file")
            local inj_type; inj_type=$(_sqli_get_type "$log_file")
            echo "[sqli]   VULNERÁVEL — DBMS: ${dbms:-?} | Tipo: ${inj_type:-?}"
            echo "SQLI|CRITICAL|$url|DBMS=${dbms}|Type=${inj_type}|${hash}_output.log" >> "$confirmed_csv"
            command -v audit &>/dev/null && audit "FINDING_CONFIRMED type=sqli target=${url} dbms=${dbms:-?}"
            ((vuln++))
        else
            echo "[sqli]   Não vulnerável"
        fi

    done < "$sqli_targets"

    echo "[sqli] Concluído: $tested testadas, $vuln vulnerável(is)"
}

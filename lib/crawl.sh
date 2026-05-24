#!/usr/bin/env bash
# Stiglitz RED — Fase Crawl (katana + ffuf)
# Mapeia endpoints, formulários e parâmetros da aplicação.
# Chamado por: stiglitz_red.sh run_crawl()

set -uo pipefail

run_crawl_phase() {
    local target="$1"
    local crawl_dir="$2"
    local auth_cookie="${3:-}"
    local auth_header="${4:-}"
    local depth="${5:-3}"
    local timeout="${6:-600}"

    mkdir -p "$crawl_dir"

    echo "[!] Crawl: alvo = $target | profundidade = $depth"

    # ── katana — crawling de endpoint ────────────────────────────────────────
    if command -v katana &>/dev/null; then
        local katana_args=(
            -u "$target"
            -d "$depth"
            -jc          # JavaScript crawling
            -kf all      # known files
            -fx          # form extraction
            -silent
            -o "$crawl_dir/katana_urls.txt"
        )

        # Autenticação via cookie
        if [ -n "$auth_cookie" ]; then
            katana_args+=(-H "Cookie: $auth_cookie")
        fi
        if [ -n "$auth_header" ]; then
            katana_args+=(-H "$auth_header")
        fi

        echo "[!] katana: crawling de $target (profundidade $depth)..."
        timeout "$timeout" katana "${katana_args[@]}" 2>/dev/null || true

        local n_urls=0
        [ -f "$crawl_dir/katana_urls.txt" ] && n_urls=$(wc -l < "$crawl_dir/katana_urls.txt")
        echo "[✓] katana: $n_urls URL(s) coletadas"
    else
        echo "[!] katana não encontrado — instalando: go install github.com/projectdiscovery/katana/cmd/katana@latest"
        touch "$crawl_dir/katana_urls.txt"
    fi

    # ── ffuf — directory/endpoint fuzzing ────────────────────────────────────
    if command -v ffuf &>/dev/null; then
        local wordlist
        wordlist=$(_find_wordlist)

        if [ -n "$wordlist" ]; then
            echo "[!] ffuf: fuzzing de endpoints em $target..."

            # shellcheck disable=SC2054  # flags ffuf com valores comma-separated (ex: -mc) são intencionais
            local ffuf_args=(
                -u "${target}/FUZZ"
                -w "$wordlist"
                -mc 200,201,301,302,403
                -ac          # auto-calibrate
                -t 50
                -timeout 10
                -o "$crawl_dir/ffuf_results.json"
                -of json
                -s           # silent
            )

            if [ -n "$auth_cookie" ]; then
                ffuf_args+=(-H "Cookie: $auth_cookie")
            fi
            if [ -n "$auth_header" ]; then
                ffuf_args+=(-H "$auth_header")
            fi

            timeout "$timeout" ffuf "${ffuf_args[@]}" 2>/dev/null || true

            # Extrair URLs encontradas pelo ffuf
            if [ -f "$crawl_dir/ffuf_results.json" ]; then
                python3 - "$crawl_dir/ffuf_results.json" "$crawl_dir/ffuf_urls.txt" << 'PYEOF'
import json, sys
try:
    data = json.load(open(sys.argv[1]))
    results = data.get('results', [])
    urls = [r.get('url','') for r in results if r.get('url')]
    with open(sys.argv[2], 'w') as f:
        f.write('\n'.join(u for u in urls if u) + '\n')
    print(f"[✓] ffuf: {len(urls)} endpoint(s) encontrado(s)")
except Exception as e:
    print(f"[!] ffuf parse error: {e}")
PYEOF
            fi
        else
            echo "[!] ffuf: wordlist não encontrada — pulando directory fuzzing"
            echo "[!]       Instale SecLists ou execute setup.sh"
        fi
    fi

    # Consolidar URLs do crawl
    cat "$crawl_dir/katana_urls.txt" "$crawl_dir/ffuf_urls.txt" 2>/dev/null \
        | grep -E '^https?://' | sort -u > "$crawl_dir/all_urls.txt" || true

    echo "[✓] Crawl concluído: $(wc -l < "$crawl_dir/all_urls.txt" 2>/dev/null || echo 0) URL(s) totais"
}

# Localiza wordlist disponível (SecLists, fallback interno)
_find_wordlist() {
    local candidates=(
        "/opt/SecLists/Discovery/Web-Content/common.txt"
        "/opt/SecLists/Discovery/Web-Content/raft-medium-directories.txt"
        "/usr/share/seclists/Discovery/Web-Content/common.txt"
        "/usr/share/wordlists/dirb/common.txt"
        "/usr/share/dirbuster/wordlists/directory-list-2.3-small.txt"
    )

    for wl in "${candidates[@]}"; do
        [ -f "$wl" ] && echo "$wl" && return 0
    done

    # Gerar wordlist mínima inline como último recurso
    local inline_wl="/tmp/stiglitz_red_wordlist_$$.txt"
    cat > "$inline_wl" << 'WL'
api
admin
login
auth
dashboard
users
user
account
accounts
profile
settings
config
health
status
metrics
debug
test
dev
internal
private
backup
upload
download
export
import
search
query
data
manage
portal
panel
cms
wp-admin
phpinfo.php
.env
.git
api/v1
api/v2
graphql
swagger
docs
WL
    echo "$inline_wl"
}

#!/usr/bin/env bash
# Stiglitz RED — Fase Recon (subfinder + httpx)
# Descobre subdomínios ativos e mapeia superfície inicial.
# Chamado por: stiglitz_red.sh run_recon()

set -uo pipefail

run_recon_phase() {
    local domain="$1"
    local recon_dir="$2"
    local live_hosts_out="$3"
    local threads="${4:-50}"

    mkdir -p "$recon_dir"

    echo "[!] Recon: domínio-alvo = $domain"

    # ── Subfinder — descoberta de subdomínios ─────────────────────────────────
    if command -v subfinder &>/dev/null; then
        echo "[!] Subfinder: enumerando subdomínios de $domain..."
        subfinder -d "$domain" \
            -t "$threads" \
            -silent \
            -o "$recon_dir/subdomains.txt" \
            2>/dev/null || true

        local n_subs=0
        [ -f "$recon_dir/subdomains.txt" ] && n_subs=$(wc -l < "$recon_dir/subdomains.txt")
        echo "[✓] Subfinder: $n_subs subdomínio(s) encontrado(s)"
    else
        echo "[!] subfinder não encontrado — usando apenas o domínio base"
        echo "$domain" > "$recon_dir/subdomains.txt"
    fi

    # Garantir que o domínio-base está na lista
    echo "$domain" >> "$recon_dir/subdomains.txt"
    sort -u "$recon_dir/subdomains.txt" -o "$recon_dir/subdomains.txt"

    # ── httpx — filtrar hosts ativos ──────────────────────────────────────────
    if command -v httpx &>/dev/null; then
        echo "[!] httpx: verificando hosts ativos..."
        httpx -l "$recon_dir/subdomains.txt" \
            -threads "$threads" \
            -silent \
            -title \
            -tech-detect \
            -status-code \
            -follow-redirects \
            -o "$recon_dir/live_hosts_httpx.txt" \
            2>/dev/null || true

        # Extrair só as URLs para live_hosts.txt
        if [ -f "$recon_dir/live_hosts_httpx.txt" ]; then
            awk '{print $1}' "$recon_dir/live_hosts_httpx.txt" \
                | grep -E '^https?://' \
                | sort -u > "$live_hosts_out" || true
        fi

        local n_live=0
        [ -f "$live_hosts_out" ] && n_live=$(wc -l < "$live_hosts_out")
        echo "[✓] httpx: $n_live host(s) ativo(s)"
    else
        echo "[!] httpx não encontrado — usando subdomínios sem verificação"
        # Converter domínios em URLs https://
        sed 's|^|https://|' "$recon_dir/subdomains.txt" > "$live_hosts_out" || true
    fi

    # Fallback: se live_hosts.txt vazio, usar o domínio base
    if [ ! -s "$live_hosts_out" ]; then
        echo "https://$domain" > "$live_hosts_out"
        echo "[!] Fallback: usando https://$domain como único host"
    fi

    echo "[✓] Recon concluído: $(wc -l < "$live_hosts_out") host(s) ativo(s)"
}

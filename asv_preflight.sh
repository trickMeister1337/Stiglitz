#!/usr/bin/env bash
# asv_preflight.sh — Modo ASV-Preflight: prevê o resultado de um scan ASV PCI.
# Roda só o subconjunto NÃO-intrusivo e deslogado das fases do Stiglitz e aplica
# o critério do ASV Program Guide (lib/asv_preflight.py via stiglitz_report.py).
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; readonly SCRIPT_DIR
trap 'echo; echo "[!] Interrompido pelo usuário — abortando."; exit 130' INT TERM

# Subconjunto ASV-safe (não-intrusivo, deslogado). Exclui P5, P9*, P10_5, P12.
readonly ASV_PHASES="P1,P2,P2_5,P3_P4,P6,P8,P10,P11"

TARGET=""
OUTDIR=""
PROXY=""
DRY_RUN=false

usage() {
    cat <<EOF
Uso: bash asv_preflight.sh <target> [--outdir <dir>] [--proxy <url>] [--dry-run]

Prevê se o alvo passaria num scan ASV PCI (CVSS base >= 4.0 + gatilhos de falha
automática). NÃO substitui um scan ASV certificado (PCI DSS Req. 11.3.2).
Saída: stiglitz_report.html (seção "ASV Preflight Verdict") + asv_verdict.json.

Opções:
  --outdir <dir>    Diretório de saída (padrão: scan_<domínio>_<ts>)
  --proxy  <url>    Proxy HTTP/SOCKS para tráfego do alvo (roteado via STIGLITZ_PROXY)
  --dry-run         Só imprime o plano; não executa o scan
EOF
    exit "${1:-0}"
}

parse_args() {
    [ $# -eq 0 ] && usage 1
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --outdir)  OUTDIR="$2"; shift 2 ;;
            --proxy)   PROXY="$2";  shift 2 ;;
            --dry-run) DRY_RUN=true; shift ;;
            -h|--help) usage 0 ;;
            -*)        echo "[!] Argumento desconhecido: $1" >&2; usage 1 ;;
            *)         TARGET="$1"; shift ;;
        esac
    done
    [ -z "$TARGET" ] && { echo "[!] Informe o alvo." >&2; usage 1; }
}

main() {
    parse_args "$@"
    echo "[*] ASV-Preflight em $TARGET (fases: $ASV_PHASES, perfil: production)"
    echo "[*] AVISO: previsão de remediação — NÃO substitui scan ASV certificado."

    local -a args=("$TARGET" --profile production --only "$ASV_PHASES")
    [ -n "$OUTDIR" ] && args+=(--outdir "$OUTDIR")
    [ "$DRY_RUN" = true ] && args+=(--dry-run)

    export STIGLITZ_ASV_PREFLIGHT=1
    export STIGLITZ_PROFILE=production
    [ -n "$PROXY" ] && export STIGLITZ_PROXY="$PROXY"
    python3 "$SCRIPT_DIR/pipeline.py" "${args[@]}"
}

main "$@"

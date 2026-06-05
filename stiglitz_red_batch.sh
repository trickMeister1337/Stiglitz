#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
#  Stiglitz RED BATCH — Orquestrador paralelo de múltiplos alvos
#  Roda N targets em paralelo via semáforo FIFO. Cada target tem seu próprio
#  output dir, audit.log e exploits_confirmed.csv. Manifesto agregado no fim.
#
#  Uso:
#    bash stiglitz_red_batch.sh --targets targets.txt --workers 3 \
#         --roe roe.txt -p staging
# ═══════════════════════════════════════════════════════════════════════════════
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RED_SCRIPT="$SCRIPT_DIR/stiglitz_red.sh"

RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[1;33m'; CYN='\033[0;36m'
BLD='\033[1m';    DIM='\033[2m';    RST='\033[0m'

# ── Defaults ───────────────────────────────────────────────────────────────────
TARGETS_FILE=""
PROFILE="staging"
ROE_FILE=""
PROFILE_FILE=""
WORKERS=2
SKIP=""
ONLY=""

usage() {
    cat <<'EOF'
Stiglitz RED BATCH — exploração em N alvos paralelos.

Uso:
  bash stiglitz_red_batch.sh --targets FILE --roe FILE [opções]

Argumentos:
  --targets FILE      Arquivo com URLs/alvos (um por linha)
  --roe FILE          Documento de RoE (obrigatório para bypass não-interativo)
  --profile-file FILE Perfil JSON customizado (validado por lib/profile_loader.py)
  -p, --profile P     lab|staging|production (padrão: staging)
  --workers N         Workers paralelos (padrão: 2; cuidado >5 — stress alvos)
  --skip LIST         Pular fases (csv): recon,surface,sqli,xss,brute,services
  --only LIST         Rodar apenas estas fases
  -h, --help          Esta mensagem
EOF
    exit 0
}

# ── Parse args ─────────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --targets)      TARGETS_FILE="$2";   shift 2 ;;
        --roe)          ROE_FILE="$2";       shift 2 ;;
        --profile-file) PROFILE_FILE="$2";   shift 2 ;;
        -p|--profile)   PROFILE="$2";        shift 2 ;;
        --workers)      WORKERS="$2";        shift 2 ;;
        --skip)         SKIP="$2";           shift 2 ;;
        --only)         ONLY="$2";           shift 2 ;;
        -h|--help)      usage ;;
        *) echo -e "${RED}[✗] argumento desconhecido: $1${RST}"; exit 1 ;;
    esac
done

# ── Validação ──────────────────────────────────────────────────────────────────
[ -z "$TARGETS_FILE" ] && { echo -e "${RED}[✗] --targets é obrigatório${RST}"; exit 1; }
[ -f "$TARGETS_FILE" ] || { echo -e "${RED}[✗] arquivo não encontrado: $TARGETS_FILE${RST}"; exit 1; }
[ -z "$ROE_FILE" ]     && { echo -e "${RED}[✗] --roe é obrigatório (modo não-interativo)${RST}"; exit 1; }
[ -f "$ROE_FILE" ]     || { echo -e "${RED}[✗] RoE não encontrado: $ROE_FILE${RST}"; exit 1; }
[ -f "$RED_SCRIPT" ]   || { echo -e "${RED}[✗] stiglitz_red.sh não encontrado: $RED_SCRIPT${RST}"; exit 1; }
if ! [[ "$WORKERS" =~ ^[0-9]+$ ]] || [ "$WORKERS" -lt 1 ]; then
    echo -e "${RED}[✗] --workers deve ser inteiro >= 1${RST}"; exit 1
fi
[ "$WORKERS" -gt 10 ] && echo -e "${YLW}[!] >10 workers pode sobrecarregar os alvos${RST}"

# ── Ler alvos ──────────────────────────────────────────────────────────────────
mapfile -t TARGETS < <(grep -vE '^\s*(#|$)' "$TARGETS_FILE" | sed 's/[[:space:]]//g')
TOTAL=${#TARGETS[@]}
[ "$TOTAL" -eq 0 ] && { echo -e "${RED}[✗] nenhum alvo válido em $TARGETS_FILE${RST}"; exit 1; }
[ "$WORKERS" -gt "$TOTAL" ] && WORKERS="$TOTAL"

# ── Diretório de batch ─────────────────────────────────────────────────────────
BATCH_TS=$(date +%Y%m%d_%H%M%S)
BATCH_DIR="$SCRIPT_DIR/stiglitz_red_batch_${BATCH_TS}"
mkdir -p "$BATCH_DIR/logs"
MANIFEST="$BATCH_DIR/manifest.csv"
echo "target,status,outdir,duration_s,confirmed" > "$MANIFEST"

# ── Banner ─────────────────────────────────────────────────────────────────────
echo -e "${CYN}${BLD}╔══════════════════════════════════════════════════════════════════╗${RST}"
echo -e "${CYN}${BLD}║      Stiglitz RED BATCH — exploração paralela multi-target       ║${RST}"
echo -e "${CYN}${BLD}╚══════════════════════════════════════════════════════════════════╝${RST}"
echo -e "  ${BLD}Alvos:${RST}   $TOTAL"
echo -e "  ${BLD}Workers:${RST} $WORKERS"
echo -e "  ${BLD}Perfil:${RST}  ${PROFILE^^}"
echo -e "  ${BLD}RoE:${RST}     $ROE_FILE"
echo -e "  ${BLD}Output:${RST}  $BATCH_DIR"
echo ""

# ── Worker: roda um stiglitz_red.sh ─────────────────────────────────────────────
run_one() {
    local target="$1" idx="$2"
    local domain; domain=$(echo "$target" | sed -E 's|https?://||' | cut -d/ -f1 | cut -d: -f1)
    local safe_domain="${domain//[^a-zA-Z0-9._-]/_}"
    local outdir="$BATCH_DIR/red_${safe_domain}"
    local log="$BATCH_DIR/logs/${safe_domain}.log"
    local t0; t0=$(date +%s)

    local args=(-t "$target" -p "$PROFILE" --roe "$ROE_FILE" --output-dir "$outdir")
    [ -n "$PROFILE_FILE" ] && args+=(--profile-file "$PROFILE_FILE")
    [ -n "$SKIP" ] && args+=(--skip "$SKIP")
    [ -n "$ONLY" ] && args+=(--only "$ONLY")

    echo -e "  ${BLD}[${idx}/${TOTAL}]${RST} iniciando: $target"
    local exit_code=0
    STIGLITZ_AUTHORIZED=1 bash "$RED_SCRIPT" "${args[@]}" > "$log" 2>&1 || exit_code=$?
    local dur=$(( $(date +%s) - t0 ))

    local status="ok"
    [ $exit_code -ne 0 ] && status="failed"
    local confirmed=0
    [ -f "$outdir/exploits_confirmed.csv" ] && \
        confirmed=$(wc -l < "$outdir/exploits_confirmed.csv" 2>/dev/null || echo 0)
    # Append no manifest com flock
    (
        flock -x 200
        echo "$target,$status,$outdir,$dur,$confirmed" >> "$MANIFEST"
    ) 200>"$MANIFEST.lock"

    if [ "$status" = "ok" ]; then
        echo -e "  ${GRN}[${idx}/${TOTAL}] ✓${RST} $target — ${dur}s ($confirmed confirmed)"
    else
        echo -e "  ${RED}[${idx}/${TOTAL}] ✗${RST} $target — falhou em ${dur}s (log: $log)"
    fi
}

# ── Semáforo FIFO ──────────────────────────────────────────────────────────────
SEM=$(mktemp -u "$BATCH_DIR/.sem.XXXXXX")
mkfifo "$SEM"
trap 'rm -f "$SEM" "$MANIFEST.lock" 2>/dev/null' EXIT
exec 3<>"$SEM"
for ((i=0; i<WORKERS; i++)); do echo "token-$i" >&3; done

# ── Disparar workers ───────────────────────────────────────────────────────────
# Padrão: cada worker é um subshell que executa run_one e, no fim, devolve o
# token ao FIFO (operação atômica dentro do mesmo subshell).
T_START=$(date +%s)
for i in "${!TARGETS[@]}"; do
    read -r -u 3 _token
    (
        run_one "${TARGETS[$i]}" "$((i + 1))"
        echo "$_token" >&3
    ) &
done
wait
T_DUR=$(( $(date +%s) - T_START ))

# ── Sumário ────────────────────────────────────────────────────────────────────
ok=$(awk -F, 'NR>1 && $2=="ok"' "$MANIFEST" | wc -l)
fail=$(awk -F, 'NR>1 && $2=="failed"' "$MANIFEST" | wc -l)
total_confirmed=$(awk -F, 'NR>1{s+=$5} END{print s+0}' "$MANIFEST")

echo ""
echo -e "${CYN}${BLD}══════════════════════════════════════════════════════════════════${RST}"
echo -e "${BLD}Sumário:${RST}"
echo -e "  Tempo total: ${T_DUR}s"
echo -e "  ${GRN}OK:${RST}     $ok"
echo -e "  ${RED}Falhas:${RST} $fail"
echo -e "  Findings confirmados (todos os alvos): $total_confirmed"
echo -e "  Manifest: $MANIFEST"
echo -e "${CYN}${BLD}══════════════════════════════════════════════════════════════════${RST}"

[ "$fail" -eq 0 ] && exit 0 || exit 1

#!/usr/bin/env bash
# bizlogic.sh — wrapper da fase de lógica de negócio/authz do Stiglitz RED.
# Aplica profile, escopo e timeout, e delega a lib/bizlogic.py.
# Uso: bizlogic.sh <scan_dir> <profile> <config> [scope_csv] [roe_accept] [timeout_s]
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

SCAN_DIR="${1:?scan_dir}"; PROFILE="${2:-staging}"; CONFIG="${3:?config}"
SCOPE_CSV="${4:-}"; ROE_ACCEPT="${5:-}"; TIMEOUT_S="${6:-600}"

if [ ! -f "$CONFIG" ]; then
    echo "  [○] bizlogic: config não encontrado ($CONFIG) — fase pulada."
    exit 0
fi

ARGS=(--config "$CONFIG" --profile "$PROFILE" --outdir "$SCAN_DIR")
[ -n "$SCOPE_CSV" ] && ARGS+=(--scope "$SCOPE_CSV")
[ "$ROE_ACCEPT" = "1" ] && ARGS+=(--roe-accept)

# Budget de wall-clock por fase (como nas demais fases do RED). 'timeout' opcional.
if command -v timeout &>/dev/null && [ "$TIMEOUT_S" -gt 0 ] 2>/dev/null; then
    timeout "$TIMEOUT_S" python3 "$SCRIPT_DIR/bizlogic.py" "${ARGS[@]}"
    RC=$?
    [ $RC -eq 124 ] && echo "  [!] bizlogic: timeout (${TIMEOUT_S}s) atingido — fase interrompida."
else
    python3 "$SCRIPT_DIR/bizlogic.py" "${ARGS[@]}"
    RC=$?
fi
command -v audit &>/dev/null && audit "PHASE_END name=bizlogic result=$([ $RC -eq 0 ] && echo ok || echo fail)"
exit $RC

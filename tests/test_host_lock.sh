#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
#  Stiglitz — Test Suite: lock por-host (lib/host_lock.sh)
# ═══════════════════════════════════════════════════════════════
# Regressão: dois `stiglitz.sh <mesmo-host>` lançados em paralelo disputavam
# singletons por-host (daemon ZAP em porta fixa + store de estado), gerando
# relatórios contaminados/divergentes. O lock por-host serializa-os.
set -uo pipefail

HERE="$(cd "$(dirname "$0")/.." && pwd)"
LOCKLIB="$HERE/lib/host_lock.sh"
TMP=$(mktemp -d /tmp/stg_hostlock_XXXXXX)
export STIGLITZ_LOCK_DIR="$TMP/locks"

GRN='\033[0;32m'; RED='\033[0;31m'; RST='\033[0m'
PASS=0; FAIL=0
cleanup() { kill "${HOLDER:-}" 2>/dev/null; rm -rf "$TMP"; }
trap cleanup EXIT

pass() { echo -e "  ${GRN}[PASS]${RST} $1"; PASS=$((PASS+1)); }
fail() { echo -e "  ${RED}[FAIL]${RST} $1"; FAIL=$((FAIL+1)); }

[ -f "$LOCKLIB" ] || { echo -e "${RED}lib/host_lock.sh ausente${RST}"; exit 1; }

# ── 1) Aquisição livre (sem outro detentor) sucede ───────────────
( source "$LOCKLIB"; stg_acquire_host_lock host.example ) >/dev/null 2>&1
[ $? -eq 0 ] && pass "aquisição livre sucede" || fail "aquisição livre deveria suceder"

# ── 2) Detentor em background mantém o lock (vivo, bloqueado num FIFO) ──
mkfifo "$TMP/gate"
( source "$LOCKLIB"; stg_acquire_host_lock host.example \
    && { touch "$TMP/held"; read -r _ < "$TMP/gate"; } ) >/dev/null 2>&1 &
HOLDER=$!
for _ in $(seq 1 50); do [ -f "$TMP/held" ] && break; sleep 0.1; done
[ -f "$TMP/held" ] && pass "detentor de background adquiriu o lock" \
    || fail "detentor de background não adquiriu o lock"

# ── 3) Segunda aquisição (mesmo host) é recusada enquanto detido ──
out=$( ( source "$LOCKLIB"; stg_acquire_host_lock host.example ) 2>&1 ); rc=$?
[ "$rc" -ne 0 ] && pass "2a aquisição recusada (contenção)" \
    || fail "2a aquisição deveria ser recusada"
echo "$out" | grep -qiE "scan|host|concorr|execu" \
    && pass "mensagem de contenção é clara" \
    || fail "mensagem de contenção ausente/obscura"

# ── 4) Host DIFERENTE não é bloqueado pelo lock de outro host ─────
( source "$LOCKLIB"; stg_acquire_host_lock outro.example ) >/dev/null 2>&1
[ $? -eq 0 ] && pass "host diferente não é bloqueado" \
    || fail "lock deveria ser por-host, não global"

# ── 5) STIGLITZ_NO_HOSTLOCK=1 ignora o lock (escape hatch) ───────
( source "$LOCKLIB"; STIGLITZ_NO_HOSTLOCK=1 stg_acquire_host_lock host.example ) >/dev/null 2>&1
[ $? -eq 0 ] && pass "STIGLITZ_NO_HOSTLOCK=1 bypassa o lock" \
    || fail "STIGLITZ_NO_HOSTLOCK=1 deveria suceder mesmo com lock detido"

# ── 6) STIGLITZ_HOSTLOCK_WAIT espera e expira sob contenção ──────
start=$(date +%s)
( source "$LOCKLIB"; STIGLITZ_HOSTLOCK_WAIT=1 stg_acquire_host_lock host.example ) >/dev/null 2>&1
rc=$?; elapsed=$(( $(date +%s) - start ))
{ [ "$rc" -ne 0 ] && [ "$elapsed" -ge 1 ]; } \
    && pass "HOSTLOCK_WAIT espera o timeout e então recusa" \
    || fail "HOSTLOCK_WAIT deveria esperar ~1s e recusar (rc=$rc, elapsed=${elapsed}s)"

kill "$HOLDER" 2>/dev/null; wait "$HOLDER" 2>/dev/null; HOLDER=""

# ── 7) Após o detentor sair, o lock é liberado (re-aquisição OK) ──
( source "$LOCKLIB"; stg_acquire_host_lock host.example ) >/dev/null 2>&1
[ $? -eq 0 ] && pass "lock liberado no exit do detentor (sem órfão)" \
    || fail "lock deveria ser liberado quando o detentor sai"

echo ""
echo -e "  Resultado: ${GRN}${PASS} PASS${RST} / ${RED}${FAIL} FAIL${RST}"
[ "$FAIL" -eq 0 ]

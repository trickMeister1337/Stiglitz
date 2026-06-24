#!/usr/bin/env bash
# lib/host_lock.sh — lock por-host p/ serializar scans do MESMO alvo.
#
# Por quê: o lock por-OUTDIR (.stiglitz.lock dentro de scan_<host>_<ts>/raw) NÃO
# impede dois `stiglitz.sh <mesmo-host>` com timestamps diferentes rodando em
# paralelo — eles disputam singletons por-host: o daemon ZAP (porta fixa) e o
# store de estado (load→reconcile→save NÃO-atômico entre processos). Resultado
# observado em produção: ZAP cross-contaminado + findings de retire/state
# divergentes entre as duas runs.
#
# Modelo: PID-file por host (igual ao lock por-OUTDIR já existente), com a seção
# crítica check-and-write protegida por um flock de vida CURTA, fechado antes de
# retornar — assim NENHUM fd de lock vaza p/ os filhos do scan (fds dinâmicos do
# bash não têm close-on-exec) e um `kill -9` vira lock stale recuperável (o PID
# morto é detectado via `kill -0` e o lock é retomado), não um bloqueio eterno.
#
# Escape hatches por env:
#   STIGLITZ_NO_HOSTLOCK=1     desliga o lock (por sua conta e risco)
#   STIGLITZ_HOSTLOCK_WAIT=N   espera até N segundos pelo lock em vez de recusar
#   STIGLITZ_LOCK_DIR=<dir>    diretório dos locks (default ~/.stiglitz/locks)
#
# Sourceado pelo stiglitz.sh. O cleanup do chamador deve remover
# "$STG_HOSTLOCK_FILE" no exit.

# Caminho do PID-lock detido por este processo (p/ o cleanup do chamador remover).
# shellcheck disable=SC2034  # lida pelo cleanup do script que faz o source
STG_HOSTLOCK_FILE=""

# Verifica/grava o host-lock (PID-file). Sucede (0) e grava o nosso PID se o
# host estiver livre; falha (1) se o host-lock aponta p/ um PID vivo. NÃO usa o
# flock aqui — só a checagem de PID vivo (kill -0) + takeover de stale.
_stg_hostlock_claim() {
    local hostlock="$1" mypid="$2"
    if [ -f "$hostlock" ]; then
        local p
        p=$(cat "$hostlock" 2>/dev/null)
        [ -n "$p" ] && kill -0 "$p" 2>/dev/null && return 1  # detido por scan vivo
    fi
    printf '%s\n' "$mypid" > "$hostlock"
    return 0
}

# Tenta adquirir atomicamente. Quando há flock, serializa o claim sob o metalock
# via `flock <file> <cmd>` — flock gerencia o PRÓPRIO fd (close-on-exec, liberado
# quando o `bash -c` filho sai), então NENHUM fd de lock vaza p/ os filhos do
# scan. Sem flock, degrada com uma janela TOCTOU mínima.
_stg_try_hostlock() {
    local metalock="$1" hostlock="$2"
    if command -v flock >/dev/null 2>&1; then
        # shellcheck disable=SC2016  # $0/$1/$2 expandem no bash -c filho (intencional)
        flock "$metalock" bash -c \
            'source "$0"; _stg_hostlock_claim "$1" "$2"' \
            "${BASH_SOURCE[0]}" "$hostlock" "$BASHPID"
    else
        _stg_hostlock_claim "$hostlock" "$BASHPID"
    fi
}

stg_acquire_host_lock() {
    local domain="$1"
    [ "${STIGLITZ_NO_HOSTLOCK:-0}" = "1" ] && return 0

    local dir="${STIGLITZ_LOCK_DIR:-$HOME/.stiglitz/locks}"
    mkdir -p "$dir" 2>/dev/null || true
    local slug
    slug=$(printf '%s' "$domain" | sed -E 's/[^A-Za-z0-9._-]/_/g')
    [ -n "$slug" ] || slug="unknown"
    local hostlock="$dir/${slug}.lock"
    local metalock="$dir/${slug}.meta"

    local wait="${STIGLITZ_HOSTLOCK_WAIT:-0}"
    [ "$wait" -ge 0 ] 2>/dev/null || wait=0
    local now deadline
    now=$(date +%s)
    deadline=$(( now + wait ))

    while :; do
        if _stg_try_hostlock "$metalock" "$hostlock"; then
            STG_HOSTLOCK_FILE="$hostlock"
            return 0
        fi
        if [ "$(date +%s)" -ge "$deadline" ]; then
            local holder
            holder=$(cat "$hostlock" 2>/dev/null)
            if [ "$wait" -gt 0 ]; then
                echo "  [✗] Outro scan do host '$domain' (PID ${holder:-?}) ainda em execução após ${wait}s — abortando" >&2
            else
                echo "  [✗] Já existe um scan em execução para o host '$domain' (PID ${holder:-?})" >&2
                echo "      Concorrência no mesmo host contamina o daemon ZAP e o store de estado → relatório divergente." >&2
                echo "      Aguarde o término, ou use STIGLITZ_HOSTLOCK_WAIT=600 (espera) / STIGLITZ_NO_HOSTLOCK=1 (ignora)." >&2
            fi
            return 1
        fi
        sleep 1
    done
}

#!/usr/bin/env bash
# Stiglitz RED — Fase XSS (dalfox)
# Testa Cross-Site Scripting em URLs com parâmetros.
# Chamado por: stiglitz_red.sh run_xss()

set -uo pipefail

run_xss_phase() {
    local scored_targets="$1"
    local xss_dir="$2"
    local workers="${3:-3}"
    local timeout_per_url="${4:-300}"
    local auth_cookie="${5:-}"
    local auth_header="${6:-}"

    mkdir -p "$xss_dir"

    if [ ! -f "$scored_targets" ] || [ ! -s "$scored_targets" ]; then
        echo "[!] XSS: sem targets para testar"
        return 0
    fi

    # Selecionar apenas URLs com parâmetros (score >= 2 = tem '?')
    local urls_with_params="$xss_dir/xss_candidates.txt"
    awk -F'|' '$1 >= 2 && $2 ~ /[?&]/' "$scored_targets" \
        | cut -d'|' -f2 > "$urls_with_params" 2>/dev/null || true

    local n_candidates
    n_candidates=$(wc -l < "$urls_with_params" 2>/dev/null || echo 0)
    echo "[!] XSS: $n_candidates URL(s) com parâmetros"

    if [ "$n_candidates" -eq 0 ]; then
        echo "[!] XSS: sem URLs com parâmetros — nada a testar"
        return 0
    fi

    # Construir argumentos comuns do dalfox
    local dalfox_base_args=(
        --silence
        --no-color
        --output-all
        -o "$xss_dir/dalfox_results.json"
        --format json
    )

    if [ -n "$auth_cookie" ]; then
        dalfox_base_args+=(--cookie "$auth_cookie")
    fi
    if [ -n "$auth_header" ]; then
        dalfox_base_args+=(--header "$auth_header")
    fi

    local xss_confirmed=0

    # Processar URLs em paralelo (workers simultâneos)
    local pids=()
    local i=0
    local results_dir="$xss_dir/per_url"
    mkdir -p "$results_dir"

    while IFS= read -r url; do
        [ -z "$url" ] && continue
        local hash
        hash=$(echo "$url" | md5sum | cut -c1-8)
        local out_file="$results_dir/${hash}.json"

        echo "[!] XSS [$((++i))]: $url"

        # Rodar dalfox em background
        (
            timeout "$timeout_per_url" dalfox url "$url" \
                "${dalfox_base_args[@]}" \
                -o "$out_file" \
                2>/dev/null || true
        ) &
        pids+=("$!")

        # Limitar paralelismo
        if [ "${#pids[@]}" -ge "$workers" ]; then
            wait "${pids[0]}" 2>/dev/null || true
            pids=("${pids[@]:1}")
        fi

    done < "$urls_with_params"

    # Aguardar todos os processos
    for pid in "${pids[@]}"; do
        wait "$pid" 2>/dev/null || true
    done

    # Consolidar resultados
    _consolidate_xss_results "$results_dir" "$xss_dir"

    xss_confirmed=$(wc -l < "$xss_dir/xss_confirmed.txt" 2>/dev/null || echo 0)
    echo "[✓] XSS: $xss_confirmed finding(s) confirmado(s)"
    if [ "$xss_confirmed" -gt 0 ] && command -v audit &>/dev/null; then
        audit "FINDING_CONFIRMED type=xss count=${xss_confirmed}"
    fi
}

# Consolida resultados JSON do dalfox em formato Stiglitz RED
_consolidate_xss_results() {
    local per_url_dir="$1"
    local xss_dir="$2"

    : > "$xss_dir/xss_confirmed.txt"
    : > "$xss_dir/xss_all_results.json"

    python3 - "$per_url_dir" "$xss_dir/xss_confirmed.txt" "$xss_dir/xss_all_results.json" << 'PYEOF'
import os, json, sys, glob

per_url_dir = sys.argv[1]
confirmed_out = sys.argv[2]
all_out = sys.argv[3]

all_findings = []
confirmed = []

for jf in glob.glob(os.path.join(per_url_dir, '*.json')):
    try:
        with open(jf) as f:
            content = f.read().strip()
        if not content:
            continue

        # dalfox pode emitir JSONL (um objeto por linha) ou array
        findings = []
        try:
            data = json.loads(content)
            if isinstance(data, list):
                findings = data
            elif isinstance(data, dict):
                findings = [data]
        except json.JSONDecodeError:
            for line in content.split('\n'):
                line = line.strip()
                if line:
                    try:
                        obj = json.loads(line)
                        if isinstance(obj, dict):
                            findings.append(obj)
                    except json.JSONDecodeError:
                        pass

        for f in findings:
            if not isinstance(f, dict):
                continue
            url = f.get('url', f.get('target', ''))
            vtype = f.get('type', f.get('evidence', ''))
            payload = f.get('payload', f.get('POC', ''))
            param = f.get('parameter', f.get('param', ''))

            if url and (vtype or payload):
                entry = {'url': url, 'type': vtype, 'payload': payload, 'parameter': param}
                all_findings.append(entry)
                confirmed.append(f"XSS|HIGH|{url}|param={param}|payload={payload[:80]}")

    except Exception:
        pass

with open(confirmed_out, 'w') as f:
    f.write('\n'.join(confirmed))

with open(all_out, 'w') as f:
    json.dump(all_findings, f, indent=2)

print(f"[✓] XSS consolidado: {len(confirmed)} finding(s)")
PYEOF
}

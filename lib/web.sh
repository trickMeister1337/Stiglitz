#!/usr/bin/env bash
# Stiglitz RED — Fase Web Scanner (Nikto)
# Filtra findings por severidade — descarta informationals e duplicatas.
# Chamado por: stiglitz_red.sh run_services()

set -uo pipefail

# Parseia JSON do Nikto e filtra por severidade mínima
_parse_nikto_json() {
    local json_file="$1" min_sev="$2"
    python3 - "$json_file" "$min_sev" << 'PYEOF'
import sys, json

path, min_sev = sys.argv[1], int(sys.argv[2])
SEV_KW = {
    3: ["sql inject", "remote code", "rce", "command inject",
        "xss", "cross-site", "csrf", "authentication bypass",
        "default credential", "directory traversal", "path traversal", "lfi", "rfi"],
    2: ["outdated", "vulnerable version", "cve-",
        "missing header", "insecure cookie", "clickjack", "open redirect"],
}

findings = []
try:
    content = open(path).read()
    if content.lstrip().startswith('<'):
        import xml.etree.ElementTree as ET
        root = ET.fromstring(content)
        for item in root.iter('item'):
            findings.append({
                "msg":    (item.findtext('description') or item.findtext('msg') or ''),
                "url":    (item.findtext('uri') or item.findtext('url') or ''),
                "method": (item.findtext('method') or 'GET'),
                "osvdb":  (item.findtext('OSVDB') or '0'),
            })
    else:
        data = json.loads(content)
        for block in (data if isinstance(data, list) else data.get("host", [data])):
            for vuln in block.get("vulnerabilities", []):
                findings.append({
                    "msg":    vuln.get("msg", ""),
                    "url":    vuln.get("url", ""),
                    "method": vuln.get("method", "GET"),
                    "osvdb":  vuln.get("OSVDB", "0"),
                })
except Exception:
    print("[]"); sys.exit(0)

seen, results = set(), []
for f in findings:
    ml = f["msg"].lower()
    sev = 1
    for s, kws in SEV_KW.items():
        if any(kw in ml for kw in kws):
            sev = s; break
    if sev < min_sev:
        continue
    key = f["url"] + "|" + f["msg"][:60]
    if key in seen: continue
    seen.add(key)
    label = {3: "HIGH", 2: "MEDIUM", 1: "INFO"}.get(sev, "INFO")
    results.append({"msg": f["msg"], "url": f["url"], "sev": label, "osvdb": f["osvdb"]})

import json as _j
print(_j.dumps(results))
PYEOF
}

# ── Runner principal ──────────────────────────────────────────────────────────
# Assinatura: run_nikto_phase(target_url, nikto_dir, timeout, auth_cookie)
run_nikto_phase() {
    local target_url="$1"
    local nikto_dir="$2"
    local timeout="${3:-700}"
    local auth_cookie="${4:-}"

    mkdir -p "$nikto_dir"

    echo "[nikto] Alvo: $target_url"

    if [ "${DRY_RUN:-false}" = true ]; then
        echo "[nikto] [DRY-RUN] nikto -h $target_url"
        return 0
    fi

    local json_out="$nikto_dir/nikto_report.xml"
    local raw_log="$nikto_dir/nikto_raw.txt"

    local nikto_args=(
        -h "$target_url"
        -Format xml
        -output "$json_out"
        -Tuning 123456789abc
        -maxtime "${timeout}s"
    )

    [ -n "$auth_cookie" ] && nikto_args+=(-cookies "$auth_cookie")

    timeout "$timeout" nikto "${nikto_args[@]}" 2>&1 | tee "$raw_log" || true

    if [ ! -s "$json_out" ]; then
        echo "[nikto] Sem output JSON — verifique $raw_log"
        return 0
    fi

    # Filtrar severidade >= 2 (MEDIUM+)
    local filtered_json
    filtered_json=$(_parse_nikto_json "$json_out" 2)

    # Salvar para evidence.py
    echo "$filtered_json" > "$nikto_dir/nikto_filtered.json"

    local count
    count=$(python3 -c "import json,sys; d=json.loads(sys.argv[1]); print(len(d))" \
        "$filtered_json" 2>/dev/null || echo 0)
    echo "[nikto] $count finding(s) de severidade MEDIUM+"
}

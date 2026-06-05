#!/usr/bin/env python3
"""
Stiglitz RED — Gerador de Prova de Conceito (PoC)

Extrai payloads confirmados dos logs sqlmap e alertas ZAP e produz:
  - Lista de PoCs estruturados (usada pelo report_generator para seção HTML)
  - poc/verify.sh — script executável para times verificarem antes/após remediação

Uso standalone: python3 lib/poc_generator.py <outdir> <target>
"""
import os
import re
import sys
import glob
import stat
from typing import List, Dict, Any, Optional


# ══════════════════════════════════════════════════════════════════
#  EXTRAÇÃO DE PAYLOAD DO SQLMAP
# ══════════════════════════════════════════════════════════════════

def _extract_sqlmap_payload(log: str) -> Optional[Dict]:
    """Extrai URL, parâmetro, técnica e payload exato do log sqlmap."""
    info: Dict[str, Any] = {
        "url": "", "parameter": "", "place": "GET",
        "technique": "", "title": "", "payload": "",
    }

    m = re.search(r"testing URL '([^']+)'", log)
    if m:
        info["url"] = m.group(1)

    # Bloco de injection point gerado pelo sqlmap quando confirma:
    # Parameter: <name> (<place>)
    #     Type: <technique>
    #     Title: <title>
    #     Payload: <payload>
    block_m = re.search(
        r"Parameter:\s*(\S+)\s+\((\w+)\)(.*?)(?=\nParameter:|\Z)",
        log, re.DOTALL,
    )
    if not block_m:
        return None

    info["parameter"] = block_m.group(1)
    info["place"] = block_m.group(2).upper()
    block = block_m.group(3)

    # Preferência de técnica para PoC: time > boolean > union > error
    PREF = ["time-based", "boolean-based", "union", "error-based"]
    entries = re.findall(
        r"Type:\s*(.+?)\n\s+Title:\s*(.+?)\n\s+Payload:\s*(.+?)(?=\n\s+Type:|\Z)",
        block, re.DOTALL,
    )
    if not entries:
        return None

    chosen = entries[0]
    for pref in PREF:
        for e in entries:
            if pref in e[0].lower():
                chosen = e
                break
        if pref in chosen[0].lower():
            break

    info["technique"] = chosen[0].strip()
    info["title"] = chosen[1].strip()
    info["payload"] = chosen[2].strip()
    return info


def _inject_param(url: str, param: str, value: str, place: str) -> str:
    """Constrói URL com parâmetro injetado."""
    if place != "GET":
        return url
    if re.search(rf"[?&]{re.escape(param)}=", url):
        return re.sub(rf"([?&]{re.escape(param)}=)[^&]*", rf"\g<1>{value}", url)
    sep = "&" if "?" in url else "?"
    return f"{url}{sep}{param}={value}"


# ══════════════════════════════════════════════════════════════════
#  GERADORES DE POC POR TIPO
# ══════════════════════════════════════════════════════════════════

def _poc_sqli_time(url: str, param: str, place: str, payload: str, title: str) -> Dict:
    sleep_payload = "1 AND SLEEP(5)-- -"
    inject_url = _inject_param(url, param, sleep_payload, place)

    if place == "GET":
        curl = (
            f"# Esperado: tempo de resposta >= 5s (confirma SQLi ativo)\n"
            f"time curl -sk -m 15 \\\n"
            f"  -A 'Mozilla/5.0' \\\n"
            f"  '{inject_url}' -o /dev/null\n"
            f"\n# Payload original confirmado pelo sqlmap:\n"
            f"# {payload}"
        )
    else:
        curl = (
            f"# Esperado: tempo de resposta >= 5s (confirma SQLi ativo)\n"
            f"time curl -sk -m 15 -X POST \\\n"
            f"  -d '{param}={sleep_payload}' \\\n"
            f"  '{url}' -o /dev/null"
        )

    return {
        "id": "", "type": "sqli_time",
        "title": f"SQL Injection (time-based) — parâmetro '{param}' [{place}]",
        "sqlmap_title": title,
        "url": url, "parameter": param, "place": place,
        "curl": curl,
        "verify": {
            "type": "time", "url": url, "param": param,
            "place": place, "payload": sleep_payload,
            "inject_url": inject_url,
        },
        "remediation": (
            "• Substituir queries dinâmicas por prepared statements\n"
            "• Validar e sanitizar input no servidor (whitelist)\n"
            "• Aplicar menor privilégio ao usuário do banco\n"
            "• Habilitar WAF com ruleset SQLi (OWASP CRS)"
        ),
    }


def _poc_sqli_boolean(url: str, param: str, place: str, payload: str, title: str) -> Dict:
    pt = "1 AND 1=1-- -"
    pf = "1 AND 1=2-- -"
    url_true  = _inject_param(url, param, pt, place)
    url_false = _inject_param(url, param, pf, place)

    curl = (
        f"# Esperado: tamanhos de resposta DIFERENTES (TRUE != FALSE)\n"
        f"TRUE_SZ=$(curl -sk '{url_true}' | wc -c)\n"
        f"FALSE_SZ=$(curl -sk '{url_false}' | wc -c)\n"
        f'echo "TRUE: ${{TRUE_SZ}} bytes | FALSE: ${{FALSE_SZ}} bytes"\n'
        f'[ "$TRUE_SZ" -ne "$FALSE_SZ" ] && echo "VULNERÁVEL" || echo "Não confirmado"\n'
        f"\n# Payload original confirmado pelo sqlmap:\n"
        f"# {payload}"
    )

    return {
        "id": "", "type": "sqli_bool",
        "title": f"SQL Injection (boolean-based) — parâmetro '{param}' [{place}]",
        "sqlmap_title": title,
        "url": url, "parameter": param, "place": place,
        "curl": curl,
        "verify": {
            "type": "boolean", "url": url, "param": param,
            "place": place, "url_true": url_true, "url_false": url_false,
        },
        "remediation": (
            "• Substituir queries dinâmicas por prepared statements\n"
            "• Validar e sanitizar input no servidor (whitelist)\n"
            "• Aplicar menor privilégio ao usuário do banco\n"
            "• Habilitar WAF com ruleset SQLi (OWASP CRS)"
        ),
    }


def _poc_cors(url: str, alert: str) -> Dict:
    curl = (
        f"# Esperado problemático: Access-Control-Allow-Origin: * ou https://evil-poc-test.com\n"
        f"# Esperado seguro: header ausente ou origem legítima\n"
        f"curl -sk -H 'Origin: https://evil-poc-test.com' -I '{url}' \\\n"
        f"  | grep -i 'access-control-allow'"
    )
    return {
        "id": "", "type": "cors",
        "title": f"CORS Misconfiguration — {alert}",
        "url": url, "parameter": "", "place": "GET",
        "curl": curl,
        "verify": {"type": "cors", "url": url, "origin": "https://evil-poc-test.com"},
        "remediation": (
            "• Restringir Access-Control-Allow-Origin a origens conhecidas\n"
            "• Nunca combinar Access-Control-Allow-Credentials: true com wildcard\n"
            "• Validar o header Origin no servidor via allowlist"
        ),
    }


def _poc_header(url: str, alert: str) -> Dict:
    # Mapear alerta → nome canônico do header
    _MAP = {
        "content security policy": "content-security-policy",
        "x-frame-options": "x-frame-options",
        "strict-transport-security": "strict-transport-security",
        "x-content-type-options": "x-content-type-options",
        "referrer-policy": "referrer-policy",
        "permissions-policy": "permissions-policy",
    }
    header = next(
        (v for k, v in _MAP.items() if k in alert.lower()),
        alert.lower().split("(")[0].strip(),
    )
    curl = (
        f"# Esperado problemático: header ausente (sem output)\n"
        f"# Esperado seguro: header presente com valor restritivo\n"
        f"curl -sk -I '{url}' | grep -i '{header}'"
    )
    return {
        "id": "", "type": "header_missing",
        "title": f"Header de Segurança Ausente — {alert}",
        "url": url, "parameter": "", "place": "GET",
        "curl": curl,
        "verify": {"type": "header_missing", "url": url, "header": header},
        "remediation": (
            f"• Adicionar o header '{header}' com valor restritivo\n"
            "• Consultar OWASP Secure Headers Project para valores recomendados\n"
            "• Validar via https://securityheaders.com"
        ),
    }


# ══════════════════════════════════════════════════════════════════
#  COLETA DE TODOS OS PoCs DE UM OUTDIR
# ══════════════════════════════════════════════════════════════════

def collect_pocs(outdir: str) -> List[Dict]:
    """Coleta PoCs de todas as fontes disponíveis no diretório de saída."""
    pocs: List[Dict] = []

    # ── SQLi: extrair dos logs sqlmap ──────────────────────────────
    seen_params: set = set()
    for log_path in sorted(glob.glob(f"{outdir}/sqlmap/*_output.log")):
        try:
            content = open(log_path, errors="replace").read()
        except OSError:
            continue

        confirmed = any(w in content.lower() for w in [
            "is vulnerable", "injection point", "injectable", "identified the following"
        ])
        if not confirmed:
            continue

        info = _extract_sqlmap_payload(content)
        if not info:
            continue

        key = (info["url"], info["parameter"], info["place"])
        if key in seen_params:
            continue
        seen_params.add(key)

        if "time" in info["technique"].lower():
            poc = _poc_sqli_time(
                info["url"], info["parameter"], info["place"],
                info["payload"], info["title"],
            )
        elif "boolean" in info["technique"].lower():
            poc = _poc_sqli_boolean(
                info["url"], info["parameter"], info["place"],
                info["payload"], info["title"],
            )
        else:
            # Fallback: gerar time-based genérico com o payload real como referência
            poc = _poc_sqli_time(
                info["url"], info["parameter"], info["place"],
                info["payload"], info["title"],
            )

        poc["source_log"] = os.path.basename(log_path)
        pocs.append(poc)

    # ── ZAP: CORS + headers ausentes — deduplica por tipo + domínio ──
    zap_path = f"{outdir}/zap_high_crit.txt"
    seen_zap: set = set()
    if os.path.exists(zap_path):
        for line in open(zap_path, errors="replace"):
            parts = line.strip().split("|")
            if len(parts) < 3:
                continue
            _risk, alert, url = parts[0], parts[1], parts[2]

            # Extrair domínio para dedup (um PoC por tipo por domínio)
            from urllib.parse import urlparse as _up
            domain = _up(url).netloc or url
            key = (alert.lower()[:40], domain)
            if key in seen_zap:
                continue
            seen_zap.add(key)

            al = alert.lower()
            if any(t in al for t in ["cors", "cross-domain", "cross-origin"]):
                pocs.append(_poc_cors(url, alert))
            elif any(t in al for t in [
                "content security policy", "x-frame-options",
                "strict-transport", "x-content-type", "missing security header",
                "referrer-policy", "permissions-policy",
            ]):
                pocs.append(_poc_header(url, alert))

    # Numerar
    for i, p in enumerate(pocs, 1):
        p["id"] = f"POC-{i:03d}"

    return pocs


# ══════════════════════════════════════════════════════════════════
#  GERADOR DO verify.sh
# ══════════════════════════════════════════════════════════════════

def generate_verify_script(outdir: str, pocs: List[Dict], target: str) -> str:
    """Gera poc/verify.sh — script shell para times validarem findings."""
    poc_dir = f"{outdir}/poc"
    os.makedirs(poc_dir, exist_ok=True)
    script_path = f"{poc_dir}/verify.sh"

    L: List[str] = [
        "#!/usr/bin/env bash",
        "# ═══════════════════════════════════════════════════════════════════════",
        f"# Stiglitz RED — Verificação de PoC  |  Alvo: {target}",
        "# Uso: bash poc/verify.sh",
        "#",
        "# Execute antes da remediação (deve FALHAR nos PoCs de vulnerabilidade)",
        "# Execute após a remediação  (deve PASSAR em todos os checks)",
        "# ═══════════════════════════════════════════════════════════════════════",
        "",
        "PASS=0; FAIL=0; WARN=0",
        "RED='\\033[0;31m'; GRN='\\033[0;32m'; YLW='\\033[1;33m'",
        "CYN='\\033[0;36m'; BLD='\\033[1m'; NC='\\033[0m'",
        "",
        "_pass(){ echo -e \"  ${GRN}[PASS]${NC} $*\"; ((PASS++)); }",
        "_fail(){ echo -e \"  ${RED}[FAIL - VULNERÁVEL]${NC} $*\"; ((FAIL++)); }",
        "_warn(){ echo -e \"  ${YLW}[WARN]${NC} $*\"; ((WARN++)); }",
        "_sec() { echo -e \"\\n${CYN}${BLD}══ $* ══${NC}\"; }",
        "",
        "command -v curl &>/dev/null || { echo 'curl não encontrado'; exit 1; }",
        "",
    ]

    if not pocs:
        L += [
            'echo "Nenhum PoC gerado — sem vulnerabilidades confirmadas neste scan."',
            "exit 0",
        ]
    else:
        for poc in pocs:
            v = poc["verify"]
            pid = poc["id"]
            title = poc["title"]

            L.append(f'_sec "{pid}: {title}"')

            if v["type"] == "time":
                inject_url = v["inject_url"]
                L += [
                    f'echo "  → {v["url"]}"',
                    f'echo "  Injetando SLEEP(5) em parâmetro \\"{v["param"]}\\" — aguarde até 15s..."',
                    f'T0=$(date +%s%3N)',
                    f"curl -sk -m 15 -A 'Mozilla/5.0' '{inject_url}' -o /dev/null 2>/dev/null",
                    f'T1=$(date +%s%3N)',
                    f'MS=$(( T1 - T0 ))',
                    f'if [ "$MS" -ge 4500 ]; then',
                    f'  _fail "{pid} Time-based SQLi CONFIRMADO ({v["param"]}) — ${{MS}}ms"',
                    f'else',
                    f'  _pass "{pid} Sem atraso detectado — ${{MS}}ms (não confirmado)"',
                    f'fi',
                    "",
                ]

            elif v["type"] == "boolean":
                L += [
                    f'echo "  → {v["url"]}"',
                    f"SZ_T=$(curl -sk -A 'Mozilla/5.0' '{v['url_true']}' 2>/dev/null | wc -c)",
                    f"SZ_F=$(curl -sk -A 'Mozilla/5.0' '{v['url_false']}' 2>/dev/null | wc -c)",
                    f'echo "  TRUE response: ${{SZ_T}} bytes | FALSE response: ${{SZ_F}} bytes"',
                    f'if [ "$SZ_T" -ne "$SZ_F" ] && [ "$SZ_T" -gt 10 ] && [ "$SZ_F" -gt 0 ]; then',
                    f'  _fail "{pid} Boolean SQLi CONFIRMADO ({v["param"]}) — TRUE=${{SZ_T}}b FALSE=${{SZ_F}}b"',
                    f'else',
                    f'  _pass "{pid} Respostas idênticas — não confirmado"',
                    f'fi',
                    "",
                ]

            elif v["type"] == "cors":
                L += [
                    f'echo "  → {v["url"]}"',
                    f"CORS=$(curl -sk -m 10 -H 'Origin: {v['origin']}' -I '{v['url']}' 2>/dev/null \\\n"
                    f"  | grep -i 'access-control-allow-origin' | tr -d '\\r')",
                    f'if echo "$CORS" | grep -qiE "\\*|evil-poc-test"; then',
                    f'  _fail "{pid} CORS exposto — $CORS"',
                    f'elif [ -n "$CORS" ]; then',
                    f'  _warn "{pid} CORS presente mas não wildcard — $CORS"',
                    f'else',
                    f'  _pass "{pid} Header CORS ausente ou restrito"',
                    f'fi',
                    "",
                ]

            elif v["type"] == "header_missing":
                header = v["header"]
                L += [
                    f'echo "  → {v["url"]}"',
                    f"HDR=$(curl -sk -m 10 -I '{v['url']}' 2>/dev/null | grep -i '{header}')",
                    f'if [ -z "$HDR" ]; then',
                    f'  _fail "{pid} Header ausente: {header}"',
                    f'else',
                    f'  _pass "{pid} Header presente: $HDR"',
                    f'fi',
                    "",
                ]

        L += [
            'echo ""',
            'echo "══════════════════════════════════════════════"',
            'echo -e "  ${GRN}PASS: $PASS${NC}  ${RED}FAIL: $FAIL${NC}  ${YLW}WARN: $WARN${NC}"',
            'echo "══════════════════════════════════════════════"',
            'if [ "$FAIL" -gt 0 ]; then',
            '  echo -e "  ${RED}Vulnerabilidades ainda presentes — remediação pendente.${NC}"',
            '  exit 1',
            'else',
            '  echo -e "  ${GRN}Todos os checks passaram.${NC}"',
            '  exit 0',
            'fi',
        ]

    with open(script_path, "w", encoding="utf-8") as f:
        f.write("\n".join(L) + "\n")
    os.chmod(script_path, os.stat(script_path).st_mode | stat.S_IXUSR | stat.S_IXGRP)
    return script_path


# ══════════════════════════════════════════════════════════════════
#  ENTRY POINT STANDALONE
# ══════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)
    _outdir, _target = sys.argv[1], sys.argv[2]
    _pocs = collect_pocs(_outdir)
    _script = generate_verify_script(_outdir, _pocs, _target)
    print(f"PoCs gerados: {len(_pocs)}")
    print(f"Script: {_script}")
    for p in _pocs:
        print(f"  {p['id']} {p['title']}")

#!/usr/bin/env python3
"""tls_confirm.py — confirmação ativa de NULL/anon ciphers reportados pelo testssl.

O testssl reporta `cipherlist_NULL`/`cipherlist_aNULL` como "offered" (CRITICAL)
de forma intermitentemente FALSA quando o alvo está atrás de um LB/WAF gerenciado
(ex.: AWS ALB), que responde de modo não-conforme ao teste de categorias de cipher.
Um único HIGH/CRITICAL falso destrói a credibilidade do deliverable.

Este módulo enumera os ciphers REALMENTE negociáveis via `nmap ssl-enum-ciphers`
(fonte independente) e refuta o achado quando nenhum cipher NULL/anon aparece.

Padrão do projeto: lógica pura + runner injetável (testável sem rede) + CLI.
A integração (Fase 3 do stiglitz.sh + stiglitz_report.py) respeita o gating de
proxy do scan — sob proxy/SOCKS o cross-check é pulado, nunca conexão direta.
"""
import json
import re
import subprocess
import sys

# Linha de cipher do nmap ssl-enum-ciphers: "<nome> (<kex>) - <GRADE A-F>".
# A âncora no grade final exclui cabeçalhos de seção, "compressors: NULL"
# (sem grade) e "least strength: A" (dois-pontos, não hífen).
_CIPHER_RE = re.compile(
    r'^[|\s_]*([A-Za-z0-9][\w-]+)\s+(?:\([^)]*\)\s+)?-\s+([A-F])\s*$')

# IDs do testssl que este módulo sabe confirmar e o que cada um procura.
_NULL_IDS = ("cipherlist_NULL",)
_ANON_IDS = ("cipherlist_aNULL",)


def parse_ssl_enum_ciphers(nmap_output):
    """Extrai os nomes de cipher das linhas graduadas do nmap ssl-enum-ciphers.

    Só linhas que terminam em ` - <A-F>` são ciphers — o que naturalmente exclui
    `compressors: NULL` (sem grade), evitando o exato FP que motivou o módulo.
    """
    ciphers = []
    for line in (nmap_output or "").splitlines():
        m = _CIPHER_RE.match(line)
        if m:
            ciphers.append(m.group(1))
    return ciphers


def _is_null(name):
    return "NULL" in name.upper()


def _is_anon(name):
    up = name.upper()
    return ("ANON" in up or up.startswith("ADH") or up.startswith("AECDH")
            or "_ANON_" in up)


def has_null_cipher(ciphers):
    """True se algum cipher negociável aplica NULL (sem) criptografia."""
    return any(_is_null(c) for c in ciphers)


def has_anon_cipher(ciphers):
    """True se algum cipher negociável é anônimo (sem autenticação do servidor)."""
    return any(_is_anon(c) for c in ciphers)


def verdict(testssl_id, ciphers):
    """confirmed | refuted | inconclusive para um id de cipherlist do testssl.

    confirmed  — o cipher inseguro está de fato entre os negociáveis.
    refuted    — não está (provável FP do testssl atrás de LB/WAF).
    inconclusive — id que este módulo não cobre (não mexe no achado).
    """
    if testssl_id in _NULL_IDS:
        return "confirmed" if has_null_cipher(ciphers) else "refuted"
    if testssl_id in _ANON_IDS:
        return "confirmed" if has_anon_cipher(ciphers) else "refuted"
    return "inconclusive"


# Severidades do testssl que contam como "problema" (espelha stiglitz_report.py).
_TLS_ISSUE_SEVERITIES = ("CRITICAL", "HIGH", "WARN", "LOW")


def count_terminal_tls_issues(findings):
    """Conta problemas TLS reais espelhando o filtro do stiglitz_report.py.

    Aceita a lista de findings ou o wrapper `{"scanResult":[{"findings":[...]}]}`.
    Exclui: severidades fora de CRITICAL/HIGH/WARN/LOW, o metadado `scanTime`, e
    artefatos do scanner local ("not supported by local OpenSSL"). Deduplica por
    `id` (o testssl varre múltiplos IPs A-record → mesmo id repetido).
    """
    if isinstance(findings, dict):
        findings = findings.get("scanResult", [{}])[0].get("findings", [])
    seen = set()
    for f in findings or []:
        if f.get("severity", "").upper() not in _TLS_ISSUE_SEVERITIES:
            continue
        fid = f.get("id", "")
        if fid == "scanTime" or fid in seen:
            continue
        if "not supported by local openssl" in f.get("finding", "").lower():
            continue
        seen.add(fid)
    return len(seen)


def _nmap_runner(host, port):
    """Runner real: nmap ssl-enum-ciphers. Retorna stdout (texto) ou ''."""
    try:
        out = subprocess.run(
            ["nmap", "-Pn", "-p", str(port), "--script", "ssl-enum-ciphers",
             str(host)],
            capture_output=True, text=True, timeout=180)
        return out.stdout or ""
    except Exception:
        return ""


def confirm(host, port, runner=_nmap_runner):
    """Enumera ciphers reais e devolve o veredito para NULL/aNULL.

    runner(host, port) -> texto do nmap (injetável p/ teste sem rede).
    """
    ciphers = parse_ssl_enum_ciphers(runner(host, int(port)))
    return {
        "host": host,
        "port": int(port),
        "ciphers": ciphers,
        "null_offered": has_null_cipher(ciphers),
        "anull_offered": has_anon_cipher(ciphers),
        "verdicts": {
            "cipherlist_NULL": verdict("cipherlist_NULL", ciphers),
            "cipherlist_aNULL": verdict("cipherlist_aNULL", ciphers),
        },
    }


def _main(argv):
    if len(argv) >= 2 and argv[0] == "confirm":
        host = argv[1]
        port = argv[2] if len(argv) > 2 else "443"
        print(json.dumps(confirm(host, port), ensure_ascii=False))
        return 0
    if len(argv) >= 2 and argv[0] == "count":
        try:
            with open(argv[1], encoding="utf-8") as fh:
                print(count_terminal_tls_issues(json.load(fh)))
        except Exception:
            print(0)
        return 0
    sys.stderr.write("uso: tls_confirm.py confirm <host> [port] | count <testssl.json>\n")
    return 2


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv[1:]))

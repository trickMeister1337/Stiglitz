#!/usr/bin/env python3
"""zap_authgate.py — detector de FP "JWT-gate" para alertas ZAP active-scan.

Quando o ZAP roda DESLOGADO contra uma API auth-gated, a requisição de ataque
recebe 401/403 ANTES de qualquer processamento; o heurístico active-scan compara
dois 401 idênticos e reporta um falso positivo (SQLi/XSS/etc.). Aqui detectamos
esses casos pelo status HTTP que a PRÓPRIA requisição de ataque recebeu
(capturado na Fase 9) e os separamos para uma seção "deferred / requires
authenticated retest" — fora das contagens de severidade.

Auto-ajuste: se o scan fosse autenticado, o ataque receberia 200 (não 401) e o
finding NÃO seria deferido — sem checagem separada de "tinha token?".

Padrão do projeto: lógica pura + runner injetável (testável sem rede) + CLI.
"""
import json
import re
import sys
import urllib.request

_STATUS_RE = re.compile(r"^HTTP/[0-9.]+\s+(\d{3})\b")
_GATE_STATUSES = (401, 403)


def extract_status(response_header):
    """Status HTTP da 1ª linha do response header do ZAP, ou None."""
    if not response_header:
        return None
    m = _STATUS_RE.match(str(response_header).lstrip())
    return int(m.group(1)) if m else None


def needs_status(alert):
    """True se o alerta é active-scan (tem `attack`) e ainda não tem attack_status."""
    return bool(alert.get("attack")) and "attack_status" not in alert


def enrich(alerts, fetch_fn):
    """Resolve attack_status para os alertas active-scan via fetch_fn(message_id)
    -> response_header_str. Dedup por messageId; falha do fetch -> status ausente.
    Muta `alerts` in place e retorna a lista."""
    cache = {}
    for a in alerts:
        if not needs_status(a):
            continue
        mid = a.get("messageId")
        if mid in (None, ""):
            continue
        if mid not in cache:
            try:
                cache[mid] = extract_status(fetch_fn(mid))
            except Exception:
                cache[mid] = None
        st = cache[mid]
        if st is not None:
            a["attack_status"] = st
    return alerts


def is_authgated_fp(alert):
    """True quando o alerta active-scan foi barrado pelo gate de auth:
    tem `attack` E attack_status ∈ {401,403}. Conservador: status ausente ou
    fora desse conjunto -> False (não esconde)."""
    return bool(alert.get("attack")) and alert.get("attack_status") in _GATE_STATUSES


def _fetch_message_header(base_url):
    """fetch_fn real: GET core/view/message/?id=<mid> no ZAP (localhost) ->
    responseHeader. Sem proxy (controle ZAP é sempre direto)."""
    def fetch(mid):
        u = f"{base_url}/JSON/core/view/message/?id={mid}"
        with urllib.request.urlopen(u, timeout=10) as r:
            data = json.loads(r.read().decode("utf-8", "replace"))
        return (data.get("message") or {}).get("responseHeader", "")
    return fetch


def main(argv):
    # uso: zap_authgate.py enrich <zap_alerts.json> <zap_base_url>
    if len(argv) >= 3 and argv[0] == "enrich":
        path, base = argv[1], argv[2].rstrip("/")
        try:
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, ValueError):
            return 0  # degrada em silêncio
        alerts = data.get("alerts", []) if isinstance(data, dict) else []
        try:
            enrich(alerts, _fetch_message_header(base))
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(data, fh, ensure_ascii=False)
        except Exception:
            return 0  # nunca aborta a fase
        return 0
    print("uso: zap_authgate.py enrich <zap_alerts.json> <zap_base_url>", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

# tests/test_mtls_stiglitz_curl_parity.py
"""Regression guard: toda chamada curl ao alvo em stiglitz.sh que carrega
${_PROXY_CURL[@]} deve também carregar ${_MTLS_CURL[@]} na mesma linha.

Exclusões legítimas:
- Linha de declaração da variável (sem 'curl' como comando)
- Chamadas ffuf: _PROXY_CURL é passado como -x ao ffuf, mTLS já coberto por _MTLS_FFUF
  (a linha do ffuf não contém 'curl')
- Curls de API ZAP (localhost) e notificações: não usam _PROXY_CURL (confirmado em grep)
"""
import os

STIGLITZ_SH = os.path.join(os.path.dirname(__file__), "..", "stiglitz.sh")


def test_every_proxy_curl_also_carries_mtls_curl():
    """Toda linha com ${_PROXY_CURL[@]} que invoca curl deve ter ${_MTLS_CURL[@]}."""
    with open(STIGLITZ_SH, encoding="utf-8") as fh:
        lines = fh.readlines()

    offenders = []
    for lineno, line in enumerate(lines, 1):
        if '"${_PROXY_CURL[@]}"' not in line:
            continue
        # Pular linhas de declaração/atribuição e chamadas não-curl (ffuf, etc.)
        if "curl" not in line:
            continue
        if '"${_MTLS_CURL[@]}"' not in line:
            offenders.append((lineno, line.rstrip()))

    assert not offenders, (
        "As seguintes linhas com _PROXY_CURL são chamadas curl ao alvo mas "
        "não carregam _MTLS_CURL — mTLS ficaria ausente em targets mTLS:\n"
        + "\n".join(f"  linha {n}: {l}" for n, l in offenders)
    )

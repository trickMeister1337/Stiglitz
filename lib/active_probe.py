# lib/active_probe.py
#!/usr/bin/env python3
"""
Stiglitz — Active Probe (par booleano + canário de reflexão).

Núcleo puro (sem rede) reusado pelos validators de injeção via poc_validator:
  - boolean_pair_verdict(): confirma SQLi blind boolean-based pelo diferencial
    true/false vs baseline.
  - canary_reflection(): confirma XSS refletido por marcador único + chars de quebra.
  - build_boolean_variants()/build_canary_variant(): montam as requests dos probes
    a partir de URL/method/body estruturados (shell-safety fica no orquestrador).

Espelha o padrão de lib/bola.py (veredito puro + reuso de normalize/response_diff
+ CLI). Sem domínio hardcoded, sem rede no núcleo.
"""
import os, re, sys, json, difflib
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode

# Reuso do normalize do poc_validator (remove tokens dinâmicos); fallback se
# importado fora do pacote. A comparação de CONTEÚDO usa difflib (não o
# response_diff, que é baseado em tamanho/erro e não distingue corpos de tamanho
# parecido com conteúdo diferente — exatamente o caso TRUE vs FALSE).
try:
    from poc_validator import normalize as _normalize
except Exception:
    def _normalize(t):
        return re.sub(r"\s+", " ", (t or "")).strip()

_SIMILAR_THRESHOLD = 0.95   # >= → corpos considerados "≈ iguais"


def _similar(a, b):
    """True se os corpos normalizados são ≈ iguais (ratio difflib >= threshold)."""
    a, b = _normalize(a), _normalize(b)
    if not a and not b:
        return True
    return difflib.SequenceMatcher(None, a, b).ratio() >= _SIMILAR_THRESHOLD


def boolean_pair_verdict(baseline_norm, true_norm, false_norm):
    """Confirma SQLi blind boolean-based pelo diferencial true/false.

    Retorna {confirmed, confidence, note}:
      TRUE≈baseline ∧ FALSE≠baseline ∧ TRUE≠FALSE → confirmed=True,  conf=88
      tudo ≈ igual (condição sem efeito)           → confirmed=False, conf=25
      sinal parcial (só um critério)               → confirmed=False, conf=40
      baseline pequeno (<50 chars normalizados)    → inconclusivo,    conf=20
    """
    if len(_normalize(baseline_norm)) < 50:
        return {"confirmed": False, "confidence": 20,
                "note": "Baseline pequeno demais para par booleano"}

    true_eq_base   = _similar(baseline_norm, true_norm)
    false_neq_base = not _similar(baseline_norm, false_norm)
    true_neq_false = not _similar(true_norm, false_norm)

    if true_eq_base and false_neq_base and true_neq_false:
        return {"confirmed": True, "confidence": 88,
                "note": "Par booleano: TRUE≈baseline, FALSE≠baseline"}
    if not false_neq_base and not true_neq_false:
        return {"confirmed": False, "confidence": 25,
                "note": "Condição sem efeito (true≈false≈baseline)"}
    return {"confirmed": False, "confidence": 40,
            "note": "Sinal parcial — diferencial booleano incompleto"}

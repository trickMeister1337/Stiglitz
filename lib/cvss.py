#!/usr/bin/env python3
"""
cvss.py — Calculadora CVSS 3.1 (Base + Temporal + Environmental).

Implementação pura (sem IO, sem dependência em runtime) conforme a
especificação oficial CVSS v3.1. Validada contra a biblioteca `cvss`
nos testes. Funções no estilo de risk_score.py.
"""
import math
from decimal import Decimal as _D, ROUND_CEILING as _ROUND_CEILING

PREFIX = "CVSS:3.1"

# Métricas válidas por chave (X = Not Defined, usado em Temporal/Environmental).
_VALID = {
    "AV": "NALP", "AC": "LH", "PR": "NLH", "UI": "NR", "S": "UC",
    "C": "HLN", "I": "HLN", "A": "HLN",
    "E": "XHFPU", "RL": "XOTWU", "RC": "XCRU",
    "CR": "XHML", "IR": "XHML", "AR": "XHML",
    "MAV": "XNALP", "MAC": "XLH", "MPR": "XNLH", "MUI": "XNR", "MS": "XUC",
    "MC": "XHLN", "MI": "XHLN", "MA": "XHLN",
}

# ── Pesos das métricas (CVSS 3.1) ────────────────────────────────────────────
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}   # Scope Unchanged
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.5}    # Scope Changed
_UI = {"N": 0.85, "R": 0.62}
_IMPACT = {"H": 0.56, "L": 0.22, "N": 0.0}

_E = {"X": 1.0, "H": 1.0, "F": 0.97, "P": 0.94, "U": 0.91}
_RL = {"X": 1.0, "U": 1.0, "W": 0.97, "T": 0.96, "O": 0.95}
_RC = {"X": 1.0, "C": 1.0, "R": 0.96, "U": 0.92}

_CIA_REQ = {"X": 1.0, "H": 1.5, "M": 1.0, "L": 0.5}

# Ordem canônica das métricas para serialização determinística.
_ORDER = ["AV", "AC", "PR", "UI", "S", "C", "I", "A",
          "E", "RL", "RC",
          "CR", "IR", "AR",
          "MAV", "MAC", "MPR", "MUI", "MS", "MC", "MI", "MA"]


def roundup(x):
    """Roundup oficial CVSS 3.1 (ceiling na 1ª casa decimal)."""
    return float(_D(str(x)).quantize(_D("0.1"), rounding=_ROUND_CEILING))


def _pr_weight(pr, scope):
    return (_PR_C if scope == "C" else _PR_U)[pr]


def _iss(c_, i_, a_):
    return 1 - (1 - _IMPACT[c_]) * (1 - _IMPACT[i_]) * (1 - _IMPACT[a_])


def base_score(m):
    """Calcula o Base Score CVSS 3.1 a partir do dict de métricas."""
    iss = _iss(m["C"], m["I"], m["A"])
    if m["S"] == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    expl = 8.22 * _AV[m["AV"]] * _AC[m["AC"]] * _pr_weight(m["PR"], m["S"]) * _UI[m["UI"]]
    if impact <= 0:
        return 0.0
    if m["S"] == "U":
        return roundup(min(impact + expl, 10))
    return roundup(min(1.08 * (impact + expl), 10))


def temporal_score(m):
    """Temporal = roundup(Base × E × RL × RC)."""
    base = base_score(m)
    return roundup(base * _E[m.get("E", "X")] * _RL[m.get("RL", "X")] * _RC[m.get("RC", "X")])


def _mod(m, key):
    """Valor de métrica modificada: usa M<key> se definido (≠X), senão a base."""
    mkey = "M" + key
    v = m.get(mkey, "X")
    return m[key] if v == "X" else v


def environmental_score(m):
    """Environmental Score CVSS 3.1 (com Temporal aplicado)."""
    mav, mac, mui, ms = _mod(m, "AV"), _mod(m, "AC"), _mod(m, "UI"), _mod(m, "S")
    mc, mi, ma = _mod(m, "C"), _mod(m, "I"), _mod(m, "A")
    # MPR depende do Modified Scope
    mpr = m["PR"] if m.get("MPR", "X") == "X" else m["MPR"]

    cr = _CIA_REQ[m.get("CR", "X")]
    ir = _CIA_REQ[m.get("IR", "X")]
    ar = _CIA_REQ[m.get("AR", "X")]

    miss = min(
        1 - (1 - cr * _IMPACT[mc]) * (1 - ir * _IMPACT[mi]) * (1 - ar * _IMPACT[ma]),
        0.915,
    )
    if ms == "U":
        mimpact = 6.42 * miss
    else:
        mimpact = 7.52 * (miss - 0.029) - 3.25 * (miss * 0.9731 - 0.02) ** 13
    mexpl = 8.22 * _AV[mav] * _AC[mac] * _pr_weight(mpr, ms) * _UI[mui]

    if mimpact <= 0:
        return 0.0
    e = _E[m.get("E", "X")] * _RL[m.get("RL", "X")] * _RC[m.get("RC", "X")]
    if ms == "U":
        return roundup(roundup(min(mimpact + mexpl, 10)) * e)
    return roundup(roundup(min(1.08 * (mimpact + mexpl), 10)) * e)


def band(score):
    """Mapeia score 0-10 → banda qualitativa CVSS 3.1 (usa 'info' para None)."""
    if score == 0.0:
        return "info"
    if score < 4.0:
        return "low"
    if score < 7.0:
        return "medium"
    if score < 9.0:
        return "high"
    return "critical"


def to_vector(m):
    """Serializa dict de métricas → string de vetor (ordem canônica, omite X)."""
    parts = [PREFIX]
    for key in _ORDER:
        v = m.get(key)
        if v and v != "X":
            parts.append(f"{key}:{v}")
    return "/".join(parts)


def parse_vector(vector):
    """Parseia uma string de vetor CVSS 3.1 → dict {metric: value}."""
    if not vector.startswith(PREFIX + "/"):
        raise ValueError(f"Vetor CVSS 3.1 inválido (prefixo): {vector!r}")
    metrics = {}
    for part in vector[len(PREFIX) + 1:].split("/"):
        if not part:
            continue
        if ":" not in part:
            raise ValueError(f"Componente inválido: {part!r}")
        key, _, val = part.partition(":")
        if key not in _VALID or val not in _VALID[key]:
            raise ValueError(f"Métrica inválida: {part!r}")
        if key in metrics:
            raise ValueError(f"Métrica duplicada: {key!r}")
        metrics[key] = val
    for req in ("AV", "AC", "PR", "UI", "S", "C", "I", "A"):
        if req not in metrics:
            raise ValueError(f"Métrica base ausente: {req}")
    return metrics

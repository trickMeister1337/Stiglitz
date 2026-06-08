# tests/test_active_probe.py
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
import active_probe as ap


# Corpos com >50B para passar o guard do response_diff.
BASE = "Resultado da busca: produto Apple encontrado no catalogo. " * 3
DIFF = "Nenhum resultado encontrado para a sua consulta no catalogo. " * 3


def test_boolean_pair_confirms_on_true_eq_base_false_differs():
    v = ap.boolean_pair_verdict(BASE, BASE, DIFF)
    assert v["confirmed"] is True
    assert v["confidence"] == 88
    assert "booleano" in v["note"].lower()


def test_boolean_pair_no_effect_not_confirmed():
    # true == false == baseline → condição sem efeito
    v = ap.boolean_pair_verdict(BASE, BASE, BASE)
    assert v["confirmed"] is False
    assert v["confidence"] == 25


def test_boolean_pair_partial_not_confirmed():
    # true difere do baseline (sinal parcial) → não confirma
    v = ap.boolean_pair_verdict(BASE, DIFF, DIFF)
    assert v["confirmed"] is False
    assert v["confidence"] == 40


def test_boolean_pair_small_baseline_inconclusive():
    v = ap.boolean_pair_verdict("curto", "outro", "mais")
    assert v["confirmed"] is False
    assert v["confidence"] == 20

# tests/test_repro.py
import os, sys, json
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
import repro as R


def test_gate_high_and_critical_pass():
    assert R.passes_gate({"severity": "high"}) is True
    assert R.passes_gate({"severity": "critical"}) is True


def test_gate_confirmed_category_passes():
    assert R.passes_gate({"severity": "low", "confirmed_category": "exploit"}) is True
    assert R.passes_gate({"severity": "info", "confirmed_category": "verified"}) is True


def test_gate_confirmed_bool_passes():
    assert R.passes_gate({"severity": "low", "confirmed": True}) is True


def test_gate_info_low_without_confirmation_fail():
    assert R.passes_gate({"severity": "info"}) is False
    assert R.passes_gate({"severity": "low"}) is False

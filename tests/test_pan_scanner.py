import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
import pan_scanner as ps

def test_luhn_valid_and_invalid():
    assert ps.luhn("4111111111111111")
    assert ps.luhn("5500000000000004")
    assert not ps.luhn("4111111111111112")

def test_mask_keeps_bin_and_last4():
    assert ps.mask("4111111111111111") == "411111******1111"

def test_scan_text_detects_pan_with_context():
    body = "erro ao salvar card=4111111111111111 cvv=123"
    hits = ps.scan_text(body)
    assert hits == ["411111******1111"]

def test_scan_text_ignores_random_long_number():
    body = "order id 1234567890123456 timestamp 9999999999999999"
    assert ps.scan_text(body) == []

def test_scan_text_luhn_valid_but_no_context():
    body = "transaction id 4111111111111111 processed ok"
    assert ps.scan_text(body) == []

def test_mask_amex_15_digit():
    assert ps.mask("378282246310005") == "378282*****0005"

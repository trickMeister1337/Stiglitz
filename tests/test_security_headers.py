import os, sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))

import security_headers as SH


# ── classify_header: present / missing / inconsistent ─────────────────────────
def test_classify_present_when_all_samples_have_it():
    assert SH.classify_header([True, True, True]) == "present"


def test_classify_missing_when_no_sample_has_it():
    assert SH.classify_header([False, False, False]) == "missing"


def test_classify_inconsistent_when_mixed():
    # exatamente o FP transitório observado ao vivo num alvo PROD:
    # algumas respostas trazem o header, outras não (config drift / LB).
    assert SH.classify_header([True, False, True]) == "inconsistent"


def test_classify_no_samples_is_missing():
    assert SH.classify_header([]) == "missing"


def test_classify_single_present():
    assert SH.classify_header([True]) == "present"


# ── header_present: detecção numa resposta crua ───────────────────────────────
def test_header_present_true():
    raw = "HTTP/2 200\nstrict-transport-security: max-age=31536000\nx-foo: 1\n".lower()
    assert SH.header_present(raw, "strict-transport-security") is True


def test_header_present_false():
    raw = "HTTP/2 200\nx-foo: 1\n".lower()
    assert SH.header_present(raw, "strict-transport-security") is False


# ── garantia anti-regressão: header presente em ≥1 amostra NÃO é "missing" ─────
def test_inconsistent_is_not_counted_as_missing():
    # o objetivo do hardening: nunca reportar como ausente um header que aparece
    # em alguma amostra (foi a origem do falso "HSTS missing").
    assert SH.classify_header([False, True, False]) != "missing"

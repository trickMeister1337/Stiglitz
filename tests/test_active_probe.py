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


def test_canary_reflection_raw_chars_confirms():
    body = 'foo <div>stg1a2b3c4d<"> bar</div>'   # PROBE_CHARS crus após o token
    v = ap.canary_reflection("stg1a2b3c4d", body)
    assert v["reflected"] is True
    assert v["encoded"] is False
    assert v["confidence"] == 90


def test_canary_reflection_encoded_is_safe():
    body = 'foo stg1a2b3c4d&lt;&quot;&gt; bar'   # PROBE_CHARS HTML-escapados
    v = ap.canary_reflection("stg1a2b3c4d", body)
    assert v["reflected"] is True
    assert v["encoded"] is True
    assert v["confidence"] == 35


def test_canary_reflection_absent():
    v = ap.canary_reflection("stg1a2b3c4d", "nenhum marcador aqui")
    assert v["reflected"] is False
    assert v["confidence"] == 0


def test_build_boolean_variants_query_injectable():
    url = "http://t.com/search?q=1'+OR+'1'='1&page=2"
    t, f = ap.build_boolean_variants(url)
    assert t["method"] == "GET" and f["method"] == "GET"
    assert "page=2" in t["url"] and "page=2" in f["url"]
    assert "AND+%271%27%3D%271" in t["url"]   # ' AND '1'='1 url-encoded
    assert "AND+%271%27%3D%272" in f["url"]   # ' AND '1'='2
    assert t["url"] != f["url"]


def test_build_boolean_variants_no_injectable_param_returns_none():
    assert ap.build_boolean_variants("http://t.com/page?id=42&name=bob") is None


def test_build_boolean_variants_body_payload_returns_none():
    # payload no body (não na query) → fora de escopo desta fase
    assert ap.build_boolean_variants("http://t.com/api", method="POST",
                                     body="q=1' OR '1'='1") is None


def test_build_canary_variant_injects_token():
    url = "http://t.com/p?name=<script>alert(1)</script>&x=1"
    token = "stgdeadbeef"
    req = ap.build_canary_variant(url, token)
    assert req is not None
    assert "x=1" in req["url"]
    assert "stgdeadbeef" in req["url"]
    assert "%3C%22%3E" in req["url"]   # PROBE_CHARS <"> url-encoded


def test_build_canary_variant_no_xss_param_returns_none():
    assert ap.build_canary_variant("http://t.com/p?id=42", "stgdeadbeef") is None

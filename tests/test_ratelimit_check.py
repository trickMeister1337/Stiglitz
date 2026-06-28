# tests/test_ratelimit_check.py
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
import ratelimit_check as rc


def test_signal_limited_on_429():
    assert rc.rate_limit_signal([403, 429], True, False) == "limited"


def test_signal_limited_on_retry_after():
    assert rc.rate_limit_signal([200, 200], False, True) == "limited"


def test_signal_gated_when_all_403():
    # FP do auth-gate: 20×403 (AWS API Gateway) → inconclusivo, não "sem rate limiting"
    assert rc.rate_limit_signal([403] * 20, False, False) == "gated"


def test_signal_unlimited_when_handler_reached():
    # respostas de um handler real de login (sem throttle) → ausência real de rate limit
    assert rc.rate_limit_signal([401, 401, 200, 400], False, False) == "unlimited"


def test_signal_mixed_403_not_gated():
    # 403 misturado com resposta de handler → não é gate puro
    assert rc.rate_limit_signal([403, 401, 401], False, False) == "unlimited"


def test_signal_empty_is_unlimited():
    # sem códigos úteis (ex.: só 0/falhas) → não classifica como gated
    assert rc.rate_limit_signal([0, 0], False, False) == "unlimited"

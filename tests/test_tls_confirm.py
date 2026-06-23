import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
import tls_confirm as tc  # noqa: E402

# Saída real do nmap ssl-enum-ciphers contra um ALB AWS (pos.example.com): só
# ciphers grade A. O testssl reportou NULL/aNULL "offered" (CRITICAL) — FP.
NMAP_STRONG = """\
| ssl-enum-ciphers:
|   TLSv1.2:
|     ciphers:
|       TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (ecdh_x25519) - A
|       TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 (ecdh_x25519) - A
|       TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (ecdh_x25519) - A
|       TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 (ecdh_x25519) - A
|     compressors:
|       NULL
|     cipher preference: server
|   TLSv1.3:
|     ciphers:
|       TLS_AKE_WITH_AES_128_GCM_SHA256 (ecdh_x25519) - A
|       TLS_AKE_WITH_AES_256_GCM_SHA384 (ecdh_x25519) - A
|       TLS_AKE_WITH_CHACHA20_POLY1305_SHA256 (ecdh_x25519) - A
|     cipher preference: server
|_  least strength: A
"""

# Servidor realmente inseguro: oferece NULL e anon ciphers.
NMAP_WEAK = """\
| ssl-enum-ciphers:
|   TLSv1.2:
|     ciphers:
|       TLS_RSA_WITH_NULL_SHA256 (rsa 2048) - F
|       TLS_ECDH_anon_WITH_AES_128_CBC_SHA (secp256r1) - F
|       TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (ecdh_x25519) - A
|     compressors:
|       NULL
|_  least strength: F
"""


def test_parse_extracts_only_graded_cipher_lines():
    ciphers = tc.parse_ssl_enum_ciphers(NMAP_STRONG)
    assert "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" in ciphers
    assert "TLS_AKE_WITH_CHACHA20_POLY1305_SHA256" in ciphers
    assert len(ciphers) == 7


def test_parse_does_not_treat_compressor_null_as_cipher():
    # A armadilha exata do FP: "NULL" sob compressors NÃO é um cipher.
    ciphers = tc.parse_ssl_enum_ciphers(NMAP_STRONG)
    assert "NULL" not in ciphers
    assert tc.has_null_cipher(ciphers) is False
    assert tc.has_anon_cipher(ciphers) is False


def test_parse_ignores_least_strength_line():
    ciphers = tc.parse_ssl_enum_ciphers(NMAP_STRONG)
    assert not any("strength" in c.lower() for c in ciphers)


def test_detects_real_null_and_anon_ciphers():
    ciphers = tc.parse_ssl_enum_ciphers(NMAP_WEAK)
    assert tc.has_null_cipher(ciphers) is True
    assert tc.has_anon_cipher(ciphers) is True


def test_verdict_refutes_testssl_null_fp_against_strong_server():
    ciphers = tc.parse_ssl_enum_ciphers(NMAP_STRONG)
    assert tc.verdict("cipherlist_NULL", ciphers) == "refuted"
    assert tc.verdict("cipherlist_aNULL", ciphers) == "refuted"


def test_verdict_confirms_when_really_offered():
    ciphers = tc.parse_ssl_enum_ciphers(NMAP_WEAK)
    assert tc.verdict("cipherlist_NULL", ciphers) == "confirmed"
    assert tc.verdict("cipherlist_aNULL", ciphers) == "confirmed"


def test_verdict_unknown_id_is_inconclusive():
    ciphers = tc.parse_ssl_enum_ciphers(NMAP_STRONG)
    assert tc.verdict("cipherlist_3DES_IDEA", ciphers) == "inconclusive"


def test_confirm_uses_injected_runner_no_network():
    # runner injetável (padrão send_fn do projeto) — testável sem rede.
    calls = {}

    def fake_runner(host, port):
        calls["host"] = host
        calls["port"] = port
        return NMAP_STRONG

    result = tc.confirm("pos.example.com", 443, runner=fake_runner)
    assert calls == {"host": "pos.example.com", "port": 443}
    assert result["null_offered"] is False
    assert result["anull_offered"] is False
    assert result["verdicts"]["cipherlist_NULL"] == "refuted"
    assert result["verdicts"]["cipherlist_aNULL"] == "refuted"
    assert "TLS_AKE_WITH_AES_128_GCM_SHA256" in result["ciphers"]


# ── Bug #3: contagem de problemas TLS do terminal (count_terminal_tls_issues) ──
# O contador do terminal (stiglitz.sh) divergia do findings.json: contava
# artefatos do scanner local ("not supported by local OpenSSL"), o metadado
# scanTime e duplicava o mesmo id por múltiplos IPs A-record. Os critérios devem
# espelhar o stiglitz_report.py.

def test_count_ignores_local_openssl_artifact():
    findings = [
        {"id": "RC4", "severity": "WARN", "finding": "RC4: not supported by local OpenSSL"},
        {"id": "cipherlist_3DES_IDEA", "severity": "LOW", "finding": "offered"},
    ]
    assert tc.count_terminal_tls_issues(findings) == 1


def test_count_dedups_same_id_across_ips():
    findings = [
        {"id": "CAA", "severity": "LOW", "finding": "missing", "ip": "1.2.3.4"},
        {"id": "CAA", "severity": "LOW", "finding": "missing", "ip": "5.6.7.8"},
    ]
    assert tc.count_terminal_tls_issues(findings) == 1


def test_count_ignores_scantime_and_ok():
    findings = [
        {"id": "scanTime", "severity": "INFO", "finding": "120"},
        {"id": "TLS1", "severity": "OK", "finding": "not offered"},
        {"id": "BREACH", "severity": "WARN", "finding": "potentially vulnerable"},
    ]
    assert tc.count_terminal_tls_issues(findings) == 1


def test_count_handles_scanresult_wrapper():
    data = {"scanResult": [{"findings": [
        {"id": "BREACH", "severity": "WARN", "finding": "vuln"},
        {"id": "scanTime", "severity": "INFO", "finding": "10"},
    ]}]}
    assert tc.count_terminal_tls_issues(data) == 1


def test_count_empty_is_zero():
    assert tc.count_terminal_tls_issues([]) == 0

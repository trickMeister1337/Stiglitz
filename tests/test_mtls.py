import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
import mtls as M
import pytest


@pytest.fixture(autouse=True)
def _clear_env(monkeypatch):
    monkeypatch.delenv("STIGLITZ_MTLS_CERT", raising=False)
    monkeypatch.delenv("STIGLITZ_MTLS_KEY", raising=False)


def _write(p, text):
    p.write_text(text, encoding="utf-8")
    return str(p)


def test_disabled_by_default():
    assert M.is_enabled() is False
    assert M.curl_cert_args() == []
    assert M.validate() is None  # no-op


def test_enabled_when_both_set(monkeypatch, tmp_path):
    c = _write(tmp_path / "c.pem", "cert"); k = _write(tmp_path / "k.pem", "key")
    monkeypatch.setenv("STIGLITZ_MTLS_CERT", c)
    monkeypatch.setenv("STIGLITZ_MTLS_KEY", k)
    assert M.is_enabled() is True
    assert M.curl_cert_args() == ["--cert", c, "--key", k]


def test_partial_config_is_error(monkeypatch, tmp_path):
    monkeypatch.setenv("STIGLITZ_MTLS_CERT", _write(tmp_path / "c.pem", "cert"))
    assert M.is_enabled() is False
    with pytest.raises(M.MtlsConfigError):
        M.validate()


def test_validate_missing_file(monkeypatch, tmp_path):
    monkeypatch.setenv("STIGLITZ_MTLS_CERT", str(tmp_path / "nope.pem"))
    monkeypatch.setenv("STIGLITZ_MTLS_KEY", _write(tmp_path / "k.pem", "key"))
    with pytest.raises(M.MtlsConfigError):
        M.validate()


def test_validate_rejects_encrypted_key(monkeypatch, tmp_path):
    c = _write(tmp_path / "c.pem", "-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----")
    k = _write(tmp_path / "k.pem", "-----BEGIN ENCRYPTED PRIVATE KEY-----\nx\n-----END ENCRYPTED PRIVATE KEY-----")
    monkeypatch.setenv("STIGLITZ_MTLS_CERT", c)
    monkeypatch.setenv("STIGLITZ_MTLS_KEY", k)
    with pytest.raises(M.MtlsConfigError):
        M.validate()


def test_key_is_encrypted_detects_traditional_pem(tmp_path):
    k = _write(tmp_path / "k.pem", "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\n")
    assert M.key_is_encrypted(k) is True
    plain = _write(tmp_path / "p.pem", "-----BEGIN PRIVATE KEY-----\nMIIxxx\n")
    assert M.key_is_encrypted(plain) is False


import ssl as _ssl


def _gen_pair(tmp_path):
    """Par cert+key PEM auto-assinado p/ teste (cryptography)."""
    pytest.importorskip("cryptography")  # CI não instala cryptography; pula em vez de falhar (espelha test_netproxy_mtls.py)
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    import datetime
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test")])
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime(2020, 1, 1))
            .not_valid_after(datetime.datetime(2030, 1, 1))
            .sign(key, hashes.SHA256()))
    cpath = tmp_path / "cert.pem"; kpath = tmp_path / "key.pem"
    cpath.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    kpath.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()))
    return str(cpath), str(kpath)


def test_client_ssl_context_none_when_disabled():
    assert M.client_ssl_context() is None


def test_client_ssl_context_loads_pair(monkeypatch, tmp_path):
    c, k = _gen_pair(tmp_path)
    monkeypatch.setenv("STIGLITZ_MTLS_CERT", c)
    monkeypatch.setenv("STIGLITZ_MTLS_KEY", k)
    ctx = M.client_ssl_context()
    assert isinstance(ctx, _ssl.SSLContext)
    assert ctx.verify_mode == _ssl.CERT_NONE  # servidor segue skip-verify (scanner)

# tests/test_netproxy_mtls.py
import os, sys, ssl, datetime
import urllib.request
import pytest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
import netproxy


def _https_handlers(opener):
    return [h for h in opener.handlers if isinstance(h, urllib.request.HTTPSHandler)]


class _FakeCtx:
    """Substituto leve de ssl.SSLContext p/ capturar chamadas a load_cert_chain.
    Permite testar a augmentação sem depender de métodos C-extension não-patcháveis."""
    def __init__(self):
        self.loaded = []

    def load_cert_chain(self, certfile, keyfile=None):
        self.loaded.append((certfile, keyfile))


def _gen_pair(tmp_path):
    """Par cert+key PEM auto-assinado (requer cryptography)."""
    pytest.importorskip("cryptography")
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test")])
    cert_obj = (x509.CertificateBuilder()
                .subject_name(name).issuer_name(name).public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(datetime.datetime(2020, 1, 1))
                .not_valid_after(datetime.datetime(2030, 1, 1))
                .sign(key, hashes.SHA256()))
    cp = tmp_path / "cert.pem"; kp = tmp_path / "key.pem"
    cp.write_bytes(cert_obj.public_bytes(serialization.Encoding.PEM))
    kp.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()))
    return str(cp), str(kp)


# ── testes make_opener (None path) ────────────────────────────────────────────

def test_make_opener_uses_mtls_context_when_none(monkeypatch):
    called = []
    ctx = ssl.create_default_context()
    monkeypatch.setattr(netproxy, "_mtls_context", lambda: (called.append(1) or ctx))
    monkeypatch.delenv("STIGLITZ_PROXY", raising=False)
    opener = netproxy.make_opener()
    assert called, "make_opener deve consultar o mtls quando ssl_context é None"
    hs = _https_handlers(opener)
    assert hs and getattr(hs[0], "_context", None) is ctx


# ── I1 fix: context explícito + mTLS ativo → cert carregado no context ────────

def test_apply_mtls_augments_explicit_context_when_enabled(monkeypatch, tmp_path):
    """_apply_mtls com mTLS ativo: carrega cert no context fornecido (fix C2/I1)."""
    c, k = _gen_pair(tmp_path)
    monkeypatch.setenv("STIGLITZ_MTLS_CERT", c)
    monkeypatch.setenv("STIGLITZ_MTLS_KEY", k)
    ctx = _FakeCtx()
    result = netproxy._apply_mtls(ctx)
    assert result is ctx, "_apply_mtls deve retornar o mesmo object context"
    assert ctx.loaded == [(c, k)], (
        "cert e key devem ser carregados no context explícito quando mTLS está ativo")


def test_apply_mtls_noop_when_disabled(monkeypatch):
    """_apply_mtls com mTLS desativado: context explícito retorna intacto."""
    monkeypatch.delenv("STIGLITZ_MTLS_CERT", raising=False)
    monkeypatch.delenv("STIGLITZ_MTLS_KEY", raising=False)
    ctx = _FakeCtx()
    result = netproxy._apply_mtls(ctx)
    assert result is ctx
    assert ctx.loaded == [], "load_cert_chain não deve ser chamado sem mTLS"


def test_apply_mtls_none_with_enabled_returns_ssl_context(monkeypatch, tmp_path):
    """_apply_mtls(None) com mTLS ativo retorna SSLContext real com cert."""
    c, k = _gen_pair(tmp_path)
    monkeypatch.setenv("STIGLITZ_MTLS_CERT", c)
    monkeypatch.setenv("STIGLITZ_MTLS_KEY", k)
    result = netproxy._apply_mtls(None)
    assert isinstance(result, ssl.SSLContext)


def test_apply_mtls_none_disabled_returns_none(monkeypatch):
    """_apply_mtls(None) sem mTLS retorna None."""
    monkeypatch.delenv("STIGLITZ_MTLS_CERT", raising=False)
    monkeypatch.delenv("STIGLITZ_MTLS_KEY", raising=False)
    assert netproxy._apply_mtls(None) is None


# ── parity de opt-in ──────────────────────────────────────────────────────────

def test_mtls_context_returns_none_without_module(monkeypatch):
    # sem env mTLS, client_ssl_context retorna None → opener sem HTTPSHandler custom
    monkeypatch.delenv("STIGLITZ_MTLS_CERT", raising=False)
    monkeypatch.delenv("STIGLITZ_MTLS_KEY", raising=False)
    monkeypatch.delenv("STIGLITZ_PROXY", raising=False)
    assert netproxy._mtls_context() is None

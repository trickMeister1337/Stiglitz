# tests/test_oauth_acquire_stiglitz.py
"""Guard: o bloco de auto-aquisição OAuth2 no stiglitz.sh deve (a) só disparar
quando AUTH_TOKEN está vazio (token manual vence), (b) invocar a CLI acquire,
(c) respeitar STIGLITZ_OAUTH_REQUIRED (fail-closed)."""
import os

STIGLITZ_SH = os.path.join(os.path.dirname(__file__), "..", "stiglitz.sh")


def _src():
    with open(STIGLITZ_SH, encoding="utf-8") as fh:
        return fh.read()


def test_acquire_block_invokes_cli():
    assert 'oauth_token.py" acquire' in _src() or 'oauth_token.py acquire' in _src()


def test_acquire_block_guards_on_empty_auth_token():
    src = _src()
    guard = src.index('[ -z "$AUTH_TOKEN" ]')
    invoke = src.index("oauth_token.py")
    # o guard de AUTH_TOKEN vazio aparece antes da invocação da aquisição
    assert guard < invoke


def test_acquire_block_respects_required():
    assert "STIGLITZ_OAUTH_REQUIRED" in _src()

# tests/test_graphql_stiglitz_integration.py
import os

ROOT = os.path.join(os.path.dirname(__file__), "..")


def _read(p):
    with open(os.path.join(ROOT, p), encoding="utf-8") as fh:
        return fh.read()


def test_dos_invoked_in_graphql_block():
    assert "graphql_dos.py" in _read("stiglitz.sh")


def test_p98_gated_on_two_tokens():
    src = _read("stiglitz.sh")
    assert "graphql_authz.py" in src
    # ancora no bloco da fase (não na ocorrência do registro _needs_network)
    i = src.index('_phase_enabled "P9_8"')
    window = src[i:i + 400]
    assert '[ -n "$TOKEN_A" ]' in window and '[ -n "$TOKEN_B" ]' in window


def test_graphql_mutate_flag_parsed():
    assert "--graphql-mutate" in _read("stiglitz.sh")


def test_report_ingests_new_json():
    src = _read("stiglitz_report.py")
    assert "graphql_dos.json" in src and "graphql_authz.json" in src


def test_pipeline_includes_p9_8():
    assert "P9_8" in _read("pipeline.py")

"""Testes do orquestrador pipeline.py (lógica pura, sem invocar ferramentas)."""
import json
import os
import sys

import pytest

# Os testes vivem em tests/; expõe a raiz do repo para importar pipeline.py.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pipeline import Phase, Pipeline, PipelineConfig, PipelineState, parse_args, _domain_of


@pytest.fixture
def outdir(tmp_path):
    return str(tmp_path / "scan_test")


def _cfg(outdir, **kw):
    kw.setdefault("target", "https://alvo.com")
    kw.setdefault("outdir", outdir)
    return PipelineConfig(**kw)


class RecordingRunner:
    """Runner injetável que registra os comandos e retorna rc programável."""
    def __init__(self, rc=0, fail_keys=None):
        self.calls = []
        self.rc = rc
        self.fail_keys = fail_keys or {}   # {phase_only: rc_sequence ou rc fixo}

    def __call__(self, cmd):
        self.calls.append(cmd)
        only = cmd[cmd.index("--only-phase") + 1]
        if only in self.fail_keys:
            v = self.fail_keys[only]
            return v.pop(0) if isinstance(v, list) and v else (v if isinstance(v, int) else 0)
        return self.rc


# ── plano / filtro ───────────────────────────────────────────────────────────
def test_plan_roda_todas_por_padrao(outdir):
    p = Pipeline(_cfg(outdir), runner=RecordingRunner())
    assert [ph.key for ph in p.plan()] == [ph.key for ph in p.phases]


def test_plan_filtra_only(outdir):
    p = Pipeline(_cfg(outdir, only=["P1", "P11"]), runner=RecordingRunner())
    assert [ph.key for ph in p.plan()] == ["P1", "P11"]


def test_p9_inclui_subfases_authz_na_mesma_invocacao(outdir):
    # P9.5/9.6/9.7/9.8 consomem o ZAP vivo iniciado pela P9 (o daemon morre no trap EXIT
    # de cada invocação do stiglitz.sh). Logo precisam rodar na MESMA invocação que a
    # P9, como unidade combinada (padrão P3_P4) — não como passos isolados do pipeline.
    p = Pipeline(_cfg(outdir), runner=RecordingRunner())
    p9 = [ph for ph in p.phases if ph.key == "P9"]
    assert len(p9) == 1
    assert p9[0].only == "P9 P9_5 P9_6 P9_7 P9_8"


def test_p3_p4_sao_unidade_combinada(outdir):
    p = Pipeline(_cfg(outdir), runner=RecordingRunner())
    p3p4 = [ph for ph in p.phases if ph.key == "P3_P4"]
    assert len(p3p4) == 1 and p3p4[0].only == "P3 P4"


# ── checkpoint (skip-if-done) ──────────────────────────────────────────────────
def test_resume_pula_fases_concluidas(outdir):
    runner = RecordingRunner()
    p = Pipeline(_cfg(outdir, only=["P1", "P2"]), runner=runner)
    p.state.mark("P1", "done")
    assert [ph.key for ph in p.plan()] == ["P2"]
    p.run(log=lambda *a: None)
    onlys = [c[c.index("--only-phase") + 1] for c in runner.calls]
    assert onlys == ["P2"]   # P1 não reexecutado


def test_no_resume_reexecuta_tudo(outdir):
    runner = RecordingRunner()
    p = Pipeline(_cfg(outdir, only=["P1"], resume=False), runner=runner)
    p.state.mark("P1", "done")
    assert [ph.key for ph in p.plan()] == ["P1"]


# ── retry ──────────────────────────────────────────────────────────────────────
def test_retry_reexecuta_ate_sucesso(outdir):
    # P1 falha 1x (rc=2) e depois passa (rc=0)
    runner = RecordingRunner(fail_keys={"P1": [2, 0]})
    p = Pipeline(_cfg(outdir, only=["P1"], retries=1), runner=runner)
    assert p.run(log=lambda *a: None) == 0
    assert len(runner.calls) == 2
    assert p.state.status("P1") == "done"


def test_aborta_quando_fase_falha_esgotando_retries(outdir):
    runner = RecordingRunner(fail_keys={"P1": 1})   # sempre rc=1
    p = Pipeline(_cfg(outdir, only=["P1", "P2"], retries=2), runner=runner)
    assert p.run(log=lambda *a: None) == 1
    assert len(runner.calls) == 3                   # 1 + 2 retries
    assert p.state.status("P1") == "failed"
    # P2 nunca chega a rodar
    onlys = [c[c.index("--only-phase") + 1] for c in runner.calls]
    assert "P2" not in onlys


# ── dry-run ──────────────────────────────────────────────────────────────────
def test_dry_run_nao_executa(outdir):
    runner = RecordingRunner()
    p = Pipeline(_cfg(outdir, dry_run=True), runner=runner)
    assert p.run(log=lambda *a: None) == 0
    assert runner.calls == []


# ── comando ────────────────────────────────────────────────────────────────────
def test_command_inclui_outdir_only_e_extras(outdir):
    p = Pipeline(_cfg(outdir, extra_args=["--token", "abc"]), runner=RecordingRunner())
    ph = next(x for x in p.phases if x.key == "P3_P4")
    cmd = p.command(ph)
    assert cmd[:3] == ["bash", p.cfg.script, "https://alvo.com"]
    assert "--outdir" in cmd and outdir in cmd
    assert cmd[cmd.index("--only-phase") + 1] == "P3 P4"
    assert cmd[-2:] == ["--token", "abc"]


# ── persistência de estado ──────────────────────────────────────────────────────
def test_estado_persiste_em_disco(outdir):
    runner = RecordingRunner()
    p = Pipeline(_cfg(outdir, only=["P1"]), runner=runner)
    p.run(log=lambda *a: None)
    sp = os.path.join(outdir, "raw", ".pipeline_state.json")
    assert os.path.exists(sp)
    data = json.load(open(sp))
    assert data["phases"]["P1"]["status"] == "done"
    # nova instância relê e respeita o checkpoint
    p2 = Pipeline(_cfg(outdir, only=["P1"]), runner=RecordingRunner())
    assert p2.plan() == []


# ── CLI ────────────────────────────────────────────────────────────────────────
def test_parse_args_only_e_passthrough():
    cfg = parse_args(["https://x.com", "--only", "P1,P5", "--token", "t", "--retries", "2"])
    assert cfg.only == ["P1", "P5"]
    assert cfg.extra_args == ["--token", "t"]
    assert cfg.retries == 2 and cfg.resume is True


def test_parse_args_outdir_default():
    cfg = parse_args(["https://api.alvo.com/x"])
    assert cfg.outdir.startswith("scan_api.alvo.com_")


def test_parse_args_profile():
    cfg = parse_args(["https://x.com", "--profile", "production"])
    assert cfg.profile == "production"


def test_parse_args_profile_default_none():
    # Sem --profile o pipeline não força perfil — herda o que o ambiente definir.
    cfg = parse_args(["https://x.com"])
    assert cfg.profile is None


def test_run_exporta_profile_para_subprocesso(outdir, monkeypatch):
    # O stiglitz.sh lê o perfil via env STIGLITZ_PROFILE; o pipeline precisa
    # exportá-lo para que as sub-invocações (oauth/bizlogic) o respeitem.
    monkeypatch.delenv("STIGLITZ_PROFILE", raising=False)
    p = Pipeline(_cfg(outdir, only=["P1"], profile="production"), runner=RecordingRunner())
    p.run(log=lambda *a: None)
    assert os.environ["STIGLITZ_PROFILE"] == "production"


def test_run_sem_profile_nao_mexe_no_env(outdir, monkeypatch):
    monkeypatch.setenv("STIGLITZ_PROFILE", "staging")
    p = Pipeline(_cfg(outdir, only=["P1"]), runner=RecordingRunner())
    p.run(log=lambda *a: None)
    assert os.environ["STIGLITZ_PROFILE"] == "staging"  # preservado


def test_domain_of():
    assert _domain_of("https://api.alvo.com:8443/path") == "api.alvo.com"
    assert _domain_of("alvo.com") == "alvo.com"

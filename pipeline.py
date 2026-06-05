#!/usr/bin/env python3
"""
pipeline.py — Orquestrador Python do Stiglitz (Fase 4, abordagem wrapper/strangler).

Dirige as fases do stiglitz.sh via `--only-phase`, fornecendo o que a cola bash
nunca teve de fato: checkpoint real (pula fases já concluídas), retry por fase,
logging estruturado e plano dry-run. Cada fase roda como subprocess:

    bash stiglitz.sh <target> --outdir <dir> --only-phase "<PX>" [extra args]

A lógica das ferramentas permanece intocada no stiglitz.sh; aqui mora só a
orquestração. P3 (testssl em background) e P4 (nuclei) rodam como uma unidade
combinada, pois são co-projetadas para paralelismo no mesmo processo.

Uso:
    python3 pipeline.py https://alvo.com [--profile staging] [--outdir DIR]
                        [--only P1,P5] [--no-resume] [--retries 2] [--dry-run]
                        [--token JWT] [--osint-dir DIR]
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime


# ─────────────────────────────────────────────────────────────────────────────
#  Registro de fases — ordem canônica + id passado a --only-phase do stiglitz.sh
# ─────────────────────────────────────────────────────────────────────────────
@dataclass(frozen=True)
class Phase:
    key: str     # identificador interno do pipeline (único)
    only: str    # valor passado a --only-phase (pode conter várias fases)
    label: str   # descrição legível


PHASES: list[Phase] = [
    Phase("P1",    "P1",    "Descoberta de subdomínios"),
    Phase("P2",    "P2",    "Mapeamento de superfície"),
    Phase("P2_5",  "P2_5",  "Detecção de WAF"),
    Phase("P3_P4", "P3 P4", "TLS (testssl) + Nuclei — paralelo"),
    Phase("P5",    "P5",    "Confirmação ativa de exploits"),
    Phase("P6",    "P6",    "Enriquecimento CVE/EPSS"),
    Phase("P8",    "P8",    "Segurança de email (SPF/DMARC/DKIM)"),
    Phase("P9",    "P9",    "Coleta de evidências (OWASP ZAP)"),
    Phase("P10",   "P10",   "Análise de JavaScript & secrets"),
    Phase("P10_5", "P10_5", "Testes complementares"),
    Phase("P11",   "P11",   "Geração de relatório"),
]


# ─────────────────────────────────────────────────────────────────────────────
#  Checkpoint persistente
# ─────────────────────────────────────────────────────────────────────────────
class PipelineState:
    """Estado persistente em <outdir>/raw/.pipeline_state.json."""

    def __init__(self, path: str):
        self.path = path
        self.data: dict = {"target": None, "started": None, "phases": {}}
        if os.path.exists(path):
            try:
                with open(path, encoding="utf-8") as f:
                    self.data = json.load(f)
            except (OSError, ValueError):
                pass
        self.data.setdefault("phases", {})

    def status(self, key: str) -> str:
        return self.data["phases"].get(key, {}).get("status", "pending")

    def is_done(self, key: str) -> bool:
        return self.status(key) == "done"

    def mark(self, key: str, status: str, **extra) -> None:
        self.data["phases"][key] = {"status": status, "ts": int(time.time()), **extra}
        self._save()

    def _save(self) -> None:
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self.data, f, indent=2)
        os.replace(tmp, self.path)


# ─────────────────────────────────────────────────────────────────────────────
#  Configuração
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class PipelineConfig:
    target: str
    outdir: str
    script: str = "stiglitz.sh"
    retries: int = 0                 # tentativas extras por fase em caso de falha
    only: list[str] | None = None    # subconjunto de phase keys a rodar
    resume: bool = True              # pular fases já marcadas 'done'
    dry_run: bool = False
    extra_args: list[str] = field(default_factory=list)  # --token, --osint-dir, ...


# ─────────────────────────────────────────────────────────────────────────────
#  Orquestrador
# ─────────────────────────────────────────────────────────────────────────────
class Pipeline:
    def __init__(self, cfg: PipelineConfig, phases: list[Phase] = PHASES, runner=None):
        self.cfg = cfg
        self.phases = phases
        self.state = PipelineState(os.path.join(cfg.outdir, "raw", ".pipeline_state.json"))
        self._runner = runner or self._subprocess_runner

    def plan(self) -> list[Phase]:
        """Fases que de fato serão executadas após filtro (--only) e checkpoint."""
        out = []
        for ph in self.phases:
            if self.cfg.only and ph.key not in self.cfg.only:
                continue
            if self.cfg.resume and self.state.is_done(ph.key):
                continue
            out.append(ph)
        return out

    def command(self, ph: Phase) -> list[str]:
        return [
            "bash", self.cfg.script, self.cfg.target,
            "--outdir", self.cfg.outdir,
            "--only-phase", ph.only,
            *self.cfg.extra_args,
        ]

    @staticmethod
    def _subprocess_runner(cmd: list[str]) -> int:
        return subprocess.run(cmd).returncode

    def run(self, log=print) -> int:
        self.state.data["target"] = self.cfg.target
        self.state.data["started"] = self.state.data.get("started") or int(time.time())
        planned = self.plan()
        skipped = [p.key for p in self.phases
                   if (not self.cfg.only or p.key in self.cfg.only) and p not in planned]
        log(f"[pipeline] outdir={self.cfg.outdir} | a executar: {len(planned)} | "
            f"já concluídas (skip): {len(skipped)}")
        for ph in planned:
            cmd = self.command(ph)
            if self.cfg.dry_run:
                log(f"[dry-run] {ph.key:<6} → {' '.join(cmd)}")
                continue
            self.state.mark(ph.key, "running")
            rc, attempts = 1, 0
            while attempts <= self.cfg.retries:
                attempts += 1
                tag = f" (tentativa {attempts}/{self.cfg.retries + 1})" if self.cfg.retries else ""
                log(f"[pipeline] ▶ {ph.key} — {ph.label}{tag}")
                rc = self._runner(cmd)
                if rc == 0:
                    break
                log(f"[pipeline] ✗ {ph.key} retornou rc={rc}")
            self.state.mark(ph.key, "done" if rc == 0 else "failed", rc=rc, attempts=attempts)
            if rc != 0:
                log(f"[pipeline] abortando — {ph.key} falhou após {attempts} tentativa(s)")
                return 1
        log("[pipeline] ✓ concluído")
        return 0


# ─────────────────────────────────────────────────────────────────────────────
#  CLI
# ─────────────────────────────────────────────────────────────────────────────
def _domain_of(target: str) -> str:
    d = re.sub(r"^https?://", "", target).split("/")[0].split(":")[0]
    return d or "target"


def _default_outdir(target: str) -> str:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"scan_{_domain_of(target)}_{ts}"


def parse_args(argv: list[str]) -> PipelineConfig:
    p = argparse.ArgumentParser(description="Orquestrador Python do Stiglitz (wrapper/strangler).")
    p.add_argument("target", help="URL do alvo (ex: https://alvo.com)")
    p.add_argument("--outdir", help="Diretório de scan (padrão: scan_<domínio>_<ts>)")
    p.add_argument("--script", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "stiglitz.sh"),
                   help="Caminho do stiglitz.sh")
    p.add_argument("--only", help="Subconjunto de fases (ex: P1,P5,P11)")
    p.add_argument("--retries", type=int, default=0, help="Tentativas extras por fase em caso de falha")
    p.add_argument("--no-resume", action="store_true", help="Não pular fases já concluídas")
    p.add_argument("--dry-run", action="store_true", help="Só imprime o plano; não executa")
    # passthrough para o stiglitz.sh
    p.add_argument("--token", help="Bearer token (scan autenticado)")
    p.add_argument("--header", help="Header de autenticação")
    p.add_argument("--osint-dir", help="Diretório de output do osint.sh")
    a = p.parse_args(argv)

    extra: list[str] = []
    if a.token:      extra += ["--token", a.token]
    if a.header:     extra += ["--header", a.header]
    if a.osint_dir:  extra += ["--osint-dir", a.osint_dir]

    return PipelineConfig(
        target=a.target,
        outdir=a.outdir or _default_outdir(a.target),
        script=a.script,
        retries=a.retries,
        only=[s.strip() for s in a.only.split(",")] if a.only else None,
        resume=not a.no_resume,
        dry_run=a.dry_run,
        extra_args=extra,
    )


def main(argv: list[str] | None = None) -> int:
    cfg = parse_args(argv if argv is not None else sys.argv[1:])
    return Pipeline(cfg).run()


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Interface comum de tracker. Opt-in via env; degrada sem erro (padrão oob.py)."""


class Tracker:
    name = "tracker"

    def enabled(self):
        raise NotImplementedError

    def sync(self, scan_dir, findings, state_summary):
        """Sincroniza findings/estado com o sistema externo.

        Retorna {"tracker", "created", "updated", "reopened", "errors": [str]}.
        NUNCA levanta — erros vão para errors[].
        """
        raise NotImplementedError

    @staticmethod
    def _result(name, created=0, updated=0, reopened=0, errors=None):
        return {"tracker": name, "created": created, "updated": updated,
                "reopened": reopened, "errors": errors or []}

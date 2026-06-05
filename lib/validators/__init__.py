"""
lib/validators — registry de plug-ins de validação.

Cada validador é uma função pura `(ctx: dict) -> (confirmed, confidence, note)`
registrada via `@register("vuln_type")`. O dispatch é feito em
`poc_validator.validate()`: se o tipo está registrado, chama o plug-in;
senão, cai no if/elif legado (migração incremental).

Estrutura do ctx:
{
    "url":          str,
    "resp_body":    str,
    "resp_headers": str,
    "status":       str,
    "patterns":     dict,         # subset relevante para o tipo
    "diff_changed": bool,
    "diff_conf":    int,
    "diff_note":    str,
    "auth_ev":      list[str],
    "dc_result":    tuple|None,   # (consistente: bool, nota: str)
    "dc_bonus":     int,
}
"""
_REGISTRY = {}


def register(vuln_type):
    """Decorator: associa um vuln_type a uma função validadora."""
    def deco(fn):
        _REGISTRY[vuln_type] = fn
        return fn
    return deco


def get(vuln_type):
    return _REGISTRY.get(vuln_type)


def registered_types():
    return sorted(_REGISTRY.keys())


# Auto-import dos validadores para popular o registry. Cada módulo
# faz @register("X") no nível de módulo, então basta importá-lo.
from . import sqli              # noqa: F401, E402
from . import xss               # noqa: F401, E402
from . import lfi               # noqa: F401, E402
from . import ssrf              # noqa: F401, E402
from . import cors              # noqa: F401, E402
from . import default_login     # noqa: F401, E402
from . import exposure          # noqa: F401, E402
from . import security_header   # noqa: F401, E402
from . import tls               # noqa: F401, E402
from . import email             # noqa: F401, E402
from . import auth_bypass       # noqa: F401, E402
from . import redirect          # noqa: F401, E402
from . import takeover          # noqa: F401, E402
from . import jwt               # noqa: F401, E402
from . import secret_aws        # noqa: F401, E402
from . import generic           # noqa: F401, E402

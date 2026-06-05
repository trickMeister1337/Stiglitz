"""
cde_scope.py — fonte de escopo CDE (Cardholder Data Environment).

Lê cde_targets.txt (gitignored) no formato `tipo alvo [label] [checkout=true]`
(tipos: web|infra|both; `#` comentário). Restringe as detecções PCI dedicadas
às URLs declaradas. Nunca contém dados reais — o arquivo é lido em runtime.
"""
import os
from urllib.parse import urlsplit


def _host(url):
    s = urlsplit(url if "://" in url else "//" + url)
    return (s.hostname or url).lower()


def default_path():
    env = os.environ.get("STIGLITZ_CDE_TARGETS")
    if env:
        return env
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(here, "cde_targets.txt")


def load_targets(path=None):
    path = path or default_path()
    out = {"web": [], "infra": [], "checkout": [], "labels": {}}
    if not path or not os.path.exists(path):
        return out
    with open(path, encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            typ, target = parts[0].lower(), parts[1]
            label = parts[2] if len(parts) >= 3 and not parts[2].startswith("checkout=") else target
            out["labels"][target] = label
            if typ == "web":
                out["web"].append(target)
            elif typ == "infra":
                out["infra"].append(target)
            elif typ == "both":
                out["web"].append(target)
                out["infra"].append(target)
            else:
                (out["web"] if "://" in target else out["infra"]).append(target)
            if any(p == "checkout=true" for p in parts[2:]):
                out["checkout"].append(target)
    return out


def _hosts(targets, keys):
    hs = set()
    for k in keys:
        for t in targets.get(k, []):
            hs.add(_host(t))
    return hs


def in_cde_scope(url, targets):
    return _host(url) in _hosts(targets, ("web", "infra"))


def cde_class(url, targets):
    return "cde" if in_cde_scope(url, targets) else None


def is_checkout(url, targets):
    return _host(url) in _hosts(targets, ("checkout",))

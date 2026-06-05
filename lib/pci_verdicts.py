"""
pci_verdicts.py — anota pci_req em findings ja existentes quando o ativo e CDE.
Mapeia categorias ja coletadas (TLS, servicos, cookies/cache) ao requisito PCI.
Nao cria findings novos; apenas etiqueta os do escopo CDE declarado.
"""
import os, sys, re
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cde_scope

_TLS_RE = re.compile(r'tls|ssl|cipher|certificad|\bcert\b', re.I)
_SVC_RE = re.compile(r'telnet|ftp|snmp|smb|rdp|mysql|postgres|mongo|redis|exposto', re.I)
_COOKIE_RE = re.compile(r'cookie|cache-control|httponly|samesite|secure flag', re.I)


def _url_of(f):
    return f.get("url") or f.get("target") or f.get("matched_at") or ""


def tag_finding(f, targets):
    """Anota f['pci_req'] in-place se o ativo for CDE e a categoria casar."""
    if not cde_scope.in_cde_scope(_url_of(f), targets):
        return f
    src = (f.get("source") or "")
    name = (f.get("name") or "")
    if src == "testssl.sh" or _TLS_RE.search(name):
        f["pci_req"] = "4.2.1"
    elif src == "Service Version" or _SVC_RE.search(name):
        f["pci_req"] = "2.2.5"
    elif _COOKIE_RE.search(name):
        f["pci_req"] = "3.2"
    return f


def tag_all(findings, targets=None):
    targets = cde_scope.load_targets() if targets is None else targets
    for f in findings:
        if "pci_req" not in f:
            tag_finding(f, targets)
    return findings

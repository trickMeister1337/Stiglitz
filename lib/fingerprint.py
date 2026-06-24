#!/usr/bin/env python3
"""
fingerprint.py — identidade estável de finding para correlação cross-scan (P1).

O diff (stiglitz_diff.py / "Evolution Since Last Scan") cruzava findings só pelo
NOME — frágil a mudança de template e cega a parâmetro/endpoint. Aqui derivamos
um fingerprint determinístico = hash(classe_vuln, host, path-template, param),
normalizando segmentos numéricos/UUID (/user/1 ≡ /user/2). Base para dedup
semântico, SLA-state e burndown/MTTR.

Puro — sem rede.
"""
import re
import hashlib
import urllib.parse

_UUID = re.compile(
    r'/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', re.I)
_NUM_SEG = re.compile(r'/\d+(?=/|$)')
_CWE = re.compile(r'CWE-\d+', re.I)


def normalize_path(url):
    """Path com segmentos numéricos/UUID → /{id} (templatiza /user/1 → /user/{id})."""
    path = urllib.parse.urlsplit(url).path or url or ""
    path = _UUID.sub('/{id}', path)
    path = _NUM_SEG.sub('/{id}', path)
    return path or "/"


def vuln_class(finding):
    """Classe da vuln: CWE (campo cwe ou embutido no cve), senão type, senão name."""
    for field in ("cwe", "cve"):
        m = _CWE.search(str(finding.get(field, "")))
        if m:
            return m.group(0).upper()
    return str(finding.get("type") or finding.get("name") or "unknown").strip().lower()


def fingerprint(finding):
    """Hash determinístico (16 hex) de (classe, host, path-template, param).

    Para findings de componente vulnerável (SCA), a classe (CWE-1395) é a mesma
    p/ todas as libs, então acrescentamos `component@version` à chave QUANDO
    presente — sem isso, libs distintas no mesmo host/path colapsam numa só
    identidade (e o dedup descarta as de menor severidade). O segmento extra só
    aparece quando há `component`, então findings não-SCA mantêm o fingerprint
    histórico (corpus geral e state cross-scan inalterados)."""
    host = urllib.parse.urlsplit(finding.get("url", "")).netloc or finding.get("host", "")
    parts = [
        vuln_class(finding),
        host,
        normalize_path(finding.get("url", "")),
        str(finding.get("param", "") or ""),
    ]
    comp = str(finding.get("component", "") or "").strip().lower()
    if comp:
        parts.append(comp + "@" + str(finding.get("version", "") or "").strip().lower())
    return hashlib.sha1("|".join(parts).encode("utf-8")).hexdigest()[:16]

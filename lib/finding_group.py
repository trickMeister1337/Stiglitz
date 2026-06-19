#!/usr/bin/env python3
"""finding_group.py — Agrupa findings replicados (mesmo problema em vários hosts).

O coletor de Security Headers emite 1 finding por (header, host); num scan amplo isso
gera dezenas de cards idênticos que poluem o deliverable e inflam a contagem de
vulnerabilidades. Aqui colapsamos os findings das fontes indicadas que compartilham o
mesmo `name` num único finding com affected_urls/affected_count — exatamente o padrão
que o report já usa para alertas ZAP (render_finding desenha a seção "Affected URLs"
quando affected_count > 1). Todos os hosts afetados são preservados.

Lógica pura — testável sem o report.
"""

_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0, "": 0}


def _rank(f):
    return _SEV_RANK.get((f.get("severity") or "info").lower(), 0)


def group_by_name(findings, sources=("Security Headers",)):
    """Colapsa os findings cujo `source` está em `sources` e que compartilham o mesmo
    `name` (mesmo problema em hosts diferentes) num único finding agrupado.

    - Findings de outras fontes passam inalterados.
    - Grupos de um único host passam inalterados (sem affected_count).
    - Severidade do grupo = a mais alta encontrada; affected_urls = hosts distintos,
      em ordem de aparição.
    - Ordem estável: grupos na ordem da 1ª aparição, depois o restante.
    """
    groups, order, passthrough = {}, [], []
    for f in findings:
        if f.get("source") in sources and f.get("name"):
            key = f["name"]
            if key not in groups:
                groups[key] = []
                order.append(key)
            groups[key].append(f)
        else:
            passthrough.append(f)

    grouped = []
    for key in order:
        grp = groups[key]
        if len(grp) == 1:
            grouped.append(grp[0])
            continue
        base = dict(max(grp, key=_rank))          # herda o de maior severidade
        urls, seen = [], set()
        for f in grp:
            u = f.get("url", "")
            if u and u not in seen:
                seen.add(u)
                urls.append(u)
        base["affected_count"] = len(urls)
        base["affected_urls"] = urls
        grouped.append(base)

    return grouped + passthrough

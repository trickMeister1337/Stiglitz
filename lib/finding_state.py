#!/usr/bin/env python3
"""
finding_state.py — ledger de estado de finding por fingerprint (P1).

Mantém um store JSON persistente (um por target) reconciliando os findings de
cada scan pela chave estável fingerprint (lib/fingerprint.py): NEW, PERSISTENT,
RESOLVED, REOPENED — com first_seen/last_seen/resolved_at e métricas (age, MTTR,
SLA breach). Habilita SLA real, retest tracking e burndown.

Store fora do repo (STIGLITZ_STATE_DIR, default ~/.stiglitz/state/) → nunca
versiona dado de alvo. Lógica pura: a data corrente é injetada (testabilidade).
"""
import os
import json
import datetime

try:
    import prioritization as _prio
except Exception:  # pragma: no cover - prioritization sempre presente em runtime
    _prio = None


def _entry(f, today_iso):
    return {
        "fingerprint": f.get("fingerprint"),
        "name": f.get("name", ""),
        "severity": f.get("severity", "info"),
        "url": f.get("url", ""),
        "first_seen": today_iso,
        "last_seen": today_iso,
        "last_scan_id": None,
        "status": "open",
        "resolved_at": None,
        "reopened_count": 0,
        "sla_due": None,
        "history": [],
    }


def reconcile(store, current_findings, today, scan_id):
    """Reconcilia o store com os findings do scan atual.

    Retorna (novo_store, transitions). transitions = lista de
    {fingerprint, event, severity}. Findings sem fingerprint são ignorados.
    """
    store = dict(store)
    today_iso = today.isoformat()
    transitions = []
    seen = set()

    for f in current_findings:
        fp = f.get("fingerprint")
        if not fp:
            continue
        seen.add(fp)
        e = store.get(fp)
        if e is None:
            e = _entry(f, today_iso)
            event = "new"
        elif e["status"] == "resolved":
            e["status"] = "open"
            e["resolved_at"] = None
            e["reopened_count"] += 1
            event = "reopened"
        else:
            event = "persistent"
        e["last_seen"] = today_iso
        e["last_scan_id"] = scan_id
        e["severity"] = f.get("severity", e.get("severity", "info"))
        e["history"].append({"date": today_iso, "event": event, "scan_id": scan_id})
        store[fp] = e
        transitions.append({"fingerprint": fp, "event": event,
                            "severity": e["severity"]})

    return store, transitions

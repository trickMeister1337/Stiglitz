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
import re as _re
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

    for fp, e in store.items():
        if fp not in seen and e["status"] == "open":
            e["status"] = "resolved"
            e["resolved_at"] = today_iso
            e["history"].append({"date": today_iso, "event": "resolved",
                                "scan_id": scan_id})
            transitions.append({"fingerprint": fp, "event": "resolved",
                                "severity": e.get("severity", "info")})

    return store, transitions


def _state_dir(state_dir=None):
    d = state_dir or os.environ.get("STIGLITZ_STATE_DIR") or \
        os.path.join(os.path.expanduser("~"), ".stiglitz", "state")
    os.makedirs(d, exist_ok=True)
    return d


def _slug(target):
    s = _re.sub(r"^https?://", "", str(target or "unknown"))
    s = _re.sub(r"[^A-Za-z0-9._-]", "_", s).strip("_")
    return s or "unknown"


def load_store(target, state_dir=None):
    p = os.path.join(_state_dir(state_dir), _slug(target) + ".json")
    if not os.path.exists(p):
        return {}
    try:
        with open(p, encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return {}


def save_store(target, store, state_dir=None):
    p = os.path.join(_state_dir(state_dir), _slug(target) + ".json")
    tmp = p + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(store, fh, ensure_ascii=False, indent=2)
    os.replace(tmp, p)
    return p


def _date(iso):
    return datetime.date.fromisoformat(iso) if iso else None


def _age_days(first_seen, today):
    d = _date(first_seen)
    return (today - d).days if d else None


def _sla_prazo(entry, today):
    """Prazo em dias via prioritization.sla_for_finding; fallback por severidade."""
    if _prio is not None:
        try:
            sla = _prio.sla_for_finding(
                {"severity": entry.get("severity", "info"), "in_kev": False}, today)
            return sla.get("days_remaining")
        except Exception:
            pass
    return {"critical": 15, "high": 30, "medium": 60, "low": 90}.get(
        entry.get("severity", "info"), 90)


def derive_metrics(store, today):
    open_by_sev = {}
    mttrs = []
    open_ages = []
    open_total = resolved_total = 0
    breached = []
    for fp, e in store.items():
        if e["status"] == "open":
            open_total += 1
            sev = e.get("severity", "info")
            open_by_sev[sev] = open_by_sev.get(sev, 0) + 1
            age = _age_days(e["first_seen"], today)
            if age is not None:
                open_ages.append(age)
                prazo = _sla_prazo(e, today)
                if prazo is not None and age > prazo:
                    breached.append(fp)
        else:
            resolved_total += 1
            f, r = _date(e["first_seen"]), _date(e.get("resolved_at"))
            if f and r:
                mttrs.append((r - f).days)
    return {
        "open_total": open_total,
        "open_by_severity": open_by_sev,
        "resolved_total": resolved_total,
        "mttr_days_avg": round(sum(mttrs) / len(mttrs), 1) if mttrs else None,
        "oldest_open_days": max(open_ages) if open_ages else 0,
        "sla_breached": breached,
    }


def attach_state(findings, store, today):
    for f in findings:
        e = store.get(f.get("fingerprint"))
        if not e:
            continue
        age = _age_days(e["first_seen"], today)
        mttr = None
        if e["status"] == "resolved":
            fd, rd = _date(e["first_seen"]), _date(e.get("resolved_at"))
            mttr = (rd - fd).days if fd and rd else None
        prazo = _sla_prazo(e, today)
        f["state"] = {
            "status": e["status"],
            "first_seen": e["first_seen"],
            "last_seen": e["last_seen"],
            "age_days": age,
            "mttr_days": mttr,
            "reopened_count": e["reopened_count"],
            "sla_breached": bool(e["status"] == "open" and age is not None
                                 and prazo is not None and age > prazo),
        }
    return findings


def apply_state(findings, target, scan_id, today=None, state_dir=None):
    """Fluxo completo p/ o report: load → reconcile → attach → save → metrics.

    Retorna o state_summary. Idempotente por (today, scan_id).
    """
    today = today or datetime.date.today()
    store = load_store(target, state_dir=state_dir)
    store, _trans = reconcile(store, findings, today, scan_id)
    attach_state(findings, store, today)
    save_store(target, store, state_dir=state_dir)
    return derive_metrics(store, today)

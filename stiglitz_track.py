#!/usr/bin/env python3
"""
stiglitz_track.py — push de findings/estado para trackers (opt-in).

Resolve um scan dir (ou findings.json), lê o state_summary e dispara os trackers
habilitados via env (hoje: DefectDojo). No-op informativo quando nenhum configurado.
Mensagens de console em PT-BR (operador); deliverable já saiu no scan.

Uso:
    python3 stiglitz_track.py <scan_dir|findings.json>
"""
import os
import sys
import json

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))

from trackers.defectdojo import DefectDojo

TRACKERS = [DefectDojo]


def _resolve_scan_dir(arg):
    if os.path.isdir(arg):
        return arg
    if os.path.isfile(arg) and arg.endswith(".json"):
        return os.path.dirname(os.path.abspath(arg)) or "."
    raise SystemExit(f"[!] caminho inválido: {arg}")


def _load_json(path, default):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return default


def run_trackers(scan_dir):
    fj = _load_json(os.path.join(scan_dir, "findings.json"), {})
    findings = fj.get("findings", []) if isinstance(fj, dict) else []
    summary = _load_json(os.path.join(scan_dir, "raw", "state_summary.json"), {})
    results = []
    for cls in TRACKERS:
        t = cls()
        if not t.enabled():
            continue
        res = t.sync(scan_dir, findings, summary)
        results.append(res)
    return results


def main(argv):
    if len(argv) < 2:
        print("uso: python3 stiglitz_track.py <scan_dir|findings.json>")
        return 2
    scan_dir = _resolve_scan_dir(argv[1])
    results = run_trackers(scan_dir)
    if not results:
        print("[○] Nenhum tracker configurado (defina DEFECTDOJO_URL/TOKEN p/ habilitar).")
        return 0
    for r in results:
        if r["errors"]:
            print(f"[!] {r['tracker']}: erros: {'; '.join(r['errors'])}")
        else:
            print(f"[✓] {r['tracker']}: {r['created']} criados, "
                  f"{r['reopened']} reabertos, {r['updated']} inalterados")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

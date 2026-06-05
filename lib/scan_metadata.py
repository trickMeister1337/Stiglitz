#!/usr/bin/env python3
"""
scan_metadata.py — Gera scan_metadata.json (comportamento/evasão do scan)

Extraído de stiglitz.sh (heredoc PYMETADATA). Recebe argumentos posicionais
via sys.argv, idêntico à invocação original do stiglitz.sh.
"""
import json, sys, os
outdir, waf_det, waf_name = sys.argv[1], sys.argv[2], sys.argv[3]
rate, conc, delay, ua = sys.argv[4], sys.argv[5], sys.argv[6], sys.argv[7]
meta = {
    "waf_detected": waf_det == "1",
    "waf_name": waf_name,
    "evasion_active": waf_det == "1",
    "evasion_techniques": (
        ["rate_limit_reduced","user_agent_rotation","origin_spoofing",
         "payload_alterations","waf_response_bypass","zap_threads_reduced"]
        if waf_det == "1" else []
    ),
    "nuclei_rate_limit": int(rate),
    "nuclei_concurrency": int(conc),
    "nuclei_delay": None if delay == "none" else delay,
    "user_agent": ua,
    "nuclei_results_before_evasion": None,
    "nuclei_results_after_evasion": None,
    "zap_results_after_evasion": None,
}
with open(os.path.join(outdir,"raw","scan_metadata.json"),"w") as f:
    json.dump(meta, f, indent=2)

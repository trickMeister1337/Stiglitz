#!/usr/bin/env python3
"""Integração de lib/tech_profile.py — regressão do Bug #1 end-to-end.

Roda o script real contra um httpx_results.jsonl de fixture e valida o
tech_profile.json: (a) título HTTP não polui o inventário; (b) o framework real
(Django) é detectado → dispara nuclei tags + ffuf profile dirigidos.
"""
import json
import os
import subprocess
import sys
import tempfile

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SCRIPT = os.path.join(_ROOT, "lib", "tech_profile.py")


def _run(jsonl_lines):
    tmp = tempfile.mkdtemp()
    raw = os.path.join(tmp, "raw")
    os.makedirs(raw)
    with open(os.path.join(raw, "httpx_results.jsonl"), "w") as fh:
        fh.write("\n".join(json.dumps(r) for r in jsonl_lines) + "\n")
    subprocess.run([sys.executable, _SCRIPT, tmp, "https://x.com"],
                   check=True, capture_output=True, text=True)
    with open(os.path.join(raw, "tech_profile.json")) as fh:
        return json.load(fh)


def test_title_does_not_pollute_inventory():
    prof = _run([{"url": "https://x.com", "title": "Not Found",
                  "tech": ["Django", "Nginx"], "webserver": "nginx"}])
    assert "Not Found" not in prof["detected"]
    assert "HSTS" not in prof["detected"]


def test_django_drives_nuclei_tags_and_ffuf_profile():
    prof = _run([{"url": "https://x.com", "title": "Not Found",
                  "tech": ["Django"], "webserver": "nginx"}])
    assert "Django" in prof["detected"]
    assert "django" in prof["nuclei_extra_tags"]
    assert prof["ffuf_profile"] == "django"

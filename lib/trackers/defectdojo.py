#!/usr/bin/env python3
"""
defectdojo.py — push para DefectDojo via reimport-scan (SARIF).

Opt-in: requer DEFECTDOJO_URL + DEFECTDOJO_TOKEN. Usa o findings.sarif (que carrega
partialFingerprints = fingerprint estável); o DefectDojo deduplica/reabre/mitiga
nativamente por unique_id_from_tool. Sem env → enabled()=False (no-op).
"""
import os

try:
    import requests
except Exception:  # pragma: no cover
    requests = None

from .base import Tracker


class DefectDojo(Tracker):
    name = "defectdojo"

    def __init__(self, session=None):
        self.url = (os.environ.get("DEFECTDOJO_URL") or "").rstrip("/")
        self.token = os.environ.get("DEFECTDOJO_TOKEN") or ""
        self.product = os.environ.get("DEFECTDOJO_PRODUCT") or "Stiglitz"
        self.engagement = os.environ.get("DEFECTDOJO_ENGAGEMENT") or "Stiglitz"
        self.verify = (os.environ.get("DEFECTDOJO_VERIFY_SSL", "true").lower()
                       != "false")
        self.session = session or (requests.Session() if requests else None)

    def enabled(self):
        return bool(self.url and self.token)

    def sync(self, scan_dir, findings, state_summary):
        if not self.enabled():
            return self._result(self.name, errors=["not configured"])
        if self.session is None:
            return self._result(self.name, errors=["requests indisponível"])
        sarif = os.path.join(scan_dir, "findings.sarif")
        if not os.path.exists(sarif):
            return self._result(self.name, errors=[f"SARIF ausente: {sarif}"])
        data = {
            "scan_type": "SARIF",
            "product_name": self.product,
            "engagement_name": self.engagement,
            "auto_create_context": "true",
            "active": "true",
            "verified": "false",
            "close_old_findings": "true",
            "deduplication_on_engagement": "true",
        }
        try:
            with open(sarif, "rb") as fh:
                resp = self.session.post(
                    f"{self.url}/api/v2/reimport-scan/",
                    headers={"Authorization": f"Token {self.token}"},
                    data=data,
                    files={"file": ("findings.sarif", fh, "application/json")},
                    verify=self.verify,
                    timeout=60,
                )
        except Exception as e:
            return self._result(self.name, errors=[str(e)])
        if resp.status_code >= 400:
            return self._result(self.name,
                                errors=[f"HTTP {resp.status_code}: {resp.text[:200]}"])
        try:
            body = resp.json()
        except Exception:
            body = {}
        return self._result(
            self.name,
            created=len(body.get("new_findings", []) or []),
            reopened=len(body.get("reactivated_findings", []) or []),
            updated=len(body.get("untouched_findings", []) or []),
        )

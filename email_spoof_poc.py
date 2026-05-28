#!/usr/bin/env python3
"""
email_spoof_poc.py — Evidência de exploração de SPF/DMARC/DKIM.

Sempre emite um verdito analítico de spoofing. Com --send (opt-in, atrás de
gate RoE), entrega um email forjado e captura o transcript SMTP como prova.

Uso de red team autorizado (RoE assinado). Console PT-BR; campos de evidência
em EN (padrão deliverable do suite).
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))


def compute_verdict(records, forged_from):
    """Mapeia status DNS → verdito de exploitabilidade de spoofing de From:."""
    spf = records["spf"]
    dmarc = records["dmarc"]
    dmarc_status = dmarc.get("status")
    dmarc_policy = dmarc.get("policy")

    if dmarc_status == "MISSING" or dmarc_policy == "none":
        status = "SPOOFABLE_INBOX"
        impact = "Forged From: of the exact domain is delivered to the inbox (DMARC absent or p=none)."
    elif dmarc_policy == "quarantine":
        status = "SPOOFABLE_SPAM"
        impact = "Forged mail is accepted but likely quarantined/spam-foldered (DMARC p=quarantine)."
    elif dmarc_policy == "reject":
        status = "BLOCKED_EXACT"
        impact = "Exact-domain spoofing blocked by DMARC p=reject; lookalike/cousin domains remain viable."
    else:
        status = "INDETERMINATE"
        impact = "DMARC policy unrecognized; manual review required."

    spf_note = None
    if spf.get("status") in ("MISSING", "PERMISSIVE", "NEUTRAL"):
        spf_note = "Envelope sender (MAIL FROM) is unprotected — eases envelope spoofing and backscatter."

    return {
        "status": status,
        "impact_en": impact,
        "spf_note_en": spf_note,
        "forged_envelope": {"mail_from": forged_from, "header_from": forged_from},
    }

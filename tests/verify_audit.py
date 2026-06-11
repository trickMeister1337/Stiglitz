#!/usr/bin/env python3
"""
verify_audit.py — Verifica a hash chain do audit trail do Stiglitz.

Cada linha do audit.log tem o formato:
    SEQ | ISO_TS | EVENT | prev_hash:curr_hash

curr_hash = sha256(prev || ts || event)[:16]

Uma divergência indica adulteração entre as duas entradas envolvidas.
A primeira entrada é AUDIT_INIT cujo prev_hash é o seed (idealmente o SHA-256
do RoE — amarra criptograficamente o trail ao documento de autorização).

Uso:
    python3 verify_audit.py <scan_dir>/audit.log
"""
import hashlib
import hmac
import os
import sys


def _h(prev, ts, event):
    return hashlib.sha256(f"{prev}|{ts}|{event}".encode()).hexdigest()[:16]


def verify(path):
    expected_seq = 0
    prev = None
    with open(path, encoding="utf-8") as f:
        for lineno, raw in enumerate(f, start=1):
            line = raw.rstrip("\n")
            if not line.strip():
                continue
            try:
                seq_str, ts, rest = [p.strip() for p in line.split(" | ", 2)]
                event, hashes = rest.rsplit(" | ", 1)
                p_h, c_h = hashes.split(":")
            except ValueError:
                return False, f"linha {lineno}: formato inválido: {line!r}"

            try:
                seq = int(seq_str)
            except ValueError:
                return False, f"linha {lineno}: SEQ não numérico"

            if seq != expected_seq:
                return False, f"linha {lineno}: SEQ esperado {expected_seq}, obtido {seq}"

            if prev is not None and p_h != prev:
                return False, (f"linha {lineno}: prev_hash diverge — "
                               f"esperado {prev}, registrado {p_h}")

            recomputed = _h(p_h, ts, event)
            if recomputed != c_h:
                return False, (f"linha {lineno}: curr_hash diverge — "
                               f"esperado {recomputed}, registrado {c_h}")

            prev = c_h
            expected_seq += 1

    if expected_seq == 0:
        return False, "audit log vazio"
    return True, f"OK — {expected_seq} entradas verificadas"


def _head_hash(path):
    """Revalida o chain e devolve (True, head) ou (False, msg). head = último curr_hash."""
    expected_seq, prev = 0, None
    with open(path, encoding="utf-8") as f:
        for lineno, raw in enumerate(f, start=1):
            line = raw.rstrip("\n")
            if not line.strip():
                continue
            try:
                seq_str, ts, rest = [p.strip() for p in line.split(" | ", 2)]
                event, hashes = rest.rsplit(" | ", 1)
                p_h, c_h = hashes.split(":")
            except ValueError:
                return False, f"linha {lineno}: formato inválido"
            if prev is not None and p_h != prev:
                return False, f"linha {lineno}: prev_hash diverge"
            if _h(p_h, ts, event) != c_h:
                return False, f"linha {lineno}: curr_hash diverge"
            prev, expected_seq = c_h, expected_seq + 1
    if expected_seq == 0:
        return False, "audit log vazio"
    return True, prev


def verify_seal(log_path, seal_path, key):
    ok, head = _head_hash(log_path)
    if not ok:
        return False, f"chain inválido: {head}"
    try:
        with open(seal_path, encoding="utf-8") as f:
            parts = f.read().strip().split()
        algo, sealed_hex = parts[0], parts[1]
        sealed_head = parts[2].split("=", 1)[1] if len(parts) > 2 and "=" in parts[2] else None
    except (OSError, IndexError, ValueError) as e:
        return False, f"selo ilegível: {e}"
    if algo != "HMAC-SHA256":
        return False, f"algoritmo de selo inesperado: {algo}"
    if sealed_head is not None and sealed_head != head:
        return False, f"cabeça do selo ({sealed_head}) diverge da recomputada ({head})"
    expected = hmac.new(key.encode(), head.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, sealed_hex):
        return False, "selo HMAC não confere (re-encadeamento ou chave errada)"
    return True, f"selo OK — cabeça {head}"


def main():
    args = sys.argv[1:]
    if not args:
        print("Uso: verify_audit.py <audit.log> [--seal <audit.log.seal> [--key K]]", file=sys.stderr)
        sys.exit(2)
    log = args[0]
    if "--seal" in args:
        seal = args[args.index("--seal") + 1]
        key = (args[args.index("--key") + 1] if "--key" in args
               else os.environ.get("STIGLITZ_AUDIT_KEY", ""))
        if not key:
            print("selo requer chave (--key ou STIGLITZ_AUDIT_KEY)", file=sys.stderr)
            sys.exit(2)
        ok, msg = verify_seal(log, seal, key)
    else:
        ok, msg = verify(log)
    print(msg)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()

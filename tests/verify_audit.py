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


def main():
    if len(sys.argv) != 2:
        print("Uso: verify_audit.py <audit.log>", file=sys.stderr)
        sys.exit(2)
    ok, msg = verify(sys.argv[1])
    print(msg)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()

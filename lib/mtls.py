#!/usr/bin/env python3
"""
mtls.py — client-cert mTLS opt-in (especialização fintech), só p/ tráfego do alvo.

Lê STIGLITZ_MTLS_CERT / STIGLITZ_MTLS_KEY (PEM; chave SEM senha). Sem config → no-op
(idêntico ao comportamento atual). Fornece o ssl_context que o netproxy injeta nos
openers urllib, args de curl, e validação fail-closed consumida pelo stiglitz.sh.

Console em PT-BR.
"""
import os
import ssl
import sys


class MtlsConfigError(Exception):
    """mTLS configurado mas material inválido (ausente/ilegível/parcial/chave com senha).
    Erro de configuração — deve ABORTAR o scan, não ser tratado como falha de rede."""


def cert_path():
    return os.environ.get("STIGLITZ_MTLS_CERT", "").strip()


def key_path():
    return os.environ.get("STIGLITZ_MTLS_KEY", "").strip()


def is_enabled():
    """True só quando cert E key estão setados."""
    return bool(cert_path() and key_path())


def key_is_encrypted(path):
    """True se o PEM da chave indica criptografia (chave com senha). Cobre PKCS#8
    ('BEGIN ENCRYPTED PRIVATE KEY') e PEM tradicional ('Proc-Type: 4,ENCRYPTED')."""
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return "ENCRYPTED" in fh.read(4096)
    except OSError:
        return False


def validate():
    """Valida o material mTLS. No-op se nem cert nem key setados. Levanta
    MtlsConfigError (PT-BR, com instrução openssl) se inválido."""
    c, k = cert_path(), key_path()
    if not c and not k:
        return
    if not (c and k):
        raise MtlsConfigError(
            "mTLS parcial: defina STIGLITZ_MTLS_CERT E STIGLITZ_MTLS_KEY (ambos os arquivos PEM)")
    for label, p in (("cert", c), ("key", k)):
        if not os.path.isfile(p):
            raise MtlsConfigError(f"mTLS {label} nao encontrado: {p!r}")
        if not os.access(p, os.R_OK):
            raise MtlsConfigError(f"mTLS {label} sem permissao de leitura: {p!r}")
    if key_is_encrypted(k):
        raise MtlsConfigError(
            f"mTLS key protegida por senha: {k!r}. Decripte antes "
            "(ex.: openssl rsa -in enc.pem -out plain.pem) — senha nao suportada nesta entrega")


def curl_cert_args():
    """Args de client-cert p/ curl via subprocess: [] sem mTLS, senão --cert/--key."""
    if not is_enabled():
        return []
    return ["--cert", cert_path(), "--key", key_path()]


def main(argv):
    if len(argv) < 2:
        print("uso: mtls.py <check|curl-args>", file=sys.stderr)
        return 2
    cmd = argv[1]
    if cmd == "check":
        try:
            validate()
        except MtlsConfigError as e:
            print(str(e), file=sys.stderr)
            return 1
        print(f"mTLS ok: cert={cert_path()} key={key_path()}" if is_enabled()
              else "mTLS desativado")
        return 0
    if cmd == "curl-args":
        print(" ".join(curl_cert_args()))
        return 0
    print(f"comando desconhecido: {cmd}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

import os, sys, hmac, hashlib, tempfile, subprocess
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tests"))
import verify_audit as V

KEY = "chave-de-teste-123"


def _build_log(path):
    """Constrói um audit.log válido (mesmo esquema do audit_init/audit do bash)."""
    seed = "00" * 8
    def h(prev, ts, ev):
        return hashlib.sha256(f"{prev}|{ts}|{ev}".encode()).hexdigest()[:16]
    lines = []
    ev0, ts0 = "AUDIT_INIT seed=" + seed, "2026-06-11T00:00:00Z"
    c0 = h(seed, ts0, ev0)
    lines.append(f"{0:04d} | {ts0} | {ev0} | {seed}:{c0}")
    prev = c0
    for i, ev in enumerate(["PHASE_START name=recon", "PHASE_END name=recon result=ok"], start=1):
        ts = f"2026-06-11T00:0{i}:00Z"
        c = h(prev, ts, ev)
        lines.append(f"{i:04d} | {ts} | {ev} | {prev}:{c}")
        prev = c
    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")
    return prev  # cabeça


def _seal_hex(head, key):
    return hmac.new(key.encode(), head.encode(), hashlib.sha256).hexdigest()


def test_verify_seal_accepts_valid():
    d = tempfile.mkdtemp()
    log = os.path.join(d, "audit.log"); head = _build_log(log)
    seal = os.path.join(d, "audit.log.seal")
    with open(seal, "w") as f:
        f.write(f"HMAC-SHA256 {_seal_hex(head, KEY)} head={head}\n")
    ok, msg = V.verify_seal(log, seal, KEY)
    assert ok, msg


def test_verify_seal_rejects_tampered_log():
    d = tempfile.mkdtemp()
    log = os.path.join(d, "audit.log"); head = _build_log(log)
    seal = os.path.join(d, "audit.log.seal")
    with open(seal, "w") as f:
        f.write(f"HMAC-SHA256 {_seal_hex(head, KEY)} head={head}\n")
    open(log, "w").write(open(log).read().replace("result=ok", "result=FALSIFICADO"))
    ok, msg = V.verify_seal(log, seal, KEY)
    assert not ok


def test_verify_seal_rejects_wrong_key():
    d = tempfile.mkdtemp()
    log = os.path.join(d, "audit.log"); head = _build_log(log)
    seal = os.path.join(d, "audit.log.seal")
    with open(seal, "w") as f:
        f.write(f"HMAC-SHA256 {_seal_hex(head, KEY)} head={head}\n")
    ok, msg = V.verify_seal(log, seal, "chave-errada")
    assert not ok


def test_verify_seal_rejects_renumbered_seq():
    d = tempfile.mkdtemp()
    log = os.path.join(d, "audit.log"); head = _build_log(log)
    seal = os.path.join(d, "audit.log.seal")
    with open(seal, "w") as f:
        f.write(f"HMAC-SHA256 {_seal_hex(head, KEY)} head={head}\n")
    # renumera o SEQ da 2ª linha (0001 -> 0009) sem tocar nos hashes
    lines = open(log).read().splitlines()
    lines[1] = lines[1].replace("0001 |", "0009 |", 1)
    open(log, "w").write("\n".join(lines) + "\n")
    ok, msg = V.verify_seal(log, seal, KEY)
    assert not ok


def test_verify_seal_rejects_seal_without_head():
    d = tempfile.mkdtemp()
    log = os.path.join(d, "audit.log"); head = _build_log(log)
    seal = os.path.join(d, "audit.log.seal")
    with open(seal, "w") as f:
        f.write(f"HMAC-SHA256 {_seal_hex(head, KEY)}\n")   # sem head=
    ok, msg = V.verify_seal(log, seal, KEY)
    assert not ok


def test_bash_openssl_matches_python_hmac():
    import shutil
    if not shutil.which("openssl"):
        import pytest; pytest.skip("openssl ausente")
    head, key = "deadbeefdeadbeef", "k"
    py = hmac.new(key.encode(), head.encode(), hashlib.sha256).hexdigest()
    out = subprocess.run(["openssl", "dgst", "-sha256", "-hmac", key, "-r"],
                         input=head, capture_output=True, text=True)
    sh = out.stdout.split()[0]
    assert sh == py

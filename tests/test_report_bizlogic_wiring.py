# tests/test_report_bizlogic_wiring.py
import os, sys, json, subprocess, tempfile, shutil

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _write(outdir, name, data):
    os.makedirs(os.path.join(outdir, "raw"), exist_ok=True)
    with open(os.path.join(outdir, "raw", name), "w") as f:
        json.dump(data, f)


def test_report_aggregates_bizlogic_and_dedups_access():
    outdir = tempfile.mkdtemp()
    try:
        # access_findings (P9.5) e bizlogic_findings (P9.7) colidem no mesmo recurso
        _write(outdir, "access_findings.json", [
            {"type": "idor_read_pii", "severity": "high", "source": "bola",
             "url": "https://t.com/api/orders/123", "confirmed": True}])
        _write(outdir, "bizlogic_findings.json", [
            {"type": "idor_read_pii", "severity": "high", "tool": "bizlogic",
             "url": "https://t.com/api/orders/123", "confirmed": True},     # dup → removido
            {"type": "amount_tampering", "severity": "high", "tool": "bizlogic",
             "url": "https://t.com/transfer", "confirmed": True}])       # único → mantém
        env = dict(os.environ, OUTDIR=outdir, TARGET="t.com", DOMAIN="t.com")
        r = subprocess.run([sys.executable, os.path.join(ROOT, "stiglitz_report.py")],
                           env=env, cwd=ROOT, capture_output=True, text=True)
        assert r.returncode == 0, r.stderr
        html = open(os.path.join(outdir, "stiglitz_report.html")).read()
        # o finding único do bizlogic aparece; a marca bola do dup permanece (P9.5 vence)
        assert "amount_tampering" in html or "transfer" in html

        # Dedup verificado no findings.json estruturado. O writer do report serializa
        # por URL (não expõe type/tool), então a checagem é por URL: o recurso colidido
        # /api/orders/123 aparece UMA só vez (bizlogic dropado, P9.5 vence) e o /transfer
        # (único do bizlogic) é mantido — total de 2 (não 3).
        findings = json.load(open(os.path.join(outdir, "findings.json"))).get("findings", [])
        orders = [f for f in findings if f.get("url") == "https://t.com/api/orders/123"]
        transfer = [f for f in findings if f.get("url") == "https://t.com/transfer"]
        assert len(orders) == 1, \
            f"recurso colidido deveria sobrar 1x (P9.5 vence), veio {len(orders)}"
        assert len(transfer) == 1, \
            f"amount_tampering (único do bizlogic) deveria ser mantido, veio {len(transfer)}"
    finally:
        shutil.rmtree(outdir)


def test_inconclusive_access_does_not_suppress_confirmed_bizlogic():
    # P9.5 (bola) inconclusiva NÃO deve suprimir um achado CONFIRMADO da P9.7
    # no mesmo recurso — só findings de acesso confirmados semeiam o dedup.
    outdir = tempfile.mkdtemp()
    try:
        _write(outdir, "access_findings.json", [
            {"type": "idor_read_pii", "severity": "info", "source": "bola",
             "url": "https://t.com/api/orders/123", "confirmed": False}])   # inconclusiva
        _write(outdir, "bizlogic_findings.json", [
            {"type": "idor_read_pii", "severity": "high", "tool": "bizlogic",
             "url": "https://t.com/api/orders/123", "confirmed": True}])     # confirmada
        env = dict(os.environ, OUTDIR=outdir, TARGET="t.com", DOMAIN="t.com")
        r = subprocess.run([sys.executable, os.path.join(ROOT, "stiglitz_report.py")],
                           env=env, cwd=ROOT, capture_output=True, text=True)
        assert r.returncode == 0, r.stderr
        findings = json.load(open(os.path.join(outdir, "findings.json"))).get("findings", [])
        orders = [f for f in findings if f.get("url") == "https://t.com/api/orders/123"]
        # o confirmado do bizlogic sobrevive (não suprimido pela P9.5 inconclusiva)
        assert len(orders) == 2, \
            f"P9.5 inconclusiva não deveria suprimir o confirmado da P9.7, veio {len(orders)}"
    finally:
        shutil.rmtree(outdir)

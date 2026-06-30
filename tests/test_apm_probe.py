import os, sys
import json

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))

from vuln_catalog import CATALOG
import apm_probe


# ── Catálogo ───────────────────────────────────────────────────────────────
def test_apm_classes_registered():
    expected = {
        "apm_unauth_ingestion":      "CWE-306",
        "apm_central_config_exposed": "CWE-306",
    }
    for klass, cwe in expected.items():
        assert klass in CATALOG, f"{klass} ausente do CATALOG"
        assert CATALOG[klass]["cwe"] == cwe
        assert CATALOG[klass]["vector"].startswith("AV:")
        assert CATALOG[klass]["title"]


# ── Fingerprint APM ──────────────────────────────────────────────────────────
def test_looks_like_apm_validation_body():
    # corpo real do APM Server num POST inválido sem auth
    body = '{"accepted":0,"errors":[{"message":"validation error: \'metadata\' required"}]}'
    assert apm_probe.looks_like_apm(400, body, 401) is True


def test_looks_like_apm_accepted():
    assert apm_probe.looks_like_apm(202, "", 401) is True


def test_looks_like_apm_auth_path():
    # intake e config ambos exigem credencial → caminho de auth do APM existe
    assert apm_probe.looks_like_apm(401, "", 401) is True


def test_looks_like_apm_not_apm_404():
    assert apm_probe.looks_like_apm(404, "Not Found", 404) is False


def test_looks_like_apm_html_is_not_apm():
    assert apm_probe.looks_like_apm(200, "<html><body>hello</body></html>", 200) is False


# ── Classificação do intake ───────────────────────────────────────────────────
def test_classify_intake_anonymous_enabled_real_case():
    # caso confirmado ao vivo contra um APM Server PROD:
    # sem auth → 400 (processou, validation error); com Bearer inválido → 401
    body = '{"accepted":0,"errors":[{"message":"validation error: \'metadata\' required"}]}'
    v = apm_probe.classify_intake(400, body, 401)
    assert v["state"] == "CONFIRMED"


def test_classify_intake_accepted_outright():
    # sem auth → 202 (aceitou de fato) é confirmação ainda mais forte
    v = apm_probe.classify_intake(202, "", 401)
    assert v["state"] == "CONFIRMED"


def test_classify_intake_protected():
    # sem auth → 401 = ingestão protegida
    v = apm_probe.classify_intake(401, "", 401)
    assert v["state"] == "REJECTED"


def test_classify_intake_400_without_apm_body_is_inconclusive():
    # 400 genérico (sem assinatura APM) não confirma — evita FP
    v = apm_probe.classify_intake(400, "Bad Request", 401)
    assert v["state"] == "INCONCLUSIVE"


def test_classify_intake_unreachable():
    v = apm_probe.classify_intake(0, "", 0)
    assert v["state"] == "INCONCLUSIVE"


# ── Classificação do config endpoint ──────────────────────────────────────────
def test_classify_config_exposed_real_case():
    # sem auth → 200 {}; com Bearer inválido → 401
    v = apm_probe.classify_config(200, 401)
    assert v["state"] == "CONFIRMED"


def test_classify_config_protected():
    v = apm_probe.classify_config(401, 401)
    assert v["state"] == "REJECTED"


def test_classify_config_no_auth_layer_inconclusive():
    # 200 sem auth E 200 com token → não há camada de auth distinguível aqui
    v = apm_probe.classify_config(200, 200)
    assert v["state"] == "INCONCLUSIVE"


# ── Construção de findings ────────────────────────────────────────────────────
def test_build_findings_emits_both_when_confirmed():
    intake_v = {"state": "CONFIRMED", "evidence": "noauth=400 badtoken=401"}
    config_v = {"state": "CONFIRMED", "evidence": "noauth=200 badtoken=401"}
    fs = apm_probe.build_findings(intake_v, config_v, "https://apm.example.com")
    klasses = {f["type"] for f in fs}
    assert "apm_unauth_ingestion" in klasses
    assert "apm_central_config_exposed" in klasses
    ingestion = next(f for f in fs if f["type"] == "apm_unauth_ingestion")
    assert ingestion["severity"] == "high"
    assert ingestion["cwe"] == "CWE-306"
    assert ingestion["url"] == "https://apm.example.com/intake/v2/events"
    assert ingestion["fingerprint"]
    assert ingestion["source"]
    config = next(f for f in fs if f["type"] == "apm_central_config_exposed")
    assert config["url"] == "https://apm.example.com/config/v1/agents"
    # fingerprints distintos (mesmo CWE-306 no mesmo host, endpoints diferentes)
    assert ingestion["fingerprint"] != config["fingerprint"]


def test_build_findings_empty_when_rejected():
    intake_v = {"state": "REJECTED", "evidence": ""}
    config_v = {"state": "REJECTED", "evidence": ""}
    assert apm_probe.build_findings(intake_v, config_v, "https://apm.example.com") == []


def test_build_findings_partial():
    intake_v = {"state": "REJECTED", "evidence": ""}
    config_v = {"state": "CONFIRMED", "evidence": "noauth=200 badtoken=401"}
    fs = apm_probe.build_findings(intake_v, config_v, "https://apm.example.com")
    assert [f["type"] for f in fs] == ["apm_central_config_exposed"]


# ── Orquestração com rede injetável ───────────────────────────────────────────
def test_run_writes_json_and_confirms(tmp_path):
    # send_fn fake reproduz o alvo real: (method, url, headers, data) -> (status, body)
    def fake_send(method, url, headers, data, timeout=15):
        auth = (headers or {}).get("Authorization", "")
        if "/intake/v2/events" in url:
            if auth:
                return (401, "")
            return (400, '{"accepted":0,"errors":[{"message":"validation error"}]}')
        if "/config/v1/agents" in url:
            if auth:
                return (401, "")
            return (200, "{}")
        return (404, "")

    scan_dir = str(tmp_path)
    os.makedirs(os.path.join(scan_dir, "raw"), exist_ok=True)
    res = apm_probe.run(scan_dir, "https://apm.example.com", send_fn=fake_send)
    assert res["summary"]["total"] == 2
    out = os.path.join(scan_dir, "raw", "apm_probe.json")
    assert os.path.exists(out)
    data = json.load(open(out))
    assert {f["type"] for f in data} == {"apm_unauth_ingestion", "apm_central_config_exposed"}


def test_run_noop_when_not_apm(tmp_path):
    def fake_send(method, url, headers, data, timeout=15):
        return (404, "Not Found")

    scan_dir = str(tmp_path)
    os.makedirs(os.path.join(scan_dir, "raw"), exist_ok=True)
    res = apm_probe.run(scan_dir, "https://not-apm.example.com", send_fn=fake_send)
    assert res["summary"]["total"] == 0
    assert res["summary"]["is_apm"] is False

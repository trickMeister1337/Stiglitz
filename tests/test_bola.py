# tests/test_bola.py
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
import vuln_catalog
import bola as B


def test_catalog_has_bfla_entry():
    e = vuln_catalog.CATALOG["bfla"]
    assert e["cwe"] == "CWE-285"
    assert "AV:N" in e["vector"]
    assert e["title"]


def test_parse_zap_messages_extracts_requests():
    dump = {
        "messages": [
            {"requestHeader": "GET /users/123 HTTP/1.1\r\nHost: t.com\r\nAuthorization: Bearer X\r\n\r\n",
             "requestBody": "",
             "responseHeader": "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n",
             "responseBody": '{"id":123,"email":"a@t.com"}'},
            {"requestHeader": "POST /login HTTP/1.1\r\nHost: t.com\r\n\r\n",
             "requestBody": "u=1", "responseHeader": "HTTP/1.1 302 Found\r\n\r\n",
             "responseBody": ""},
        ]
    }
    import json
    reqs = B.parse_zap_messages(json.dumps(dump))
    assert len(reqs) == 2
    r0 = reqs[0]
    assert r0["method"] == "GET"
    assert r0["url"].endswith("/users/123")
    assert r0["status"] == 200
    assert "email" in r0["resp_body"]
    assert reqs[1]["method"] == "POST"


def test_parse_zap_messages_ignores_garbage():
    assert B.parse_zap_messages("not json") == []
    assert B.parse_zap_messages('{"messages": "x"}') == []
    assert B.parse_zap_messages("") == []


def test_is_object_ref_request_detects_object_handles():
    assert B.is_object_ref_request({"url": "/users/123"}) is True
    assert B.is_object_ref_request({"url": "/api/orders/42/items"}) is True
    assert B.is_object_ref_request(
        {"url": "/x?account=550e8400-e29b-41d4-a716-446655440000"}) is True
    assert B.is_object_ref_request({"url": "/profile?id=7"}) is True
    assert B.is_object_ref_request({"url": "/about"}) is False
    assert B.is_object_ref_request({"url": "/login"}) is False
    assert B.is_object_ref_request({"url": ""}) is False


def test_is_safe_method():
    assert B.is_safe_method("GET") is True
    assert B.is_safe_method("head") is True
    assert B.is_safe_method("OPTIONS") is True
    assert B.is_safe_method("POST") is False
    assert B.is_safe_method("DELETE") is False
    assert B.is_safe_method("") is False


def test_extract_canary_pulls_ids_and_pii():
    body = '{"id":123,"email":"alice@target.com","name":"Alice","cpf":"123.456.789-09"}'
    can = B.extract_canary(body, "application/json")
    assert "alice@target.com" in can
    assert "123.456.789-09" in can
    assert "123" in can  # id


def test_extract_canary_empty_when_no_handles():
    assert B.extract_canary("<html><body>welcome</body></html>", "text/html") == set()
    assert B.extract_canary("", "application/json") == set()


def test_canary_is_pii_flags_email_cpf():
    assert B.canary_is_pii({"alice@target.com"}) is True
    assert B.canary_is_pii({"123.456.789-09"}) is True
    assert B.canary_is_pii({"123"}) is False


OWNER = {"status": 200, "body": '{"id":123,"email":"alice@target.com"}'}


def test_verdict_protected_when_cross_denied():
    cross = {"status": 403, "body": "forbidden"}
    unauth = {"status": 401, "body": "no"}
    v = B.verdict(OWNER, cross, unauth, {"alice@target.com", "123"})
    assert v["state"] == "PROTECTED"


def test_verdict_public_when_unauth_sees_same_body():
    cross = {"status": 200, "body": OWNER["body"]}
    unauth = {"status": 200, "body": OWNER["body"]}   # qualquer um acessa
    v = B.verdict(OWNER, cross, unauth, {"alice@target.com", "123"})
    assert v["state"] == "PUBLIC"


def test_verdict_confirmed_when_cross_sees_owner_object():
    cross = {"status": 200, "body": OWNER["body"]}     # idêntico ao dono
    unauth = {"status": 401, "body": "no"}             # anônimo negado
    v = B.verdict(OWNER, cross, unauth, {"alice@target.com", "123"})
    assert v["state"] == "CONFIRMED"
    assert v["canary_hit"] is True
    assert v["confidence"] >= 85


def test_verdict_inconclusive_when_canary_absent():
    # cross vê 200 com MESMO template mas dados próprios (sem canário do dono)
    cross = {"status": 200, "body": '{"id":999,"email":"bob@target.com"}'}
    unauth = {"status": 401, "body": "no"}
    v = B.verdict(OWNER, cross, unauth, {"alice@target.com", "123"})
    assert v["state"] == "INCONCLUSIVE"
    assert v["canary_hit"] is False
    assert v["confidence"] < 60


def test_classify_picks_bfla_idor_bola():
    # path privilegiado → bfla
    assert B.classify({"url": "https://t.com/admin/users/1"}, {"x"}) == "bfla"
    # PII no canário → idor_read_pii
    assert B.classify({"url": "https://t.com/users/1"}, {"alice@target.com"}) == "idor_read_pii"
    # objeto sem PII → bola
    assert B.classify({"url": "https://t.com/orders/9"}, {"9"}) == "bola"


def test_build_findings_schema_and_fingerprint():
    results = [{
        "req": {"url": "https://t.com/users/123", "method": "GET"},
        "verdict": {"state": "CONFIRMED", "canary_hit": True, "confidence": 90},
        "canary": {"alice@target.com", "123"},
        "direction": "B->A",
    }]
    out = B.build_findings(results)
    assert len(out) == 1
    f = out[0]
    assert f["type"] == "idor_read_pii"
    assert f["cwe"] == "CWE-639"
    assert f["url"] == "https://t.com/users/123"
    assert f["confirmed"] is True
    assert f["severity"] == "high"
    assert f["direction"] == "B->A"
    assert len(f["fingerprint"]) == 16


def test_build_findings_skips_non_actionable():
    results = [
        {"req": {"url": "https://t.com/a/1"}, "verdict": {"state": "PROTECTED", "confidence": 0},
         "canary": set(), "direction": "B->A"},
        {"req": {"url": "https://t.com/a/2"}, "verdict": {"state": "PUBLIC", "confidence": 0},
         "canary": set(), "direction": "B->A"},
    ]
    assert B.build_findings(results) == []


import json as _json


def _fake_replay_factory():
    # Simula: cross com token "B" vê o objeto do dono em /users/123 (BOLA);
    # unauth sempre negado; /about é público.
    def replay_fn(req, token):
        url = req["url"]
        if "/users/123" in url:
            if token is None:
                return {"status": 401, "body": "no"}
            return {"status": 200, "body": '{"id":123,"email":"alice@target.com"}'}
        return {"status": 404, "body": ""}
    return replay_fn


def test_run_confirms_bola_bidirectional(tmp_path):
    msgs_a = _json.dumps({"messages": [
        {"requestHeader": "GET /users/123 HTTP/1.1\r\nHost: t.com\r\n\r\n", "requestBody": "",
         "responseHeader": "HTTP/1.1 200 OK\r\n\r\n",
         "responseBody": '{"id":123,"email":"alice@target.com"}'},
    ]})
    msgs_b = _json.dumps({"messages": []})
    out = str(tmp_path)
    res = B.run(msgs_a, msgs_b, "tokA", "tokB", out, replay_fn=_fake_replay_factory())
    assert any(f["type"] == "idor_read_pii" and f["confirmed"] for f in res["findings"])
    assert os.path.exists(os.path.join(out, "access_control.json"))


def test_cli_run_returns_zero(tmp_path, monkeypatch, capsys):
    msgs_a = tmp_path / "a.json"
    msgs_a.write_text('{"messages": []}')
    msgs_b = tmp_path / "b.json"
    msgs_b.write_text('{"messages": []}')
    monkeypatch.setenv("BOLA_TOKEN_A", "x")
    monkeypatch.setenv("BOLA_TOKEN_B", "y")
    rc = B.main(["bola.py", "run", str(msgs_a), str(msgs_b), str(tmp_path)])
    assert rc == 0


def test_cli_unknown_command_returns_2():
    assert B.main(["bola.py", "bogus"]) == 2


def test_replay_rejects_non_http_url():
    # URL que começaria com '-' (argv smuggling) ou esquema não-http → rejeitado sem curl
    assert B.replay({"url": "-O/etc/passwd", "method": "GET"}, "tok")["status"] == 0
    assert B.replay({"url": "file:///etc/passwd", "method": "GET"}, None)["status"] == 0
    assert B.replay({"url": "", "method": "GET"}, "tok")["status"] == 0


def test_replay_rejects_unsafe_method():
    assert B.replay({"url": "https://t.com/users/1", "method": "DELETE"}, "tok")["status"] == 0


def test_replay_parses_status_marker_with_embedded_marker(monkeypatch):
    import subprocess

    class _P:
        # corpo contém o marcador fake; o real é o ÚLTIMO (rfind) anexado pelo curl
        stdout = "data __HTTP_STATUS__:fake more\n__HTTP_STATUS__:200"

    monkeypatch.setattr(subprocess, "run", lambda *a, **k: _P())
    r = B.replay({"url": "https://t.com/users/1", "method": "GET"}, "tok")
    assert r["status"] == 200
    assert r["body"].startswith("data __HTTP_STATUS__:fake more")


def test_replay_auth_header_before_url(monkeypatch):
    # Regressão: o header Authorization deve vir ANTES do '--'/url. Se vier depois,
    # o curl trata "Authorization: Bearer ..." como segunda URL e o token nunca é
    # enviado → o replay "cross" do token B roda DESLOGADO (falso PROTECTED → FN de BOLA).
    import subprocess
    captured = {}

    class _P:
        stdout = "{}\n__HTTP_STATUS__:200"

    def fake_run(cmd, *a, **k):
        captured["cmd"] = cmd
        return _P()

    monkeypatch.setattr(subprocess, "run", fake_run)
    B.replay({"url": "https://t.com/users/1", "method": "GET"}, "TOKB")
    cmd = captured["cmd"]
    assert "--" in cmd
    dd = cmd.index("--")
    auth_idx = next(i for i, a in enumerate(cmd)
                    if isinstance(a, str) and a.startswith("Authorization: Bearer"))
    assert auth_idx < dd, "header Authorization deve preceder o '--'/url"
    assert "Authorization: Bearer TOKB" in cmd


def test_replay_unauth_sends_no_auth_header(monkeypatch):
    import subprocess
    captured = {}

    class _P:
        stdout = "{}\n__HTTP_STATUS__:401"

    def fake_run(cmd, *a, **k):
        captured["cmd"] = cmd
        return _P()

    monkeypatch.setattr(subprocess, "run", fake_run)
    B.replay({"url": "https://t.com/users/1", "method": "GET"}, None)
    assert not any(isinstance(a, str) and a.startswith("Authorization:")
                   for a in captured["cmd"])


def test_run_writes_access_findings_array_in_raw(tmp_path):
    msgs_a = _json.dumps({"messages": [
        {"requestHeader": "GET /users/123 HTTP/1.1\r\nHost: t.com\r\n\r\n", "requestBody": "",
         "responseHeader": "HTTP/1.1 200 OK\r\n\r\n",
         "responseBody": '{"id":123,"email":"alice@target.com"}'},
    ]})
    msgs_b = _json.dumps({"messages": []})
    out = str(tmp_path)
    B.run(msgs_a, msgs_b, "tokA", "tokB", out, replay_fn=_fake_replay_factory())
    p = os.path.join(out, "raw", "access_findings.json")
    assert os.path.exists(p)
    arr = _json.load(open(p))
    assert isinstance(arr, list)
    assert any(f["type"] == "idor_read_pii" for f in arr)

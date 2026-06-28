# tests/test_graphql_authz.py
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
import graphql_authz as gz


def _msg(method, url, body, status=200, resp=""):
    return {"method": method, "url": url, "req_body": body,
            "status": status, "resp_body": resp, "req_headers": ""}


def test_select_only_graphql_posts():
    msgs = [
        _msg("POST", "http://t/graphql", '{"query":"{ me { id } }"}'),
        _msg("GET", "http://t/graphql", ""),                       # não-POST
        _msg("POST", "http://t/api/users/1", '{"x":1}'),            # não-graphql path
        _msg("POST", "http://t/v1/graphql", '{"query":"mutation { x }"}'),
    ]
    out = gz.select_graphql_messages(msgs)
    urls = [m["url"] for m in out]
    assert urls == ["http://t/graphql", "http://t/v1/graphql"]


def test_classify_mutation_is_bfla():
    req = _msg("POST", "http://t/graphql", '{"query":"mutation { deleteUser(id:1){ ok } }"}')
    assert gz._classify(req) == "graphql_bfla"

def test_classify_sensitive_name_is_bfla():
    req = _msg("POST", "http://t/graphql", '{"query":"{ adminPanel { secret } }"}')
    assert gz._classify(req) == "graphql_bfla"

def test_classify_plain_query_is_bola():
    req = _msg("POST", "http://t/graphql", '{"query":"{ account(id:1){ balance } }"}')
    assert gz._classify(req) == "graphql_bola"


def test_select_endpoint_substr_case_insensitive():
    # path com caixa mista + endpoint_substr com caixa mista devem casar
    msgs = [_msg("POST", "http://t/GraphQL", '{"query":"{ me { id } }"}')]
    out = gz.select_graphql_messages(msgs, "GraphQL")
    assert len(out) == 1


def test_replay_auth_header_before_url(monkeypatch):
    # Regressão CRÍTICA: o header Authorization deve vir ANTES do '--'/url. Se vier
    # depois, o curl trata "Authorization: Bearer ..." como segunda URL e o token
    # nunca é enviado — quebrando todo o replay autenticado.
    import subprocess
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd

        class R:
            stdout = '{"data":{}}\n__HTTP_STATUS__:200'
        return R()

    monkeypatch.setattr(subprocess, "run", fake_run)
    out = gz._replay(_msg("POST", "http://t/graphql", '{"query":"{ me { id } }"}'), "TOKENXYZ")
    cmd = captured["cmd"]
    assert "--" in cmd
    dd = cmd.index("--")
    auth_idx = next(i for i, a in enumerate(cmd)
                    if isinstance(a, str) and a.startswith("Authorization: Bearer"))
    assert auth_idx < dd, "header Authorization deve preceder o '--'/url"
    assert "Authorization: Bearer TOKENXYZ" in cmd
    assert out["status"] == 200


def test_replay_unauth_has_no_auth_header(monkeypatch):
    import subprocess
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd

        class R:
            stdout = '{}\n__HTTP_STATUS__:401'
        return R()

    monkeypatch.setattr(subprocess, "run", fake_run)
    out = gz._replay(_msg("POST", "http://t/graphql", '{"query":"{ me { id } }"}'), None)
    assert not any(isinstance(a, str) and a.startswith("Authorization:")
                   for a in captured["cmd"])
    assert out["status"] == 401

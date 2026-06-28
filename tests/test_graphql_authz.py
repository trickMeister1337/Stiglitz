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

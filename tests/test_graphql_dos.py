# tests/test_graphql_dos.py
import os, sys, json
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
import graphql_dos as gd


def test_build_alias_probe_has_n_aliases():
    p = gd.build_alias_probe(5)
    assert p["query"].count("__typename") == 5
    assert "a0:__typename" in p["query"] and "a4:__typename" in p["query"]

def test_build_batch_probe_len():
    b = gd.build_batch_probe(7)
    assert isinstance(b, list) and len(b) == 7
    assert all(x == {"query": "{__typename}"} for x in b)

def test_is_graphql_response_data_or_errors():
    assert gd._is_graphql_response(200, '{"data":{"__typename":"Query"}}') is True
    assert gd._is_graphql_response(400, '{"errors":[{"message":"x"}]}') is True
    assert gd._is_graphql_response(200, '<html>nope</html>') is False

def test_classify_alias_finds_when_all_resolved():
    data = {"data": {f"a{i}": "Query" for i in range(10)}}
    f = gd.classify_alias_response(200, json.dumps(data), 10)
    assert f and f["type"] == "graphql_no_complexity_limit" and f["severity"] == "medium"

def test_classify_alias_none_when_errors():
    body = '{"errors":[{"message":"max complexity exceeded"}]}'
    assert gd.classify_alias_response(200, body, 10) is None

def test_classify_alias_none_when_partial():
    data = {"data": {f"a{i}": "Query" for i in range(3)}}
    assert gd.classify_alias_response(200, json.dumps(data), 10) is None

def test_classify_batch_finds_array():
    body = json.dumps([{"data": {}}, {"data": {}}, {"data": {}}])
    f = gd.classify_batch_response(200, body, 3)
    assert f and f["type"] == "graphql_batching_enabled" and f["severity"] == "low"

def test_classify_batch_none_single_object():
    assert gd.classify_batch_response(200, '{"data":{}}', 3) is None

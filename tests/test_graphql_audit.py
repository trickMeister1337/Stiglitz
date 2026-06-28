import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
import graphql_audit as G

SCHEMA_RESP = {"data": {"__schema": {
    "queryType": {"name": "Query"},
    "mutationType": {"name": "Mutation"},
    "types": [
        {"name": "Query", "fields": [{"name": "users"}, {"name": "me"}]},
        {"name": "Mutation", "fields": [{"name": "deleteUser"}, {"name": "login"}]},
        {"name": "User", "fields": [{"name": "id"}, {"name": "password"}]},
    ]}}}

DISABLED_RESP = {"errors": [{"message": "GraphQL introspection is not allowed"}]}


def test_introspection_query_is_valid():
    q = G.introspection_query()
    assert "__schema" in q
    assert "queryType" in q


def test_is_introspection_enabled():
    assert G.is_introspection_enabled(SCHEMA_RESP) is True
    assert G.is_introspection_enabled(DISABLED_RESP) is False
    assert G.is_introspection_enabled({}) is False


def test_parse_introspection_extracts_types_and_mutations():
    info = G.parse_introspection(SCHEMA_RESP)
    assert "User" in info["types"]
    assert "deleteUser" in info["mutations"]
    assert info["query_type"] == "Query"


def test_parse_introspection_none_when_disabled():
    assert G.parse_introspection(DISABLED_RESP) is None


def test_findings_when_introspection_enabled():
    fnds = G.findings_from_response(SCHEMA_RESP, "http://t/graphql")
    intro = [f for f in fnds if f["type"] == "graphql_introspection"]
    assert intro and intro[0]["severity"] in ("medium", "low")
    assert "http://t/graphql" == intro[0]["url"]


def test_findings_flag_sensitive_mutations():
    fnds = G.findings_from_response(SCHEMA_RESP, "http://t/graphql")
    sens = [f for f in fnds if f["type"] == "graphql_sensitive_mutation"]
    assert any("deleteUser" in f["description"] for f in sens)


def test_no_findings_when_introspection_disabled():
    assert G.findings_from_response(DISABLED_RESP, "http://t/graphql") == []


# --- is_mutation ---

def test_is_mutation_json_body_true():
    assert G.is_mutation('{"query":"mutation { deleteUser(id:1){ ok } }"}') is True

def test_is_mutation_named_mutation_true():
    assert G.is_mutation('mutation Foo($a:Int){ pay(amount:$a){ id } }') is True

def test_is_mutation_anonymous_query_false():
    assert G.is_mutation('{"query":"{ me { id } }"}') is False

def test_is_mutation_explicit_query_false():
    assert G.is_mutation('{"query":"query Q { account(id:1){ id } }"}') is False

def test_is_mutation_subscription_false():
    assert G.is_mutation('subscription { onEvent { id } }') is False

def test_is_mutation_leading_comment_and_space_true():
    assert G.is_mutation('{"query":"  # comentário\\n  mutation { x }"}') is True

def test_is_mutation_batch_any_mutation_true():
    assert G.is_mutation('[{"query":"{ a }"},{"query":"mutation { b }"}]') is True

def test_is_mutation_empty_false():
    assert G.is_mutation("") is False

import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
import openapi_diff as od

_OAS3 = {
    "openapi": "3.0.0",
    "paths": {"/cards/{id}": {"get": {"responses": {"200": {"content": {
        "application/json": {"schema": {"$ref": "#/components/schemas/Card"}}}}}}}},
    "components": {"schemas": {"Card": {"type": "object", "properties": {
        "id": {"type": "string"}, "last4": {"type": "string"}}}}},
}
_SW2 = {
    "swagger": "2.0",
    "paths": {"/u": {"get": {"responses": {"200": {"schema": {"$ref": "#/definitions/U"}}}}}},
    "definitions": {"U": {"properties": {"name": {"type": "string"}}}},
}


def test_resolve_oas3_ref():
    assert od.resolve_response_schema(_OAS3, "/cards/{id}", "GET") == {"id", "last4"}


def test_resolve_swagger2_definitions():
    assert od.resolve_response_schema(_SW2, "/u", "GET") == {"name"}


def test_resolve_inline_properties():
    spec = {"openapi": "3.0.0", "paths": {"/x": {"get": {"responses": {"200": {"content": {
        "application/json": {"schema": {"properties": {"a": {}, "b": {}}}}}}}}}}}
    assert od.resolve_response_schema(spec, "/x", "GET") == {"a", "b"}


def test_resolve_cyclic_ref_terminates():
    spec = {"openapi": "3.0.0",
            "paths": {"/x": {"get": {"responses": {"200": {"content": {
                "application/json": {"schema": {"$ref": "#/components/schemas/Node"}}}}}}}},
            "components": {"schemas": {"Node": {"properties": {"self": {"$ref": "#/components/schemas/Node"}}}}}}
    # não deve travar; retorna as chaves de topo
    assert od.resolve_response_schema(spec, "/x", "GET") == {"self"}


def test_resolve_missing_schema_is_empty():
    spec = {"openapi": "3.0.0", "paths": {"/x": {"get": {"responses": {"200": {}}}}}}
    assert od.resolve_response_schema(spec, "/x", "GET") == set()


def test_observed_fields_top_level_json():
    assert od.observed_fields('{"id":1,"last4":"1234","pan":"x"}', "application/json") == {"id", "last4", "pan"}


def test_observed_fields_non_json_is_empty():
    assert od.observed_fields("<html>hi</html>", "text/html") == set()


def test_excessive_fields_detects_extra():
    assert od.excessive_fields('{"id":1,"last4":"1","full_pan":"x"}', {"id", "last4"}, "application/json") == {"full_pan"}


def test_excessive_fields_no_extra_is_empty():
    assert od.excessive_fields('{"id":1,"last4":"1"}', {"id", "last4"}, "application/json") == set()


def test_excessive_fields_empty_declared_is_empty():
    # sem baseline declarado -> não inventa exposição
    assert od.excessive_fields('{"id":1}', set(), "application/json") == set()


def test_classify_excessive_base_medium():
    assert od.classify_excessive({"nickname"}, '{"nickname":"joe"}') == "medium"


def test_classify_excessive_pii_high():
    assert od.classify_excessive({"email"}, '{"email":"a@b.com"}') == "high"


def test_classify_excessive_pan_critical():
    # PAN Luhn-válido com contexto de cartão
    body = '{"card_number":"4111111111111111"}'
    assert od.classify_excessive({"card_number"}, body) == "critical"


def test_classify_excessive_numeric_id_field_is_not_pii():
    # Campo id numérico NÃO é PII (bug: extract_canary.isdigit() fazia retornar "high")
    # Esperado: "medium" (não é CPF/CNPJ/email validado)
    body = '{"id":1,"order_id":"998877","nickname":"joe"}'
    assert od.classify_excessive({"nickname"}, body) == "medium"


_SPEC_PATHS = {"openapi": "3.0.0", "paths": {
    "/cards/{id}": {"get": {}}, "/users": {"get": {}}}}


def test_matchers_match_templated_path():
    m = od.documented_path_matchers(_SPEC_PATHS)
    # /cards/123 casa (documentado); não é shadow
    assert od.shadow_paths(["https://h/cards/123"], m) == []


def test_shadow_path_not_in_spec():
    m = od.documented_path_matchers(_SPEC_PATHS)
    assert od.shadow_paths(["https://h/admin/debug"], m) == ["/admin/debug"]


def test_shadow_ignores_querystring():
    m = od.documented_path_matchers(_SPEC_PATHS)
    assert od.shadow_paths(["https://h/users?page=2"], m) == []


def test_shadow_dedups_and_filters_scope():
    m = od.documented_path_matchers(_SPEC_PATHS)
    urls = ["https://h/admin", "https://h/admin", "https://evil.com/x"]
    assert od.shadow_paths(urls, m, scope_host="h") == ["/admin"]


def test_build_finding_excessive_shape():
    f = od._finding("openapi_excessive_data",
                    "Excessive Data Exposure vs OpenAPI schema", "high", "CWE-213",
                    "https://h/cards/1", "desc", "ev", method="GET")
    assert f["type"] == "openapi_excessive_data"
    assert f["severity"] == "high"
    assert f["cwe"] == "CWE-213"
    assert f["source"] == "openapi_diff" and f["tool"] == "openapi_diff"
    assert f["fingerprint"] and f["fingerprint"] != "0" * 16


def test_build_finding_distinct_types_distinct_fingerprints():
    a = od._finding("openapi_excessive_data", "n", "medium", "CWE-213", "https://h/x", "d", "e")
    b = od._finding("openapi_shadow_endpoint", "n", "low", "CWE-1059", "https://h/x", "d", "e")
    assert a["fingerprint"] != b["fingerprint"]

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

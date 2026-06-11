import os, sys, json
sys.path[:0] = [os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "lib")]
import openapi_seed as OS


BASE = "https://chargebacks.bee2pay.com"


def test_openapi3_substitutes_path_params():
    spec = {"openapi": "3.0.1", "paths": {
        "/api/v1/Chargeback/{tenantId}/{chargebackId}": {"get": {}},
    }}
    urls = OS.spec_to_urls(spec, BASE, sample="1")
    assert urls == ["https://chargebacks.bee2pay.com/api/v1/Chargeback/1/1"]


def test_swagger2_basepath_is_prefixed():
    spec = {"swagger": "2.0", "basePath": "/api", "paths": {
        "/orders/{id}": {"get": {}},
    }}
    urls = OS.spec_to_urls(spec, BASE, sample="1")
    assert urls == ["https://chargebacks.bee2pay.com/api/orders/1"]


def test_servers_path_prefix_no_double_when_path_has_it():
    # servers url já traz /api/v1; o path também → não duplica
    spec = {"openapi": "3.0.0", "servers": [{"url": "/api/v1"}], "paths": {
        "/api/v1/users/{id}": {"get": {}},
    }}
    urls = OS.spec_to_urls(spec, BASE, sample="1")
    assert urls == ["https://chargebacks.bee2pay.com/api/v1/users/1"]


def test_servers_path_prefix_added_when_path_relative():
    spec = {"openapi": "3.0.0", "servers": [{"url": "/api/v1"}], "paths": {
        "/users/{id}": {"get": {}},
    }}
    urls = OS.spec_to_urls(spec, BASE, sample="1")
    assert urls == ["https://chargebacks.bee2pay.com/api/v1/users/1"]


def test_accepts_json_text_and_dedups():
    spec = {"openapi": "3.0.0", "paths": {
        "/a/{x}": {"get": {}},
        "/a/{y}": {"post": {}},   # mesma forma após substituição → dedup
        "/b": {"get": {}},
    }}
    urls = OS.spec_to_urls(json.dumps(spec), BASE, sample="1")
    assert urls == ["https://chargebacks.bee2pay.com/a/1",
                    "https://chargebacks.bee2pay.com/b"]


def test_invalid_or_empty_spec_returns_empty():
    assert OS.spec_to_urls("não é json", BASE) == []
    assert OS.spec_to_urls({}, BASE) == []
    assert OS.spec_to_urls({"openapi": "3.0", "paths": "bad"}, BASE) == []


def test_cli_reads_file_and_prints_urls(tmp_path, capsys):
    spec = {"openapi": "3.0.0", "paths": {"/api/v1/Chargeback/{tenantId}/{chargebackId}": {"get": {}}}}
    p = tmp_path / "spec.json"
    p.write_text(json.dumps(spec))
    rc = OS.main([str(p), BASE])
    out = capsys.readouterr().out.strip().splitlines()
    assert rc == 0
    assert out == ["https://chargebacks.bee2pay.com/api/v1/Chargeback/1/1"]

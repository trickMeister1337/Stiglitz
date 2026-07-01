import os, sys, json as _json
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
import service_exposure as se


class _Recorder:
    """send_fn fake: roteia por (method, path-sem-querystring) e registra as chamadas."""
    def __init__(self, routes):
        self.routes = routes          # {(method, path): (status, body)}
        self.calls = []

    def __call__(self, method, url, headers, data, timeout=15):
        from urllib.parse import urlsplit
        self.calls.append((method, url, dict(headers or {})))
        return self.routes.get((method, urlsplit(url).path), (404, ""))


def test_markers_match_all_present_non_html():
    assert se.markers_match('{"tagline":"You Know, for Search","version":{"lucene_version":"9.7"}}',
                            ["you know, for search", "lucene_version"]) is True


def test_markers_match_html_body_disqualifies():
    assert se.markers_match("<html><body>You Know, for Search</body></html>",
                            ["you know, for search"]) is False


def test_markers_match_missing_marker():
    assert se.markers_match('{"tagline":"You Know, for Search"}', ["lucene_version"]) is False


def test_is_service_requires_200():
    assert se.is_service(401, '{"lucene_version":"9.7"}', ["lucene_version"]) is False
    assert se.is_service(200, '{"lucene_version":"9.7"}', ["lucene_version"]) is True


def test_catalog_has_expected_services():
    names = {s["name"] for s in se.SERVICE_CATALOG.values()}
    assert {"Elasticsearch", "Kibana", "Grafana", "Spring Boot Actuator", "Consul",
            "etcd", "Docker Engine API", "Kubernetes API", "RabbitMQ Management",
            "Apache Airflow", "Jenkins"} <= names
    # cada probe traz os campos exigidos pelo finding
    for spec in se.SERVICE_CATALOG.values():
        assert spec["fingerprint"] and spec["probes"]
        for pr in spec["probes"]:
            assert {"path", "finding_class", "severity", "cwe", "name", "exposes", "remediation"} <= set(pr)


def test_classify_rejected_when_auth_required():
    v = se.classify_exposure(401, "")
    assert v["state"] == "REJECTED"
    v = se.classify_exposure(403, "")
    assert v["state"] == "REJECTED"


def test_classify_confirmed_on_200():
    v = se.classify_exposure(200, '{"ok":true}')
    assert v["state"] == "CONFIRMED"


def test_classify_confirmed_reinforced_by_auth_contrast():
    v = se.classify_exposure(200, "{}", auth_status=401)
    assert v["state"] == "CONFIRMED"
    assert "invalid token" in v["evidence"]


def test_classify_inconclusive_on_other_status():
    assert se.classify_exposure(404, "")["state"] == "INCONCLUSIVE"
    assert se.classify_exposure(0, "")["state"] == "INCONCLUSIVE"


def test_build_findings_schema_and_cwe():
    spec = se.SERVICE_CATALOG["elasticsearch"]
    probe = spec["probes"][0]
    verdict = {"state": "CONFIRMED", "evidence": "without auth -> HTTP 200"}
    out = se.build_findings("elasticsearch", [(probe, verdict)], "https://host")
    assert len(out) == 1
    f = out[0]
    assert f["tool"] == "service_exposure"
    assert f["type"] == "elasticsearch_unauth_data"
    assert f["source"] == "Service Exposure"
    assert f["severity"] == "high"
    assert f["cwe"] == "CWE-306"
    assert f["url"] == "https://host/_cat/indices"   # query string removida
    assert "Elasticsearch" in f["name"]
    assert f["fingerprint"] and f["fingerprint"] != "0" * 16
    assert "all index names" in f["description"]


def test_docker_version_marker_matches_real_docker_engine_body():
    """Corpo real do Docker Engine /version (apiversion+components+"Os":"linux") ainda
    deve casar o fingerprint do catálogo docker."""
    docker_body = (
        '{"Platform":{"Name":""},"Components":[{"Name":"Engine","Version":"24.0.5"}],'
        '"Version":"24.0.5","ApiVersion":"1.43","MinAPIVersion":"1.12",'
        '"GitCommit":"a61e2b4","GoVersion":"go1.20.6","Os":"linux","Arch":"amd64",'
        '"KernelVersion":"5.15.0","BuildTime":"2023-08-03"}')
    markers = se.SERVICE_CATALOG["docker"]["fingerprint"][0]["markers"]
    assert se.markers_match(docker_body, markers) is True


def test_docker_version_marker_no_longer_matches_generic_apiversion_components_body():
    """Um corpo só com apiversion+components (sem o 3º marker distintivo do Docker)
    não deve mais casar como docker -- reduz cross-match com etcd/k8s em /version."""
    generic_body = '{"apiVersion":"v1","components":["a","b"]}'
    markers = se.SERVICE_CATALOG["docker"]["fingerprint"][0]["markers"]
    assert se.markers_match(generic_body, markers) is False


def test_build_findings_unknown_service_key_degrades_gracefully():
    """service_key fora do catálogo -> spec={} ; _finding não pode estourar KeyError
    (bracket access em spec['name']/probe['exposes']/probe['name']/probe['severity'])."""
    spec = se.SERVICE_CATALOG["elasticsearch"]
    probe = spec["probes"][0]
    verdict = {"state": "CONFIRMED", "evidence": "without auth -> HTTP 200"}
    out = se.build_findings("__inexistente__", [(probe, verdict)], "https://host")
    assert len(out) == 1
    f = out[0]
    assert f["url"] == "https://host/_cat/indices"


def test_build_findings_distinct_endpoints_distinct_fingerprints():
    spec = se.SERVICE_CATALOG["actuator"]
    v = {"state": "CONFIRMED", "evidence": "x"}
    out = se.build_findings("actuator", [(spec["probes"][0], v), (spec["probes"][1], v)], "https://h")
    assert len({f["fingerprint"] for f in out}) == 2


def test_run_detects_elasticsearch_and_emits_finding(tmp_path):
    routes = {
        ("GET", "/"): (200, '{"tagline":"You Know, for Search","version":{"lucene_version":"9.7"}}'),
        ("GET", "/_cat/indices"): (200, '[{"index":"users"}]'),
    }
    rec = _Recorder(routes)
    res = se.run(str(tmp_path), "https://host", send_fn=rec, timeout=1)
    assert res["summary"]["service"] == "elasticsearch"
    assert res["summary"]["total"] == 1
    assert res["findings"][0]["type"] == "elasticsearch_unauth_data"
    # gravou o JSON
    saved = _json.load(open(tmp_path / "raw" / "service_exposure.json"))
    assert saved[0]["type"] == "elasticsearch_unauth_data"


def test_run_failsafe_no_service(tmp_path):
    rec = _Recorder({})  # tudo 404
    res = se.run(str(tmp_path), "https://host", send_fn=rec, timeout=1)
    assert res["summary"]["service"] is None
    assert res["findings"] == []


def test_run_only_uses_get(tmp_path):
    routes = {
        ("GET", "/"): (200, '{"tagline":"You Know, for Search","version":{"lucene_version":"9.7"}}'),
        ("GET", "/_cat/indices"): (200, "[]"),
    }
    rec = _Recorder(routes)
    se.run(str(tmp_path), "https://host", send_fn=rec, timeout=1)
    assert all(c[0] == "GET" for c in rec.calls)   # NÃO-DESTRUTIVO


def test_run_rejected_emits_nothing(tmp_path):
    routes = {
        ("GET", "/"): (200, '{"tagline":"You Know, for Search","version":{"lucene_version":"9.7"}}'),
        ("GET", "/_cat/indices"): (401, ""),
    }
    rec = _Recorder(routes)
    res = se.run(str(tmp_path), "https://host", send_fn=rec, timeout=1)
    assert res["summary"]["service"] == "elasticsearch"
    assert res["findings"] == []

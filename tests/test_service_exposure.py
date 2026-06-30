import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
import service_exposure as se


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


def test_build_findings_distinct_endpoints_distinct_fingerprints():
    spec = se.SERVICE_CATALOG["actuator"]
    v = {"state": "CONFIRMED", "evidence": "x"}
    out = se.build_findings("actuator", [(spec["probes"][0], v), (spec["probes"][1], v)], "https://h")
    assert len({f["fingerprint"] for f in out}) == 2

#!/usr/bin/env python3
"""
service_exposure.py — probe config-driven de serviços com exposição/acesso sem auth.

Generaliza o padrão do apm_probe.py num CATÁLOGO: serviço novo = uma entrada de
dados, não um módulo novo. Fecha a "cegueira de descoberta" (Modo A): serviços de
API pura (ES/Kibana/Grafana/Actuator/Consul/etcd/Docker/K8s/RabbitMQ/Airflow/Jenkins)
que o spider/katana não alcançam por falta de links e o nuclei não cobre por template.

Núcleo puro (catálogo + fingerprint + classificadores, testável sem rede) +
orquestração de rede fina (curl via netproxy/mtls, injetável). Findings em EN
(deliverable); console/comentários PT-BR.

Não-destrutivo: SOMENTE GET. Fail-safe: só emite com serviço fingerprintado E
veredito CONFIRMED. Espelha apm_probe.py / oauth_audit.py.

Uso (CLI): python3 lib/service_exposure.py <scan_dir> <target_url>
"""
import os
import sys
import json
import urllib.parse

import netproxy
import mtls

try:
    from fingerprint import fingerprint as _fingerprint
except Exception:  # importado fora de lib/
    def _fingerprint(f):
        return "0" * 16

_PROBE_TOKEN = "Bearer service-exposure-invalid-probe"

# ── Catálogo de serviços (conhecimento da ferramenta; dado embutido) ───────────
# Cada entrada: fingerprint (confirma o serviço, markers que COEXISTEM no corpo) +
# probes (endpoints sensíveis, só GET). description é gerada por template a partir
# de name/path/exposes; remediation é específica por serviço.
SERVICE_CATALOG = {
    "elasticsearch": {
        "name": "Elasticsearch",
        "fingerprint": [{"path": "/", "markers": ["you know, for search", "lucene_version"]}],
        "probes": [{"path": "/_cat/indices?format=json", "finding_class": "elasticsearch_unauth_data",
                    "severity": "high", "cwe": "CWE-306",
                    "name": "Elasticsearch indices readable without authentication",
                    "exposes": "all index names and document counts",
                    "remediation": "Enable the Elasticsearch security features (xpack.security.enabled: true) "
                                   "and require credentials; never expose the HTTP API to untrusted networks."}],
        "port": 9200,
    },
    "kibana": {
        "name": "Kibana",
        "fingerprint": [{"path": "/api/status", "markers": ["\"version\"", "kibana"]}],
        "probes": [{"path": "/api/status", "finding_class": "kibana_unauth_status",
                    "severity": "medium", "cwe": "CWE-306",
                    "name": "Kibana status API readable without authentication",
                    "exposes": "version, plugin and infrastructure status",
                    "remediation": "Enable Kibana/Elastic security and require login; restrict network exposure."}],
        "port": 5601,
    },
    "grafana": {
        "name": "Grafana",
        "fingerprint": [{"path": "/api/health", "markers": ["\"database\"", "\"version\""]}],
        "probes": [{"path": "/api/org", "finding_class": "grafana_anon_org",
                    "severity": "medium", "cwe": "CWE-306",
                    "name": "Grafana organization API reachable anonymously",
                    "exposes": "organization details with anonymous access enabled",
                    "remediation": "Disable anonymous auth ([auth.anonymous] enabled = false) and require login."}],
        "port": 3000,
    },
    "actuator": {
        "name": "Spring Boot Actuator",
        "fingerprint": [{"path": "/actuator", "markers": ["_links", "self"]}],
        "probes": [{"path": "/actuator/env", "finding_class": "actuator_env_exposed",
                    "severity": "high", "cwe": "CWE-200",
                    "name": "Spring Boot Actuator /env exposed without authentication",
                    "exposes": "environment properties (may include secrets and connection strings)",
                    "remediation": "Restrict actuator endpoints (management.endpoints.web.exposure.include) "
                                   "and require authentication; never expose /env, /heapdump in production."},
                   {"path": "/actuator/heapdump", "finding_class": "actuator_heapdump_exposed",
                    "severity": "high", "cwe": "CWE-200",
                    "name": "Spring Boot Actuator /heapdump downloadable without authentication",
                    "exposes": "a full JVM heap dump (credentials, tokens, in-memory data)",
                    "remediation": "Disable /heapdump exposure and require authentication on actuator endpoints."}],
        "port": 8080,
    },
    "consul": {
        "name": "Consul",
        "fingerprint": [{"path": "/v1/agent/self", "markers": ["\"config\"", "\"member\""]}],
        "probes": [{"path": "/v1/catalog/services", "finding_class": "consul_catalog_exposed",
                    "severity": "high", "cwe": "CWE-306",
                    "name": "Consul service catalog readable without an ACL token",
                    "exposes": "the full service catalog (internal topology)",
                    "remediation": "Enable ACLs with a default-deny policy (acl.default_policy = deny) and require tokens."}],
        "port": 8500,
    },
    "etcd": {
        "name": "etcd",
        "fingerprint": [{"path": "/version", "markers": ["etcdserver", "etcdcluster"]}],
        "probes": [{"path": "/v2/keys/", "finding_class": "etcd_keys_exposed",
                    "severity": "high", "cwe": "CWE-306",
                    "name": "etcd key-value store readable without authentication",
                    "exposes": "cluster keys (often config and secrets)",
                    "remediation": "Enable client cert auth / RBAC and require TLS client certificates."}],
        "port": 2379,
    },
    "docker": {
        "name": "Docker Engine API",
        "fingerprint": [{"path": "/version", "markers": ["apiversion", "components"]}],
        "probes": [{"path": "/containers/json", "finding_class": "docker_api_exposed",
                    "severity": "critical", "cwe": "CWE-306",
                    "name": "Docker Engine API exposed without authentication",
                    "exposes": "container control (equivalent to host root access)",
                    "remediation": "Never expose the Docker socket/API over TCP without mTLS; bind to localhost only."}],
        "port": 2375,
    },
    "kubernetes": {
        "name": "Kubernetes API",
        "fingerprint": [{"path": "/version", "markers": ["gitversion", "\"major\"", "\"minor\""]}],
        "probes": [{"path": "/api", "finding_class": "kubernetes_anon_api",
                    "severity": "high", "cwe": "CWE-306",
                    "name": "Kubernetes API reachable anonymously",
                    "exposes": "API group discovery with anonymous access enabled",
                    "remediation": "Disable anonymous auth (--anonymous-auth=false) and enforce RBAC."}],
        "port": 6443,
    },
    "rabbitmq": {
        "name": "RabbitMQ Management",
        "fingerprint": [{"path": "/api/overview", "markers": ["rabbitmq_version", "management_version"]}],
        "probes": [{"path": "/api/overview", "finding_class": "rabbitmq_mgmt_exposed",
                    "severity": "medium", "cwe": "CWE-306",
                    "name": "RabbitMQ Management API readable without authentication",
                    "exposes": "broker overview, nodes and stats",
                    "remediation": "Require authentication on the management plugin; do not expose default guest access."}],
        "port": 15672,
    },
    "airflow": {
        "name": "Apache Airflow",
        "fingerprint": [{"path": "/api/v1/health", "markers": ["metadatabase", "scheduler"]}],
        "probes": [{"path": "/api/v1/dags", "finding_class": "airflow_dags_exposed",
                    "severity": "high", "cwe": "CWE-306",
                    "name": "Airflow DAGs API readable without authentication",
                    "exposes": "workflow definitions and schedules",
                    "remediation": "Set the API auth backend to require authentication (auth_backends) and disable anonymous access."}],
        "port": 8080,
    },
    "jenkins": {
        "name": "Jenkins",
        "fingerprint": [{"path": "/api/json", "markers": ["hudson.model.hudson"]}],
        "probes": [{"path": "/script", "finding_class": "jenkins_script_console",
                    "severity": "critical", "cwe": "CWE-306",
                    "name": "Jenkins Groovy script console reachable without authentication",
                    "exposes": "arbitrary Groovy execution on the controller (RCE)",
                    "remediation": "Enable security (matrix/role auth), require login, and restrict the /script console to admins."}],
        "port": 8080,
    },
}


# ── Fingerprint (puro) ─────────────────────────────────────────────────────────
def markers_match(body, markers):
    """True se TODOS os markers (case-insensitive) estão no corpo e o corpo não é HTML.

    Corpo HTML desqualifica — uma SPA catch-all devolve index.html 200 p/ qualquer
    path (mesma guarda anti-FP do js_chunks.is_js_payload)."""
    b = (body or "").lower()
    if "<html" in b:
        return False
    return bool(markers) and all(str(m).lower() in b for m in markers)


def is_service(status, body, markers):
    """O serviço está fingerprintado: HTTP 200 + markers presentes em corpo não-HTML."""
    return status == 200 and markers_match(body, markers)


# ── Classificador (puro) ───────────────────────────────────────────────────────
def classify_exposure(probe_status, probe_body, auth_status=None):
    """Veredito sobre o endpoint sensível acessado sem credencial.

    REJECTED   — 401/403 (protegido);
    CONFIRMED  — 200 sem auth (reforçado quando a 2ª sonda com token inválido dá 401/403);
    INCONCLUSIVE — qualquer outro status (404, host fora do ar, etc.).
    """
    if probe_status in (401, 403):
        return {"state": "REJECTED",
                "evidence": f"endpoint without auth -> HTTP {probe_status} (authentication required)"}
    if probe_status == 200:
        if auth_status in (401, 403):
            return {"state": "CONFIRMED",
                    "evidence": (f"without auth -> HTTP 200 (processed); "
                                 f"with invalid token -> HTTP {auth_status}")}
        return {"state": "CONFIRMED",
                "evidence": "endpoint without auth -> HTTP 200 (no authentication enforced)"}
    return {"state": "INCONCLUSIVE",
            "evidence": f"endpoint without auth -> HTTP {probe_status}"}

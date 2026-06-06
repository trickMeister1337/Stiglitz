import os, sys, json, subprocess
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
import service_versions as sv

LIB = os.path.join(os.path.dirname(__file__), "..", "lib", "service_versions.py")

# ─────────────────── dangerous_service (função pura) ───────────────────
def test_dangerous_service_known_ports():
    assert sv.dangerous_service(6379) == "Redis"
    assert sv.dangerous_service(27017) == "MongoDB"
    assert sv.dangerous_service(9200) == "Elasticsearch"
    assert sv.dangerous_service(2379) == "etcd"


def test_dangerous_service_benign_ports_are_none():
    assert sv.dangerous_service(80) is None
    assert sv.dangerous_service(443) is None
    assert sv.dangerous_service(22) is None


def test_dangerous_service_name_fallback_for_nonstandard_port():
    # Serviço sensível rodando em porta fora do padrão — detecta pelo banner.
    assert sv.dangerous_service(16379, "redis") == "Redis"
    assert sv.dangerous_service(12345, "mongodb") == "MongoDB"


# ─────────────────── emissão do finding via main (subprocess) ───────────────────
NMAP_XML_REDIS = """<?xml version="1.0"?>
<nmaprun>
 <host>
  <address addr="203.0.113.7" addrtype="ipv4"/>
  <ports>
   <port protocol="tcp" portid="6379">
    <state state="open"/>
    <service name="redis" product="Redis key-value store" version="6.0.5"/>
   </port>
  </ports>
 </host>
</nmaprun>
"""


def _run(tmp_path):
    raw = tmp_path / "raw"
    raw.mkdir()
    (raw / "nmap.xml").write_text(NMAP_XML_REDIS)
    subprocess.run([sys.executable, LIB, str(tmp_path), "http://t"],
                   check=True, capture_output=True)
    return json.load(open(raw / "service_findings.json"))


def test_main_emits_exposed_service_finding_for_redis(tmp_path):
    findings = _run(tmp_path)
    exposed = [f for f in findings if f.get("type") == "exposed_service"]
    assert len(exposed) == 1
    f = exposed[0]
    assert f["severity"] in ("high", "critical")
    assert "Redis" in f["name"]
    assert "6379" in f["url"]


def test_main_no_exposed_finding_for_https(tmp_path):
    raw = tmp_path / "raw"
    raw.mkdir()
    (raw / "nmap.xml").write_text(NMAP_XML_REDIS.replace(
        'portid="6379"', 'portid="443"').replace(
        'name="redis" product="Redis key-value store"',
        'name="https" product="nginx"'))
    subprocess.run([sys.executable, LIB, str(tmp_path), "http://t"],
                   check=True, capture_output=True)
    findings = json.load(open(raw / "service_findings.json"))
    assert [f for f in findings if f.get("type") == "exposed_service"] == []

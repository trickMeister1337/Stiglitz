import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
import pci_verdicts as pv

TARGETS = {"web": ["https://api.example.com"], "infra": [], "checkout": [], "labels": {}}

def test_tags_tls_finding_in_cde():
    f = {"source": "testssl.sh", "name": "TLS 1.0 (obsoleto)",
         "url": "https://api.example.com", "severity": "high"}
    pv.tag_finding(f, TARGETS)
    assert f.get("pci_req") == "4.2.1"

def test_tags_service_finding_in_cde():
    f = {"source": "Service Version", "name": "ftp exposto",
         "url": "api.example.com:21/tcp", "severity": "high"}
    pv.tag_finding(f, TARGETS)
    assert f.get("pci_req") == "2.2.5"

def test_no_tag_outside_cde():
    f = {"source": "testssl.sh", "name": "TLS 1.0", "url": "https://other.com", "severity": "high"}
    pv.tag_finding(f, TARGETS)
    assert "pci_req" not in f

def test_tag_all_does_not_overwrite_existing():
    f = {"source": "testssl.sh", "name": "TLS 1.0",
         "url": "https://api.example.com", "pci_req": "CUSTOM"}
    pv.tag_all([f], TARGETS)
    assert f["pci_req"] == "CUSTOM"

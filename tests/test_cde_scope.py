import os, sys, tempfile, textwrap
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
import cde_scope

SAMPLE = textwrap.dedent("""
    # comentário
    web    https://checkout.example.com   checkout-app   checkout=true
    web    https://api.example.com
    infra  10.0.0.5                       db-node
    both   https://gateway.example.com
""")

def _write(tmp_path, content):
    p = os.path.join(tmp_path, "cde_targets.txt")
    with open(p, "w") as f:
        f.write(content)
    return p

def test_parse_types_and_checkout(tmp_path):
    t = cde_scope.load_targets(_write(tmp_path, SAMPLE))
    assert "https://checkout.example.com" in t["web"]
    assert "https://gateway.example.com" in t["web"]      # both → web
    assert "https://gateway.example.com" in t["infra"]    # both → infra
    assert "10.0.0.5" in t["infra"]
    assert "https://checkout.example.com" in t["checkout"]
    assert "https://api.example.com" not in t["checkout"]

def test_in_cde_scope_by_host(tmp_path):
    t = cde_scope.load_targets(_write(tmp_path, SAMPLE))
    assert cde_scope.in_cde_scope("https://api.example.com/v1/users", t)
    assert cde_scope.in_cde_scope("https://checkout.example.com/pay", t)
    assert not cde_scope.in_cde_scope("https://www.other.com/", t)
    assert cde_scope.in_cde_scope("https://API.EXAMPLE.COM/path", t)

def test_is_checkout(tmp_path):
    t = cde_scope.load_targets(_write(tmp_path, SAMPLE))
    assert cde_scope.is_checkout("https://checkout.example.com/step1", t)
    assert not cde_scope.is_checkout("https://api.example.com/x", t)

def test_cde_class(tmp_path):
    t = cde_scope.load_targets(_write(tmp_path, SAMPLE))
    assert cde_scope.cde_class("https://api.example.com/x", t) == "cde"
    assert cde_scope.cde_class("https://www.other.com/", t) is None

def test_missing_file_returns_empty():
    t = cde_scope.load_targets("/nonexistent/cde_targets.txt")
    assert t["web"] == [] and t["infra"] == [] and t["checkout"] == []
    assert not cde_scope.in_cde_scope("https://anything.example.com", t)

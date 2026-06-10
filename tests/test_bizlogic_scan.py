import os, sys, json
sys.path[:0] = [os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "lib")]
import bizlogic_scan as BS
import jwt_audit
import bizlogic


def _jwt(payload):
    import base64
    def b64(d): return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
    return f"{b64({'alg':'none'})}.{b64(payload)}.sig"


def test_account_id_from_sub_claim():
    tok = _jwt({"sub": "user-42"})
    assert BS._account_id(tok, fallback="X") == "user-42"


def test_account_id_prefers_sub_then_uid_then_user_id():
    assert BS._account_id(_jwt({"uid": "u1"}), fallback="X") == "u1"
    assert BS._account_id(_jwt({"user_id": "u2"}), fallback="X") == "u2"
    assert BS._account_id(_jwt({"sub": "s", "uid": "u"}), fallback="X") == "s"
    assert BS._account_id(_jwt({"uid": "u", "user_id": "ui"}), fallback="X") == "u"


def test_account_id_fallback_when_opaque_token():
    assert BS._account_id("not-a-jwt", fallback="A") == "A"


def _zap_dump(entries):
    # entries: list[(method, url, status)]
    msgs = [{"requestHeader": f"{m} {u} HTTP/1.1\r\nHost: x\r\n\r\n",
             "responseHeader": f"HTTP/1.1 {s} OK\r\n\r\n", "responseBody": "{}"}
            for (m, u, s) in entries]
    return json.dumps({"messages": msgs})


def test_derive_endpoints_picks_idlike_get_2xx():
    dump = _zap_dump([
        ("GET", "https://t.com/api/orders/12345", 200),   # id-like → entra
        ("GET", "https://t.com/api/health", 200),          # sem id → fora
        ("POST", "https://t.com/api/orders/1", 200),       # não-GET → fora
        ("GET", "https://t.com/admin/users/7", 200),       # privilegiado → privesc
    ])
    eps = BS._derive_endpoints(dump, base_url="https://t.com", priv_prefixes=("/admin",))
    paths = {e["path"]: e for e in eps}
    assert "/api/orders/12345" in paths
    assert paths["/api/orders/12345"]["tests"] == ["idor_read"]
    assert paths["/api/orders/12345"]["object_of"] == "A"
    assert paths["/api/orders/12345"]["method"] == "GET"
    assert "/api/health" not in paths
    assert "privesc" in paths["/admin/users/7"]["tests"]


def test_derive_endpoints_empty_when_no_candidates():
    dump = _zap_dump([("GET", "https://t.com/api/health", 200)])
    assert BS._derive_endpoints(dump, "https://t.com", ("/admin",)) == []


def test_build_config_full():
    dump = _zap_dump([("GET", "https://t.com/api/orders/12345", 200)])
    cfg = BS.build_config_from_zap(dump, _jwt({"sub": "a1"}), _jwt({"sub": "b1"}),
                                   base_url="https://t.com")
    assert cfg["base_url"] == "https://t.com"
    assert cfg["accounts"]["A"]["id"] == "a1"
    assert cfg["accounts"]["A"]["auth"] == {"type": "bearer", "token": _jwt({"sub": "a1"})}
    assert cfg["accounts"]["B"]["id"] == "b1"
    assert cfg["endpoints"][0]["path"] == "/api/orders/12345"
    # Config válida segundo o próprio bizlogic
    bizlogic.validate_config(cfg)


def test_build_config_none_when_no_endpoints():
    dump = _zap_dump([("GET", "https://t.com/api/health", 200)])
    assert BS.build_config_from_zap(dump, _jwt({"sub": "a"}), _jwt({"sub": "b"}),
                                    "https://t.com") is None


def test_merge_manual_overrides_and_adds():
    auto = {"base_url": "https://t.com",
            "accounts": {"A": {"id": "a"}, "B": {"id": "b"}},
            "endpoints": [{"name": "auto GET /x", "method": "GET", "path": "/x",
                           "object_of": "A", "tests": ["idor_read"]}]}
    manual = {"sentinel": "STIG_SENTINEL",
              "endpoints": [
                  {"name": "auto GET /x", "method": "GET", "path": "/x",
                   "object_of": "A", "tests": ["idor_read", "privesc"]},   # override por name
                  {"name": "transfer", "method": "POST", "path": "/transfer",
                   "object_of": "A", "tests": ["amount_tampering"],
                   "body": "{\"amount\":100}"},                            # novo
              ]}
    merged = BS.merge_manual_config(auto, manual)
    by_name = {e["name"]: e for e in merged["endpoints"]}
    assert by_name["auto GET /x"]["tests"] == ["idor_read", "privesc"]  # manual venceu
    assert "transfer" in by_name
    assert merged["sentinel"] == "STIG_SENTINEL"   # chaves topo do manual propagam


def test_merge_manual_none_returns_auto():
    auto = {"base_url": "x", "accounts": {}, "endpoints": []}
    assert BS.merge_manual_config(auto, None) is auto


def test_to_report_findings_maps_schema():
    biz = [{"name": "IDOR read: orders", "vuln_class": "idor_read_pii",
            "url": "https://t.com/api/orders/123", "method": "GET",
            "severity": "high", "confirmed": True, "tool": "bizlogic",
            "evidence": {"cross_account": "B"}}]
    out = BS.to_report_findings(biz)
    f = out[0]
    assert f["type"] == "idor_read_pii"
    assert f["severity"] == "high"
    assert f["tool"] == "bizlogic"
    assert f["url"] == "https://t.com/api/orders/123"
    assert f["confirmed"] is True
    assert "fingerprint" in f and f["fingerprint"]


def test_to_report_findings_dedup_key_present():
    biz = [{"name": "x", "vuln_class": "idor_read_pii",
            "url": "https://t.com/api/orders/123", "method": "GET",
            "severity": "high", "confirmed": True, "tool": "bizlogic", "evidence": {}}]
    assert BS.to_report_findings(biz)[0]["_dedup_key"] == ("t.com", "/api/orders/123", "idor_read_pii")


def test_cli_writes_outputs(tmp_path):
    outdir = str(tmp_path)
    os.makedirs(os.path.join(outdir, "raw"), exist_ok=True)
    dump = _zap_dump([("GET", "https://t.com/api/orders/12345", 200)])
    with open(os.path.join(outdir, "raw", "zap_messages_a.json"), "w") as f:
        f.write(dump)
    # idor_read é read-only e faz GET real; --base-url aponta p/ porta local recusada
    # (ConnectionRefused instantâneo) → run() degrada p/ lista vazia SEM rede lenta.
    # O teste valida a orquestração e a gravação dos arquivos, não o resultado da vuln.
    rc = BS.main(["--outdir", outdir, "--token-a", _jwt({"sub": "a"}),
                  "--token-b", _jwt({"sub": "b"}), "--base-url", "http://127.0.0.1:1",
                  "--profile", "production"])
    assert rc == 0
    assert os.path.exists(os.path.join(outdir, "raw", "bizlogic.json"))
    assert os.path.exists(os.path.join(outdir, "raw", "bizlogic_findings.json"))
    # bizlogic_findings.json é uma lista JSON válida
    with open(os.path.join(outdir, "raw", "bizlogic_findings.json")) as f:
        assert isinstance(json.load(f), list)


def test_cli_skips_gracefully_without_history(tmp_path):
    outdir = str(tmp_path)
    os.makedirs(os.path.join(outdir, "raw"), exist_ok=True)
    rc = BS.main(["--outdir", outdir, "--token-a", _jwt({"sub": "a"}),
                  "--token-b", _jwt({"sub": "b"}), "--base-url", "https://t.com",
                  "--profile", "production"])
    assert rc == 0   # sem histórico e sem config → no-op gracioso

import os, sys, json, threading, importlib
from http.server import BaseHTTPRequestHandler, HTTPServer

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ROOT)

CAPTURED = {}

class _H(BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        CAPTURED["path"] = self.path
        CAPTURED["auth"] = self.headers.get("Authorization")
        CAPTURED["body_has_sarif"] = b"findings.sarif" in self.rfile.read(n)
        self.send_response(201)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"new_findings": [1, 2]}).encode())
    def log_message(self, *a):
        pass

def test_run_trackers_posts_to_live_defectdojo(monkeypatch, tmp_path):
    srv = HTTPServer(("127.0.0.1", 0), _H)
    threading.Thread(target=srv.handle_request, daemon=True).start()
    port = srv.server_address[1]
    (tmp_path / "findings.json").write_text(json.dumps({"findings": []}))
    (tmp_path / "raw").mkdir()
    (tmp_path / "raw" / "state_summary.json").write_text("{}")
    (tmp_path / "findings.sarif").write_text('{"runs":[]}')
    monkeypatch.setenv("DEFECTDOJO_URL", f"http://127.0.0.1:{port}")
    monkeypatch.setenv("DEFECTDOJO_TOKEN", "tok")
    track = importlib.reload(importlib.import_module("stiglitz_track"))
    results = track.run_trackers(str(tmp_path))
    assert CAPTURED["path"] == "/api/v2/reimport-scan/"
    assert CAPTURED["auth"] == "Token tok"
    assert CAPTURED["body_has_sarif"] is True
    assert results[0]["created"] == 2

def test_run_trackers_noop_without_env(monkeypatch, tmp_path):
    monkeypatch.delenv("DEFECTDOJO_URL", raising=False)
    monkeypatch.delenv("DEFECTDOJO_TOKEN", raising=False)
    (tmp_path / "findings.json").write_text(json.dumps({"findings": []}))
    track = importlib.reload(importlib.import_module("stiglitz_track"))
    assert track.run_trackers(str(tmp_path)) == []

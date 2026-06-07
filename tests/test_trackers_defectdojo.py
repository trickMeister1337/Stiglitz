import os, sys, json, importlib
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))

def _fresh_dd():
    import trackers.defectdojo as dd
    return importlib.reload(dd)

class _Resp:
    def __init__(self, status=201, payload=None):
        self.status_code = status
        self._p = payload or {}
        self.text = json.dumps(self._p)
    def json(self):
        return self._p

class _Session:
    """Captura o request e devolve resposta canned. Sem rede."""
    def __init__(self, resp):
        self.resp = resp
        self.calls = []
    def post(self, url, **kw):
        self.calls.append((url, kw))
        return self.resp

def test_enabled_requires_url_and_token(monkeypatch):
    monkeypatch.delenv("DEFECTDOJO_URL", raising=False)
    monkeypatch.delenv("DEFECTDOJO_TOKEN", raising=False)
    dd = _fresh_dd()
    assert dd.DefectDojo().enabled() is False
    monkeypatch.setenv("DEFECTDOJO_URL", "https://dd.local")
    monkeypatch.setenv("DEFECTDOJO_TOKEN", "tok")
    assert _fresh_dd().DefectDojo().enabled() is True

def test_sync_posts_reimport_with_sarif(monkeypatch, tmp_path):
    monkeypatch.setenv("DEFECTDOJO_URL", "https://dd.local")
    monkeypatch.setenv("DEFECTDOJO_TOKEN", "tok")
    monkeypatch.setenv("DEFECTDOJO_PRODUCT", "Acme")
    dd = _fresh_dd()
    sarif = tmp_path / "findings.sarif"
    sarif.write_text('{"runs":[]}')
    sess = _Session(_Resp(201, {"new_findings": [1, 2]}))
    res = dd.DefectDojo(session=sess).sync(str(tmp_path), findings=[], state_summary={})
    url, kw = sess.calls[0]
    assert url == "https://dd.local/api/v2/reimport-scan/"
    assert kw["headers"]["Authorization"] == "Token tok"
    assert kw["data"]["scan_type"] == "SARIF"
    assert kw["data"]["product_name"] == "Acme"
    assert kw["data"]["auto_create_context"] == "true"
    assert "file" in kw["files"]
    assert res["errors"] == []
    assert res["created"] == 2

def test_sync_records_transport_error(monkeypatch, tmp_path):
    monkeypatch.setenv("DEFECTDOJO_URL", "https://dd.local")
    monkeypatch.setenv("DEFECTDOJO_TOKEN", "tok")
    dd = _fresh_dd()
    (tmp_path / "findings.sarif").write_text("{}")
    class _Boom:
        def post(self, *a, **k):
            raise OSError("conn refused")
    res = dd.DefectDojo(session=_Boom()).sync(str(tmp_path), findings=[], state_summary={})
    assert res["errors"] and "conn refused" in res["errors"][0]

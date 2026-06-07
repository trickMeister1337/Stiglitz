# tests/test_takeover.py
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
import takeover as T


def test_is_external_cname_distinguishes_third_party_from_apex():
    b = "target.com"
    assert T.is_external_cname("x.target.com.s3.amazonaws.com", b) is True
    assert T.is_external_cname("myorg.github.io", b) is True
    assert T.is_external_cname("cdn.target.com", b) is False   # interno
    assert T.is_external_cname("target.com", b) is False       # apex
    assert T.is_external_cname("TARGET.COM.", b) is False      # apex (case/dot)
    assert T.is_external_cname("", b) is False
    assert T.is_external_cname("anything.io", "") is False      # sem apex


def _recs():
    # forma do dnsx -cname -json: host + cname (lista)
    return [
        {"host": "ok.target.com", "cname": ["myorg.github.io"]},
        {"host": "cdn.target.com", "cname": ["edge.target.com"]},   # interno
        {"host": "novo.target.com", "cname": ["d1.cloudfront.net", "x.target.com"]},
        {"host": "semcname.target.com"},                            # sem cname
        {"host": "strform.target.com", "cname": "app.herokuapp.com"},  # cname string
    ]


def test_select_external_keeps_only_third_party_first_match():
    out = T.select_external(_recs(), "target.com")
    hosts = [h for h, _c in out]
    assert "ok.target.com" in hosts
    assert "novo.target.com" in hosts
    assert "strform.target.com" in hosts
    assert "cdn.target.com" not in hosts
    assert "semcname.target.com" not in hosts
    d = dict(out)
    assert d["novo.target.com"] == "d1.cloudfront.net"   # primeiro externo


def test_cname_map_picks_first_cname_normalized():
    m = T.cname_map(_recs())
    assert m["ok.target.com"] == "myorg.github.io"
    assert m["strform.target.com"] == "app.herokuapp.com"
    assert "semcname.target.com" not in m


def test_parse_nuclei_extracts_confirmed_takeovers():
    jsonl = "\n".join([
        '{"template-id":"github-takeover","host":"https://ok.target.com",'
        '"matched-at":"https://ok.target.com","info":{"name":"GitHub Takeover","severity":"high"}}',
        '   ',  # linha em branco ignorada
        'not-json-line',  # ignorada
        '{"template-id":"heroku-takeover","host":"app.target.com:443",'
        '"info":{"severity":"medium"}}',
        '{"info":{"name":"sem host"}}',  # sem host → ignorada
    ])
    res = T.parse_nuclei(jsonl)
    assert len(res) == 2
    a = next(r for r in res if r["host"] == "ok.target.com")
    assert a["service"] == "github-takeover"
    assert a["severity"] == "high"
    assert a["matched_at"] == "https://ok.target.com"
    b = next(r for r in res if r["host"] == "app.target.com")  # porta removida
    assert b["severity"] == "medium"

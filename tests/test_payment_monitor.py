import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
import payment_page_monitor as ppm

HTML = '''
<html><head>
<script src="https://checkout.example.com/app.js" integrity="sha384-abc"></script>
<script src="https://cdn.thirdparty.example.com/track.js"></script>
</head></html>
'''

def test_extract_scripts_classifies_and_flags_sri():
    items = ppm.extract_scripts(HTML, "https://checkout.example.com/pay")
    by_src = {i["src"]: i for i in items}
    assert by_src["https://checkout.example.com/app.js"]["third_party"] is False
    assert by_src["https://checkout.example.com/app.js"]["has_sri"] is True
    tp = by_src["https://cdn.thirdparty.example.com/track.js"]
    assert tp["third_party"] is True
    assert tp["has_sri"] is False

def test_diff_detects_new_script():
    prev = [{"src": "https://checkout.example.com/app.js", "sha384": "h1"}]
    curr = [{"src": "https://checkout.example.com/app.js", "sha384": "h1"},
            {"src": "https://cdn.evil.example.com/skim.js", "sha384": "h2"}]
    new, changed = ppm.diff_scripts(prev, curr)
    assert "https://cdn.evil.example.com/skim.js" in new
    assert changed == []

def test_extract_scripts_absolutizes_root_relative():
    html = '<script src="/cdn/app.js"></script>'
    items = ppm.extract_scripts(html, "https://checkout.example.com/checkout/pay")
    assert items[0]["src"] == "https://checkout.example.com/cdn/app.js"

def test_diff_detects_changed_script():
    prev = [{"src": "https://checkout.example.com/app.js", "sha384": "h1"}]
    curr = [{"src": "https://checkout.example.com/app.js", "sha384": "h2"}]
    new, changed = ppm.diff_scripts(prev, curr)
    assert new == []
    assert "https://checkout.example.com/app.js" in changed

def test_extract_scripts_ignores_data_src_and_data_integrity():
    html = ('<script data-src="https://cdn.lazy.example.com/x.js"></script>'
            '<script src="https://cdn.t.example.com/y.js" data-integrity="foo"></script>')
    items = ppm.extract_scripts(html, "https://checkout.example.com/pay")
    srcs = [i["src"] for i in items]
    assert "https://cdn.lazy.example.com/x.js" not in srcs
    yj = [i for i in items if i["src"] == "https://cdn.t.example.com/y.js"][0]
    assert yj["has_sri"] is False

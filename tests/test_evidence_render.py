import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
import evidence_render as E


def test_small_content_stays_inline():
    plan = E.plan_evidence("short body", max_inline=6000)
    assert plan["mode"] == "inline"
    assert plan["content"] == "short body"


def test_large_content_goes_sidecar_with_snippet():
    body = "x" * 50000
    plan = E.plan_evidence(body, max_inline=6000, snippet_chars=3000)
    assert plan["mode"] == "sidecar"
    assert plan["snippet"] == body[:3000]
    assert plan["content"] == body          # conteúdo íntegro preservado p/ o arquivo lateral
    assert plan["kb"] == round(50000 / 1024)
    assert plan["filename"].startswith("ev_") and plan["filename"].endswith(".txt")


def test_threshold_boundary_is_inclusive():
    body = "a" * 6000
    assert E.plan_evidence(body, max_inline=6000)["mode"] == "inline"
    assert E.plan_evidence(body + "a", max_inline=6000)["mode"] == "sidecar"


def test_filename_is_content_addressed_and_stable():
    a = "y" * 20000
    b = "z" * 20000
    assert E.plan_evidence(a)["filename"] == E.plan_evidence(a)["filename"]   # determinístico
    assert E.plan_evidence(a)["filename"] != E.plan_evidence(b)["filename"]   # difere por conteúdo


def test_kb_uses_utf8_byte_length():
    # caractere multibyte: 'é' = 2 bytes em UTF-8 → kb conta bytes, não code points
    body = "é" * 10000          # 10000 chars, 20000 bytes
    plan = E.plan_evidence(body, max_inline=5000)
    assert plan["kb"] == round(20000 / 1024)


def test_snippet_kb_reported_for_sidecar():
    body = "w" * 40000
    plan = E.plan_evidence(body, snippet_chars=3000)
    assert plan["snippet_kb"] == round(3000 / 1024)

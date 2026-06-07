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

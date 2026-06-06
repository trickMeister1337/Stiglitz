import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
import risk_context as R


def test_reachability_tier_priority():
    assert R.reachability_tier(behind_waf=False, internal=False) == "internet"
    assert R.reachability_tier(behind_waf=True, internal=False) == "waf"
    assert R.reachability_tier(behind_waf=True, internal=True) == "internal"  # internal domina


def test_reachability_multiplier_order():
    assert (R.reachability_multiplier("internet")
            > R.reachability_multiplier("waf")
            > R.reachability_multiplier("internal"))


def test_exploit_label():
    assert "Metasploit" in R.exploit_label(exploitdb=False, metasploit=True)
    assert "ExploitDB" in R.exploit_label(exploitdb=True, metasploit=False)
    assert R.exploit_label(exploitdb=False, metasploit=False) == ""


def test_exploit_boost_order():
    assert (R.exploit_boost(False, True)
            > R.exploit_boost(True, False)
            > R.exploit_boost(False, False) == 1.0)


def test_risk_priority_scales_and_caps():
    assert R.risk_priority(9.0, 1.0, 1.2) == 10.0       # capado em 10
    assert R.risk_priority(8.0, 0.6, 1.0) == 4.8        # internal de-prioriza
    assert R.risk_priority(0.0, 1.0, 1.5) == 0.0


def test_annotate_sets_reachability_exploit_and_priority():
    f = {"cvss_environmental": 8.0, "asset_class": "internal"}
    R.annotate(f, behind_waf=False, exploitdb=False, metasploit=True)
    assert f["reachability"]["tier"] == "internal"
    assert f["exploit_intel"]["metasploit"] is True
    assert f["exploit_intel"]["available"] is True
    # 8.0 * mult(internal) * boost(metasploit), capado
    assert f["risk_priority"] == R.risk_priority(8.0, R.reachability_multiplier("internal"),
                                                 R.exploit_boost(False, True))


def test_annotate_internet_exposed_with_exploit_outranks_internal():
    a = {"cvss_environmental": 7.0}                      # internet + exploit público
    b = {"cvss_environmental": 7.0, "asset_class": "internal"}  # interno, sem exploit
    R.annotate(a, behind_waf=False, exploitdb=True, metasploit=False)
    R.annotate(b, behind_waf=False, exploitdb=False, metasploit=False)
    assert a["risk_priority"] > b["risk_priority"]

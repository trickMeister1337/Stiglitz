#!/usr/bin/env python3
"""Testes do motor de criticidade (cvss, catalog, classifier, criticality)."""
import os
import sys
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
sys.path[:0] = [_ROOT, os.path.join(_ROOT, "lib")]


class TestCVSSParse(unittest.TestCase):
    def test_parse_vector_extracts_metrics(self):
        import cvss as c
        m = c.parse_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        self.assertEqual(m["AV"], "N")
        self.assertEqual(m["S"], "U")
        self.assertEqual(m["C"], "H")

    def test_parse_vector_rejects_bad_prefix(self):
        import cvss as c
        with self.assertRaises(ValueError):
            c.parse_vector("AV:N/AC:L")


class TestCVSSBase(unittest.TestCase):
    def test_roundup_examples(self):
        import cvss as c
        self.assertEqual(c.roundup(4.0), 4.0)
        self.assertEqual(c.roundup(4.02), 4.1)
        self.assertEqual(c.roundup(6.000001), 6.1)

    def test_base_critical_rce(self):
        import cvss as c
        # Log4Shell-like: AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H → 10.0
        m = c.parse_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")
        self.assertEqual(c.base_score(m), 10.0)

    def test_base_scope_unchanged(self):
        import cvss as c
        # AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H → 9.8
        m = c.parse_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        self.assertEqual(c.base_score(m), 9.8)

    def test_base_zero_when_no_impact(self):
        import cvss as c
        m = c.parse_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")
        self.assertEqual(c.base_score(m), 0.0)


class TestCVSSTemporal(unittest.TestCase):
    def test_temporal_confirmed_equals_base(self):
        import cvss as c
        # E:H/RC:C/RL:U → multiplicadores 1.0 → temporal == base
        m = c.parse_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:H/RC:C")
        self.assertEqual(c.temporal_score(m), 9.8)

    def test_temporal_potential_lower_than_base(self):
        import cvss as c
        m = c.parse_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:P/RC:R")
        self.assertLess(c.temporal_score(m), 9.8)


class TestCVSSEnvironmental(unittest.TestCase):
    def test_env_requirements_raise_score(self):
        import cvss as c
        low  = c.parse_vector("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N/CR:L")
        high = c.parse_vector("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N/CR:H")
        self.assertGreater(c.environmental_score(high), c.environmental_score(low))

    def test_env_defaults_to_base_when_no_modifiers(self):
        import cvss as c
        m = c.parse_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        self.assertEqual(c.environmental_score(m), 9.8)

    def test_env_zero_when_no_impact(self):
        import cvss as c
        m = c.parse_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/CR:H")
        self.assertEqual(c.environmental_score(m), 0.0)


class TestCVSSBandAndSerialize(unittest.TestCase):
    def test_band_mapping(self):
        import cvss as c
        self.assertEqual(c.band(0.0), "info")
        self.assertEqual(c.band(3.9), "low")
        self.assertEqual(c.band(4.0), "medium")
        self.assertEqual(c.band(7.0), "high")
        self.assertEqual(c.band(9.0), "critical")

    def test_to_vector_roundtrip(self):
        import cvss as c
        s = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:H/RC:C/CR:H"
        self.assertEqual(c.to_vector(c.parse_vector(s)), s)


class TestCVSSAgainstReference(unittest.TestCase):
    """Valida a calculadora in-house contra a biblioteca `cvss` (referência)."""

    VECTORS = [
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:N",
        "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N/E:H/RC:C",
        "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N/E:P/RC:R",
        "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N/CR:H/IR:H",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:H/RC:C/CR:H/IR:H/AR:L",
        "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N/MAV:A/CR:L",
    ]

    def _import_ref_cvss3(self):
        """Importa CVSS3 da biblioteca de referência (instalada via pip), contornando
        o sombreamento causado por lib/cvss.py no sys.path."""
        import importlib
        import importlib.util
        orig = sys.path[:]
        # Remove temporariamente os diretórios que contêm nosso lib/cvss.py
        sys.path = [p for p in sys.path if not (
            p.endswith("/lib") or p.endswith("/criticality-engine")
        )]
        try:
            if "cvss" in sys.modules:
                del sys.modules["cvss"]
            import cvss as _ref_pkg
            CVSS3 = _ref_pkg.CVSS3
        finally:
            sys.path = orig
            # Re-register our cvss module as 'cvss' so subsequent imports work
            if "cvss" in sys.modules:
                del sys.modules["cvss"]
        return CVSS3

    def test_base_temporal_environmental_match_reference(self):
        CVSS3 = self._import_ref_cvss3()  # biblioteca de referência  # noqa: N806
        import cvss as c
        for v in self.VECTORS:
            ref = CVSS3(v)
            ref_base, ref_temp, ref_env = ref.scores()  # (base, temporal, environmental)
            m = c.parse_vector(v)
            self.assertEqual(c.base_score(m), ref_base, f"BASE divergiu: {v}")
            self.assertEqual(c.temporal_score(m), ref_temp, f"TEMPORAL divergiu: {v}")
            self.assertEqual(c.environmental_score(m), ref_env, f"ENV divergiu: {v}")


class TestVulnCatalog(unittest.TestCase):
    def test_lookup_known_class(self):
        import vuln_catalog as vc
        e = vc.lookup("idor_read_pii")
        self.assertEqual(e["cwe"], "CWE-639")
        self.assertIn("C:H", e["vector"])

    def test_lookup_by_cwe(self):
        import vuln_catalog as vc
        e = vc.lookup("CWE-352")
        self.assertIsNotNone(e)
        self.assertIn("csrf", e["title"].lower())

    def test_lookup_unknown_returns_none(self):
        import vuln_catalog as vc
        self.assertIsNone(vc.lookup("classe_inexistente"))


class TestAssetClassifier(unittest.TestCase):
    def test_infer_cde(self):
        import asset_classifier as ac
        self.assertEqual(ac.classify_asset("app-tokenize.dev2.example.com", "/"), "cde")
        self.assertEqual(ac.classify_asset("3ds.example.com", "/"), "cde")

    def test_infer_funds(self):
        import asset_classifier as ac
        self.assertEqual(ac.classify_asset("app-gateway-cielo.hml2.example.com", "/"), "funds")
        self.assertEqual(ac.classify_asset("checkout.example.com", "/"), "funds")

    def test_infer_internal_and_public(self):
        import asset_classifier as ac
        self.assertEqual(ac.classify_asset("app-hml-kibana-v2.hml2.example.com", "/"), "internal")
        self.assertEqual(ac.classify_asset("www.example.com", "/"), "public")

    def test_default_when_no_match(self):
        import asset_classifier as ac
        self.assertEqual(ac.classify_asset("acme-widget.example.com", "/"), "default")

    def test_override_wins(self):
        import asset_classifier as ac
        ov = [{"match": "checkout.example.com", "data_class": "cde"}]
        self.assertEqual(ac.classify_asset("checkout.example.com", "/", ov), "cde")

    def test_requirements_for(self):
        import asset_classifier as ac
        self.assertEqual(ac.requirements_for("cde"), {"CR": "H", "IR": "H", "AR": "M"})
        self.assertEqual(ac.requirements_for("public"), {"CR": "L", "IR": "L", "AR": "L"})
        self.assertEqual(ac.requirements_for("default"), {"CR": "M", "IR": "M", "AR": "M"})


class TestScoreFinding(unittest.TestCase):
    def test_cve_finding_uses_nvd_vector(self):
        import criticality as cr
        # NVD 9.8 puramente teórico (confirmed=False, in_kev=False, epss=0.0)
        # → E:P/RC:R reduz para "high" (não "critical")
        f = {"name": "RCE", "severity": "critical",
             "cvss_vector_nvd": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
        out = cr.score_finding(f, asset_class="default", confirmed=False,
                               in_kev=False, epss=0.0)
        self.assertEqual(out["score_source"], "nvd")
        # Teórico: E:P/RC:R → env 8.9 → "high"
        self.assertEqual(out["severity"], "high")

    def test_cve_nvd98_in_kev_is_critical(self):
        import criticality as cr
        # NVD 9.8 + in_kev=True (não confirmado por nós) → E:H/RC:C → "critical"
        f = {"name": "RCE", "severity": "critical",
             "cvss_vector_nvd": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
        out = cr.score_finding(f, asset_class="default", confirmed=False,
                               in_kev=True, epss=0.0)
        self.assertEqual(out["score_source"], "nvd")
        self.assertEqual(out["severity"], "critical")

    def test_cve_nvd98_epss_high_is_critical(self):
        import criticality as cr
        # NVD 9.8 + epss=0.6 (não confirmado) → E:H/RC:C → "critical"
        f = {"name": "RCE", "severity": "critical",
             "cvss_vector_nvd": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
        out = cr.score_finding(f, asset_class="default", confirmed=False,
                               in_kev=False, epss=0.6)
        self.assertEqual(out["score_source"], "nvd")
        self.assertEqual(out["severity"], "critical")

    def test_catalog_finding_without_cve(self):
        import criticality as cr
        f = {"name": "IDOR", "severity": "medium", "vuln_class": "idor_read_pii"}
        out = cr.score_finding(f, asset_class="cde", confirmed=True)
        self.assertEqual(out["score_source"], "catalog")
        # CDE (CR:H) + confirmado deve elevar acima do base puro
        self.assertGreater(out["cvss_environmental"], out["cvss_base"])

    def test_estimated_when_no_cve_no_class(self):
        import criticality as cr
        f = {"name": "Algo", "severity": "high"}
        out = cr.score_finding(f, asset_class="default", confirmed=False)
        self.assertEqual(out["score_source"], "estimated")
        self.assertEqual(out["severity"], "medium")

    def test_confirmed_raises_score(self):
        import criticality as cr
        f = {"name": "IDOR", "severity": "medium", "vuln_class": "idor_write"}
        pot = cr.score_finding(f, "funds", confirmed=False)
        con = cr.score_finding(f, "funds", confirmed=True)
        self.assertGreater(con["cvss_environmental"], pot["cvss_environmental"])

    def test_severity_tool_preserved(self):
        import criticality as cr
        f = {"name": "x", "severity": "low", "vuln_class": "ssrf"}
        out = cr.score_finding(f, "cde", confirmed=True)
        self.assertEqual(out["severity_tool"], "low")

    def test_rl_u_always_in_vector(self):
        import criticality as cr
        # RL:U deve estar em todos os vetores, independente do caso
        f = {"name": "Test", "severity": "medium",
             "cvss_vector_nvd": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
        for kwargs in [
            {"confirmed": False, "in_kev": False, "epss": 0.0},
            {"confirmed": True,  "in_kev": False, "epss": 0.0},
            {"confirmed": False, "in_kev": True,  "epss": 0.0},
            {"confirmed": False, "in_kev": False, "epss": 0.3},
            {"confirmed": False, "in_kev": False, "epss": 0.6},
        ]:
            out = cr.score_finding(f, asset_class="default", **kwargs)
            self.assertIn("RL:U", out["cvss_vector"],
                          f"RL:U ausente no vetor para kwargs={kwargs}")

    def test_internal_asset_mav_a_reduces_score(self):
        import criticality as cr
        # NVD base 9.8, asset_class="internal", não confirmado → env "high" (MAV:A reduz)
        f = {"name": "RCE", "severity": "critical",
             "cvss_vector_nvd": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
        out = cr.score_finding(f, asset_class="internal", confirmed=False,
                               in_kev=False, epss=0.0)
        self.assertEqual(out["severity"], "high")
        self.assertIn("MAV:A", out["cvss_vector"])

    def test_modified_metrics_for(self):
        import asset_classifier as ac
        self.assertEqual(ac.modified_metrics_for("internal"), {"MAV": "A"})
        self.assertEqual(ac.modified_metrics_for("cde"), {})
        self.assertEqual(ac.modified_metrics_for("default"), {})

    def test_cve_epss_medium_uses_ef_branch(self):
        import criticality as cr
        f = {"name": "RCE", "severity": "critical",
             "cvss_vector_nvd": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
        out = cr.score_finding(f, asset_class="default", confirmed=False,
                               in_kev=False, epss=0.3)
        self.assertIn("E:F", out["cvss_vector"])
        self.assertIn("RC:C", out["cvss_vector"])

    def test_enrich_findings_end_to_end(self):
        import criticality as cr
        findings = [{"name": "IDOR", "severity": "medium", "vuln_class": "idor_read_pii",
                     "url": "https://app-tokenize.dev2.example.com/api/x", "confirmed": True}]
        out = cr.enrich_findings(findings)
        self.assertIs(out[0], findings[0])  # mutação in-place
        self.assertEqual(findings[0]["asset_class"], "cde")
        self.assertIn("cvss_environmental", findings[0])
        self.assertEqual(findings[0]["severity_tool"], "medium")


class TestEnrichFindingsEpssScoreAlias(unittest.TestCase):
    """Fix A: enrich_findings deve aceitar 'epss_score' (campo de cve_enrich.py)
    além de 'epss' — sem este fix o KEV/EPSS-aware nunca dispara para findings
    Nuclei cujo campo foi preenchido por cve_enrich.py como 'epss_score'."""

    def test_epss_score_field_triggers_kev_epss_aware_branch(self):
        """Finding com epss_score=0.6 (≥0.5) deve usar E:H/RC:C → 'critical'."""
        import criticality as cr
        f = {
            "name": "RCE via Log4Shell",
            "severity": "critical",
            "cvss_vector_nvd": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "epss_score": 0.6,   # campo gravado pelo cve_enrich.py
        }
        out = cr.score_finding(f, asset_class="default", confirmed=False,
                               in_kev=False,
                               epss=float(f.get("epss") or f.get("epss_score") or 0.0))
        self.assertIn("E:H", out["cvss_vector"])
        self.assertEqual(out["severity"], "critical")

    def test_enrich_findings_reads_epss_score_alias(self):
        """enrich_findings deve ler 'epss_score' do finding (não só 'epss')."""
        import criticality as cr
        # NVD 9.8 base, epss_score=0.6 → E:H/RC:C → severity critical
        f = {
            "name": "RCE",
            "severity": "critical",
            "cvss_vector_nvd": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "epss_score": 0.6,
            "url": "https://example.com/vuln",
        }
        cr.enrich_findings([f])
        self.assertIn("E:H", f["cvss_vector"])
        self.assertEqual(f["severity"], "critical")

    def test_enrich_findings_epss_score_medium_range_uses_ef_branch(self):
        """epss_score=0.3 (em [0.1, 0.5)) → E:F no vetor."""
        import criticality as cr
        f = {
            "name": "SQLi",
            "severity": "high",
            "cvss_vector_nvd": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "epss_score": 0.3,
            "url": "https://example.com/sqli",
        }
        cr.enrich_findings([f])
        self.assertIn("E:F", f["cvss_vector"])


class TestInjectCveSignals(unittest.TestCase):
    """Fix B: função _inject_cve_signals que injeta in_kev/epss_score/cvss_vector_nvd
    num finding Nuclei a partir do cve_enrichment dict produzido por cve_enrich.py.
    Deve estar importável de stiglitz_report (ou de um módulo lib)."""

    def _import_inject(self):
        """Importa _inject_cve_signals de stiglitz_report via runpy para evitar
        executar o módulo inteiro (que lê env vars e arquivos)."""
        import importlib.util, sys, os
        _ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        # Tentamos importar de um módulo lib que exponha a função.
        # Se não existir ainda, ImportError vai falhar o teste (RED).
        sys.path[:0] = [_ROOT, os.path.join(_ROOT, "lib")]
        from report_helpers import inject_cve_signals  # noqa
        return inject_cve_signals

    def test_inject_sets_in_kev_true_when_any_cve_in_kev(self):
        inject = self._import_inject()
        finding = {"name": "RCE", "severity": "critical",
                   "cve": "CVE-2024-12345", "cve_ids": ["CVE-2024-12345"]}
        enrichment = {
            "CVE-2024-12345": {
                "cve_id": "CVE-2024-12345", "in_kev": True,
                "epss_score": 0.72, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "cvss_v3": 9.8, "cvss_v2": None,
            }
        }
        inject(finding, enrichment)
        self.assertTrue(finding.get("in_kev"))

    def test_inject_sets_epss_score_to_max_across_cves(self):
        inject = self._import_inject()
        finding = {"name": "Multi-CVE", "severity": "high",
                   "cve": "CVE-2024-00001, CVE-2024-00002",
                   "cve_ids": ["CVE-2024-00001", "CVE-2024-00002"]}
        enrichment = {
            "CVE-2024-00001": {"in_kev": False, "epss_score": 0.2, "cvss_vector": "",
                               "cvss_v3": 7.5, "cvss_v2": None},
            "CVE-2024-00002": {"in_kev": False, "epss_score": 0.45, "cvss_vector": "",
                               "cvss_v3": 8.1, "cvss_v2": None},
        }
        inject(finding, enrichment)
        self.assertAlmostEqual(finding.get("epss_score", 0), 0.45)

    def test_inject_sets_cvss_vector_nvd_when_vector_present(self):
        inject = self._import_inject()
        finding = {"name": "RCE", "severity": "critical",
                   "cve": "CVE-2024-12345", "cve_ids": ["CVE-2024-12345"]}
        enrichment = {
            "CVE-2024-12345": {
                "in_kev": False, "epss_score": 0.0,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "cvss_v3": 9.8, "cvss_v2": None,
            }
        }
        inject(finding, enrichment)
        self.assertEqual(finding.get("cvss_vector_nvd"),
                         "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")

    def test_inject_does_not_set_cvss_vector_nvd_when_no_vector(self):
        """Se o enrichment só tem score numérico (sem vetor), não inventa vetor."""
        inject = self._import_inject()
        finding = {"name": "RCE", "severity": "critical",
                   "cve": "CVE-2024-12345", "cve_ids": ["CVE-2024-12345"]}
        enrichment = {
            "CVE-2024-12345": {
                "in_kev": False, "epss_score": 0.0,
                "cvss_vector": "",   # vazio — só score numérico
                "cvss_v3": 9.8, "cvss_v2": None,
            }
        }
        inject(finding, enrichment)
        self.assertNotIn("cvss_vector_nvd", finding)

    def test_inject_in_kev_false_stays_false_when_no_kev(self):
        inject = self._import_inject()
        finding = {"name": "XSS", "severity": "medium",
                   "cve": "CVE-2024-99999", "cve_ids": ["CVE-2024-99999"]}
        enrichment = {
            "CVE-2024-99999": {"in_kev": False, "epss_score": 0.0,
                               "cvss_vector": "", "cvss_v3": 6.5, "cvss_v2": None}
        }
        inject(finding, enrichment)
        self.assertFalse(finding.get("in_kev", False))


class TestScanPathEnrichFindingsIntegration(unittest.TestCase):
    """Fix C+E: integração entre injeção de sinais CVE e enrich_findings.
    Simula o caminho do scan: finding Nuclei com CVE → inject_cve_signals →
    enrich_findings → severity 'critical' e cvss_environmental presente."""

    def _import_inject(self):
        import sys, os
        _ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        sys.path[:0] = [_ROOT, os.path.join(_ROOT, "lib")]
        from report_helpers import inject_cve_signals
        return inject_cve_signals

    def test_nuclei_finding_in_kev_becomes_critical_after_full_pipeline(self):
        """Finding Nuclei com CVE in_kev=True: após inject + enrich → critical."""
        import criticality as cr
        inject = self._import_inject()

        finding = {
            "name": "Log4Shell",
            "severity": "high",   # ferramenta disse "high"
            "cve": "CVE-2021-44228",
            "cve_ids": ["CVE-2021-44228"],
            "url": "https://example.com/app",
        }
        enrichment = {
            "CVE-2021-44228": {
                "in_kev": True,
                "epss_score": 0.97,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                "cvss_v3": 10.0, "cvss_v2": None,
            }
        }
        inject(finding, enrichment)
        cr.enrich_findings([finding])

        self.assertTrue(finding.get("in_kev"))
        self.assertAlmostEqual(finding.get("epss_score", 0), 0.97)
        self.assertIn("cvss_environmental", finding)
        self.assertEqual(finding["severity"], "critical")
        self.assertEqual(finding["score_source"], "nvd")

    def test_nuclei_finding_no_cve_falls_back_to_estimated(self):
        """Finding Nuclei sem CVE: score_source='estimated', severity calculada."""
        import criticality as cr
        inject = self._import_inject()

        finding = {
            "name": "Missing Security Header",
            "severity": "medium",
            "cve": "",
            "cve_ids": [],
            "url": "https://example.com/",
        }
        inject(finding, {})  # enrichment vazio
        cr.enrich_findings([finding])

        self.assertIn("cvss_environmental", finding)
        self.assertEqual(finding["score_source"], "estimated")
        self.assertEqual(finding["severity_tool"], "medium")


class TestInjectCveSignalsNoneSafety(unittest.TestCase):
    """M-1 / M-6 — inject_cve_signals deve ser None-safe."""

    def _import_inject(self):
        import sys, os
        _ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        sys.path[:0] = [_ROOT, os.path.join(_ROOT, "lib")]
        from report_helpers import inject_cve_signals
        return inject_cve_signals

    def test_none_enrichment_returns_finding_unchanged(self):
        """inject_cve_signals(finding, None) não lança exceção e retorna o finding."""
        inject = self._import_inject()
        finding = {
            "name": "RCE",
            "severity": "critical",
            "cve": "CVE-2024-12345",
            "cve_ids": ["CVE-2024-12345"],
        }
        result = inject(finding, None)
        self.assertIs(result, finding, "Deve retornar o mesmo objeto finding")

    def test_none_enrichment_does_not_set_in_kev(self):
        """inject_cve_signals(finding, None) não seta in_kev no finding."""
        inject = self._import_inject()
        finding = {"name": "Test", "severity": "high", "cve": "CVE-2024-00001"}
        inject(finding, None)
        self.assertNotIn("in_kev", finding,
                         "in_kev não deve ser injetado quando cve_enrichment é None")

    def test_none_enrichment_does_not_set_epss(self):
        """inject_cve_signals(finding, None) não seta epss_score no finding."""
        inject = self._import_inject()
        finding = {"name": "Test", "severity": "high", "cve": "CVE-2024-00001"}
        inject(finding, None)
        self.assertNotIn("epss_score", finding,
                         "epss_score não deve ser injetado quando cve_enrichment é None")

    def test_empty_dict_enrichment_is_also_falsy_safe(self):
        """inject_cve_signals(finding, {}) com CVE ausente no dict não seta in_kev."""
        inject = self._import_inject()
        finding = {"name": "Test", "severity": "high", "cve": "CVE-2024-99999"}
        inject(finding, {})
        # CVE não está no enrichment vazio; in_kev deve ser False (não ausente)
        self.assertFalse(finding.get("in_kev", False))

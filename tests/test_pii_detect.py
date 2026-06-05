#!/usr/bin/env python3
"""
Testes do detector de PII (lib/pii_detect.py).

Cobre a lacuna que deixou passar "37 Employee PII Email Addresses Hardcoded
in Public JavaScript Bundle": o Stiglitz baixava o bundle e só procurava
secrets/endpoints/frameworks — e-mail corporativo, CPF/CNPJ e telefone não
eram detectados.

Uso: python3 tests/test_pii_detect.py  |  python3 -m pytest tests/test_pii_detect.py
"""
import os
import sys
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
sys.path[:0] = [_ROOT, os.path.join(_ROOT, "lib"), _HERE]

from pii_detect import (
    registrable_domain,
    mask_email,
    valid_cpf,
    valid_cnpj,
    extract_pii,
    build_pii_findings,
)
import criticality


class TestRegistrableDomain(unittest.TestCase):
    def test_reduces_host_to_registrable(self):
        self.assertEqual(registrable_domain("app.hml.acme-corp.com"), "acme-corp.com")

    def test_handles_two_part_br_tld(self):
        self.assertEqual(registrable_domain("app.minhaempresa.com.br"), "minhaempresa.com.br")


class TestCpfValidation(unittest.TestCase):
    def test_accepts_valid_cpf(self):
        self.assertTrue(valid_cpf("52998224725"))

    def test_rejects_bad_checksum(self):
        self.assertFalse(valid_cpf("12345678900"))

    def test_rejects_all_same_digits(self):
        self.assertFalse(valid_cpf("11111111111"))


class TestCnpjValidation(unittest.TestCase):
    def test_accepts_valid_cnpj(self):
        self.assertTrue(valid_cnpj("11222333000181"))

    def test_rejects_bad_checksum(self):
        self.assertFalse(valid_cnpj("11222333000100"))


class TestMaskEmail(unittest.TestCase):
    def test_masks_local_part_keeps_domain(self):
        self.assertEqual(mask_email("joao.silva@acme-corp.com"), "joa***@acme-corp.com")


class TestExtractPii(unittest.TestCase):
    def test_classifies_corporate_vs_external_email(self):
        js = 'var team=["joao.silva@acme-corp.com","author@some-oss.io"];'
        pii = extract_pii(js, ["acme-corp.com"])
        self.assertIn("joao.silva@acme-corp.com", pii["emails_corporate"])
        self.assertNotIn("joao.silva@acme-corp.com", pii["emails_external"])
        self.assertIn("author@some-oss.io", pii["emails_external"])
        self.assertNotIn("author@some-oss.io", pii["emails_corporate"])

    def test_subdomain_email_counts_as_corporate(self):
        pii = extract_pii('x="suporte@hml.acme-corp.com"', ["acme-corp.com"])
        self.assertIn("suporte@hml.acme-corp.com", pii["emails_corporate"])

    def test_detects_valid_cpf_rejects_invalid(self):
        js = 'doc1="529.982.247-25"; doc2="123.456.789-00";'
        pii = extract_pii(js, ["acme-corp.com"])
        self.assertIn("529.982.247-25", pii["cpf"])
        self.assertNotIn("123.456.789-00", pii["cpf"])

    def test_detects_valid_cnpj(self):
        pii = extract_pii('cnpj="11.222.333/0001-81"', ["acme-corp.com"])
        self.assertIn("11.222.333/0001-81", pii["cnpj"])

    def test_detects_formatted_br_phone(self):
        pii = extract_pii('tel="+55 (11) 99876-5432"', ["acme-corp.com"])
        self.assertTrue(any("99876-5432" in p for p in pii["phones"]))

    def test_bare_eleven_digits_is_not_a_phone(self):
        # IDs/timestamps de 11 dígitos crus não podem virar telefone (FP).
        pii = extract_pii('id="12345678901"', ["acme-corp.com"])
        self.assertEqual(pii["phones"], [])


class TestBuildPiiFindings(unittest.TestCase):
    def test_emits_finding_for_corporate_emails(self):
        pii = {"emails_corporate": ["a@acme-corp.com", "b@acme-corp.com"],
               "emails_external": [], "cpf": [], "cnpj": [], "phones": []}
        findings = build_pii_findings(pii, "https://app.hml.acme-corp.com", "https://x/app.js")
        self.assertTrue(findings)
        f = findings[0]
        for key in ("id", "source", "name", "severity", "url", "description", "remediation"):
            self.assertIn(key, f)
        self.assertEqual(f["source"], "pii")
        self.assertTrue(f["id"].startswith("PII-"))

    def test_no_finding_when_nothing_sensitive(self):
        pii = {"emails_corporate": [], "emails_external": ["x@github.io"],
               "cpf": [], "cnpj": [], "phones": []}
        self.assertEqual(build_pii_findings(pii, "https://t", ""), [])

    def test_description_masks_emails(self):
        pii = {"emails_corporate": ["joao.silva@acme-corp.com"],
               "emails_external": [], "cpf": [], "cnpj": [], "phones": []}
        f = build_pii_findings(pii, "https://t", "")[0]
        self.assertNotIn("joao.silva@acme-corp.com", f["description"])
        self.assertIn("joa***@acme-corp.com", f["description"])


class TestPiiSeverityScoring(unittest.TestCase):
    """A criticidade não pode soterrar PII em 'low' só porque o asset é público.
    O finding É sobre dado pessoal → classe 'pii' (CR:H), não 'public' (CR:L)."""

    def test_build_sets_vuln_class_cwe_and_data_class(self):
        pii = {"emails_corporate": ["a@acme-corp.com"], "emails_external": [],
               "cpf": [], "cnpj": [], "phones": []}
        f = build_pii_findings(pii, "https://t", "")[0]
        self.assertIn("vuln_class", f)
        self.assertEqual(f["data_class"], "pii")
        self.assertTrue(f["cwe"].startswith("CWE-"))

    def test_corporate_email_scores_medium_not_low(self):
        # URL no bundle (/assets/...js) classificaria 'public' (CR:L) → 'low'.
        # O hint data_class=pii deve manter o achado em 'medium'.
        pii = {"emails_corporate": ["a@acme-corp.com"], "emails_external": [],
               "cpf": [], "cnpj": [], "phones": []}
        f = build_pii_findings(pii, "https://app.hml.acme-corp.com",
                               "https://app.hml.acme-corp.com/assets/x.js")[0]
        criticality.enrich_findings([f])
        self.assertEqual(f["severity"], "medium")

    def test_cpf_scores_high(self):
        pii = {"emails_corporate": [], "emails_external": [],
               "cpf": ["529.982.247-25"], "cnpj": [], "phones": []}
        f = build_pii_findings(pii, "https://t", "https://t/assets/x.js")[0]
        criticality.enrich_findings([f])
        self.assertEqual(f["severity"], "high")


class TestEnrichRespectsDataClassHint(unittest.TestCase):
    def test_data_class_hint_overrides_url_classification(self):
        # /assets casaria com a classe 'public'; o hint força 'pii'.
        f = {"url": "https://h/assets/x.js", "severity": "medium",
             "vuln_class": "pii_email_exposure", "data_class": "pii"}
        criticality.enrich_findings([f])
        self.assertEqual(f["asset_class"], "pii")

    def test_without_hint_url_classification_still_applies(self):
        f = {"url": "https://h/assets/x.js", "severity": "medium"}
        criticality.enrich_findings([f])
        self.assertEqual(f["asset_class"], "public")


if __name__ == "__main__":
    unittest.main(verbosity=2)

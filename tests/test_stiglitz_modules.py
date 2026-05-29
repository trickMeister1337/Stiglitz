#!/usr/bin/env python3
"""
Testes dos módulos Python extraídos do stiglitz.sh (lib/*.py).

Esses módulos são scripts CLI (leem sys.argv e executam código no nível de
módulo), então são testados via subprocess contra fixtures em diretórios
temporários — não por import.
"""
import os
import sys
import glob
import json
import subprocess
import tempfile
import shutil
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LIB = os.path.join(ROOT, "lib")


def _run_module(module, *args, timeout=60):
    """Executa lib/<module> com os argumentos posicionais dados."""
    return subprocess.run(
        [sys.executable, os.path.join(LIB, module), *args],
        capture_output=True, text=True, timeout=timeout,
    )


class _TmpScanDir(unittest.TestCase):
    """Base: cria um OUTDIR temporário com subdir raw/."""
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        os.makedirs(os.path.join(self.tmp, "raw"), exist_ok=True)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _write_raw(self, name, content):
        with open(os.path.join(self.tmp, "raw", name), "w") as f:
            f.write(content)

    def _read_raw_json(self, name):
        with open(os.path.join(self.tmp, "raw", name)) as f:
            return json.load(f)


class TestTechProfile(_TmpScanDir):
    def test_httpx_tech_detect_parsing(self):
        # status code [200] não deve virar tecnologia; versões devem ser extraídas
        self._write_raw("httpx_results.txt",
                        "https://t.com [200] [WordPress:6.3,PHP:8.1,Nginx:1.18.0]\n")
        r = _run_module("tech_profile.py", self.tmp, "https://t.com")
        self.assertEqual(r.returncode, 0, r.stderr)
        det = self._read_raw_json("tech_profile.json")["detected"]
        self.assertEqual(det["WordPress"]["version"], "6.3")
        self.assertEqual(det["PHP"]["version"], "8.1")
        self.assertEqual(det["Nginx"]["version"], "1.18.0")
        self.assertNotIn("200", det)

    def test_path_fingerprint(self):
        self._write_raw("katana_urls.txt",
                        "https://t.com/wp-admin/index.php\n"
                        "https://t.com/actuator/health\n")
        r = _run_module("tech_profile.py", self.tmp, "https://t.com")
        self.assertEqual(r.returncode, 0, r.stderr)
        det = self._read_raw_json("tech_profile.json")["detected"]
        self.assertIn("WordPress", det)
        self.assertEqual(det["WordPress"]["source"], "path_fingerprint")
        self.assertIn("Spring Boot", det)

    def test_derivation_wordpress(self):
        # WordPress detectado deve derivar tags Nuclei, ffuf profile e CMS scanner
        self._write_raw("httpx_results.txt", "https://t.com [WordPress:6.3]\n")
        r = _run_module("tech_profile.py", self.tmp, "https://t.com")
        self.assertEqual(r.returncode, 0, r.stderr)
        p = self._read_raw_json("tech_profile.json")
        self.assertIn("wordpress", p["nuclei_extra_tags"])
        self.assertIn("wp", p["nuclei_extra_tags"])
        self.assertEqual(p["ffuf_profile"], "wordpress")
        self.assertEqual(p["cms_scanner"], "wpscan")
        self.assertIn("WordPress", p["categories"].get("cms", []))

    def test_empty_input_is_generic(self):
        r = _run_module("tech_profile.py", self.tmp, "https://t.com")
        self.assertEqual(r.returncode, 0, r.stderr)
        p = self._read_raw_json("tech_profile.json")
        self.assertEqual(p["total_detected"], 0)
        self.assertEqual(p["ffuf_profile"], "generic")
        self.assertIsNone(p["cms_scanner"])

    def test_version_findings_probe_integration(self):
        # PROBES confirmadas entram com confidence "confirmed"
        self._write_raw("version_findings.json", json.dumps([
            {"name": "Apache 2.4.49", "detected_version": "2.4.49",
             "is_outdated": True, "min_version": "2.4.62", "cve": "CVE-2021-41773"}
        ]))
        r = _run_module("tech_profile.py", self.tmp, "https://t.com")
        self.assertEqual(r.returncode, 0, r.stderr)
        det = self._read_raw_json("tech_profile.json")["detected"]
        self.assertIn("Apache", det)
        self.assertEqual(det["Apache"]["confidence"], "confirmed")
        self.assertTrue(det["Apache"]["outdated"])


class TestScanMetadata(_TmpScanDir):
    def test_waf_detected_enables_evasion(self):
        r = _run_module("scan_metadata.py", self.tmp, "1", "Cloudflare",
                        "5", "2", "1s-3s", "Mozilla/5.0")
        self.assertEqual(r.returncode, 0, r.stderr)
        m = self._read_raw_json("scan_metadata.json")
        self.assertTrue(m["waf_detected"])
        self.assertTrue(m["evasion_active"])
        self.assertIn("user_agent_rotation", m["evasion_techniques"])
        self.assertEqual(m["nuclei_rate_limit"], 5)
        self.assertEqual(m["nuclei_delay"], "1s-3s")

    def test_no_waf_no_evasion(self):
        r = _run_module("scan_metadata.py", self.tmp, "0", "",
                        "50", "10", "none", "curl/8")
        self.assertEqual(r.returncode, 0, r.stderr)
        m = self._read_raw_json("scan_metadata.json")
        self.assertFalse(m["waf_detected"])
        self.assertEqual(m["evasion_techniques"], [])
        self.assertIsNone(m["nuclei_delay"])


class TestModulesCompile(unittest.TestCase):
    """Todo módulo lib/*.py + stiglitz_report.py deve compilar (glob cobre módulos novos)."""
    def test_all_lib_modules_compile(self):
        import py_compile
        modules = sorted(glob.glob(os.path.join(LIB, "*.py")))
        self.assertGreater(len(modules), 0, "nenhum módulo lib/*.py encontrado")
        for path in modules:
            py_compile.compile(path, doraise=True)
        py_compile.compile(os.path.join(ROOT, "stiglitz_report.py"), doraise=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)

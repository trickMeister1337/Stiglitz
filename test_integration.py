#!/usr/bin/env python3
"""
End-to-end integration test against a live, deliberately-vulnerable target
(OWASP Juice Shop in CI). Proves the detect → aggregate → report → SARIF
chain works on a real app, not just that modules compile.

Skipped unless STIGLITZ_TEST_TARGET is set, e.g.:
    STIGLITZ_TEST_TARGET=http://localhost:3000 python -m pytest test_integration.py -v
"""
import os
import re
import sys
import json
import shutil
import tempfile
import subprocess
import unittest

ROOT = os.path.dirname(os.path.abspath(__file__))
LIB = os.path.join(ROOT, "lib")
TARGET = os.environ.get("STIGLITZ_TEST_TARGET", "").rstrip("/")


@unittest.skipUnless(TARGET, "set STIGLITZ_TEST_TARGET to run the integration scan")
class TestLiveScan(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.outdir = tempfile.mkdtemp(prefix="stiglitz_it_")
        os.makedirs(os.path.join(cls.outdir, "raw"), exist_ok=True)
        cls.domain = re.sub(r"^https?://", "", TARGET).split("/")[0].split(":")[0]
        # Seed httpx output so security_headers.py knows what to probe
        with open(os.path.join(cls.outdir, "raw", "httpx_results.txt"), "w") as f:
            f.write(TARGET + "\n")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.outdir, ignore_errors=True)

    def _run(self, module, *args, timeout=90):
        r = subprocess.run([sys.executable, os.path.join(LIB, module), *args],
                           capture_output=True, text=True, timeout=timeout)
        return r

    def test_01_security_headers_probe(self):
        r = self._run("security_headers.py", self.outdir)
        self.assertEqual(r.returncode, 0, r.stderr)
        path = os.path.join(self.outdir, "raw", "security_headers.json")
        self.assertTrue(os.path.exists(path), "security_headers.json not produced")
        data = json.load(open(path))
        # Juice Shop is missing several security headers — expect findings
        missing = [h for entry in data for h in entry.get("missing", {})]
        self.assertGreater(len(missing), 0, "expected missing security headers on the target")

    def test_02_secscan_probe(self):
        r = self._run("secscan.py", self.outdir, TARGET, self.domain)
        self.assertEqual(r.returncode, 0, r.stderr)
        path = os.path.join(self.outdir, "raw", "secscan_findings.json")
        self.assertTrue(os.path.exists(path), "secscan_findings.json not produced")

    def test_03_report_and_sarif(self):
        env = dict(os.environ, OUTDIR=self.outdir, TARGET=TARGET,
                   DOMAIN=self.domain, SCAN_START_TS="0")
        r = subprocess.run([sys.executable, os.path.join(ROOT, "stiglitz_report.py")],
                           capture_output=True, text=True, timeout=120, env=env)
        self.assertEqual(r.returncode, 0, r.stderr)

        # findings.json with at least one real finding
        fj = os.path.join(self.outdir, "findings.json")
        self.assertTrue(os.path.exists(fj), "findings.json not produced")
        findings = json.load(open(fj))
        self.assertGreaterEqual(findings["summary"]["total"], 1,
                                "expected at least one finding on a vulnerable target")

        # valid SARIF 2.1.0
        sf = os.path.join(self.outdir, "findings.sarif")
        self.assertTrue(os.path.exists(sf), "findings.sarif not produced")
        sarif = json.load(open(sf))
        self.assertEqual(sarif["version"], "2.1.0")
        run = sarif["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "Stiglitz")
        levels = {res["level"] for res in run["results"]}
        self.assertTrue(levels <= {"error", "warning", "note", "none"},
                        f"invalid SARIF levels: {levels}")
        self.assertGreaterEqual(len(run["results"]), 1, "SARIF has no results")

        # HTML report rendered
        self.assertTrue(os.path.exists(os.path.join(self.outdir, "stiglitz_report.html")))


if __name__ == "__main__":
    unittest.main(verbosity=2)

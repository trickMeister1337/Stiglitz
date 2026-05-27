#!/usr/bin/env python3
"""
Stiglitz RED — Testes unitários dos módulos Python.

Uso: python3 test_lib.py
"""
import sys
import os
import json
import tempfile
import shutil
import unittest

# Add lib/ to path
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))

from parsers import parse_nuclei, parse_zap, extract_all_urls, _normalize_zap_alerts
from evidence import extract_sqlmap_evidence, format_evidence, collect_and_consolidate, is_valid_url, strip_ansi
from report_generator import generate_report
from ingest import (
    parse_nuclei as ingest_parse_nuclei,
    parse_zap as ingest_parse_zap,
    parse_nmap,
    parse_cves,
    build_sqli_targets,
    build_brute_targets,
    _url_score,
    _has_injectable_param,
    ingest,
)
from poc_generator import (
    collect_pocs,
    _extract_sqlmap_payload,
    _inject_param,
)


class TestParsers(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def test_parse_nuclei_extracts_cves(self):
        nuclei_file = os.path.join(self.tmpdir, "nuclei.json")
        with open(nuclei_file, "w") as f:
            f.write('{"info":{"classification":{"cve":["CVE-2021-44228"]}},"matched-at":"https://test.com/api?id=1"}\n')
            f.write('{"info":{"classification":{"cve":["CVE-2023-1234"]}},"matched-at":"https://test.com/search?q=x"}\n')
            f.write('{"info":{"classification":{}},"matched-at":"https://test.com"}\n')

        result = parse_nuclei(nuclei_file, self.tmpdir)
        self.assertEqual(result["cves"], 2)
        self.assertEqual(result["urls_params"], 2)
        self.assertEqual(result["urls_total"], 3)

        # Verify files
        with open(os.path.join(self.tmpdir, "cves_found.txt")) as f:
            cves = [l.strip() for l in f if l.strip()]
        self.assertIn("CVE-2021-44228", cves)
        self.assertIn("CVE-2023-1234", cves)

    def test_parse_nuclei_handles_string_cve(self):
        nuclei_file = os.path.join(self.tmpdir, "nuclei.json")
        with open(nuclei_file, "w") as f:
            f.write('{"info":{"classification":{"cve":"CVE-2024-9999"}},"matched-at":"https://t.com"}\n')
        result = parse_nuclei(nuclei_file, self.tmpdir)
        self.assertEqual(result["cves"], 1)

    def test_parse_zap_array_format(self):
        zap_file = os.path.join(self.tmpdir, "zap.json")
        with open(zap_file, "w") as f:
            json.dump([
                {"alert": "SQL Injection", "risk": "High", "url": "https://t.com/login?u=a"},
                {"alert": "XSS", "risk": "High", "url": "https://t.com/search"},
                {"alert": "Missing CSP", "risk": "Medium", "url": "https://t.com"},
            ], f)
        result = parse_zap(zap_file, self.tmpdir)
        self.assertEqual(result["sqli"], 1)
        self.assertEqual(result["high_crit"], 2)

    def test_parse_zap_nested_format(self):
        zap_file = os.path.join(self.tmpdir, "zap.json")
        with open(zap_file, "w") as f:
            json.dump({"site": [{"alerts": [
                {"alert": "SQL Injection", "risk": "Critical", "url": "https://t.com/api"}
            ]}]}, f)
        result = parse_zap(zap_file, self.tmpdir)
        self.assertEqual(result["sqli"], 1)
        self.assertEqual(result["high_crit"], 1)

    def test_parse_zap_handles_string_elements(self):
        zap_file = os.path.join(self.tmpdir, "zap.json")
        with open(zap_file, "w") as f:
            json.dump(["some string", {"alert": "Test", "risk": "Low", "url": "https://t.com"}], f)
        result = parse_zap(zap_file, self.tmpdir)
        self.assertEqual(result["high_crit"], 0)  # string element skipped

    def test_parse_zap_riskdesc_format(self):
        zap_file = os.path.join(self.tmpdir, "zap.json")
        with open(zap_file, "w") as f:
            json.dump([{"alert": "SQL Injection", "risk": "High (Medium)", "url": "https://t.com/x"}], f)
        result = parse_zap(zap_file, self.tmpdir)
        self.assertEqual(result["sqli"], 1)
        self.assertEqual(result["high_crit"], 1)

    def test_normalize_zap_alerts_dict_with_alerts_key(self):
        raw = {"alerts": [{"alert": "Test", "url": "https://t.com"}]}
        alerts = _normalize_zap_alerts(raw)
        self.assertEqual(len(alerts), 1)

    def test_extract_all_urls_consolidates_sources(self):
        # Create mock input files
        with open(os.path.join(self.tmpdir, "input_nuclei.jsonl"), "w") as f:
            f.write('{"matched-at":"https://t.com/api?id=1"}\n')
        with open(os.path.join(self.tmpdir, "input_zap.json"), "w") as f:
            json.dump([{"url": "https://t.com/login?user=a", "alert": "SQLi", "risk": "High"}], f)
        with open(os.path.join(self.tmpdir, "input_httpx.jsonl"), "w") as f:
            f.write('{"url":"https://t.com/admin"}\n')

        result = extract_all_urls(self.tmpdir, "t.com")
        self.assertGreater(result["params"], 0)
        self.assertGreater(result["total"], 0)

        with open(os.path.join(self.tmpdir, "urls_with_params.txt")) as f:
            urls = [l.strip() for l in f if l.strip()]
        self.assertTrue(any("id=1" in u for u in urls))

    def test_extract_urls_excludes_static_files(self):
        """robots.txt, .css, .js, images NÃO devem virar targets SQLi."""
        with open(os.path.join(self.tmpdir, "input_httpx.jsonl"), "w") as f:
            f.write('{"url":"https://t.com/robots.txt"}\n')
            f.write('{"url":"https://t.com/style.css"}\n')
            f.write('{"url":"https://t.com/app.js"}\n')
            f.write('{"url":"https://t.com/logo.png"}\n')
            f.write('{"url":"https://t.com/sitemap.xml"}\n')
            f.write('{"url":"https://t.com/api/users"}\n')  # Este SIM deve entrar

        result = extract_all_urls(self.tmpdir, "t.com")
        with open(os.path.join(self.tmpdir, "urls_with_params.txt")) as f:
            urls = [l.strip() for l in f if l.strip()]

        # Nenhuma URL estática deve ter virado target com parâmetro
        static_in_params = [u for u in urls if any(
            ext in u for ext in [".txt?", ".css?", ".js?", ".png?", ".xml?"]
        )]
        self.assertEqual(len(static_in_params), 0,
            f"URLs estáticas viraram targets SQLi: {static_in_params}")

        # Mas api/users deve ter gerado variantes
        api_urls = [u for u in urls if "/api/users" in u]
        self.assertGreater(len(api_urls), 0, "URL dinâmica /api/users deveria gerar variantes")

    def test_extract_urls_excludes_http_headers_as_params(self):
        """Headers HTTP reportados pelo ZAP como 'param' NÃO são query params."""
        with open(os.path.join(self.tmpdir, "input_zap.json"), "w") as f:
            json.dump([
                {"url": "https://t.com/", "alert": "Missing CSP", "risk": "Medium",
                 "param": "x-content-type-options"},
                {"url": "https://t.com/page", "alert": "Missing Header", "risk": "Low",
                 "param": "cache-control"},
                {"url": "https://t.com/api", "alert": "SQLi", "risk": "High",
                 "param": "user_id"},  # Este SIM é param real
            ], f)

        result = extract_all_urls(self.tmpdir, "t.com")
        with open(os.path.join(self.tmpdir, "urls_with_params.txt")) as f:
            urls = [l.strip() for l in f if l.strip()]

        # Headers NÃO devem virar params
        header_urls = [u for u in urls if "x-content-type" in u or "cache-control" in u]
        self.assertEqual(len(header_urls), 0,
            f"Headers HTTP viraram query params: {header_urls}")

        # Mas user_id SIM deve estar
        real_params = [u for u in urls if "user_id" in u]
        self.assertGreater(len(real_params), 0, "Param real user_id deveria estar")

    def test_extract_urls_excludes_external_domains_in_evidence_fields(self):
        """URLs externas em campos other/evidence (mozilla.org, owasp.org) NÃO devem ser testadas."""
        with open(os.path.join(self.tmpdir, "input_zap.json"), "w") as f:
            json.dump([
                {"url": "https://webapp.target.com/api", "alert": "Missing HSTS", "risk": "Medium",
                 "reference": "https://caniuse.com/stricttransportsecurity"},
                {"url": "https://webapp.target.com/login", "alert": "XSS", "risk": "High",
                 "other": "See https://developer.mozilla.org/en-US/docs/Web/HTTP",
                 "evidence": "https://owasp.org/www-community/attacks/xss/"},
                {"url": "https://webapp.target.com/search?q=test", "alert": "SQLi", "risk": "High"},
            ], f)

        result = extract_all_urls(self.tmpdir, "webapp.target.com")
        with open(os.path.join(self.tmpdir, "urls_with_params.txt")) as f:
            urls = [l.strip() for l in f if l.strip()]
        with open(os.path.join(self.tmpdir, "all_target_urls.txt")) as f:
            all_urls = [l.strip() for l in f if l.strip()]

        # NENHUMA URL externa deve estar presente
        external = [u for u in all_urls if "caniuse.com" in u or "mozilla.org" in u or "owasp.org" in u]
        self.assertEqual(len(external), 0,
            f"URLs externas encontradas: {external}")

        # URL do alvo deve estar
        target_urls = [u for u in all_urls if "webapp.target.com" in u]
        self.assertGreater(len(target_urls), 0, "URLs do alvo deveriam estar presentes")

    def test_extract_urls_excludes_external_domains(self):
        """URLs de domínios externos (caniuse.com, owasp.org) NÃO devem ser testadas."""
        with open(os.path.join(self.tmpdir, "input_zap.json"), "w") as f:
            json.dump([
                {"url": "https://target.com/page", "alert": "Missing HSTS", "risk": "Medium",
                 "reference": "https://caniuse.com/stricttransportsecurity https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"},
                {"url": "https://target.com/login", "alert": "CSP", "risk": "Medium",
                 "other": "See https://owasp.org/www-community/controls/Content_Security_Policy"},
                {"url": "https://target.com/api?id=1", "alert": "SQLi", "risk": "High"},
            ], f)

        result = extract_all_urls(self.tmpdir, "target.com")
        with open(os.path.join(self.tmpdir, "urls_with_params.txt")) as f:
            urls = [l.strip() for l in f if l.strip()]
        with open(os.path.join(self.tmpdir, "all_target_urls.txt")) as f:
            all_u = [l.strip() for l in f if l.strip()]

        # Nenhuma URL externa
        external = [u for u in all_u if "caniuse.com" in u or "mozilla.org" in u or "owasp.org" in u]
        self.assertEqual(len(external), 0,
            f"URLs externas vazaram: {external}")

        # URLs do target devem estar
        target_urls = [u for u in all_u if "target.com" in u]
        self.assertGreater(len(target_urls), 0, "URLs do target devem estar presentes")


class TestEvidence(unittest.TestCase):
    def test_extract_sqlmap_evidence_finds_parameter(self):
        log = """
[10:00:01] [INFO] testing URL 'https://target.com/search?q=test'
[10:00:05] [INFO] parameter 'q' is vulnerable
[10:00:05] [INFO] Place: GET
[10:00:06] [INFO] Type: boolean-based blind
[10:00:07] [INFO] back-end DBMS: MySQL >= 5.0
[10:00:08] [INFO] current user: 'app_user'
[10:00:09] [INFO] current database: 'production_db'
"""
        tmpdir = tempfile.mkdtemp()
        try:
            info = extract_sqlmap_evidence(log, tmpdir)
            self.assertTrue(info["injectable"])
            self.assertEqual(info["parameter"], "q")
            self.assertIn("boolean", info["techniques"][0].lower())
            self.assertIn("MySQL", info["dbms"])
            self.assertEqual(info["current_user"], "app_user")
            self.assertEqual(info["current_db"], "production_db")
        finally:
            shutil.rmtree(tmpdir)

    def test_extract_sqlmap_rejects_false_ending_as_table(self):
        """'[*] ending @ 23:30:40' NÃO é nome de tabela."""
        log = "[*] ending @ 23:30:40 /2026-04-29/\n[*] starting @ 10:00:00\n[*] shutting down"
        info = extract_sqlmap_evidence(log, tempfile.mkdtemp())
        self.assertEqual(len(info["tables"]), 0, f"False tables: {info['tables']}")

    def test_format_evidence_rejects_no_real_data(self):
        """Se não tem parameter/technique/dbms/csv, retorna None."""
        info = {"parameter":"","place":"","techniques":[],"dbms":"",
                "current_user":"","current_db":"","banner":"",
                "tables":[],"csv_data":[],"target_url":"","injectable":False}
        self.assertIsNone(format_evidence(info))

    def test_is_valid_url_rejects_malformed(self):
        """URLs sem hostname ou com filename como host são rejeitadas."""
        from evidence import is_valid_url
        self.assertFalse(is_valid_url("http:?action=1"))
        self.assertFalse(is_valid_url("http:?id=1"))
        self.assertFalse(is_valid_url("40eab1dc_output.log"))
        self.assertFalse(is_valid_url(""))
        self.assertFalse(is_valid_url("not_a_url"))
        self.assertTrue(is_valid_url("https://target.com/api?id=1"))
        self.assertTrue(is_valid_url("https://sub.target.com/page"))

    def test_strip_ansi_removes_terminal_codes(self):
        from evidence import strip_ansi
        text = "\033[0;32m[✓]\033[0m VULNERÁVEL: \033[1;31mtest\033[0m"
        clean = strip_ansi(text)
        self.assertNotIn("\033", clean)
        self.assertIn("VULNERÁVEL", clean)

    def test_extract_sqlmap_evidence_reads_csv(self):
        tmpdir = tempfile.mkdtemp()
        try:
            csv_path = os.path.join(tmpdir, "results-04282026.csv")
            with open(csv_path, "w") as f:
                f.write("Target URL,Place,Parameter,Technique(s),Note(s)\n")
                f.write("https://t.com/api,GET,id,boolean-based blind,\n")
                f.write("https://t.com/api,GET,name,time-based blind,\n")

            info = extract_sqlmap_evidence("", tmpdir)
            self.assertEqual(len(info["csv_data"]), 1)
            self.assertEqual(len(info["csv_data"][0]["rows"]), 2)
            self.assertIn("Target URL", info["csv_data"][0]["header"])
        finally:
            shutil.rmtree(tmpdir)

    def test_format_evidence_professional(self):
        info = {
            "parameter": "q", "place": "GET", "techniques": ["boolean-based blind"],
            "dbms": "MySQL >= 5.0", "current_user": "root", "current_db": "app",
            "banner": "5.7.38", "tables": ["users", "orders"], "csv_data": [],
            "target_url": "", "injectable": True
        }
        text = format_evidence(info)
        self.assertIsNotNone(text)
        self.assertIn("Parâmetro vulnerável: q (GET)", text)
        self.assertIn("boolean-based blind", text)
        self.assertIn("MySQL", text)
        self.assertIn("root", text)

    def test_collect_and_consolidate_deduplicates(self):
        tmpdir = tempfile.mkdtemp()
        try:
            for d in ["sqlmap", "metasploit", "hydra", "nikto", "searchsploit"]:
                os.makedirs(os.path.join(tmpdir, d), exist_ok=True)

            # Create confirmed CSV with duplicates
            with open(os.path.join(tmpdir, "exploits_confirmed.csv"), "w") as f:
                f.write("status|target|tool|detail\n")
                f.write("VULNERABLE|https://t.com/api?id=1|sqlmap|level=3,risk=2\n")
                f.write("VULNERABLE|https://t.com/api?name=x|sqlmap|level=3,risk=2\n")
                f.write("VULNERABLE|https://t.com/api?q=y|sqlmap|level=3,risk=2\n")

            for path in ["cves_found.txt", "open_services.txt", "stiglitz_red.log",
                         "zap_high_crit.txt", "urls_with_params.txt"]:
                open(os.path.join(tmpdir, path), "w").close()

            result = collect_and_consolidate(tmpdir)
            findings = result["findings"]
            # Should be consolidated into 1 finding, not 3
            self.assertLessEqual(len(findings), 2)
            if findings:
                self.assertGreaterEqual(findings[0].get("count", 1), 3)
        finally:
            shutil.rmtree(tmpdir)


class TestReportGenerator(unittest.TestCase):
    def test_generate_report_creates_html(self):
        tmpdir = tempfile.mkdtemp()
        try:
            for d in ["sqlmap", "metasploit", "hydra", "nikto", "searchsploit"]:
                os.makedirs(os.path.join(tmpdir, d), exist_ok=True)
            for path in ["exploits_confirmed.csv", "cves_found.txt", "open_services.txt",
                         "stiglitz_red.log", "zap_high_crit.txt"]:
                with open(os.path.join(tmpdir, path), "w") as f:
                    if "csv" in path:
                        f.write("status|target|tool|detail\n")

            report_path = generate_report(tmpdir, "test.com", "staging", 5, 0, 0, "1.0.0")
            self.assertTrue(os.path.exists(report_path))

            with open(report_path) as f:
                html = f.read()
            self.assertIn("Stiglitz RED", html)
            self.assertIn("test.com", html)
            self.assertIn("CONFIDENTIAL", html)
            self.assertIn("<style>", html)
            self.assertGreater(len(html), 3000)
        finally:
            shutil.rmtree(tmpdir)

    def test_generate_report_with_findings(self):
        tmpdir = tempfile.mkdtemp()
        try:
            for d in ["sqlmap", "metasploit", "hydra", "nikto", "searchsploit"]:
                os.makedirs(os.path.join(tmpdir, d), exist_ok=True)

            with open(os.path.join(tmpdir, "exploits_confirmed.csv"), "w") as f:
                f.write("status|target|tool|detail\n")
                f.write("VULNERABLE|https://t.com/api?id=1|sqlmap|level=3,risk=2\n")

            # Create a sqlmap log
            with open(os.path.join(tmpdir, "sqlmap", "abc12345_output.log"), "w") as f:
                f.write("[10:00:01] [INFO] testing URL 'https://t.com/api?id=1'\n")
                f.write("[10:00:05] [INFO] parameter 'id' is vulnerable\n")
                f.write("[10:00:06] [INFO] Type: boolean-based blind\n")
                f.write("[10:00:07] [INFO] back-end DBMS: MySQL >= 5.0\n")

            for path in ["cves_found.txt", "open_services.txt", "stiglitz_red.log", "zap_high_crit.txt"]:
                open(os.path.join(tmpdir, path), "w").close()

            report_path = generate_report(tmpdir, "t.com", "staging", 1, 1, 0, "1.0.0")
            with open(report_path) as f:
                html = f.read()

            self.assertIn("RED-001", html)
            self.assertIn("boolean", html.lower())
            self.assertIn("MySQL", html)
        finally:
            shutil.rmtree(tmpdir)


class TestIngest(unittest.TestCase):
    def setUp(self):
        self.scan_dir = tempfile.mkdtemp()
        os.makedirs(os.path.join(self.scan_dir, "raw"), exist_ok=True)

    def tearDown(self):
        shutil.rmtree(self.scan_dir)

    def _write_raw(self, name, content):
        path = os.path.join(self.scan_dir, "raw", name)
        with open(path, "w") as f:
            f.write(content)
        return path

    def test_has_injectable_param_detects_id(self):
        self.assertTrue(_has_injectable_param("https://t.com/api?id=1"))
        self.assertTrue(_has_injectable_param("https://t.com/page?user=admin"))
        self.assertTrue(_has_injectable_param("https://t.com/x?q=test&token=abc"))

    def test_has_injectable_param_rejects_safe(self):
        self.assertFalse(_has_injectable_param("https://t.com/api"))
        self.assertFalse(_has_injectable_param("https://t.com/api?color=blue"))

    def test_url_score_injectable_param_gets_higher_score(self):
        score_injectable = _url_score("https://t.com/api?id=1")
        score_plain      = _url_score("https://t.com/page")
        self.assertGreater(score_injectable, score_plain)

    def test_url_score_api_path_bonus(self):
        self.assertGreater(
            _url_score("https://t.com/api/users?id=1"),
            _url_score("https://t.com/page?id=1"),
        )

    def test_parse_nuclei_extracts_cves_from_jsonl(self):
        self._write_raw("nuclei.json",
            '{"info":{"classification":{"cve-id":["CVE-2021-44228"]}},"matched-at":"https://t.com/api?id=1"}\n'
            '{"info":{"classification":{}},"matched-at":"https://t.com/home"}\n'
        )
        items = ingest_parse_nuclei(self.scan_dir)
        self.assertEqual(len(items), 2)

    def test_parse_zap_returns_alerts(self):
        self._write_raw("zap_alerts.json", json.dumps([
            {"alert": "SQL Injection", "risk": "High", "url": "https://t.com/login?u=a"},
            {"alert": "XSS", "risk": "High", "url": "https://t.com/search"},
        ]))
        alerts = ingest_parse_zap(self.scan_dir)
        self.assertEqual(len(alerts), 2)

    def test_parse_nmap_extracts_services(self):
        self._write_raw("nmap.txt",
            "Nmap scan report for target.com\n"
            "22/tcp  open  ssh     OpenSSH 8.9\n"
            "80/tcp  open  http    nginx 1.24\n"
            "443/tcp open  https   nginx 1.24\n"
            "Not shown: 997 closed\n"
        )
        services = parse_nmap(self.scan_dir)
        self.assertEqual(len(services), 3)
        ports = [s["port"] for s in services]
        self.assertIn(22, ports)
        self.assertIn(443, ports)

    def test_parse_cves_deduplicates(self):
        self._write_raw("nuclei.json",
            '{"info":{"classification":{"cve-id":["CVE-2021-44228"]}},"matched-at":"https://t.com/a"}\n'
            '{"info":{"classification":{"cve-id":["CVE-2021-44228"]}},"matched-at":"https://t.com/b"}\n'
            '{"info":{"classification":{"cve-id":["CVE-2023-1234"]}},"matched-at":"https://t.com/c"}\n'
        )
        cves = parse_cves(self.scan_dir)
        self.assertEqual(len(cves), 2)
        self.assertIn("CVE-2021-44228", cves)
        self.assertIn("CVE-2023-1234", cves)

    def test_build_sqli_targets_scores_injectable_higher(self):
        self._write_raw("nuclei.json",
            '{"info":{"classification":{}},"matched-at":"https://t.com/api?id=1"}\n'
            '{"info":{"classification":{}},"matched-at":"https://t.com/home"}\n'
        )
        targets = build_sqli_targets(self.scan_dir, {})
        # URL with injectable param should be higher priority (appears first)
        injectable = [u for u in targets if "id=1" in u]
        plain      = [u for u in targets if "/home" in u]
        if injectable and plain:
            self.assertLess(targets.index(injectable[0]), targets.index(plain[0]))

    def test_build_brute_targets_filters_brutable_services(self):
        services = [
            {"host": "10.0.0.1", "port": 22,   "service": "ssh",   "version": ""},
            {"host": "10.0.0.1", "port": 80,   "service": "http",  "version": ""},
            {"host": "10.0.0.1", "port": 9999, "service": "unknown", "version": ""},
        ]
        targets = build_brute_targets(services)
        service_names = {t["service"] for t in targets}
        self.assertIn("ssh",  service_names)
        self.assertIn("http", service_names)
        self.assertNotIn("unknown", service_names)

    def test_build_brute_targets_deduplicates(self):
        services = [
            {"host": "10.0.0.1", "port": 22, "service": "ssh", "version": ""},
            {"host": "10.0.0.1", "port": 22, "service": "ssh", "version": "8.9"},
        ]
        targets = build_brute_targets(services)
        self.assertEqual(len(targets), 1)

    def test_ingest_creates_output_files(self):
        self._write_raw("nuclei.json",
            '{"info":{"classification":{"cve-id":["CVE-2023-1234"]}},"matched-at":"https://t.com/api?id=1"}\n'
        )
        self._write_raw("nmap.txt",
            "Nmap scan report for t.com\n22/tcp open ssh OpenSSH 8.9\n"
        )
        self._write_raw("zap_alerts.json", "[]")

        outdir = tempfile.mkdtemp()
        try:
            summary = ingest(self.scan_dir, outdir)
            self.assertIn("sqli_urls",     summary)
            self.assertIn("cves",          summary)
            self.assertIn("services",      summary)
            self.assertIn("brute_targets", summary)
            self.assertEqual(summary["cves"], 1)
            self.assertEqual(summary["services"], 1)
            self.assertTrue(os.path.exists(os.path.join(outdir, "cves_found.txt")))
            self.assertTrue(os.path.exists(os.path.join(outdir, "ingest_summary.json")))
        finally:
            shutil.rmtree(outdir)


class TestPocGenerator(unittest.TestCase):

    SQLMAP_LOG_TIME = """
[10:00:01] [INFO] testing URL 'https://target.com/api?id=1'
[10:00:05] [INFO] parameter 'id' is vulnerable
[10:00:10] [INFO] sqlmap identified the following injection point(s) with a total of 46 HTTP(s) requests:
---
Parameter: id (GET)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: id=1 AND SLEEP(5)-- -

    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1 AND 1=1-- -
---
"""

    SQLMAP_LOG_BOOL_ONLY = """
[10:00:01] [INFO] testing URL 'https://target.com/search?q=test'
[10:00:05] [INFO] parameter 'q' is vulnerable
[10:00:10] [INFO] sqlmap identified the following injection point(s):
---
Parameter: q (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind
    Payload: q=test AND 1=1-- -
---
"""

    def test_extract_payload_time_based(self):
        info = _extract_sqlmap_payload(self.SQLMAP_LOG_TIME)
        self.assertIsNotNone(info)
        self.assertEqual(info["url"],       "https://target.com/api?id=1")
        self.assertEqual(info["parameter"], "id")
        self.assertEqual(info["place"],     "GET")
        self.assertIn("time-based", info["technique"])

    def test_extract_payload_boolean_fallback(self):
        info = _extract_sqlmap_payload(self.SQLMAP_LOG_BOOL_ONLY)
        self.assertIsNotNone(info)
        self.assertEqual(info["parameter"], "q")
        self.assertIn("boolean-based", info["technique"])

    def test_extract_payload_empty_log_returns_none(self):
        self.assertIsNone(_extract_sqlmap_payload(""))
        self.assertIsNone(_extract_sqlmap_payload("no injection here"))

    def test_inject_param_replaces_existing(self):
        url = "https://t.com/api?id=1&name=foo"
        result = _inject_param(url, "id", "PAYLOAD", "GET")
        self.assertIn("id=PAYLOAD", result)
        self.assertIn("name=foo", result)

    def test_inject_param_appends_new(self):
        url = "https://t.com/api?name=foo"
        result = _inject_param(url, "id", "PAYLOAD", "GET")
        self.assertIn("id=PAYLOAD", result)

    def test_inject_param_post_returns_url_unchanged(self):
        url = "https://t.com/api"
        result = _inject_param(url, "id", "PAYLOAD", "POST")
        self.assertEqual(result, url)

    def test_collect_pocs_from_sqlmap_logs(self):
        tmpdir = tempfile.mkdtemp()
        try:
            sqlmap_dir = os.path.join(tmpdir, "sqlmap")
            os.makedirs(sqlmap_dir)
            with open(os.path.join(sqlmap_dir, "abc123_output.log"), "w") as f:
                f.write(self.SQLMAP_LOG_TIME)

            pocs = collect_pocs(tmpdir)

            self.assertGreater(len(pocs), 0)
            self.assertIn("id", pocs[0]["parameter"])
            self.assertIn("curl", pocs[0])
            self.assertIn("remediation", pocs[0])
            self.assertTrue(all(p.get("id") for p in pocs), "Todo PoC deve ter ID")
        finally:
            shutil.rmtree(tmpdir)

    def test_collect_pocs_assigns_sequential_ids(self):
        tmpdir = tempfile.mkdtemp()
        try:
            sqlmap_dir = os.path.join(tmpdir, "sqlmap")
            os.makedirs(sqlmap_dir)
            for i, log in enumerate([self.SQLMAP_LOG_TIME, self.SQLMAP_LOG_BOOL_ONLY]):
                with open(os.path.join(sqlmap_dir, f"log{i}_output.log"), "w") as f:
                    f.write(log)

            pocs = collect_pocs(tmpdir)

            ids = [p["id"] for p in pocs]
            self.assertEqual(len(ids), len(set(ids)), "IDs devem ser únicos")
        finally:
            shutil.rmtree(tmpdir)

    def test_collect_pocs_empty_dir_returns_empty(self):
        tmpdir = tempfile.mkdtemp()
        try:
            os.makedirs(os.path.join(tmpdir, "sqlmap"), exist_ok=True)
            pocs = collect_pocs(tmpdir)
            self.assertEqual(pocs, [])
        finally:
            shutil.rmtree(tmpdir)


class TestPocValidator(unittest.TestCase):
    """Lógica de confirmação/confiança — a parte mais sensível a falsos positivos."""

    def test_clamp_single_definition(self):
        import poc_validator as pv
        # Deve haver exatamente uma definição ativa, aceitando 3 args e retornando 3-tupla
        confirmed, conf, note = pv._clamp_confidence(True, 90, "ok")
        self.assertEqual((confirmed, conf, note), (True, 90, "ok"))

    def test_clamp_downgrades_low_confidence(self):
        import poc_validator as pv
        confirmed, conf, _ = pv._clamp_confidence(True, 50, "")
        self.assertFalse(confirmed, "Confiança < MIN_CONFIRM_CONFIDENCE não pode ficar confirmada")

    def test_clamp_caps_at_99(self):
        import poc_validator as pv
        _, conf, _ = pv._clamp_confidence(True, 150, "")
        self.assertEqual(conf, 99)

    def test_sanitize_nuclei_curl_function_removed(self):
        # A denylist frágil foi removida: o curl-command do Nuclei nunca é
        # confiado/encaminhado; o curl é sempre reconstruído com shlex.quote.
        import poc_validator as pv
        self.assertFalse(hasattr(pv, "_sanitize_nuclei_curl"))
        self.assertFalse(hasattr(pv, "_CMD_INJECTION_RE"))

    def test_build_safe_baseline_neutralizes_single_quote_sqli(self):
        import poc_validator as pv
        clean, safe = pv.build_safe_baseline("curl 'http://x/?id=1 OR 1=1'", "http://x")
        self.assertNotIn("OR 1=1", safe)

    def test_build_safe_baseline_neutralizes_double_quote_sqli(self):
        import poc_validator as pv
        # Antes só aspas simples eram tratadas → payload em aspas duplas era FN
        clean, safe = pv.build_safe_baseline('curl "http://x/?id=1 UNION SELECT 1"', "http://x")
        self.assertNotIn("UNION SELECT", safe)

    def test_response_diff_ignores_small_change(self):
        import poc_validator as pv
        base = "a" * 1000
        payload = "a" * 1010  # 1% — abaixo do threshold
        changed, conf, _ = pv.response_diff(pv.normalize(base), pv.normalize(payload))
        self.assertFalse(changed)

    def test_response_diff_flags_new_error_message(self):
        import poc_validator as pv
        base = "welcome home " * 20
        payload = base + " you have an SQL error in your syntax"
        changed, conf, _ = pv.response_diff(pv.normalize(base), pv.normalize(payload))
        self.assertTrue(changed)
        self.assertGreaterEqual(conf, 20, "Mensagem de erro nova é sinal forte")

    def test_sqli_size_only_diff_not_confirmed_without_doublecheck(self):
        import poc_validator as pv
        # diff só por tamanho (diff_conf=15), sem double-check → NÃO confirma (anti-FP)
        confirmed, conf, _ = pv.validate(
            "sqli", "http://x/?id=1", "resposta dinâmica", "", "200",
            diff_changed=True, diff_conf=15, diff_note="mudou 40%", dc_result=None)
        self.assertFalse(confirmed)

    def test_sqli_size_only_diff_confirmed_with_doublecheck(self):
        import poc_validator as pv
        confirmed, conf, _ = pv.validate(
            "sqli", "http://x/?id=1", "resposta", "", "200",
            diff_changed=True, diff_conf=15, diff_note="mudou 40%",
            dc_result=(True, "consistente"))
        self.assertTrue(confirmed)
        self.assertGreaterEqual(conf, 60)


class TestOOB(unittest.TestCase):
    """Confirmação Out-of-Band (lib/oob.py)."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_disabled_without_server(self):
        import oob
        # Sem INTERACTSH_SERVER no env e sem arg → sessão desabilitada.
        old = os.environ.pop("INTERACTSH_SERVER", None)
        try:
            s = oob.OOBSession()
            self.assertFalse(s.enabled)
            self.assertFalse(s.start(), "start() deve falhar sem servidor configurado")
        finally:
            if old is not None:
                os.environ["INTERACTSH_SERVER"] = old

    def test_new_payload_unique_and_scoped(self):
        import oob
        s = oob.OOBSession(out_dir=self.tmpdir)
        s.domain = "abcdef0123456789abcd.oast.test"
        t1, u1 = s.new_payload("ssrf")
        t2, u2 = s.new_payload("ssrf")
        self.assertNotEqual(t1, t2, "tokens devem ser únicos por payload")
        self.assertIn(s.domain, u1)
        self.assertTrue(u1.startswith("http://") and u1.endswith("/"))

    def test_matches_correlation(self):
        import oob
        s = oob.OOBSession(out_dir=self.tmpdir)
        s.domain = "abcdef0123456789abcd.oast.test"
        token = "ssrfdeadbeefcafe"
        interaction = {
            "protocol": "dns", "unique-id": "u1", "timestamp": "t1",
            "full-id": f"{token}.{s.domain}", "remote-address": "203.0.113.5",
            "raw-request": "",
        }
        with open(s._jsonl, "w") as f:
            f.write(json.dumps(interaction) + "\n")
        self.assertEqual(len(s.matches(token)), 1, "callback do token deve casar")
        # collect() já marcou como visto; outro token não casa em nova leitura
        self.assertEqual(s.matches("outrotoken000000"), [])

    def test_inject_ssrf_uses_candidate_param(self):
        import oob
        cmd = oob.inject_oob_url("http://alvo/api?url=orig&x=1",
                                 "http://tok.oast.test/", "ssrf")
        self.assertIsNotNone(cmd)
        self.assertIn("tok.oast.test", cmd)
        self.assertTrue(cmd.startswith("curl "))

    def test_inject_rce_blocked_in_production(self):
        import oob
        self.assertIsNone(
            oob.inject_oob_url("http://alvo/", "http://h.oast.test/", "rce", "production"))
        # lab permite
        self.assertIsNotNone(
            oob.inject_oob_url("http://alvo/", "http://h.oast.test/", "rce", "lab"))


class TestDomainFilter(unittest.TestCase):
    """Fix do _strip_www: lstrip removia caracteres soltos, quebrando o filtro."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def _run(self, urls, target):
        with open(os.path.join(self.tmpdir, "input_nuclei.jsonl"), "w") as f:
            for u in urls:
                f.write(json.dumps({"matched-at": u, "info": {"name": "x", "severity": "info"}}) + "\n")
        extract_all_urls(self.tmpdir, target)
        return open(os.path.join(self.tmpdir, "all_target_urls.txt")).read()

    def test_www_prefix_stripped_not_chars(self):
        # web.com NÃO deve virar eb.com (bug do lstrip). URL de web.com deve passar.
        content = self._run(["http://web.com/?id=1"], "web.com")
        self.assertIn("http://web.com/?id=1", content,
                      "URL do próprio domínio não pode ser descartada pelo bug do lstrip")

    def test_external_domain_excluded(self):
        content = self._run(["http://evil.com/?id=1"], "web.com")
        self.assertNotIn("evil.com", content)

    def test_www_target_matches_apex(self):
        # alvo www.example.com deve aceitar URL do apex example.com
        content = self._run(["http://example.com/?id=1"], "www.example.com")
        self.assertIn("http://example.com/?id=1", content)


if __name__ == "__main__":
    # Run with verbose output
    unittest.main(verbosity=2)

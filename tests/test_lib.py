#!/usr/bin/env python3
"""
Stiglitz RED — Testes unitários dos módulos Python.

Uso: python3 tests/test_lib.py  |  python3 -m pytest tests/test_lib.py
"""
import sys
import os
import json
import tempfile
import shutil
import unittest

# Os testes vivem em tests/; expõe a raiz do repo, lib/ e o próprio tests/
# (módulos irmãos como verify_audit) no sys.path para imports em pytest e unittest.
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
sys.path[:0] = [_ROOT, os.path.join(_ROOT, "lib"), _HERE]

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

    def test_url_in_scope_no_scope_means_open(self):
        # Sem STIGLITZ_SCOPE_DOMAINS no env, _url_in_scope permite tudo (uso standalone).
        import poc_validator as pv
        old = pv.SCOPE_DOMAINS[:]
        pv.SCOPE_DOMAINS = []
        try:
            self.assertTrue(pv._url_in_scope("http://any.external/x"))
        finally:
            pv.SCOPE_DOMAINS = old

    def test_url_in_scope_filters_external(self):
        import poc_validator as pv
        old = pv.SCOPE_DOMAINS[:]
        pv.SCOPE_DOMAINS = ["target.com"]
        try:
            self.assertTrue(pv._url_in_scope("http://target.com/?x=1"))
            self.assertTrue(pv._url_in_scope("http://api.target.com/?x=1"))  # subdomínio
            self.assertFalse(pv._url_in_scope("http://evil.com/?x=1"))
            self.assertFalse(pv._url_in_scope("not-a-url"))
        finally:
            pv.SCOPE_DOMAINS = old


class TestOAuthRefresh(unittest.TestCase):
    """oauth_refresh.py — refresh nativo de access tokens."""

    def setUp(self):
        root = os.path.dirname(os.path.abspath(__file__))
        sys.path.insert(0, os.path.join(root, "lib"))
        # Limpa env relacionado
        for k in ("STIGLITZ_OAUTH_TOKEN_URL", "STIGLITZ_OAUTH_REFRESH_TOKEN",
                  "STIGLITZ_OAUTH_CLIENT_ID", "STIGLITZ_OAUTH_CLIENT_SECRET"):
            os.environ.pop(k, None)

    def test_disabled_without_env(self):
        import oauth_refresh as oa
        self.assertFalse(oa.is_enabled())

    def test_enabled_when_env_set(self):
        import oauth_refresh as oa
        os.environ["STIGLITZ_OAUTH_TOKEN_URL"]     = "https://idp/token"
        os.environ["STIGLITZ_OAUTH_REFRESH_TOKEN"] = "rt-123"
        try:
            self.assertTrue(oa.is_enabled())
        finally:
            del os.environ["STIGLITZ_OAUTH_TOKEN_URL"]
            del os.environ["STIGLITZ_OAUTH_REFRESH_TOKEN"]

    def test_refresh_raises_without_config(self):
        import oauth_refresh as oa
        with self.assertRaises(oa.OAuthError):
            oa.refresh_access_token()

    def test_apply_to_curl_injects_header(self):
        import oauth_refresh as oa
        original = "curl -sk https://api/foo"
        out = oa.apply_to_curl(original, "tok-XYZ")
        self.assertIn("-H", out)
        self.assertIn("Authorization: Bearer tok-XYZ", out)

    def test_apply_to_curl_replaces_existing_authorization(self):
        # Authorization existente deve ser substituído, não duplicado
        import oauth_refresh as oa
        original = "curl -sk -H 'Authorization: Bearer old-token' https://api/foo"
        out = oa.apply_to_curl(original, "new-token")
        self.assertIn("Bearer new-token", out)
        self.assertNotIn("old-token", out)

    def test_apply_to_curl_noop_without_token(self):
        import oauth_refresh as oa
        original = "curl -sk https://api/foo"
        self.assertEqual(oa.apply_to_curl(original, ""), original)

    def test_refresh_uses_mock_endpoint(self):
        """Smoke test usando um mini-servidor HTTP local."""
        import oauth_refresh as oa
        from http.server import BaseHTTPRequestHandler, HTTPServer
        import threading

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(length).decode()
                if "refresh_token=rt-OK" in body:
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(b'{"access_token":"new-AT","token_type":"Bearer"}')
                else:
                    self.send_response(401)
                    self.end_headers()
            def log_message(self, *_): pass

        server = HTTPServer(("127.0.0.1", 0), Handler)
        port = server.server_address[1]
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
        try:
            os.environ["STIGLITZ_OAUTH_TOKEN_URL"] = f"http://127.0.0.1:{port}/token"
            os.environ["STIGLITZ_OAUTH_REFRESH_TOKEN"] = "rt-OK"
            tok = oa.refresh_access_token(timeout=5)
            self.assertEqual(tok, "new-AT")
            # refresh inválido → OAuthError
            os.environ["STIGLITZ_OAUTH_REFRESH_TOKEN"] = "rt-BAD"
            with self.assertRaises(oa.OAuthError):
                oa.refresh_access_token(timeout=5)
        finally:
            server.shutdown()
            for k in ("STIGLITZ_OAUTH_TOKEN_URL", "STIGLITZ_OAUTH_REFRESH_TOKEN"):
                os.environ.pop(k, None)


class TestRedBatch(unittest.TestCase):
    """stiglitz_red_batch.sh — multi-target paralelo."""

    def setUp(self):
        self.root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.script = os.path.join(self.root, "stiglitz_red_batch.sh")

    def test_script_exists_and_executable(self):
        self.assertTrue(os.path.isfile(self.script))
        self.assertTrue(os.access(self.script, os.X_OK))

    def test_help_shows_required_args(self):
        import subprocess
        r = subprocess.run(["bash", self.script, "--help"],
                           capture_output=True, text=True, timeout=10)
        self.assertEqual(r.returncode, 0)
        self.assertIn("--targets", r.stdout)
        self.assertIn("--roe", r.stdout)
        self.assertIn("--workers", r.stdout)
        self.assertIn("--profile-file", r.stdout)

    def test_missing_targets_aborts(self):
        import subprocess
        r = subprocess.run(["bash", self.script, "--roe", "/tmp/x"],
                           capture_output=True, text=True, timeout=10)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("targets", r.stdout + r.stderr)

    def test_missing_roe_aborts(self):
        import subprocess, tempfile
        tf = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False)
        tf.write("https://a.com\n"); tf.close()
        try:
            r = subprocess.run(["bash", self.script, "--targets", tf.name],
                               capture_output=True, text=True, timeout=10)
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("roe", (r.stdout + r.stderr).lower())
        finally:
            os.unlink(tf.name)


class TestTrend(unittest.TestCase):
    """stiglitz_trend.py — análise longitudinal cross-engagement."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        import stiglitz_trend as st
        self.st = st

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _mkscan(self, domain, ts, risk, findings):
        d = os.path.join(self.tmpdir, f"scan_{domain}_{ts}")
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "stiglitz_report.html"), "w") as f:
            f.write(f"<html><body>Risk Score: {risk}</body></html>")
        with open(os.path.join(d, "findings.json"), "w") as f:
            json.dump({"findings": findings}, f)
        return d

    def test_extract_timestamp_from_dir_name(self):
        d = os.path.join(self.tmpdir, "scan_alvo.com_20260301_120000")
        os.makedirs(d)
        ts = self.st._extract_timestamp(d)
        self.assertEqual(ts.year, 2026)
        self.assertEqual(ts.month, 3)
        self.assertEqual(ts.day, 1)

    def test_extract_domain_from_dir_name(self):
        self.assertEqual(
            self.st._extract_domain("scan_target.com_20260520_120000"),
            "target.com")

    def test_extract_risk_from_report(self):
        d = self._mkscan("t.com", "20260301_120000", 67, [])
        self.assertEqual(self.st._extract_risk(d), 67)

    def test_extract_stats_counts_severity(self):
        d = self._mkscan("t.com", "20260301_120000", 50,
                         [{"severity": "critical"}, {"severity": "high"},
                          {"severity": "high"}, {"severity": "low"}])
        s = self.st._extract_stats(d)
        self.assertEqual(s["critical"], 1)
        self.assertEqual(s["high"], 2)
        self.assertEqual(s["low"], 1)

    def test_collect_sorts_by_timestamp(self):
        # Cria 3 scans em ordem invertida — collect deve ordenar
        d3 = self._mkscan("t.com", "20260520_120000", 52, [])
        d1 = self._mkscan("t.com", "20260301_120000", 65, [])
        d2 = self._mkscan("t.com", "20260415_120000", 78, [])
        rows = self.st.collect([d3, d1, d2])
        self.assertEqual([r["risk"] for r in rows], [65, 78, 52])

    def test_render_html_includes_trend_deltas(self):
        d1 = self._mkscan("t.com", "20260301_120000", 65, [{"severity": "high"}])
        d2 = self._mkscan("t.com", "20260520_120000", 52, [])
        rows = self.st.collect([d1, d2])
        out = os.path.join(self.tmpdir, "trend.html")
        self.st.render_html(rows, out)
        content = open(out).read()
        self.assertIn("Stiglitz Trend", content)
        self.assertIn("t.com", content)
        # Delta -13 com sinal e cor verde (melhorou)
        self.assertIn("-13", content)
        self.assertIn("#27ae60", content)


class TestValidatorPlugins(unittest.TestCase):
    """Plug-in de validadores (lib/validators/)."""

    def setUp(self):
        root = os.path.dirname(os.path.abspath(__file__))
        sys.path.insert(0, os.path.join(root, "lib"))

    def test_registry_populated(self):
        import validators
        regs = validators.registered_types()
        self.assertIn("sqli", regs)
        self.assertIn("xss", regs)

    def test_registry_returns_callable(self):
        import validators
        fn = validators.get("sqli")
        self.assertIsNotNone(fn)
        self.assertTrue(callable(fn))

    def test_registry_unknown_returns_none(self):
        import validators
        self.assertIsNone(validators.get("not_a_type"))

    def test_sqli_plugin_error_pattern_confirms(self):
        from validators.sqli import validate as sqli_validate
        ctx = {
            "url": "http://x/", "resp_body": "You have an error in your SQL syntax",
            "resp_headers": "", "status": "500", "patterns": {"patterns": ["error in your sql"]},
            "diff_changed": False, "diff_conf": 0, "diff_note": "",
            "auth_ev": [], "dc_result": None, "dc_bonus": 0,
        }
        confirmed, conf, note = sqli_validate(ctx)
        self.assertTrue(confirmed)
        self.assertGreaterEqual(conf, 90)

    def test_sqli_plugin_size_only_diff_requires_doublecheck(self):
        # Sem double-check consistente, diff só por tamanho NÃO confirma
        from validators.sqli import validate as sqli_validate
        ctx_base = {
            "url": "http://x/", "resp_body": "", "resp_headers": "",
            "status": "200", "patterns": {"patterns": []},
            "diff_changed": True, "diff_conf": 15, "diff_note": "mudou 40%",
            "auth_ev": [], "dc_bonus": 0,
        }
        # Sem dc
        confirmed, _, _ = sqli_validate({**ctx_base, "dc_result": None})
        self.assertFalse(confirmed)
        # Com dc consistente
        confirmed, conf, _ = sqli_validate({**ctx_base, "dc_result": (True, "ok")})
        self.assertTrue(confirmed)
        self.assertGreaterEqual(conf, 60)

    def test_all_classify_types_have_plugin(self):
        """Cada vuln_type retornado por classify_vuln deve ter um plug-in
        registrado. Garante que o dispatch nunca cai no if/elif legado."""
        import validators
        # Estes são os tipos que classify_vuln() pode retornar (poc_validator.py).
        expected = {
            "sqli", "xss", "lfi", "ssrf", "cors", "jwt", "secret_aws",
            "default_login", "redirect", "takeover", "exposure",
            "auth_bypass", "security_header", "tls", "email", "generic",
        }
        regs = set(validators.registered_types())
        missing = expected - regs
        self.assertFalse(missing, f"Tipos sem plug-in: {missing}")

    def test_xss_plugin_pattern_reflection(self):
        from validators.xss import validate as xss_validate
        ctx = {
            "url": "http://x/", "resp_body": "<script>alert(1)</script>",
            "resp_headers": "", "status": "200",
            "patterns": {"patterns": [r"<script>alert\(1\)</script>"]},
            "diff_changed": False, "diff_conf": 0, "diff_note": "",
            "auth_ev": [], "dc_result": None, "dc_bonus": 0,
        }
        confirmed, conf, _ = xss_validate(ctx)
        self.assertTrue(confirmed)
        self.assertGreaterEqual(conf, 90)


class TestProfileLoader(unittest.TestCase):
    """Profile DSL JSON-Schema — lib/profile_loader.py."""

    def setUp(self):
        root = os.path.dirname(os.path.abspath(__file__))
        sys.path.insert(0, os.path.join(root, "lib"))

    def test_validates_minimum_profile(self):
        import profile_loader as pl
        out = pl.validate({"sqlmap": {"level": 3, "risk": 2}})
        self.assertEqual(out["sqlmap_level"], 3)
        self.assertEqual(out["sqlmap_risk"], 2)

    def test_rejects_out_of_range(self):
        import profile_loader as pl
        with self.assertRaises(ValueError):
            pl.validate({"sqlmap": {"level": 99}})
        with self.assertRaises(ValueError):
            pl.validate({"sqlmap": {"risk": 0}})
        with self.assertRaises(ValueError):
            pl.validate({"crawl_depth": -1})

    def test_rejects_bad_techniques(self):
        import profile_loader as pl
        with self.assertRaises(ValueError):
            pl.validate({"sqlmap": {"techniques": "INVALID"}})

    def test_rejects_invalid_name(self):
        import profile_loader as pl
        with self.assertRaises(ValueError):
            pl.validate({"name": "has spaces"})
        with self.assertRaises(ValueError):
            pl.validate({"name": "../path"})

    def test_rejects_unknown_timeout_keys(self):
        import profile_loader as pl
        with self.assertRaises(ValueError):
            pl.validate({"timeouts": {"unknown_tool": 60}})

    def test_emit_includes_declare_for_associative(self):
        """Em perfis com '-' no nome, falta de `declare -gA` causaria
        bash a tratar a chave como aritmética (eng-custom → eng - custom)."""
        import profile_loader as pl
        out = pl.validate({"sqlmap": {"level": 3}, "brute_force": False})
        bash = pl.emit_bash(out, "eng-custom")
        self.assertIn("declare -gA PROFILE_SQLMAP_LEVEL", bash)
        self.assertIn('PROFILE_SQLMAP_LEVEL["eng-custom"]="3"', bash)
        self.assertIn('PROFILE_BRUTE_FORCE["eng-custom"]="false"', bash)

    def test_emit_bool_to_bash_literal(self):
        import profile_loader as pl
        out = pl.validate({"brute_force": True, "nikto_enabled": False})
        bash = pl.emit_bash(out, "staging")
        self.assertIn('PROFILE_BRUTE_FORCE["staging"]="true"', bash)
        self.assertIn('PROFILE_NIKTO_ENABLED["staging"]="false"', bash)


class TestReportModules(unittest.TestCase):
    """Módulos lib/report/ extraídos de stiglitz_report.py."""

    def setUp(self):
        # Adiciona lib/ ao sys.path para importar lib/report/*
        root = os.path.dirname(os.path.abspath(__file__))
        sys.path.insert(0, os.path.join(root, "lib"))

    def test_cwe_enrich_known_cwe(self):
        from report.cwe_data import cwe_enrich
        r = cwe_enrich("CWE-89")
        self.assertEqual(r["sev"], "CRITICAL")
        self.assertGreaterEqual(r["cvss"], 9.0)
        # Aceita também só o número
        self.assertEqual(cwe_enrich("89"), r)

    def test_cwe_enrich_unknown_returns_none(self):
        from report.cwe_data import cwe_enrich
        self.assertIsNone(cwe_enrich(""))
        self.assertIsNone(cwe_enrich(None))
        self.assertIsNone(cwe_enrich("CWE-99999"))

    def test_cvss_to_sev_bands(self):
        from report.cwe_data import cvss_to_sev
        self.assertEqual(cvss_to_sev(9.8), "critical")
        self.assertEqual(cvss_to_sev(8.0), "high")
        self.assertEqual(cvss_to_sev(5.0), "medium")
        self.assertEqual(cvss_to_sev(1.0), "low")
        self.assertEqual(cvss_to_sev(0.0), "info")
        self.assertIsNone(cvss_to_sev(None))

    def test_sarif_structure_valid(self):
        from report.sarif import build_sarif
        findings = [
            {"name": "SQL Injection", "severity": "critical",
             "cve": "CVE-2024-1234", "url": "https://t.com/api",
             "source": "Nuclei", "description": "SQLi found"},
            {"name": "XSS",           "severity": "medium",
             "cve": "CWE-79", "url": "https://t.com/search",
             "source": "ZAP"},
        ]
        s = build_sarif(findings, "https://t.com")
        self.assertEqual(s["version"], "2.1.0")
        self.assertEqual(len(s["runs"]), 1)
        self.assertEqual(s["runs"][0]["tool"]["driver"]["name"], "Stiglitz")
        self.assertEqual(len(s["runs"][0]["results"]), 2)
        # Regras únicas por CVE/CWE
        rule_ids = [r["id"] for r in s["runs"][0]["tool"]["driver"]["rules"]]
        self.assertIn("CVE-2024-1234", rule_ids)
        self.assertIn("CWE-79", rule_ids)

    def test_sarif_levels_match_severity(self):
        from report.sarif import build_sarif
        findings = [
            {"name": "A", "severity": "critical", "url": "x"},
            {"name": "B", "severity": "high",     "url": "x"},
            {"name": "C", "severity": "medium",   "url": "x"},
            {"name": "D", "severity": "low",      "url": "x"},
            {"name": "E", "severity": "info",     "url": "x"},
        ]
        s = build_sarif(findings, "x")
        levels = [r["level"] for r in s["runs"][0]["results"]]
        self.assertEqual(levels, ["error", "error", "warning", "note", "none"])

    def test_sarif_falls_back_to_target_when_url_missing(self):
        from report.sarif import build_sarif
        findings = [{"name": "X", "severity": "high"}]  # sem url
        s = build_sarif(findings, "https://target.com")
        loc = s["runs"][0]["results"][0]["locations"][0]
        self.assertEqual(loc["physicalLocation"]["artifactLocation"]["uri"],
                         "https://target.com")

    def test_exec_summary_renders(self):
        from report.exec_summary import build_exec_summary
        html_out = build_exec_summary(
            target="https://target.com", domain="target.com",
            risk=85, risk_label="CRITICAL — Immediate Action",
            timestamp="28/05/2026 09:00",
            stats={"critical": 2, "high": 5, "medium": 3, "low": 1},
            findings=[
                {"name": "SQLi", "severity": "critical",
                 "impact": "DB takeover", "remediation": "Prepared stmts"},
                {"name": "XSS", "severity": "high",
                 "impact": "Session hijack", "remediation": "Escape output"},
            ],
            kev_matches={"CVE-2021-44228": {}},
        )
        # Estrutura básica
        self.assertIn("<!DOCTYPE html>", html_out)
        self.assertIn("target.com", html_out)
        self.assertIn("85/100", html_out)
        self.assertIn("CRITICAL", html_out)
        # KEV alert deve aparecer
        self.assertIn("Active Exploitation", html_out)
        self.assertIn("CVE-2021-44228", html_out)
        # Top vulns aparecem com seus nomes (escapados)
        self.assertIn("SQLi", html_out)
        self.assertIn("XSS", html_out)

    def test_exec_summary_escapes_target(self):
        # XSS via target name não pode injetar markup no exec summary
        from report.exec_summary import build_exec_summary
        html_out = build_exec_summary(
            target="<script>alert(1)</script>", domain="x",
            risk=10, risk_label="LOW", timestamp="t",
            stats={"critical": 0, "high": 0, "medium": 0, "low": 0},
            findings=[],
        )
        self.assertNotIn("<script>alert(1)</script>", html_out)
        self.assertIn("&lt;script&gt;", html_out)

    def test_sarif_helpuri_only_for_cves(self):
        from report.sarif import build_sarif
        findings = [
            {"name": "X", "severity": "high", "cve": "CVE-2024-1234", "url": "x"},
            {"name": "Y", "severity": "high",                          "url": "x"},
        ]
        s = build_sarif(findings, "x")
        rules = {r["id"]: r for r in s["runs"][0]["tool"]["driver"]["rules"]}
        self.assertIn("helpUri", rules["CVE-2024-1234"])
        self.assertIn("nvd.nist.gov", rules["CVE-2024-1234"]["helpUri"])
        # Findings sem CVE não devem ter helpUri
        non_cve = [rid for rid in rules if not rid.startswith("CVE-")]
        self.assertGreater(len(non_cve), 0)
        for rid in non_cve:
            self.assertNotIn("helpUri", rules[rid])


class TestAuditChain(unittest.TestCase):
    """Hash chain do audit trail — verify_audit.py detecta adulteração."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.script = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                   "verify_audit.py")
        # Importa o verificador como módulo
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        import verify_audit
        self.va = verify_audit

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _build_chain(self, events, seed="seed1234"):
        """Constrói um audit.log válido a partir de uma lista de eventos."""
        path = os.path.join(self.tmpdir, "audit.log")
        prev = seed
        ts = "2026-05-28T12:00:00Z"
        with open(path, "w") as f:
            init_event = f"AUDIT_INIT seed={seed}"
            h = self.va._h(seed, ts, init_event)
            f.write(f"0000 | {ts} | {init_event} | {seed}:{h}\n")
            prev = h
            for i, ev in enumerate(events, start=1):
                h = self.va._h(prev, ts, ev)
                f.write(f"{i:04d} | {ts} | {ev} | {prev}:{h}\n")
                prev = h
        return path

    def test_valid_chain_verifies(self):
        path = self._build_chain(["PROFILE=lab", "AUTHORIZED via=interactive"])
        ok, msg = self.va.verify(path)
        self.assertTrue(ok, f"chain válida deveria passar: {msg}")
        self.assertIn("3 entradas", msg)

    def test_tampered_event_detected(self):
        path = self._build_chain(["PROFILE=lab", "AUTHORIZED via=interactive"])
        # Altera o evento da segunda linha sem recalcular hashes
        with open(path) as f:
            lines = f.readlines()
        lines[1] = lines[1].replace("PROFILE=lab", "PROFILE=production")
        with open(path, "w") as f:
            f.writelines(lines)
        ok, msg = self.va.verify(path)
        self.assertFalse(ok)
        self.assertIn("curr_hash diverge", msg)

    def test_reordered_lines_detected(self):
        path = self._build_chain(["EV_A", "EV_B", "EV_C"])
        with open(path) as f:
            lines = f.readlines()
        # Swap linha 1 e 2
        lines[1], lines[2] = lines[2], lines[1]
        with open(path, "w") as f:
            f.writelines(lines)
        ok, msg = self.va.verify(path)
        self.assertFalse(ok)

    def test_empty_log_fails(self):
        path = os.path.join(self.tmpdir, "empty.log")
        open(path, "w").close()
        ok, msg = self.va.verify(path)
        self.assertFalse(ok)
        self.assertIn("vazio", msg)


class TestRiskScore(unittest.TestCase):
    """Risk score — valores absolutos (antes só havia checagens relacionais)."""

    def _stats(self, c=0, h=0, m=0, l=0):
        return {"critical": c, "high": h, "medium": m, "low": l, "info": 0}

    def test_empty_is_zero(self):
        from risk_score import compute_risk
        r = compute_risk(self._stats(), {}, [], [])
        self.assertEqual(r["risk"], 0)
        self.assertEqual(r["base_risk"], 0)
        self.assertEqual(r["kev_bonus"], 0)

    def test_only_low_is_low_band(self):
        from risk_score import compute_risk
        r = compute_risk(self._stats(l=2), {}, [], [])
        # floor=5 + qty=1 → base=6; sem bônus → 6 (< 15 = BAIXO)
        self.assertEqual(r["risk"], 6)

    def test_one_medium_is_medium_band(self):
        from risk_score import compute_risk
        r = compute_risk(self._stats(m=1), {}, [], [])
        # floor=15 + qty=1 → base=16
        self.assertEqual(r["base_risk"], 16)
        self.assertEqual(r["risk"], 16)

    def test_high_finding_stays_below_70_without_critical_or_kev(self):
        # Cap da banda CRÍTICA — sem severidade crítica nem KEV, risk <= 69
        from risk_score import compute_risk
        r = compute_risk(self._stats(h=10), {}, [], [])
        self.assertLessEqual(r["risk"], 69, "Não pode virar CRÍTICO sem crítico/KEV")

    def test_critical_finding_reaches_critical_band(self):
        from risk_score import compute_risk
        r = compute_risk(self._stats(c=1, h=1), {}, [], [])
        # floor=70 + qty=(6+3)=9 → base=79
        self.assertEqual(r["base_risk"], 79)
        self.assertEqual(r["risk"], 79)
        self.assertGreaterEqual(r["risk"], 70)

    def test_kev_bonus_capped_at_50(self):
        from risk_score import compute_risk
        cves = {f"CVE-2024-{i}": {"in_kev": True} for i in range(10)}
        r = compute_risk(self._stats(h=1), cves, [], [])
        self.assertEqual(r["kev_count"], 10)
        self.assertEqual(r["kev_bonus"], 50, "KEV capado em +50 mesmo com 10 CVEs")

    def test_kev_alone_promotes_to_critical_band(self):
        # 1 CVE no KEV (sem severidade crítica): floor=high(40)+qty=3=43, +kev=25 → 68
        # Mas o teto de 69 NÃO se aplica quando kev_count > 0 → pode passar
        from risk_score import compute_risk
        cves = {"CVE-2024-1": {"in_kev": True}}
        r = compute_risk(self._stats(h=1), cves, [], [])
        self.assertEqual(r["kev_count"], 1)
        # base=43 + kev=25 = 68 → ainda na banda ALTO; mas SEM o cap em 69.
        # Adicionando mais um KEV chegaria ao crítico:
        cves2 = {f"CVE-2024-{i}": {"in_kev": True} for i in range(2)}
        r2 = compute_risk(self._stats(h=5), cves2, [], [])
        # base=40+qty=15=55, +kev=50 → 105 → cap 100 → CRÍTICO
        self.assertGreaterEqual(r2["risk"], 70)

    def test_epss_bonus_capped_at_30(self):
        from risk_score import compute_risk
        cves = {f"CVE-2024-{i}": {"epss_score": 0.9} for i in range(10)}
        # Cada CVE com EPSS>=0.5 dá +15; 10 daria 150 → cap em 30
        r = compute_risk(self._stats(m=1), cves, [], [])
        self.assertEqual(r["epss_bonus"], 30)

    def test_js_secrets_only_cannot_fabricate_critical(self):
        # Muitos secrets JS sem severidade crítica e sem KEV → cap em 69
        from risk_score import compute_risk
        secrets = [{"type": "AWS Access Key"}] * 5 + [{"type": "Hardcoded Password"}] * 5
        r = compute_risk(self._stats(m=2), {}, secrets, [])
        self.assertLessEqual(r["risk"], 69)

    def test_js_bonus_capped_at_30(self):
        from risk_score import compute_risk
        secrets = [{"type": "AWS Access Key"}] * 20  # 20*15=300 → cap 30
        r = compute_risk(self._stats(m=1), {}, secrets, [])
        self.assertEqual(r["js_bonus"], 30)


class TestFindingShape(unittest.TestCase):
    """Garante que findings emitidos pelos lib/*.py usam o schema canônico
    (name/description) — observado em scan real onde secscan.py emitia
    title/detail e o agregador entregava finding vazio no relatório."""

    def setUp(self):
        self.root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    def test_secscan_emits_name_description_not_title_detail(self):
        path = os.path.join(self.root, "lib", "secscan.py")
        with open(path) as f:
            content = f.read()
        self.assertNotIn('"title":', content,
                         "secscan.py deve usar 'name', não 'title'")
        self.assertNotIn('"detail":', content,
                         "secscan.py deve usar 'description', não 'detail'")
        self.assertIn('"name":', content)
        self.assertIn('"description":', content)

    def test_all_lib_findings_use_canonical_schema(self):
        """Verifica que todos os módulos *_findings usam name/description."""
        files = ["secscan.py", "version_fingerprint.py",
                 "monitoring_check.py", "ratelimit_check.py"]
        for fname in files:
            path = os.path.join(self.root, "lib", fname)
            if not os.path.exists(path):
                continue
            with open(path) as f:
                content = f.read()
            # Se o arquivo emite findings (tem .append( com dict), checa schema
            if 'findings.append' in content or 'findings.append(' in content:
                self.assertIn('"name":', content,
                              f"{fname} deve usar 'name' nos findings")


class TestProductionProfile(unittest.TestCase):
    """Asserts que o perfil production aplica restrições reais nos scripts."""

    def setUp(self):
        self.root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    def test_sqli_production_uses_readonly_techniques(self):
        # lib/sqli.sh em production NUNCA pode emitir stacked queries (S)
        with open(os.path.join(self.root, "lib", "sqli.sh")) as f:
            content = f.read()
        # Deve existir um case por perfil com a flag --technique adequada
        self.assertIn('production) technique="BEU"', content,
                      "Production deve usar técnicas read-only (BEU, sem S/T)")
        self.assertIn('staging)    technique="BEUT"', content,
                      "Staging não deve incluir stacked (S)")
        # E o template do sqlmap deve usar a variável $technique
        self.assertIn('--technique="$technique"', content)

    def test_msf_production_uses_check_only(self):
        # lib/msf.sh com payload NONE deve emitir `check` (não `run -j`)
        with open(os.path.join(self.root, "lib", "msf.sh")) as f:
            content = f.read()
        self.assertIn('check_only=true', content)
        self.assertIn('echo "check"', content,
                      "Modo check-only deve emitir `check` no RC do msf")
        # E auxiliares devem ser pulados em check-only
        self.assertIn("[[ \"$mod\" == exploit/* ]] || continue", content,
                      "Auxiliares devem ser pulados em check-only")

    def test_red_orchestrator_validates_scope_domains(self):
        # stiglitz_red.sh valida cada SCOPE_DOMAIN com regex (anti-injeção)
        with open(os.path.join(self.root, "stiglitz_red.sh")) as f:
            content = f.read()
        self.assertIn("Domínio de escopo inválido", content)
        self.assertIn("--roe", content)

    def test_red_gate_requires_roe_for_bypass(self):
        # stiglitz_red.sh: bypass via STIGLITZ_AUTHORIZED exige --roe
        with open(os.path.join(self.root, "stiglitz_red.sh")) as f:
            content = f.read()
        self.assertIn("Bypass do orquestrador requer --roe", content)

    def test_pci_active_controls_phase_present(self):
        # pci_scan.sh: fase 7.5 emite EVIDÊNCIA ATIVA para Reqs 2/4/8/10/12
        # em vez de inferir conformidade da ausência de findings.
        # NOTA: pci_scan.sh é gitignored (versionado separadamente) — pula
        # quando ausente para permitir checkout limpo do repo público.
        pci = os.path.join(self.root, "pci_scan.sh")
        if not os.path.exists(pci):
            self.skipTest("pci_scan.sh ausente (gitignored neste repo)")
        with open(pci) as f:
            content = f.read()
        self.assertIn("CONTROLES PCI ATIVOS", content)
        self.assertIn("default-creds-probe", content,
                      "Req 2: probe ativo de credenciais default")
        self.assertIn("mfa-presence-probe", content,
                      "Req 8: heurística de MFA")
        self.assertIn("logging-headers-probe", content,
                      "Req 10: presença de headers de correlação")
        self.assertIn("tls-legacy-probe", content,
                      "Req 4: TLS 1.0/1.1 deve ser recusado")
        self.assertIn("security-txt-probe", content,
                      "Req 12.10: security.txt (RFC 9116)")
        # Multi-target: itera WEB_TARGETS com cap
        self.assertIn("PCI_ACTIVE_TARGETS_MAX", content)


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
        cmds = oob.inject_oob_url("http://alvo/api?url=orig&x=1",
                                  "http://tok.oast.test/", "ssrf")
        self.assertEqual(len(cmds), 1, "SSRF gera um único payload")
        self.assertIn("tok.oast.test", cmds[0])
        self.assertTrue(cmds[0].startswith("curl "))

    def test_inject_rce_blocked_in_production(self):
        import oob
        self.assertEqual(
            oob.inject_oob_url("http://alvo/", "http://h.oast.test/", "rce", "production"),
            [])
        cmds = oob.inject_oob_url("http://alvo/", "http://h.oast.test/", "rce", "lab")
        self.assertEqual(len(cmds), 1)

    def test_inject_ssti_emits_multiple_engines(self):
        # SSTI dispara payloads para várias engines (Log4j, Jinja2, Twig,
        # ERB, Velocity, Smarty, SpEL, FreeMarker). Qualquer callback confirma.
        import oob
        cmds = oob.inject_oob_url("http://alvo/?p=x", "http://h.oast.test/", "ssti", "lab")
        self.assertGreaterEqual(len(cmds), 5, "Várias engines SSTI devem ser cobertas")
        joined = "\n".join(cmds)
        self.assertIn("jndi:ldap", joined, "Log4j")
        self.assertIn("__subclasses__", joined, "Jinja2 / Python")
        self.assertIn("Runtime", joined, "SpEL / Velocity")
        # Todos apontam para o host OOB
        for c in cmds:
            self.assertIn("h.oast.test", c)

    def test_inject_ssti_blocked_in_production(self):
        import oob
        self.assertEqual(
            oob.inject_oob_url("http://alvo/?p=x", "http://h.oast.test/",
                               "ssti", "production"),
            [])


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

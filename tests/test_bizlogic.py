#!/usr/bin/env python3
"""Testes do módulo de lógica de negócio/authz (bizlogic)."""
import json
import os
import re
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
sys.path[:0] = [_ROOT, os.path.join(_ROOT, "lib")]


class _App(BaseHTTPRequestHandler):
    seen_keys = set()
    lock = threading.Lock()
    transfers = 0
    balance = 0.01  # saldo finito do endpoint seguro: cobre exatamente 1 sentinela
    nicknames = {}  # id -> nickname; estado mutável p/ testar idor_write via re-leitura
    admin_actions = 0  # conta ações mutantes em /vuln/admin (prova de envio real)

    def log_message(self, *a):
        pass

    def _send(self, code, obj):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(obj).encode())

    def _body(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length) if length else b"{}"
        try:
            return json.loads(raw or b"{}")
        except ValueError:
            return {}

    def do_GET(self):
        p = self.path
        if p.startswith("/vuln/accounts/"):
            acct = p.rsplit("/", 1)[1]
            return self._send(200, {"owner": acct, "balance": 100,
                                    "nickname": type(self).nicknames.get(acct, "")})
        if p.startswith("/safe/accounts/"):
            acct = p.rsplit("/", 1)[1]
            if self.headers.get("X-Acct") == acct:
                return self._send(200, {"owner": acct, "balance": 100,
                                        "nickname": type(self).nicknames.get(acct, "")})
            return self._send(403, {"error": "forbidden"})
        if p == "/vuln/admin":
            return self._send(200, {"users": ["u1", "u2"]})
        if p == "/safe/admin":
            if self.headers.get("X-Admin") == "1":
                return self._send(200, {"users": ["u1", "u2"]})
            return self._send(403, {"error": "forbidden"})
        return self._send(404, {})

    def do_PUT(self):
        body = self._body()
        p = self.path
        # IDOR write: /vuln muta sem checar dono; /safe só o dono (X-Acct == id).
        if p.startswith("/vuln/accounts/"):
            acct = p.rsplit("/", 1)[1]
            type(self).nicknames[acct] = body.get("nickname", "")
            return self._send(200, {"status": "updated", "owner": acct})
        if p.startswith("/safe/accounts/"):
            acct = p.rsplit("/", 1)[1]
            if self.headers.get("X-Acct") != acct:
                return self._send(403, {"error": "forbidden"})
            type(self).nicknames[acct] = body.get("nickname", "")
            return self._send(200, {"status": "updated", "owner": acct})
        # /vuln/admin via método privilegiado mutante (POST/PUT): aceita → privesc mutante
        if p == "/vuln/admin":
            type(self).admin_actions += 1
            return self._send(200, {"status": "admin-action-done"})
        return self._send(404, {})

    def do_POST(self):
        body = self._body()
        p = self.path
        if p == "/vuln/transfer":
            type(self).transfers += 1
            return self._send(200, {"status": "done"})
        if p == "/trap/transfer":
            # Validação no CORPO, não no status: HTTP 200 + {"error": ...}.
            return self._send(200, {"error": "invalid amount"})
        if p == "/vuln/admin":
            type(self).admin_actions += 1
            return self._send(200, {"status": "admin-action-done"})
        if p == "/safe/transfer":
            amt = body.get("amount")
            # Endpoint seguro: exige decimal monetário positivo com até 2 casas.
            # Rejeita negativos, zero, sub-centavos, notação científica e não-numéricos.
            if not (isinstance(amt, str) and re.fullmatch(r"\d+(\.\d{1,2})?", amt)
                    and float(amt) > 0):
                return self._send(400, {"error": "invalid amount"})
            value = float(amt)
            key = self.headers.get("Idempotency-Key")
            # Débito atômico: idempotência (replay) + saldo finito (race) sob lock.
            with type(self).lock:
                if key and key in type(self).seen_keys:
                    return self._send(409, {"error": "duplicate"})
                if value > type(self).balance:
                    return self._send(409, {"error": "insufficient funds"})
                type(self).balance -= value
                if key:
                    type(self).seen_keys.add(key)
                type(self).transfers += 1
            return self._send(200, {"status": "done"})
        return self._send(404, {})


class AppTestCase(unittest.TestCase):
    def setUp(self):
        _App.seen_keys = set()
        _App.transfers = 0
        _App.balance = 0.01
        _App.nicknames = {}
        _App.admin_actions = 0
        self.srv = HTTPServer(("127.0.0.1", 0), _App)
        self.base = f"http://127.0.0.1:{self.srv.server_address[1]}"
        self.t = threading.Thread(target=self.srv.serve_forever, daemon=True)
        self.t.start()

    def tearDown(self):
        self.srv.shutdown()

VALID_CFG = {
    "base_url": "http://localhost:0",
    "accounts": {
        "A": {"auth": {"type": "bearer", "token": "ta"}, "id": "1"},
        "B": {"auth": {"type": "bearer", "token": "tb"}, "id": "2"},
    },
    "sentinel": {"amount": "0.01", "recipient": "test-rcpt"},
    "endpoints": [
        {"name": "get_acct", "method": "GET", "path": "/api/accounts/{id}",
         "owner_param": "id", "object_of": "A", "tests": ["idor_read"]},
    ],
}


class TestConfig(unittest.TestCase):
    def test_load_json(self):
        import bizlogic
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(VALID_CFG, f)
            path = f.name
        cfg = bizlogic.load_config(path)
        self.assertEqual(cfg["base_url"], "http://localhost:0")
        os.unlink(path)

    def test_missing_required_raises(self):
        import bizlogic
        with self.assertRaises(ValueError):
            bizlogic.validate_config({"base_url": "x"})  # sem accounts/endpoints

    def test_validate_ok(self):
        import bizlogic
        bizlogic.validate_config(VALID_CFG)  # não levanta


class TestAuth(unittest.TestCase):
    def test_bearer(self):
        import bizlogic
        h = bizlogic.auth_headers({"auth": {"type": "bearer", "token": "abc"}})
        self.assertEqual(h["Authorization"], "Bearer abc")

    def test_cookie(self):
        import bizlogic
        h = bizlogic.auth_headers({"auth": {"type": "cookie", "cookie": "s=1"}})
        self.assertEqual(h["Cookie"], "s=1")

    def test_header(self):
        import bizlogic
        h = bizlogic.auth_headers({"auth": {"type": "header", "headers": {"X-Auth": "k"}}})
        self.assertEqual(h["X-Auth"], "k")

    def test_unknown_type_raises(self):
        import bizlogic
        with self.assertRaises(ValueError):
            bizlogic.auth_headers({"auth": {"type": "magic"}})


class TestHttp(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from http.server import BaseHTTPRequestHandler, HTTPServer

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass
            def do_GET(self):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'{"ok":true}')
        cls.srv = HTTPServer(("127.0.0.1", 0), H)
        cls.port = cls.srv.server_address[1]
        cls.t = threading.Thread(target=cls.srv.serve_forever, daemon=True)
        cls.t.start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def test_http_request_returns_status_and_body(self):
        import bizlogic
        r = bizlogic.http_request("GET", f"http://127.0.0.1:{self.port}/x", {}, None)
        self.assertEqual(r.status, 200)
        self.assertIn("ok", r.body)


class TestEquivalence(unittest.TestCase):
    def test_same_json_equivalent(self):
        import bizlogic
        self.assertTrue(bizlogic.responses_equivalent('{"a":1,"b":2}', '{"a":1,"b":2}'))

    def test_dynamic_tokens_ignored(self):
        import bizlogic
        a = '{"a":1,"ts":"2026-01-01T00:00:00","req_id":"x1"}'
        b = '{"a":1,"ts":"2026-06-06T12:00:00","req_id":"x2"}'
        self.assertTrue(bizlogic.responses_equivalent(a, b))

    def test_different_data_not_equivalent(self):
        import bizlogic
        self.assertFalse(bizlogic.responses_equivalent('{"owner":"A","x":1}',
                                                       '{"owner":"B","x":9}'))


class TestIdorRead(AppTestCase):
    def _cfg(self, path):
        return {
            "base_url": self.base,
            "accounts": {"A": {"auth": {"type": "header", "headers": {"X-Acct": "A"}}, "id": "A"},
                          "B": {"auth": {"type": "header", "headers": {"X-Acct": "B"}}, "id": "B"}},
            "endpoints": [{"name": "acct", "method": "GET", "path": path,
                           "owner_param": "id", "object_of": "A", "tests": ["idor_read"]}],
        }

    def test_vulnerable_endpoint_confirms(self):
        import bizlogic
        cfg = self._cfg("/vuln/accounts/{id}")
        f = bizlogic.test_idor_read(cfg, cfg["endpoints"][0])
        self.assertIsNotNone(f)
        self.assertTrue(f["confirmed"])
        self.assertEqual(f["vuln_class"], "idor_read_pii")

    def test_safe_endpoint_no_finding(self):
        import bizlogic
        cfg = self._cfg("/safe/accounts/{id}")
        f = bizlogic.test_idor_read(cfg, cfg["endpoints"][0])
        self.assertIsNone(f)


class TestPrivesc(AppTestCase):
    def _cfg(self, path):
        return {"base_url": self.base,
                "accounts": {"A": {"auth": {"type": "header", "headers": {}}, "id": "A"}},
                "endpoints": [{"name": "admin", "method": "GET", "path": path,
                               "tests": ["privesc"]}]}

    def test_vuln_admin_confirms(self):
        import bizlogic
        cfg = self._cfg("/vuln/admin")
        f = bizlogic.test_privesc(cfg, cfg["endpoints"][0], actor="A")
        self.assertIsNotNone(f)
        self.assertEqual(f["vuln_class"], "priv_escalation")

    def test_safe_admin_no_finding(self):
        import bizlogic
        cfg = self._cfg("/safe/admin")
        self.assertIsNone(bizlogic.test_privesc(cfg, cfg["endpoints"][0], actor="A"))


class TestAmount(AppTestCase):
    def _cfg(self, path):
        return {"base_url": self.base,
                "accounts": {"A": {"auth": {"type": "header", "headers": {}}, "id": "A"}},
                "sentinel": {"amount": "0.01", "recipient": "r"},
                "endpoints": [{"name": "transfer", "method": "POST", "path": path,
                               "body": {"amount": "{amount}", "to": "{recipient}"},
                               "money_params": ["amount"], "tests": ["amount_tampering"]}]}

    def test_vuln_transfer_confirms(self):
        import bizlogic
        cfg = self._cfg("/vuln/transfer")
        f = bizlogic.test_amount_tampering(cfg, cfg["endpoints"][0], actor="A",
                                           mutate_allowed=True, dry_run=False)
        self.assertIsNotNone(f)
        self.assertEqual(f["vuln_class"], "amount_tampering")

    def test_safe_transfer_no_finding(self):
        import bizlogic
        cfg = self._cfg("/safe/transfer")
        self.assertIsNone(bizlogic.test_amount_tampering(cfg, cfg["endpoints"][0],
                          actor="A", mutate_allowed=True, dry_run=False))

    def test_dry_run_does_not_confirm(self):
        import bizlogic
        cfg = self._cfg("/vuln/transfer")
        f = bizlogic.test_amount_tampering(cfg, cfg["endpoints"][0], actor="A",
                                           mutate_allowed=False, dry_run=True)
        self.assertFalse(f["confirmed"])


class TestRaceIdem(AppTestCase):
    def _cfg(self, path):
        return {"base_url": self.base,
                "accounts": {"A": {"auth": {"type": "header", "headers": {}}, "id": "A"}},
                "sentinel": {"amount": "0.01", "recipient": "r"},
                "endpoints": [{"name": "transfer", "method": "POST", "path": path,
                               "body": {"amount": "{amount}", "to": "{recipient}"},
                               "idempotency_header": "Idempotency-Key",
                               "tests": ["race", "idempotency"]}]}

    def test_race_vuln_confirms(self):
        import bizlogic
        cfg = self._cfg("/vuln/transfer")
        f = bizlogic.test_race(cfg, cfg["endpoints"][0], actor="A", workers=5,
                               mutate_allowed=True, dry_run=False)
        self.assertIsNotNone(f)
        self.assertEqual(f["vuln_class"], "race_condition_funds")

    def test_race_safe_no_finding(self):
        import bizlogic
        cfg = self._cfg("/safe/transfer")
        self.assertIsNone(bizlogic.test_race(cfg, cfg["endpoints"][0], actor="A",
                          workers=5, mutate_allowed=True, dry_run=False))

    def test_idempotency_vuln_confirms(self):
        import bizlogic
        cfg = self._cfg("/vuln/transfer")
        f = bizlogic.test_idempotency(cfg, cfg["endpoints"][0], actor="A",
                                      mutate_allowed=True, dry_run=False)
        self.assertIsNotNone(f)

    def test_idempotency_safe_no_finding(self):
        import bizlogic
        cfg = self._cfg("/safe/transfer")
        self.assertIsNone(bizlogic.test_idempotency(cfg, cfg["endpoints"][0],
                          actor="A", mutate_allowed=True, dry_run=False))


class TestRun(AppTestCase):
    def _cfg(self):
        return {"base_url": self.base,
                "accounts": {"A": {"auth": {"type": "header", "headers": {"X-Acct": "A"}}, "id": "A"},
                              "B": {"auth": {"type": "header", "headers": {"X-Acct": "B"}}, "id": "B"}},
                "sentinel": {"amount": "0.01", "recipient": "r"},
                "endpoints": [{"name": "acct", "method": "GET", "path": "/vuln/accounts/{id}",
                               "owner_param": "id", "object_of": "A", "tests": ["idor_read"]}]}

    def test_run_emits_findings(self):
        import bizlogic
        host = self.base.split("://", 1)[1].split(":")[0]
        findings = bizlogic.run(self._cfg(), profile="staging", scope=[host])
        self.assertTrue(any(f["vuln_class"] == "idor_read_pii" for f in findings))

    def test_run_blocks_out_of_scope(self):
        import bizlogic
        findings = bizlogic.run(self._cfg(), profile="staging", scope=["other.example.com"])
        self.assertEqual(findings, [])  # host fora de escopo → nada executado

    def test_production_does_not_mutate(self):
        import bizlogic
        cfg = self._cfg()
        cfg["endpoints"] = [{"name": "t", "method": "POST", "path": "/vuln/transfer",
                             "body": {"amount": "{amount}", "to": "{recipient}"},
                             "money_params": ["amount"], "tests": ["amount_tampering"]}]
        host = self.base.split("://", 1)[1].split(":")[0]
        findings = bizlogic.run(cfg, profile="production", scope=[host])
        # production → dry-run: finding presente mas não confirmado
        self.assertTrue(all(not f["confirmed"] for f in findings))


class TestIngest(unittest.TestCase):
    def test_parse_bizlogic_reads_file(self):
        import ingest
        import tempfile
        d = tempfile.mkdtemp()
        os.makedirs(os.path.join(d, "raw"))
        with open(os.path.join(d, "raw", "bizlogic.json"), "w") as f:
            json.dump([{"name": "x", "vuln_class": "idor_read_pii", "url": "http://h/a",
                        "confirmed": True, "severity": "high"}], f)
        out = ingest.parse_bizlogic(d)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["vuln_class"], "idor_read_pii")


class TestCriticalityIntegration(unittest.TestCase):
    def test_confirmed_bizlogic_finding_scored_high_on_funds(self):
        import criticality
        findings = [{"name": "IDOR write", "vuln_class": "idor_write", "severity": "high",
                     "url": "https://payments-gateway.staging.example.com/api/transfer",
                     "confirmed": True}]
        criticality.enrich_findings(findings)
        f = findings[0]
        self.assertIn("cvss_environmental", f)
        self.assertEqual(f["asset_class"], "funds")
        self.assertIn(f["severity"], ("high", "critical"))
        self.assertEqual(f["score_source"], "catalog")


class TestYamlConfig(unittest.TestCase):
    def test_load_yaml(self):
        import bizlogic
        import tempfile
        y = ("base_url: http://localhost:1\n"
             "accounts: {A: {auth: {type: bearer, token: t}, id: '1'}}\n"
             "endpoints: [{name: e, method: GET, path: /x, tests: [idor_read]}]\n")
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
            f.write(y); path = f.name
        cfg = bizlogic.load_config(path)
        self.assertEqual(cfg["base_url"], "http://localhost:1")
        os.unlink(path)


class TestGateAndCli(unittest.TestCase):
    def test_roe_gate_blocks_non_interactive(self):
        import bizlogic
        self.assertFalse(bizlogic.roe_gate(assume_yes=False, interactive=False))

    def test_roe_gate_assume_yes(self):
        import bizlogic
        self.assertTrue(bizlogic.roe_gate(assume_yes=True))

    def test_parse_args_defaults(self):
        import bizlogic
        a = bizlogic.parse_args(["--config", "c.json", "--profile", "staging"])
        self.assertEqual(a.profile, "staging")
        self.assertFalse(a.roe_accept)


class TestTamperAndRace(unittest.TestCase):
    def test_tamper_variations_cover_cases(self):
        import bizlogic
        base = {"amount": "{amount}", "to": "{recipient}"}
        vs = bizlogic.tamper_variations(base, ["amount"], {"amount": "0.01", "recipient": "r"})
        amounts = [v["amount"] for v in vs]
        self.assertIn("-0.01", amounts)       # negativo
        self.assertIn("0", amounts)           # zero
        self.assertIn("0.001", amounts)       # casas extras
        self.assertTrue(any(a == "1e9" or a == "1000000000" for a in amounts))  # overflow
        for v in vs:
            self.assertEqual(v["to"], "r")    # placeholders resolvidos

    def test_detect_double_spend(self):
        import bizlogic
        self.assertTrue(bizlogic.detect_double_spend([200, 200, 409], allowed=1))
        self.assertFalse(bizlogic.detect_double_spend([200, 409, 409], allowed=1))


# ── Correções da revisão adversarial ────────────────────────────────────────

class TestValidateAccountsType(unittest.TestCase):
    def test_accounts_as_list_raises_valueerror(self):
        import bizlogic
        cfg = {"base_url": "http://x", "accounts": ["A", "B"],
               "endpoints": [{"name": "e", "method": "GET", "path": "/x", "tests": []}]}
        with self.assertRaises(ValueError):
            bizlogic.validate_config(cfg)

    def test_account_not_object_raises(self):
        import bizlogic
        cfg = {"base_url": "http://x", "accounts": {"A": "nope"},
               "endpoints": [{"name": "e", "method": "GET", "path": "/x", "tests": []}]}
        with self.assertRaises(ValueError):
            bizlogic.validate_config(cfg)


class TestPrivescGating(AppTestCase):
    def _cfg(self, method):
        return {"base_url": self.base,
                "accounts": {"A": {"auth": {"type": "header", "headers": {}}, "id": "A"}},
                "endpoints": [{"name": "admin", "method": method, "path": "/vuln/admin",
                               "tests": ["privesc"]}]}

    def test_mutating_privesc_dry_run_does_not_send(self):
        import bizlogic
        cfg = self._cfg("POST")
        f = bizlogic.test_privesc(cfg, cfg["endpoints"][0], mutate_allowed=False, dry_run=True)
        self.assertIsNotNone(f)
        self.assertFalse(f["confirmed"])
        self.assertEqual(_App.admin_actions, 0)  # NENHUMA requisição mutante enviada

    def test_production_profile_does_not_mutate_privesc(self):
        import bizlogic
        host = self.base.split("://", 1)[1].split(":")[0]
        bizlogic.run(self._cfg("POST"), profile="production", scope=[host])
        self.assertEqual(_App.admin_actions, 0)  # production = dry-run também p/ privesc

    def test_mutating_privesc_confirms_when_allowed(self):
        import bizlogic
        cfg = self._cfg("POST")
        f = bizlogic.test_privesc(cfg, cfg["endpoints"][0], mutate_allowed=True, dry_run=False)
        self.assertIsNotNone(f)
        self.assertTrue(f["confirmed"])
        self.assertGreaterEqual(_App.admin_actions, 1)

    def test_get_privesc_always_executes(self):
        import bizlogic
        cfg = {"base_url": self.base,
               "accounts": {"A": {"auth": {"type": "header", "headers": {}}, "id": "A"}},
               "endpoints": [{"name": "admin", "method": "GET", "path": "/vuln/admin",
                              "tests": ["privesc"]}]}
        f = bizlogic.test_privesc(cfg, cfg["endpoints"][0], mutate_allowed=False, dry_run=True)
        self.assertIsNotNone(f)
        self.assertTrue(f["confirmed"])  # GET é read-only → sempre executa


class TestIdorWrite(AppTestCase):
    def _cfg(self, path):
        return {"base_url": self.base,
                "accounts": {"A": {"auth": {"type": "header", "headers": {"X-Acct": "A"}}, "id": "A"},
                              "B": {"auth": {"type": "header", "headers": {"X-Acct": "B"}}, "id": "B"}},
                "endpoints": [{"name": "acct", "method": "PUT", "path": path,
                               "owner_param": "id", "object_of": "A",
                               "body": {"nickname": "stiglitz-canary"}, "tests": ["idor_write"]}]}

    def test_vuln_confirms_via_reread(self):
        import bizlogic
        cfg = self._cfg("/vuln/accounts/{id}")
        f = bizlogic.test_idor_write(cfg, cfg["endpoints"][0], mutate_allowed=True, dry_run=False)
        self.assertIsNotNone(f)
        self.assertTrue(f["confirmed"])  # re-leitura como A reflete a mudança
        self.assertEqual(f["vuln_class"], "idor_write")

    def test_safe_owner_check_no_finding(self):
        import bizlogic
        cfg = self._cfg("/safe/accounts/{id}")
        # B tenta escrever no recurso de A → 403 (owner check) → sem finding
        self.assertIsNone(
            bizlogic.test_idor_write(cfg, cfg["endpoints"][0], mutate_allowed=True, dry_run=False))

    def test_dry_run_does_not_confirm(self):
        import bizlogic
        cfg = self._cfg("/vuln/accounts/{id}")
        f = bizlogic.test_idor_write(cfg, cfg["endpoints"][0], mutate_allowed=False, dry_run=True)
        self.assertFalse(f["confirmed"])


class TestAmountBodyCorroboration(AppTestCase):
    def test_200_with_error_body_not_confirmed(self):
        import bizlogic
        cfg = {"base_url": self.base,
               "accounts": {"A": {"auth": {"type": "header", "headers": {}}, "id": "A"}},
               "sentinel": {"amount": "0.01", "recipient": "r"},
               "endpoints": [{"name": "t", "method": "POST", "path": "/trap/transfer",
                              "body": {"amount": "{amount}", "to": "{recipient}"},
                              "money_params": ["amount"], "tests": ["amount_tampering"]}]}
        # /trap/transfer devolve 200 + {"error":...} → não deve confirmar
        self.assertIsNone(
            bizlogic.test_amount_tampering(cfg, cfg["endpoints"][0], actor="A",
                                           mutate_allowed=True, dry_run=False))


class TestResolveNested(unittest.TestCase):
    def test_resolves_nested_placeholders(self):
        import bizlogic
        out = bizlogic._resolve({"meta": {"from": "{owner}"}, "amount": "{amount}",
                                 "items": [{"to": "{recipient}"}]},
                                {"owner": "acct-1", "amount": "0.01", "recipient": "r"})
        self.assertEqual(out["meta"]["from"], "acct-1")
        self.assertEqual(out["amount"], "0.01")
        self.assertEqual(out["items"][0]["to"], "r")

    def test_unresolved_detector(self):
        import bizlogic
        self.assertEqual(bizlogic._unresolved_placeholders({"a": "ok"}), [])
        self.assertIn("{x}", bizlogic._unresolved_placeholders({"a": "{x}"}))


class TestDoubleSpendNone(unittest.TestCase):
    def test_none_counts_as_failure(self):
        import bizlogic
        # worker que morreu (None) não conta como sucesso e não levanta TypeError
        self.assertFalse(bizlogic.detect_double_spend([200, None, None], allowed=1))
        self.assertTrue(bizlogic.detect_double_spend([200, 200, None], allowed=1))


class TestScopeAtRequest(AppTestCase):
    def test_http_request_blocked_out_of_scope(self):
        import bizlogic
        bizlogic._ACTIVE_SCOPE = ["other.example.com"]
        try:
            r = bizlogic.http_request("GET", f"{self.base}/vuln/admin", {}, None)
        finally:
            bizlogic._ACTIVE_SCOPE = None
        self.assertEqual(r.status, 0)
        self.assertEqual(r.body, "__out_of_scope__")

    def test_http_request_allowed_in_scope(self):
        import bizlogic
        bizlogic._ACTIVE_SCOPE = ["127.0.0.1"]
        try:
            r = bizlogic.http_request("GET", f"{self.base}/vuln/admin", {}, None)
        finally:
            bizlogic._ACTIVE_SCOPE = None
        self.assertEqual(r.status, 200)


if __name__ == "__main__":
    unittest.main()

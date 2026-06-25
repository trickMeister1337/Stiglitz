import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
import zap_authgate as Z


def test_extract_status_parses_first_line():
    assert Z.extract_status("HTTP/1.1 401 Unauthorized\r\nServer: x\r\n") == 401
    assert Z.extract_status("HTTP/2 403 Forbidden\n") == 403
    assert Z.extract_status("HTTP/1.1 200 OK\r\n") == 200


def test_extract_status_handles_garbage_and_empty():
    assert Z.extract_status("") is None
    assert Z.extract_status("not an http response") is None
    assert Z.extract_status(None) is None


def test_needs_status_only_for_active_scan_without_status():
    assert Z.needs_status({"attack": "1 OR 1=1", "messageId": "5"}) is True
    assert Z.needs_status({"attack": "", "messageId": "5"}) is False          # passivo
    assert Z.needs_status({"attack": "x", "attack_status": 401}) is False     # já tem


def test_is_authgated_fp_matrix():
    assert Z.is_authgated_fp({"attack": "1 OR 1=1", "attack_status": 401}) is True
    assert Z.is_authgated_fp({"attack": "1 OR 1=1", "attack_status": 403}) is True
    assert Z.is_authgated_fp({"attack": "1 OR 1=1", "attack_status": 200}) is False
    assert Z.is_authgated_fp({"attack": "1 OR 1=1", "attack_status": 500}) is False
    assert Z.is_authgated_fp({"attack": "1 OR 1=1"}) is False                  # status ausente
    assert Z.is_authgated_fp({"attack": "", "attack_status": 401}) is False    # passivo + 401


def test_enrich_populates_status_and_dedups_by_message_id():
    calls = []
    def fetch(mid):
        calls.append(mid)
        return "HTTP/1.1 401 Unauthorized\r\n"
    alerts = [
        {"attack": "a", "messageId": "7"},
        {"attack": "b", "messageId": "7"},   # mesmo messageId -> não refetch
        {"attack": "", "messageId": "9"},    # passivo -> ignorado
    ]
    Z.enrich(alerts, fetch)
    assert alerts[0]["attack_status"] == 401
    assert alerts[1]["attack_status"] == 401   # reusa o status do messageId 7
    assert "attack_status" not in alerts[2]    # passivo não recebe
    assert calls == ["7"]                       # uma única chamada (dedup)


def test_enrich_tolerates_fetch_failure():
    def fetch(mid):
        raise RuntimeError("zap down")
    alerts = [{"attack": "a", "messageId": "7"}]
    Z.enrich(alerts, fetch)
    assert "attack_status" not in alerts[0]    # falha -> status ausente (fail-safe)

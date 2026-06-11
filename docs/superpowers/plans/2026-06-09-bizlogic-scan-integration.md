# bizlogic no scan (Fase P9.7) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ativar o `lib/bizlogic.py` no scan como subfase P9.7, derivando config read-only do histórico ZAP+tokens e habilitando mutantes via config manual sob opt-in.

**Architecture:** Novo módulo `lib/bizlogic_scan.py` (lógica pura + CLI) monta a config a partir do dump ZAP (`bola.parse_zap_messages`) e dos JWTs (`jwt_audit.decode_jwt`), chama `bizlogic.run()` intacto, e grava `raw/bizlogic.json` + `raw/bizlogic_findings.json` (schema do report). `stiglitz.sh` ganha a fase P9.7 e a flag `--bizlogic-mutate`. `stiglitz_report.py` agrega `bizlogic_findings.json` e deduplica contra `access_findings` (P9.5).

**Tech Stack:** Python 3 (stdlib + reuso de `lib/bola.py`, `lib/jwt_audit.py`, `lib/bizlogic.py`), bash, pytest.

**Referência:** `docs/superpowers/specs/2026-06-09-bizlogic-scan-integration-design.md`

---

## Notas de schema (referência para as tasks)

- **Conta bizlogic** (lida por `bizlogic.auth_headers`): `{"id": <str>, "auth": {"type": "bearer", "token": <jwt>}}`.
- **Endpoint bizlogic** (validado por `bizlogic.validate_config`): exige `name`, `method`, `path`, `tests`. `idor_read`/`idor_write` usam `object_of` (nome da conta dona). Paths são **concretos** (id de A já embutido) — `bizlogic._url` faz `base_url + path` e o `_resolve` é no-op quando não há `{id}`.
- **Config topo** (`REQUIRED_TOP`): `base_url`, `accounts`, `endpoints`.
- **Finding bizlogic** (de `bizlogic._finding`): `{name, vuln_class, url, method, severity, confirmed, tool, evidence}`.
- **`bola.parse_zap_messages(text)`** → `list[{method, url, req_headers, req_body, status, resp_body}]`.
- **`bola.is_object_ref_request(req)`** → bool (id numérico/UUID/param id no URL).
- **`jwt_audit.decode_jwt(token)`** → `(header, payload)`; `payload` é dict de claims.

---

## Task 1: `_account_id` — id da conta via claim JWT + fallback

**Files:**
- Create: `lib/bizlogic_scan.py`
- Test: `tests/test_bizlogic_scan.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_bizlogic_scan.py
import os, sys, json
sys.path[:0] = [os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "lib")]
import bizlogic_scan as BS
import jwt_audit


def _jwt(payload):
    import base64
    def b64(d): return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
    return f"{b64({'alg':'none'})}.{b64(payload)}.sig"


def test_account_id_from_sub_claim():
    tok = _jwt({"sub": "user-42"})
    assert BS._account_id(tok, fallback="X") == "user-42"


def test_account_id_prefers_sub_then_uid_then_user_id():
    assert BS._account_id(_jwt({"uid": "u1"}), fallback="X") == "u1"
    assert BS._account_id(_jwt({"user_id": "u2"}), fallback="X") == "u2"


def test_account_id_fallback_when_opaque_token():
    assert BS._account_id("not-a-jwt", fallback="A") == "A"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_bizlogic_scan.py::test_account_id_from_sub_claim -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'bizlogic_scan'`

- [ ] **Step 3: Write minimal implementation**

```python
# lib/bizlogic_scan.py
#!/usr/bin/env python3
"""
bizlogic_scan.py — Builder de config do bizlogic a partir do histórico ZAP + tokens,
para a fase P9.7 do stiglitz.sh. Lógica pura + CLI; reusa lib/bizlogic.py intacto.

Read-only auto-derivado (idor_read/privesc). Mutantes só via config manual + --mutate.
Console PT-BR; campos de evidência em EN (padrão deliverable do suite).
"""
import argparse
import json
import os
import sys
import urllib.parse

import bola
import jwt_audit
import bizlogic

_CLAIM_KEYS = ("sub", "uid", "user_id")


def _account_id(token, fallback):
    """Extrai um id estável da conta do claim JWT (sub/uid/user_id); fallback se opaco."""
    try:
        _hdr, payload = jwt_audit.decode_jwt(token)
    except Exception:
        return fallback
    if not isinstance(payload, dict):
        return fallback
    for k in _CLAIM_KEYS:
        v = payload.get(k)
        if v not in (None, ""):
            return str(v)
    return fallback
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_bizlogic_scan.py -v`
Expected: PASS (3 tests)

- [ ] **Step 5: Commit**

```bash
git add lib/bizlogic_scan.py tests/test_bizlogic_scan.py
git commit -m "feat(bizlogic_scan): _account_id via claim JWT + fallback (P9.7)"
```

---

## Task 2: `_derive_endpoints` — endpoints id-like do histórico ZAP

**Files:**
- Modify: `lib/bizlogic_scan.py`
- Test: `tests/test_bizlogic_scan.py`

- [ ] **Step 1: Write the failing test**

```python
def _zap_dump(entries):
    # entries: list[(method, url, status)]
    msgs = [{"requestHeader": f"{m} {u} HTTP/1.1\r\nHost: x\r\n\r\n",
             "responseHeader": f"HTTP/1.1 {s} OK\r\n\r\n", "responseBody": "{}"}
            for (m, u, s) in entries]
    return json.dumps({"messages": msgs})


def test_derive_endpoints_picks_idlike_get_2xx():
    dump = _zap_dump([
        ("GET", "https://t.com/api/orders/12345", 200),   # id-like → entra
        ("GET", "https://t.com/api/health", 200),          # sem id → fora
        ("POST", "https://t.com/api/orders/1", 200),       # não-GET → fora
        ("GET", "https://t.com/admin/users/7", 200),       # privilegiado → privesc
    ])
    eps = BS._derive_endpoints(dump, base_url="https://t.com", priv_prefixes=("/admin",))
    paths = {e["path"]: e for e in eps}
    assert "/api/orders/12345" in paths
    assert paths["/api/orders/12345"]["tests"] == ["idor_read"]
    assert paths["/api/orders/12345"]["object_of"] == "A"
    assert paths["/api/orders/12345"]["method"] == "GET"
    assert "/api/health" not in paths
    assert "privesc" in paths["/admin/users/7"]["tests"]


def test_derive_endpoints_empty_when_no_candidates():
    dump = _zap_dump([("GET", "https://t.com/api/health", 200)])
    assert BS._derive_endpoints(dump, "https://t.com", ("/admin",)) == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_bizlogic_scan.py::test_derive_endpoints_picks_idlike_get_2xx -v`
Expected: FAIL — `AttributeError: module 'bizlogic_scan' has no attribute '_derive_endpoints'`

- [ ] **Step 3: Write minimal implementation**

```python
DEFAULT_PRIV_PREFIXES = ("/admin", "/internal", "/manage")


def _rel_path(url):
    """Path relativo (com query, se houver) de uma URL absoluta ou já relativa."""
    sp = urllib.parse.urlsplit(url)
    rel = sp.path or url
    if sp.query:
        rel += "?" + sp.query
    return rel


def _derive_endpoints(zap_dump_text, base_url, priv_prefixes=DEFAULT_PRIV_PREFIXES):
    """Extrai endpoints read-only candidatos do dump ZAP: GET 2xx com object-ref.
    Paths concretos (id de A embutido). object_of='A'. privesc quando bate priv_prefixes."""
    eps = []
    seen = set()
    for req in bola.parse_zap_messages(zap_dump_text):
        if req.get("method") != "GET":
            continue
        status = req.get("status") or 0
        if not (200 <= int(status) < 300):
            continue
        if not bola.is_object_ref_request(req):
            continue
        path = _rel_path(req.get("url") or "")
        if not path or path in seen:
            continue
        seen.add(path)
        tests = ["idor_read"]
        if any(path.startswith(p) for p in priv_prefixes):
            tests.append("privesc")
        eps.append({"name": f"auto {req['method']} {path}", "method": "GET",
                    "path": path, "object_of": "A", "tests": tests})
    return eps
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_bizlogic_scan.py -v`
Expected: PASS (5 tests)

- [ ] **Step 5: Commit**

```bash
git add lib/bizlogic_scan.py tests/test_bizlogic_scan.py
git commit -m "feat(bizlogic_scan): _derive_endpoints id-like GET 2xx do dump ZAP (P9.7)"
```

---

## Task 3: `build_config_from_zap` — monta config completa (ou None)

**Files:**
- Modify: `lib/bizlogic_scan.py`
- Test: `tests/test_bizlogic_scan.py`

- [ ] **Step 1: Write the failing test**

```python
def test_build_config_full():
    dump = _zap_dump([("GET", "https://t.com/api/orders/12345", 200)])
    cfg = BS.build_config_from_zap(dump, _jwt({"sub": "a1"}), _jwt({"sub": "b1"}),
                                   base_url="https://t.com")
    assert cfg["base_url"] == "https://t.com"
    assert cfg["accounts"]["A"]["id"] == "a1"
    assert cfg["accounts"]["A"]["auth"] == {"type": "bearer", "token": _jwt({"sub": "a1"})}
    assert cfg["accounts"]["B"]["id"] == "b1"
    assert cfg["endpoints"][0]["path"] == "/api/orders/12345"
    # Config válida segundo o próprio bizlogic
    bizlogic.validate_config(cfg)


def test_build_config_none_when_no_endpoints():
    dump = _zap_dump([("GET", "https://t.com/api/health", 200)])
    assert BS.build_config_from_zap(dump, _jwt({"sub": "a"}), _jwt({"sub": "b"}),
                                    "https://t.com") is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_bizlogic_scan.py::test_build_config_full -v`
Expected: FAIL — `AttributeError: ... 'build_config_from_zap'`

- [ ] **Step 3: Write minimal implementation**

```python
def build_config_from_zap(zap_dump_text, token_a, token_b, base_url,
                          priv_prefixes=DEFAULT_PRIV_PREFIXES):
    """Monta config bizlogic read-only do dump ZAP + 2 tokens. None se inviável."""
    endpoints = _derive_endpoints(zap_dump_text, base_url, priv_prefixes)
    if not endpoints:
        return None
    return {
        "base_url": base_url,
        "accounts": {
            "A": {"id": _account_id(token_a, "A"),
                  "auth": {"type": "bearer", "token": token_a}},
            "B": {"id": _account_id(token_b, "B"),
                  "auth": {"type": "bearer", "token": token_b}},
        },
        "endpoints": endpoints,
    }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_bizlogic_scan.py -v`
Expected: PASS (7 tests)

- [ ] **Step 5: Commit**

```bash
git add lib/bizlogic_scan.py tests/test_bizlogic_scan.py
git commit -m "feat(bizlogic_scan): build_config_from_zap (read-only) (P9.7)"
```

---

## Task 4: `merge_manual_config` — mescla bizlogic.yaml manual

**Files:**
- Modify: `lib/bizlogic_scan.py`
- Test: `tests/test_bizlogic_scan.py`

- [ ] **Step 1: Write the failing test**

```python
def test_merge_manual_overrides_and_adds():
    auto = {"base_url": "https://t.com",
            "accounts": {"A": {"id": "a"}, "B": {"id": "b"}},
            "endpoints": [{"name": "auto GET /x", "method": "GET", "path": "/x",
                           "object_of": "A", "tests": ["idor_read"]}]}
    manual = {"sentinel": "STIG_SENTINEL",
              "endpoints": [
                  {"name": "auto GET /x", "method": "GET", "path": "/x",
                   "object_of": "A", "tests": ["idor_read", "privesc"]},   # override por name
                  {"name": "transfer", "method": "POST", "path": "/transfer",
                   "object_of": "A", "tests": ["amount_tampering"],
                   "body": "{\"amount\":100}"},                            # novo
              ]}
    merged = BS.merge_manual_config(auto, manual)
    by_name = {e["name"]: e for e in merged["endpoints"]}
    assert by_name["auto GET /x"]["tests"] == ["idor_read", "privesc"]  # manual venceu
    assert "transfer" in by_name
    assert merged["sentinel"] == "STIG_SENTINEL"   # chaves topo do manual propagam


def test_merge_manual_none_returns_auto():
    auto = {"base_url": "x", "accounts": {}, "endpoints": []}
    assert BS.merge_manual_config(auto, None) is auto
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_bizlogic_scan.py::test_merge_manual_overrides_and_adds -v`
Expected: FAIL — `AttributeError: ... 'merge_manual_config'`

- [ ] **Step 3: Write minimal implementation**

```python
def merge_manual_config(auto_cfg, manual_cfg):
    """Mescla a config manual sobre a auto: endpoints por 'name' (manual vence),
    e chaves de topo do manual (ex.: sentinel) propagam. None → retorna auto intacto."""
    if not manual_cfg:
        return auto_cfg
    merged = dict(auto_cfg)
    by_name = {e["name"]: e for e in auto_cfg.get("endpoints", [])}
    for ep in manual_cfg.get("endpoints", []):
        by_name[ep["name"]] = ep
    merged["endpoints"] = list(by_name.values())
    for k, v in manual_cfg.items():
        if k != "endpoints":
            merged[k] = v
    return merged
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_bizlogic_scan.py -v`
Expected: PASS (9 tests)

- [ ] **Step 5: Commit**

```bash
git add lib/bizlogic_scan.py tests/test_bizlogic_scan.py
git commit -m "feat(bizlogic_scan): merge_manual_config (mutantes via bizlogic.yaml) (P9.7)"
```

---

## Task 5: `to_report_findings` — transforma findings → schema do report + fingerprint

**Files:**
- Modify: `lib/bizlogic_scan.py`
- Test: `tests/test_bizlogic_scan.py`

- [ ] **Step 1: Write the failing test**

```python
def test_to_report_findings_maps_schema():
    biz = [{"name": "IDOR read: orders", "vuln_class": "idor_read_pii",
            "url": "https://t.com/api/orders/123", "method": "GET",
            "severity": "high", "confirmed": True, "tool": "bizlogic",
            "evidence": {"cross_account": "B"}}]
    out = BS.to_report_findings(biz)
    f = out[0]
    assert f["type"] == "idor_read_pii"
    assert f["severity"] == "high"
    assert f["tool"] == "bizlogic"
    assert f["url"] == "https://t.com/api/orders/123"
    assert f["confirmed"] is True
    assert "fingerprint" in f and f["fingerprint"]


def test_to_report_findings_dedup_key_present():
    biz = [{"name": "x", "vuln_class": "idor_read_pii",
            "url": "https://t.com/api/orders/123", "method": "GET",
            "severity": "high", "confirmed": True, "tool": "bizlogic", "evidence": {}}]
    assert BS.to_report_findings(biz)[0]["_dedup_key"] == ("t.com", "/api/orders/123", "idor_read_pii")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_bizlogic_scan.py::test_to_report_findings_maps_schema -v`
Expected: FAIL — `AttributeError: ... 'to_report_findings'`

- [ ] **Step 3: Write minimal implementation**

```python
def _dedup_key(url, vuln_class):
    """Chave de dedup estável: (host, path, vuln_class). Casa com a P9.5 quando
    a mesma vuln_class (idor_read_pii) aparece no mesmo recurso."""
    sp = urllib.parse.urlsplit(url or "")
    return ((sp.hostname or "").lower(), sp.path or (url or ""), vuln_class)


def to_report_findings(biz_findings):
    """Transforma findings nativos do bizlogic no schema agregado pelo report
    (campos: type, name, severity, url, tool, confirmed, detail, fingerprint).
    Acrescenta _dedup_key para o passo de dedup vs access_findings (P9.5)."""
    out = []
    for f in biz_findings:
        vc = f.get("vuln_class", "bizlogic")
        url = f.get("url", "")
        host, path, _ = _dedup_key(url, vc)
        out.append({
            "type": vc,
            "name": f.get("name", vc),
            "severity": f.get("severity", "medium") if f.get("confirmed") else "info",
            "url": url,
            "target": url,
            "tool": f.get("tool", "bizlogic"),
            "confirmed": bool(f.get("confirmed")),
            "detail": json.dumps(f.get("evidence", {}), ensure_ascii=False)[:600],
            "fingerprint": f"bizlogic:{vc}:{host}:{path}",
            "_dedup_key": (host, path, vc),
        })
    return out
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_bizlogic_scan.py -v`
Expected: PASS (11 tests)

- [ ] **Step 5: Commit**

```bash
git add lib/bizlogic_scan.py tests/test_bizlogic_scan.py
git commit -m "feat(bizlogic_scan): to_report_findings + dedup key (P9.7)"
```

---

## Task 6: CLI `main()` — orquestra build + bizlogic.run + grava outputs

**Files:**
- Modify: `lib/bizlogic_scan.py`
- Test: `tests/test_bizlogic_scan.py`

- [ ] **Step 1: Write the failing test**

```python
def test_cli_writes_outputs(tmp_path):
    outdir = str(tmp_path)
    os.makedirs(os.path.join(outdir, "raw"), exist_ok=True)
    dump = _zap_dump([("GET", "https://t.com/api/orders/12345", 200)])
    with open(os.path.join(outdir, "raw", "zap_messages_a.json"), "w") as f:
        f.write(dump)
    # idor_read é read-only e faz GET real; --base-url aponta p/ porta local recusada
    # (ConnectionRefused instantâneo) → run() degrada p/ lista vazia SEM rede lenta.
    # O teste valida a orquestração e a gravação dos arquivos, não o resultado da vuln.
    rc = BS.main(["--outdir", outdir, "--token-a", _jwt({"sub": "a"}),
                  "--token-b", _jwt({"sub": "b"}), "--base-url", "http://127.0.0.1:1",
                  "--profile", "production"])
    assert rc == 0
    assert os.path.exists(os.path.join(outdir, "raw", "bizlogic.json"))
    assert os.path.exists(os.path.join(outdir, "raw", "bizlogic_findings.json"))
    # bizlogic_findings.json é uma lista JSON válida
    with open(os.path.join(outdir, "raw", "bizlogic_findings.json")) as f:
        assert isinstance(json.load(f), list)


def test_cli_skips_gracefully_without_history(tmp_path):
    outdir = str(tmp_path)
    os.makedirs(os.path.join(outdir, "raw"), exist_ok=True)
    rc = BS.main(["--outdir", outdir, "--token-a", _jwt({"sub": "a"}),
                  "--token-b", _jwt({"sub": "b"}), "--base-url", "https://t.com",
                  "--profile", "production"])
    assert rc == 0   # sem histórico e sem config → no-op gracioso
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_bizlogic_scan.py::test_cli_skips_gracefully_without_history -v`
Expected: FAIL — `AttributeError: ... 'main'`

- [ ] **Step 3: Write minimal implementation**

```python
def _strip_dedup_keys(report_findings):
    return [{k: v for k, v in f.items() if k != "_dedup_key"} for f in report_findings]


def parse_args(argv=None):
    p = argparse.ArgumentParser(description="Builder de config do bizlogic p/ o scan (P9.7).")
    p.add_argument("--outdir", required=True)
    p.add_argument("--token-a", required=True)
    p.add_argument("--token-b", required=True)
    p.add_argument("--base-url", required=True)
    p.add_argument("--config", default=None, help="bizlogic.yaml/.json (mutantes)")
    p.add_argument("--mutate", action="store_true", help="habilita testes mutantes (RoE explícito)")
    p.add_argument("--profile", default="staging", choices=["lab", "staging", "production"])
    p.add_argument("--scope", default="")
    p.add_argument("--timeout", type=int, default=120)
    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    raw_a = os.path.join(args.outdir, "raw", "zap_messages_a.json")
    zap_text = ""
    if os.path.exists(raw_a):
        with open(raw_a, encoding="utf-8") as f:
            zap_text = f.read()

    auto_cfg = build_config_from_zap(zap_text, args.token_a, args.token_b, args.base_url) \
        if zap_text else None

    manual_cfg = None
    if args.config and os.path.exists(args.config):
        manual_cfg = bizlogic.load_config(args.config)

    if auto_cfg is None and manual_cfg is None:
        print("  [○] bizlogic-scan: sem histórico ZAP e sem config — fase pulada.")
        return 0

    cfg = auto_cfg or {"base_url": args.base_url, "accounts": {
        "A": {"id": _account_id(args.token_a, "A"), "auth": {"type": "bearer", "token": args.token_a}},
        "B": {"id": _account_id(args.token_b, "B"), "auth": {"type": "bearer", "token": args.token_b}},
    }, "endpoints": []}
    if manual_cfg is not None:
        cfg = merge_manual_config(cfg, manual_cfg)

    # Mutação: só com --mutate (consentimento RoE explícito) E profile permissivo.
    profile = args.profile
    if not args.mutate:
        profile = "production"   # força dry-run em bizlogic.run (sem mutação)
    elif profile in ("staging", "lab"):
        if not bizlogic.roe_gate(assume_yes=True):
            print("  [!] bizlogic-scan: RoE negado — abortando mutação.")
            return 1

    scope = [s.strip() for s in args.scope.split(",") if s.strip()]
    try:
        findings = bizlogic.run(cfg, profile=profile, scope=scope, outdir=args.outdir)
    except Exception as e:
        print(f"  [!] bizlogic-scan: run falhou ({e}) — fase degradada.")
        findings = []

    rep = _strip_dedup_keys(to_report_findings(findings))
    os.makedirs(os.path.join(args.outdir, "raw"), exist_ok=True)
    with open(os.path.join(args.outdir, "raw", "bizlogic_findings.json"), "w", encoding="utf-8") as fh:
        json.dump(rep, fh, ensure_ascii=False, indent=2)
    # Garante bizlogic.json mesmo quando run não gravou (lista vazia)
    bj = os.path.join(args.outdir, "raw", "bizlogic.json")
    if not os.path.exists(bj):
        with open(bj, "w", encoding="utf-8") as fh:
            json.dump(findings, fh, ensure_ascii=False, indent=2)
    print(f"  [✓] bizlogic-scan: {len(findings)} finding(s) → raw/bizlogic_findings.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_bizlogic_scan.py -v && python3 -m py_compile lib/bizlogic_scan.py`
Expected: PASS (13 tests) + compile OK

- [ ] **Step 5: Commit**

```bash
git add lib/bizlogic_scan.py tests/test_bizlogic_scan.py
git commit -m "feat(bizlogic_scan): CLI main() — build + bizlogic.run + outputs (P9.7)"
```

---

## Task 7: `stiglitz.sh` — flag `--bizlogic-mutate` + fase P9.7

**Files:**
- Modify: `stiglitz.sh` (parse de args perto da linha 296-301; nova fase após o bloco P9.6 que termina em `fi  # fim P9.6`, ~linha 1824)

- [ ] **Step 1: Adicionar parse da flag + var**

Localize o bloco de defaults de tokens (~linha 282-283) e adicione após `TOKEN_B=""`:

```bash
BIZLOGIC_MUTATE=0  # opt-in p/ testes mutantes de lógica de negócio (P9.7)
```

No `case` de parse de args (~linha 294-301), adicione um ramo:

```bash
        --bizlogic-mutate)   BIZLOGIC_MUTATE=1 ;;
```

- [ ] **Step 2: Adicionar a fase P9.7 após o `fi  # fim P9.6`**

> Nota de estilo: o banner abaixo usa o formato **sem `/11`** (alinhado ao cleanup P0 da branch
> `chore/p0-fases-docs-cleanup`). Se esta branch for executada/mergeada antes do P0, os demais banners
> ainda terão `/11` — a divergência se resolve no merge do P0. Mantenha sem `/11`.

Insira imediatamente após a linha `fi  # fim P9.6`:

```bash
# ====================== FASE 9.7: BUSINESS LOGIC AUTHZ ======================
if _phase_enabled "P9_7" && [ -n "$TOKEN_A" ] && [ -n "$TOKEN_B" ]; then
phase_start "P9_7"
phase_banner "FASE 9.7: BUSINESS LOGIC AUTHZ (IDOR/privesc/amount-tampering)"

# Config manual opcional (mutantes): env ou bizlogic.yaml/json no cwd/outdir
_biz_cfg=""
for _c in "${STIGLITZ_BIZLOGIC_CONFIG:-}" "bizlogic.yaml" "bizlogic.json" \
          "$OUTDIR/bizlogic.yaml" "$OUTDIR/bizlogic.json"; do
    [ -n "$_c" ] && [ -f "$_c" ] && { _biz_cfg="$_c"; break; }
done

_biz_mutate=""
[ "$BIZLOGIC_MUTATE" = "1" ] && _biz_mutate="1"
_biz_profile="${STIGLITZ_PROFILE:-staging}"

if python3 "$SCRIPT_DIR/lib/bizlogic_scan.py" \
        --outdir "$OUTDIR" --token-a "$TOKEN_A" --token-b "$TOKEN_B" \
        --base-url "https://${TARGET}" --profile "$_biz_profile" \
        ${STIGLITZ_SCOPE_DOMAINS:+--scope "${STIGLITZ_SCOPE_DOMAINS// /,}"} \
        ${_biz_cfg:+--config "$_biz_cfg"} \
        ${_biz_mutate:+--mutate}; then
    echo -e "  ${GREEN}[✓] Business Logic concluído → raw/bizlogic_findings.json${NC}"
else
    echo -e "  ${YELLOW}[!] bizlogic-scan: módulo retornou erro${NC}"
fi

phase_end "P9_7"
phase_done "FASE_9_7"
fi  # fim P9.7
```

- [ ] **Step 3: Verificar sintaxe**

Run: `bash -n stiglitz.sh && shellcheck --severity=warning stiglitz.sh`
Expected: sem erros; sem warnings novos

- [ ] **Step 4: Smoke — a fase aparece no dry-run sem 2 tokens (skip) e o parse não quebra**

Run: `bash stiglitz.sh https://example.com --dry-run --token-a x --token-b y 2>&1 | grep -i "9.7\|business" || echo "ok (dry-run pode pular a fase)"`
Expected: sem erro de sintaxe/execução

- [ ] **Step 5: Commit**

```bash
git add stiglitz.sh
git commit -m "feat(scan): fase P9.7 Business Logic Authz + flag --bizlogic-mutate"
```

---

## Task 8: `stiglitz_report.py` — agrega bizlogic_findings + dedup vs access_findings

**Files:**
- Modify: `stiglitz_report.py` (tabela de findings ~linha 884-885)
- Test: `tests/test_report_bizlogic_wiring.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_report_bizlogic_wiring.py
import os, sys, json, subprocess, tempfile, shutil

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _write(outdir, name, data):
    os.makedirs(os.path.join(outdir, "raw"), exist_ok=True)
    with open(os.path.join(outdir, "raw", name), "w") as f:
        json.dump(data, f)


def test_report_aggregates_bizlogic_and_dedups_access():
    outdir = tempfile.mkdtemp()
    try:
        # access_findings (P9.5) e bizlogic_findings (P9.7) colidem no mesmo recurso
        _write(outdir, "access_findings.json", [
            {"type": "idor_read_pii", "severity": "high", "tool": "bola",
             "url": "https://t.com/api/orders/123", "confirmed": True,
             "_dedup_key": ["t.com", "/api/orders/123", "idor_read_pii"]}])
        _write(outdir, "bizlogic_findings.json", [
            {"type": "idor_read_pii", "severity": "high", "tool": "bizlogic",
             "url": "https://t.com/api/orders/123", "confirmed": True,
             "_dedup_key": ["t.com", "/api/orders/123", "idor_read_pii"]},     # dup → removido
            {"type": "amount_tampering", "severity": "high", "tool": "bizlogic",
             "url": "https://t.com/transfer", "confirmed": True,
             "_dedup_key": ["t.com", "/transfer", "amount_tampering"]}])       # único → mantém
        env = dict(os.environ, OUTDIR=outdir, TARGET="t.com")
        r = subprocess.run([sys.executable, os.path.join(ROOT, "stiglitz_report.py")],
                           env=env, cwd=ROOT, capture_output=True, text=True)
        assert r.returncode == 0, r.stderr
        html = open(os.path.join(outdir, "stiglitz_report.html")).read()
        # o finding único do bizlogic aparece; a marca bola do dup permanece (P9.5 vence)
        assert "amount_tampering" in html or "transfer" in html
    finally:
        shutil.rmtree(outdir)
```

> Nota: se `stiglitz_report.py` exigir mais env/arquivos para rodar standalone, o executor deve
> espelhar o setup de `tests/test_report_state_wiring.py` (mesmo padrão de invocação).

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_report_bizlogic_wiring.py -v`
Expected: FAIL — `amount_tampering` ausente (bizlogic_findings.json ainda não é lido)

- [ ] **Step 3: Adicionar bizlogic à tabela + dedup**

No `stiglitz_report.py`, na lista de tuplas (após a linha `('oauth_findings.json', 'oauth_findings'),`, ~linha 885), adicione:

```python
    ('bizlogic_findings.json',   'bizlogic_findings'),
```

Logo após o loop de carga (após a linha `version_findings.append(_vf)` e seu `except`, ~linha 897), adicione o passo de dedup:

```python
# Dedup P9.7 (bizlogic) vs P9.5 (access): mesma (host,path,vuln_class) → P9.5 vence.
_access_keys = set()
for _vf in version_findings:
    if _vf.get("tool") in ("bola", "access") and _vf.get("_dedup_key"):
        _access_keys.add(tuple(_vf["_dedup_key"]))
version_findings = [
    _vf for _vf in version_findings
    if not (_vf.get("tool") == "bizlogic"
            and _vf.get("_dedup_key") and tuple(_vf["_dedup_key"]) in _access_keys)
]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_report_bizlogic_wiring.py -v && python3 -m py_compile stiglitz_report.py`
Expected: PASS + compile OK

- [ ] **Step 5: Run da suíte completa para garantir não-regressão**

Run: `python3 -m pytest tests/ -q`
Expected: todos passando (contagem anterior + novos)

- [ ] **Step 6: Commit**

```bash
git add stiglitz_report.py tests/test_report_bizlogic_wiring.py
git commit -m "feat(report): agrega bizlogic_findings (P9.7) + dedup vs access (P9.5)"
```

---

## Task 9: Docs — CLAUDE.md, CHANGELOG, ROADMAP

**Files:**
- Modify: `CLAUDE.md`, `CHANGELOG.md`, `docs/ROADMAP.md`

- [ ] **Step 1: CLAUDE.md — fase P9.7 + módulo + flag**

Na lista de fases do `stiglitz.sh` (sob "Fase 9"), adicione após a linha da Fase 9.6:

```markdown
   - **Fase 9.7** — Business Logic Authz (`lib/bizlogic_scan.py`) — reusa `lib/bizlogic.py`: read-only auto-derivado (idor_read/privesc) do histórico ZAP + 2 tokens; mutantes (idor_write/amount-tampering/race/idempotency) opt-in via `--bizlogic-mutate` + `bizlogic.yaml` + gating de profile/RoE. Dedup vs P9.5 por fingerprint.
```

Na tabela `lib/`, adicione uma linha:

```markdown
| `bizlogic_scan.py` | Builder de config do `bizlogic` para a fase P9.7 do scan: deriva read-only do dump ZAP (`bola.parse_zap_messages`) + claims JWT (`jwt_audit`); mescla `bizlogic.yaml` para mutantes; grava `raw/bizlogic_findings.json`. Lógica pura + CLI |
```

- [ ] **Step 2: CHANGELOG.md — entrada**

Sob a seção "## Unreleased" (criar no topo se não existir):

```markdown
- **bizlogic no scan (Fase P9.7)** — `lib/bizlogic_scan.py` ativa a engine de lógica de negócio/authz no `stiglitz.sh`. Read-only (idor_read/privesc) auto-derivado do histórico ZAP + tokens; mutantes opt-in via `--bizlogic-mutate` + `bizlogic.yaml` + gating de profile (production→dry-run) + RoE. Findings deduplicados contra a P9.5 (access control) por fingerprint. `lib/bizlogic.py` permanece intacto.
```

- [ ] **Step 3: ROADMAP — marcar follow-up**

Em `docs/ROADMAP.md`, na seção "Follow-ups conhecidos", marque o item de bizlogic/scan como concluído (ou mova para P1 feitos):

```markdown
- ✅ **bizlogic no scan** (fase **P9.7**, `lib/bizlogic_scan.py`): read-only auto-derivado do ZAP+tokens; mutantes opt-in (`--bizlogic-mutate` + config) com gating profile/RoE; dedup vs P9.5
```

- [ ] **Step 4: Commit**

```bash
git add CLAUDE.md CHANGELOG.md docs/ROADMAP.md
git commit -m "docs: registra fase P9.7 bizlogic no scan (CLAUDE.md/CHANGELOG/ROADMAP)"
```

---

## Validação final (após todas as tasks)

- [ ] `bash -n stiglitz.sh` limpo
- [ ] `shellcheck --severity=warning stiglitz.sh` sem warnings novos
- [ ] `python3 -m py_compile lib/bizlogic_scan.py stiglitz_report.py` OK
- [ ] `python3 -m pytest tests/ -q` — toda a suíte verde
- [ ] Smoke: `bash stiglitz.sh https://example.com --dry-run --token-a x --token-b y` não quebra

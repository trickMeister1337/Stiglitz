# Boolean-pair / canário nos validators — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reduzir FP/FN dos validators de injeção adicionando confirmação por par booleano (SQLi blind) e canário de reflexão (XSS), generalizando o padrão de veredito puro do `lib/bola.py`.

**Architecture:** Novo módulo puro `lib/active_probe.py` (builders de payload estruturados + vereditos puros + CLI), reusando `normalize`/`response_diff` de `poc_validator`. O `confirm_nuclei` dispara os probes e injeta o resultado no `ctx`; os plug-ins `validators/sqli.py` e `validators/xss.py` apenas **elevam** o sinal quando presente — ausência de probe = comportamento atual (zero regressão).

**Tech Stack:** Python 3 (stdlib: `re`, `os`, `urllib.parse`, `html`, `unittest`), pytest, curl (via `run_cmd` existente).

**Spec:** `docs/superpowers/specs/2026-06-07-validators-boolean-pair-canary-design.md`

---

## File Structure

- **Create** `lib/active_probe.py` — builders (`build_boolean_variants`, `new_canary_token`, `build_canary_variant`) + vereditos puros (`boolean_pair_verdict`, `canary_reflection`) + CLI. Núcleo puro, sem rede.
- **Create** `tests/test_active_probe.py` — testes unitários do módulo puro + CLI.
- **Modify** `lib/validators/sqli.py` — consumir `ctx["bool_pair"]`.
- **Modify** `lib/validators/xss.py` — consumir `ctx["canary"]`.
- **Modify** `lib/poc_validator.py` — `validate(...)` ganha kwargs `bool_pair`/`canary` (repassados ao `ctx` do plug-in); `confirm_nuclei` dispara os probes.
- **Modify** `tests/test_lib.py` — estender `TestValidatorPlugins` (sqli bool_pair, xss canary).

Convenção de import (igual `tests/test_bola.py`): os testes inserem `lib/` em `sys.path` e fazem `import active_probe`. O `lib/active_probe.py` importa `from poc_validator import normalize, response_diff` com fallback try/except (padrão do `lib/bola.py`).

---

## Task 1: `boolean_pair_verdict` (veredito puro)

**Files:**
- Create: `lib/active_probe.py`
- Test: `tests/test_active_probe.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_active_probe.py
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
import active_probe as ap


# Corpos com >50B para passar o guard do response_diff.
BASE = "Resultado da busca: produto Apple encontrado no catalogo. " * 3
DIFF = "Nenhum resultado encontrado para a sua consulta no catalogo. " * 3


def test_boolean_pair_confirms_on_true_eq_base_false_differs():
    v = ap.boolean_pair_verdict(BASE, BASE, DIFF)
    assert v["confirmed"] is True
    assert v["confidence"] == 88
    assert "booleano" in v["note"].lower()


def test_boolean_pair_no_effect_not_confirmed():
    # true == false == baseline → condição sem efeito
    v = ap.boolean_pair_verdict(BASE, BASE, BASE)
    assert v["confirmed"] is False
    assert v["confidence"] == 25


def test_boolean_pair_partial_not_confirmed():
    # true difere do baseline (sinal parcial) → não confirma
    v = ap.boolean_pair_verdict(BASE, DIFF, DIFF)
    assert v["confirmed"] is False
    assert v["confidence"] == 40


def test_boolean_pair_small_baseline_inconclusive():
    v = ap.boolean_pair_verdict("curto", "outro", "mais")
    assert v["confirmed"] is False
    assert v["confidence"] == 20
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_active_probe.py -v`
Expected: FAIL com `ModuleNotFoundError: No module named 'active_probe'`.

- [ ] **Step 3: Write minimal implementation**

```python
# lib/active_probe.py
#!/usr/bin/env python3
"""
Stiglitz — Active Probe (par booleano + canário de reflexão).

Núcleo puro (sem rede) reusado pelos validators de injeção via poc_validator:
  - boolean_pair_verdict(): confirma SQLi blind boolean-based pelo diferencial
    true/false vs baseline.
  - canary_reflection(): confirma XSS refletido por marcador único + chars de quebra.
  - build_boolean_variants()/build_canary_variant(): montam as requests dos probes
    a partir de URL/method/body estruturados (shell-safety fica no orquestrador).

Espelha o padrão de lib/bola.py (veredito puro + reuso de normalize/response_diff
+ CLI). Sem domínio hardcoded, sem rede no núcleo.
"""
import os, re, sys, json, difflib
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode

# Reuso do normalize do poc_validator (remove tokens dinâmicos); fallback se
# importado fora do pacote. A comparação de CONTEÚDO usa difflib (não o
# response_diff, que é baseado em tamanho/erro e não distingue corpos de tamanho
# parecido com conteúdo diferente — exatamente o caso TRUE vs FALSE).
try:
    from poc_validator import normalize as _normalize
except Exception:
    def _normalize(t):
        return re.sub(r"\s+", " ", (t or "")).strip()

_SIMILAR_THRESHOLD = 0.95   # >= → corpos considerados "≈ iguais"


def _similar(a, b):
    """True se os corpos normalizados são ≈ iguais (ratio difflib >= threshold)."""
    a, b = _normalize(a), _normalize(b)
    if not a and not b:
        return True
    return difflib.SequenceMatcher(None, a, b).ratio() >= _SIMILAR_THRESHOLD


def boolean_pair_verdict(baseline_norm, true_norm, false_norm):
    """Confirma SQLi blind boolean-based pelo diferencial true/false.

    Retorna {confirmed, confidence, note}:
      TRUE≈baseline ∧ FALSE≠baseline ∧ TRUE≠FALSE → confirmed=True,  conf=88
      tudo ≈ igual (condição sem efeito)           → confirmed=False, conf=25
      sinal parcial (só um critério)               → confirmed=False, conf=40
      baseline pequeno (<50 chars normalizados)    → inconclusivo,    conf=20
    """
    if len(_normalize(baseline_norm)) < 50:
        return {"confirmed": False, "confidence": 20,
                "note": "Baseline pequeno demais para par booleano"}

    true_eq_base   = _similar(baseline_norm, true_norm)
    false_neq_base = not _similar(baseline_norm, false_norm)
    true_neq_false = not _similar(true_norm, false_norm)

    if true_eq_base and false_neq_base and true_neq_false:
        return {"confirmed": True, "confidence": 88,
                "note": "Par booleano: TRUE≈baseline, FALSE≠baseline"}
    if not false_neq_base and not true_neq_false:
        return {"confirmed": False, "confidence": 25,
                "note": "Condição sem efeito (true≈false≈baseline)"}
    return {"confirmed": False, "confidence": 40,
            "note": "Sinal parcial — diferencial booleano incompleto"}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_active_probe.py -v`
Expected: PASS (4 testes).

- [ ] **Step 5: Commit**

```bash
git add lib/active_probe.py tests/test_active_probe.py
git commit -m "feat(active_probe): boolean_pair_verdict (SQLi blind boolean-based, P1)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 2: `canary_reflection` (veredito puro)

**Files:**
- Modify: `lib/active_probe.py`
- Test: `tests/test_active_probe.py`

- [ ] **Step 1: Write the failing test**

```python
# adicionar em tests/test_active_probe.py

def test_canary_reflection_raw_chars_confirms():
    body = 'foo <div>stg1a2b3c4d<"> bar</div>'   # PROBE_CHARS crus após o token
    v = ap.canary_reflection("stg1a2b3c4d", body)
    assert v["reflected"] is True
    assert v["encoded"] is False
    assert v["confidence"] == 90


def test_canary_reflection_encoded_is_safe():
    body = 'foo stg1a2b3c4d&lt;&quot;&gt; bar'   # PROBE_CHARS HTML-escapados
    v = ap.canary_reflection("stg1a2b3c4d", body)
    assert v["reflected"] is True
    assert v["encoded"] is True
    assert v["confidence"] == 35


def test_canary_reflection_absent():
    v = ap.canary_reflection("stg1a2b3c4d", "nenhum marcador aqui")
    assert v["reflected"] is False
    assert v["confidence"] == 0
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_active_probe.py -k canary -v`
Expected: FAIL com `AttributeError: module 'active_probe' has no attribute 'canary_reflection'`.

- [ ] **Step 3: Write minimal implementation**

```python
# adicionar em lib/active_probe.py (após boolean_pair_verdict)

PROBE_CHARS = '<">'   # quebra-de-contexto benigna anexada ao token do canário


def new_canary_token():
    """Marcador único 'stg' + 8 hex (os.urandom). Alfanumérico → busca inequívoca."""
    return "stg" + os.urandom(4).hex()


def canary_reflection(token, resp_body):
    """Detecta reflexão de `token` + PROBE_CHARS no corpo.

    Retorna {reflected, encoded, confidence, note}:
      token + PROBE_CHARS crus (< " >)  → reflected, !encoded, conf=90 (XSS provável)
      token + PROBE_CHARS HTML-escapados → reflected,  encoded, conf=35 (provável safe)
      token ausente                      → reflected=False,     conf=0
    """
    body = resp_body or ""
    if token not in body:
        return {"reflected": False, "encoded": False, "confidence": 0,
                "note": "Canário não refletido"}

    # Janela após cada ocorrência do token — procura PROBE_CHARS crus vs escapados.
    raw = False
    enc = False
    for m in re.finditer(re.escape(token), body):
        window = body[m.end():m.end() + 16]
        if any(c in window for c in PROBE_CHARS):
            raw = True
            break
        if re.search(r"&(?:lt|gt|quot|#x?\d+);", window):
            enc = True
    if raw:
        return {"reflected": True, "encoded": False, "confidence": 90,
                "note": "Canário refletido com chars de quebra crus (XSS provável)"}
    return {"reflected": True, "encoded": True, "confidence": 35,
            "note": "Canário refletido mas escapado/neutralizado (provável safe)"}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_active_probe.py -k canary -v`
Expected: PASS (3 testes).

- [ ] **Step 5: Commit**

```bash
git add lib/active_probe.py tests/test_active_probe.py
git commit -m "feat(active_probe): canary_reflection + new_canary_token (XSS refletido, P1)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 3: Builders de request (`build_boolean_variants`, `build_canary_variant`)

**Files:**
- Modify: `lib/active_probe.py`
- Test: `tests/test_active_probe.py`

- [ ] **Step 1: Write the failing test**

```python
# adicionar em tests/test_active_probe.py

def test_build_boolean_variants_query_injectable():
    url = "http://t.com/search?q=1'+OR+'1'='1&page=2"
    t, f = ap.build_boolean_variants(url)
    assert t["method"] == "GET" and f["method"] == "GET"
    assert "page=2" in t["url"] and "page=2" in f["url"]
    assert "AND+%271%27%3D%271" in t["url"]   # ' AND '1'='1 url-encoded
    assert "AND+%271%27%3D%272" in f["url"]   # ' AND '1'='2
    assert t["url"] != f["url"]


def test_build_boolean_variants_no_injectable_param_returns_none():
    assert ap.build_boolean_variants("http://t.com/page?id=42&name=bob") is None


def test_build_boolean_variants_body_payload_returns_none():
    # payload no body (não na query) → fora de escopo desta fase
    assert ap.build_boolean_variants("http://t.com/api", method="POST",
                                     body="q=1' OR '1'='1") is None


def test_build_canary_variant_injects_token():
    url = "http://t.com/p?name=<script>alert(1)</script>&x=1"
    token = "stgdeadbeef"
    req = ap.build_canary_variant(url, token)
    assert req is not None
    assert "x=1" in req["url"]
    assert "stgdeadbeef" in req["url"]
    assert "%3C%22%3E" in req["url"]   # PROBE_CHARS <"> url-encoded


def test_build_canary_variant_no_xss_param_returns_none():
    assert ap.build_canary_variant("http://t.com/p?id=42", "stgdeadbeef") is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_active_probe.py -k "build_" -v`
Expected: FAIL com `AttributeError: ... has no attribute 'build_boolean_variants'`.

- [ ] **Step 3: Write minimal implementation**

```python
# adicionar em lib/active_probe.py (após canary_reflection)

# Mesmas keywords SQL do build_safe_baseline (poc_validator).
_SQLI_KW = re.compile(
    r"(?:\bOR\b|\bAND\b|\bUNION\b|\bSELECT\b|\bDROP\b|\bINSERT\b|\bUPDATE\b"
    r"|\bDELETE\b|\bEXEC\b|\bCAST\b|\bSLEEP\b|\bWAITFOR\b|\bBENCHMARK\b|--|')",
    re.IGNORECASE)

# Chars que sinalizam um parâmetro carregando payload XSS.
_XSS_HINT = re.compile(r"[<>\"']|script|javascript:|onerror|onload", re.IGNORECASE)


def _rebuild_query(url, key, new_value):
    """Devolve `url` com o parâmetro `key` da query trocado por `new_value`
    (demais parâmetros preservados, na ordem)."""
    parts = urlsplit(url)
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    rebuilt = [(k, new_value if k == key else v) for k, v in pairs]
    return urlunsplit((parts.scheme, parts.netloc, parts.path,
                       urlencode(rebuilt), parts.fragment))


def _first_param(url, hint_re):
    """(key, value) do primeiro parâmetro de query cujo valor casa `hint_re`, ou None."""
    parts = urlsplit(url)
    for k, v in parse_qsl(parts.query, keep_blank_values=True):
        if hint_re.search(v or ""):
            return k, v
    return None


def build_boolean_variants(url, method="GET", body=""):
    """(true_req, false_req) | None — cada req é {"url","method","body"}.

    Detecta na query o parâmetro injetável (valor com keyword SQL) e troca o
    valor por `1' AND '1'='1` (true) / `1' AND '1'='2` (false). Só query string
    nesta fase. None se nenhum parâmetro injetável for achado."""
    hit = _first_param(url, _SQLI_KW)
    if not hit:
        return None
    key, _v = hit
    true_req = {"method": method, "body": body,
                "url": _rebuild_query(url, key, "1' AND '1'='1")}
    false_req = {"method": method, "body": body,
                 "url": _rebuild_query(url, key, "1' AND '1'='2")}
    return true_req, false_req


def build_canary_variant(url, token, method="GET", body=""):
    """canary_req | None — {"url","method","body"}.

    Detecta na query o parâmetro com payload XSS-ish e troca o valor por
    `token + PROBE_CHARS`. Só query string nesta fase. None se nada substituível."""
    hit = _first_param(url, _XSS_HINT)
    if not hit:
        return None
    key, _v = hit
    return {"method": method, "body": body,
            "url": _rebuild_query(url, key, token + PROBE_CHARS)}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_active_probe.py -k "build_" -v`
Expected: PASS (5 testes).

Nota: `urlencode` codifica `' AND '1'='1` como `1%27+AND+%271%27%3D%271` — a substring
`AND+%271%27%3D%271` aparece, satisfazendo a asserção. PROBE_CHARS `<">` vira `%3C%22%3E`.

- [ ] **Step 5: Commit**

```bash
git add lib/active_probe.py tests/test_active_probe.py
git commit -m "feat(active_probe): builders de request boolean/canary (query-string, P1)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 4: CLI do `active_probe`

**Files:**
- Modify: `lib/active_probe.py`
- Test: `tests/test_active_probe.py`

- [ ] **Step 1: Write the failing test**

```python
# adicionar em tests/test_active_probe.py
import subprocess

_AP_PATH = os.path.join(os.path.dirname(__file__), "..", "lib", "active_probe.py")


def test_cli_verdict_bool_confirmed():
    out = subprocess.run(
        [sys.executable, _AP_PATH, "verdict-bool", BASE, BASE, DIFF],
        capture_output=True, text=True)
    assert out.returncode == 0
    data = json.loads(out.stdout)
    assert data["confirmed"] is True


def test_cli_verdict_canary_raw(tmp_path):
    body_file = tmp_path / "body.txt"
    body_file.write_text('x stgdeadbeef<"> y')
    out = subprocess.run(
        [sys.executable, _AP_PATH, "verdict-canary", "stgdeadbeef", str(body_file)],
        capture_output=True, text=True)
    assert out.returncode == 0
    data = json.loads(out.stdout)
    assert data["reflected"] is True and data["encoded"] is False
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_active_probe.py -k cli -v`
Expected: FAIL — o script não tem bloco CLI (stdout vazio → `json.loads` levanta).

- [ ] **Step 3: Write minimal implementation**

```python
# adicionar no FINAL de lib/active_probe.py

def _main(argv):
    if len(argv) >= 5 and argv[1] == "verdict-bool":
        print(json.dumps(boolean_pair_verdict(argv[2], argv[3], argv[4])))
        return 0
    if len(argv) >= 4 and argv[1] == "verdict-canary":
        with open(argv[3], encoding="utf-8", errors="replace") as fh:
            body = fh.read()
        print(json.dumps(canary_reflection(argv[2], body)))
        return 0
    sys.stderr.write(
        "uso: active_probe.py verdict-bool <baseline> <true> <false>\n"
        "     active_probe.py verdict-canary <token> <body-file>\n")
    return 2


if __name__ == "__main__":
    sys.exit(_main(sys.argv))
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_active_probe.py -v`
Expected: PASS (todos os testes do arquivo).

- [ ] **Step 5: Commit**

```bash
git add lib/active_probe.py tests/test_active_probe.py
git commit -m "feat(active_probe): CLI verdict-bool/verdict-canary (paridade bola/takeover, P1)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 5: `validators/sqli.py` consome `ctx["bool_pair"]`

**Files:**
- Modify: `lib/validators/sqli.py`
- Test: `tests/test_lib.py` (`TestValidatorPlugins`)

- [ ] **Step 1: Write the failing test**

```python
# adicionar em tests/test_lib.py, dentro de class TestValidatorPlugins

    def test_sqli_plugin_bool_pair_confirms_over_weak_diff(self):
        # bool_pair confirmado tem prioridade sobre size-diff fraco sem double-check
        from validators.sqli import validate as sqli_validate
        ctx = {
            "url": "http://x/", "resp_body": "", "resp_headers": "",
            "status": "200", "patterns": {"patterns": []},
            "diff_changed": True, "diff_conf": 15, "diff_note": "mudou 40%",
            "auth_ev": [], "dc_result": None, "dc_bonus": 0,
            "bool_pair": {"confirmed": True, "confidence": 88, "note": "par ok"},
        }
        confirmed, conf, note = sqli_validate(ctx)
        self.assertTrue(confirmed)
        self.assertEqual(conf, 88)
        self.assertIn("booleano", note.lower())

    def test_sqli_plugin_bool_pair_absent_keeps_legacy(self):
        # sem bool_pair, size-diff fraco sem dc continua NÃO confirmando (regressão)
        from validators.sqli import validate as sqli_validate
        ctx = {
            "url": "http://x/", "resp_body": "", "resp_headers": "",
            "status": "200", "patterns": {"patterns": []},
            "diff_changed": True, "diff_conf": 15, "diff_note": "mudou 40%",
            "auth_ev": [], "dc_result": None, "dc_bonus": 0,
        }
        confirmed, _, _ = sqli_validate(ctx)
        self.assertFalse(confirmed)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_lib.py -k "bool_pair" -v`
Expected: FAIL — `test_sqli_plugin_bool_pair_confirms_over_weak_diff` não confirma
(o size-diff fraco sem dc retorna `(False, 45, ...)` hoje).

- [ ] **Step 3: Write minimal implementation**

```python
# em lib/validators/sqli.py, no início de validate(ctx), logo após a docstring,
# ANTES do loop de patterns:

    # Par booleano (active_probe): sinal determinístico — prioridade sobre size-diff.
    bp = ctx.get("bool_pair")
    if bp and bp.get("confirmed"):
        return True, bp["confidence"], f"Par booleano confirmado: {bp.get('note', '')}"
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_lib.py -k "TestValidatorPlugins" -v`
Expected: PASS (incluindo os testes pré-existentes de sqli — `ctx.get` não quebra os antigos).

- [ ] **Step 5: Commit**

```bash
git add lib/validators/sqli.py tests/test_lib.py
git commit -m "feat(validators): sqli consome ctx[bool_pair] (par booleano, P1)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 6: `validators/xss.py` consome `ctx["canary"]`

**Files:**
- Modify: `lib/validators/xss.py`
- Test: `tests/test_lib.py` (`TestValidatorPlugins`)

- [ ] **Step 1: Write the failing test**

```python
# adicionar em tests/test_lib.py, dentro de class TestValidatorPlugins

    def test_xss_plugin_canary_raw_confirms(self):
        from validators.xss import validate as xss_validate
        ctx = {
            "url": "http://x/", "resp_body": "irrelevante", "resp_headers": "",
            "status": "200", "patterns": {"patterns": []},
            "diff_changed": False, "diff_conf": 0, "diff_note": "",
            "auth_ev": [], "dc_result": None, "dc_bonus": 0,
            "canary": {"reflected": True, "encoded": False, "confidence": 90,
                       "note": "cru"},
        }
        confirmed, conf, note = xss_validate(ctx)
        self.assertTrue(confirmed)
        self.assertEqual(conf, 90)
        self.assertIn("canário", note.lower())

    def test_xss_plugin_canary_encoded_not_confirmed(self):
        from validators.xss import validate as xss_validate
        ctx = {
            "url": "http://x/", "resp_body": "irrelevante", "resp_headers": "",
            "status": "200", "patterns": {"patterns": []},
            "diff_changed": False, "diff_conf": 0, "diff_note": "",
            "auth_ev": [], "dc_result": None, "dc_bonus": 0,
            "canary": {"reflected": True, "encoded": True, "confidence": 35,
                       "note": "escapado"},
        }
        confirmed, conf, _ = xss_validate(ctx)
        self.assertFalse(confirmed)
        self.assertEqual(conf, 35)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_lib.py -k "canary" -v`
Expected: FAIL — sem leitura de `ctx["canary"]`, o xss cai no fallback e retorna
`(False, 20, "Payload não refletido...")`, divergindo das asserções.

- [ ] **Step 3: Write minimal implementation**

```python
# em lib/validators/xss.py, no início de validate(ctx), logo após a docstring,
# ANTES do loop de patterns:

    # Canário de reflexão (active_probe): refletido sem encoding = XSS provável.
    cn = ctx.get("canary")
    if cn and cn.get("reflected") and not cn.get("encoded"):
        return True, cn["confidence"], f"Canário refletido sem encoding: {cn.get('note', '')}"
    if cn and cn.get("reflected") and cn.get("encoded"):
        return False, cn["confidence"], f"Canário refletido mas HTML-encodado (provável safe): {cn.get('note', '')}"
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_lib.py -k "TestValidatorPlugins" -v`
Expected: PASS (incluindo `test_xss_plugin_pattern_reflection` pré-existente).

- [ ] **Step 5: Commit**

```bash
git add lib/validators/xss.py tests/test_lib.py
git commit -m "feat(validators): xss consome ctx[canary] (canário de reflexão, P1)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 7: `validate()` aceita kwargs `bool_pair`/`canary`

**Files:**
- Modify: `lib/poc_validator.py` (assinatura de `validate` ~linha 375; montagem do `ctx` ~407-414)
- Test: `tests/test_lib.py` (`TestPocValidator`)

- [ ] **Step 1: Write the failing test**

```python
# adicionar em tests/test_lib.py, dentro de class TestPocValidator

    def test_validate_passes_bool_pair_to_plugin(self):
        import poc_validator as pv
        confirmed, conf, note = pv.validate(
            "sqli", "http://x/", "", "", "200",
            bool_pair={"confirmed": True, "confidence": 88, "note": "par ok"})
        self.assertTrue(confirmed)
        self.assertEqual(conf, 88)

    def test_validate_passes_canary_to_plugin(self):
        import poc_validator as pv
        confirmed, conf, note = pv.validate(
            "xss", "http://x/", "irrelevante", "", "200",
            canary={"reflected": True, "encoded": False, "confidence": 90, "note": "cru"})
        self.assertTrue(confirmed)
        self.assertEqual(conf, 90)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_lib.py -k "passes_bool_pair or passes_canary" -v`
Expected: FAIL com `TypeError: validate() got an unexpected keyword argument 'bool_pair'`.

- [ ] **Step 3: Write minimal implementation**

Em `lib/poc_validator.py`, alterar a assinatura de `validate` (a linha atual termina em `auth_ev=None, dc_result=None):`):

```python
def validate(vuln_type, url, resp_body, resp_headers, status,
             method_results=None, diff_changed=False, diff_conf=0,
             diff_note="", auth_ev=None, dc_result=None,
             bool_pair=None, canary=None):
```

E no dict `ctx` montado para o plug-in (bloco `ctx = { ... }` ~linhas 407-414), acrescentar duas chaves antes do fechamento `}`:

```python
            "method_results": method_results or {},
            "bool_pair": bool_pair,
            "canary": canary,
        }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_lib.py -k "TestPocValidator" -v`
Expected: PASS (novos + pré-existentes).

- [ ] **Step 5: Commit**

```bash
git add lib/poc_validator.py tests/test_lib.py
git commit -m "feat(poc_validator): validate() repassa bool_pair/canary ao ctx do plug-in (P1)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 8: Wiring ativo no `confirm_nuclei`

**Files:**
- Modify: `lib/poc_validator.py` (`confirm_nuclei`, bloco após `diff_changed = response_diff(...)` ~linhas 810-837)
- Test: `tests/test_lib.py` (`TestPocValidator`) — testa o helper `_req_to_curl` (puro), não a rede.

- [ ] **Step 1: Write the failing test**

```python
# adicionar em tests/test_lib.py, dentro de class TestPocValidator

    def test_req_to_curl_quotes_url_and_method(self):
        import poc_validator as pv
        req = {"url": "http://t.com/s?q=1' AND '1'='1", "method": "GET", "body": ""}
        cmd = pv._req_to_curl(req)
        self.assertIn("curl ", cmd)
        self.assertIn("-X GET", cmd)
        # URL com aspas simples deve estar shell-quotada (sem aspas cruas soltas)
        self.assertIn("http://t.com/s?q=1", cmd)
        self.assertIn("-D -", cmd)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_lib.py -k "req_to_curl" -v`
Expected: FAIL com `AttributeError: module 'poc_validator' has no attribute '_req_to_curl'`.

- [ ] **Step 3: Write minimal implementation**

Em `lib/poc_validator.py`, adicionar o helper perto dos outros utilitários de curl
(ex.: logo após `build_safe_baseline`):

```python
def _req_to_curl(req):
    """Monta um curl shell-safe a partir de {"url","method","body"} (active_probe).
    Toda a shell-safety (shlex.quote) fica concentrada aqui."""
    method = req.get("method", "GET")
    url    = req.get("url", "")
    body   = req.get("body", "")
    cmd = f"curl -sk -L -X {shlex.quote(method)} --max-time 15 {shlex.quote(url)}"
    if body and method in ("POST", "PUT", "PATCH"):
        cmd += f" --data {shlex.quote(body[:500])}"
    return cmd + " -D - -w '\\n===Stiglitz_STATUS:%{http_code}==='"
```

Importar o módulo no topo do arquivo (perto dos outros try-imports opcionais, ~linha 28):

```python
# Active probe (par booleano + canário) — opcional, degrada sem erro.
try:
    import active_probe as _ap
    _ACTIVE_PROBE_AVAILABLE = True
except Exception:
    _ACTIVE_PROBE_AVAILABLE = False
```

Em `confirm_nuclei`, logo após o bloco que calcula
`diff_changed, diff_conf, diff_note = response_diff(...)` e `auth_ev = check_auth_evidence(...)`
(antes de montar `method_results`), inserir o disparo dos probes:

```python
                # Active probe: par booleano (sqli) / canário (xss). Sempre on.
                # Builder None ou fetch falho → sinal ausente → fallback (sem regressão).
                bool_pair = None
                canary    = None
                if _ACTIVE_PROBE_AVAILABLE and vuln_type == "sqli":
                    variants = _ap.build_boolean_variants(url, method, req_body)
                    if variants:
                        t_req, f_req = variants
                        t_out, t_err = run_cmd(_apply_oauth(_req_to_curl(t_req)), timeout=15, retries=1)
                        f_out, f_err = run_cmd(_apply_oauth(_req_to_curl(f_req)), timeout=15, retries=1)
                        if not t_err and not f_err:
                            _, _, t_body = parse_http_response(t_out)
                            _, _, f_body = parse_http_response(f_out)
                            bool_pair = _ap.boolean_pair_verdict(
                                normalize(base_body), normalize(t_body), normalize(f_body))
                elif _ACTIVE_PROBE_AVAILABLE and vuln_type == "xss":
                    token = _ap.new_canary_token()
                    c_req = _ap.build_canary_variant(url, token, method, req_body)
                    if c_req:
                        c_out, c_err = run_cmd(_apply_oauth(_req_to_curl(c_req)), timeout=15, retries=1)
                        if not c_err:
                            _, _, c_body = parse_http_response(c_out)
                            canary = _ap.canary_reflection(token, c_body)
```

E na chamada de `validate(...)` dentro de `confirm_nuclei` (a que passa `dc_result=dc`),
acrescentar os dois kwargs:

```python
                confirmed, confidence, poc_note = validate(
                    vuln_type, url, resp_body, resp_headers, status,
                    method_results=method_results,
                    diff_changed=diff_changed, diff_conf=diff_conf,
                    diff_note=diff_note, auth_ev=auth_ev, dc_result=dc,
                    bool_pair=bool_pair, canary=canary)
```

- [ ] **Step 4: Run test + compilação**

Run: `python3 -m pytest tests/test_lib.py -k "req_to_curl" -v && python3 -m py_compile lib/poc_validator.py lib/active_probe.py`
Expected: PASS + compilação sem erro.

- [ ] **Step 5: Commit**

```bash
git add lib/poc_validator.py tests/test_lib.py
git commit -m "feat(poc_validator): confirm_nuclei dispara probes boolean/canary (P1)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 9: Suite completa + validação ao vivo (Juice Shop)

**Files:** nenhum arquivo novo — verificação de não-regressão e validação de ponta a ponta.

- [ ] **Step 1: Rodar a suite Python inteira**

Run: `python3 -m pytest tests/ -q`
Expected: todos passam (baseline atual: 465 passed, 4 skipped — agora + ~21 novos testes).

- [ ] **Step 2: Compilar todos os módulos**

Run: `python3 -m py_compile lib/*.py stiglitz_report.py pipeline.py`
Expected: sem erro.

- [ ] **Step 3: Sanidade da CLI do active_probe**

Run: `python3 lib/active_probe.py verdict-canary stgdeadbeef <(printf 'x stgdeadbeef<"> y')`
Expected: JSON com `"reflected": true, "encoded": false, "confidence": 90`.

- [ ] **Step 4: Validação ao vivo (Juice Shop via docker)**

```bash
docker run --rm -d -p 3000:3000 bkimminich/juice-shop
# SQLi boolean-based no parâmetro de busca:
python3 - <<'PY'
import sys; sys.path.insert(0, "lib")
import active_probe as ap
v = ap.build_boolean_variants("http://localhost:3000/rest/products/search?q=apple")
print("variants:", v)   # None esperado (sem keyword SQL na URL benigna) → confirma fallback
PY
```
Expected: documentar no commit/memória que o probe ativo só dispara quando o finding do
Nuclei já traz payload SQL na URL (caso real de SQLi), e que em URL benigna retorna `None`
(fallback). Se houver finding SQLi real do Nuclei no scan do Juice Shop, confirmar que
`boolean_pair_verdict` eleva a confiança sem marcar o baseline como FP.

- [ ] **Step 5: Verificação final (shellcheck dos scripts inalterados como sanidade do repo)**

Run: `bash -n stiglitz.sh && shellcheck --severity=warning lib/*.sh 2>/dev/null; echo done`
Expected: sem novos warnings (esta entrega é só-Python; scripts bash não mudaram).

Sem commit nesta task (é verificação). Se algum teste falhar, voltar à task correspondente.

---

## Notas de não-regressão (revisar ao executar)

- Os testes pré-existentes de `TestValidatorPlugins` montam `ctx` **sem** `bool_pair`/`canary`;
  o uso de `ctx.get(...)` garante que continuem passando.
- `validate()` mantém os defaults `bool_pair=None, canary=None` → todos os call sites atuais
  (`confirm_zap`, `confirm_tls`, etc.) seguem funcionando sem alteração.
- `active_probe` importa `normalize`/`response_diff` com fallback → importável isolado nos testes.
- Builders retornam `None` em qualquer ambiguidade → o caminho legado é sempre o piso de comportamento.

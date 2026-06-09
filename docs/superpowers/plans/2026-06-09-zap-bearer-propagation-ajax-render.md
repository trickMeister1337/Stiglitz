# ZAP bearer-token propagation + AJAX render (chromium) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Propagar o bearer token (e header custom) para todo o tráfego da Fase 9 do ZAP — spider, AJAX spider, active-scan e o histórico que a P9.5 (BOLA) consome — e fazer o AJAX Spider renderizar via chromium-headless.

**Architecture:** Reordenar a injeção do replacer `Authorization` para ANTES do spider (causa-raiz: hoje entra só no pre-warm, pós-spider), extraída num helper bash `zap_inject_auth_headers()`. Pré-check de `exp` do JWT como função pura em `lib/jwt_audit.py` (reusa `decode_jwt`, `now_ts` injetável → testável). Preflight de browser escolhe `chrome-headless` para o AJAX Spider. Degradação graciosa em todos os pontos.

**Tech Stack:** Bash (ZAP REST API via `zap_api_call`), Python 3 stdlib (`jwt_audit.py`), pytest/unittest, OWASP ZAP 2.17, chromium.

**Spec:** `docs/superpowers/specs/2026-06-09-zap-bearer-propagation-ajax-render-design.md`

---

## File Structure

- **Modify** `lib/jwt_audit.py` — adicionar função pura `exp_status()` + subcomando CLI `exp-check` no bloco `__main__`. Responsabilidade: lógica de classificação do `exp` (pura, sem rede, sem relógio).
- **Modify** `tests/test_lib.py` — nova classe `TestJwtExp` (unit do `exp_status`) + guard estrutural de ordenação no `stiglitz.sh`.
- **Modify** `stiglitz.sh` — (a) novo helper `zap_inject_auth_headers()` após `zap_setup_auth_context` (~linha 181); (b) chamada do helper antes do spider (~linha 1429); (c) remover replacer duplicado do pre-warm; (d) preflight de browser + `setOptionBrowserId` no bloco AJAX.
- **Modify** `CLAUDE.md` (raiz do Stiglitz) e `docs/ROADMAP.md` — doc da Fase 9 e marcar item P1 concluído (após validação).

---

## Task 1: `exp_status()` — função pura de classificação do exp

**Files:**
- Modify: `lib/jwt_audit.py`
- Test: `tests/test_lib.py`

- [ ] **Step 1: Write the failing tests**

Adicionar ao fim de `tests/test_lib.py` (antes do bloco `if __name__ == "__main__": unittest.main()`, se houver):

```python
class TestJwtExp(unittest.TestCase):
    """exp_status: classificação determinística do exp do JWT (now_ts injetado)."""

    def _token(self, payload):
        import jwt_audit as ja
        # header trivial + payload arbitrário; assinatura vazia (não verificada aqui)
        h = ja.b64url_encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
        p = ja.b64url_encode(json.dumps(payload).encode())
        return f"{h}.{p}."

    def test_expired(self):
        import jwt_audit as ja
        st = ja.exp_status(self._token({"exp": 1000}), 1980, now_ts=2000)
        self.assertEqual(st["state"], "expired")
        self.assertEqual(st["exp"], 1000)
        self.assertEqual(st["remaining"], -1000)

    def test_expires_within_window(self):
        import jwt_audit as ja
        st = ja.exp_status(self._token({"exp": 2500}), 1980, now_ts=2000)
        self.assertEqual(st["state"], "expires_within")
        self.assertEqual(st["remaining"], 500)

    def test_ok_comfortably_valid(self):
        import jwt_audit as ja
        st = ja.exp_status(self._token({"exp": 100000}), 1980, now_ts=2000)
        self.assertEqual(st["state"], "ok")

    def test_no_exp_claim(self):
        import jwt_audit as ja
        st = ja.exp_status(self._token({"sub": "u1"}), 1980, now_ts=2000)
        self.assertEqual(st["state"], "no_exp")
        self.assertIsNone(st["exp"])

    def test_malformed_token(self):
        import jwt_audit as ja
        st = ja.exp_status("not-a-jwt", 1980, now_ts=2000)
        self.assertEqual(st["state"], "malformed")
        self.assertIsNone(st["remaining"])
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd ~/Stiglitz && python3 -m pytest tests/test_lib.py::TestJwtExp -v`
Expected: FAIL — `AttributeError: module 'jwt_audit' has no attribute 'exp_status'`.

- [ ] **Step 3: Implement `exp_status` in `lib/jwt_audit.py`**

Inserir logo após a função `crack_hs256` (antes de `_finding`, ~linha 92):

```python
def exp_status(token, window_seconds, now_ts):
    """Classifica o exp do JWT contra uma janela de scan, SEM usar relógio (now_ts injetado).

    Retorna dict {"state", "exp", "remaining"}:
      "malformed"      — token não decodificável
      "no_exp"         — payload sem exp (ou exp não-numérico)
      "expired"        — exp <= now_ts
      "expires_within" — now_ts < exp <= now_ts + window_seconds
      "ok"             — exp > now_ts + window_seconds
    remaining = exp - now_ts (segundos) quando exp presente, senão None.
    """
    try:
        _, payload = decode_jwt(token)
    except (ValueError, json.JSONDecodeError):
        return {"state": "malformed", "exp": None, "remaining": None}
    exp = payload.get("exp")
    if not isinstance(exp, (int, float)) or isinstance(exp, bool):
        return {"state": "no_exp", "exp": None, "remaining": None}
    exp = int(exp)
    remaining = exp - int(now_ts)
    if remaining <= 0:
        state = "expired"
    elif remaining <= window_seconds:
        state = "expires_within"
    else:
        state = "ok"
    return {"state": state, "exp": exp, "remaining": remaining}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd ~/Stiglitz && python3 -m pytest tests/test_lib.py::TestJwtExp -v`
Expected: PASS (5 passed).

- [ ] **Step 5: Compile check + commit**

```bash
cd ~/Stiglitz
python3 -m py_compile lib/jwt_audit.py
git add lib/jwt_audit.py tests/test_lib.py
git commit -m "feat(jwt): exp_status — pre-check de expiracao p/ janela de scan (P1)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 2: CLI `exp-check` no `jwt_audit.py`

**Files:**
- Modify: `lib/jwt_audit.py:160-162` (bloco `__main__`)
- Test: `tests/test_lib.py` (classe `TestJwtExp`)

- [ ] **Step 1: Write the failing test**

Adicionar ao `TestJwtExp`:

```python
    def test_cli_exp_check_expired(self):
        import subprocess, os
        repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        h = __import__("jwt_audit").b64url_encode(json.dumps({"alg": "none"}).encode())
        p = __import__("jwt_audit").b64url_encode(json.dumps({"exp": 1000}).encode())
        tok = f"{h}.{p}."
        out = subprocess.run(
            ["python3", os.path.join(repo, "lib", "jwt_audit.py"), "exp-check", tok, "1980", "2000"],
            capture_output=True, text=True)
        self.assertEqual(out.stdout.split()[0], "expired")
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd ~/Stiglitz && python3 -m pytest tests/test_lib.py::TestJwtExp::test_cli_exp_check_expired -v`
Expected: FAIL — o `__main__` cai no `main()` e levanta/erra (não imprime `expired`).

- [ ] **Step 3: Implement the CLI branch**

Substituir o bloco `__main__` no fim de `lib/jwt_audit.py`:

```python
if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "exp-check":
        st = exp_status(sys.argv[2], int(sys.argv[3]), int(sys.argv[4]))
        rem = "" if st["remaining"] is None else st["remaining"]
        print(f"{st['state']} {rem}")
    else:
        main(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else "",
             sys.argv[3] if len(sys.argv) > 3 else "")
```

- [ ] **Step 4: Run to verify it passes**

Run: `cd ~/Stiglitz && python3 -m pytest tests/test_lib.py::TestJwtExp -v`
Expected: PASS (6 passed).

- [ ] **Step 5: Compile check + commit**

```bash
cd ~/Stiglitz
python3 -m py_compile lib/jwt_audit.py
git add lib/jwt_audit.py tests/test_lib.py
git commit -m "feat(jwt): CLI exp-check consumivel pelo stiglitz.sh (P1)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 3: Helper `zap_inject_auth_headers()` + reordenar antes do spider

**Files:**
- Modify: `stiglitz.sh` (definição após `zap_setup_auth_context` ~linha 181; chamada ~linha 1429; remoções no pre-warm ~1505-1513 e ~1543-1552)
- Test: `tests/test_lib.py` (guard estrutural de ordenação)

- [ ] **Step 1: Write the failing structural test**

Adicionar ao `TestJwtExp` (ou nova classe `TestStiglitzPhase9Order`):

```python
class TestStiglitzPhase9Order(unittest.TestCase):
    """Garante que o token é injetado ANTES do spider (fronteira do BOLA)."""

    def _sh(self):
        repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(repo, "stiglitz.sh"), encoding="utf-8") as fh:
            return fh.read()

    def test_inject_helper_called_before_spider(self):
        sh = self._sh()
        # "zap_inject_auth_headers\n" casa a CHAMADA (a definição é "...() {")
        call = sh.index("zap_inject_auth_headers\n")
        spider = sh.index("spider/action/scan")
        self.assertLess(call, spider, "auth headers devem ser injetados antes do spider")

    def test_no_duplicate_authtoken_replacer_in_prewarm(self):
        sh = self._sh()
        # A regra AuthToken deve ser adicionada uma única vez (no helper)
        self.assertEqual(sh.count("description=AuthToken&enabled=true"), 1)
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd ~/Stiglitz && python3 -m pytest tests/test_lib.py::TestStiglitzPhase9Order -v`
Expected: `test_inject_helper_called_before_spider` FALHA (`ValueError: substring not found` — helper ainda não existe). `test_no_duplicate_authtoken_replacer_in_prewarm` PASSA já aqui (só há 1 ocorrência da regra no pre-warm) — é um invariante que protege contra a Task 3 introduzir a 2ª cópia sem remover a antiga; deve continuar passando no GREEN.

- [ ] **Step 3a: Definir o helper após `zap_setup_auth_context`**

Inserir após a linha `}` que fecha `zap_setup_auth_context` (~linha 181), antes de `wait_for_zap_progress`:

```bash
# ── Injeção de bearer token / header custom no HttpSender do ZAP (replacer) ──
# Roda ANTES do spider para que spider/AJAX/active-scan e o histórico que a P9.5
# (BOLA) consome herdem o Authorization. Pre-check de exp avisa (não aborta) se o
# JWT expira dentro da janela estimada do scan.
zap_inject_auth_headers() {
    if [ -n "${AUTH_TOKEN:-}" ]; then
        local _win _now _expst _state _rem _auth_enc
        _win=$(( ZAP_SPIDER_TIMEOUT + ${ZAP_AJAX_TIMEOUT:-180} + ZAP_SCAN_TIMEOUT ))
        _now=$(date +%s)
        _expst=$(python3 "$SCRIPT_DIR/lib/jwt_audit.py" exp-check "$AUTH_TOKEN" "$_win" "$_now" 2>/dev/null)
        _state="${_expst%% *}"; _rem="${_expst##* }"
        case "$_state" in
            expired)
                echo -e "  ${RED}[✗] Token JWT já expirou — spider/scan rodarão deslogados${NC}" ;;
            expires_within)
                echo -e "  ${YELLOW}[!] Token JWT expira em ~$(( ${_rem:-0} / 60 ))min (janela do scan ~$(( _win / 60 ))min) — possível perda de cobertura no fim${NC}" ;;
        esac
        _auth_enc=$(_url_quote "Bearer ${AUTH_TOKEN}")
        zap_api_call "replacer/action/addRule" \
            "description=AuthToken&enabled=true&matchType=REQ_HEADER&matchString=Authorization&replacement=${_auth_enc}" \
            > /dev/null 2>&1
        echo -e "  ${GREEN}[✓] Authorization Bearer injetado no ZAP (antes do spider)${NC}"
    fi
    if [ -n "${AUTH_HEADER:-}" ]; then
        local _hname _hval _hval_enc
        _hname="${AUTH_HEADER%%:*}"; _hval="${AUTH_HEADER#*:}"
        _hval_enc=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1].strip(),safe=''))" "$_hval")
        zap_api_call "replacer/action/addRule" \
            "description=CustomHeader&enabled=true&matchType=REQ_HEADER&matchString=${_hname}&replacement=${_hval_enc}" \
            > /dev/null 2>&1
        echo -e "  ${GREEN}[✓] Header customizado injetado no ZAP (antes do spider)${NC}"
    fi
}
```

- [ ] **Step 3b: Chamar o helper antes do spider**

Localizar (~linha 1427-1431):

```bash
        # ── ZAP Context autenticado (#3): configura scan logado se STIGLITZ_AUTH_* setado
        zap_setup_auth_context

        # ── ZAP Spider: complementa o Katana ou age sozinho ────────────
```

Substituir por:

```bash
        # ── ZAP Context autenticado (#3): configura scan logado se STIGLITZ_AUTH_* setado
        zap_setup_auth_context

        # ── Bearer/header no HttpSender ANTES do spider (fronteira do BOLA) ──
        zap_inject_auth_headers

        # ── ZAP Spider: complementa o Katana ou age sozinho ────────────
```

- [ ] **Step 3c: Remover o replacer duplicado do pre-warm (Authorization)**

Localizar (~linhas 1505-1513):

```bash
        # Injetar token de autenticação no ZAP se fornecido
        if [ -n "$AUTH_TOKEN" ]; then
            _auth_enc=$(python3 -c \
                "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1],safe=''))" \
                "Bearer ${AUTH_TOKEN}" 2>/dev/null)
            zap_api_call "replacer/action/addRule" \
                "description=AuthToken&enabled=true&matchType=REQ_HEADER&matchString=Authorization&replacement=${_auth_enc}" \
                > /dev/null 2>&1
            echo -e "  ${GREEN}[✓] Authorization header injetado no ZAP${NC}"
            # Force-crawl endpoints autenticados com o token injetado
```

Substituir por (mantendo o force-crawl, removendo só o replacer já feito no helper):

```bash
        # Token já injetado no HttpSender por zap_inject_auth_headers (antes do spider).
        # Aqui apenas o force-crawl + katana autenticado, que dependem do token presente.
        if [ -n "$AUTH_TOKEN" ]; then
            # Force-crawl endpoints autenticados com o token injetado
```

- [ ] **Step 3d: Remover o replacer duplicado do pre-warm (header custom)**

Localizar (~linhas 1543-1552):

```bash
        if [ -n "$AUTH_HEADER" ]; then
            _hname="${AUTH_HEADER%%:*}"; _hval="${AUTH_HEADER#*:}"
            _hval_enc=$(python3 -c \
                "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1].strip(),safe=''))" \
                "$_hval" 2>/dev/null)
            zap_api_call "replacer/action/addRule" \
                "description=CustomHeader&enabled=true&matchType=REQ_HEADER&matchString=${_hname}&replacement=${_hval_enc}" \
                > /dev/null 2>&1
            echo -e "  ${GREEN}[✓] Header customizado injetado no ZAP${NC}"
        fi
        sleep 3
```

Substituir por (header custom já tratado no helper):

```bash
        sleep 3
```

- [ ] **Step 3e: Limpar o `unset` órfão do pre-warm**

Localizar (~linha 1554):

```bash
        unset _pw_path _pw_url _pw_enc _robots _rpath _renc _hname _hval _hval_enc _auth_enc
```

Substituir por (vars de header/token não existem mais neste bloco):

```bash
        unset _pw_path _pw_url _pw_enc _robots _rpath _renc
```

- [ ] **Step 4: Run structural test + syntax + shellcheck**

```bash
cd ~/Stiglitz
python3 -m pytest tests/test_lib.py::TestStiglitzPhase9Order -v   # PASS (2 passed)
bash -n stiglitz.sh                                               # sem saída
shellcheck --severity=warning stiglitz.sh                        # sem warnings novos
```
Expected: pytest PASS; `bash -n` silencioso; shellcheck sem warning novo introduzido.

- [ ] **Step 5: Commit**

```bash
cd ~/Stiglitz
git add stiglitz.sh tests/test_lib.py
git commit -m "feat(zap): injeta bearer/header ANTES do spider — expande fronteira do BOLA (P1)

Causa-raiz: replacer Authorization entrava no pre-warm, depois de spider/AJAX.
Extraido p/ helper zap_inject_auth_headers() chamado antes do spider; spider,
AJAX, active-scan e historico (P9.5) passam a carregar o token. Pre-check de exp
avisa sem abortar. Guard estrutural de ordenacao no test_lib.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 4: Preflight de browser + `setOptionBrowserId` (AJAX chromium)

**Files:**
- Modify: `stiglitz.sh` (bloco AJAX Spider ~linhas 1445-1469)
- Test: `tests/test_lib.py` (guard estrutural)

- [ ] **Step 1: Write the failing structural test**

Adicionar ao `TestStiglitzPhase9Order`:

```python
    def test_ajax_sets_browser_id(self):
        sh = self._sh()
        self.assertIn("ajaxSpider/action/setOptionBrowserId", sh)
        self.assertIn("chrome-headless", sh)
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd ~/Stiglitz && python3 -m pytest tests/test_lib.py::TestStiglitzPhase9Order::test_ajax_sets_browser_id -v`
Expected: FAIL — strings ainda não presentes.

- [ ] **Step 3: Inserir preflight no início do bloco AJAX**

Localizar (~linhas 1445-1448):

```bash
        if [ "${STIGLITZ_AJAX_SPIDER:-1}" = "1" ]; then
            echo -e "  ${BLUE}[…] AJAX Spider (SPA crawl headless)...${NC}"
            # inScope=true exige escopo definido (senão internal_error — validado);
            # com contexto autenticado usamos scanAsUser+inScope, senão inScope=false.
```

Substituir por:

```bash
        if [ "${STIGLITZ_AJAX_SPIDER:-1}" = "1" ]; then
            echo -e "  ${BLUE}[…] AJAX Spider (SPA crawl headless)...${NC}"
            # Preflight: o browser default do ZAP é firefox-headless. Escolher o que
            # existe no host (chromium preferido neste ambiente; firefox se houver).
            _ajax_browser=""
            if command -v chromium >/dev/null 2>&1 || command -v chromium-browser >/dev/null 2>&1 \
               || command -v google-chrome >/dev/null 2>&1 || command -v chrome >/dev/null 2>&1; then
                _ajax_browser="chrome-headless"
            elif command -v firefox >/dev/null 2>&1 || command -v firefox-esr >/dev/null 2>&1; then
                _ajax_browser="firefox-headless"
            fi
            if [ -z "$_ajax_browser" ]; then
                echo -e "  ${YELLOW}[○] Nenhum browser (chromium/firefox) no host — AJAX Spider pulado${NC}"
            else
                zap_api_call "ajaxSpider/action/setOptionBrowserId" "String=${_ajax_browser}" > /dev/null 2>&1
                if [ "$_ajax_browser" = "chrome-headless" ]; then
                    _chr_bin=$(command -v chromium 2>/dev/null || command -v chromium-browser 2>/dev/null || command -v google-chrome 2>/dev/null)
                    [ -n "$_chr_bin" ] && zap_api_call "selenium/action/setOptionChromeBinaryPath" "String=$(_url_quote "$_chr_bin")" > /dev/null 2>&1
                fi
                echo -e "  ${BLUE}[…] AJAX Spider usará browser: ${_ajax_browser}${NC}"
            fi
            # inScope=true exige escopo definido (senão internal_error — validado);
            # com contexto autenticado usamos scanAsUser+inScope, senão inScope=false.
            if [ -n "$_ajax_browser" ]; then
```

- [ ] **Step 3b: Fechar o `if` do browser em volta da execução AJAX**

O bloco existente que inicia o AJAX (`if [ -n "$ZAP_CONTEXT_ID" ]; then ... fi` + o `if echo "$_ajax_start" | grep -q "OK"` ... até o `unset`) passa a ficar DENTRO do novo `if [ -n "$_ajax_browser" ]; then`. Localizar o fim do bloco AJAX (~linhas 1468-1469):

```bash
            unset _ajax_start _ajax_st _ajax_waited _ajax_n
        fi
```

Substituir por (fecha o `if browser` antes do `fi` do AJAX_SPIDER, e limpa as vars novas):

```bash
            unset _ajax_start _ajax_st _ajax_waited _ajax_n
            fi  # fim if _ajax_browser
            unset _ajax_browser _chr_bin
        fi
```

> Nota de indentação: o conteúdo entre o novo `if [ -n "$_ajax_browser" ]; then` (Step 3) e este `fi` é o bloco AJAX original; não precisa re-indentar para o `bash -n` passar, mas mantenha consistência visual ao revisar.

- [ ] **Step 4: Run structural test + syntax + shellcheck**

```bash
cd ~/Stiglitz
python3 -m pytest tests/test_lib.py::TestStiglitzPhase9Order -v   # PASS (3 passed)
bash -n stiglitz.sh                                               # sem saída
shellcheck --severity=warning stiglitz.sh                        # sem warning novo
```
Expected: pytest PASS; `bash -n` silencioso; shellcheck limpo.

- [ ] **Step 5: Commit**

```bash
cd ~/Stiglitz
git add stiglitz.sh tests/test_lib.py
git commit -m "feat(zap): AJAX Spider via chrome-headless com preflight de browser (P1)

Default do ZAP e firefox-headless; sem firefox no ambiente. Preflight escolhe
chrome-headless (chromium) e aponta o binario via selenium setOptionChromeBinaryPath;
firefox como fallback; sem browser -> pula com degradacao.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 5: Validação ao vivo (Juice Shop + ZAP via docker)

**Files:** nenhum (verificação). Pré-requisito: docker disponível.

- [ ] **Step 1: Subir o alvo de lab**

```bash
docker run --rm -d -p 3000:3000 --name juice bkimminich/juice-shop
sleep 20 && curl -s -o /dev/null -w "%{http_code}\n" http://localhost:3000   # 200
```

- [ ] **Step 2: Obter um JWT do Juice Shop (login)**

```bash
TOKEN=$(curl -s -X POST http://localhost:3000/rest/user/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@juice-sh.op","password":"admin123"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['authentication']['token'])")
echo "${TOKEN:0:24}..."   # deve imprimir prefixo do JWT
```
> Se as credenciais default não logarem, registrar um usuário via `/api/Users` e logar com ele.

- [ ] **Step 3: Rodar a Fase 9 autenticada**

```bash
cd ~/Stiglitz
mkdir -p ~/scans/_lab/juice
bash stiglitz.sh http://localhost:3000 --token "$TOKEN" \
  --outdir ~/scans/_lab/juice --only-phase "P9" 2>&1 | tee ~/scans/_lab/juice_p9.log
```

- [ ] **Step 4: Verificar propagação do bearer (BOLA frontier)**

Confirmar no log/saída:
- linha `[✓] Authorization Bearer injetado no ZAP (antes do spider)` ANTES de `Iniciando ZAP Spider`.
- contagem de URLs no contexto ZAP (`Total no contexto ZAP: ...`) — rodar também SEM `--token` para baseline e comparar; autenticado deve descobrir rotas a mais (ex.: `/rest/basket/*`, `/api/*`).

```bash
grep -nE "Authorization Bearer injetado|Iniciando ZAP Spider|Total no contexto ZAP" ~/scans/_lab/juice_p9.log
```
Expected: a linha de injeção aparece ANTES da do spider; total autenticado >= baseline.

- [ ] **Step 5: Verificar render AJAX (chromium)**

Confirmar no log:
- `AJAX Spider usará browser: chrome-headless`.
- `AJAX Spider: N rota(s) client-side descoberta(s)` com **N > 0** (renderizou) — NÃO `[○] indisponível`.

```bash
grep -nE "AJAX Spider usará browser|rota\(s\) client-side|AJAX Spider indisponível" ~/scans/_lab/juice_p9.log
```
Expected: browser chrome-headless + N>0.

> **Se o confinamento snap bloquear o chromium** (AJAX cai em indisponível/erro de launch): registrar no log de validação e documentar o caminho de destrave em `docs/ROADMAP.md` (chromium não-snap via apt OU ZAP não-snap). O critério de pronto aceita "degradação confirmada + caminho documentado" para a parte AJAX, conforme o spec.

- [ ] **Step 6: Teardown**

```bash
docker stop juice 2>/dev/null || true
```

---

## Task 6: Documentação + roadmap

**Files:**
- Modify: `CLAUDE.md` (raiz `~/Stiglitz`) — descrição da Fase 9
- Modify: `docs/ROADMAP.md`

- [ ] **Step 1: Atualizar a descrição da Fase 9 no `CLAUDE.md`**

No item "Fase 9 — ZAP Spider + Active Scan", acrescentar uma linha sobre a propagação do bearer ANTES do spider e o AJAX via chrome-headless. Exemplo de texto a inserir:

```markdown
   - **Bearer token / header custom** são injetados no HttpSender do ZAP (replacer) **antes** do spider, de modo que spider/AJAX/active-scan e o histórico que a Fase 9.5 (BOLA) consome rodem autenticados. Pré-check de `exp` do JWT avisa (sem abortar) se o token expira dentro da janela do scan.
   - **AJAX Spider** seleciona o browser por preflight (`chrome-headless` preferido; `firefox-headless` se houver), com degradação graciosa quando nenhum browser está disponível.
```

- [ ] **Step 2: Marcar o item P1 no `docs/ROADMAP.md`**

Mover o item da seção "P1 restante (ordem de retorno)" para "Feitos e mergeados em `main`", com bullet:

```markdown
- ✅ **ZAP bearer-token session propagation + AJAX render** (Fase 9): bearer/header
  injetados no HttpSender ANTES do spider (spider/AJAX/active-scan/histórico P9.5 herdam
  o token — fronteira do BOLA expandida); pré-check de `exp` (`jwt_audit.exp_status`);
  AJAX Spider via `chrome-headless` com preflight de browser. Validado ao vivo no Juice Shop.
```
> Se a validação AJAX ficou bloqueada pelo snap, ajustar o texto para "render AJAX com caminho de destrave documentado" em vez de "validado ao vivo".

- [ ] **Step 3: Commit**

```bash
cd ~/Stiglitz
git add CLAUDE.md docs/ROADMAP.md
git commit -m "docs: Fase 9 bearer propagation + AJAX chromium; roadmap P1 (P1)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 7: Suite completa + finalização da branch

- [ ] **Step 1: Rodar a suite inteira**

```bash
cd ~/Stiglitz
python3 -m pytest tests/test_lib.py -q
bash -n stiglitz.sh && shellcheck --severity=warning stiglitz.sh
```
Expected: suite verde (514 passed + os novos casos = ~520 passed / 4 skipped); `bash -n` e shellcheck limpos.

- [ ] **Step 2: Finalizar a branch**

Usar a skill `superpowers:finishing-a-development-branch` para decidir merge na `main` vs PR. O push fica a critério do operador (trabalho sincronizado entre máquinas).

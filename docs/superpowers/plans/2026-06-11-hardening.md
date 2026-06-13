# Frente 5 — Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Quatro reforços de robustez/segurança no Stiglitz: estreitar bare `except:`, selar o `audit.log` com HMAC, aplicar escopo consistente nas fases ofensivas e validar saída pós-fase no checkpoint.

**Architecture:** Unidades independentes. A (Python, edição local em 4 arquivos) + B (bash `audit_seal` + `verify_audit.py` em Python) + C (helper de escopo reusado por brute/sqli/xss) + D (helper bash `phase_output_ok` nos call-sites) + E (docs). Cada uma é uma task isolada; sem dependência entre elas.

**Tech Stack:** Python 3 (stdlib: `hmac`, `hashlib`, `json`, `urllib`), bash, `openssl`, pytest, shellcheck.

**Spec:** `docs/superpowers/specs/2026-06-11-hardening-design.md`

---

## File Structure

- **Modify** `lib/parsers.py` — estreitar 9 `except:`.
- **Modify** `lib/js_analysis.py` — estreitar 2 `except:`.
- **Modify** `lib/cve_enrich.py` — estreitar 2 `except:`.
- **Modify** `lib/security_headers.py` — estreitar 1 `except:`.
- **Create** `tests/test_parsers_degrade.py` — regressão: parsers degrada em entrada malformada após o estreitamento.
- **Modify** `stiglitz_red.sh` — `audit_seal()` + chamada no finalize (`run_report`/fim do `main`); helper de escopo + uso em brute/sqli/xss.
- **Modify** `tests/verify_audit.py` — `verify_seal()` + CLI `--seal`/`--key`.
- **Create** `tests/test_audit_seal.py` — TDD do selo (Python) + cross-check com `openssl`.
- **Create** `lib/scope.py` — helper puro `in_scope` + CLI de filtro.
- **Create** `tests/test_scope.py` — testes do helper.
- **Modify** `stiglitz.sh` — `phase_output_ok()` + wiring nos call-sites de `phase_done`.
- **Create** `tests/test_phase_output_ok.py` — testa o helper (via subprocess bash) ou um espelho Python testável.
- **Modify** `CLAUDE.md`, `docs/ROADMAP.md` — docs.

Convenção de import nos testes Python (padrão do repo): `sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))`.

---

## Task A: Estreitar bare `except:` em `lib/*.py`

**Files:**
- Modify: `lib/parsers.py`, `lib/js_analysis.py`, `lib/cve_enrich.py`, `lib/security_headers.py`
- Test: `tests/test_parsers_degrade.py`

**Tabela de estreitamento (reconfirmar os números de linha com `grep -rEn "except\s*:" lib/` — eles deslocam):**

| Arquivo:linha | Contexto do `try` | Trocar `except:` por |
|---|---|---|
| `parsers.py:154` | `json.loads(line)` + `dict.get` + regex | `except (json.JSONDecodeError, ValueError, TypeError, AttributeError):` |
| `parsers.py:164` | `open()` + `json.load` | `except (json.JSONDecodeError, ValueError, OSError):` |
| `parsers.py:204` | `json.loads(line)` | `except (json.JSONDecodeError, ValueError):` |
| `parsers.py:222` | `open()` + `json.load` + `dict` ops | `except (json.JSONDecodeError, ValueError, OSError, AttributeError):` |
| `parsers.py:234` | leitura de arquivo texto (linhas) | `except (OSError, UnicodeDecodeError):` |
| `parsers.py:256` | `open()`+`json.load`+iteração de dict | `except (json.JSONDecodeError, ValueError, OSError, AttributeError, TypeError):` |
| `parsers.py:283` | `open()`+`json.load`+iteração (OpenAPI) | `except (json.JSONDecodeError, ValueError, OSError, AttributeError, TypeError):` |
| `parsers.py:300` | `open()`+`json.load`+iteração | `except (json.JSONDecodeError, ValueError, OSError, AttributeError):` |
| `parsers.py:321` | `urllib.request.urlopen` + decode + regex | `except (urllib.error.URLError, OSError, ValueError, UnicodeDecodeError):` |
| `js_analysis.py:181` | `checker(ver)` (comparação de versão) | `except (ValueError, TypeError, AttributeError, IndexError):` |
| `js_analysis.py:211` | `urllib.request.urlopen` (já há `except HTTPError` acima) | `except (urllib.error.URLError, OSError):` |
| `cve_enrich.py:36` | `json.load` do cache KEV | `except (json.JSONDecodeError, ValueError, OSError, KeyError):` |
| `cve_enrich.py:78` | `json.loads(line)` + dict ops | `except (json.JSONDecodeError, ValueError, AttributeError, TypeError):` |
| `security_headers.py:152` | handler por-URL amplo (rede+parse+headers) | `except Exception:` (amplo legítimo; NÃO bare — deixa de mascarar `KeyboardInterrupt`/`SystemExit`) + comentário |

> Confirmar que `urllib.error` está importado em `parsers.py`/`js_analysis.py` (eles usam `urllib.request`; `import urllib.error` pode faltar — adicionar se necessário). `js_analysis.py:211` mantém `st=0; ct=""; body=""` no corpo do except (não mudar o corpo, só o cabeçalho).

- [ ] **Step 1: Write the failing/guard test** (regressão de degradação para o site testável `parsers.py`)

A função pública testável é a extração de URLs do `parsers.py`. Inspecionar o nome real com `grep -nE "^def " lib/parsers.py` (provável `extract_urls(outdir, target)` ou similar) e usar o nome correto no teste.

```python
# tests/test_parsers_degrade.py
import os, sys, tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
import parsers as P


def test_extract_urls_degrades_on_malformed_inputs():
    """JSON inválido / arquivos corrompidos não devem levantar — devem degradar."""
    outdir = tempfile.mkdtemp()
    os.makedirs(os.path.join(outdir, ""), exist_ok=True)
    # input_nuclei.jsonl com linha não-JSON  + input_zap.json corrompido
    with open(os.path.join(outdir, "input_nuclei.jsonl"), "w") as f:
        f.write("isto não é json\n{\"matched-at\": \"http://t/a\"}\n")
    with open(os.path.join(outdir, "input_zap.json"), "w") as f:
        f.write("{ corrompido")
    with open(os.path.join(outdir, "input_httpx.jsonl"), "w") as f:
        f.write("{quebrado\n")
    # Descobrir a assinatura real; ajustar a chamada conforme `grep ^def lib/parsers.py`.
    result = P.extract_urls(outdir, "t.com")     # nome/assinatura a confirmar no Step 0
    assert result is not None                     # não levantou; a linha válida foi parseada
```

- [ ] **Step 2: Run to verify it passes BEFORE (caracterização) e falha se o estreitamento quebrar**

Run: `cd /home/trick/Stiglitz && python3 -m pytest tests/test_parsers_degrade.py -v`
Expected: PASS já com o código atual (bare `except:` degrada). Este teste é o guard: deve continuar PASS depois do estreitamento. (Se a assinatura de `extract_urls` divergir, ajustar o teste no Step 1 — NÃO é placeholder, é confirmar o nome real.)

- [ ] **Step 3: Aplicar os estreitamentos da tabela**

Editar cada site conforme a tabela. Para cada arquivo, após editar, confirmar imports (`import json`, `import urllib.error` onde usado). Não mudar o corpo dos except (só o cabeçalho `except ...:`).

- [ ] **Step 4: Verificar — testes + py_compile + suíte**

Run: `cd /home/trick/Stiglitz && python3 -m pytest tests/test_parsers_degrade.py -v && python3 -m py_compile lib/parsers.py lib/js_analysis.py lib/cve_enrich.py lib/security_headers.py && python3 -m pytest tests/ -q`
Expected: o guard PASS, py_compile limpo, suíte completa verde (sem regressão). Confirmar zero bare excepts: `grep -rEn "except\s*:" lib/` retorna vazio.

- [ ] **Step 5: Commit**

```bash
cd /home/trick/Stiglitz
git add lib/parsers.py lib/js_analysis.py lib/cve_enrich.py lib/security_headers.py tests/test_parsers_degrade.py
git commit -m "harden(lib): estreita 14 bare except: para tipos específicos

Para de mascarar KeyboardInterrupt/SystemExit e bugs; preserva a degradação
do erro esperado. parsers.py ×9, js_analysis.py ×2, cve_enrich.py ×2,
security_headers.py ×1 (este amplo legítimo → except Exception).

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task B: Selo HMAC no `audit.log`

**Files:**
- Modify: `tests/verify_audit.py` (add `verify_seal` + CLI), `stiglitz_red.sh` (`audit_seal()` + chamada no finalize)
- Test: `tests/test_audit_seal.py`

Contexto confirmado: `audit_init`/`audit` (stiglitz_red.sh:68-92) constroem o chain; `curr_hash = sha256(prev|ts|event)[:16]`; a CABEÇA é o último `curr_hash` (último campo após `:`). `verify_audit.py:verify(path)` já valida o chain e ao fim `prev` contém a cabeça.

- [ ] **Step 1: Write the failing test (Python — canônico)**

```python
# tests/test_audit_seal.py
import os, sys, hmac, hashlib, tempfile, subprocess
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))  # raiz: verify_audit em tests/
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tests"))
import verify_audit as V

KEY = "chave-de-teste-123"


def _build_log(path):
    """Constrói um audit.log válido (mesmo esquema do audit_init/audit do bash)."""
    seed = "00" * 8
    lines, prev = [], seed
    def h(prev, ts, ev):
        return hashlib.sha256(f"{prev}|{ts}|{ev}".encode()).hexdigest()[:16]
    rows = [("AUDIT_INIT seed=" + seed, seed)]
    seq = 0
    ev0, ts0 = "AUDIT_INIT seed=" + seed, "2026-06-11T00:00:00Z"
    c0 = h(seed, ts0, ev0)
    lines.append(f"{seq:04d} | {ts0} | {ev0} | {seed}:{c0}")
    prev = c0
    for i, ev in enumerate(["PHASE_START name=recon", "PHASE_END name=recon result=ok"], start=1):
        ts = f"2026-06-11T00:0{i}:00Z"
        c = h(prev, ts, ev)
        lines.append(f"{i:04d} | {ts} | {ev} | {prev}:{c}")
        prev = c
    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")
    return prev  # cabeça


def _seal_hex(head, key):
    return hmac.new(key.encode(), head.encode(), hashlib.sha256).hexdigest()


def test_verify_seal_accepts_valid():
    d = tempfile.mkdtemp()
    log = os.path.join(d, "audit.log")
    head = _build_log(log)
    seal = os.path.join(d, "audit.log.seal")
    with open(seal, "w") as f:
        f.write(f"HMAC-SHA256 {_seal_hex(head, KEY)} head={head}\n")
    ok, msg = V.verify_seal(log, seal, KEY)
    assert ok, msg


def test_verify_seal_rejects_tampered_log():
    d = tempfile.mkdtemp()
    log = os.path.join(d, "audit.log")
    head = _build_log(log)
    seal = os.path.join(d, "audit.log.seal")
    with open(seal, "w") as f:
        f.write(f"HMAC-SHA256 {_seal_hex(head, KEY)} head={head}\n")
    # adultera o log: muda um evento → cabeça recomputada diverge → selo não bate
    data = open(log).read().replace("result=ok", "result=FALSIFICADO")
    open(log, "w").write(data)
    ok, msg = V.verify_seal(log, seal, KEY)
    assert not ok


def test_verify_seal_rejects_wrong_key():
    d = tempfile.mkdtemp()
    log = os.path.join(d, "audit.log")
    head = _build_log(log)
    seal = os.path.join(d, "audit.log.seal")
    with open(seal, "w") as f:
        f.write(f"HMAC-SHA256 {_seal_hex(head, KEY)} head={head}\n")
    ok, msg = V.verify_seal(log, seal, "chave-errada")
    assert not ok
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd /home/trick/Stiglitz && python3 -m pytest tests/test_audit_seal.py -v`
Expected: FAIL — `AttributeError: module 'verify_audit' has no attribute 'verify_seal'`.

- [ ] **Step 3: Implement `verify_seal` em `tests/verify_audit.py`**

Adicionar `import hmac` no topo e a função (reusa `verify` para validar o chain e obter a cabeça):

```python
def _head_hash(path):
    """Revalida o chain e devolve (ok, head_or_msg). head = último curr_hash."""
    expected_seq, prev = 0, None
    with open(path, encoding="utf-8") as f:
        for lineno, raw in enumerate(f, start=1):
            line = raw.rstrip("\n")
            if not line.strip():
                continue
            try:
                seq_str, ts, rest = [p.strip() for p in line.split(" | ", 2)]
                event, hashes = rest.rsplit(" | ", 1)
                p_h, c_h = hashes.split(":")
            except ValueError:
                return False, f"linha {lineno}: formato inválido"
            if prev is not None and p_h != prev:
                return False, f"linha {lineno}: prev_hash diverge"
            if _h(p_h, ts, event) != c_h:
                return False, f"linha {lineno}: curr_hash diverge"
            prev, expected_seq = c_h, expected_seq + 1
    if expected_seq == 0:
        return False, "audit log vazio"
    return True, prev


def verify_seal(log_path, seal_path, key):
    ok, head = _head_hash(log_path)
    if not ok:
        return False, f"chain inválido: {head}"
    try:
        with open(seal_path, encoding="utf-8") as f:
            parts = f.read().strip().split()
        algo, sealed_hex = parts[0], parts[1]
        sealed_head = parts[2].split("=", 1)[1] if len(parts) > 2 and "=" in parts[2] else None
    except (OSError, IndexError, ValueError) as e:
        return False, f"selo ilegível: {e}"
    if algo != "HMAC-SHA256":
        return False, f"algoritmo de selo inesperado: {algo}"
    if sealed_head is not None and sealed_head != head:
        return False, f"cabeça do selo ({sealed_head}) diverge da recomputada ({head})"
    expected = hmac.new(key.encode(), head.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, sealed_hex):
        return False, "selo HMAC não confere (re-encadeamento ou chave errada)"
    return True, f"selo OK — cabeça {head}"
```

Estender `main()` para aceitar o modo selo (chave via `--key` ou env `STIGLITZ_AUDIT_KEY`):

```python
def main():
    args = sys.argv[1:]
    if not args:
        print("Uso: verify_audit.py <audit.log> [--seal <audit.log.seal> [--key K]]", file=sys.stderr)
        sys.exit(2)
    log = args[0]
    if "--seal" in args:
        seal = args[args.index("--seal") + 1]
        key = (args[args.index("--key") + 1] if "--key" in args
               else os.environ.get("STIGLITZ_AUDIT_KEY", ""))
        if not key:
            print("selo requer chave (--key ou STIGLITZ_AUDIT_KEY)", file=sys.stderr)
            sys.exit(2)
        ok, msg = verify_seal(log, seal, key)
    else:
        ok, msg = verify(log)
    print(msg)
    sys.exit(0 if ok else 1)
```

Adicionar `import os` no topo se faltar.

- [ ] **Step 4: Run to verify Python tests pass**

Run: `cd /home/trick/Stiglitz && python3 -m pytest tests/test_audit_seal.py -v && python3 -m py_compile tests/verify_audit.py`
Expected: 3 PASS + compile limpo.

- [ ] **Step 5: Implement `audit_seal()` no bash + cross-check test**

Em `stiglitz_red.sh`, após `audit()` (~linha 92), adicionar:

```bash
audit_seal() {
    # Sela a CABEÇA do hash-chain com HMAC-SHA256(STIGLITZ_AUDIT_KEY). Sem chave, não sela.
    [ -z "$AUDIT_LOG" ] || [ ! -s "$AUDIT_LOG" ] && return 0
    if [ -z "${STIGLITZ_AUDIT_KEY:-}" ]; then
        audit "SEAL_SKIPPED reason=no_key" 2>/dev/null || true
        return 0
    fi
    local head; head=$(awk -F'[ :]+' 'END{print $NF}' "$AUDIT_LOG" 2>/dev/null)
    [ -z "$head" ] && return 0
    local mac
    if has openssl; then
        mac=$(printf '%s' "$head" | openssl dgst -sha256 -hmac "$STIGLITZ_AUDIT_KEY" -r 2>/dev/null | cut -d' ' -f1)
    else
        mac=$(STIGLITZ_AUDIT_KEY="$STIGLITZ_AUDIT_KEY" python3 -c \
          'import os,hmac,hashlib,sys;print(hmac.new(os.environ["STIGLITZ_AUDIT_KEY"].encode(),sys.argv[1].encode(),hashlib.sha256).hexdigest())' "$head" 2>/dev/null)
    fi
    [ -z "$mac" ] && { warn "audit_seal: falha ao computar HMAC — não selado"; return 0; }
    printf 'HMAC-SHA256 %s head=%s\n' "$mac" "$head" > "$AUDIT_LOG.seal"
    chmod 600 "$AUDIT_LOG.seal" 2>/dev/null || true
}
```

> `has` é o helper de detecção de comando já usado no script (ex.: `has hydra`). Confirmar o nome (`grep -nE "^has\(\)|has\(\)" stiglitz_red.sh`); se for `command -v`, ajustar.

Chamar `audit_seal` no finalize — ao fim de `main()` (após `run_report`, ~linha 1201) ou num `trap EXIT` dedicado. Local escolhido: última linha de `main()` antes do retorno.

Cross-check test (garante que o `openssl` do bash produz o MESMO HMAC que o `hmac` do Python):

```python
# acrescentar em tests/test_audit_seal.py
def test_bash_openssl_matches_python_hmac():
    import shutil
    if not shutil.which("openssl"):
        import pytest; pytest.skip("openssl ausente")
    head, key = "deadbeefdeadbeef", "k"
    py = hmac.new(key.encode(), head.encode(), hashlib.sha256).hexdigest()
    out = subprocess.run(
        ["openssl", "dgst", "-sha256", "-hmac", key, "-r"],
        input=head, capture_output=True, text=True)
    sh = out.stdout.split()[0]
    assert sh == py
```

- [ ] **Step 6: Verificar bash + suíte**

Run: `cd /home/trick/Stiglitz && bash -n stiglitz_red.sh && shellcheck --severity=warning stiglitz_red.sh && python3 -m pytest tests/test_audit_seal.py -v && python3 -m pytest tests/ -q`
Expected: `bash -n` ok, shellcheck limpo, 4 testes do selo PASS, suíte verde.

- [ ] **Step 7: Commit**

```bash
cd /home/trick/Stiglitz
git add stiglitz_red.sh tests/verify_audit.py tests/test_audit_seal.py
git commit -m "harden(audit): selo HMAC da cabeça do hash-chain no finalize

audit_seal() grava audit.log.seal = HMAC-SHA256(STIGLITZ_AUDIT_KEY, cabeça).
Sem chave, degrada (SEAL_SKIPPED). verify_audit.py --seal valida e rejeita
re-encadeamento pós-fato / chave errada. openssl com fallback python.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task C: Escopo consistente nas fases ofensivas (Opção A)

**Files:**
- Create: `lib/scope.py` (helper puro + CLI), Test: `tests/test_scope.py`
- Modify: `stiglitz_red.sh` (usar o helper em brute/sqli/xss + warn/audit sem escopo)

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_scope.py
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
import scope as S


def test_in_scope_exact_and_subdomain():
    assert S.in_scope("https://a.com/x", ["a.com"]) is True
    assert S.in_scope("https://api.a.com/x", ["a.com"]) is True


def test_out_of_scope():
    assert S.in_scope("https://evil.com/?redirect=a.com", ["a.com"]) is False
    assert S.in_scope("https://nota.com/x", ["a.com"]) is False


def test_no_scope_is_fail_open():
    assert S.in_scope("https://anything.com/x", []) is True


def test_malformed_url_with_scope_is_out():
    assert S.in_scope("not a url", ["a.com"]) is False
    assert S.in_scope("", ["a.com"]) is False


def test_filter_lines():
    lines = ["https://a.com/1", "https://evil.com/2", "https://api.a.com/3"]
    assert S.filter_in_scope(lines, ["a.com"]) == ["https://a.com/1", "https://api.a.com/3"]
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd /home/trick/Stiglitz && python3 -m pytest tests/test_scope.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'scope'`.

- [ ] **Step 3: Implement `lib/scope.py`**

```python
#!/usr/bin/env python3
"""scope.py — escopo de engajamento: in_scope(url, scope_domains).

Fail-open só quando scope_domains vazio (operador não delimitou). Com escopo,
in-scope = host igual a um domínio do escopo ou subdomínio real dele. URL
malformada com escopo definido => fora de escopo. Puro, sem rede. CLI filtra
stdin → stdout. Ponto único de verdade reusado por ingest/brute/sqli/xss.
"""
import sys
import urllib.parse


def _norm(domains):
    return [d.strip().lower().lstrip("*.") for d in domains if d and d.strip()]


def in_scope(url, scope_domains):
    sd = _norm(scope_domains)
    if not sd:                       # sem escopo: fail-open (operador não delimitou)
        return True
    try:
        host = (urllib.parse.urlsplit(url).hostname or "").lower()
    except (ValueError, AttributeError):
        return False
    if not host:
        return False
    return any(host == d or host.endswith("." + d) for d in sd)


def filter_in_scope(lines, scope_domains):
    out = []
    for line in lines:
        u = line.strip()
        if u and in_scope(u, scope_domains):
            out.append(u)
    return out


def _main(argv):
    # uso: scope.py <dom1> [dom2 ...]  (lê URLs do stdin, imprime as in-scope)
    sd = argv
    for u in filter_in_scope(sys.stdin.read().splitlines(), sd):
        print(u)
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
```

- [ ] **Step 4: Run to verify it passes**

Run: `cd /home/trick/Stiglitz && python3 -m pytest tests/test_scope.py -v && python3 -m py_compile lib/scope.py`
Expected: 5 PASS + compile limpo.

- [ ] **Step 5: Aplicar nas fases ofensivas do `stiglitz_red.sh`**

Adicionar um helper bash que filtra um arquivo de alvos via `lib/scope.py` quando há escopo, e emite warn/audit quando não há. Inserir perto dos outros helpers (após `audit_seal`):

```bash
scope_guard() {
    # scope_guard <fase> <arquivo_de_alvos>  — filtra in-scope se houver escopo;
    # senão, warn alto + audit. Não-bloqueante. Edita o arquivo in-place quando filtra.
    local phase="$1" file="$2"
    if [ "${#SCOPE_DOMAINS[@]}" -eq 0 ]; then
        warn "ESCOPO NÃO DEFINIDO — fase '$phase' rodará sem filtro de escopo (fail-open)"
        audit "SCOPE_NONE phase=$phase" 2>/dev/null || true
        return 0
    fi
    [ -s "$file" ] || return 0
    local before after tmp; before=$(wc -l < "$file" 2>/dev/null || echo 0)
    tmp=$(mktemp)
    python3 "$LIB/scope.py" "${SCOPE_DOMAINS[@]}" < "$file" > "$tmp" 2>/dev/null || { rm -f "$tmp"; return 0; }
    after=$(wc -l < "$tmp" 2>/dev/null || echo 0)
    mv "$tmp" "$file"
    audit "SCOPE_FILTERED phase=$phase before=$before after=$after" 2>/dev/null || true
    [ "$before" != "$after" ] && info "Escopo: $phase filtrado $before→$after alvos"
}
```

Chamar `scope_guard` antes de consumir alvos nas fases ofensivas:
- **brute** (`run_brute`, antes do `run_brute_phase`): `scope_guard brute "$OUTDIR/data/open_services.txt"`.
- **sqli** e **xss**: localizar onde lêem a lista de alvos (`grep -nE "targets_scored|run_sqli|run_xss" stiglitz_red.sh`) e chamar `scope_guard sqli <arquivo>` / `scope_guard xss <arquivo>` antes do loop de ataque.

> `$LIB` é o dir de libs já usado (`source "$LIB/brute.sh"`). `SCOPE_DOMAINS` é o array já populado de `--scope`/`--scope-file`. `open_services.txt` pode conter `host:porta` — se não for URL, `scope.py` o trata como fora (host vazio); por isso, para serviços, passar como `http://host` ou ajustar `scope_guard` para serviços (prefixar `//host`). Confirmar o formato de `open_services.txt` no Step 0 e adaptar (ex.: `sed 's#^#//#'` antes do filtro para extrair host de `host:porta`).

- [ ] **Step 6: Verificar bash + suíte**

Run: `cd /home/trick/Stiglitz && bash -n stiglitz_red.sh && shellcheck --severity=warning stiglitz_red.sh && python3 -m pytest tests/ -q`
Expected: ok / limpo / verde.

- [ ] **Step 7: Commit**

```bash
cd /home/trick/Stiglitz
git add lib/scope.py tests/test_scope.py stiglitz_red.sh
git commit -m "harden(scope): in_scope consistente em brute/sqli/xss + warn sem escopo

lib/scope.py vira ponto único de verdade (fail-open só sem escopo). scope_guard
filtra os alvos das fases ofensivas quando escopo definido (audit SCOPE_FILTERED)
e emite warn+audit SCOPE_NONE quando não há (Opção A, não-bloqueante).

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task D: Validação de saída pós-fase no checkpoint

**Files:**
- Modify: `stiglitz.sh` (`phase_output_ok()` + wiring nos call-sites de `phase_done`)
- Test: `tests/test_phase_output_ok.py` (via subprocess do bash)

Contexto: `phase_done()` (stiglitz.sh:460) faz `echo "$1=done:..." >> "$STIGLITZ_STATE"`. `phase_skip()` (466) checa se está done. Validar saída ANTES de marcar.

- [ ] **Step 1: Write the failing test (testa o helper via bash subprocess)**

```python
# tests/test_phase_output_ok.py
import os, subprocess, tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Extrai a função phase_output_ok do stiglitz.sh e a exercita isolada.
_HARNESS = r'''
set -e
# stub das deps usadas pelo helper:
warn() {{ echo "WARN: $*" >&2; }}
source_phase_output_ok() {{
  # carrega só a função do script sem rodar o script inteiro
  eval "$(awk '/^phase_output_ok\(\) \{{/,/^\}}/' "{root}/stiglitz.sh")"
}}
source_phase_output_ok
if phase_output_ok "FASE_X" "$1" "$2"; then echo OK; else echo FAIL; fi
'''


def _run(harness_args):
    d = tempfile.mkdtemp()
    present = os.path.join(d, "present.txt"); open(present, "w").write("x\n")
    empty = os.path.join(d, "empty.txt"); open(empty, "w").close()
    missing = os.path.join(d, "missing.txt")
    mapping = {"present": present, "empty": empty, "missing": missing}
    a, b = (mapping[x] for x in harness_args)
    script = _HARNESS.format(root=ROOT)
    r = subprocess.run(["bash", "-c", script, "bash", a, b], capture_output=True, text=True)
    return r.stdout.strip()


def test_all_present_nonempty_ok():
    assert "OK" in _run(("present", "present"))


def test_one_empty_fails():
    assert "FAIL" in _run(("present", "empty"))


def test_one_missing_fails():
    assert "FAIL" in _run(("present", "missing"))
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd /home/trick/Stiglitz && python3 -m pytest tests/test_phase_output_ok.py -v`
Expected: FAIL — a função `phase_output_ok` ainda não existe (awk extrai vazio → comando não encontrado).

- [ ] **Step 3: Implement `phase_output_ok()` em `stiglitz.sh`**

Inserir logo após `phase_skip()` (~linha 468):

```bash
phase_output_ok() {
    # phase_output_ok <fase> <artefato...> — sucesso se TODOS existem e são não-vazios.
    local phase="$1"; shift
    local art
    for art in "$@"; do
        if [ ! -s "$art" ]; then
            warn "$phase: saída ausente/vazia ($art) — não marcando como concluída (resume re-executará)"
            return 1
        fi
    done
    return 0
}
```

- [ ] **Step 4: Wire nos call-sites principais** (guardar `phase_done` com `phase_output_ok`)

Mapa fase→artefato (caminhos relativos a `$OUTDIR`; confirmar os nomes reais com `grep` perto de cada `phase_done`):

| Call-site | Guarda sugerida |
|---|---|
| `phase_done "FASE_1"` (694) | subdomínios: `phase_output_ok FASE_1 "$OUTDIR/raw/subdomains.txt" && phase_done "FASE_1"` |
| `phase_done "FASE_4"` (1185) | nuclei: `phase_output_ok FASE_4 "$OUTDIR/raw/nuclei.jsonl" && phase_done "FASE_4"` |
| `phase_done "FASE_9"` (1735) | dump ZAP: `phase_output_ok FASE_9 "$OUTDIR/raw/zap_alerts.json" && phase_done "FASE_9"` |

> Aplicar o padrão `phase_output_ok <FASE> <artefato...> && phase_done "<FASE>"` SOMENTE nas fases com artefato obrigatório quando rodam OK. Fases que podem legitimamente não produzir nada (ex.: P5/P6/P8 sem achados) ficam como estão (continuam chamando `phase_done` direto) para não impedir o avanço. Confirmar os nomes reais dos artefatos com `grep -nE "OUTDIR.*\.(json|jsonl|txt)" stiglitz.sh` perto de cada fase antes de fixar o mapa.

- [ ] **Step 5: Verificar**

Run: `cd /home/trick/Stiglitz && bash -n stiglitz.sh && shellcheck --severity=warning stiglitz.sh && python3 -m pytest tests/test_phase_output_ok.py -v && python3 -m pytest tests/ -q`
Expected: ok / limpo / 3 PASS / suíte verde.

- [ ] **Step 6: Commit**

```bash
cd /home/trick/Stiglitz
git add stiglitz.sh tests/test_phase_output_ok.py
git commit -m "harden(checkpoint): valida saída antes de phase_done

phase_output_ok exige artefato(s) existente(s)+não-vazio(s) antes de marcar a
fase concluída; senão warn e não marca (resume re-executa em vez de pular fase
falha em silêncio). Aplicado às fases com artefato obrigatório (P1/P4/P9).

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task E: Docs — `CLAUDE.md` + `ROADMAP.md`

**Files:** Modify `CLAUDE.md`, `docs/ROADMAP.md`

- [ ] **Step 1: `CLAUDE.md`** — na seção "Validação", documentar o selo do audit (`STIGLITZ_AUDIT_KEY` + `verify_audit.py --seal`) e a fronteira de ameaça (cobre adulteração por quem não tem a chave). Adicionar `scope.py` na tabela `lib/` (após `takeover.py`): linha curta — "Escopo de engajamento: `in_scope(url, scope_domains)` (fail-open só sem escopo), reusado por ingest/brute/sqli/xss; CLI filtra stdin. Lógica pura".

- [ ] **Step 2: `docs/ROADMAP.md`** — marcar a Frente 5 como concluída no estilo dos itens P1 feitos (`- ✅ **hardening (Frente 5)** ...`), citando os 4 reforços. Não incluir dado de alvo.

- [ ] **Step 3: Commit**

```bash
cd /home/trick/Stiglitz
git add CLAUDE.md docs/ROADMAP.md
git commit -m "docs(hardening): registra selo de audit, scope.py e marca Frente 5

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Self-Review (preenchido)

**Spec coverage:** (a)→Task A; (b)→Task B; (c)→Task C; (d)→Task D; docs→Task E. ✓
**Placeholders:** os "confirmar no Step 0" são instruções de verificação contra o código real (nomes/linhas deslocam), não TBDs — cada um vem com o comando `grep` e a ação. Código real fornecido em todos os steps de implementação. ✓
**Type/contract consistency:** `verify_seal(log, seal, key)` e `_head_hash` usados consistentemente; `in_scope(url, scope_domains)`/`filter_in_scope` idem nos testes e no `scope_guard`; `phase_output_ok <fase> <art...>` idem. Selo: formato `HMAC-SHA256 <hex> head=<head>` consistente entre `audit_seal` (bash), `verify_seal` (py) e os testes. ✓
**Ordem:** A → B → C → D → E (independentes; A primeiro firma a suíte). ✓
**Higiene:** sem alvo/cliente/token; `audit.log.seal` nunca contém a chave. ✓
